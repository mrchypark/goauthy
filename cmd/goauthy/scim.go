package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/scim"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	maxSCIMProvidersFileSize = 64 << 10
	maxSCIMTokenFileSize     = 4096
	maxSCIMCAFileSize        = 256 << 10
	maxSCIMProviders         = 16
	defaultSCIMDrainLimit    = 64
	// Tombstone cleanup only removes records whose provider-scoped delete jobs
	// are terminally successful. Keeping this bounded keeps one reconciliation
	// pass from monopolizing the database.
	defaultSCIMTombstoneCleanupLimit = 64
)

type scimProvidersDocument struct {
	Providers []json.RawMessage `json:"providers"`
}

type scimProviderFileConfig struct {
	ID              string `json:"id"`
	BaseURL         string `json:"base_url"`
	TokenFile       string `json:"token_file"`
	CAFile          string `json:"ca_file"`
	SyncDeleteUsers bool   `json:"sync_delete_users"`
}

type configuredSCIMProvider struct {
	client       *scim.Client
	deletePolicy scim.DeletePolicy
}

// scimRuntime owns the process-local provider clients and the durable work
// queue. The queue contains desired projection data only; provider tokens stay in
// these in-memory clients.
type scimRuntime struct {
	identities  *identity.Store
	outbox      *scim.Outbox
	mappings    *scim.UserMappingStore
	providers   map[string]configuredSCIMProvider
	providerIDs []string
	drainLimit  int
	wake        chan struct{}
	configStore *scim.ConfigStore
	// now is the claim clock. Run installs the scheduler clock so every
	// drained job takes a fresh reading; a nil clock keeps the caller's pass
	// time, which keeps callers that supply a fixed time deterministic.
	now func() time.Time
	// beforeTombstoneEnqueue is a test seam for the cleanup/recreation fence.
	beforeTombstoneEnqueue func()
}

// scimRuntimeFromEnv is optional: an absent providers file disables outbound
// SCIM without changing the rest of server startup.
func scimRuntimeFromEnv(getenv func(string) string, db *rhiza.DB, identities *identity.Store, keyring scim.EnvelopeKeyring) (*scimRuntime, error) {
	if getenv == nil {
		return nil, errors.New("SCIM environment loader is not configured")
	}
	path := getenv("GOAUTHY_SCIM_PROVIDERS_FILE")
	if path == "" && db == nil {
		return nil, nil
	}
	if db == nil || identities == nil {
		return nil, errors.New("SCIM requires identity and Rhiza stores")
	}

	clients := make(map[string]configuredSCIMProvider)
	ids := make([]string, 0)

	if path != "" {
		providers, err := loadSCIMProviders(path)
		if err != nil {
			return nil, err
		}
		for id, provider := range providers {
			client, err := scim.New(scim.Config{BaseURL: provider.baseURL, Token: provider.token, RootCAs: provider.rootCAs})
			if err != nil {
				return nil, fmt.Errorf("configure SCIM provider %q: %w", id, err)
			}
			deletePolicy := scim.UnlinkRemote
			if provider.syncDeleteUsers {
				deletePolicy = scim.DeleteRemote
			}
			clients[id] = configuredSCIMProvider{client: client, deletePolicy: deletePolicy}
			ids = append(ids, id)
		}
	}

	var configStore *scim.ConfigStore
	if keyring != nil {
		configStore = scim.NewConfigStore(db, keyring)
	}

	mappings := scim.NewUserMappingStore(db)
	resolver := func(ctx context.Context, id string) (scim.Reconciler, error) {
		if provider, ok := clients[id]; ok {
			return provider.client, nil
		}
		if configStore != nil {
			cfg, found, err := configStore.GetClientConfig(ctx, id)
			if err != nil {
				return nil, err
			}
			if found && cfg.Enabled && cfg.BearerToken != "" {
				var rootCAs *x509.CertPool
				if len(cfg.CACertPEM) > 0 {
					rootCAs = x509.NewCertPool()
					if !rootCAs.AppendCertsFromPEM(cfg.CACertPEM) {
						return nil, errors.New("invalid SCIM CA certificate")
					}
				}
				client, err := scim.New(scim.Config{BaseURL: cfg.Endpoint, Token: cfg.BearerToken, RootCAs: rootCAs})
				if err != nil {
					return nil, fmt.Errorf("configure SCIM provider %q: %w", id, err)
				}
				return client, nil
			}
		}
		return nil, errors.New("SCIM provider is not configured")
	}
	outbox := scim.NewOutbox(db, resolver, scim.OutboxConfig{Mapping: mappings})
	tombstoneProviders := make([]identity.SCIMTombstoneProvider, 0, len(ids))
	for _, id := range ids {
		provider := clients[id]
		tombstoneProviders = append(tombstoneProviders, identity.SCIMTombstoneProvider{ID: id, DeletePolicy: provider.deletePolicy})
	}
	if err := identities.ConfigureSCIMTombstoneProviders(tombstoneProviders); err != nil {
		return nil, fmt.Errorf("configure SCIM tombstone providers: %w", err)
	}
	return &scimRuntime{identities: identities, outbox: outbox, mappings: mappings, providers: clients, providerIDs: ids, drainLimit: defaultSCIMDrainLimit, wake: make(chan struct{}, 1), configStore: configStore}, nil
}

type loadedSCIMProvider struct {
	baseURL         string
	token           string
	rootCAs         *x509.CertPool
	syncDeleteUsers bool
}

func loadSCIMProviders(path string) (map[string]loadedSCIMProvider, error) {
	if path == "" {
		return nil, errors.New("SCIM providers file path is empty")
	}
	data, err := readSCIMRegularFile(path, maxSCIMProvidersFileSize, "SCIM providers")
	if err != nil {
		return nil, err
	}
	if err := rejectDuplicateJSONNames(data); err != nil {
		return nil, errors.New("SCIM providers file contains duplicate JSON fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document scimProvidersDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode SCIM providers file: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("SCIM providers file must contain exactly one JSON document")
	}
	if len(document.Providers) < 1 || len(document.Providers) > maxSCIMProviders {
		return nil, fmt.Errorf("SCIM providers must contain 1 to %d providers", maxSCIMProviders)
	}
	providers := make(map[string]loadedSCIMProvider, len(document.Providers))
	for _, raw := range document.Providers {
		config, err := decodeSCIMProvider(raw)
		if err != nil {
			return nil, err
		}
		if _, exists := providers[config.ID]; exists {
			return nil, errors.New("duplicate SCIM provider id")
		}
		token, err := loadSCIMToken(config.TokenFile)
		if err != nil {
			return nil, err
		}
		rootCAs, err := loadSCIMRootCAs(config.CAFile)
		if err != nil {
			return nil, err
		}
		providers[config.ID] = loadedSCIMProvider{baseURL: config.BaseURL, token: token, rootCAs: rootCAs, syncDeleteUsers: config.SyncDeleteUsers}
	}
	return providers, nil
}

func decodeSCIMProvider(data []byte) (scimProviderFileConfig, error) {
	if err := rejectDuplicateJSONNames(data); err != nil {
		return scimProviderFileConfig{}, errors.New("SCIM provider contains duplicate JSON fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var config scimProviderFileConfig
	if err := decoder.Decode(&config); err != nil {
		return scimProviderFileConfig{}, errors.New("decode SCIM provider configuration")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return scimProviderFileConfig{}, errors.New("SCIM provider must contain exactly one JSON object")
	}
	if !validSCIMProviderID(config.ID) {
		return scimProviderFileConfig{}, errors.New("invalid SCIM provider id")
	}
	if !validSCIMBaseURL(config.BaseURL) {
		return scimProviderFileConfig{}, errors.New("SCIM provider base_url must be an HTTPS URL")
	}
	if config.TokenFile == "" || strings.TrimSpace(config.TokenFile) != config.TokenFile {
		return scimProviderFileConfig{}, errors.New("SCIM provider token_file is invalid")
	}
	if config.CAFile != "" && strings.TrimSpace(config.CAFile) != config.CAFile {
		return scimProviderFileConfig{}, errors.New("SCIM provider ca_file is invalid")
	}
	return config, nil
}

func validSCIMBaseURL(raw string) bool {
	parsed, err := url.Parse(raw)
	return strictHTTPSURL(raw) && err == nil && parsed.RawPath == "" && parsed.Opaque == ""
}

func rejectDuplicateJSONNames(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		switch delimiter := token.(type) {
		case json.Delim:
			switch delimiter {
			case '{':
				seen := make(map[string]struct{})
				for decoder.More() {
					name, err := decoder.Token()
					if err != nil {
						return err
					}
					key, ok := name.(string)
					if !ok {
						return errors.New("object key is not a string")
					}
					if _, exists := seen[key]; exists {
						return errors.New("duplicate object key")
					}
					seen[key] = struct{}{}
					if err := walk(); err != nil {
						return err
					}
				}
				_, err = decoder.Token()
				return err
			case '[':
				for decoder.More() {
					if err := walk(); err != nil {
						return err
					}
				}
				_, err = decoder.Token()
				return err
			}
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON documents")
		}
		return err
	}
	return nil
}

func validSCIMProviderID(id string) bool {
	if id == "" || len(id) > 64 || id != strings.TrimSpace(id) {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') || (i == 0 && (c == '-' || c == '_')) {
			return false
		}
	}
	return true
}

func loadSCIMToken(path string) (string, error) {
	data, err := readSCIMRegularFile(path, maxSCIMTokenFileSize, "SCIM token")
	if err != nil {
		return "", err
	}
	data = trimOneSCIMLineEnding(data)
	if len(data) == 0 || !utf8.Valid(data) {
		return "", errors.New("SCIM token must be non-empty UTF-8 without whitespace or control characters")
	}
	for _, r := range string(data) {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", errors.New("SCIM token must be non-empty UTF-8 without whitespace or control characters")
		}
	}
	return string(data), nil
}

func loadSCIMRootCAs(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := readSCIMRegularFile(path, maxSCIMCAFileSize, "SCIM CA")
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(data)) > 0 {
		data = bytes.TrimSpace(data)
		if !bytes.HasPrefix(data, []byte("-----BEGIN ")) {
			return nil, errors.New("SCIM CA file must contain only valid PEM certificates")
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, errors.New("SCIM CA file must contain only valid PEM certificates")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New("SCIM CA file must contain only valid PEM certificates")
		}
		pool.AddCert(cert)
		count++
		data = rest
	}
	if count == 0 {
		return nil, errors.New("SCIM CA file must contain at least one PEM certificate")
	}
	return pool, nil
}

func readSCIMRegularFile(path string, limit int, label string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s file: %w", label, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat %s file: %w", label, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s file must be a regular file", label)
	}
	if info.Mode().Perm()&0o007 != 0 {
		return nil, fmt.Errorf("%s file is accessible to other users", label)
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", label, err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%s file exceeds %d bytes", label, limit)
	}
	return data, nil
}

func trimOneSCIMLineEnding(data []byte) []byte {
	if len(data) >= 2 && data[len(data)-2] == '\r' && data[len(data)-1] == '\n' {
		return data[:len(data)-2]
	}
	if len(data) > 0 && data[len(data)-1] == '\n' {
		return data[:len(data)-1]
	}
	return data
}

// Step scans all local users once for every provider and then executes at most
// drainLimit due durable jobs. Tombstones fan out only to their deletion-time
// provider snapshots that remain configured. Groups are enqueued once all local
// members can be resolved to each provider's remote SCIM User IDs.
// The supplied time stamps projection and cleanup; each claim then takes its
// own reading from the runtime's claim clock, so callers that supply a fixed
// time stay deterministic. Absent mappings and provider 404s use the outbox's
// no-op semantics.
func (r *scimRuntime) Step(ctx context.Context, now time.Time) error {
	if r == nil || r.identities == nil || r.outbox == nil || ctx == nil || now.IsZero() || len(r.providerIDs) == 0 || r.drainLimit <= 0 {
		return errors.New("SCIM runtime is not configured")
	}
	localUsers, err := r.identities.ListSCIMUsers(ctx)
	if err != nil {
		return err
	}
	tombstones, err := r.identities.ListSCIMDeletedUsers(ctx)
	if err != nil {
		return err
	}
	for _, deleted := range tombstones {
		if !deleted.HardDelete {
			continue
		}
		// A complete generated hard-delete snapshot must retain at least one
		// provider obligation. Missing rows are malformed durable state; do not
		// let the later NOT EXISTS cleanup condition treat them as success.
		if deleted.ProviderSnapshotComplete && deleted.Generation != "" && len(deleted.Providers) == 0 {
			return errors.New("invalid hard-delete SCIM tombstone provider snapshot")
		}
		for _, provider := range deleted.Providers {
			if provider.DeletePolicy != scim.DeleteRemote {
				return errors.New("invalid hard-delete SCIM tombstone provider policy")
			}
		}
	}
	if r.beforeTombstoneEnqueue != nil {
		r.beforeTombstoneEnqueue()
	}
	tombstoned := make(map[string]struct{}, len(tombstones))
	for _, user := range tombstones {
		tombstoned[user.ExternalID] = struct{}{}
	}
	userNames := make(map[string]string, len(localUsers))
	for _, user := range localUsers {
		if _, deleted := tombstoned[user.ExternalID]; deleted {
			continue
		}
		userNames[user.ExternalID] = user.UserName
	}
	groups, err := r.identities.ListSCIMGroups(ctx)
	if err != nil {
		return err
	}
	for _, providerID := range r.providerIDs {
		for _, local := range localUsers {
			if _, deleted := tombstoned[local.ExternalID]; deleted {
				continue
			}
			_, err := r.outbox.EnqueueUser(ctx, providerID, scim.User{ExternalID: local.ExternalID, UserName: local.UserName, Active: local.Active}, now)
			if err != nil {
				return err
			}
		}
		if r.mappings == nil {
			continue
		}
		for _, local := range groups {
			members := make([]scim.GroupMember, 0, len(local.Members))
			for _, subject := range local.Members {
				remoteID, found, err := r.mappings.Lookup(ctx, providerID, subject)
				if err != nil {
					return err
				}
				if !found {
					members = nil
					break
				}
				members = append(members, scim.GroupMember{Value: remoteID, Display: userNames[subject]})
			}
			if len(members) != len(local.Members) {
				continue
			}
			if _, err := r.outbox.EnqueueGroup(ctx, providerID, scim.Group{ExternalID: local.ExternalID, DisplayName: local.DisplayName, Members: members}, now); err != nil {
				if !errors.Is(err, scim.ErrGroupTooLarge) {
					return err
				}
				// One group above the supported projection size fails on every
				// pass. Record it durably and keep projecting everything else:
				// unrelated providers, and the deletes already queued for them,
				// must not stall behind it.
				if err := r.recordGroupProjectionFailure(ctx, providerID, local, err, now); err != nil {
					return err
				}
				continue
			}
		}
	}
	for _, deleted := range tombstones {
		if !deleted.ProviderSnapshotComplete || deleted.Generation == "" {
			continue
		}
		for _, provider := range deleted.Providers {
			if _, configured := r.providers[provider.ID]; !configured {
				continue
			}
			_, admitted, err := r.outbox.EnqueueTombstoneDelete(ctx, provider.ID, scim.User{ExternalID: deleted.ExternalID, UserName: deleted.UserName, Active: deleted.Active}, provider.DeletePolicy, deleted.Generation, now)
			if err != nil {
				return err
			}
			if !admitted {
				continue
			}
		}
	}
	for range r.drainLimit {
		// Claims take a fresh reading. One pass may deliver up to drainLimit
		// jobs, and a lease derived from the timestamp captured before
		// projection can already be expired by the time a later claim runs,
		// which would let another replica take over work still in flight.
		claimNow := now
		if r.now != nil {
			claimNow = r.now().UTC()
		}
		if err := r.outbox.Step(ctx, claimNow); err != nil {
			return err
		}
	}
	if _, err := r.identities.CleanupSCIMDeletedUsers(ctx, defaultSCIMTombstoneCleanupLimit); err != nil {
		return err
	}
	if _, err := r.outbox.Cleanup(ctx, now, defaultSCIMTombstoneCleanupLimit); err != nil {
		return err
	}
	return nil
}

// recordGroupProjectionFailure writes the durable failure record for a group
// the projection boundary rejected. The enqueue wrote no row, so this event is
// the only trace that outlives the pass. It is gated on the event id, which
// keeps a permanently oversized group from writing one event per pass; the
// event log's own retention releases that id again.
func (r *scimRuntime) recordGroupProjectionFailure(ctx context.Context, providerID string, group identity.SCIMGroup, reason error, now time.Time) error {
	action := `GroupCreateUpdate(` + strconv.Quote(group.ExternalID) + `)`
	event := eventlog.ScimFailure("scim-projection/"+providerID+"/"+group.ExternalID, providerID, action, 0, now)
	text := *event.Text + " / " + reason.Error()
	event.Text = &text
	statement, err := event.Statement(`NOT EXISTS (SELECT 1 FROM event_log WHERE id=?)`, event.ID)
	if err != nil {
		return err
	}
	// The request id stays within Rhiza's 64 byte limit and is unique per pass,
	// while the event id keeps the durable record itself stable.
	_, err = storage.Execute(ctx, r.outbox.DB, rhiza.ExecuteRequest{RequestID: "sp/" + event.ID + "/" + strconv.FormatInt(now.UnixMilli(), 10), Statements: []rhiza.SQLStatement{statement}})
	return err
}

// Wake requests reconciliation after a committed identity creation. A buffered
// signal coalesces bursts and retains a request arriving during a running Step.
// It carries no user data and never waits for a provider or a worker to start.
// Startup/periodic scans recover a signal lost to process exit from durable users.
func (r *scimRuntime) Wake() {
	if r == nil {
		return
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Run performs reconciliation at startup, on creation wakes and on a ticker.
// Worker errors are reported through onError and never returned as readiness
// failures; configuration and context validation errors are returned directly.
func (r *scimRuntime) Run(ctx context.Context, interval time.Duration, now func() time.Time, onError func(error)) error {
	if r == nil || r.identities == nil || r.outbox == nil || len(r.providerIDs) == 0 || r.drainLimit <= 0 || ctx == nil || interval <= 0 || now == nil {
		return errors.New("SCIM runtime scheduler is not configured")
	}
	r.now = now
	step := func() {
		if err := r.Step(ctx, now().UTC()); err != nil && ctx.Err() == nil && onError != nil {
			onError(err)
		}
	}
	if ctx.Err() != nil {
		return nil
	}
	step()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-r.wake:
			// ponytail: reuse the O(users*providers) scan; use targeted durable
			// projection work if measured creation load makes scans too costly.
			step()
		case <-ticker.C:
			step()
		}
	}
}
