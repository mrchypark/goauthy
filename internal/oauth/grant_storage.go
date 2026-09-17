package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

type transactionContextKey struct{}

type transaction struct {
	passwordGeneration                  int64
	authenticationGeneration            int64
	targetRefreshSignature              string
	attempt                             string
	kind                                string
	key                                 string
	deviceCodeDigest                    string
	deviceClaimDigest                   string
	deviceRequestID                     string
	requestID                           string
	oidcSID                             string
	issueNow                            int64
	sourceAccessSignature               string
	sourceAccessExpiresAt               int64
	actorAccessSignature                string
	actorAccessExpiresAt                int64
	targetAccessSignature               string
	principalSubject                    string
	principalRevision                   int64
	accounts                            []accountExpiry
	customCatalogRevision               int64
	customCatalogSet                    bool
	clientPolicyPrefix                  string
	clientPolicyRevision                int64
	clientPolicySet                     bool
	clientPolicyClientID                string
	clientCredentialsClaimsRevision     int64
	clientCredentialsClaimsSet          bool
	managedClientID                     string
	managedClientRevision               int64
	managedClientGeneration             string
	managedClientSet                    bool
	dpopPolicy                          dpopPolicySnapshot
	exchangeAccessCutoffStatement       int
	exchangeAccessCutoffArgument        int
	exchangeRequestCutoffStatement      int
	exchangeRequestCutoffArgument       int
	exchangeActorAccessCutoffStatement  int
	exchangeActorAccessCutoffArgument   int
	exchangeActorRequestCutoffStatement int
	exchangeActorRequestCutoffArgument  int
	statements                          []rhiza.SQLStatement
	done                                bool
}

type requestRecord struct {
	ID                string                     `json:"id"`
	ClientID          string                     `json:"client_id"`
	RequestedAt       int64                      `json:"requested_at_unix_ms"`
	RequestedScopes   []string                   `json:"requested_scopes"`
	GrantedScopes     []string                   `json:"granted_scopes"`
	RequestedAudience []string                   `json:"requested_audience"`
	GrantedAudience   []string                   `json:"granted_audience"`
	Form              url.Values                 `json:"form"`
	ExpiresAt         map[fosite.TokenType]int64 `json:"expires_at_unix_ms"`
	Username          string                     `json:"username,omitempty"`
	Subject           string                     `json:"subject,omitempty"`
	Extra             map[string]interface{}     `json:"extra,omitempty"`
	EphemeralClient   *ephemeralClientRecord     `json:"ephemeral_client,omitempty"`
	ManagedClient     *managedClientRecord       `json:"managed_client,omitempty"`
}

type managedClientRecord struct {
	ID            string   `json:"id"`
	Revision      int64    `json:"revision"`
	Generation    string   `json:"generation"`
	Enabled       bool     `json:"enabled"`
	Confidential  bool     `json:"confidential"`
	RedirectURIs  []string `json:"redirect_uris"`
	Scopes        []string `json:"scopes"`
	DefaultScopes []string `json:"default_scopes"`
	GrantTypes    []string `json:"grant_types"`
}

// ephemeralClientRecord is a sanitized, immutable metadata snapshot. Fosite
// stores only the client ID by default; retaining this record prevents a token
// redemption or resource request from refetching a mutable remote document.
type ephemeralClientRecord struct {
	ID                      string   `json:"id"`
	Name                    string   `json:"name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	Scopes                  []string `json:"scopes"`
	AllowedResources        []string `json:"allowed_resources,omitempty"`
	AllowedResourcesPresent bool     `json:"allowed_resources_present,omitempty"`
}

// These values are accepted at a token endpoint but are only inputs to the
// current request. Persisted requests are replayed for validation and token
// metadata, so credential and single-use artifacts must not cross this
// boundary. The callers deliberately sanitize different subsets of a form;
// keep this final guard centralized and copy values so the request is not
// mutated or aliased by storage.
var transientRequestFormFields = map[string]struct{}{
	"client_secret":             {},
	"client_assertion":          {},
	"client_assertion_type":     {},
	"subject_token":             {},
	"subject_token_type":        {},
	"actor_token":               {},
	"actor_token_type":          {},
	"assertion":                 {},
	"code":                      {},
	"code_verifier":             {},
	"device_code":               {},
	"refresh_token":             {},
	"password":                  {},
	"id_token_hint":             {},
	"request":                   {},
	"request_uri":               {},
	exchangeSourceSignatureForm: {},
	exchangeSourceExpiryForm:    {},
	exchangeActorSignatureForm:  {},
	exchangeActorExpiryForm:     {},
}

func persistedRequestForm(form url.Values) url.Values {
	if form == nil {
		return nil
	}
	persisted := make(url.Values, len(form))
	for key, values := range form {
		if _, transient := transientRequestFormFields[key]; transient {
			continue
		}
		persisted[key] = append([]string(nil), values...)
	}
	return persisted
}

func (r ephemeralClientRecord) clone() ephemeralClientRecord {
	r.RedirectURIs = append([]string(nil), r.RedirectURIs...)
	r.Scopes = append([]string(nil), r.Scopes...)
	if r.AllowedResources != nil {
		r.AllowedResources = append([]string{}, r.AllowedResources...)
	}
	return r
}

func (s *Store) BeginTX(ctx context.Context) (context.Context, error) {
	if txFrom(ctx) != nil {
		return ctx, fmt.Errorf("nested OAuth storage transaction")
	}
	attempt := make([]byte, 16)
	if _, err := rand.Read(attempt); err != nil {
		return ctx, err
	}
	tx := &transaction{
		attempt:                             base64.RawURLEncoding.EncodeToString(attempt),
		exchangeAccessCutoffStatement:       -1,
		exchangeAccessCutoffArgument:        -1,
		exchangeRequestCutoffStatement:      -1,
		exchangeRequestCutoffArgument:       -1,
		exchangeActorAccessCutoffStatement:  -1,
		exchangeActorAccessCutoffArgument:   -1,
		exchangeActorRequestCutoffStatement: -1,
		exchangeActorRequestCutoffArgument:  -1,
	}
	tx.accounts, _ = ctx.Value(accountExpiryContextKey{}).([]accountExpiry)
	tx.dpopPolicy, _ = ctx.Value(dpopPolicyContextKey{}).(dpopPolicySnapshot)
	if snapshot, ok := ctx.Value(principalSnapshotContextKey{}).(principalSnapshot); ok {
		if snapshot.subject != "" && snapshot.revision > 0 {
			tx.principalSubject, tx.principalRevision = snapshot.subject, snapshot.revision
		}
		// The custom resolver is independent of the optional principal resolver.
		if snapshot.custom.enabled {
			tx.customCatalogRevision, tx.customCatalogSet = snapshot.custom.catalogRevision, true
		}
		// Managed metadata is fenced by managedClientGuard, not the bootstrap policy table.
		if snapshot.policySet && !snapshot.policy.managedClient {
			tx.clientPolicyPrefix, tx.clientPolicyRevision, tx.clientPolicyClientID, tx.clientPolicySet = snapshot.policy.Prefix, snapshot.policy.Revision, snapshot.policyClientID, true
		}
		if snapshot.clientClaims.set {
			tx.clientCredentialsClaimsRevision, tx.clientCredentialsClaimsSet = snapshot.clientClaims.revision, true
		}
	}
	return context.WithValue(ctx, transactionContextKey{}, tx), nil
}

// clientCredentialsClaimsGuard ties a bootstrap machine-policy snapshot to
// the exact Rhiza write that persists its access token. A missing policy is a
// first-class revision-zero snapshot, so creation racing issuance fails too.
func clientCredentialsClaimsGuard(ctx context.Context) (string, []any) {
	set, revision := false, int64(0)
	if tx := txFrom(ctx); tx != nil && tx.clientCredentialsClaimsSet {
		set, revision = true, tx.clientCredentialsClaimsRevision
	} else if snapshot, ok := ctx.Value(principalSnapshotContextKey{}).(principalSnapshot); ok && snapshot.clientClaims.set {
		set, revision = true, snapshot.clientClaims.revision
	}
	if !set {
		return "", nil
	}
	clientID, _ := ctx.Value(clientCredentialsClaimsClientIDContextKey{}).(string)
	if clientID == "" {
		return ` AND 0`, nil
	}
	if revision == 0 {
		return ` AND NOT EXISTS (SELECT 1 FROM bootstrap_client_credentials_claims WHERE client_id=?)`, []any{clientID}
	}
	return ` AND EXISTS (SELECT 1 FROM bootstrap_client_credentials_claims WHERE client_id=? AND revision=?)`, []any{clientID, revision}
}

type dpopPolicyContextKey struct{}
type dpopPolicySnapshot struct {
	clientID     string
	proofPresent bool
}

func (p dpopPolicySnapshot) guard() (string, []any) {
	if p.clientID == "" {
		return "", nil
	}
	// Keep client existence and the current binding requirement in the same
	// atomic mutation as grant consumption and token creation.
	return ` AND EXISTS (SELECT 1 FROM dynamic_oauth_clients WHERE client_id=? AND (dpop_bound_access_tokens=0 OR ?=1))`, []any{p.clientID, p.proofPresent}
}

type clientCredentialsClaimsClientIDContextKey struct{}

func (s *Store) Commit(ctx context.Context) error {
	tx := txFrom(ctx)
	if tx == nil || tx.done || tx.requestID == "" || len(tx.statements) == 0 {
		return fmt.Errorf("invalid OAuth storage transaction")
	}
	if tx.kind == "device" {
		// Keep the claim digest as a durable consumed marker. This makes the
		// post-commit proof specific to this claim; clearing it would let a
		// losing concurrent claim mistake another worker's consumed row for its
		// own successful issuance.
		guard, args := tx.deviceGuard()
		tx.statements = append(tx.statements, rhiza.SQLStatement{SQL: `UPDATE oauth_device_grants
			SET state = 'consumed', claim_until_unix_ms = 0, token_request_id = ?
			WHERE device_code_digest = ? AND ` + guard,
			Args: append([]any{tx.deviceRequestID, tx.deviceCodeDigest}, args...)})
	}
	cutoff := s.now().UTC()
	if tx.kind == "exchange" && !tx.bindExchangeCutoff(cutoff.UnixMilli()) {
		return fmt.Errorf("invalid token-exchange transaction")
	}
	if limit := accountDeadline(ctx); !limit.IsZero() && !limit.After(cutoff) {
		return fosite.ErrInvalidGrant
	}
	for i := range tx.statements {
		for j, arg := range tx.statements[i].Args {
			if _, ok := arg.(accountExpiryCutoff); ok {
				tx.statements[i].Args[j] = cutoff.UnixMilli()
			}
		}
	}
	tx.done = true
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: tx.requestID, Statements: tx.statements})
	if err != nil {
		if errors.Is(err, rhiza.ErrRequestConflict) && (tx.kind == "code" || tx.kind == "refresh") {
			return fosite.ErrSerializationFailure
		}
		return err
	}
	if tx.kind == "password" {
		return s.verifyPasswordIssue(ctx, tx)
	}
	if tx.kind == "exchange" {
		result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT
			(SELECT COUNT(*) FROM oauth_access_tokens WHERE signature = ?),
			(SELECT COUNT(*) FROM oauth_token_requests WHERE signature = ?)`, Args: []any{tx.targetAccessSignature, tx.targetAccessSignature}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return err
		}
		if len(result.Rows) != 1 || len(result.Rows[0]) != 2 || result.Rows[0][0] != int64(1) || result.Rows[0][1] != int64(1) {
			return fosite.ErrSerializationFailure
		}
		return nil
	}
	if tx.kind == "issue" && (tx.oidcSID != "" || tx.principalSubject != "" || tx.clientPolicySet || tx.managedClientSet || len(tx.accounts) != 0) {
		result, err := s.db.Query(ctx, rhiza.QueryRequest{
			SQL: `SELECT 1 FROM oauth_authorize_codes WHERE signature = ?`, Args: []any{tx.key}, Consistency: rhiza.ConsistencyLinearizable,
		})
		if err != nil {
			return err
		}
		if len(result.Rows) != 1 {
			return fosite.ErrSerializationFailure
		}
		return nil
	}
	if tx.kind == "device" {
		result, err := s.db.Query(ctx, rhiza.QueryRequest{
			SQL:  `SELECT 1 FROM oauth_device_grants WHERE device_code_digest = ? AND claim_token_digest = ? AND state = 'consumed'`,
			Args: []any{tx.deviceCodeDigest, tx.deviceClaimDigest}, Consistency: rhiza.ConsistencyLinearizable,
		})
		if err != nil {
			return err
		}
		if len(result.Rows) != 1 {
			return fosite.ErrSerializationFailure
		}
		return nil
	}
	if tx.kind != "code" && tx.kind != "refresh" {
		return nil
	}
	column, table := "used_attempt", "oauth_authorize_codes"
	if tx.kind == "refresh" {
		column, table = "rotated_attempt", "oauth_refresh_tokens"
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:  `SELECT 1 FROM ` + table + ` WHERE signature = ? AND ` + column + ` = ?`,
		Args: []any{tx.key, tx.attempt}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}
	if len(result.Rows) != 1 {
		return fosite.ErrSerializationFailure
	}
	return nil
}

func (s *Store) SetDeviceRequestID(ctx context.Context, id string) error {
	tx := txFrom(ctx)
	if tx == nil || tx.kind != "device" || id == "" {
		return errors.New("invalid device request id")
	}
	tx.deviceRequestID = id
	return nil
}

// BeginTokenExchangeTX opens a target-token issuance transaction guarded by
// the source access-token row that was already cryptographically validated by
// the RFC 8693 handler. The source remains reusable; its expiry and presence
// are checked again in the same replicated mutation that creates the target.
func (s *Store) BeginTokenExchangeTX(ctx context.Context, sourceAccessSignature string, sourceExpiresAt time.Time) (context.Context, error) {
	return s.beginTokenExchangeTX(ctx, sourceAccessSignature, sourceExpiresAt, "", time.Time{})
}

// BeginTokenExchangeActorTX adds an independently validated actor access
// token to the exchange guard. Both source and actor must remain active until
// the target write commits.
func (s *Store) BeginTokenExchangeActorTX(ctx context.Context, sourceAccessSignature string, sourceExpiresAt time.Time, actorAccessSignature string, actorExpiresAt time.Time) (context.Context, error) {
	return s.beginTokenExchangeTX(ctx, sourceAccessSignature, sourceExpiresAt, actorAccessSignature, actorExpiresAt)
}

func (s *Store) beginTokenExchangeTX(ctx context.Context, sourceAccessSignature string, sourceExpiresAt time.Time, actorAccessSignature string, actorExpiresAt time.Time) (context.Context, error) {
	if sourceAccessSignature == "" || !sourceExpiresAt.After(time.Now().UTC()) {
		return ctx, fmt.Errorf("invalid token-exchange source")
	}
	if (actorAccessSignature == "") != actorExpiresAt.IsZero() || (actorAccessSignature != "" && !actorExpiresAt.After(time.Now().UTC())) {
		return ctx, fmt.Errorf("invalid token-exchange actor")
	}
	ctx, err := s.BeginTX(ctx)
	if err != nil {
		return ctx, err
	}
	tx := txFrom(ctx)
	tx.kind = "exchange"
	tx.sourceAccessSignature = sourceAccessSignature
	tx.sourceAccessExpiresAt = sourceExpiresAt.UTC().UnixMilli()
	if actorAccessSignature != "" {
		tx.actorAccessSignature, tx.actorAccessExpiresAt = actorAccessSignature, actorExpiresAt.UTC().UnixMilli()
	}
	return ctx, nil
}

func (*Store) Rollback(ctx context.Context) error {
	tx := txFrom(ctx)
	if tx == nil || tx.done {
		return nil
	}
	tx.done = true
	tx.statements = nil
	return nil
}

func txFrom(ctx context.Context) *transaction {
	tx, _ := ctx.Value(transactionContextKey{}).(*transaction)
	return tx
}

func configureTX(ctx context.Context, kind, key string) (*transaction, error) {
	tx := txFrom(ctx)
	if tx == nil || tx.done {
		return nil, fmt.Errorf("OAuth operation requires an active transaction")
	}
	if tx.kind != "" && (tx.kind != kind || tx.key != key) {
		return nil, fmt.Errorf("mixed OAuth storage transaction")
	}
	if tx.kind == "" {
		tx.kind, tx.key = kind, key
		attemptID := "/" + requestIDPart(tx.attempt)
		switch kind {
		case "issue":
			tx.requestID = "oauth-code-issue/" + key
		case "code":
			tx.requestID = "oauth-code-exchange/" + requestIDPart(key) + attemptID
		case "refresh":
			tx.requestID = "oauth-refresh/" + requestIDPart(key) + attemptID
		case "reuse":
			tx.requestID = "oauth-refresh-reuse/" + key
		case "device":
			tx.requestID = "oauth-device-exchange/" + key
		default:
			return nil, fmt.Errorf("unknown OAuth transaction kind")
		}
	}
	return tx, nil
}

func requestIDPart(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:20]
}

// BeginDeviceTX binds an approved-device claim to the token artifacts written
// by this transaction.  The claim values are digested before entering storage
// or a request ID, so neither device codes nor claim tokens are persisted in
// OAuth request data or operation identifiers.
func (s *Store) BeginDeviceTX(ctx context.Context, deviceCode, claimToken string) (context.Context, error) {
	if deviceCode == "" || claimToken == "" {
		return ctx, errors.New("device exchange requires a claim")
	}
	ctx, err := s.BeginTX(ctx)
	if err != nil {
		return ctx, err
	}
	deviceDigest := deviceCodeDigest(deviceCode)
	claimDigest := deviceCodeDigest(claimToken)
	tx, err := configureTX(ctx, "device", deviceDigest[:20]+"/"+claimDigest[:20])
	if err != nil {
		_ = s.Rollback(ctx)
		return ctx, err
	}
	tx.deviceCodeDigest, tx.deviceClaimDigest = deviceDigest, claimDigest
	tx.issueNow = time.Now().UTC().UnixMilli()
	return ctx, nil
}

// Read the subject from the exact durable claim, not caller-supplied metadata.
// The same predicate guards every artifact and the consumed marker.
func (tx *transaction) deviceGuard() (string, []any) {
	accountGuard, accountArgs := tx.principalGuard()
	return `EXISTS (SELECT 1 FROM oauth_device_grants d JOIN identity_users u ON u.subject=d.subject
		WHERE d.device_code_digest=? AND d.claim_token_digest=? AND d.state='approved'
		AND d.claim_until_unix_ms > ? AND d.expires_at_unix_ms > ? AND u.disabled=0
		AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?)
		AND (d.managed_client_generation IS NOT NULL OR NOT EXISTS (SELECT 1 FROM managed_oauth_clients mc0 WHERE mc0.id=d.client_id))
		AND (d.managed_client_generation IS NULL OR EXISTS (SELECT 1 FROM managed_oauth_clients mc WHERE mc.id=d.client_id AND mc.generation=d.managed_client_generation AND mc.enabled=1 AND mc.deleted=0)))` + accountGuard,
		append([]any{tx.deviceCodeDigest, tx.deviceClaimDigest, accountExpiryCutoff{}, accountExpiryCutoff{}, accountExpiryCutoff{}}, accountArgs...)
}

func deviceCodeDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Store) mutate(ctx context.Context, requestID string, statements ...rhiza.SQLStatement) error {
	if tx := txFrom(ctx); tx != nil {
		if tx.done {
			return fmt.Errorf("OAuth storage transaction is closed")
		}
		tx.statements = append(tx.statements, statements...)
		return nil
	}
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	return err
}

// principalGuard fences code/refresh, device, and exchange issuance. It ties the
// resolver's linearizable snapshot to the same Rhiza Execute that consumes a
// grant and creates its token artifacts.
func (tx *transaction) principalGuard() (string, []any) {
	if tx == nil {
		return "", nil
	}
	guard, args := tx.accountExpiryGuard()
	if tx.kind == "password" {
		guard += ` AND EXISTS (SELECT 1 FROM identity_users u JOIN identity_authentication_modes m ON m.subject=u.subject WHERE u.subject=? AND u.password_generation=? AND m.mode='password' AND m.generation=? AND u.disabled=0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?))`
		args = append(args, tx.principalSubject, tx.passwordGeneration, tx.authenticationGeneration, accountExpiryCutoff{})
	}
	dpopGuard, dpopArgs := tx.dpopPolicy.guard()
	guard += dpopGuard
	args = append(args, dpopArgs...)
	if tx.principalSubject == "" {
		if !tx.clientPolicySet && !tx.customCatalogSet {
			return guard, args
		}
	} else {
		now := tx.issueNowMillis()
		guard += ` AND EXISTS (SELECT 1 FROM identity_users WHERE subject=? AND disabled=0
			AND (user_expires_at_unix_ms IS NULL OR user_expires_at_unix_ms > ?))`
		args = append(args, tx.principalSubject, now)
		if tx.principalRevision >= 1 {
			guard += ` AND COALESCE((SELECT revision FROM rbac_principal_versions WHERE subject=?), 1)=?`
			args = append(args, tx.principalSubject, tx.principalRevision)
		}
	}
	if !tx.clientPolicySet {
		if !tx.customCatalogSet {
			return guard, args
		}
		return guard + ` AND EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?)`, append(args, tx.customCatalogRevision)
	}
	if tx.clientPolicyClientID == "" || tx.clientPolicyRevision < 0 {
		return ` AND 0`, nil
	}
	if tx.clientPolicyRevision == 0 {
		guard, args = guard+` AND NOT EXISTS (SELECT 1 FROM bootstrap_client_login_restrictions WHERE client_id=?)`, append(args, tx.clientPolicyClientID)
		if tx.customCatalogSet {
			guard, args = guard+` AND EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?)`, append(args, tx.customCatalogRevision)
		}
		return guard, args
	}
	if tx.clientPolicyPrefix == "" {
		guard, args = guard+` AND EXISTS (SELECT 1 FROM bootstrap_client_login_restrictions
			WHERE client_id=? AND restrict_group_prefix IS NULL AND revision=?)`, append(args, tx.clientPolicyClientID, tx.clientPolicyRevision)
	} else {
		guard, args = guard+` AND EXISTS (SELECT 1 FROM bootstrap_client_login_restrictions
			WHERE client_id=? AND restrict_group_prefix=? AND revision=?)`, append(args, tx.clientPolicyClientID, tx.clientPolicyPrefix, tx.clientPolicyRevision)
	}
	if tx.customCatalogSet {
		guard, args = guard+` AND EXISTS (SELECT 1 FROM claims_catalog WHERE id=1 AND revision=?)`, append(args, tx.customCatalogRevision)
	}
	return guard, args
}

func encodeRequest(request fosite.Requester) (string, error) {
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok {
		return "", fmt.Errorf("unsupported OAuth session type %T", request.GetSession())
	}
	record := requestRecord{
		ID: request.GetID(), ClientID: request.GetClient().GetID(), RequestedAt: request.GetRequestedAt().UnixMilli(),
		RequestedScopes: append([]string(nil), request.GetRequestedScopes()...), GrantedScopes: append([]string(nil), request.GetGrantedScopes()...),
		RequestedAudience: append([]string(nil), request.GetRequestedAudience()...), GrantedAudience: append([]string(nil), request.GetGrantedAudience()...),
		Form: persistedRequestForm(request.GetRequestForm()), ExpiresAt: map[fosite.TokenType]int64{}, Username: session.Username, Subject: session.Subject, Extra: session.Extra,
	}
	if client, ok := request.GetClient().(*ephemeralClient); ok {
		snapshot := client.metadata.clone()
		record.EphemeralClient = &snapshot
	}
	if client, ok := request.GetClient().(*clients.Client); ok {
		record.ManagedClient = &managedClientRecord{ID: client.ID, Revision: client.Revision, Generation: client.Generation, Enabled: client.Enabled, Confidential: client.Confidential, RedirectURIs: append([]string(nil), client.RedirectURIs...), Scopes: append([]string(nil), client.Scopes...), DefaultScopes: append([]string(nil), client.DefaultScopes...), GrantTypes: append([]string(nil), client.GrantTypes...)}
	}
	for _, tokenType := range []fosite.TokenType{fosite.AuthorizeCode, fosite.AccessToken, fosite.RefreshToken} {
		if expiry := session.GetExpiresAt(tokenType); !expiry.IsZero() {
			record.ExpiresAt[tokenType] = expiry.UnixMilli()
		}
	}
	encoded, err := json.Marshal(record)
	return string(encoded), err
}

func managedClientGuard(request fosite.Requester) (string, []any) {
	client, ok := request.GetClient().(*clients.Client)
	if !ok || client.ID == "" || client.Generation == "" || client.Revision < 0 {
		return "", nil
	}
	return ` AND EXISTS (SELECT 1 FROM managed_oauth_clients WHERE id=? AND generation=? AND revision=? AND enabled=1 AND deleted=0)`, []any{client.ID, client.Generation, client.Revision}
}

func (tx *transaction) managedGuard() (string, []any) {
	if tx == nil || !tx.managedClientSet || tx.managedClientID == "" || tx.managedClientGeneration == "" || tx.managedClientRevision < 0 {
		return "", nil
	}
	return ` AND EXISTS (SELECT 1 FROM managed_oauth_clients WHERE id=? AND generation=? AND revision=? AND enabled=1 AND deleted=0)`, []any{tx.managedClientID, tx.managedClientGeneration, tx.managedClientRevision}
}

// exchangeInputClientGuard repeats the input-client validity check in the
// target-token mutation. Validation has already decoded the request, but a
// managed client can be disabled/reincarnated or a dynamic registration can be
// deleted before that mutation commits. CIMD records carry an immutable
// ephemeral_client snapshot, and the configured bootstrap client has no row to
// revalidate, so both retain their established lifetime semantics.
func (s *Store) exchangeInputClientGuard(signature string) (string, []any) {
	bootstrapID := ""
	if s.client != nil {
		bootstrapID = s.client.GetID()
	}
	return ` AND (
		EXISTS (SELECT 1 FROM oauth_token_requests input
			JOIN managed_oauth_clients client ON client.id=json_extract(input.request_json, '$.managed_client.id')
			WHERE input.signature=?
				AND client.generation=json_extract(input.request_json, '$.managed_client.generation')
				AND client.enabled=1 AND client.deleted=0)
		OR EXISTS (SELECT 1 FROM oauth_token_requests input
			WHERE input.signature=?
				AND json_extract(input.request_json, '$.managed_client.id') IS NULL
				AND json_extract(input.request_json, '$.ephemeral_client.id') IS NOT NULL)
		OR EXISTS (SELECT 1 FROM oauth_token_requests input
			WHERE input.signature=?
				AND json_extract(input.request_json, '$.managed_client.id') IS NULL
				AND json_extract(input.request_json, '$.ephemeral_client.id') IS NULL
				AND json_extract(input.request_json, '$.client_id')=?)
		OR EXISTS (SELECT 1 FROM oauth_token_requests input
			JOIN dynamic_oauth_clients client ON client.client_id=json_extract(input.request_json, '$.client_id')
			WHERE input.signature=?
				AND json_extract(input.request_json, '$.managed_client.id') IS NULL
				AND json_extract(input.request_json, '$.ephemeral_client.id') IS NULL)
	)`, []any{signature, signature, signature, bootstrapID, signature}
}

func (s *Store) captureManagedSnapshot(ctx context.Context, table, signature string, tx *transaction) error {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT request_json FROM ` + table + ` WHERE signature=?`, Args: []any{signature}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return err
	}
	var record requestRecord
	encoded, ok := result.Rows[0][0].(string)
	if !ok || json.Unmarshal([]byte(encoded), &record) != nil || record.ManagedClient == nil {
		return nil
	}
	client, err := s.GetClient(ctx, record.ManagedClient.ID)
	if err != nil {
		return err
	}
	current, ok := client.(*clients.Client)
	if !ok || current.Generation != record.ManagedClient.Generation {
		return fosite.ErrInvalidGrant
	}
	tx.managedClientSet = true
	tx.managedClientID, tx.managedClientRevision, tx.managedClientGeneration = current.ID, current.Revision, current.Generation
	return nil
}

func (s *Store) decodeRequest(ctx context.Context, encoded string, target fosite.Session) (fosite.Requester, error) {
	var record requestRecord
	if err := json.Unmarshal([]byte(encoded), &record); err != nil || record.ID == "" || record.ClientID == "" {
		return nil, fmt.Errorf("invalid stored OAuth request")
	}
	if target == nil {
		target = &fosite.DefaultSession{}
	}
	session, ok := target.(*fosite.DefaultSession)
	if !ok {
		return nil, fmt.Errorf("unsupported OAuth session type %T", target)
	}
	// Fosite loads an authorization-code session once while parsing the token
	// request and again while producing the response. The verified DPoP cnf
	// is attached between those operations; preserve only that exact value so
	// the second load cannot drop the sender constraint. No other transient
	// destination Extra data is trusted or retained.
	preservedDPoPJKT := sessionDPoPJKT(session)
	if session.ExpiresAt == nil {
		session.ExpiresAt = make(map[fosite.TokenType]time.Time, len(record.ExpiresAt))
	}
	for tokenType, expiry := range record.ExpiresAt {
		session.ExpiresAt[tokenType] = time.UnixMilli(expiry).UTC()
	}
	session.Username, session.Subject, session.Extra = record.Username, record.Subject, record.Extra
	if validDPoPJKT(preservedDPoPJKT) {
		if session.Extra == nil {
			session.Extra = make(map[string]any)
		}
		session.Extra[dpopCNFExtra] = map[string]string{dpopJKTClaim: preservedDPoPJKT}
	}
	var (
		client fosite.Client
		err    error
	)
	if record.ManagedClient != nil {
		managed := record.ManagedClient
		if managed.ID != record.ClientID || !managed.Enabled || s.managedClients == nil {
			return nil, fosite.ErrNotFound
		}
		current, currentErr := s.GetClient(ctx, managed.ID)
		if currentErr != nil {
			return nil, currentErr
		}
		currentManaged, managedOK := current.(*clients.Client)
		if !managedOK || !currentManaged.Enabled || currentManaged.Generation != managed.Generation {
			return nil, fosite.ErrNotFound
		}
		// Keep the persisted incarnation binding, but authenticate against the
		// current client snapshot so cosmetic metadata/secret rotations do not
		// strand existing grants. A generation change (disable/re-enable or
		// replacement) rejects the old grant above.
		client = currentManaged
	} else if record.EphemeralClient != nil {
		if record.EphemeralClient.ID != record.ClientID {
			return nil, fmt.Errorf("invalid ephemeral client snapshot")
		}
		client, err = newEphemeralClientRecord(record.EphemeralClient.clone())
	} else {
		client, err = s.GetClient(ctx, record.ClientID)
	}
	if err != nil {
		return nil, err
	}
	request := fosite.NewRequest()
	request.ID, request.Client, request.RequestedAt, request.Form, request.Session = record.ID, client, time.UnixMilli(record.RequestedAt).UTC(), record.Form, session
	request.SetRequestedScopes(record.RequestedScopes)
	for _, scope := range record.GrantedScopes {
		request.GrantScope(scope)
	}
	request.SetRequestedAudience(record.RequestedAudience)
	for _, audience := range record.GrantedAudience {
		request.GrantAudience(audience)
	}
	return request, nil
}

func validDPoPJKT(value string) bool {
	if len(value) != 43 {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func (s *Store) CreateAuthorizeCodeSession(ctx context.Context, signature string, request fosite.Requester) error {
	tx, err := configureTX(ctx, "issue", signature)
	if err != nil {
		return err
	}
	if err := capAuthorizeCodeSession(ctx, request.GetSession(), s.now().UTC()); err != nil {
		return err
	}
	encoded, err := encodeRequest(request)
	if err != nil {
		return err
	}
	if err := tx.guardOIDCIssue(request); err != nil {
		return err
	}
	managedGuard, managedArgs := managedClientGuard(request)
	if managedGuard != "" {
		tx.managedClientSet = true
		tx.managedClientID = request.GetClient().GetID()
		managed := request.GetClient().(*clients.Client)
		tx.managedClientRevision, tx.managedClientGeneration = managed.Revision, managed.Generation
	}
	now := tx.issueNowMillis()
	codeSQL, codeArgs := `INSERT INTO oauth_authorize_codes (signature, request_json, expires_at_unix_ms) VALUES (?, ?, ?)`, []any{signature, encoded, request.GetSession().GetExpiresAt(fosite.AuthorizeCode).UnixMilli()}
	guard, guardArgs := tx.principalGuard()
	if tx.oidcSID != "" || guard != "" {
		codeSQL = `INSERT INTO oauth_authorize_codes (signature, request_json, expires_at_unix_ms)
			SELECT ?, ?, ? WHERE 1=1`
		if tx.oidcSID != "" {
			codeSQL += ` AND EXISTS (SELECT 1 FROM browser_sessions
				WHERE token_digest = ? AND subject = ? AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms > ? AND last_seen_at_unix_ms > ?)`
			codeArgs = append(codeArgs, tx.oidcSID, request.GetSession().GetSubject(), now, now-s.browserSessionIdleTimeout.Milliseconds())
		}
		codeSQL += guard
		codeArgs = append(codeArgs, guardArgs...)
	}
	if managedGuard != "" && !strings.Contains(codeSQL, " WHERE ") {
		codeSQL = `INSERT INTO oauth_authorize_codes (signature, request_json, expires_at_unix_ms) SELECT ?, ?, ? WHERE 1=1`
	}
	codeSQL += managedGuard
	codeArgs = append(codeArgs, managedArgs...)
	tx.statements = append(tx.statements,
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_pkce_requests WHERE expires_at_unix_ms <= ?`, Args: []any{now}},
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_authorize_codes WHERE expires_at_unix_ms <= ?`, Args: []any{now}},
		rhiza.SQLStatement{SQL: codeSQL, Args: codeArgs},
	)
	return nil
}

func (s *Store) GetAuthorizeCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:  `SELECT request_json, invalidated FROM oauth_authorize_codes WHERE signature = ?`,
		Args: []any{signature}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return nil, fosite.ErrNotFound
	}
	encoded, ok0 := result.Rows[0][0].(string)
	invalidated, ok1 := result.Rows[0][1].(int64)
	if !ok0 || !ok1 {
		return nil, fmt.Errorf("invalid authorization code row")
	}
	request, err := s.decodeRequest(ctx, encoded, session)
	if err != nil {
		return nil, err
	}
	if invalidated != 0 {
		return request, fosite.ErrInvalidatedAuthorizeCode
	}
	if err := capAccountSession(ctx, request.GetSession(), s.now().UTC()); err != nil {
		return nil, err
	}
	if snapshot, ok := ctx.Value(principalSnapshotContextKey{}).(principalSnapshot); ok && snapshot.signature == signature {
		if err := setPrincipalClaims(request, snapshot.claims); err != nil {
			return nil, err
		}
		if err := setCustomAccessClaims(request, snapshot.custom.access); err != nil {
			return nil, err
		}
	}
	return request, nil
}

func (s *Store) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	tx, err := configureTX(ctx, "code", signature)
	if err != nil {
		return err
	}
	if err := s.captureManagedSnapshot(ctx, "oauth_authorize_codes", signature, tx); err != nil {
		return err
	}
	guard, guardArgs := tx.principalGuard()
	managedGuard, managedArgs := tx.managedGuard()
	guard += managedGuard
	guardArgs = append(guardArgs, managedArgs...)
	args := append([]any{tx.attempt, signature}, guardArgs...)
	tx.statements = append(tx.statements,
		rhiza.SQLStatement{SQL: `UPDATE oauth_authorize_codes SET invalidated = 1, used_attempt = ? WHERE signature = ? AND invalidated = 0` + guard, Args: args},
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_pkce_requests WHERE signature = ? AND EXISTS (
			SELECT 1 FROM oauth_authorize_codes WHERE signature = ? AND used_attempt = ?)` + guard, Args: append([]any{signature, signature, tx.attempt}, guardArgs...)},
	)
	return nil
}

func (s *Store) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	tx, err := configureTX(ctx, "issue", signature)
	if err != nil {
		return err
	}
	if err := capAuthorizeCodeSession(ctx, request.GetSession(), s.now().UTC()); err != nil {
		return err
	}
	encoded, err := encodeRequest(request)
	if err != nil {
		return err
	}
	if err := tx.guardOIDCIssue(request); err != nil {
		return err
	}
	managedGuard, managedArgs := managedClientGuard(request)
	if managedGuard != "" {
		tx.managedClientSet = true
		tx.managedClientID = request.GetClient().GetID()
		managed := request.GetClient().(*clients.Client)
		tx.managedClientRevision, tx.managedClientGeneration = managed.Revision, managed.Generation
	}
	now := tx.issueNowMillis()
	sql, args := `INSERT INTO oauth_pkce_requests (signature, request_json, expires_at_unix_ms) VALUES (?, ?, ?)`, []any{signature, encoded, request.GetSession().GetExpiresAt(fosite.AuthorizeCode).UnixMilli()}
	guard, guardArgs := tx.principalGuard()
	if tx.oidcSID != "" || guard != "" {
		sql = `INSERT INTO oauth_pkce_requests (signature, request_json, expires_at_unix_ms)
			SELECT ?, ?, ? WHERE 1=1`
		if tx.oidcSID != "" {
			sql += ` AND EXISTS (SELECT 1 FROM browser_sessions
				WHERE token_digest = ? AND subject = ? AND revoked_at_unix_ms IS NULL AND expires_at_unix_ms > ? AND last_seen_at_unix_ms > ?)`
			args = append(args, tx.oidcSID, request.GetSession().GetSubject(), now, now-s.browserSessionIdleTimeout.Milliseconds())
		}
		sql += guard
		args = append(args, guardArgs...)
	}
	if managedGuard != "" && !strings.Contains(sql, " WHERE ") {
		sql = `INSERT INTO oauth_pkce_requests (signature, request_json, expires_at_unix_ms) SELECT ?, ?, ? WHERE 1=1`
	}
	sql += managedGuard
	args = append(args, managedArgs...)
	tx.statements = append(tx.statements, rhiza.SQLStatement{SQL: sql, Args: args})
	return nil
}

func (tx *transaction) issueNowMillis() int64 {
	if tx.issueNow == 0 {
		tx.issueNow = time.Now().UTC().UnixMilli()
	}
	return tx.issueNow
}

// guardOIDCIssue makes a supplied browser session part of the same replicated
// write as authorization-code persistence. OIDC adds nonce/authentication
// claims separately, but the session binding also applies to plain OAuth.
func (tx *transaction) guardOIDCIssue(request fosite.Requester) error {
	session, ok := request.GetSession().(*fosite.DefaultSession)
	if !ok || session.Extra == nil {
		if request.GetGrantedScopes().Has(openidScope) {
			return errors.New("OIDC browser session is missing")
		}
		return nil
	}
	raw, exists := session.Extra[oidcSessionIDExtra]
	if !exists {
		if request.GetGrantedScopes().Has(openidScope) {
			return errors.New("OIDC browser session is missing")
		}
		return nil
	}
	sid, validType := raw.(string)
	if !validType || !validOIDCSessionID(sid) {
		return errors.New("OIDC browser session ID is invalid")
	}
	if tx.oidcSID != "" && tx.oidcSID != sid {
		return errors.New("mixed OIDC session in OAuth storage transaction")
	}
	tx.oidcSID = sid
	return nil
}

func (s *Store) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT request_json FROM oauth_pkce_requests WHERE signature = ?`, Args: []any{signature}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return nil, fosite.ErrNotFound
	}
	encoded, ok := result.Rows[0][0].(string)
	if !ok {
		return nil, fmt.Errorf("invalid PKCE request row")
	}
	return s.decodeRequest(ctx, encoded, session)
}

// DeletePKCERequestSession intentionally defers deletion until the guarded
// authorization-code transaction. Fosite calls this before validation and
// before opening its token transaction; deleting here would make retry after a
// wrong verifier impossible and split single-use state across two mutations.
func (*Store) DeletePKCERequestSession(context.Context, string) error { return nil }

func (s *Store) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	if tx := txFrom(ctx); tx != nil && tx.kind == "password" && (request.GetSession() == nil || request.GetSession().GetSubject() != tx.principalSubject) {
		return fosite.ErrInvalidGrant
	}
	encoded, err := encodeRequest(request)
	if err != nil {
		return err
	}
	requestedScopes, _ := json.Marshal(request.GetRequestedScopes())
	grantedScopes, _ := json.Marshal(request.GetGrantedScopes())
	requestedAudience, _ := json.Marshal(request.GetRequestedAudience())
	// The access-token index is used by resource mutation guards; the request
	// JSON separately retains explicit grants for Fosite refresh validation.
	audiences, err := accessResourceAudiences(request)
	if err != nil {
		return err
	}
	grantedAudience, _ := json.Marshal(audiences)
	args := []any{signature, request.GetID(), request.GetClient().GetID(), request.GetRequestedAt().UnixMilli(),
		request.GetSession().GetExpiresAt(fosite.AccessToken).UnixMilli(), string(requestedScopes), string(grantedScopes),
		string(requestedAudience), string(grantedAudience)}
	insertSQL := `INSERT INTO oauth_access_tokens
		(signature, request_id, client_id, requested_at_unix_ms, expires_at_unix_ms,
		 requested_scopes, granted_scopes, requested_audience, granted_audience)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	requestSQL := `INSERT INTO oauth_token_requests (signature, request_json) VALUES (?, ?)`
	tx := txFrom(ctx)
	var sourceInputGuardArgs, actorInputGuardArgs []any
	clientCredentialsGuarded := false
	if tx != nil && (tx.kind == "code" || tx.kind == "refresh") {
		column, table := "used_attempt", "oauth_authorize_codes"
		if tx.kind == "refresh" {
			column, table = "rotated_attempt", "oauth_refresh_tokens"
		}
		guard, guardArgs := tx.principalGuard()
		condition := ` WHERE EXISTS (SELECT 1 FROM ` + table + ` WHERE signature = ? AND ` + column + ` = ?)` + guard
		args = append(args, tx.key, tx.attempt)
		args = append(args, guardArgs...)
		insertSQL = `INSERT INTO oauth_access_tokens
			(signature, request_id, client_id, requested_at_unix_ms, expires_at_unix_ms,
			 requested_scopes, granted_scopes, requested_audience, granted_audience)
			SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?` + condition
		requestSQL = `INSERT INTO oauth_token_requests (signature, request_json) SELECT ?, ?` + condition
	} else if tx := txFrom(ctx); tx != nil && tx.kind == "device" {
		guard, guardArgs := tx.deviceGuard()
		condition := ` WHERE ` + guard
		insertSQL = `INSERT INTO oauth_access_tokens
			(signature, request_id, client_id, requested_at_unix_ms, expires_at_unix_ms,
			 requested_scopes, granted_scopes, requested_audience, granted_audience)
			SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?` + condition
		args = append(args, guardArgs...)
		requestSQL = `INSERT INTO oauth_token_requests (signature, request_json) SELECT ?, ?` + condition
	} else if tx != nil && tx.kind == "password" {
		if signature == "" || tx.targetAccessSignature != "" {
			return errors.New("invalid password target signature")
		}
		tx.targetAccessSignature = signature
		tx.requestID = "oauth-password/" + signature
		guard, guardArgs := tx.principalGuard()
		condition := ` WHERE 1=1` + guard
		insertSQL = strings.Replace(insertSQL, `VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, `SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?`+condition, 1)
		requestSQL = `INSERT INTO oauth_token_requests (signature, request_json) SELECT ?, ?` + condition
		args = append(args, guardArgs...)
	} else if tx := txFrom(ctx); tx != nil && tx.kind == "exchange" {
		if signature == "" || (tx.targetAccessSignature != "" && tx.targetAccessSignature != signature) {
			return errors.New("invalid token-exchange target signature")
		}
		tx.targetAccessSignature = signature
		tx.requestID = tokenExchangeRequestID(signature)
		condition := ` WHERE EXISTS (SELECT 1 FROM oauth_access_tokens
			WHERE signature = ? AND expires_at_unix_ms = ? AND expires_at_unix_ms > ?)
			AND EXISTS (SELECT 1 FROM oauth_token_requests WHERE signature = ?)`
		insertSQL = `INSERT INTO oauth_access_tokens
			(signature, request_id, client_id, requested_at_unix_ms, expires_at_unix_ms,
			 requested_scopes, granted_scopes, requested_audience, granted_audience)
			SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?` + condition
		// Commit rebinds this placeholder to its own UTC millisecond so a
		// source token expiring while the transaction is queued cannot mint a
		// target token.
		args = append(args, tx.sourceAccessSignature, tx.sourceAccessExpiresAt, int64(0), tx.sourceAccessSignature)
		tx.exchangeAccessCutoffArgument = len(args) - 2
		sourceInputGuard, sourceInputArgs := s.exchangeInputClientGuard(tx.sourceAccessSignature)
		condition += sourceInputGuard
		args = append(args, sourceInputArgs...)
		sourceInputGuardArgs = sourceInputArgs
		if tx.actorAccessSignature != "" {
			condition += ` AND EXISTS (SELECT 1 FROM oauth_access_tokens
				WHERE signature = ? AND expires_at_unix_ms = ? AND expires_at_unix_ms > ?)
				AND EXISTS (SELECT 1 FROM oauth_token_requests WHERE signature = ?)`
			args = append(args, tx.actorAccessSignature, tx.actorAccessExpiresAt, int64(0), tx.actorAccessSignature)
			tx.exchangeActorAccessCutoffArgument = len(args) - 2
			actorInputGuard, actorInputArgs := s.exchangeInputClientGuard(tx.actorAccessSignature)
			condition += actorInputGuard
			args = append(args, actorInputArgs...)
			actorInputGuardArgs = actorInputArgs
		}
		principalGuard, principalArgs := tx.principalGuard()
		condition += principalGuard
		args = append(args, principalArgs...)
		insertSQL = `INSERT INTO oauth_access_tokens
			(signature, request_id, client_id, requested_at_unix_ms, expires_at_unix_ms,
			 requested_scopes, granted_scopes, requested_audience, granted_audience)
			SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?` + condition
		requestSQL = `INSERT INTO oauth_token_requests (signature, request_json) SELECT ?, ?` + condition
	}
	requestArgs := []any{signature, encoded}
	// Client credentials uses no grant-row transaction. Its policy revision is
	// therefore made a predicate of both durable token writes in one Execute.
	if tx == nil {
		if guard, guardArgs := clientCredentialsClaimsGuard(ctx); guard != "" {
			insertSQL = `INSERT INTO oauth_access_tokens
				(signature, request_id, client_id, requested_at_unix_ms, expires_at_unix_ms,
				 requested_scopes, granted_scopes, requested_audience, granted_audience)
				SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE 1=1` + guard
			requestSQL = `INSERT INTO oauth_token_requests (signature, request_json) SELECT ?, ? WHERE 1=1` + guard
			args = append(args, guardArgs...)
			clientCredentialsGuarded = true
			// requestSQL is assembled below, where the same guard arguments are
			// appended after its two value parameters.
		}
	}
	policy, _ := ctx.Value(dpopPolicyContextKey{}).(dpopPolicySnapshot)
	dpopGuard, dpopArgs := policy.guard()
	if tx != nil && tx.kind != "exchange" {
		dpopGuard, dpopArgs = "", nil // Already included through principalGuard/deviceGuard.
	}
	if dpopGuard != "" && !strings.Contains(insertSQL, " WHERE ") {
		insertSQL = strings.Replace(insertSQL, "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", "SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE 1=1", 1)
	}
	insertSQL += dpopGuard
	args = append(args, dpopArgs...)
	if tx == nil && dpopGuard != "" {
		clientCredentialsGuarded = true
	}
	if dpopGuard != "" && !strings.Contains(requestSQL, " WHERE ") {
		requestSQL = strings.Replace(requestSQL, " VALUES (?, ?)", " SELECT ?, ? WHERE 1=1", 1)
	}
	requestSQL += dpopGuard
	managedGuard, managedArgs := managedClientGuard(request)
	if managedGuard != "" {
		if !strings.Contains(insertSQL, " WHERE ") {
			insertSQL = strings.Replace(insertSQL, "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", "SELECT ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE 1=1", 1)
		}
		insertSQL += managedGuard
		args = append(args, managedArgs...)
		if tx == nil && request.GetRequestForm().Get("grant_type") == "client_credentials" {
			clientCredentialsGuarded = true
		}
	}
	cleanupAccessSQL := `DELETE FROM oauth_access_tokens WHERE expires_at_unix_ms <= ?`
	cleanupRequestSQL := `DELETE FROM oauth_token_requests WHERE NOT EXISTS (
		SELECT 1 FROM oauth_access_tokens WHERE oauth_access_tokens.signature = oauth_token_requests.signature)`
	cleanupAccessArgs := []any{time.Now().UTC().UnixMilli()}
	cleanupRequestArgs := []any(nil)
	if tx != nil && (tx.kind == "code" || tx.kind == "refresh") {
		guard, guardArgs := tx.principalGuard()
		cleanupAccessSQL += guard
		cleanupRequestSQL += guard
		cleanupAccessArgs = append(cleanupAccessArgs, guardArgs...)
		cleanupRequestArgs = append(cleanupRequestArgs, guardArgs...)
	}
	statements := []rhiza.SQLStatement{
		{SQL: cleanupAccessSQL, Args: cleanupAccessArgs},
		{SQL: cleanupRequestSQL, Args: cleanupRequestArgs},
		{SQL: insertSQL, Args: args},
	}
	if tx == nil {
		if guard, guardArgs := clientCredentialsClaimsGuard(ctx); guard != "" {
			requestArgs = append(requestArgs, guardArgs...)
		}
	}
	if tx != nil && (tx.kind == "code" || tx.kind == "refresh") {
		requestArgs = append(requestArgs, tx.key, tx.attempt)
		_, guardArgs := tx.principalGuard()
		requestArgs = append(requestArgs, guardArgs...)
	} else if tx := txFrom(ctx); tx != nil && tx.kind == "device" {
		_, guardArgs := tx.deviceGuard()
		requestArgs = append(requestArgs, guardArgs...)
	} else if tx != nil && tx.kind == "password" {
		_, guardArgs := tx.principalGuard()
		requestArgs = append(requestArgs, guardArgs...)
	} else if tx := txFrom(ctx); tx != nil && tx.kind == "exchange" {
		requestArgs = append(requestArgs, tx.sourceAccessSignature, tx.sourceAccessExpiresAt, int64(0), tx.sourceAccessSignature)
		tx.exchangeRequestCutoffArgument = len(requestArgs) - 2
		requestArgs = append(requestArgs, sourceInputGuardArgs...)
		if tx.actorAccessSignature != "" {
			requestArgs = append(requestArgs, tx.actorAccessSignature, tx.actorAccessExpiresAt, int64(0), tx.actorAccessSignature)
			tx.exchangeActorRequestCutoffArgument = len(requestArgs) - 2
			requestArgs = append(requestArgs, actorInputGuardArgs...)
		}
		_, principalArgs := tx.principalGuard()
		requestArgs = append(requestArgs, principalArgs...)
	}
	requestArgs = append(requestArgs, dpopArgs...)
	if managedGuard != "" {
		if !strings.Contains(requestSQL, " WHERE ") {
			requestSQL = strings.Replace(requestSQL, " VALUES (?, ?)", " SELECT ?, ? WHERE 1=1", 1)
		}
		requestSQL += managedGuard
		requestArgs = append(requestArgs, managedArgs...)
	}
	statements = append(statements, rhiza.SQLStatement{SQL: requestSQL, Args: requestArgs})
	if (tx == nil && request.GetRequestForm().Get("grant_type") == "client_credentials") || (tx != nil && (tx.kind == "code" || tx.kind == "password")) {
		lastUsedAt := s.now().UTC().UnixMilli()
		lastUsedSQL := `UPDATE dynamic_oauth_clients
			SET last_used_at_unix_ms = CASE WHEN last_used_at_unix_ms IS NULL OR last_used_at_unix_ms < ? THEN ? ELSE last_used_at_unix_ms END
			WHERE client_id = ? AND EXISTS (
				SELECT 1 FROM oauth_access_tokens
				WHERE signature = ? AND request_id = ? AND client_id = dynamic_oauth_clients.client_id
			) AND EXISTS (
				SELECT 1 FROM oauth_token_requests WHERE signature = ?
			)`
		lastUsedArgs := []any{
			lastUsedAt, lastUsedAt, request.GetClient().GetID(), signature, request.GetID(), signature,
		}
		if tx != nil && tx.kind == "code" {
			guard, guardArgs := tx.principalGuard()
			lastUsedSQL += ` AND EXISTS (SELECT 1 FROM oauth_authorize_codes WHERE signature = ? AND used_attempt = ?)` + guard
			lastUsedArgs = append(lastUsedArgs, tx.key, tx.attempt)
			lastUsedArgs = append(lastUsedArgs, guardArgs...)
		}
		statements = append(statements, rhiza.SQLStatement{SQL: lastUsedSQL, Args: lastUsedArgs})
	}
	if tx := txFrom(ctx); tx != nil && tx.kind == "exchange" {
		if tx.exchangeAccessCutoffArgument < 0 || tx.exchangeRequestCutoffArgument < 0 || (tx.actorAccessSignature != "" && (tx.exchangeActorAccessCutoffArgument < 0 || tx.exchangeActorRequestCutoffArgument < 0)) {
			return errors.New("invalid token-exchange source guard")
		}
		start := len(tx.statements)
		tx.exchangeAccessCutoffStatement = start + 2
		tx.exchangeRequestCutoffStatement = start + 3
		if tx.actorAccessSignature != "" {
			tx.exchangeActorAccessCutoffStatement = start + 2
			tx.exchangeActorRequestCutoffStatement = start + 3
		}
	}
	logoutURI := ""
	if client, ok := request.GetClient().(interface{ GetBackchannelLogoutURI() string }); ok {
		logoutURI = client.GetBackchannelLogoutURI()
	} else if request.GetClient().GetID() == s.client.GetID() {
		logoutURI = s.backChannelLogoutURI
	}
	if tx != nil && (tx.kind == "password" || tx.kind == "code") {
		allowPrivate, allowHTTP := int64(0), int64(0)
		if s.backChannelAllowPrivate {
			allowPrivate = 1
		}
		if s.backChannelAllowHTTP {
			allowHTTP = 1
		}
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO oidc_user_clients
   (subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms)
   SELECT ?,?,COALESCE((SELECT COALESCE(backchannel_logout_uri,'') FROM dynamic_oauth_clients WHERE client_id=?),?),?,?,? WHERE EXISTS (
    SELECT 1 FROM oauth_access_tokens WHERE signature=? AND request_id=? AND client_id=?
   ) AND EXISTS (SELECT 1 FROM oauth_token_requests WHERE signature=?)
   ON CONFLICT(subject,client_id) DO UPDATE SET logout_uri=excluded.logout_uri,
    allow_private=excluded.allow_private,allow_http=excluded.allow_http`, Args: []any{
			request.GetSession().GetSubject(), request.GetClient().GetID(), request.GetClient().GetID(), logoutURI, allowPrivate, allowHTTP,
			s.now().UTC().UnixMilli(), signature, request.GetID(), request.GetClient().GetID(), signature,
		}})
	}
	browserSessionBound := false
	if session, ok := request.GetSession().(*fosite.DefaultSession); ok {
		_, browserSessionBound = session.Extra[oidcSessionIDExtra]
	}
	if tx := txFrom(ctx); tx != nil && tx.kind == "code" && (request.GetGrantedScopes().Has(openidScope) || browserSessionBound) {
		session, ok := request.GetSession().(*fosite.DefaultSession)
		if !ok || session.Extra == nil || session.Subject == "" {
			return errors.New("OIDC browser session is missing")
		}
		sid, _ := session.Extra[oidcSessionIDExtra].(string)
		if !validOIDCSessionID(sid) {
			return errors.New("OIDC browser session ID is invalid")
		}
		allowPrivate, allowHTTP := int64(0), int64(0)
		if s.backChannelAllowPrivate {
			allowPrivate = 1
		}
		if s.backChannelAllowHTTP {
			allowHTTP = 1
		}
		statements = append(statements, rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO oidc_session_clients
			(sid, client_id, logout_uri, allow_private, allow_http, created_at_unix_ms)
			SELECT ?, ?, COALESCE((SELECT COALESCE(backchannel_logout_uri,'') FROM dynamic_oauth_clients WHERE client_id=?),?), ?, ?, ? WHERE EXISTS (
				SELECT 1 FROM oauth_authorize_codes WHERE signature = ? AND used_attempt = ?)`, Args: []any{
			sid, request.GetClient().GetID(), request.GetClient().GetID(), logoutURI, allowPrivate, allowHTTP, time.Now().UTC().UnixMilli(), tx.key, tx.attempt,
		}})

	}
	if clientCredentialsGuarded {
		response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "oauth-access-create/" + signature, Statements: statements})
		if err != nil {
			return err
		}
		if response.RowsAffected < 2 {
			return fosite.ErrSerializationFailure
		}
		return nil
	}
	return s.mutate(ctx, "oauth-access-create/"+signature, statements...)
}

func tokenExchangeRequestID(targetSignature string) string {
	sum := sha256.Sum256([]byte(targetSignature))
	return "oauth-token-exchange/" + base64.RawURLEncoding.EncodeToString(sum[:])[:32]
}

func (tx *transaction) bindExchangeCutoff(cutoff int64) bool {
	locations := [][2]int{
		{tx.exchangeAccessCutoffStatement, tx.exchangeAccessCutoffArgument},
		{tx.exchangeRequestCutoffStatement, tx.exchangeRequestCutoffArgument},
	}
	if tx.actorAccessSignature != "" {
		locations = append(locations,
			[2]int{tx.exchangeActorAccessCutoffStatement, tx.exchangeActorAccessCutoffArgument},
			[2]int{tx.exchangeActorRequestCutoffStatement, tx.exchangeActorRequestCutoffArgument},
		)
	}
	for _, location := range locations {
		statement, argument := location[0], location[1]
		if statement < 0 || statement >= len(tx.statements) || argument < 0 || argument >= len(tx.statements[statement].Args) {
			return false
		}
		tx.statements[statement].Args[argument] = cutoff
	}
	return true
}

func (s *Store) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	if signature == "" {
		return nil, fosite.ErrNotFound
	}
	if s.beforeAccessTokenLookup != nil {
		s.beforeAccessTokenLookup()
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT request_json FROM oauth_token_requests WHERE signature = ?`, Args: []any{signature}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 1 && len(result.Rows[0]) == 1 {
		if encoded, ok := result.Rows[0][0].(string); ok {
			return s.decodeRequest(ctx, encoded, session)
		}
	}
	return nil, fosite.ErrNotFound
}

func (s *Store) accessTokenExpiry(ctx context.Context, signature string) (time.Time, error) {
	if signature == "" {
		return time.Time{}, fosite.ErrNotFound
	}
	if s.beforeAccessTokenLookup != nil {
		s.beforeAccessTokenLookup()
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT expires_at_unix_ms FROM oauth_access_tokens WHERE signature = ?`, Args: []any{signature}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return time.Time{}, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		return time.Time{}, fosite.ErrNotFound
	}
	expires, ok := result.Rows[0][0].(int64)
	if !ok {
		return time.Time{}, errors.New("invalid access token expiry")
	}
	return time.UnixMilli(expires).UTC(), nil
}

func (s *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	if signature == "" {
		return nil
	}
	if s.beforeAccessTokenLookup != nil {
		s.beforeAccessTokenLookup()
	}
	return s.mutate(ctx, "oauth-access-delete/"+signature,
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_access_tokens WHERE signature = ?`, Args: []any{signature}},
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_token_requests WHERE signature = ?`, Args: []any{signature}},
	)
}

func (s *Store) CreateRefreshTokenSession(ctx context.Context, signature, accessSignature string, request fosite.Requester) error {
	if tx := txFrom(ctx); tx != nil && tx.kind == "password" && (request.GetSession() == nil || request.GetSession().GetSubject() != tx.principalSubject) {
		return fosite.ErrInvalidGrant
	}
	if tx := txFrom(ctx); tx != nil && tx.kind == "exchange" {
		return errors.New("token exchange does not issue refresh tokens")
	}
	encoded, err := encodeRequest(request)
	if err != nil {
		return err
	}
	args := []any{signature, accessSignature, request.GetID(), encoded, request.GetSession().GetExpiresAt(fosite.RefreshToken).UnixMilli()}
	sql := `INSERT INTO oauth_refresh_tokens
		(signature, access_signature, request_id, request_json, expires_at_unix_ms) VALUES (?, ?, ?, ?, ?)`
	tx := txFrom(ctx)
	if tx != nil && (tx.kind == "code" || tx.kind == "refresh") {
		column, table := "used_attempt", "oauth_authorize_codes"
		if tx.kind == "refresh" {
			column, table = "rotated_attempt", "oauth_refresh_tokens"
		}
		guard, guardArgs := tx.principalGuard()
		sql = `INSERT INTO oauth_refresh_tokens
			(signature, access_signature, request_id, request_json, expires_at_unix_ms)
			SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM ` + table + ` WHERE signature = ? AND ` + column + ` = ?)` + guard
		args = append(args, tx.key, tx.attempt)
		args = append(args, guardArgs...)
	} else if tx := txFrom(ctx); tx != nil && tx.kind == "device" {
		guard, guardArgs := tx.deviceGuard()
		sql = `INSERT INTO oauth_refresh_tokens
			(signature, access_signature, request_id, request_json, expires_at_unix_ms)
			SELECT ?, ?, ?, ?, ? WHERE ` + guard
		args = append(args, guardArgs...)
	}
	if tx != nil && tx.kind == "password" {
		if signature == "" || accessSignature != tx.targetAccessSignature || tx.targetRefreshSignature != "" {
			return errors.New("invalid password refresh signature")
		}
		tx.targetRefreshSignature = signature
		guard, guardArgs := tx.principalGuard()
		sql = strings.Replace(sql, `VALUES (?, ?, ?, ?, ?)`, `SELECT ?, ?, ?, ?, ? WHERE 1=1`+guard, 1)
		args = append(args, guardArgs...)
	}
	managedGuard, managedArgs := managedClientGuard(request)
	if managedGuard != "" {
		if strings.Contains(sql, " WHERE ") {
			sql += managedGuard
		} else {
			sql = strings.Replace(sql, "VALUES (?, ?, ?, ?, ?)", "SELECT ?, ?, ?, ?, ? WHERE 1=1", 1)
		}
		args = append(args, managedArgs...)
	}
	cleanupSQL := `DELETE FROM oauth_refresh_tokens WHERE expires_at_unix_ms <= ?`
	cleanupArgs := []any{time.Now().UTC().UnixMilli()}
	if tx != nil && (tx.kind == "code" || tx.kind == "refresh") {
		guard, guardArgs := tx.principalGuard()
		cleanupSQL += guard
		cleanupArgs = append(cleanupArgs, guardArgs...)
	}
	return s.mutate(ctx, "oauth-refresh-create/"+signature,
		rhiza.SQLStatement{SQL: cleanupSQL, Args: cleanupArgs},
		rhiza.SQLStatement{SQL: sql, Args: args},
	)
}

func (s *Store) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT request_json, active FROM oauth_refresh_tokens WHERE signature = ?`, Args: []any{signature}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return nil, fosite.ErrNotFound
	}
	encoded, ok0 := result.Rows[0][0].(string)
	active, ok1 := result.Rows[0][1].(int64)
	if !ok0 || !ok1 {
		return nil, fmt.Errorf("invalid refresh token row")
	}
	request, err := s.decodeRequest(ctx, encoded, session)
	if err != nil {
		return nil, err
	}
	if active == 0 {
		return request, fosite.ErrInactiveToken
	}
	if snapshot, ok := ctx.Value(principalSnapshotContextKey{}).(principalSnapshot); ok && snapshot.signature == signature {
		if err := setPrincipalClaims(request, snapshot.claims); err != nil {
			return nil, err
		}
		if err := setCustomAccessClaims(request, snapshot.custom.access); err != nil {
			return nil, err
		}
	}
	return request, nil
}

func (s *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	if tx := txFrom(ctx); tx != nil && tx.kind == "" {
		if _, err := configureTX(ctx, "reuse", signature); err != nil {
			return err
		}
	}
	return s.mutate(ctx, "oauth-refresh-delete/"+signature, rhiza.SQLStatement{SQL: `DELETE FROM oauth_refresh_tokens WHERE signature = ?`, Args: []any{signature}})
}

func (s *Store) RotateRefreshToken(ctx context.Context, requestID, signature string) error {
	tx, err := configureTX(ctx, "refresh", signature)
	if err != nil {
		return err
	}
	if err := s.captureManagedSnapshot(ctx, "oauth_refresh_tokens", signature, tx); err != nil {
		return err
	}
	guard := `EXISTS (SELECT 1 FROM oauth_refresh_tokens WHERE signature = ? AND rotated_attempt = ?)`
	principalGuard, principalArgs := tx.principalGuard()
	managedGuard, managedArgs := tx.managedGuard()
	principalGuard += managedGuard
	principalArgs = append(principalArgs, managedArgs...)
	rotateArgs := append([]any{tx.attempt, signature, requestID}, principalArgs...)
	guardArgs := append([]any{requestID, signature, tx.attempt}, principalArgs...)
	tx.statements = append(tx.statements,
		rhiza.SQLStatement{SQL: `UPDATE oauth_refresh_tokens SET active = 0, rotated_attempt = ?
			WHERE signature = ? AND request_id = ? AND active = 1` + principalGuard, Args: rotateArgs},
		rhiza.SQLStatement{SQL: `UPDATE oauth_refresh_tokens SET active = 0 WHERE request_id = ? AND ` + guard + principalGuard, Args: guardArgs},
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_access_tokens WHERE request_id = ? AND ` + guard + principalGuard, Args: guardArgs},
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_token_requests WHERE NOT EXISTS (
			SELECT 1 FROM oauth_access_tokens WHERE oauth_access_tokens.signature = oauth_token_requests.signature)` + principalGuard, Args: principalArgs},
	)
	return nil
}

func (s *Store) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return s.mutate(ctx, "oauth-revoke-refresh/"+requestID,
		rhiza.SQLStatement{SQL: `UPDATE oauth_refresh_tokens SET active = 0 WHERE request_id = ?`, Args: []any{requestID}},
	)
}

func (s *Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	return s.mutate(ctx, "oauth-revoke-access/"+requestID,
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_access_tokens WHERE request_id = ?`, Args: []any{requestID}},
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_token_requests WHERE NOT EXISTS (
			SELECT 1 FROM oauth_access_tokens WHERE oauth_access_tokens.signature = oauth_token_requests.signature)`},
		rhiza.SQLStatement{SQL: `UPDATE oauth_refresh_tokens SET active = 0 WHERE request_id = ?`, Args: []any{requestID}},
	)
}

// RevokeOIDCSession invalidates every persisted OAuth artifact carrying sid.
// The one replicated transaction also invalidates pending authorization codes:
// otherwise a code issued immediately before logout could mint new tokens after
// the token rows had been removed.
func (s *Store) RevokeOIDCSession(ctx context.Context, sid string) error {
	if !validOIDCSessionID(sid) {
		return errors.New("invalid OIDC session ID")
	}
	requestID, err := oidcSessionRevocationRequestID(sid)
	if err != nil {
		return err
	}
	eventID, err := oidcBackchannelEventID()
	if err != nil {
		return err
	}
	statements, err := SessionRevocationStatements(sid, eventID, time.Now())
	if err != nil {
		return err
	}
	return s.mutate(ctx, requestID, statements...)
}

// SessionRevocationStatements is the shared local OAuth/browser revocation
// batch for RP logout and administrator deletion. The caller must authorize
// the operation and execute the whole batch in one Rhiza transaction.
// Device grants have no browser SID and are intentionally not user-wide revoked.
func SessionRevocationStatements(sid, eventID string, at time.Time) ([]rhiza.SQLStatement, error) {
	if !validOIDCSessionID(sid) || strings.TrimSpace(eventID) == "" || at.IsZero() || at.UnixMilli() < 0 {
		return nil, errors.New("invalid session revocation")
	}
	const sidJSONPath = "$.extra.goauthy_oidc_session_id"
	now := at.UTC().UnixMilli()
	return []rhiza.SQLStatement{
		rhiza.SQLStatement{SQL: `INSERT OR IGNORE INTO oidc_backchannel_deliveries
			(event_id, client_id, sid, logout_uri, allow_private, allow_http, attempts,
			 next_attempt_at_unix_ms, created_at_unix_ms)
			SELECT ?, client_id, sid, logout_uri, allow_private, allow_http, 0, ?, ?
			FROM oidc_session_clients
			WHERE sid = ? AND logout_uri <> '' AND EXISTS (
				SELECT 1 FROM browser_sessions WHERE token_digest = ? AND revoked_at_unix_ms IS NULL)`, Args: []any{eventID, now, now, sid, sid}},
		rhiza.SQLStatement{SQL: `UPDATE browser_sessions SET revoked_at_unix_ms = COALESCE(revoked_at_unix_ms, ?)
			WHERE token_digest = ?`, Args: []any{now, sid}},
		{SQL: `DELETE FROM browser_authorization_interactions WHERE session_digest=?`, Args: []any{sid}},
		rhiza.SQLStatement{SQL: `UPDATE oauth_authorize_codes SET invalidated = 1
			WHERE invalidated = 0 AND json_extract(request_json, '` + sidJSONPath + `') = ?`, Args: []any{sid}},
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_pkce_requests WHERE signature IN (
			SELECT signature FROM oauth_authorize_codes WHERE json_extract(request_json, '` + sidJSONPath + `') = ?)`, Args: []any{sid}},
		rhiza.SQLStatement{SQL: `UPDATE oauth_refresh_tokens SET active = 0
			WHERE active = 1 AND json_extract(request_json, '` + sidJSONPath + `') = ?`, Args: []any{sid}},
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_access_tokens WHERE signature IN (
			SELECT signature FROM oauth_token_requests WHERE json_extract(request_json, '` + sidJSONPath + `') = ?)`, Args: []any{sid}},
		rhiza.SQLStatement{SQL: `DELETE FROM oauth_token_requests
			WHERE json_extract(request_json, '` + sidJSONPath + `') = ?`, Args: []any{sid}},
		rhiza.SQLStatement{SQL: `DELETE FROM oidc_session_clients WHERE sid = ?`, Args: []any{sid}},
	}, nil
}

func validOIDCSessionID(sid string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(sid)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == sid
}

func oidcSessionRevocationRequestID(sid string) (string, error) {
	attempt := make([]byte, 16)
	if _, err := rand.Read(attempt); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(sid))
	return "oauth-sid/" + base64.RawURLEncoding.EncodeToString(digest[:16]) + "/" + base64.RawURLEncoding.EncodeToString(attempt), nil
}

func oidcBackchannelEventID() (string, error) {
	event := make([]byte, 16)
	if _, err := rand.Read(event); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(event), nil
}
