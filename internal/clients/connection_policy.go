package clients

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// ConnectionPolicy contains only public authorization policy, never an
// authentication secret, secret verifier, or token. The pin does not establish
// cross-node authentication-secret consistency.
type ConnectionPolicy struct {
	ID               string   `json:"id"`
	Enabled          bool     `json:"enabled"`
	Confidential     bool     `json:"confidential"`
	RedirectURIs     []string `json:"redirect_uris"`
	Scopes           []string `json:"scopes"`
	GrantTypes       []string `json:"enabled_flows"`
	Audiences        []string `json:"audience"`
	DefaultAudiences []string `json:"default_aud"`
	ForceMFA         bool     `json:"force_mfa"`
	Generation       string   `json:"-"`
}

type BootstrapConnectionConfig struct {
	Issuer      string           `json:"issuer"`
	Resource    string           `json:"resource"`
	AuthMethods []string         `json:"auth_methods"`
	Client      ConnectionPolicy `json:"client"`
}

// CheckBootstrapConnectionsInactive allows unconfigured installations only when
// no node has pinned the feature. Removing a resource cannot bypass an old pin.
func (s *Store) CheckBootstrapConnectionsInactive(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrInvalid
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM bootstrap_connection_policy LIMIT 1`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(q.Rows) != 0 {
		return ErrConflict
	}
	return nil
}

// PinBootstrapConnections is a first-registration CAS, never an update. It is
// called only when connections are configured. Conflicting nodes fail closed.
func (s *Store) PinBootstrapConnections(ctx context.Context, cfg BootstrapConnectionConfig) error {
	validURL := func(raw string) bool {
		u, err := url.Parse(raw)
		return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
	}
	if s == nil || s.db == nil || !idPattern.MatchString(cfg.Client.ID) || !cfg.Client.Enabled || !validURL(cfg.Issuer) || !validURL(cfg.Resource) || !slices.Contains(cfg.Client.Audiences, cfg.Resource) || len(cfg.AuthMethods) == 0 {
		return ErrInvalid
	}
	canonical := func(v []string) []string { v = append([]string{}, v...); slices.Sort(v); return slices.Compact(v) }
	cfg.AuthMethods = canonical(cfg.AuthMethods)
	cfg.Client.RedirectURIs = canonical(cfg.Client.RedirectURIs)
	cfg.Client.Scopes = canonical(cfg.Client.Scopes)
	cfg.Client.GrantTypes = canonical(cfg.Client.GrantTypes)
	cfg.Client.Audiences = canonical(cfg.Client.Audiences)
	cfg.Client.DefaultAudiences = canonical(cfg.Client.DefaultAudiences)
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(digest[:])
	metadata, err := json.Marshal(cfg.Client)
	if err != nil {
		return err
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "bootstrap-connections-pin-" + randomID(), SQL: `INSERT INTO bootstrap_connection_policy(singleton,id,config_digest,generation,metadata_json)
	 SELECT 1,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM bootstrap_connection_policy)
	 AND EXISTS(SELECT 1 FROM managed_oauth_client_bootstrap WHERE id=?)
	 AND NOT EXISTS(SELECT 1 FROM managed_oauth_clients WHERE id=?)
	 AND NOT EXISTS(SELECT 1 FROM dynamic_oauth_clients WHERE client_id=?)`, Args: []any{cfg.Client.ID, fingerprint, randomGeneration(), string(metadata), cfg.Client.ID, cfg.Client.ID, cfg.Client.ID}})
	if err != nil {
		return err
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM bootstrap_connection_policy WHERE id=? AND config_digest=?
	 AND EXISTS(SELECT 1 FROM managed_oauth_client_bootstrap WHERE id=?)
	 AND NOT EXISTS(SELECT 1 FROM managed_oauth_clients WHERE id=?)
	 AND NOT EXISTS(SELECT 1 FROM dynamic_oauth_clients WHERE client_id=?)`, Args: []any{cfg.Client.ID, fingerprint, cfg.Client.ID, cfg.Client.ID, cfg.Client.ID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(q.Rows) != 1 {
		return ErrConflict
	}
	return nil
}

// GetConnectionPolicyWithGuard resolves both kinds through the same relation
// used by subsequent transactional SaaS guards; a managed shadow never falls back.
func (s *Store) GetConnectionPolicyWithGuard(ctx context.Context, id string, authority func() (string, []any)) (ConnectionPolicy, error) {
	guard, args := guardArgs(authority)
	if s == nil || s.db == nil || guard == "0" {
		return ConnectionPolicy{}, ErrUnauthorized
	}
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT generation,enabled,metadata_json FROM connection_client_policies WHERE id=? AND deleted=0 AND (` + guard + `)`, Args: append([]any{id}, args...), Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return ConnectionPolicy{}, err
	}
	if len(q.Rows) != 1 {
		return ConnectionPolicy{}, ErrNotFound
	}
	r := q.Rows[0]
	var p ConnectionPolicy
	g, ok := r[0].(string)
	enabled, okEnabled := r[1].(int64)
	meta, okMeta := r[2].(string)
	if !ok || !okEnabled || !okMeta || g == "" || (enabled != 0 && enabled != 1) || json.Unmarshal([]byte(meta), &p) != nil {
		return ConnectionPolicy{}, ErrInvalid
	}
	p.ID, p.Generation, p.Enabled = id, g, enabled == 1
	return p, nil
}
