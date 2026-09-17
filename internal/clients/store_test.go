package clients

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func testStore(t *testing.T, reserved ...string) (*Store, context.Context) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "managed-client-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "managed-client-test-barrier", SQL: `INSERT INTO master_key_retirement_barrier(barrier_id,epoch,old_key_id,replacement_key_id,membership_digest,state,prepared_at_unix_ms) VALUES (1,1,'old','master',?, 'prepared',1)`, Args: []any{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}); err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "master"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	kr, err := oidc.LoadKeyring(d, "master")
	if err != nil {
		t.Fatal(err)
	}
	return NewStore(db, kr, reserved...), ctx
}

func auth() func() (string, []any)   { return func() (string, []any) { return "1", nil } }
func denied() func() (string, []any) { return func() (string, []any) { return "0", nil } }
func newClient(conf bool) NewRequest {
	return NewRequest{ID: "managed-test-client", Confidential: conf, RedirectURIs: []string{"https://example.test/callback"}}
}
func updateOf(c Client, conf, enabled bool) UpdateRequest {
	return UpdateRequest{Name: c.Name, Confidential: conf, RedirectURIs: c.RedirectURIs, Enabled: enabled, Scopes: c.Scopes, DefaultScopes: c.DefaultScopes, GrantTypes: c.GrantTypes}
}

func TestStoreCRUDSecretTransitionsAndGuards(t *testing.T) {
	s, ctx := testStore(t, "bootstrap")
	c, err := s.CreateWithGuard(ctx, newClient(true), auth())
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.ReadSecretWithGuard(ctx, c.ID, auth())
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || len(c.SecretHash) == 0 {
		t.Fatal("confidential secret missing")
	}
	name := "renamed"
	u := updateOf(c, true, true)
	u.Name = &name
	changed, err := s.UpdateWithGuard(ctx, c.ID, c.Revision, u, auth())
	if err != nil {
		t.Fatal(err)
	}
	secret2, err := s.ReadSecretWithGuard(ctx, c.ID, auth())
	if err != nil || secret2 != secret {
		t.Fatalf("name update changed secret: %v", err)
	}
	if _, err := s.UpdateWithGuard(ctx, c.ID, c.Revision, u, auth()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update=%v", err)
	}
	if _, err := s.GetWithGuard(ctx, c.ID, denied()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("guarded read=%v", err)
	}
	rotatedClient, err := s.RotateSecretWithGuard(ctx, c.ID, changed.Revision, auth())
	if err != nil {
		t.Fatal(err)
	}
	rotated, err := s.ReadSecretWithGuard(ctx, c.ID, auth())
	if err != nil || rotated == secret {
		t.Fatalf("rotation secret=%q err=%v", rotated, err)
	}
	public, err := s.UpdateWithGuard(ctx, c.ID, rotatedClient.Revision, updateOf(changed, false, true), auth())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadSecretWithGuard(ctx, public.ID, auth()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("public secret=%v", err)
	}
	if err := s.DeleteWithGuard(ctx, public.ID, public.Revision, denied()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("guarded delete=%v", err)
	}
	if err := s.DeleteWithGuard(ctx, public.ID, public.Revision, auth()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetWithGuard(ctx, public.ID, auth()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted get=%v", err)
	}
	if _, err := s.CreateWithGuard(ctx, newClient(false), auth()); err == nil {
		t.Fatal("deleted ID reused")
	}
}

func TestStoreBootstrapIsDurable(t *testing.T) {
	s, ctx := testStore(t)
	if err := s.EnsureBootstrap(ctx, "bootstrap"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureBootstrap(ctx, "bootstrap"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureBootstrap(ctx, "other-bootstrap"); !errors.Is(err, ErrReserved) {
		t.Fatalf("changed bootstrap=%v", err)
	}
	if _, err := s.CreateWithGuard(ctx, NewRequest{ID: "bootstrap", RedirectURIs: []string{"https://example.test/callback"}}, auth()); err == nil {
		t.Fatalf("bootstrap create=%v", err)
	}
}

func TestStoreRejectsDynamicIDCollisionsBothDirections(t *testing.T) {
	s, ctx := testStore(t)
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "managed-client-dynamic-owner", SQL: `INSERT INTO dynamic_oauth_clients(client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,created_at_unix_ms) VALUES ('dynamic-owned',NULL,'token-dynamic-owned','[]','[]','[]','[]','[]','none','dynamic',1)`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateWithGuard(ctx, NewRequest{ID: "dynamic-owned", RedirectURIs: []string{"https://example.test/callback"}}, auth()); err == nil {
		t.Fatal("managed client shadowed dynamic client")
	}
	c, err := s.CreateWithGuard(ctx, NewRequest{ID: "managed-owned", RedirectURIs: []string{"https://example.test/callback"}}, auth())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "managed-client-dynamic-shadow", SQL: `INSERT INTO dynamic_oauth_clients(client_id,secret_hash,registration_token_digest,redirect_uris_json,scopes_json,grant_types_json,response_types_json,audiences_json,token_endpoint_auth_method,name,created_at_unix_ms) VALUES (?,NULL,?,'[]','[]','[]','[]','[]','none','dynamic',1)`, Args: []any{c.ID, "token-shadow"}}); err == nil {
		t.Fatal("dynamic client shadowed managed client")
	}
}

func TestStoreManagedDeviceOnlyPolicy(t *testing.T) {
	s, ctx := testStore(t)
	c, err := s.CreateWithGuard(ctx, NewRequest{ID: "managed-device", Scopes: []string{"goauthy.read"}, DefaultScopes: []string{"goauthy.read"}, GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"}}, auth())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.RedirectURIs) != 0 || len(c.GetResponseTypes()) != 0 || !contains(c.GrantTypes, "urn:ietf:params:oauth:grant-type:device_code") {
		t.Fatalf("device-only client=%+v", c)
	}
	if _, err := s.CreateWithGuard(ctx, NewRequest{ID: "bad-public-machine", Confidential: false, GrantTypes: []string{"client_credentials"}}, auth()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("public client credentials error=%v", err)
	}
	exchange := "urn:ietf:params:oauth:grant-type:token-exchange"
	if _, err := s.CreateWithGuard(ctx, NewRequest{ID: "managed-exchange", Confidential: true, Scopes: []string{"goauthy.read"}, DefaultScopes: []string{"goauthy.read"}, GrantTypes: []string{exchange}}, auth()); err != nil {
		t.Fatalf("confidential token exchange=%v", err)
	}
	if _, err := s.CreateWithGuard(ctx, NewRequest{ID: "bad-public-exchange", Confidential: false, Scopes: []string{"goauthy.read"}, DefaultScopes: []string{"goauthy.read"}, GrantTypes: []string{exchange}}, auth()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("public token exchange error=%v", err)
	}
}

func TestManagedGroupPrefixPersistenceAndSecretRotation(t *testing.T) {
	s, ctx := testStore(t)
	in := newClient(true)
	prefix := " team/"
	in.RestrictGroupPrefix = &prefix
	c, err := s.CreateWithGuard(ctx, in, auth())
	if err != nil {
		t.Fatal(err)
	}
	c, err = s.RotateSecretWithGuard(ctx, c.ID, c.Revision, auth())
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetWithGuard(ctx, c.ID, auth())
	if err != nil || got.RestrictGroupPrefix == nil || *got.RestrictGroupPrefix != prefix {
		t.Fatalf("prefix not preserved: %+v %v", got, err)
	}
	u := updateOf(c, true, true)
	invalid := "x"
	u.RestrictGroupPrefix = &invalid
	if _, err := s.UpdateWithGuard(ctx, c.ID, c.Revision, u, auth()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid prefix: %v", err)
	}
	u.RestrictGroupPrefix = nil
	if _, err := s.UpdateWithGuard(ctx, c.ID, c.Revision, u, auth()); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetWithGuard(ctx, c.ID, auth())
	if err != nil || got.RestrictGroupPrefix != nil {
		t.Fatalf("prefix not cleared: %+v %v", got, err)
	}
}

func TestManagedBackchannelURIPersistenceAndSecretRotation(t *testing.T) {
	s, ctx := testStore(t)
	in := newClient(true)
	prefix := "https://rp.example.test/backchannel"
	in.BackchannelLogoutURI = &prefix
	c, err := s.CreateWithGuard(ctx, in, auth())
	if err != nil {
		t.Fatal(err)
	}
	c, err = s.RotateSecretWithGuard(ctx, c.ID, c.Revision, auth())
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetWithGuard(ctx, c.ID, auth())
	if err != nil || got.BackchannelLogoutURI == nil || *got.BackchannelLogoutURI != prefix {
		t.Fatalf("prefix not preserved: %+v %v", got, err)
	}
	u := updateOf(c, true, true)
	invalid := "https://rp.example.test/ bad"
	u.BackchannelLogoutURI = &invalid
	if _, err := s.UpdateWithGuard(ctx, c.ID, c.Revision, u, auth()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid prefix: %v", err)
	}
	u.BackchannelLogoutURI = nil
	if _, err := s.UpdateWithGuard(ctx, c.ID, c.Revision, u, auth()); err != nil {
		t.Fatal(err)
	}
	got, err = s.GetWithGuard(ctx, c.ID, auth())
	if err != nil || got.BackchannelLogoutURI != nil {
		t.Fatalf("prefix not cleared: %+v %v", got, err)
	}
}

func TestBackchannelURIUpdatesAssociationsAtomically(t *testing.T) {
	s, ctx := testStore(t)
	c, err := s.CreateWithGuard(ctx, newClient(false), auth())
	if err != nil {
		t.Fatal(err)
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "association-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO oidc_user_clients(subject,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('user',?,'old',0,0,1)`, Args: []any{c.ID}},
		{SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES('sid',?,'old',0,0,1)`, Args: []any{c.ID}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		t.Helper()
		for _, table := range []string{"oidc_user_clients", "oidc_session_clients"} {
			q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT logout_uri FROM " + table + " WHERE client_id=?", Args: []any{c.ID}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != want {
				t.Fatalf("association %s: %+v %v", table, q, err)
			}
		}
	}
	uri := "https://new.example.test/logout"
	u := updateOf(c, false, true)
	u.BackchannelLogoutURI = &uri
	if _, err = s.UpdateWithGuard(ctx, c.ID, c.Revision, u, denied()); err == nil {
		t.Fatal("denied update accepted")
	}
	check("old")
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "sync-failure", SQL: `CREATE TRIGGER reject_uri_sync BEFORE UPDATE ON oidc_session_clients BEGIN SELECT RAISE(ABORT,'sync failed'); END`})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.UpdateWithGuard(ctx, c.ID, c.Revision, u, auth()); err == nil {
		t.Fatal("failed sync committed")
	}
	check("old")
	got, err := s.GetWithGuard(ctx, c.ID, auth())
	if err != nil || got.Revision != c.Revision || got.BackchannelLogoutURI != nil {
		t.Fatal("metadata not rolled back", err)
	}
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "sync-restore", SQL: `DROP TRIGGER reject_uri_sync`})
	if err != nil {
		t.Fatal(err)
	}
	c, err = s.UpdateWithGuard(ctx, c.ID, c.Revision, u, auth())
	if err != nil {
		t.Fatal(err)
	}
	check(uri)
	u.BackchannelLogoutURI = nil
	if _, err = s.UpdateWithGuard(ctx, c.ID, c.Revision, u, auth()); err != nil {
		t.Fatal(err)
	}
	check("")
}
