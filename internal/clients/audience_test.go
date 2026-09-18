package clients

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestManagedClientAudienceRejectsEmptyQueryOrFragment(t *testing.T) {
	for _, raw := range []string{"https://api.example/path?", "https://api.example/path#"} {
		if !errors.Is(validateAudiences([]string{raw}), ErrInvalid) {
			t.Fatalf("accepted query or fragment marker: %q", raw)
		}
	}
}

func TestManagedClientDefaultAudiencesRoundTripPreserveClearAndRotate(t *testing.T) {
	s, ctx := testStore(t)
	c, err := s.CreateWithGuard(ctx, NewRequest{
		ID: "default-audience-client", Confidential: true, RedirectURIs: []string{"https://example.test/callback"},
		Audiences: []string{"https://api.example.test/allowed"}, DefaultAudiences: []string{"https://api.example.test/default-a", "https://api.example.test/default-b"},
	}, auth())
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.ReadSecretWithGuard(ctx, c.ID, auth())
	if err != nil {
		t.Fatal(err)
	}
	defaults := c.GetDefaultAudience()
	defaults[0] = "https://other.example.test/default"
	if c.DefaultAudiences[0] != "https://api.example.test/default-a" {
		t.Fatal("GetDefaultAudience exposes client backing storage")
	}
	loaded, err := s.GetWithGuard(ctx, c.ID, auth())
	if err != nil || !slices.Equal(loaded.DefaultAudiences, c.DefaultAudiences) {
		t.Fatalf("stored defaults=%v err=%v", loaded.DefaultAudiences, err)
	}
	preserve := UpdateRequest{Name: c.Name, Confidential: true, RedirectURIs: c.RedirectURIs, Enabled: true, Scopes: c.Scopes, DefaultScopes: c.DefaultScopes, GrantTypes: c.GrantTypes, Audiences: nil, DefaultAudiences: nil}
	preserved, err := s.UpdateWithGuard(ctx, c.ID, c.Revision, preserve, auth())
	if err != nil || !slices.Equal(preserved.DefaultAudiences, c.DefaultAudiences) || preserved.Generation != c.Generation {
		t.Fatalf("preserve=%#v err=%v", preserved, err)
	}
	if got, err := s.ReadSecretWithGuard(ctx, c.ID, auth()); err != nil || got != secret {
		t.Fatalf("preserve changed secret=%q err=%v", got, err)
	}
	preserve.DefaultAudiences = []string{}
	cleared, err := s.UpdateWithGuard(ctx, c.ID, preserved.Revision, preserve, auth())
	if err != nil || len(cleared.DefaultAudiences) != 0 || cleared.Generation == preserved.Generation {
		t.Fatalf("clear=%#v err=%v", cleared, err)
	}
	rotated, err := s.RotateSecretWithGuard(ctx, c.ID, cleared.Revision, auth())
	if err != nil || len(rotated.DefaultAudiences) != 0 {
		t.Fatalf("rotation=%#v err=%v", rotated, err)
	}
}

func TestManagedClientAudiencesRoundTripPreserveClearAndRotate(t *testing.T) {
	s, ctx := testStore(t)
	c, err := s.CreateWithGuard(ctx, NewRequest{ID: "audience-client", Confidential: true, RedirectURIs: []string{"https://example.test/callback"}, Audiences: []string{"https://api.example.test/resource"}}, auth())
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.ReadSecretWithGuard(ctx, c.ID, auth())
	if err != nil {
		t.Fatal(err)
	}
	oldGen := c.Generation
	copy := c.GetAudience()
	copy[0] = "https://other.example.test"
	if c.Audiences[0] != "https://api.example.test/resource" {
		t.Fatal("GetAudience exposes client backing storage")
	}
	loaded, err := s.GetWithGuard(ctx, c.ID, auth())
	if err != nil || len(loaded.Audiences) != 1 || loaded.Audiences[0] != c.Audiences[0] {
		t.Fatalf("stored audience did not round trip: %v", err)
	}
	u := UpdateRequest{Name: c.Name, Confidential: true, RedirectURIs: c.RedirectURIs, Enabled: true, Scopes: c.Scopes, DefaultScopes: c.DefaultScopes, GrantTypes: c.GrantTypes, Audiences: nil}
	c2, err := s.UpdateWithGuard(ctx, c.ID, c.Revision, u, auth())
	if err != nil || len(c2.Audiences) != 1 || c2.Generation != oldGen {
		t.Fatalf("preserve=%#v err=%v", c2, err)
	}
	if got, err := s.ReadSecretWithGuard(ctx, c.ID, auth()); err != nil || got != secret {
		t.Fatal("secret changed on preserve")
	}
	u.Audiences = []string{}
	c3, err := s.UpdateWithGuard(ctx, c.ID, c2.Revision, u, auth())
	if err != nil || len(c3.Audiences) != 0 || c3.Generation == oldGen {
		t.Fatalf("clear=%#v err=%v", c3, err)
	}
	if got, err := s.ReadSecretWithGuard(ctx, c.ID, auth()); err != nil || got != secret {
		t.Fatal("secret changed on audience rotation")
	}
	if _, err := s.UpdateWithGuard(ctx, c.ID, c2.Revision, u, auth()); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale=%v", err)
	}
}

func TestManagedClientAudienceLegacyAndValidation(t *testing.T) {
	s, ctx := testStore(t)
	c, err := s.CreateWithGuard(ctx, newClient(false), auth())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "legacy-audience", SQL: `UPDATE managed_oauth_clients SET metadata_json=json_remove(metadata_json,'$.audience') WHERE id=?`, Args: []any{c.ID}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetWithGuard(ctx, c.ID, auth())
	if err != nil || got.Audiences == nil {
		t.Fatalf("legacy=%#v err=%v", got, err)
	}
	for _, aud := range [][]string{{"http://api.example"}, {"https://user:pass@api.example/x"}, {"https://api.example/x?q=1"}, {"https://api.example/#x"}, {"https://api.example/ bad"}, {"https://api.example", "https://api.example"}, {""}, {"https://:443/path"}, {"https://api.example/" + strings.Repeat("a", 2048)}, make([]string, 33)} {
		_, err = s.UpdateWithGuard(ctx, c.ID, got.Revision, UpdateRequest{Name: got.Name, Confidential: false, RedirectURIs: got.RedirectURIs, Enabled: true, Scopes: got.Scopes, DefaultScopes: got.DefaultScopes, GrantTypes: got.GrantTypes, Audiences: aud}, auth())
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %q: %v", aud, err)
		}
	}
	if _, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "invalid-stored-audience", SQL: `UPDATE managed_oauth_clients SET metadata_json=json_set(metadata_json,'$.audience',json('["http://api.example"]')) WHERE id=?`, Args: []any{c.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetWithGuard(ctx, c.ID, auth()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid stored audience accepted: %v", err)
	}
}

func TestManagedClientDefaultAudienceLegacyAndValidation(t *testing.T) {
	s, ctx := testStore(t)
	c, err := s.CreateWithGuard(ctx, newClient(false), auth())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "legacy-default-audience", SQL: `UPDATE managed_oauth_clients SET metadata_json=json_remove(metadata_json,'$.default_aud') WHERE id=?`, Args: []any{c.ID}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetWithGuard(ctx, c.ID, auth())
	if err != nil || got.DefaultAudiences == nil {
		t.Fatalf("legacy=%#v err=%v", got, err)
	}
	for _, defaults := range [][]string{{"http://api.example"}, {"https://api.example/x?q=1"}, {""}, {"https://api.example", "https://api.example"}, make([]string, 33)} {
		_, err = s.UpdateWithGuard(ctx, c.ID, got.Revision, UpdateRequest{Name: got.Name, Confidential: false, RedirectURIs: got.RedirectURIs, Enabled: true, Scopes: got.Scopes, DefaultScopes: got.DefaultScopes, GrantTypes: got.GrantTypes, DefaultAudiences: defaults}, auth())
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted %q: %v", defaults, err)
		}
	}
	if _, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "invalid-stored-default-audience", SQL: `UPDATE managed_oauth_clients SET metadata_json=json_set(metadata_json,'$.default_aud',json('["http://api.example"]')) WHERE id=?`, Args: []any{c.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetWithGuard(ctx, c.ID, auth()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid stored default audience accepted: %v", err)
	}
}
