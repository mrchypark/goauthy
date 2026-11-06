package clients

import (
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestConnectionPolicySchema(t *testing.T) {
	s, ctx := testStore(t)
	rows, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM connection_client_policies`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
		t.Fatalf("empty shared policy relation: rows=%v err=%v", rows.Rows, err)
	}
	if err := s.CheckBootstrapConnectionsInactive(ctx); err != nil {
		t.Fatalf("never-pinned deployment gated: %v", err)
	}
}

func bootstrapPolicyConfig() BootstrapConnectionConfig {
	return BootstrapConnectionConfig{Issuer: "https://issuer.example", Resource: "https://api.example/connections", AuthMethods: []string{"client_secret_basic", "client_secret_post"}, Client: ConnectionPolicy{ID: "bootstrap-policy", Enabled: true, Confidential: true, RedirectURIs: []string{"https://app.example/callback"}, Scopes: []string{"openid", "goauthy.read"}, GrantTypes: []string{"authorization_code", "refresh_token"}, Audiences: []string{"https://api.example/connections"}}}
}

func TestBootstrapConnectionPolicyImmutableAndConcurrent(t *testing.T) {
	s, ctx := testStore(t)
	a := bootstrapPolicyConfig()
	if err := s.EnsureBootstrap(ctx, a.Client.ID); err != nil {
		t.Fatal(err)
	}
	b := bootstrapPolicyConfig()
	b.Client.RedirectURIs = []string{"https://other.example/callback"}
	var wg sync.WaitGroup
	results := make([]error, 2)
	for i, cfg := range []BootstrapConnectionConfig{a, b} {
		wg.Go(func() { results[i] = NewStore(s.db, nil).PinBootstrapConnections(ctx, cfg) })
	}
	wg.Wait()
	winner := 0
	if results[0] != nil {
		winner = 1
	}
	if results[winner] != nil || !errors.Is(results[1-winner], ErrConflict) {
		t.Fatalf("pin conflict: %v", results)
	}
	configs := []BootstrapConnectionConfig{a, b}
	if err := NewStore(s.db, nil).PinBootstrapConnections(ctx, configs[winner]); err != nil {
		t.Fatalf("identical node: %v", err)
	}
	if err := s.CheckBootstrapConnectionsInactive(ctx); !errors.Is(err, ErrConflict) {
		t.Fatalf("unset resource bypassed persisted pin: %v", err)
	}
	if err := s.PinBootstrapConnections(ctx, configs[1-winner]); !errors.Is(err, ErrConflict) {
		t.Fatalf("loser replay: %v", err)
	}
	want := configs[winner]
	got, err := s.GetConnectionPolicyWithGuard(ctx, want.Client.ID, auth())
	if err != nil || !slices.Equal(got.RedirectURIs, want.Client.RedirectURIs) {
		t.Fatalf("winner policy=%+v err=%v", got, err)
	}
	reordered := want
	reordered.Client.Scopes = slices.Clone(want.Client.Scopes)
	slices.Reverse(reordered.Client.Scopes)
	if err := s.PinBootstrapConnections(ctx, reordered); err != nil {
		t.Fatalf("set order changed fingerprint: %v", err)
	}
	for name, alter := range map[string]func(*BootstrapConnectionConfig){
		"issuer": func(c *BootstrapConnectionConfig) { c.Issuer = "https://changed.example" },
		"resource": func(c *BootstrapConnectionConfig) {
			c.Resource = "https://different.example"
			c.Client.Audiences = []string{c.Resource}
		},
		"scope":       func(c *BootstrapConnectionConfig) { c.Client.Scopes = []string{"openid"} },
		"auth method": func(c *BootstrapConnectionConfig) { c.AuthMethods = []string{"client_secret_basic"} },
		"MFA":         func(c *BootstrapConnectionConfig) { c.Client.ForceMFA = true },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := want
			alter(&cfg)
			if err := s.PinBootstrapConnections(ctx, cfg); !errors.Is(err, ErrConflict) {
				t.Fatalf("different static policy: %v", err)
			}
		})
	}
	for _, sql := range []string{`UPDATE bootstrap_connection_policy SET config_digest=config_digest`, `DELETE FROM bootstrap_connection_policy`} {
		if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "reject-policy-mutation-" + randomID(), SQL: sql}); err == nil {
			t.Fatal("immutable policy changed")
		}
	}
	if _, err := s.GetConnectionPolicyWithGuard(ctx, want.Client.ID, denied()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("authority guard ignored: %v", err)
	}
}

func TestBootstrapConnectionPolicyRejectsManagedShadow(t *testing.T) {
	for _, deleted := range []int{0, 1} {
		t.Run(string(rune('0'+deleted)), func(t *testing.T) {
			s, ctx := testStore(t)
			cfg := bootstrapPolicyConfig()
			if err := s.EnsureBootstrap(ctx, cfg.Client.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.PinBootstrapConnections(ctx, cfg); err != nil {
				t.Fatal(err)
			}
			// Simulate a pre-existing/corrupt shadow via UPDATE; normal INSERT is
			// already rejected by the bootstrap reservation's database trigger.
			other, err := s.CreateWithGuard(ctx, NewRequest{ID: "shadow-source", RedirectURIs: []string{"https://app.example/callback"}}, auth())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: "seed-shadow", SQL: `UPDATE managed_oauth_clients SET id=?,enabled=0,deleted=? WHERE id=?`, Args: []any{cfg.Client.ID, deleted, other.ID}}); err != nil {
				t.Fatal(err)
			}
			if _, err := s.GetConnectionPolicyWithGuard(ctx, cfg.Client.ID, auth()); !errors.Is(err, ErrNotFound) {
				t.Fatalf("shadow fallback: %v", err)
			}
			if err := s.PinBootstrapConnections(ctx, cfg); !errors.Is(err, ErrConflict) {
				t.Fatalf("shadow restart accepted: %v", err)
			}
		})
	}
}

func TestPublicBootstrapConnectionPolicy(t *testing.T) {
	s, ctx := testStore(t)
	cfg := bootstrapPolicyConfig()
	cfg.Client.Confidential = false
	cfg.AuthMethods = []string{"none"}
	if err := s.EnsureBootstrap(ctx, cfg.Client.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.PinBootstrapConnections(ctx, cfg); err != nil {
		t.Fatalf("public bootstrap unnecessarily gated managed connections: %v", err)
	}
	p, err := s.GetConnectionPolicyWithGuard(ctx, cfg.Client.ID, auth())
	if err != nil || p.Confidential {
		t.Fatalf("public policy: %+v %v", p, err)
	}
}
