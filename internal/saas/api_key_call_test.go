package saas

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestCallAPIKeyEncryptedStoreToTLSProvider(t *testing.T) {
	for _, scenario := range []string{"success", "unbound", "different-policy", "revoked-before", "revoked-inflight", "rotated-inflight", "authority-inflight"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, store, db, b := credentialStoreFixture(t)
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "call-api-key-method", SQL: `UPDATE auth_collection_definitions SET auth_method='api_key',providers_json='[]' WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
				t.Fatal(err)
			}
			cfg := APIKeyConnectorConfig{ID: "test-provider", Header: "Authorization", Prefix: "Bearer ", Operations: []APIKeyOperationConfig{{ID: "account", URL: "https://example.com/account", ResponseFields: map[string]string{"id": "string"}}}}
			connector, err := NewAPIKeyConnector(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var allowed atomic.Bool
			allowed.Store(true)
			authority := func() (string, []any) {
				if allowed.Load() {
					return "1", nil
				}
				return "0", nil
			}
			if scenario == "unbound" {
				_, err = store.PutAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-call-key", authority)
			} else {
				_, err = store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 0, "synthetic-call-key", connector, connector.Digest(), authority)
			}
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "revoked-before" {
				if err := store.RevokeAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, authority); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "different-policy" {
				cfg.Operations[0].URL = "https://example.com/changed"
				connector, err = NewAPIKeyConnector(cfg)
				if err != nil {
					t.Fatal(err)
				}
			}
			var calls atomic.Int64
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Header.Get("Authorization") != "Bearer synthetic-call-key" || r.Method != http.MethodGet || r.URL.Path != "/account" {
					t.Error("unexpected outbound request contract")
				}
				switch scenario {
				case "revoked-inflight":
					if err := store.RevokeAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, authority); err != nil {
						t.Error(err)
					}
				case "rotated-inflight":
					if _, err := store.PutBoundAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, "synthetic-next-key", connector, connector.Digest(), authority); err != nil {
						t.Error(err)
					}
				case "authority-inflight":
					allowed.Store(false)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"account-1","private_field":"not-projected"}`))
			}))
			defer server.Close()
			connector.client = apiKeyConnectorTLSClient(t, server)
			result, err := store.CallAPIKey(ctx, b.Owner, b.CollectionID, b.ConnectionID, connector, "account", authority)
			if scenario == "success" {
				if err != nil || string(result["id"]) != `"account-1"` || len(result) != 1 {
					t.Fatalf("result=%v err=%v", result, err)
				}
			} else if err == nil || result != nil {
				t.Fatal("denied or changed authority released provider data")
			}
			wantCalls := int64(1)
			if scenario == "unbound" || scenario == "different-policy" || scenario == "revoked-before" {
				wantCalls = 0
			}
			if calls.Load() != wantCalls {
				t.Fatalf("outbound calls=%d want=%d", calls.Load(), wantCalls)
			}
		})
	}
}
