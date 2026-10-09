package saas

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAPIKeyCallFailureLogRedactsDetails(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	const secret = "synthetic-private-storage-detail"
	logAPIKeyCallFailure("credential_preflight", errors.New(secret))
	if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "stage=credential_preflight") || !strings.Contains(output.String(), "error_class=unknown") {
		t.Fatalf("unsafe or incomplete diagnostic: %s", output.String())
	}
}

func TestCallAPIKeyEncryptedStoreToTLSProvider(t *testing.T) {
	t.Parallel()
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

type apiKeyPostflightMutationTransport struct {
	base   http.RoundTripper
	mutate func() error
}

func (transport apiKeyPostflightMutationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := transport.base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if err := transport.mutate(); err != nil {
		_ = response.Body.Close()
		return nil, err
	}
	return response, nil
}

func TestCallAPIKeyPostflightCiphertextSnapshot(t *testing.T) {
	t.Parallel()
	for _, scenario := range []string{"unchanged", "rewrapped", "tampered"} {
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			ctx, store, db, binding, connector := registeredAPIKeyFixture(t, "postflight-"+scenario)
			if _, err := store.PutBoundAPIKey(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 0, "synthetic-postflight-key", connector, connector.Digest(), credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			connector, err := store.APIKeyConnector(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			binding, _, err = store.loadAPIKey(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			before := readCredentialEnvelope(t, ctx, db, binding.ConnectionID)

			unavailableKeys := credentialKeys(t, "unavailable", "unavailable")
			var providerCalls atomic.Int64
			var interpositionErr error
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				providerCalls.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/account" {
					t.Error("unexpected outbound request contract")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"account-1","active":true}`))
			}))
			defer server.Close()
			client := apiKeyConnectorTLSClient(t, server)
			client.Transport = apiKeyPostflightMutationTransport{base: client.Transport, mutate: func() (mutationErr error) {
				defer func() { interpositionErr = mutationErr }()
				switch scenario {
				case "unchanged":
					// The proof from preflight remains valid for this exact binding
					// and ciphertext; postflight must not need this retired key.
					store.keys = unavailableKeys
				case "rewrapped":
					purpose, err := credentialPurpose(binding)
					if err != nil {
						return err
					}
					rewrapped, err := store.keys.RewrapEnvelope(purpose, before)
					if err != nil {
						return err
					}
					if bytes.Equal(rewrapped, before) {
						return errors.New("rewrap did not change the envelope")
					}
					response, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "api-key-postflight-rewrap", SQL: `UPDATE saas_connection_credentials SET credential=? WHERE connection_id=? AND token_version=?`, Args: []any{rewrapped, binding.ConnectionID, binding.TokenVersion}})
					if err != nil {
						return err
					}
					if response.Status != "committed" || response.MutationReceipt.RowsAffected != 1 {
						return errors.New("rewrap interposition did not update one credential")
					}
					return nil
				case "tampered":
					tampered := append([]byte(nil), before...)
					tampered[len(tampered)-1] ^= 1
					response, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "api-key-postflight-tamper", SQL: `UPDATE saas_connection_credentials SET credential=? WHERE connection_id=? AND token_version=?`, Args: []any{tampered, binding.ConnectionID, binding.TokenVersion}})
					if err != nil {
						return err
					}
					if response.Status != "committed" || response.MutationReceipt.RowsAffected != 1 {
						return errors.New("tamper interposition did not update one credential")
					}
					return nil
				}
				return nil
			}}
			connector.client = client

			result, err := store.CallAPIKey(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, connector, "account", credentialAuthority())
			if interpositionErr != nil {
				t.Fatalf("interposition failed: %v", interpositionErr)
			}
			if providerCalls.Load() != 1 {
				t.Fatalf("provider calls=%d want=1", providerCalls.Load())
			}
			switch scenario {
			case "unchanged", "rewrapped":
				if err != nil || string(result["id"]) != `"account-1"` || string(result["active"]) != "true" || len(result) != 2 {
					t.Fatalf("current credential result was not released: err=%v", err)
				}
			case "tampered":
				if err == nil || result != nil {
					t.Fatal("tampered current ciphertext released provider data")
				}
			}
		})
	}
}
