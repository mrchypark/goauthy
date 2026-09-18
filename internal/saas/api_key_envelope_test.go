package saas

import (
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAPIKeyEncryptedStorageCanDecryptAndRewrap(t *testing.T) {
	for _, mode := range []string{"custody", "destination-bound"} {
		t.Run(mode, func(t *testing.T) {
			ctx, store, db, binding := credentialStoreFixture(t)
			store.keys = credentialKeys(t, "master", "master", "next")
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "api-key-test-definition", SQL: `UPDATE auth_collection_definitions SET auth_method='api_key',providers_json='[]' WHERE id=?`, Args: []any{binding.CollectionID}}); err != nil {
				t.Fatal(err)
			}
			var digest string
			var putErr error
			if mode == "destination-bound" {
				connector, err := NewAPIKeyConnector(validAPIKeyConnectorConfig())
				if err != nil {
					t.Fatal(err)
				}
				digest = connector.Digest()
				_, putErr = store.PutBoundAPIKey(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 0, "synthetic-reversible-key", connector, digest, credentialAuthority())
			} else {
				_, putErr = store.PutAPIKey(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 0, "synthetic-reversible-key", credentialAuthority())
			}
			if putErr != nil {
				t.Fatal(putErr)
			}
			binding.ProviderID = apiKeyProviderID
			envelope := readCredentialEnvelope(t, ctx, db, binding.ConnectionID)
			value, err := openCredential(store.keys, binding, envelope)
			if err != nil || value.APIKey != "synthetic-reversible-key" || value.AccessToken != "" || value.ConnectorDigest != digest {
				t.Fatalf("stored API key cannot be recovered: %v", err)
			}
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "api-key-next-key", SQL: `UPDATE master_key_retirement_barrier SET old_key_id='master',replacement_key_id='next' WHERE barrier_id=1`}); err != nil {
				t.Fatal(err)
			}
			rotated := credentialKeys(t, "next", "master", "next")
			result, err := RewrapCredentialEnvelopeBatch(ctx, db, rotated, "")
			if err != nil || result.Rewrapped != 1 {
				t.Fatalf("key rewrap=%+v err=%v", result, err)
			}
			envelope = readCredentialEnvelope(t, ctx, db, binding.ConnectionID)
			value, err = openCredential(credentialKeys(t, "next", "next"), binding, envelope)
			if err != nil || value.APIKey != "synthetic-reversible-key" || value.ConnectorDigest != digest {
				t.Fatalf("rewrapped API key cannot be recovered: %v", err)
			}
			binding.Owner = "other-owner"
			if _, err := openCredential(rotated, binding, envelope); err == nil {
				t.Fatal("API-key ciphertext accepted another owner binding")
			}
		})
	}
}
