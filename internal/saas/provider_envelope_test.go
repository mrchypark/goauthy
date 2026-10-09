package saas

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

func TestProviderSecretPurposeBindsIDAndGeneration(t *testing.T) {
	t.Parallel()
	a := providerSecretPurpose("github", "generation-a")
	if a == providerSecretPurpose("github", "generation-b") || a == providerSecretPurpose("other", "generation-a") {
		t.Fatal("provider secret purpose is not bound")
	}
	if len(a) == 0 {
		t.Fatal("empty provider secret purpose")
	}
}

func TestProviderEnvelopeInspectionAndRewrap(t *testing.T) {
	t.Parallel()
	ctx, credentials, db, _ := credentialStoreFixture(t)
	store, err := NewProviderStore(db, credentials.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, providerInputForTest("0123456789012345"), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	family, err := InspectProviderEnvelopeReferences(ctx, db, credentials.keys)
	if err != nil || family.Total != 1 {
		t.Fatalf("family=%+v err=%v", family, err)
	}
	result, err := RewrapProviderEnvelopeBatch(ctx, db, credentials.keys, "")
	if err != nil || result.Rewrapped != 0 || !result.Done {
		t.Fatalf("rewrap=%+v err=%v", result, err)
	}
	if _, err := store.LoadOAuth2(ctx, "github", credentialAuthority()); err != nil {
		t.Fatal(err)
	}
}

func TestProviderEnvelopeTwoRotationsAndAPIKeyHasNoSecret(t *testing.T) {
	t.Parallel()
	ctx, _, db, _ := credentialStoreFixture(t)
	keys := credentialKeys(t, "key-a", "key-a", "key-b", "key-c")
	store, err := NewProviderStore(db, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, providerInputForTest("rotation-test-secret"), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	api := ProviderInput{ID: "billing", Name: "Billing", Kind: "api_key", Enabled: true, Connector: &APIKeyConnectorConfig{ID: "billing", Header: "X-API-Key", Operations: []APIKeyOperationConfig{{ID: "account", URL: "https://api.example/account", ResponseFields: map[string]string{"id": "string"}}}}}
	if _, err := store.Create(ctx, api, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	for _, active := range []string{"key-b", "key-c"} {
		rotated := credentialKeys(t, active, "key-a", "key-b", "key-c")
		result, err := RewrapProviderEnvelopeBatch(ctx, db, rotated, "")
		if err != nil || result.Rewrapped != 1 {
			t.Fatalf("%s result=%+v err=%v", active, result, err)
		}
		family, err := InspectProviderEnvelopeReferences(ctx, db, rotated)
		if err != nil || family.Total != 1 || family.ByKeyID[active] != 1 {
			t.Fatalf("%s family=%+v err=%v", active, family, err)
		}
		reader, err := NewProviderStore(db, rotated)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.LoadOAuth2(ctx, "github", credentialAuthority()); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkProviderEnvelopeRewrap32(b *testing.B) {
	for _, tc := range []struct {
		name string
		old  bool
	}{
		{name: "active32"},
		{name: "oldkey32", old: true},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				ctx, credentials, db, err := providerEnvelopeBenchmarkFixture(b, tc.old)
				if err != nil {
					b.Fatal("provider rewrap fixture setup failed")
				}
				b.StartTimer()
				result, err := RewrapProviderEnvelopeBatch(ctx, db, credentials, "")
				b.StopTimer()
				if err != nil {
					b.Fatal("provider rewrap failed")
				}
				wantRewrapped := 0
				if tc.old {
					wantRewrapped = 32
				}
				if result.Rewrapped != wantRewrapped || result.Cursor != "rewrap-31" || result.Done {
					b.Fatalf("unexpected 32-row batch result: rewrapped=%d cursor=%q done=%v", result.Rewrapped, result.Cursor, result.Done)
				}
				if tc.old {
					family, err := InspectProviderEnvelopeReferences(ctx, db, credentials)
					if err != nil || family.Total != 32 || family.ByKeyID["key-b"] != 32 {
						b.Fatal("rewrapped key-reference verification failed")
					}
				}
				// Each old-key row reaches one ExecuteEnvelope call in the
				// implementation. Rewrapped verifies all 32 CAS updates landed
				// in this isolated no-writer fixture; active rows submit none.
			}
		})
	}
}

func providerEnvelopeBenchmarkFixture(b *testing.B, old bool) (context.Context, *oidc.Keyring, *rhiza.DB, error) {
	b.Helper()
	ctx, credentials, db, _ := credentialStoreFixture(b)
	keys := credentials.keys
	seedKeys := keys
	if old {
		var err error
		seedKeys, err = providerEnvelopeBenchmarkKeyring(b, "key-a", "key-a", "key-b")
		if err != nil {
			return nil, nil, nil, err
		}
		keys, err = providerEnvelopeBenchmarkKeyring(b, "key-b", "key-a", "key-b")
		if err != nil {
			return nil, nil, nil, err
		}
	}
	store, err := NewProviderStore(db, seedKeys)
	if err != nil {
		return nil, nil, nil, err
	}
	for i := 0; i < 32; i++ {
		input := providerInputForTest("synthetic-provider-secret")
		input.ID = fmt.Sprintf("rewrap-%02d", i)
		input.Name = input.ID
		if _, err := store.Create(ctx, input, credentialAuthority()); err != nil {
			return nil, nil, nil, err
		}
	}
	return ctx, keys, db, nil
}

func providerEnvelopeBenchmarkKeyring(b *testing.B, active string, ids ...string) (*oidc.Keyring, error) {
	b.Helper()
	dir := b.TempDir()
	for i, id := range ids {
		key := make([]byte, 32)
		for j := range key {
			key[j] = byte(i + 1)
		}
		encoded := []byte(base64.RawURLEncoding.EncodeToString(key))
		if err := os.WriteFile(filepath.Join(dir, id), encoded, 0o600); err != nil {
			return nil, err
		}
	}
	return oidc.LoadKeyring(dir, active)
}
