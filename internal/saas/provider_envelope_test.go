package saas

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
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

func TestProviderEnvelopeBenchmarkFixtureLifecycle(t *testing.T) {
	lifecycle := &providerEnvelopeFixtureLifecycle{}
	for i := 0; i < 3; i++ {
		wantErr := i == 2
		err := withProviderEnvelopeBenchmarkFixture(t, false, lifecycle, func(context.Context, *oidc.Keyring, *rhiza.DB) error {
			if wantErr {
				return errors.New("synthetic post-operation validation failure")
			}
			return nil
		})
		if (err != nil) != wantErr {
			t.Fatalf("iteration %d error=%v, wantErr=%v", i, err, wantErr)
		}
		if lifecycle.live != 0 {
			t.Fatalf("iteration %d retained %d live fixtures", i, lifecycle.live)
		}
	}
	if lifecycle.opened != 3 || lifecycle.closed != 3 || lifecycle.maxLive != 1 {
		t.Fatalf("fixture counts opened=%d closed=%d maxLive=%d, want 3/3/1", lifecycle.opened, lifecycle.closed, lifecycle.maxLive)
	}
	for _, root := range lifecycle.roots {
		if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("fixture directory %q remains: stat err=%v", root, err)
		}
	}
}

type providerEnvelopeFixtureLifecycle struct {
	opened  int
	closed  int
	live    int
	maxLive int
	roots   []string
}

type providerEnvelopeBenchmarkFixtureData struct {
	ctx  context.Context
	keys *oidc.Keyring
	db   *rhiza.DB
	root string
}

func withProviderEnvelopeBenchmarkFixture(tb testing.TB, old bool, lifecycle *providerEnvelopeFixtureLifecycle, run func(context.Context, *oidc.Keyring, *rhiza.DB) error) (err error) {
	tb.Helper()
	fixture, err := openProviderEnvelopeBenchmarkFixture(tb, old)
	if err != nil {
		return err
	}
	if lifecycle != nil {
		lifecycle.opened++
		lifecycle.live++
		lifecycle.maxLive = max(lifecycle.maxLive, lifecycle.live)
		lifecycle.roots = append(lifecycle.roots, fixture.root)
	}
	defer func() {
		closeErr := fixture.close()
		if lifecycle != nil {
			lifecycle.closed++
			lifecycle.live--
		}
		if err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	return run(fixture.ctx, fixture.keys, fixture.db)
}

func openProviderEnvelopeBenchmarkFixture(tb testing.TB, old bool) (_ *providerEnvelopeBenchmarkFixtureData, err error) {
	tb.Helper()
	template := saasMigratedTemplate(tb)
	root, err := os.MkdirTemp("", "goauthy-provider-rewrap-")
	if err != nil {
		return nil, err
	}
	fixture := &providerEnvelopeBenchmarkFixtureData{ctx: context.Background(), root: root}
	defer func() {
		if err != nil {
			_ = fixture.close()
		}
	}()
	if err = copyDirTree(template, root); err != nil {
		return nil, err
	}
	fixture.db, err = rhiza.Open(fixture.ctx, rhiza.Config{NodeID: "saas-credential-test", DataDir: root})
	if err != nil {
		return nil, err
	}
	if _, err = storage.Execute(fixture.ctx, fixture.db, rhiza.ExecuteRequest{RequestID: "saas-credential-fence", SQL: `INSERT INTO master_key_retirement_barrier(barrier_id,epoch,old_key_id,replacement_key_id,membership_digest,state,prepared_at_unix_ms) VALUES (1,1,'old','master',?,'prepared',1)`, Args: []any{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}); err != nil {
		return nil, err
	}
	seedActive, active := "master", "master"
	if old {
		seedActive, active = "key-a", "key-b"
	}
	seedKeys, err := providerEnvelopeBenchmarkKeyring(tb, root, seedActive, "master", "key-a", "key-b")
	if err != nil {
		return nil, err
	}
	fixture.keys, err = providerEnvelopeBenchmarkKeyring(tb, root, active, "master", "key-a", "key-b")
	if err != nil {
		return nil, err
	}
	store, err := NewProviderStore(fixture.db, seedKeys)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 32; i++ {
		input := providerInputForTest("synthetic-provider-secret")
		input.ID = fmt.Sprintf("rewrap-%02d", i)
		input.Name = input.ID
		if _, err = store.Create(fixture.ctx, input, credentialAuthority()); err != nil {
			return nil, err
		}
	}
	return fixture, nil
}

func (f *providerEnvelopeBenchmarkFixtureData) close() error {
	var closeErr error
	if f.db != nil {
		closeErr = f.db.Close()
		f.db = nil
	}
	removeErr := os.RemoveAll(f.root)
	if closeErr != nil {
		return closeErr
	}
	return removeErr
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
				err := withProviderEnvelopeBenchmarkFixture(b, tc.old, nil, func(ctx context.Context, credentials *oidc.Keyring, db *rhiza.DB) error {
					b.StartTimer()
					result, err := RewrapProviderEnvelopeBatch(ctx, db, credentials, "")
					b.StopTimer()
					if err != nil {
						return errors.New("provider rewrap failed")
					}
					wantRewrapped := 0
					if tc.old {
						wantRewrapped = 32
					}
					if result.Rewrapped != wantRewrapped || result.Cursor != "rewrap-31" || result.Done {
						return fmt.Errorf("unexpected 32-row batch result: rewrapped=%d cursor=%q done=%v", result.Rewrapped, result.Cursor, result.Done)
					}
					if tc.old {
						family, err := InspectProviderEnvelopeReferences(ctx, db, credentials)
						if err != nil || family.Total != 32 || family.ByKeyID["key-b"] != 32 {
							return errors.New("rewrapped key-reference verification failed")
						}
					}
					// Each old-key row reaches one ExecuteEnvelope call in the
					// implementation. Rewrapped verifies all 32 CAS updates landed
					// in this isolated no-writer fixture; active rows submit none.
					return nil
				})
				if err != nil {
					b.Fatal("provider rewrap benchmark iteration failed")
				}
			}
		})
	}
}

func providerEnvelopeBenchmarkKeyring(tb testing.TB, root, active string, ids ...string) (*oidc.Keyring, error) {
	tb.Helper()
	dir, err := os.MkdirTemp(root, "keyring-")
	if err != nil {
		return nil, err
	}
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
