package upstreamprovider

import (
	"errors"
	"testing"
	"time"
)

// --- Rhiza envelope roundtrip: version + source ---

func TestRhizaStoreRuntimeBindingRoundTrip(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	tx.ProviderSource = "registry"
	tx.RuntimeVersion = "v1.2.3"
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	got, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProviderSource != "registry" || got.RuntimeVersion != "v1.2.3" {
		t.Fatalf("runtime binding = (%q, %q), want %q %q", "registry", "v1.2.3", got.ProviderSource, got.RuntimeVersion)
	}
}

func TestRhizaStoreRuntimeBindingSourceOnlyRejects(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	tx.ProviderSource = "registry"
	tx.RuntimeVersion = ""
	if err := store.Save(ctx, tx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("partial source: error=%v, want ErrInvalidConfig", err)
	}
}

func TestRhizaStoreRuntimeBindingVersionOnlyRejects(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	tx.ProviderSource = ""
	tx.RuntimeVersion = "v1.0"
	if err := store.Save(ctx, tx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("partial version: error=%v, want ErrInvalidConfig", err)
	}
}

func TestRhizaStoreRuntimeBindingUnknownSourceRejects(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	tx.ProviderSource = "unknown"
	tx.RuntimeVersion = "v1.0"
	if err := store.Save(ctx, tx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unknown source: error=%v, want ErrInvalidConfig", err)
	}
}

func TestRhizaStoreRuntimeBindingMalformedVersionRejects(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	tx.ProviderSource = "registry"
	tx.RuntimeVersion = "v1.0 with spaces"
	if err := store.Save(ctx, tx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("malformed version: error=%v, want ErrInvalidConfig", err)
	}
}

func TestRhizaStoreRuntimeBindingLongVersionRejects(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	tx.ProviderSource = "registry"
	long := ""
	for i := 0; i < 129; i++ {
		long += "a"
	}
	tx.RuntimeVersion = long
	if err := store.Save(ctx, tx); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("long version: error=%v, want ErrInvalidConfig", err)
	}
}

func TestRhizaStoreLegacyRuntimeBindingBothEmpty(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	tx.ProviderSource = ""
	tx.RuntimeVersion = ""
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	got, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProviderSource != "" || got.RuntimeVersion != "" {
		t.Fatalf("legacy binding = (%q, %q), want empty", got.ProviderSource, got.RuntimeVersion)
	}
}

// --- ValidateRuntimeBinding unit tests ---

func TestValidateRuntimeBindingBothEmpty(t *testing.T) {
	t.Parallel()
	if err := validateRuntimeBinding("", ""); err != nil {
		t.Fatalf("both empty: %v", err)
	}
}

func TestValidateRuntimeBindingRegistryManaged(t *testing.T) {
	t.Parallel()
	if err := validateRuntimeBinding("registry", "v1.0"); err != nil {
		t.Fatalf("registry v1.0: %v", err)
	}
}

func TestValidateRuntimeBindingRegistryMaxVersion(t *testing.T) {
	t.Parallel()
	max := ""
	for i := 0; i < 128; i++ {
		max += "a"
	}
	if err := validateRuntimeBinding("registry", max); err != nil {
		t.Fatalf("max version: %v", err)
	}
}

func TestValidateRuntimeBindingPartialSource(t *testing.T) {
	t.Parallel()
	if err := validateRuntimeBinding("registry", ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("partial source: %v", err)
	}
}

func TestValidateRuntimeBindingPartialVersion(t *testing.T) {
	t.Parallel()
	if err := validateRuntimeBinding("", "v1.0"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("partial version: %v", err)
	}
}

func TestValidateRuntimeBindingUnknownSource(t *testing.T) {
	t.Parallel()
	if err := validateRuntimeBinding("external", "v1.0"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unknown source: %v", err)
	}
}

func TestValidateRuntimeBindingMalformedVersion(t *testing.T) {
	t.Parallel()
	for _, v := range []string{"v1.0 beta", "v1.0@latest", "v1.0#bad"} {
		if err := validateRuntimeBinding("registry", v); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("version %q: %v", v, err)
		}
	}
}

func TestValidateRuntimeBindingLongVersion(t *testing.T) {
	t.Parallel()
	long := ""
	for i := 0; i < 129; i++ {
		long += "a"
	}
	if err := validateRuntimeBinding("registry", long); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("long version: %v", err)
	}
}

// --- AuthURL params -> saved binding ---

func TestGenerateAuthURLCopiesRuntimeBinding(t *testing.T) {
	t.Parallel()
	cfg, p, store, params, binding, now := authProtocolFixture(t)
	params.ProviderSource = "registry"
	params.RuntimeVersion = "v2.0"
	result := mustGenAuthURL(t, cfg, p, store, params, binding, now)
	if result.Transaction.ProviderSource != "registry" {
		t.Fatalf("ProviderSource = %q, want registry", result.Transaction.ProviderSource)
	}
	if result.Transaction.RuntimeVersion != "v2.0" {
		t.Fatalf("RuntimeVersion = %q, want v2.0", result.Transaction.RuntimeVersion)
	}
}

func TestGenerateAuthURLRejectsPartialRuntimeBinding(t *testing.T) {
	t.Parallel()
	cfg, p, _, _, binding, _ := authProtocolFixture(t)
	params := AuthorizationParams{
		CallbackURI:    "https://app.example.com/cb",
		Scopes:         []string{"openid", "profile"},
		ProviderSource: "registry",
		RuntimeVersion: "",
	}
	_, err := GenerateAuthorizationURL(
		nil, p, cfg, newTestStore(), params, binding, "google", time.Now(),
	)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("partial binding in auth URL: %v", err)
	}
}

func TestGenerateAuthURLRejectsUnknownSource(t *testing.T) {
	t.Parallel()
	cfg, p, _, _, binding, _ := authProtocolFixture(t)
	params := AuthorizationParams{
		CallbackURI:    "https://app.example.com/cb",
		Scopes:         []string{"openid", "profile"},
		ProviderSource: "external",
		RuntimeVersion: "v1.0",
	}
	_, err := GenerateAuthorizationURL(
		nil, p, cfg, newTestStore(), params, binding, "google", time.Now(),
	)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unknown source in auth URL: %v", err)
	}
}

// --- Replay rejection with runtime binding ---

func TestRhizaStoreRuntimeBindingReplayRejects(t *testing.T) {
	t.Parallel()
	ctx, store, _ := testRhizaStore(t)
	tx := testRhizaTransaction()
	tx.ProviderSource = "registry"
	tx.RuntimeVersion = "v1.0"
	if err := store.Save(ctx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Consume(ctx, tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, tx.CreatedAt); !errors.Is(err, ErrTransactionAlreadyConsumed) {
		t.Fatalf("replay error=%v", err)
	}
}
