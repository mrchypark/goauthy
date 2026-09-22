package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/account"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
	"github.com/mrchypark/goauthy/internal/storage"
)

// stubStore satisfies upstreamprovider.Store without a real DB.
type stubStore struct{}

func (stubStore) Save(context.Context, upstreamprovider.Transaction) error { return nil }
func (stubStore) Consume(context.Context, string, string, string, time.Time) (upstreamprovider.Transaction, error) {
	return upstreamprovider.Transaction{}, nil
}

// stubExchanger satisfies upstreamprovider.TokenExchanger.
type stubExchanger struct{}

func (stubExchanger) ExchangeCode(context.Context, string, string, string, string) (*upstreamprovider.TokenExchangeResult, error) {
	return nil, nil
}

// stubVerifier satisfies upstreamprovider.TokenVerifier.
type stubVerifier struct{}

func (stubVerifier) VerifyIDToken(context.Context, string, string, string) (*upstreamprovider.IDTokenClaims, error) {
	return nil, nil
}

func coexistTestDB(t *testing.T) *rhiza.DB {
	t.Helper()
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "coexist-test", DataDir: migratedDataDir(t, "coexist-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

func coexistTestAccountHandler(t *testing.T, db *rhiza.DB) *account.Handler {
	t.Helper()
	browserStore, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	identityStore, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	h, err := account.New("https://goauthy.test", browserStore, identityStore, credential.DefaultRules())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func coexistTestUpstreamRuntime(t *testing.T) *upstreamRuntime {
	t.Helper()
	configs := map[string]upstreamprovider.Config{"static": {
		Kind:                  upstreamprovider.ProviderKindOIDC,
		Issuer:                "https://issuer.example.test",
		AuthorizationEndpoint: "https://issuer.example.test/authorize",
		TokenEndpoint:         "https://issuer.example.test/token",
		JWKSURI:               "https://issuer.example.test/jwks",
		ClientID:              "client",
	}}
	allowedCallbacks := map[string]bool{"https://goauthy.test/upstream/static/callback": true}
	callbacks := map[string]string{"static": "https://goauthy.test/upstream/static/callback"}
	hooks := upstreamprovider.LocalLoginHooks{
		Prepare:  func(*http.Request, string) (string, string, string, error) { return "", "", "", nil },
		Current:  func(*http.Request) (string, string, error) { return "", "", nil },
		Resolve:  func(context.Context, upstreamprovider.SubjectResult) (string, error) { return "", nil },
		Complete: func(http.ResponseWriter, *http.Request, string, string, string, *upstreamprovider.OIDCSession) {},
	}
	linkHooks := upstreamprovider.LinkHooks{
		Current: func(*http.Request) (string, string, string, error) { return "", "", "", nil },
		Link:    func(context.Context, string, upstreamprovider.SubjectResult, time.Time) (upstreamprovider.LinkDecision, error) { return 0, nil },
	}
	handler, err := upstreamprovider.NewLocalLoginAndLinkHandler(configs, stubStore{}, stubExchanger{}, stubVerifier{}, nil, allowedCallbacks, hooks, callbacks, linkHooks)
	if err != nil {
		t.Fatal(err)
	}
	return &upstreamRuntime{handler: handler, callbacks: callbacks, providerIDs_: []string{"static"}, localHooks: hooks, linkHooks: linkHooks}
}

func TestCoexistStaticDynamicNoPanic(t *testing.T) {
	t.Parallel()
	db := coexistTestDB(t)
	accountHandler := coexistTestAccountHandler(t, db)
	runtime := coexistTestUpstreamRuntime(t)
	if err := accountHandler.ConfigureExternalLinks(
		runtime.handler.LinkStartHandler(), runtime.providerIDs(),
	); err != nil {
		t.Fatal(err)
	}
	dynamic := newDynamicUpstreamDispatcher(
		"https://goauthy.test",
		nil,
		stubStore{},
		runtime.providerIDs(),
		runtime.handler.LinkStartHandler(),
		runtime.localHooks,
		runtime.linkHooks,
		nil,
	)
	mux := http.NewServeMux()
	mountUpstreamRoutes(mux, runtime, accountHandler, nil)
	mountDynamicUpstreamRoutes(mux, dynamic, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/v1/providers/static/link", nil))
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("POST link: expected 401 or 403, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/static/link", nil))
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("DELETE link: expected 401 or 403, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/upstream/static/start?redirect_uri=https://goauthy.test/upstream/static/callback", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatalf("static start returned 404")
	}
}

func TestCoexistDynamicOnlyLinks(t *testing.T) {
	t.Parallel()
	db := coexistTestDB(t)
	accountHandler := coexistTestAccountHandler(t, db)
	dynamic := newDynamicUpstreamDispatcher(
		"https://goauthy.test",
		nil,
		stubStore{},
		nil,
		nil,
		upstreamprovider.LocalLoginHooks{
			Prepare:  func(*http.Request, string) (string, string, string, error) { return "", "", "", nil },
			Current:  func(*http.Request) (string, string, error) { return "", "", nil },
			Resolve:  func(context.Context, upstreamprovider.SubjectResult) (string, error) { return "", nil },
			Complete: func(http.ResponseWriter, *http.Request, string, string, string, *upstreamprovider.OIDCSession) {},
		},
		upstreamprovider.LinkHooks{
			Current: func(*http.Request) (string, string, string, error) { return "", "", "", nil },
			Link:    func(context.Context, string, upstreamprovider.SubjectResult, time.Time) (upstreamprovider.LinkDecision, error) { return 0, nil },
		},
		nil,
	)
	if err := accountHandler.ConfigureDynamicExternalLinks(
		dynamic.linkStartHandler(), dynamic.exists,
	); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mountDynamicUpstreamRoutes(mux, dynamic, accountHandler)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/v1/providers/dyn00000000000000001/link", nil))
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("dynamic-only POST link: expected 401 or 403, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/auth/v1/providers/dyn00000000000000001/link", nil))
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Fatalf("dynamic-only DELETE link: expected 401 or 403, got %d", rec.Code)
	}
}

func TestLegacyNilStaticReturnsNoRoutes(t *testing.T) {
	t.Parallel()
	mux := http.NewServeMux()
	mountUpstreamRoutes(mux, nil, nil, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/v1/providers/foo/link", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unregistered route, got %d", rec.Code)
	}
}
