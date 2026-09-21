package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/apikey"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

// drtCanonicalTestToken is a valid 32-byte base64url browser token for test fixtures.
var drtCanonicalTestToken = func() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}()

var drtCanonicalTestDigest = func() string {
	d, _ := browser.CanonicalTokenDigest(drtCanonicalTestToken)
	return d
}()

const (
	drtLocalIssuer    = "https://local.example.test"
	drtUpstreamIssuer = "https://upstream.example.test"
	drtProviderID     = "AbCdEfGhIjKlMnOpQrStUvWx"
	drtStaticID       = "XyZaBcDeFgHiJkLmNoPqRsTu"
	drtClientID       = "test-client-id"
	drtAuthEP         = "https://upstream.example.test/authorize"
	drtTokenEP        = "https://upstream.example.test/token"
	drtUserInfoEP     = "https://upstream.example.test/userinfo"
)

var drtJWKSEP = "https://upstream.example.test/jwks"

type drtFixture struct {
	db         *rhiza.DB
	keyring    *oidc.Keyring
	store      *upstreamprovider.RegistryStore
	rhizaStore upstreamprovider.Store
	keys       *apikey.Store
	principal  *apikey.Principal
	ctx        context.Context
	t          *testing.T
}

func drtNewFixture(t *testing.T) *drtFixture {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "dispatcher-rt-test", DataDir: migratedDataDir(t, "dispatcher-rt-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{5}, 32))
	if err := os.WriteFile(filepath.Join(dir, "dev-1"), []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	kr, err := oidc.LoadKeyring(dir, "dev-1")
	if err != nil {
		t.Fatal(err)
	}
	rs, err := upstreamprovider.NewRegistryStore(db, kr)
	if err != nil {
		t.Fatal(err)
	}
	st, err := upstreamprovider.NewRhizaStore(db, kr)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := apikey.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := keys.Create(ctx, nil, apikey.Request{
		Name:   "drt-manager",
		Access: []apikey.Access{{Group: "AuthProviders", AccessRights: []apikey.Right{apikey.Create, apikey.Update, apikey.Delete}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	p, err := keys.Authenticate(ctx, "API-Key "+token)
	if err != nil {
		t.Fatal(err)
	}
	return &drtFixture{db: db, keyring: kr, store: rs, rhizaStore: st, keys: keys, principal: &p, ctx: ctx, t: t}
}

func (f *drtFixture) seedProvider(id string) {
	f.t.Helper()
	req := drtValidRequest()
	if _, err := f.store.CreateAuthorized(f.ctx, id, "seed/"+id, req, f.keys, f.principal); err != nil {
		f.t.Fatal(err)
	}
}

func (f *drtFixture) disableProvider(id string) {
	f.t.Helper()
	req := drtValidRequest()
	req.Name = "Disabled Provider"
	req.Enabled = false
	if _, err := f.store.UpdateAuthorized(f.ctx, id, "update/"+id, req, f.keys, f.principal); err != nil {
		f.t.Fatal(err)
	}
}

func (f *drtFixture) updateProviderBump(id string) {
	f.t.Helper()
	req := drtValidRequest()
	req.Name = "Updated Provider"
	if _, err := f.store.UpdateAuthorized(f.ctx, id, "bump/"+id, req, f.keys, f.principal); err != nil {
		f.t.Fatal(err)
	}
}

func drtValidRequest() upstreamprovider.ProviderRequest {
	return upstreamprovider.ProviderRequest{
		Name: "Test Provider", Typ: "oidc", Enabled: true,
		Issuer: drtUpstreamIssuer, AuthorizationEndpoint: drtAuthEP,
		TokenEndpoint: drtTokenEP, UserinfoEndpoint: drtUserInfoEP,
		ClientID: drtClientID, JWKS: &drtJWKSEP, Scope: "openid profile",
		UsePKCE: true, ClientSecretBasic: true, ClientSecretPost: false,
	}
}

func drtReadVersion(t *testing.T, db *rhiza.DB, id string) string {
	t.Helper()
	result, err := db.Query(t.Context(), rhiza.QueryRequest{
		SQL:  "SELECT version FROM auth_provider_runtime_versions WHERE provider_id=?",
		Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 {
		t.Fatalf("read version %s: rows=%d err=%v", id, len(result.Rows), err)
	}
	ver, ok := result.Rows[0][0].(string)
	if !ok || ver == "" {
		t.Fatalf("version %s: %v", id, result.Rows[0][0])
	}
	return ver
}

func drtFakeLocalHooks() upstreamprovider.LocalLoginHooks {
	return upstreamprovider.LocalLoginHooks{
		Prepare: func(r *http.Request, rawInteraction string) (string, string, string, error) {
			return drtCanonicalTestToken, drtCanonicalTestDigest, upstreamprovider.DigestSHA256(rawInteraction), nil
		},
		Current: func(r *http.Request) (string, string, error) {
			return drtCanonicalTestToken, drtCanonicalTestDigest, nil
		},
		Resolve: func(ctx context.Context, upstream upstreamprovider.SubjectResult) (string, error) {
			return "local-subject", nil
		},
		Complete: func(w http.ResponseWriter, r *http.Request, rawSessionToken, interactionDigest, localSubject string, upstream *upstreamprovider.OIDCSession) {
			w.WriteHeader(http.StatusOK)
		},
	}
}

func drtFakeLinkHooks() upstreamprovider.LinkHooks {
	return upstreamprovider.LinkHooks{
		Current: func(r *http.Request) (string, string, string, error) {
			return "", "", "", errors.New("no link session")
		},
		Link: func(ctx context.Context, localSubject string, upstream upstreamprovider.SubjectResult, now time.Time) (upstreamprovider.LinkDecision, error) {
			return upstreamprovider.LinkDecisionLinked, nil
		},
	}
}

func drtDispatcher(t *testing.T, f *drtFixture, staticIDs []string) *dynamicUpstreamDispatcher {
	t.Helper()
	return newDynamicUpstreamDispatcher(drtLocalIssuer, f.store, f.rhizaStore, staticIDs, nil,
		drtFakeLocalHooks(), drtFakeLinkHooks(), func(_ context.Context, _ oauth.UpstreamLogout) error { return nil })
}

func drtMux(d *dynamicUpstreamDispatcher) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("GET /upstream/{providerID}/start", d)
	mux.Handle("GET /upstream/{providerID}/callback", d)
	return mux
}

func TestDynamicDispatcherReservesStaticIDs(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	f.seedProvider(drtStaticID)
	d := drtDispatcher(t, f, []string{drtStaticID})
	mux := drtMux(d)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest("GET", "/upstream/"+drtStaticID+"/start?redirect_uri="+url.QueryEscape(drtLocalIssuer+"/upstream/"+drtStaticID+"/callback")+"&interaction=test", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("static ID dispatch: got %d, want 404", rec.Code)
	}
}

func TestDynamicDispatcherRejectsEmptyProviderID(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	d := drtDispatcher(t, f, nil)
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest("GET", "/upstream//start", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("empty ID: got %d, want 404", rec.Code)
	}
}

func TestDynamicDispatcherRejectsInvalidProviderID(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	d := drtDispatcher(t, f, nil)
	for _, id := range []string{"short", "AbCdEfGhIjKl!", strings.Repeat("a", 25)} {
		rec := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/upstream/"+id+"/start", nil)
		r.SetPathValue("providerID", id)
		d.ServeHTTP(rec, r)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("invalid ID %q: got %d, want 404", id, rec.Code)
		}
	}
}

func TestDynamicDispatcherMissingProviderNotFound(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	d := drtDispatcher(t, f, nil)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/upstream/"+drtProviderID+"/start", nil)
	r.SetPathValue("providerID", drtProviderID)
	d.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing provider: got %d, want 404", rec.Code)
	}
}

func TestDynamicDispatcherDisabledProviderNotFound(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	f.seedProvider(drtProviderID)
	f.disableProvider(drtProviderID)
	_, _, err := f.store.GetRuntime(f.ctx, drtProviderID)
	if !errors.Is(err, upstreamprovider.ErrProviderNotFound) {
		t.Fatalf("disabled GetRuntime: err=%v", err)
	}
	d := drtDispatcher(t, f, nil)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/upstream/"+drtProviderID+"/start", nil)
	r.SetPathValue("providerID", drtProviderID)
	d.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled provider: got %d, want 404", rec.Code)
	}
}

func TestDynamicDispatcherExistsDisabledReturnsFalse(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	f.seedProvider(drtProviderID)
	d := drtDispatcher(t, f, nil)
	ok, err := d.exists(context.Background(), drtProviderID)
	if err != nil || !ok {
		t.Fatalf("exists(enabled): ok=%v err=%v, want true/nil", ok, err)
	}
	f.disableProvider(drtProviderID)
	ok, err = d.exists(context.Background(), drtProviderID)
	if err != nil || !ok {
		t.Fatalf("exists(disabled): ok=%v err=%v, want true/nil (row still exists)", ok, err)
	}
	ok, err = d.exists(context.Background(), "NnNnNnNnNnNnNnNnNnNnNnNn")
	if err != nil || ok {
		t.Fatalf("exists(missing): ok=%v err=%v, want false/nil", ok, err)
	}
}

func TestDynamicDispatcherExistsClosedDBError(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	f.seedProvider(drtProviderID)
	d := drtDispatcher(t, f, nil)
	_ = f.db.Close()
	_, err := d.exists(context.Background(), drtProviderID)
	if err == nil {
		t.Fatal("exists(closed DB): expected error, got nil")
	}
}

func TestDynamicDispatcherVersionMissingNotFound(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	f.seedProvider(drtProviderID)
	if _, err := storage.Execute(f.ctx, f.db, rhiza.ExecuteRequest{
		RequestID: "del-ver-drt", SQL: "DELETE FROM auth_provider_runtime_versions WHERE provider_id=?", Args: []any{drtProviderID},
	}); err != nil {
		t.Fatal(err)
	}
	d := drtDispatcher(t, f, nil)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/upstream/"+drtProviderID+"/start", nil)
	r.SetPathValue("providerID", drtProviderID)
	d.ServeHTTP(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("version missing: got %d, want 404", rec.Code)
	}
}

func TestDynamicDispatcherCreateAfterConstructLocalStart(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	d := drtDispatcher(t, f, nil)
	mux := drtMux(d)
	f.seedProvider(drtProviderID)
	wantCallback := drtLocalIssuer + "/upstream/" + drtProviderID + "/callback"
	rec := httptest.NewRecorder()
	reqURL := "/upstream/" + drtProviderID + "/start?redirect_uri=" + url.QueryEscape(wantCallback) + "&interaction=test-interaction"
	mux.ServeHTTP(rec, httptest.NewRequest("GET", reqURL, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("/start: got %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if !strings.HasPrefix(loc.String(), drtUpstreamIssuer) {
		t.Fatalf("auth URL base = %s, want prefix %s", loc.String(), drtUpstreamIssuer)
	}
	gotCallback := loc.Query().Get("redirect_uri")
	if gotCallback != wantCallback {
		t.Fatalf("redirect_uri = %q, want %q", gotCallback, wantCallback)
	}
	if drtUpstreamIssuer == drtLocalIssuer {
		t.Fatal("upstream and local issuers must differ")
	}
}

func TestDynamicDispatcherStartPersistsTxSourceAndVersion(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	d := drtDispatcher(t, f, nil)
	mux := drtMux(d)
	f.seedProvider(drtProviderID)
	wantCallback := drtLocalIssuer + "/upstream/" + drtProviderID + "/callback"
	startRec := httptest.NewRecorder()
	reqURL := "/upstream/" + drtProviderID + "/start?redirect_uri=" + url.QueryEscape(wantCallback) + "&interaction=inspect-tx"
	mux.ServeHTTP(startRec, httptest.NewRequest("GET", reqURL, nil))
	if startRec.Code != http.StatusFound {
		t.Fatalf("/start: got %d, want 302; body=%s", startRec.Code, startRec.Body.String())
	}
	loc, err := url.Parse(startRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("no state in auth URL")
	}
	// LocalStartHandler uses sessionDigest as the browser binding.
	sessionDigest := drtCanonicalTestDigest
	stateDigest := upstreamprovider.DigestSHA256(state)
	now := time.Now().UTC()
	tx, err := f.rhizaStore.Consume(f.ctx, stateDigest, sessionDigest, drtProviderID, now)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if tx.ProviderSource != "registry" {
		t.Fatalf("tx.ProviderSource = %q, want registry", tx.ProviderSource)
	}
	if tx.RuntimeVersion == "" {
		t.Fatal("tx.RuntimeVersion is empty")
	}
	cfg, _, err := f.store.RuntimeConfig(f.ctx, drtProviderID)
	if err != nil {
		t.Fatalf("RuntimeConfig: %v", err)
	}
	if tx.RuntimeVersion != cfg.RuntimeVersion {
		t.Fatalf("tx.RuntimeVersion = %q, cfg = %q", tx.RuntimeVersion, cfg.RuntimeVersion)
	}
	if tx.ProviderID != drtProviderID {
		t.Fatalf("tx.ProviderID = %q, want %q", tx.ProviderID, drtProviderID)
	}
}

func TestDynamicDispatcherAllThreeProtocolFlagsFromDB(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	f.seedProvider(drtProviderID)
	cfg, _, err := f.store.RuntimeConfig(f.ctx, drtProviderID)
	if err != nil {
		t.Fatalf("RuntimeConfig: %v", err)
	}
	if cfg.Protocol.UsePKCE == nil || !*cfg.Protocol.UsePKCE {
		t.Fatal("UsePKCE not true")
	}
	if cfg.Protocol.ClientSecretBasic == nil || !*cfg.Protocol.ClientSecretBasic {
		t.Fatal("ClientSecretBasic not true")
	}
	if cfg.Protocol.ClientSecretPost == nil || *cfg.Protocol.ClientSecretPost {
		t.Fatal("ClientSecretPost should be false")
	}
}

func TestDynamicDispatcherVersionChangedCallbackFailsClosed(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	d := drtDispatcher(t, f, nil)
	mux := drtMux(d)
	f.seedProvider(drtProviderID)
	v1 := drtReadVersion(t, f.db, drtProviderID)
	wantCallback := drtLocalIssuer + "/upstream/" + drtProviderID + "/callback"
	startRec := httptest.NewRecorder()
	reqURL := "/upstream/" + drtProviderID + "/start?redirect_uri=" + url.QueryEscape(wantCallback) + "&interaction=sess"
	mux.ServeHTTP(startRec, httptest.NewRequest("GET", reqURL, nil))
	if startRec.Code != http.StatusFound {
		t.Fatalf("/start: got %d, want 302; body=%s", startRec.Code, startRec.Body.String())
	}
	loc, err := url.Parse(startRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("no state in auth URL")
	}
	cookies := startRec.Result().Cookies()
	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "__Host-goauthy_upstream_state" {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("missing state cookie")
	}
	// Bump version via UpdateAuthorized (real mutation path).
	f.updateProviderBump(drtProviderID)
	v2 := drtReadVersion(t, f.db, drtProviderID)
	if v2 == v1 {
		t.Fatalf("version did not change: %q", v2)
	}
	cbRec := httptest.NewRecorder()
	cbURL := "/upstream/" + drtProviderID + "/callback?state=" + url.QueryEscape(state) + "&code=dummy-code"
	cbReq := httptest.NewRequest("GET", cbURL, nil)
	cbReq.AddCookie(stateCookie)
	mux.ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusBadRequest {
		t.Fatalf("version-changed callback: got %d, want 400; body=%s", cbRec.Code, cbRec.Body.String())
	}
}

func TestDynamicDispatcherMountDynamicRoutes(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	d := drtDispatcher(t, f, nil)
	mux := http.NewServeMux()
	mountDynamicUpstreamRoutes(mux, d, nil)
	for _, path := range []string{
		"/upstream/" + drtProviderID + "/start",
		"/upstream/" + drtProviderID + "/callback",
	} {
		req := httptest.NewRequest("GET", path, nil)
		_, pattern := mux.Handler(req)
		if pattern == "" {
			t.Fatalf("%s: route not registered", path)
		}
	}
}

func TestDynamicDispatcherConsumeRejectsClosedDB(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	_ = f.db.Close()
	_, err := f.rhizaStore.Consume(f.ctx, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", "someprovider", time.Now())
	if err == nil {
		t.Fatal("Consume(closed DB): expected error, got nil")
	}
}

// TestDynamicDispatcherReusesManagedJWKSCache covers the public managed
// backchannel endpoint: sequential dispatches of one provider version must share
// a verifier so an invalid logout token cannot drive a fresh JWKS fetch per
// request, and a configuration change must select a new cache identity.
func TestDynamicDispatcherReusesManagedJWKSCache(t *testing.T) {
	t.Parallel()
	f := drtNewFixture(t)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: privateKey.Public(), KeyID: "k1", Algorithm: "EdDSA", Use: "sig"}}}
	var fetches atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(keys)
	}))
	defer server.Close()

	seed := drtValidRequest()
	seed.JWKS = &server.URL
	if _, err := f.store.CreateAuthorized(f.ctx, drtProviderID, "seed/jwks-cache", seed, f.keys, f.principal); err != nil {
		t.Fatal(err)
	}
	d := drtDispatcher(t, f, nil)
	d.client = server.Client()
	mux := http.NewServeMux()
	mountDynamicUpstreamRoutes(mux, d, nil)

	token := unknownKeyLogoutToken()
	dispatch := func() int64 {
		t.Helper()
		form := url.Values{"logout_token": {token}}
		req := httptest.NewRequest(http.MethodPost, "/upstream/"+drtProviderID+"/backchannel-logout", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("logout dispatch: got %d, want 400; body=%s", rec.Code, rec.Body.String())
		}
		return fetches.Load()
	}

	first := dispatch()
	second := dispatch()
	if second != first {
		t.Fatalf("second dispatch refetched JWKS: %d then %d", first, second)
	}
	if first == 0 {
		t.Fatal("dispatches did not reach the JWKS endpoint through the dispatcher's shared client")
	}

	// A configuration change must not reuse keys fetched under the old version.
	seed.Name = "Updated Provider"
	if _, err := f.store.UpdateAuthorized(f.ctx, drtProviderID, "bump/jwks-cache", seed, f.keys, f.principal); err != nil {
		t.Fatal(err)
	}
	if bumped := dispatch(); bumped <= first {
		t.Fatalf("provider version change reused the previous JWKS cache: %d then %d", first, bumped)
	}
}

// unknownKeyLogoutToken is a well-formed compact JWS whose kid is absent from
// the fetched key set, which also exercises the verifier's miss refresh.
func unknownKeyLogoutToken() string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"unknown-key"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"` + drtUpstreamIssuer + `"}`))
	return header + "." + payload + "." + base64.RawURLEncoding.EncodeToString([]byte("signature"))
}
