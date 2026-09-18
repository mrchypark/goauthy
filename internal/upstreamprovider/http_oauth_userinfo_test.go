package upstreamprovider

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

// TestOAuthUserInfoCallback tests genericOAuth (oauth_userinfo) callback
// integration through LocalStartHandler + LocalCallbackHandler with a real
// TLS token and userinfo server, real OAuth2TokenExchanger, no ID token or JWKS.
// Three focused cases: success, replay rejection, changed-version rejection.
func TestOAuthUserInfoCallback(t *testing.T) {
	const (
		providerID = managedID
		at         = "access-token-ot"
		knownSub   = "AbCdEfGhIjKlMnOpQrStUvWx"
		issuer     = "https://issuer.example.test"
		clientID   = "test-client"
	)

	var tokenHits, userinfoHits atomic.Int32

	// Real TLS token server: returns Bearer access_token.
	tokenSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": at, "token_type": "Bearer"})
	}))
	defer tokenSrv.Close()

	// Real TLS userinfo server: returns known sub.
	userinfoSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userinfoHits.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer "+at {
			t.Errorf("userinfo auth = %q, want Bearer %s", got, at)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": knownSub})
	}))
	defer userinfoSrv.Close()

	cfg := Config{
		Kind:                  ProviderKindOAuthUserInfo,
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/auth",
		TokenEndpoint:         tokenSrv.URL,
		UserInfoEndpoint:      userinfoSrv.URL,
		ClientID:              clientID,
		Scopes:                []string{"openid", "profile"},
		Protocol: ProviderProtocol{
			UsePKCE:           boolPtr(true),
			ClientSecretBasic: boolPtr(true),
			ClientSecretPost:  boolPtr(false),
		},
		ProviderSource: "registry",
		RuntimeVersion: "v1",
	}

	exchanger, err := NewOAuth2TokenExchanger(
		map[string]Config{providerID: cfg},
		map[string]string{providerID: "client-secret"},
		testOnlyClientTrustedCA(tokenSrv),
	)
	if err != nil {
		t.Fatal(err)
	}

	// --- Case 1: successful callback ---
	t.Run("success", func(t *testing.T) {
		tokenHits.Store(0)
		userinfoHits.Store(0)
		hooks := &localHookRecorder{
			session:     testCanonicalTestToken,
			digest:      testCanonicalTestDigest,
			interaction: DigestSHA256("interaction"),
		}
		store := newTestStore()
		verifier, vErr := NewJWKSVerifier(map[string]Config{providerID: cfg}, nil)
		if vErr != nil {
			t.Fatal(vErr)
		}
		h, err := NewLocalLoginHandler(
			map[string]Config{providerID: cfg},
			store, exchanger, verifier,
			newCryptoProvider(newFixedRandom(make([]byte, 256))),
			map[string]bool{"https://app.example.com/callback": true},
			hooks.hooks(),
		)
		if err != nil {
			t.Fatal(err)
		}
		h.now = func() time.Time { return fixedNow }

		// Start
		startRec := httptest.NewRecorder()
		startReq := httptest.NewRequest(http.MethodGet,
			"/upstream/"+providerID+"/start?redirect_uri=https://app.example.com/callback&interaction=interaction", nil)
		startReq.SetPathValue("providerID", providerID)
		h.LocalStartHandler().ServeHTTP(startRec, startReq)
		if startRec.Code != http.StatusFound {
			t.Fatalf("start status=%d body=%q", startRec.Code, startRec.Body.String())
		}
		stateCookie, _ := getCookies(t, startRec)
		startURL, _ := url.Parse(startRec.Header().Get("Location"))
		state := startURL.Query().Get("state")

		// Callback
		cbRec := httptest.NewRecorder()
		cbReq := httptest.NewRequest(http.MethodGet,
			"/upstream/"+providerID+"/callback?state="+url.QueryEscape(state)+"&code=auth-code", nil)
		cbReq.SetPathValue("providerID", providerID)
		if stateCookie != nil {
			cbReq.AddCookie(stateCookie)
		}
		h.LocalCallbackHandler().ServeHTTP(cbRec, cbReq)

		if cbRec.Code != http.StatusNoContent {
			t.Fatalf("success status=%d body=%q", cbRec.Code, cbRec.Body.String())
		}
		if got := tokenHits.Load(); got != 1 {
			t.Fatalf("token requests=%d, want 1", got)
		}
		if got := userinfoHits.Load(); got != 1 {
			t.Fatalf("userinfo requests=%d, want 1", got)
		}
		hooks.mu.Lock()
		resolved := hooks.resolved
		gotUpstream := hooks.gotUpstream
		gotOIDC := hooks.gotOIDC
		completed := hooks.completed
		hooks.mu.Unlock()

		if resolved != 1 {
			t.Fatalf("resolve calls=%d, want 1", resolved)
		}
		if gotUpstream.Subject != knownSub {
			t.Fatalf("resolved subject=%q, want %q", gotUpstream.Subject, knownSub)
		}
		if gotUpstream.ProviderID != providerID {
			t.Fatalf("resolved providerID=%q, want %q", gotUpstream.ProviderID, providerID)
		}
		ns := computeNamespace(issuer, clientID)
		if gotUpstream.IdentityNamespace == "" {
			t.Fatalf("IdentityNamespace is empty, want %q", ns)
		}
		if gotUpstream.IdentityNamespace != ns {
			t.Fatalf("IdentityNamespace=%q, want %q", gotUpstream.IdentityNamespace, ns)
		}
		if completed != 1 {
			t.Fatalf("complete calls=%d, want 1", completed)
		}
		if gotOIDC != nil {
			t.Fatalf("Complete received non-nil OIDCSession: %#v", gotOIDC)
		}
		// Verify transaction namespace consistent with cfg.
		store.mu.Lock()
		var tx Transaction
		for _, v := range store.transactions {
			tx = v
			break
		}
		store.mu.Unlock()
		if tx.Issuer != issuer {
			t.Fatalf("tx.Issuer=%q, want %q", tx.Issuer, issuer)
		}
		if tx.ClientID != clientID {
			t.Fatalf("tx.ClientID=%q, want %q", tx.ClientID, clientID)
		}
	})

	// --- Case 2: replay same callback must fail ---
	t.Run("replay_rejects", func(t *testing.T) {
		tokenHits.Store(0)
		userinfoHits.Store(0)
		hooks := &localHookRecorder{
			session:     testCanonicalTestToken,
			digest:      testCanonicalTestDigest,
			interaction: DigestSHA256("interaction"),
		}
		store := newTestStore()
		verifier, vErr := NewJWKSVerifier(map[string]Config{providerID: cfg}, nil)
		if vErr != nil {
			t.Fatal(vErr)
		}
		h, err := NewLocalLoginHandler(
			map[string]Config{providerID: cfg},
			store, exchanger, verifier,
			newCryptoProvider(newFixedRandom(make([]byte, 256))),
			map[string]bool{"https://app.example.com/callback": true},
			hooks.hooks(),
		)
		if err != nil {
			t.Fatal(err)
		}
		h.now = func() time.Time { return fixedNow }

		startRec := httptest.NewRecorder()
		startReq := httptest.NewRequest(http.MethodGet,
			"/upstream/"+providerID+"/start?redirect_uri=https://app.example.com/callback&interaction=interaction", nil)
		startReq.SetPathValue("providerID", providerID)
		h.LocalStartHandler().ServeHTTP(startRec, startReq)
		if startRec.Code != http.StatusFound {
			t.Fatalf("start status=%d", startRec.Code)
		}
		stateCookie, _ := getCookies(t, startRec)
		startURL, _ := url.Parse(startRec.Header().Get("Location"))
		state := startURL.Query().Get("state")

		// First callback succeeds.
		first := httptest.NewRecorder()
		firstReq := httptest.NewRequest(http.MethodGet,
			"/upstream/"+providerID+"/callback?state="+url.QueryEscape(state)+"&code=auth-code", nil)
		firstReq.SetPathValue("providerID", providerID)
		if stateCookie != nil {
			firstReq.AddCookie(stateCookie)
		}
		h.LocalCallbackHandler().ServeHTTP(first, firstReq)
		if first.Code != http.StatusNoContent {
			t.Fatalf("first callback status=%d", first.Code)
		}

		// Replay same callback must fail.
		replay := httptest.NewRecorder()
		replayReq := httptest.NewRequest(http.MethodGet,
			"/upstream/"+providerID+"/callback?state="+url.QueryEscape(state)+"&code=auth-code", nil)
		replayReq.SetPathValue("providerID", providerID)
		if stateCookie != nil {
			replayReq.AddCookie(stateCookie)
		}
		h.LocalCallbackHandler().ServeHTTP(replay, replayReq)
		if replay.Code != http.StatusBadRequest {
			t.Fatalf("replay status=%d, want %d", replay.Code, http.StatusBadRequest)
		}
		// Zero additional token/userinfo requests after the first success.
		if got := tokenHits.Load(); got != 1 {
			t.Fatalf("token requests=%d, want 1 (no additional after replay)", got)
		}
		if got := userinfoHits.Load(); got != 1 {
			t.Fatalf("userinfo requests=%d, want 1 (no additional after replay)", got)
		}
	})

	// --- Case 3: changed version rejects BEFORE token/userinfo ---
	t.Run("changed_version_rejects", func(t *testing.T) {
		tokenHits.Store(0)
		userinfoHits.Store(0)
		hooks := &localHookRecorder{
			session:     testCanonicalTestToken,
			digest:      testCanonicalTestDigest,
			interaction: DigestSHA256("interaction"),
		}
		store := newTestStore()
		verifier, vErr := NewJWKSVerifier(map[string]Config{providerID: cfg}, nil)
		if vErr != nil {
			t.Fatal(vErr)
		}
		h, err := NewLocalLoginHandler(
			map[string]Config{providerID: cfg},
			store, exchanger, verifier,
			newCryptoProvider(newFixedRandom(make([]byte, 256))),
			map[string]bool{"https://app.example.com/callback": true},
			hooks.hooks(),
		)
		if err != nil {
			t.Fatal(err)
		}
		h.now = func() time.Time { return fixedNow }

		// Start with v1.
		startRec := httptest.NewRecorder()
		startReq := httptest.NewRequest(http.MethodGet,
			"/upstream/"+providerID+"/start?redirect_uri=https://app.example.com/callback&interaction=interaction", nil)
		startReq.SetPathValue("providerID", providerID)
		h.LocalStartHandler().ServeHTTP(startRec, startReq)
		if startRec.Code != http.StatusFound {
			t.Fatalf("start status=%d", startRec.Code)
		}
		stateCookie, _ := getCookies(t, startRec)
		startURL, _ := url.Parse(startRec.Header().Get("Location"))
		state := startURL.Query().Get("state")

		// Swap handler config to v2 (simulates runtime upgrade).
		cfgV2 := cfg
		cfgV2.RuntimeVersion = "v2"
		h.configs[providerID] = cfgV2

		// Callback must reject BEFORE any token/userinfo request.
		cbRec := httptest.NewRecorder()
		cbReq := httptest.NewRequest(http.MethodGet,
			"/upstream/"+providerID+"/callback?state="+url.QueryEscape(state)+"&code=auth-code", nil)
		cbReq.SetPathValue("providerID", providerID)
		if stateCookie != nil {
			cbReq.AddCookie(stateCookie)
		}
		h.LocalCallbackHandler().ServeHTTP(cbRec, cbReq)
		if cbRec.Code != http.StatusBadRequest {
			t.Fatalf("changed version status=%d, want %d", cbRec.Code, http.StatusBadRequest)
		}
		if got := tokenHits.Load(); got != 0 {
			t.Fatalf("token requests=%d, want 0", got)
		}
		if got := userinfoHits.Load(); got != 0 {
			t.Fatalf("userinfo requests=%d, want 0", got)
		}
	})
}
