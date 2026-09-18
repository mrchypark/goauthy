// Command goauthy-upstream-fixture is a deterministic, test-only upstream provider.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	maxRequestBody = 4096
	maxCodes       = 1024
	codeLifetime   = 5 * time.Minute
)

type config struct {
	addr, issuer, clientID, clientSecret, callbackURI, githubCallbackURI, subject string
	certFile, keyFile                                                             string
	allowManagedCallbacks                                                         bool
	allowTestClaims                                                               bool
}

func configFromEnv(getenv func(string) string) (config, error) {
	c := config{addr: getenv("LISTEN_ADDR"), issuer: getenv("ISSUER"), clientID: getenv("CLIENT_ID"), clientSecret: getenv("CLIENT_SECRET"), callbackURI: getenv("CALLBACK_URI"), subject: getenv("SUBJECT"), certFile: getenv("TLS_CERT_FILE"), keyFile: getenv("TLS_KEY_FILE")}
	if c.addr == "" {
		c.addr = ":8443"
	}
	if c.certFile == "" { // Compatibility with the E2E harness's explicit names.
		c.certFile = getenv("UPSTREAM_FIXTURE_TLS_CERT_FILE")
	}
	if c.keyFile == "" {
		c.keyFile = getenv("UPSTREAM_FIXTURE_TLS_KEY_FILE")
	}
	if c.subject == "" {
		c.subject = "fixture-subject"
	}
	if c.certFile == "" || c.keyFile == "" || c.clientID == "" || len(c.clientSecret) < 16 {
		return config{}, errors.New("TLS_CERT_FILE, TLS_KEY_FILE, CLIENT_ID, and CLIENT_SECRET (at least 16 bytes) are required")
	}
	if !exactHTTPS(c.issuer) || !exactHTTPS(c.callbackURI) {
		return config{}, errors.New("ISSUER and CALLBACK_URI must be exact HTTPS URLs")
	}
	c.githubCallbackURI = getenv("GITHUB_CALLBACK_URI")
	if c.githubCallbackURI == "" {
		c.githubCallbackURI = deriveGitHubCallback(c.callbackURI)
	}
	if !exactHTTPS(c.githubCallbackURI) {
		return config{}, errors.New("GITHUB_CALLBACK_URI must be an exact HTTPS URL")
	}
	if getenv("ALLOW_MANAGED_CALLBACKS") == "1" {
		c.allowManagedCallbacks = true
	}
	if getenv("ALLOW_TEST_CLAIMS") == "1" {
		c.allowTestClaims = true
	}
	return c, nil
}

func deriveGitHubCallback(callback string) string {
	u, err := url.Parse(callback)
	if err != nil {
		return ""
	}
	if strings.HasSuffix(u.Path, "/fixture/callback") {
		u.Path = strings.TrimSuffix(u.Path, "/fixture/callback") + "/github/callback"
	} else {
		u.Path = strings.TrimSuffix(u.Path, "/callback") + "/github/callback"
	}
	u.RawPath = ""
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

func exactHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.RawQuery == "" && u.Fragment == ""
}

type codeRecord struct {
	challenge, nonce string
	redirectURI      string
	expires          time.Time
	github           bool
	testClaims       map[string]any
}

type handler struct {
	cfg          config
	now          func() time.Time
	random       io.Reader
	private      ed25519.PrivateKey
	public       jose.JSONWebKey
	mu           sync.Mutex
	codes        map[string]codeRecord
	githubTokens map[string]struct{}
}

func newHandler(c config, now func() time.Time, entropy io.Reader) (*handler, error) {
	if now == nil {
		now = time.Now
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	public, private, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &handler{cfg: c, now: now, random: entropy, private: private, public: jose.JSONWebKey{Key: public, KeyID: "fixture", Algorithm: string(jose.EdDSA), Use: "sig"}, codes: make(map[string]codeRecord), githubTokens: make(map[string]struct{})}, nil
}

func (h *handler) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/readyz":
		if r.Method == http.MethodGet && r.URL.RawQuery == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
	case "/authorize":
		h.authorize(w, r)
		return
	case "/login/oauth/authorize":
		h.githubAuthorize(w, r)
		return
	case "/token":
		h.token(w, r)
		return
	case "/login/oauth/access_token":
		h.githubToken(w, r)
		return
	case "/user":
		h.githubUser(w, r)
		return
	case "/jwks":
		if r.Method == http.MethodGet && r.URL.RawQuery == "" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{h.public}})
			return
		}
	}
	h.invalid(w, http.StatusBadRequest)
}

func (h *handler) authorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.invalid(w, http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	for key := range q {
		switch key {
		case "client_id", "redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method":
		default:
			if !h.cfg.allowTestClaims || !strings.HasPrefix(key, "fixture_") {
				h.invalid(w, http.StatusBadRequest)
				return
			}
			if !claimKeys[key] {
				h.invalid(w, http.StatusBadRequest)
				return
			}
			if v := q.Get(key); len(v) > 256 {
				h.invalid(w, http.StatusBadRequest)
				return
			}
		}
		if len(q[key]) != 1 {
			h.invalid(w, http.StatusBadRequest)
			return
		}
	}
	state, nonce, challenge := q.Get("state"), q.Get("nonce"), q.Get("code_challenge")
	redirectURI := q.Get("redirect_uri")
	if q.Get("client_id") != h.cfg.clientID || !h.isValidRedirectURI(redirectURI) || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || !bounded(q.Get("scope"), 1024) || !hasOpenID(q.Get("scope")) || !bounded(state, 1024) || !bounded(nonce, 255) || !validChallenge(challenge) {
		h.invalid(w, http.StatusBadRequest)
		return
	}
	code, err := h.randomToken(32)
	if err != nil {
		h.invalid(w, http.StatusServiceUnavailable)
		return
	}
	now := h.now().UTC()
	h.mu.Lock()
	h.cleanup(now)
	if len(h.codes) >= maxCodes {
		h.mu.Unlock()
		h.invalid(w, http.StatusServiceUnavailable)
		return
	}
	var tc map[string]any
	if h.cfg.allowTestClaims {
		tc = extractTestClaims(q)
	}
	h.codes[code] = codeRecord{challenge: challenge, nonce: nonce, expires: now.Add(codeLifetime), redirectURI: redirectURI, testClaims: tc}
	h.mu.Unlock()
	callback, _ := url.Parse(redirectURI)
	values := callback.Query()
	values.Set("code", code)
	values.Set("state", state)
	callback.RawQuery = values.Encode()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", callback.String())
	w.WriteHeader(http.StatusFound)
}

func (h *handler) githubAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.RawQuery == "" {
		h.invalid(w, http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	callbackURI := h.githubCallbackURI()
	if !onlyOne(q, "client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method") ||
		q.Get("client_id") != h.cfg.clientID || q.Get("redirect_uri") != callbackURI || q.Get("response_type") != "code" ||
		q.Get("scope") != "read:user" || !bounded(q.Get("state"), 1024) || !validChallenge(q.Get("code_challenge")) || q.Get("code_challenge_method") != "S256" {
		h.invalid(w, http.StatusBadRequest)
		return
	}
	code, err := h.randomToken(32)
	if err != nil {
		h.invalid(w, http.StatusServiceUnavailable)
		return
	}
	now := h.now().UTC()
	h.mu.Lock()
	h.cleanup(now)
	if len(h.codes) >= maxCodes {
		h.mu.Unlock()
		h.invalid(w, http.StatusServiceUnavailable)
		return
	}
	h.codes[code] = codeRecord{challenge: q.Get("code_challenge"), expires: now.Add(codeLifetime), github: true}
	h.mu.Unlock()
	callback, _ := url.Parse(callbackURI)
	values := callback.Query()
	values.Set("code", code)
	values.Set("state", q.Get("state"))
	callback.RawQuery = values.Encode()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", callback.String())
	w.WriteHeader(http.StatusFound)
}

func (h *handler) githubCallbackURI() string {
	if h.cfg.githubCallbackURI != "" {
		return h.cfg.githubCallbackURI
	}
	return deriveGitHubCallback(h.cfg.callbackURI)
}

func (h *handler) token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || !h.validBasicAuth(r) {
		h.invalid(w, http.StatusUnauthorized)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := r.ParseForm(); err != nil {
		h.invalid(w, http.StatusBadRequest)
		return
	}
	allowed := []string{"grant_type", "code", "redirect_uri", "code_verifier"}
	if r.PostForm.Has("client_id") {
		if r.PostForm.Get("client_id") != h.cfg.clientID {
			h.invalid(w, http.StatusBadRequest)
			return
		}
		allowed = append(allowed, "client_id")
	}
	if !onlyOne(r.PostForm, allowed...) || r.PostForm.Get("grant_type") != "authorization_code" || !bounded(r.PostForm.Get("code"), 256) || !validVerifier(r.PostForm.Get("code_verifier")) {
		h.invalid(w, http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")
	now := h.now().UTC()
	h.mu.Lock()
	h.cleanup(now)
	record, ok := h.codes[code]
	if ok {
		delete(h.codes, code) // Consume before verification so every attempt is one-use.
	}
	h.mu.Unlock()
	if !ok || record.github || record.expires.Before(now) || !matchesChallenge(record.challenge, r.PostForm.Get("code_verifier")) || r.PostForm.Get("redirect_uri") != record.redirectURI {
		h.invalid(w, http.StatusBadRequest)
		return
	}
	access, err := h.randomToken(32)
	if err != nil {
		h.invalid(w, http.StatusServiceUnavailable)
		return
	}
	idToken, err := h.idToken(record.nonce, now, record.testClaims)
	if err != nil {
		h.invalid(w, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
}

func (h *handler) githubToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.RawQuery != "" {
		h.invalid(w, http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	callbackURI := h.githubCallbackURI()
	if err := r.ParseForm(); err != nil || !onlyOne(r.PostForm, "client_id", "client_secret", "grant_type", "code", "redirect_uri", "code_verifier") ||
		r.PostForm.Get("client_id") != h.cfg.clientID || r.PostForm.Get("client_secret") != h.cfg.clientSecret || r.PostForm.Get("grant_type") != "authorization_code" ||
		r.PostForm.Get("redirect_uri") != callbackURI || !bounded(r.PostForm.Get("code"), 256) || !validVerifier(r.PostForm.Get("code_verifier")) {
		h.invalid(w, http.StatusBadRequest)
		return
	}
	code := r.PostForm.Get("code")
	now := h.now().UTC()
	h.mu.Lock()
	h.cleanup(now)
	record, ok := h.codes[code]
	if ok {
		delete(h.codes, code)
	}
	valid := ok && record.github && record.expires.After(now) && matchesChallenge(record.challenge, r.PostForm.Get("code_verifier"))
	if valid {
		access, err := h.randomToken(32)
		if err == nil {
			if h.githubTokens == nil {
				h.githubTokens = make(map[string]struct{})
			}
			h.githubTokens[access] = struct{}{}
			h.mu.Unlock()
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": access, "token_type": "bearer", "scope": "read:user"})
			return
		}
	}
	h.mu.Unlock()
	h.invalid(w, http.StatusBadRequest)
}

func (h *handler) githubUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		h.invalid(w, http.StatusBadRequest)
		return
	}
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		h.invalid(w, http.StatusUnauthorized)
		return
	}
	h.mu.Lock()
	_, ok := h.githubTokens[parts[1]]
	h.mu.Unlock()
	if !ok {
		h.invalid(w, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": 123456789, "login": "fixture-user", "name": "Fixture User"})
}

func (h *handler) idToken(nonce string, now time.Time, testClaims map[string]any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: h.private}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), h.public.KeyID))
	if err != nil {
		return "", err
	}
	claims := map[string]any{
		"iss":   h.cfg.issuer,
		"sub":   h.cfg.subject,
		"aud":   h.cfg.clientID,
		"nonce": nonce,
		"iat":   now.Unix(),
		"exp":   now.Add(codeLifetime).Unix(),
	}
	for k, v := range testClaims {
		if !reservedClaims[k] {
			claims[k] = v
		}
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

var claimKeys = map[string]bool{
	"fixture_email":          true,
	"fixture_email_verified": true,
	"fixture_mfa":            true,
	"fixture_given_name":     true,
	"fixture_family_name":    true,
}

var reservedClaims = map[string]bool{
	"iss": true, "sub": true, "aud": true,
	"nonce": true, "iat": true, "exp": true,
}

// extractTestClaims pulls bounded per-authorization claims from query params.
// Protected keys (iss/sub/aud/nonce/iat/exp) are never overridden.
func extractTestClaims(q url.Values) map[string]any {
	m := make(map[string]any)
	if v := q.Get("fixture_email"); v != "" {
		m["email"] = v
	}
	if q.Get("fixture_email_verified") == "1" {
		m["email_verified"] = true
	}
	if q.Get("fixture_mfa") == "1" {
		m["amr"] = []any{"mfa"}
	}
	if v := q.Get("fixture_given_name"); v != "" {
		m["given_name"] = v
	}
	if v := q.Get("fixture_family_name"); v != "" {
		m["family_name"] = v
	}
	return m
}

func (h *handler) validBasicAuth(r *http.Request) bool {
	id, secret, ok := r.BasicAuth()
	return ok && subtle.ConstantTimeCompare([]byte(id), []byte(h.cfg.clientID)) == 1 && subtle.ConstantTimeCompare([]byte(secret), []byte(h.cfg.clientSecret)) == 1
}

func (h *handler) randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(h.random, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (h *handler) cleanup(now time.Time) {
	for code, record := range h.codes {
		if !record.expires.After(now) {
			delete(h.codes, code)
		}
	}
}

func (h *handler) invalid(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "invalid request", status)
}

func hasOpenID(scope string) bool {
	return strings.Contains(" "+strings.TrimSpace(scope)+" ", " openid ")
}
func bounded(value string, max int) bool { return len(value) > 0 && len(value) <= max }
func validChallenge(value string) bool {
	return len(value) == 43 && strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == ""
}
func validVerifier(value string) bool {
	return len(value) >= 43 && len(value) <= 128 && strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") == ""
}
func matchesChallenge(challenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(challenge), []byte(base64.RawURLEncoding.EncodeToString(sum[:]))) == 1
}
func onlyOne(values url.Values, allowed ...string) bool {
	if len(values) != len(allowed) {
		return false
	}
	for _, key := range allowed {
		if len(values[key]) != 1 {
			return false
		}
	}
	return true
}

func (h *handler) isValidRedirectURI(redirectURI string) bool {
	if redirectURI == h.cfg.callbackURI {
		return true
	}
	if !h.cfg.allowManagedCallbacks {
		return false
	}
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" {
		return false
	}
	base, err := url.Parse(h.cfg.callbackURI)
	if err != nil || u.Host != base.Host {
		return false
	}
	return validManagedCallbackPath(u.Path)
}

func validManagedCallbackPath(path string) bool {
	const prefix = "/upstream/"
	const suffix = "/callback"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) || len(path) != len(prefix)+24+len(suffix) {
		return false
	}
	id := path[len(prefix) : len(path)-len(suffix)]
	for i := 0; i < 24; i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func main() {
	c, err := configFromEnv(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	h, err := newHandler(c, time.Now, rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fixture setup failed")
		os.Exit(2)
	}
	server := &http.Server{Addr: c.addr, Handler: http.HandlerFunc(h.serveHTTP), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	if err := server.ListenAndServeTLS(c.certFile, c.keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, "fixture server failed")
	}
}
