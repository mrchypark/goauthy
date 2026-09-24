// Command goauthy-saas-oauth-fixture is a deterministic, test-only OAuth provider.
package main

import (
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
)

const (
	fixtureClientID = "goauthy-saas-oauth-fixture"
	fixtureSecret   = "goauthy-saas-oauth-fixture-secret"
	maxBody         = 4096
	codeTTL         = 5 * time.Minute
)

type config struct{ addr, certFile, keyFile, redirectURI string }

func configFromEnv(getenv func(string) string) (config, error) {
	c := config{addr: getenv("SAAS_OAUTH_FIXTURE_ADDR"), certFile: getenv("SAAS_OAUTH_FIXTURE_TLS_CERT_FILE"), keyFile: getenv("SAAS_OAUTH_FIXTURE_TLS_KEY_FILE"), redirectURI: getenv("SAAS_OAUTH_FIXTURE_REDIRECT_URI")}
	if c.addr == "" {
		c.addr = ":8443"
	}
	if c.certFile == "" || c.keyFile == "" {
		return config{}, errors.New("SAAS_OAUTH_FIXTURE_TLS_CERT_FILE and SAAS_OAUTH_FIXTURE_TLS_KEY_FILE are required")
	}
	if !exactHTTPS(c.redirectURI) {
		return config{}, errors.New("SAAS_OAUTH_FIXTURE_REDIRECT_URI must be an exact HTTPS URL")
	}
	return c, nil
}

type codeRecord struct {
	challenge string
	expires   time.Time
}
type refreshRecord struct{}
type stats struct {
	Authorize, Token, UserInfo, Healthz           int
	AuthFailures, TokenFailures, UserInfoFailures int
	Model, ModelFailures                          int
}
type handler struct {
	cfg     config
	now     func() time.Time
	random  io.Reader
	mu      sync.Mutex
	codes   map[string]codeRecord
	access  map[string]struct{}
	refresh map[string]refreshRecord
	stats   stats
}

func newHandler(c config, now func() time.Time, random io.Reader) *handler {
	if now == nil {
		now = time.Now
	}
	if random == nil {
		random = rand.Reader
	}
	return &handler{cfg: c, now: now, random: random, codes: map[string]codeRecord{}, access: map[string]struct{}{}, refresh: map[string]refreshRecord{}}
}

func (h *handler) serveHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/authorize":
		h.authorize(w, r)
	case "/token":
		h.token(w, r)
	case "/userinfo":
		h.userinfo(w, r)
	case "/v1/chat/completions":
		h.model(w, r)
	case "/healthz":
		h.healthz(w, r)
	case "/stats":
		h.statsEndpoint(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *handler) authorize(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.stats.Authorize++
	h.mu.Unlock()
	q := r.URL.Query()
	keys := []string{"client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method"}
	if r.Method != http.MethodGet || r.URL.RawQuery == "" || len(q) != len(keys) || !oneEach(q, keys...) || q.Get("client_id") != fixtureClientID || q.Get("redirect_uri") != h.cfg.redirectURI || q.Get("response_type") != "code" || q.Get("scope") == "" || q.Get("state") == "" || !validVerifier(q.Get("code_challenge")) || q.Get("code_challenge_method") != "S256" {
		h.fail(w, http.StatusBadRequest, "authorize")
		return
	}
	code, err := h.tokenString(32)
	if err != nil {
		h.fail(w, http.StatusServiceUnavailable, "authorize")
		return
	}
	now := h.now().UTC()
	h.mu.Lock()
	h.cleanup(now)
	h.codes[code] = codeRecord{q.Get("code_challenge"), now.Add(codeTTL)}
	h.mu.Unlock()
	u, _ := url.Parse(h.cfg.redirectURI)
	v := u.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	u.RawQuery = v.Encode()
	w.Header().Set("Location", u.String())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusFound)
}

func (h *handler) token(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.stats.Token++
	h.mu.Unlock()
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || !h.basicAuth(r) {
		h.fail(w, http.StatusUnauthorized, "token")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	if err := r.ParseForm(); err != nil {
		h.fail(w, http.StatusBadRequest, "token")
		return
	}
	grant := r.PostForm.Get("grant_type")
	if grant == "authorization_code" {
		h.authorizationToken(w, r)
		return
	}
	if grant == "refresh_token" {
		h.refreshToken(w, r)
		return
	}
	h.fail(w, http.StatusBadRequest, "token")
}

func (h *handler) authorizationToken(w http.ResponseWriter, r *http.Request) {
	if len(r.PostForm) != 4 || !oneEach(r.PostForm, "grant_type", "code", "redirect_uri", "code_verifier") || !validVerifier(r.PostForm.Get("code_verifier")) || r.PostForm.Get("redirect_uri") != h.cfg.redirectURI {
		h.fail(w, http.StatusBadRequest, "token")
		return
	}
	code := r.PostForm.Get("code")
	now := h.now().UTC()
	h.mu.Lock()
	rec, ok := h.codes[code]
	delete(h.codes, code)
	h.mu.Unlock()
	if !ok || !rec.expires.After(now) || !matches(rec.challenge, r.PostForm.Get("code_verifier")) {
		h.fail(w, http.StatusBadRequest, "token")
		return
	}
	h.issue(w)
}

func (h *handler) refreshToken(w http.ResponseWriter, r *http.Request) {
	if len(r.PostForm) != 2 || !oneEach(r.PostForm, "grant_type", "refresh_token") {
		h.fail(w, http.StatusBadRequest, "token")
		return
	}
	rt := r.PostForm.Get("refresh_token")
	h.mu.Lock()
	_, ok := h.refresh[rt]
	delete(h.refresh, rt)
	h.mu.Unlock()
	if !ok {
		h.fail(w, http.StatusBadRequest, "token")
		return
	}
	h.issue(w)
}

func (h *handler) issue(w http.ResponseWriter) {
	a, err := h.uniqueToken(h.access)
	if err != nil {
		h.fail(w, http.StatusServiceUnavailable, "token")
		return
	}
	rt, err := h.uniqueToken(h.refresh)
	if err != nil {
		h.fail(w, http.StatusServiceUnavailable, "token")
		return
	}
	h.mu.Lock()
	h.access[a] = struct{}{}
	h.refresh[rt] = refreshRecord{}
	h.mu.Unlock()
	h.json(w, http.StatusOK, map[string]any{"access_token": a, "token_type": "Bearer", "expires_in": 300, "refresh_token": rt})
}

func (h *handler) uniqueToken(existing any) (string, error) {
	for range 8 {
		t, err := h.tokenString(32)
		if err != nil {
			return "", err
		}
		h.mu.Lock()
		var present bool
		switch m := existing.(type) {
		case map[string]struct{}:
			_, present = m[t]
		case map[string]refreshRecord:
			_, present = m[t]
		}
		h.mu.Unlock()
		if !present {
			return t, nil
		}
	}
	return "", errors.New("token entropy repeated")
}

func (h *handler) userinfo(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.stats.UserInfo++
	h.mu.Unlock()
	p := strings.Fields(r.Header.Get("Authorization"))
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || len(p) != 2 || !strings.EqualFold(p[0], "Bearer") {
		h.fail(w, http.StatusUnauthorized, "userinfo")
		return
	}
	h.mu.Lock()
	_, ok := h.access[p[1]]
	h.mu.Unlock()
	if !ok {
		h.fail(w, http.StatusUnauthorized, "userinfo")
		return
	}
	h.json(w, http.StatusOK, map[string]any{"sub": "fixture-subject"})
}

// model is a bounded non-streaming consumer target, not an inference service.
func (h *handler) model(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.stats.Model++
	_, valid := h.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	h.mu.Unlock()
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.ForceQuery || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || !valid {
		h.fail(w, http.StatusUnauthorized, "model")
		return
	}
	var request struct {
		Messages []json.RawMessage `json:"messages"`
		Stream   bool              `json:"stream"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	if decoder.Decode(&request) != nil || len(request.Messages) == 0 || request.Stream || decoder.Decode(new(any)) != io.EOF {
		h.fail(w, http.StatusBadRequest, "model")
		return
	}
	h.json(w, http.StatusOK, map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": "fixture-model-ok"}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
}

func (h *handler) healthz(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.stats.Healthz++
	h.mu.Unlock()
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		h.fail(w, http.StatusBadRequest, "healthz")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h *handler) statsEndpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.RawQuery != "" {
		h.fail(w, http.StatusBadRequest, "stats")
		return
	}
	h.mu.Lock()
	s := h.stats
	h.mu.Unlock()
	h.json(w, http.StatusOK, s)
}
func (h *handler) basicAuth(r *http.Request) bool {
	id, secret, ok := r.BasicAuth()
	return ok && subtle.ConstantTimeCompare([]byte(id), []byte(fixtureClientID)) == 1 && subtle.ConstantTimeCompare([]byte(secret), []byte(fixtureSecret)) == 1
}
func (h *handler) tokenString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(h.random, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (h *handler) cleanup(now time.Time) {
	for c, v := range h.codes {
		if !v.expires.After(now) {
			delete(h.codes, c)
		}
	}
}
func (h *handler) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (h *handler) fail(w http.ResponseWriter, status int, kind string) {
	h.mu.Lock()
	if kind == "token" {
		h.stats.TokenFailures++
	}
	if kind == "authorize" {
		h.stats.AuthFailures++
	}
	if kind == "userinfo" {
		h.stats.UserInfoFailures++
	}
	if kind == "model" {
		h.stats.ModelFailures++
	}
	h.mu.Unlock()
	http.Error(w, "invalid request", status)
}
func validVerifier(v string) bool {
	return len(v) >= 43 && len(v) <= 128 && strings.Trim(v, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~") == ""
}
func matches(challenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(challenge), []byte(base64.RawURLEncoding.EncodeToString(sum[:]))) == 1
}

func oneEach(values url.Values, keys ...string) bool {
	for _, key := range keys {
		if len(values[key]) != 1 {
			return false
		}
	}
	return true
}

func exactHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == ""
}

func main() {
	c, err := configFromEnv(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	h := newHandler(c, time.Now, rand.Reader)
	s := &http.Server{Addr: c.addr, Handler: http.HandlerFunc(h.serveHTTP), ReadHeaderTimeout: 5 * time.Second}
	if err := s.ListenAndServeTLS(c.certFile, c.keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
