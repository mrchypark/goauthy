// GoAuthy Demo is a local relying party for hands-on OIDC and SSO checks.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
	"golang.org/x/oauth2"
)

type config struct {
	Name, Listen, Issuer, ClientID, SecretFile string
	ForceLogin                                 bool
}

type pendingLogin struct {
	Binding, Verifier, Nonce string
	Expires                  time.Time
}

type accountSession struct {
	Subject, Email string
	EmailVerified  bool
	Expires        time.Time
}

type demo struct {
	cfg      config
	origin   string
	oauth    oauth2.Config
	client   *http.Client
	mu       sync.Mutex
	pending  map[string]pendingLogin
	sessions map[string]accountSession
}

func main() {
	var cfg config
	flag.StringVar(&cfg.Name, "name", "GoAuthy Demo A", "App name")
	flag.StringVar(&cfg.Listen, "listen", "127.0.0.1:18081", "Loopback listener")
	flag.StringVar(&cfg.Issuer, "issuer", "http://localhost:18080", "Local GoAuthy issuer")
	flag.StringVar(&cfg.ClientID, "client-id", "goauthy-demo-a", "Managed client ID")
	flag.StringVar(&cfg.SecretFile, "client-secret-file", "", "Owner-only client secret file")
	flag.BoolVar(&cfg.ForceLogin, "force-login", false, "Show GoAuthy login for each app sign-in")
	flag.Parse()
	if err := run(cfg); err != nil {
		log.Fatal(err)
	}
}

func run(cfg config) error {
	if err := validateConfig(cfg); err != nil {
		return err
	}
	info, err := os.Lstat(cfg.SecretFile)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > 4096 {
		return errors.New("client secret file must be regular and owner-only")
	}
	secret, err := os.ReadFile(cfg.SecretFile)
	if err != nil || len(secret) > 4096 || strings.TrimSpace(string(secret)) == "" {
		return errors.New("cannot read client secret file")
	}
	app := newDemo(cfg, strings.TrimSpace(string(secret)))
	server := &http.Server{Addr: cfg.Listen, Handler: app.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: time.Minute}
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return errors.New("demo loopback port is unavailable")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		shutdown, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("%s listening at %s", cfg.Name, app.origin)
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func validateConfig(cfg config) error {
	host, port, err := net.SplitHostPort(cfg.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || port == "0" || port == "" {
		return errors.New("demo listener must use a loopback IP and a nonzero port")
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme != "http" || issuer.User != nil || issuer.Path != "" || issuer.RawQuery != "" || issuer.Fragment != "" ||
		(issuer.Hostname() != "localhost" && (net.ParseIP(issuer.Hostname()) == nil || !net.ParseIP(issuer.Hostname()).IsLoopback())) {
		return errors.New("demo issuer must be a local HTTP origin")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{2,128}$`).MatchString(cfg.ClientID) || strings.TrimSpace(cfg.Name) == "" || cfg.SecretFile == "" {
		return errors.New("demo name, client ID and secret file are required")
	}
	return nil
}

func newDemo(cfg config, secret string) *demo {
	_, port, _ := net.SplitHostPort(cfg.Listen)
	origin := "http://localhost:" + port
	return &demo{
		cfg: cfg, origin: origin,
		oauth:   oauth2.Config{ClientID: cfg.ClientID, ClientSecret: secret, RedirectURL: origin + "/callback", Scopes: []string{"openid", "email", "profile"}, Endpoint: oauth2.Endpoint{AuthURL: cfg.Issuer + "/oidc/authorize", TokenURL: cfg.Issuer + "/oidc/token", AuthStyle: oauth2.AuthStyleInHeader}},
		client:  &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		pending: make(map[string]pendingLogin), sessions: make(map[string]accountSession),
	}
}

func (d *demo) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", d.home)
	mux.HandleFunc("GET /login", d.login)
	mux.HandleFunc("GET /callback", d.callback)
	mux.HandleFunc("POST /logout", d.logout)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		// Native form POSTs need a non-null Origin for the strict logout check.
		// Only the origin can be sent as a referrer; paths and queries stay private.
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		if r.Host != strings.TrimPrefix(d.origin, "http://") {
			http.Error(w, "Use the configured localhost address.", http.StatusBadRequest)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (d *demo) cookieName(kind string) string { return "goauthy_demo_" + d.cfg.ClientID + "_" + kind }

func (d *demo) cookie(w http.ResponseWriter, kind, value string, age int) {
	path := "/"
	if kind == "transaction" {
		path = "/callback"
	}
	http.SetCookie(w, &http.Cookie{Name: d.cookieName(kind), Value: value, Path: path, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: age})
}

func (d *demo) prune(now time.Time) {
	for key, pending := range d.pending {
		if !now.Before(pending.Expires) {
			delete(d.pending, key)
		}
	}
	for key, session := range d.sessions {
		if !now.Before(session.Expires) {
			delete(d.sessions, key)
		}
	}
}

func (d *demo) login(w http.ResponseWriter, r *http.Request) {
	state, binding, nonce, verifier := rand.Text(), rand.Text(), rand.Text(), oauth2.GenerateVerifier()
	d.mu.Lock()
	d.prune(time.Now())
	if len(d.pending) >= 1024 {
		d.mu.Unlock()
		http.Error(w, "Too many pending logins. Try again later.", http.StatusServiceUnavailable)
		return
	}
	d.pending[state] = pendingLogin{Binding: binding, Nonce: nonce, Verifier: verifier, Expires: time.Now().Add(5 * time.Minute)}
	d.mu.Unlock()
	d.cookie(w, "transaction", binding, 300)
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)}
	if d.cfg.ForceLogin {
		options = append(options, oauth2.SetAuthURLParam("prompt", "login"))
	}
	http.Redirect(w, r, d.oauth.AuthCodeURL(state, options...), http.StatusSeeOther)
}

func (d *demo) takePending(r *http.Request) (pendingLogin, bool) {
	query := r.URL.Query()
	state := query.Get("state")
	cookie, err := r.Cookie(d.cookieName("transaction"))
	if err != nil || state == "" || len(query["state"]) != 1 || len(query["code"]) != 1 || query.Get("code") == "" || query.Has("error") {
		return pendingLogin{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.prune(time.Now())
	pending, ok := d.pending[state]
	if !ok || subtle.ConstantTimeCompare([]byte(pending.Binding), []byte(cookie.Value)) != 1 {
		return pendingLogin{}, false
	}
	delete(d.pending, state)
	return pending, true
}

func (d *demo) callback(w http.ResponseWriter, r *http.Request) {
	pending, ok := d.takePending(r)
	if !ok {
		http.Error(w, "Login callback is invalid or expired. Start again.", http.StatusBadRequest)
		return
	}
	d.cookie(w, "transaction", "", -1)
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, d.client)
	tokens, err := d.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(pending.Verifier))
	if err != nil {
		http.Error(w, "GoAuthy did not complete this login. Start again.", http.StatusBadGateway)
		return
	}
	compact, _ := tokens.Extra("id_token").(string)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, d.cfg.Issuer+"/oidc/jwks.json", nil)
	if err != nil {
		http.Error(w, "Cannot request GoAuthy's signing keys. Start again.", http.StatusBadGateway)
		return
	}
	response, err := d.client.Do(req)
	if err != nil {
		http.Error(w, "Cannot verify GoAuthy's signing keys. Start again.", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	var keys jose.JSONWebKeySet
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&keys) != nil {
		http.Error(w, "Cannot verify GoAuthy's signing keys. Start again.", http.StatusBadGateway)
		return
	}
	session, err := d.verify(compact, tokens.AccessToken, pending.Nonce, keys, time.Now())
	if err != nil {
		http.Error(w, "GoAuthy's identity response did not validate. Start again.", http.StatusBadGateway)
		return
	}
	id := rand.Text()
	d.mu.Lock()
	d.prune(time.Now())
	if len(d.sessions) >= 1024 {
		d.mu.Unlock()
		http.Error(w, "Too many app sessions. Try again later.", http.StatusServiceUnavailable)
		return
	}
	if old, err := r.Cookie(d.cookieName("session")); err == nil {
		delete(d.sessions, old.Value)
	}
	d.sessions[id] = session
	d.mu.Unlock()
	d.cookie(w, "session", id, int(time.Until(session.Expires).Seconds()))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (d *demo) verify(compact, accessToken, nonce string, keys jose.JSONWebKeySet, now time.Time) (accountSession, error) {
	claims, err := oidc.VerifyIDToken(compact, keys, d.cfg.Issuer, d.cfg.ClientID, now)
	if err != nil || nonce == "" || subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 ||
		(claims.AccessTokenHash != "" && claims.AccessTokenHash != oidc.AccessTokenHash(accessToken)) {
		return accountSession{}, errors.New("identity validation failed")
	}
	session := accountSession{Subject: claims.Subject, Expires: claims.ExpiresAt}
	if claims.Profile.Email != nil {
		session.Email = *claims.Profile.Email
	}
	if claims.Profile.EmailVerified != nil {
		session.EmailVerified = *claims.Profile.EmailVerified
	}
	return session, nil
}

func (d *demo) home(w http.ResponseWriter, r *http.Request) {
	var session accountSession
	d.mu.Lock()
	d.prune(time.Now())
	if cookie, err := r.Cookie(d.cookieName("session")); err == nil {
		session = d.sessions[cookie.Value]
	}
	d.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = homePage.Execute(w, struct {
		Name, ClientID string
		Account        accountSession
		Accent         string
	}{d.cfg.Name, d.cfg.ClientID, session, map[bool]string{true: "violet", false: "blue"}[strings.HasSuffix(d.cfg.ClientID, "-b")]})
}

func (d *demo) logout(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != d.origin {
		http.Error(w, "Logout must be submitted from this app.", http.StatusForbidden)
		return
	}
	d.mu.Lock()
	if cookie, err := r.Cookie(d.cookieName("session")); err == nil {
		delete(d.sessions, cookie.Value)
	}
	d.mu.Unlock()
	d.cookie(w, "session", "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

var homePage = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Name}}</title>
<style>body{margin:0;background:#f4f6fb;color:#15213a;font:17px/1.5 system-ui,sans-serif}.wrap{max-width:780px;margin:9vh auto;padding:24px}.card{background:white;border:1px solid #dbe1ed;border-radius:18px;padding:clamp(24px,5vw,48px);box-shadow:0 16px 40px #17213a0c}.eyebrow{letter-spacing:.12em;text-transform:uppercase;font-size:12px;color:#53617c}h1{font-size:clamp(30px,6vw,48px);line-height:1.15;margin:14px 0 20px}.blue{--accent:#2453d4}.violet{--accent:#713bc9}.badge{display:inline-block;padding:6px 12px;background:#eaf5ee;color:#24653a;border-radius:30px;font-size:14px}.out{background:#eef1f7;color:#586278}a.button,button{display:inline-block;border:0;border-radius:9px;background:var(--accent);color:white;padding:12px 20px;font:inherit;text-decoration:none;cursor:pointer}a:focus-visible,button:focus-visible{outline:3px solid #e6a02d;outline-offset:4px}dt{color:#59657a;font-size:14px;margin-top:20px}dd{margin:4px 0;overflow-wrap:anywhere}code{font-size:15px}footer{font-size:14px;color:#65718a;margin-top:28px}.actions{margin-top:28px}form{margin:0}</style></head>
<body class="{{.Accent}}"><main class="wrap"><div class="card"><div class="eyebrow">Two apps · One GoAuthy ID</div><h1>{{.Name}}</h1>
{{if .Account.Subject}}<span class="badge">Signed in · Identity verified</span><p>You are signed in to this app with your GoAuthy ID account.</p><dl><dt>Verified account subject</dt><dd id="account-subject"><code>{{.Account.Subject}}</code></dd><dt>Email</dt><dd id="account-email">{{if .Account.Email}}{{.Account.Email}}{{else}}No email claim supplied{{end}}</dd><dt>Email verified by GoAuthy</dt><dd>{{.Account.EmailVerified}}</dd><dt>App client</dt><dd><code>{{.ClientID}}</code></dd></dl><div class="actions"><form action="/logout" method="post"><button type="submit">Sign out of this app</button></form></div>
{{else}}<span class="badge out">Signed out</span><p>Use your GoAuthy ID account to sign in. Then open the other demo and use the same account.</p><dl><dt>App client</dt><dd><code>{{.ClientID}}</code></dd></dl><div class="actions"><a class="button" href="/login">Sign in with GoAuthy ID</a></div>{{end}}</div><footer>Each demo has its own session. Signing out here keeps your GoAuthy ID and the other demo signed in.</footer></main></body></html>`))
