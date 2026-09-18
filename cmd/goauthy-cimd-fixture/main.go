// Command goauthy-cimd-fixture serves bounded, deterministic client metadata
// documents for local CIMD end-to-end tests. It is not an identity provider.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	maxAdminBody = 1024
	tlsAddr      = ":8443"
	adminAddr    = "127.0.0.1:8082"
)

type config struct {
	addr, adminAddr                                                     string
	certificateFile, keyFile, clientID, redirectURI, privateRedirectURL string
}

func configFromEnv(getenv func(string) string) (config, error) {
	c := config{
		addr: getenv("CIMD_FIXTURE_ADDR"), adminAddr: getenv("CIMD_FIXTURE_ADMIN_ADDR"),
		certificateFile: getenv("CIMD_FIXTURE_TLS_CERT_FILE"), keyFile: getenv("CIMD_FIXTURE_TLS_KEY_FILE"),
		clientID: getenv("CIMD_FIXTURE_CLIENT_ID"), redirectURI: getenv("CIMD_FIXTURE_REDIRECT_URI"),
		privateRedirectURL: getenv("CIMD_FIXTURE_PRIVATE_REDIRECT_URL"),
	}
	if c.addr == "" {
		c.addr = tlsAddr
	}
	if c.adminAddr == "" {
		c.adminAddr = adminAddr
	}
	if err := loopbackAddr(c.adminAddr); err != nil {
		return config{}, fmt.Errorf("CIMD_FIXTURE_ADMIN_ADDR: %w", err)
	}
	if c.certificateFile == "" || c.keyFile == "" {
		return config{}, errors.New("CIMD_FIXTURE_TLS_CERT_FILE and CIMD_FIXTURE_TLS_KEY_FILE are required")
	}
	if err := exactHTTPSURL(c.clientID); err != nil {
		return config{}, fmt.Errorf("CIMD_FIXTURE_CLIENT_ID: %w", err)
	}
	if err := exactHTTPSURL(c.redirectURI); err != nil {
		return config{}, fmt.Errorf("CIMD_FIXTURE_REDIRECT_URI: %w", err)
	}
	if !sameOrigin(c.clientID, c.redirectURI) {
		return config{}, errors.New("CIMD_FIXTURE_REDIRECT_URI must share the CIMD client ID origin")
	}
	if c.privateRedirectURL == "" {
		c.privateRedirectURL = "https://127.0.0.1/sentinel"
	}
	if err := privateHTTPURL(c.privateRedirectURL); err != nil {
		return config{}, fmt.Errorf("CIMD_FIXTURE_PRIVATE_REDIRECT_URL: %w", err)
	}
	return c, nil
}

func exactHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an exact HTTPS URL")
	}
	return nil
}

func sameOrigin(left, right string) bool {
	a, _ := url.Parse(left)
	b, _ := url.Parse(right)
	return strings.EqualFold(a.Hostname(), b.Hostname()) && effectivePort(a.Port()) == effectivePort(b.Port())
}

func effectivePort(port string) string {
	if port == "" {
		return "443"
	}
	return port
}

func privateHTTPURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.Fragment != "" {
		return errors.New("must be an HTTP(S) URL")
	}
	addr, err := netip.ParseAddr(u.Hostname())
	if err != nil || !(addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified()) {
		return errors.New("must target a private IP address")
	}
	return nil
}

func loopbackAddr(raw string) error {
	host, _, err := net.SplitHostPort(raw)
	if err != nil {
		return errors.New("must be host:port")
	}
	if host == "localhost" {
		return nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() {
		return errors.New("must bind a loopback address")
	}
	return nil
}

type negatives struct {
	Mismatch        int
	Invalid         int
	RedirectPrivate int
	Sentinel        int
}

type state struct {
	mu                                        sync.Mutex
	mode                                      string
	version, requests                         int
	negative                                  negatives
	clientID, redirectURI, privateRedirectURL string
}

func newState(c config) *state {
	s := &state{clientID: c.clientID, redirectURI: c.redirectURI, privateRedirectURL: c.privateRedirectURL}
	s.reset()
	return s
}

func (s *state) reset() {
	s.mode, s.version, s.requests, s.negative = "valid", 1, 0, negatives{}
}

func document(clientID, redirectURI string, version int) []byte {
	return []byte(fmt.Sprintf(`{"client_id":%q,"client_name":"goauthy-cimd-%d","redirect_uris":[%q],"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none","scope":"goauthy.read"}`, clientID, version, redirectURI))
}

func allowRead(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery != "" {
		http.Error(w, "query parameters are not accepted", http.StatusBadRequest)
		return false
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

func writeDocument(w http.ResponseWriter, r *http.Request, body []byte) {
	w.Header().Set("Cache-Control", "public, max-age=600")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

func (s *state) good(w http.ResponseWriter, r *http.Request) {
	if !allowRead(w, r) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests++
	if s.mode == "invalid" {
		writeDocument(w, r, []byte(`{"client_id":`))
		return
	}
	writeDocument(w, r, document(s.clientID, s.redirectURI, s.version))
}

// pathBoundDocument returns valid metadata whose client_id is exactly the
// requested fixture path. This keeps multi-client E2E cases independent of
// fixture timing or mutable admin state.
func (s *state) pathBoundDocument(w http.ResponseWriter, r *http.Request) {
	if !allowRead(w, r) {
		return
	}
	s.mu.Lock()
	s.requests++
	clientID, redirectURI, version := s.clientID, s.redirectURI, s.version
	s.mu.Unlock()
	u, _ := url.Parse(clientID) // config validation guarantees a URL.
	u.Path, u.RawPath = r.URL.Path, ""
	writeDocument(w, r, document(u.String(), redirectURI, version))
}

func (s *state) mismatch(w http.ResponseWriter, r *http.Request) {
	if !allowRead(w, r) {
		return
	}
	s.mu.Lock()
	s.requests++
	s.negative.Mismatch++
	id, redirect, version := s.clientID, s.redirectURI, s.version
	s.mu.Unlock()
	writeDocument(w, r, document(id, redirect, version))
}

func (s *state) invalid(w http.ResponseWriter, r *http.Request) {
	if !allowRead(w, r) {
		return
	}
	s.mu.Lock()
	s.requests++
	s.negative.Invalid++
	s.mu.Unlock()
	writeDocument(w, r, []byte(`{"client_id":`))
}

func (s *state) redirectPrivate(w http.ResponseWriter, r *http.Request) {
	if !allowRead(w, r) {
		return
	}
	s.mu.Lock()
	s.requests++
	s.negative.RedirectPrivate++
	destination := s.privateRedirectURL
	s.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Location", destination)
	w.WriteHeader(http.StatusFound)
}

func rejectAdminMethod(w http.ResponseWriter, r *http.Request, allowed string) bool {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		http.Error(w, "query parameters are not accepted", http.StatusBadRequest)
		return true
	}
	if r.Method == allowed {
		return false
	}
	w.Header().Set("Allow", allowed)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return true
}

func (s *state) adminState(w http.ResponseWriter, r *http.Request) {
	if rejectAdminMethod(w, r, http.MethodGet) {
		return
	}
	s.mu.Lock()
	result := struct {
		Requests        int    `json:"requests"`
		DocumentVersion int    `json:"document_version"`
		Mode            string `json:"mode"`
		Negative        struct {
			Mismatch        int `json:"mismatch"`
			Invalid         int `json:"invalid"`
			RedirectPrivate int `json:"redirect_private"`
			Sentinel        int `json:"sentinel"`
		} `json:"negative"`
	}{Requests: s.requests, DocumentVersion: s.version, Mode: s.mode}
	result.Negative.Mismatch, result.Negative.Invalid, result.Negative.RedirectPrivate, result.Negative.Sentinel = s.negative.Mismatch, s.negative.Invalid, s.negative.RedirectPrivate, s.negative.Sentinel
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (s *state) adminDocument(w http.ResponseWriter, r *http.Request) {
	if rejectAdminMethod(w, r, http.MethodPost) {
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		http.Error(w, "content type must be application/json", http.StatusUnsupportedMediaType)
		return
	}
	var in struct {
		Mode string `json:"mode"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdminBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil || decoder.Decode(&struct{}{}) != io.EOF || (in.Mode != "valid" && in.Mode != "invalid") {
		http.Error(w, "invalid document input", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.mode = in.Mode
	s.version++
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *state) adminReset(w http.ResponseWriter, r *http.Request) {
	if rejectAdminMethod(w, r, http.MethodPost) {
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 0))
	if err != nil || len(body) != 0 {
		http.Error(w, "request body is not accepted", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.reset()
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *state) sentinel(w http.ResponseWriter, r *http.Request) {
	if rejectAdminMethod(w, r, http.MethodGet) {
		return
	}
	s.mu.Lock()
	s.negative.Sentinel++
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *state) documentHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/good", s.good)
	mux.HandleFunc("/allow", s.pathBoundDocument)
	mux.HandleFunc("/deny", s.pathBoundDocument)
	mux.HandleFunc("/recovery", s.pathBoundDocument)
	mux.HandleFunc("/mismatch", s.mismatch)
	mux.HandleFunc("/invalid", s.invalid)
	mux.HandleFunc("/redirect-private", s.redirectPrivate)
	mux.HandleFunc("/sentinel", s.sentinel)
	return mux
}
func (s *state) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/state", s.adminState)
	mux.HandleFunc("/admin/document", s.adminDocument)
	mux.HandleFunc("/admin/reset", s.adminReset)
	return mux
}

func server(addr string, handler http.Handler) *http.Server {
	return &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
}

func run() error {
	c, err := configFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(c.certificateFile, c.keyFile)
	if err != nil {
		return fmt.Errorf("load TLS certificate: %w", err)
	}
	s := newState(c)
	public := server(c.addr, s.documentHandler())
	public.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}
	admin := server(c.adminAddr, s.adminHandler())
	listener, err := net.Listen("tcp", c.addr)
	if err != nil {
		return err
	}
	errCh := make(chan error, 2)
	go func() { errCh <- public.ServeTLS(listener, "", "") }()
	go func() { errCh <- admin.ListenAndServe() }()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = public.Shutdown(shutdownCtx)
	return admin.Shutdown(shutdownCtx)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
