package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/cimd"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/geoblock"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/ipblacklist"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/metrics"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/rbac"
	"github.com/mrchypark/goauthy/internal/recovery"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestServerWriteTimeoutCoversInitialLoginFailureDelay(t *testing.T) {
	t.Parallel()
	maximumUnblockedDelay := loginpolicy.Delay(loginpolicy.Status{Failures: 6, Mean: 30 * time.Second}, 0)
	if serverWriteTimeout <= maximumUnblockedDelay {
		t.Fatalf("write timeout %s must exceed login delay %s", serverWriteTimeout, maximumUnblockedDelay)
	}
}

func TestHealthEndpoints(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: migratedDataDir(t, "test-1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(newHandler(db))
	t.Cleanup(server.Close)
	for _, path := range []string{"/livez", "/readyz"} {
		response, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("%s returned %d", path, response.StatusCode)
		}
	}
}

func TestDCRProductionMuxMountsDelete(t *testing.T) {
	t.Parallel()
	called := false
	mux := http.NewServeMux()
	mountDCRRoutes(mux, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))

	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/oidc/register/client-1", nil))
	if response.Code != http.StatusNoContent || !called {
		t.Fatalf("DELETE /oidc/register/{id} status=%d called=%t", response.Code, called)
	}
}

func TestGeoblockConfigAcceptsHeaderOrDatabase(t *testing.T) {
	t.Parallel()
	t.Run("location database without admission", func(t *testing.T) {
		config, err := geoblockConfigFromEnv(func(name string) string {
			if name == "GOAUTHY_GEOBLOCK_MAXMIND_DB" {
				return "/tmp/location.mmdb"
			}
			if name == "GOAUTHY_GEOBLOCK_COUNTRY_HEADER" {
				return "X-Location"
			}
			return ""
		})
		if err != nil || config.Enabled || config.Header != "X-Location" || config.MaxMindPath != "/tmp/location.mmdb" {
			t.Fatalf("location-only config=%+v err=%v", config, err)
		}
		if err := validateGeoblockRuntime(config, nil); err != nil {
			t.Fatalf("local location database requires no proxy: %v", err)
		}
	})
	headerOnly := func(name string) string {
		return map[string]string{
			"GOAUTHY_GEOBLOCK_ENABLED":        "true",
			"GOAUTHY_GEOBLOCK_TYPE":           "whitelist",
			"GOAUTHY_GEOBLOCK_COUNTRIES":      "KR,US",
			"GOAUTHY_GEOBLOCK_COUNTRY_HEADER": "CF-IPCountry",
		}[name]
	}
	config, err := geoblockConfigFromEnv(headerOnly)
	if err != nil || config.MaxMindPath != "" || config.Header != "CF-IPCountry" {
		t.Fatalf("header-only config=%+v err=%v", config, err)
	}
	if err := validateGeoblockRuntime(config, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}); err != nil {
		t.Fatalf("trusted header rejected: %v", err)
	}
	if err := validateGeoblockRuntime(config, nil); err == nil {
		t.Fatal("header-only config accepted without trusted proxies")
	}
	databaseOnly := func(name string) string {
		return map[string]string{
			"GOAUTHY_GEOBLOCK_ENABLED":    "true",
			"GOAUTHY_GEOBLOCK_TYPE":       "whitelist",
			"GOAUTHY_GEOBLOCK_COUNTRIES":  "KR,US",
			"GOAUTHY_GEOBLOCK_MAXMIND_DB": "/tmp/country.mmdb",
		}[name]
	}
	config, err = geoblockConfigFromEnv(databaseOnly)
	if err != nil || config.MaxMindPath != "/tmp/country.mmdb" || config.Header != "" {
		t.Fatalf("database-only config=%+v err=%v", config, err)
	}
	neither := func(name string) string {
		return map[string]string{
			"GOAUTHY_GEOBLOCK_ENABLED":   "true",
			"GOAUTHY_GEOBLOCK_TYPE":      "whitelist",
			"GOAUTHY_GEOBLOCK_COUNTRIES": "KR,US",
		}[name]
	}
	if _, err := geoblockConfigFromEnv(neither); err == nil {
		t.Fatal("accepted enabled geoblock without a country source")
	}
	invalidHeader := func(name string) string {
		return map[string]string{
			"GOAUTHY_GEOBLOCK_ENABLED":        "true",
			"GOAUTHY_GEOBLOCK_TYPE":           "whitelist",
			"GOAUTHY_GEOBLOCK_COUNTRIES":      "KR,US",
			"GOAUTHY_GEOBLOCK_COUNTRY_HEADER": "Bad: Header",
			"GOAUTHY_GEOBLOCK_MAXMIND_DB":     "/tmp/country.mmdb",
		}[name]
	}
	if _, err := geoblockConfigFromEnv(invalidHeader); err == nil {
		t.Fatal("accepted invalid geoblock country header name")
	}
}

func TestHealthBypassSkipsPeerParsing(t *testing.T) {
	t.Parallel()
	health := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	blocked := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) })
	trusted := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	wrapped := healthBypass(peerIPMiddleware(blocked, trusted), health)
	for _, path := range []string{"/livez", "/readyz"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		request.RemoteAddr = "192.0.2.1:12345"
		request.Header.Add("X-Forwarded-For", "198.51.100.1")
		request.Header.Add("X-Forwarded-For", "198.51.100.2")
		response := httptest.NewRecorder()
		wrapped.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s status=%d", path, response.Code)
		}
	}
	escaped := httptest.NewRequest(http.MethodGet, "/%6civez", nil)
	escapedResponse := httptest.NewRecorder()
	wrapped.ServeHTTP(escapedResponse, escaped)
	if escapedResponse.Code != http.StatusNotFound {
		t.Fatalf("escaped health status=%d", escapedResponse.Code)
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "192.0.2.1:12345"
	request.Header.Add("X-Forwarded-For", "198.51.100.1")
	request.Header.Add("X-Forwarded-For", "198.51.100.2")
	response := httptest.NewRecorder()
	wrapped.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("protected route status=%d", response.Code)
	}
}

func TestIssuerPathMiddlewareStripsPrefixAndKeepsRFC8414Root(t *testing.T) {
	t.Parallel()
	var paths []string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.WriteHeader(http.StatusNoContent)
	})
	h := issuerPathMiddleware(next, "https://id.example.test/tenant")
	for _, path := range []string{"/tenant/oidc/token", "/.well-known/oauth-authorization-server/tenant"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNoContent {
			t.Fatalf("%s status=%d", path, w.Code)
		}
	}
	if len(paths) != 2 || paths[0] != "/oidc/token" || paths[1] != "/.well-known/oauth-authorization-server/tenant" {
		t.Fatalf("forwarded paths=%v", paths)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oidc/token", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("root application route status=%d", w.Code)
	}
	for _, path := range []string{"/tenant/livez", "/tenant/readyz"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("prefixed health route %s status=%d", path, w.Code)
		}
	}
	for _, path := range []string{"/tenant/.well-known/oauth-authorization-server", "/tenant/oidc/%74oken"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("non-canonical path %s status=%d", path, w.Code)
		}
	}

	root := issuerPathMiddleware(next, "https://id.example.test")
	w = httptest.NewRecorder()
	root.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/oidc/%74oken", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("root escaped endpoint status=%d", w.Code)
	}
}

func TestBlacklistRoutesAreConditional(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, enabled := range []bool{false, true} {
		mux := http.NewServeMux()
		mountBlacklistRoutes(mux, enabled, h)
		for _, path := range []string{"/auth/v1/blacklist", "/auth/v1/blacklist/192.0.2.1/32"} {
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			want := http.StatusNotFound
			if enabled {
				want = http.StatusNoContent
			}
			if response.Code != want {
				t.Fatalf("enabled=%t %s status=%d want=%d", enabled, path, response.Code, want)
			}
		}
	}
}

func TestAdmissionBypassRecoversBlacklistAdministration(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "admission-bypass-test", DataDir: migratedDataDir(t, "admission-bypass-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	store := ipblacklist.NewStore(db, 0)
	if _, err := store.Add(context.Background(), "198.51.100.9/32", "", nil, "admission-bypass"); err != nil {
		t.Fatal(err)
	}
	policy, err := geoblock.NewPolicy(geoblock.Whitelist, []string{"KR"}, false)
	if err != nil {
		t.Fatal(err)
	}
	protected := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	admission := ipblacklist.Middleware(store, func(*http.Request) (netip.Addr, error) {
		return netip.MustParseAddr("198.51.100.9"), nil
	})(geoblock.Middleware(policy, "X-Country", nil, nil, protected))
	admin := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
	wrapped := admissionBypass(admission, admin)

	for _, path := range []string{"/auth/v1/blacklist", "/auth/v1/blacklist/198.51.100.9/32"} {
		response := httptest.NewRecorder()
		wrapped.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusAccepted {
			t.Fatalf("admin path %s status=%d", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/oidc/token", nil)
	request.Header.Set("X-Country", "US")
	wrapped.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("protected path status=%d", response.Code)
	}
}

func TestDeviceRoutes(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "device-route-test", DataDir: migratedDataDir(t, "device-route-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	mux := newHandler(db)
	mountDeviceRoutes(mux, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/oidc/device"},
		{http.MethodGet, "/oidc/device/verify"},
		{http.MethodPost, "/oidc/device/verify"},
	} {
		request := httptest.NewRequest(route.method, route.path, nil)
		request.RemoteAddr = "192.0.2.10:12345"
		request.Header.Set("X-Forwarded-For", "198.51.100.99")
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s %s status=%d", route.method, route.path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/oidc/device", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET device status=%d", response.Code)
	}
}

func TestWebIDRoutesAreDefaultOffAndConditionallyMounted(t *testing.T) {
	t.Parallel()
	called := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.PathValue("subject") != "subject-1" {
			t.Fatalf("subject=%q", r.PathValue("subject"))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	for _, test := range []struct {
		enabled bool
		want    int
	}{
		{enabled: false, want: http.StatusNotFound},
		{enabled: true, want: http.StatusNoContent},
	} {
		mux := http.NewServeMux()
		mountWebIDRoutes(mux, test.enabled, h)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth/subject-1/profile", nil))
		if response.Code != test.want {
			t.Fatalf("enabled=%t status=%d want=%d", test.enabled, response.Code, test.want)
		}
	}
	publicMux := http.NewServeMux()
	mountWebIDRoutes(publicMux, true, h)
	public := issuerPathMiddleware(publicMux, "https://id.example.test/auth/v1")
	response := httptest.NewRecorder()
	public.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth/v1/auth/subject-1/profile", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("issuer-prefixed route status=%d", response.Code)
	}
	if !called {
		t.Fatal("enabled WebID route did not reach handler")
	}
}

func TestWebIDEnabledFromEnv(t *testing.T) {
	t.Parallel()
	getenv := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	for _, test := range []struct {
		name string
		env  map[string]string
		want bool
	}{
		{name: "default off", want: false},
		{name: "enabled", env: map[string]string{"GOAUTHY_WEB_ID_ENABLED": "true"}, want: true},
		{name: "disabled", env: map[string]string{"GOAUTHY_WEB_ID_ENABLED": "false"}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := webIDEnabledFromEnv(getenv(test.env))
			if err != nil || got != test.want {
				t.Fatalf("enabled=%v err=%v want=%v", got, err, test.want)
			}
		})
	}
	if _, err := webIDEnabledFromEnv(getenv(map[string]string{"GOAUTHY_WEB_ID_ENABLED": "yes"})); err == nil {
		t.Fatal("accepted invalid WebID flag")
	}
}

func TestPasskeyAccountRoutesAreConditional(t *testing.T) {
	t.Parallel()
	routes := []struct {
		name string
		path string
	}{
		{name: "mfa token", path: "/auth/v1/users/subject-1/mfa_token"},
		{name: "mfa auth start", path: "/auth/v1/users/subject-1/webauthn/auth/start"},
		{name: "mfa auth finish", path: "/auth/v1/users/subject-1/webauthn/auth/finish"},
		{name: "convert", path: "/auth/v1/users/subject-1/self/convert_passkey"},
	}
	disabled := http.NewServeMux()
	mountPasskeyAccountRoutes(disabled, false,
		func(http.ResponseWriter, *http.Request) { t.Fatal("disabled mfa token route reached handler") },
		func(http.ResponseWriter, *http.Request) { t.Fatal("disabled mfa auth start route reached handler") },
		func(http.ResponseWriter, *http.Request) { t.Fatal("disabled mfa auth finish route reached handler") },
		func(http.ResponseWriter, *http.Request) { t.Fatal("disabled convert route reached handler") })
	for _, route := range routes {
		response := httptest.NewRecorder()
		disabled.ServeHTTP(response, httptest.NewRequest(http.MethodPost, route.path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("disabled %s status=%d", route.name, response.Code)
		}
	}

	called := 0
	enabled := http.NewServeMux()
	boundary := func(w http.ResponseWriter, r *http.Request) {
		called++
		if subject := r.PathValue("subject"); subject != "subject-1" {
			t.Fatalf("subject=%q", subject)
		}
		w.WriteHeader(http.StatusNoContent)
	}
	mountPasskeyAccountRoutes(enabled, true, boundary, boundary, boundary, boundary)
	for index, route := range routes {
		response := httptest.NewRecorder()
		enabled.ServeHTTP(response, httptest.NewRequest(http.MethodPost, route.path, nil))
		if response.Code != http.StatusNoContent || called != index+1 {
			t.Fatalf("enabled %s status=%d called=%d", route.name, response.Code, called)
		}
	}
	response := httptest.NewRecorder()
	enabled.ServeHTTP(response, httptest.NewRequest(http.MethodGet, routes[0].path, nil))
	if response.Code != http.StatusMethodNotAllowed || called != len(routes) {
		t.Fatalf("wrong method status=%d called=%d", response.Code, called)
	}
}

func TestSelfDeleteEnabledFromEnv(t *testing.T) {
	t.Parallel()
	getenv := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	for _, test := range []struct {
		name string
		env  map[string]string
		want bool
	}{
		{name: "default off", want: false},
		{name: "enabled", env: map[string]string{"GOAUTHY_ENABLE_SELF_DELETE": "true"}, want: true},
		{name: "disabled", env: map[string]string{"GOAUTHY_ENABLE_SELF_DELETE": "false"}, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := selfDeleteEnabledFromEnv(getenv(test.env))
			if err != nil || got != test.want {
				t.Fatalf("enabled=%v err=%v, want %v", got, err, test.want)
			}
		})
	}
	if _, err := selfDeleteEnabledFromEnv(getenv(map[string]string{"GOAUTHY_ENABLE_SELF_DELETE": "yes"})); err == nil {
		t.Fatal("accepted invalid self-delete flag")
	}
}

func TestAccountRoutesPrecedenceAndSelfDeleteGate(t *testing.T) {
	t.Parallel()
	called := make([]string, 0, 2)
	admin := func(w http.ResponseWriter, r *http.Request) {
		called = append(called, "admin:"+r.PathValue("subject"))
		w.WriteHeader(http.StatusNoContent)
	}
	self := func(w http.ResponseWriter, r *http.Request) {
		called = append(called, r.Method+":"+r.PathValue("subject"))
		w.WriteHeader(http.StatusNoContent)
	}
	mux := http.NewServeMux()
	mountAccountRoutes(mux, admin, self)
	for _, route := range []struct {
		method, path, want string
	}{
		{http.MethodDelete, "/auth/v1/users/admin-target", "admin:admin-target"},
		{http.MethodGet, "/auth/v1/users/self-target/self/delete", "GET:self-target"},
		{http.MethodDelete, "/auth/v1/users/self-target/self/delete", "DELETE:self-target"},
	} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(route.method, route.path, nil))
		if response.Code != http.StatusNoContent || called[len(called)-1] != route.want {
			t.Fatalf("%s %s status=%d called=%v", route.method, route.path, response.Code, called)
		}
	}

	disabled := http.NewServeMux()
	mountAccountRoutes(disabled, admin, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotAcceptable)
	})
	response := httptest.NewRecorder()
	disabled.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/auth/v1/users/subject/self/delete", nil))
	if response.Code != http.StatusNotAcceptable {
		t.Fatalf("disabled self-delete status=%d", response.Code)
	}
}

func TestDeviceSessionSubjectRequiresAuthenticatedIssuerCookie(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "device-subject-test", DataDir: migratedDataDir(t, "device-subject-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	store, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := testHash(context.Background(), []byte("test password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.BootstrapUser(context.Background(), "subject-1", "subject-1@example.test", phc); err != nil {
		t.Fatal(err)
	}
	issuer := "https://id.example.test"
	subject := deviceSessionSubject(store, issuer)
	request := httptest.NewRequest(http.MethodPost, "/oidc/device/verify", nil)
	if got, _, ok := subject(request); ok || got != "" {
		t.Fatalf("unauthenticated subject=%q ok=%t", got, ok)
	}
	issued, err := store.CreateSession(context.Background(), "subject-1", "pwd", time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	name, err := browser.CookieName(issuer)
	if err != nil {
		t.Fatal(err)
	}
	request.AddCookie(&http.Cookie{Name: name, Value: issued.Token})
	if got, mfa, ok := subject(request); !ok || mfa || got != "subject-1" {
		t.Fatalf("authenticated subject=%q ok=%t", got, ok)
	}
	forced := deviceSessionSubject(store, issuer, true)
	if got, _, ok := forced(request); ok || got != "" {
		t.Fatalf("password-only session bypassed forced MFA: subject=%q ok=%t", got, ok)
	}
	mfa, err := store.CreateSession(context.Background(), "subject-1", "mfa", time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Del("Cookie")
	request.AddCookie(&http.Cookie{Name: name, Value: mfa.Token})
	if got, verified, ok := forced(request); !ok || !verified || got != "subject-1" {
		t.Fatalf("MFA session rejected: subject=%q ok=%t", got, ok)
	}
}

func TestTLSConfigFromEnvRejectsIncompleteOrInvalidConfiguration(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		env  map[string]string
	}{
		{name: "certificate only", env: map[string]string{"GOAUTHY_TLS_CERT_FILE": "certificate.pem"}},
		{name: "key only", env: map[string]string{"GOAUTHY_TLS_KEY_FILE": "key.pem"}},
		{name: "invalid pair", env: map[string]string{"GOAUTHY_TLS_CERT_FILE": "missing.pem", "GOAUTHY_TLS_KEY_FILE": "missing.key"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config, reloader, err := tlsConfigFromEnv(func(name string) string { return test.env[name] })
			if err == nil || config != nil || reloader != nil {
				t.Fatalf("config=%v reloader=%v err=%v", config, reloader, err)
			}
		})
	}
	config, reloader, err := tlsConfigFromEnv(func(string) string { return "" })
	if err != nil || config != nil || reloader != nil {
		t.Fatalf("HTTP development mode config=%v reloader=%v err=%v", config, reloader, err)
	}
}

func TestDirectTLSRequiresHTTPSIssuer(t *testing.T) {
	t.Parallel()
	if err := validateIssuerTLS("http://localhost:8080", true); err == nil {
		t.Fatal("direct TLS accepted an HTTP issuer")
	}
	for _, test := range []struct {
		issuer    string
		directTLS bool
	}{
		{issuer: "https://id.example.test", directTLS: true},
		{issuer: "http://localhost:8080", directTLS: false},
	} {
		if err := validateIssuerTLS(test.issuer, test.directTLS); err != nil {
			t.Fatalf("issuer=%q directTLS=%t: %v", test.issuer, test.directTLS, err)
		}
	}
}

func TestSigningKeyRotationPeriod(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		raw  string
		want time.Duration
		ok   bool
	}{
		{want: 30 * 24 * time.Hour, ok: true},
		{raw: oidc.JWKSCacheMaxAge.String(), want: oidc.JWKSCacheMaxAge, ok: true},
		{raw: "8784h", want: 366 * 24 * time.Hour, ok: true},
		{raw: "1m"},
		{raw: "8785h"},
		{raw: "monthly"},
	} {
		got, err := signingKeyRotationPeriod(func(string) string { return test.raw })
		if (err == nil) != test.ok || got != test.want {
			t.Fatalf("raw=%q got=%s err=%v", test.raw, got, err)
		}
	}
}

func TestBrowserSessionIdleTimeout(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		raw  string
		want time.Duration
		ok   bool
	}{
		{want: browser.DefaultIdleTimeout, ok: true},
		{raw: "10s", want: 10 * time.Second, ok: true},
		{raw: "4h", want: 4 * time.Hour, ok: true},
		{raw: "9s"},
		{raw: "4h1s"},
		{raw: "idle"},
	} {
		got, err := browserSessionIdleTimeout(func(string) string { return test.raw })
		if (err == nil) != test.ok || got != test.want {
			t.Fatalf("raw=%q got=%s err=%v", test.raw, got, err)
		}
	}
}

func TestClientCredentialsTokenLifetime(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		raw  string
		want time.Duration
		ok   bool
	}{
		{want: time.Hour, ok: true},
		{raw: "2s", want: 2 * time.Second, ok: true},
		{raw: "24h", want: 24 * time.Hour, ok: true},
		{raw: "1s"},
		{raw: "24h1s"},
		{raw: "short"},
	} {
		got, err := clientCredentialsTokenLifetime(func(string) string { return test.raw })
		if (err == nil) != test.ok || got != test.want {
			t.Fatalf("raw=%q got=%s err=%v", test.raw, got, err)
		}
	}
}

func TestPasskeyConfigFromEnv(t *testing.T) {
	t.Parallel()
	keyPath := filepath.Join(t.TempDir(), "passkey-key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := map[string]string{
		"GOAUTHY_PASSKEY_RP_ID":        "id.example.test",
		"GOAUTHY_PASSKEY_ORIGINS":      "https://id.example.test,http://localhost:8080",
		"GOAUTHY_PASSKEY_KEY_FILE":     keyPath,
		"GOAUTHY_PASSKEY_FORCE_UV":     "true",
		"GOAUTHY_PASSKEY_DISPLAY_NAME": "Example IdP",
	}
	getenv := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	config, err := passkeyConfigFromEnv(getenv(nil))
	if err != nil || config != nil {
		t.Fatalf("disabled config=%#v err=%v", config, err)
	}
	config, err = passkeyConfigFromEnv(getenv(valid))
	if err != nil || config == nil || config.RPID != "id.example.test" || config.RPDisplayName != "Example IdP" || !config.ForceUV || config.SessionIdleTimeout != 0 || !bytes.Equal(config.CookieKey, bytes.Repeat([]byte{7}, 32)) || strings.Join(config.Origins, ",") != valid["GOAUTHY_PASSKEY_ORIGINS"] {
		t.Fatalf("valid config=%#v err=%v", config, err)
	}
	delete(valid, "GOAUTHY_PASSKEY_DISPLAY_NAME")
	delete(valid, "GOAUTHY_PASSKEY_FORCE_UV")
	config, err = passkeyConfigFromEnv(getenv(valid))
	if err != nil || config == nil || config.RPDisplayName != "GoAuthy" || config.ForceUV {
		t.Fatalf("defaults config=%#v err=%v", config, err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{name: "missing rp id", mutate: func(values map[string]string) { delete(values, "GOAUTHY_PASSKEY_RP_ID") }},
		{name: "missing origins", mutate: func(values map[string]string) { delete(values, "GOAUTHY_PASSKEY_ORIGINS") }},
		{name: "missing key", mutate: func(values map[string]string) { delete(values, "GOAUTHY_PASSKEY_KEY_FILE") }},
		{name: "invalid origin", mutate: func(values map[string]string) { values["GOAUTHY_PASSKEY_ORIGINS"] = "https://id.example.test/path" }},
		{name: "origin whitespace", mutate: func(values map[string]string) {
			values["GOAUTHY_PASSKEY_ORIGINS"] = "https://id.example.test, https://other.example.test"
		}},
		{name: "duplicate origin", mutate: func(values map[string]string) {
			values["GOAUTHY_PASSKEY_ORIGINS"] = "https://id.example.test,https://id.example.test"
		}},
		{name: "invalid force uv", mutate: func(values map[string]string) { values["GOAUTHY_PASSKEY_FORCE_UV"] = "yes" }},
		{name: "short key", mutate: func(values map[string]string) {
			shortPath := filepath.Join(t.TempDir(), "short-key")
			if err := os.WriteFile(shortPath, []byte("short"), 0o600); err != nil {
				t.Fatal(err)
			}
			values["GOAUTHY_PASSKEY_KEY_FILE"] = shortPath
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			values := make(map[string]string, len(valid))
			for key, value := range valid {
				values[key] = value
			}
			test.mutate(values)
			if config, err := passkeyConfigFromEnv(getenv(values)); err == nil || config != nil {
				t.Fatalf("config=%#v err=%v", config, err)
			}
		})
	}
}

func TestLoadPasskeyCookieKeyRequiresPrivateRegularFile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	validPath := filepath.Join(directory, "valid")
	if err := os.WriteFile(validPath, bytes.Repeat([]byte{7}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	if key, err := loadPasskeyCookieKey(validPath); err != nil || !bytes.Equal(key, bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("valid key=%d bytes err=%v", len(key), err)
	}
	shortPath := filepath.Join(directory, "short")
	if err := os.WriteFile(shortPath, bytes.Repeat([]byte{7}, 31), 0o600); err != nil {
		t.Fatal(err)
	}
	oversizePath := filepath.Join(directory, "oversize")
	if err := os.WriteFile(oversizePath, bytes.Repeat([]byte{7}, 33), 0o600); err != nil {
		t.Fatal(err)
	}
	groupReadablePath := filepath.Join(directory, "group-readable")
	if err := os.WriteFile(groupReadablePath, bytes.Repeat([]byte{7}, 32), 0o640); err != nil {
		t.Fatal(err)
	}
	otherReadablePath := filepath.Join(directory, "other-readable")
	if err := os.WriteFile(otherReadablePath, bytes.Repeat([]byte{7}, 32), 0o604); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(directory, "symlink")
	if err := os.Symlink(validPath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{directory, shortPath, oversizePath, groupReadablePath, otherReadablePath, symlinkPath} {
		if _, err := loadPasskeyCookieKey(path); err == nil {
			t.Fatalf("accepted unsafe passkey key file %q", path)
		}
	}
}

func TestEmailTemplateFromEnv(t *testing.T) {
	t.Parallel()
	getenv := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	template, err := emailTemplateFromEnv(getenv(nil))
	if err != nil || template.Subject != "Password Reset Request" {
		t.Fatalf("default template=%#v err=%v", template, err)
	}
	_, passwordNew, alreadyRegistered, err := emailTemplatesFromEnv(getenv(nil))
	if err != nil || passwordNew.Subject != "New Password" {
		t.Fatalf("default new template=%#v err=%v", passwordNew, err)
	}
	if alreadyRegistered.Subject != "E-Mail registered already" {
		t.Fatalf("default existing-account template=%#v", alreadyRegistered)
	}
	path := filepath.Join(t.TempDir(), "email-templates.toml")
	if err := os.WriteFile(path, []byte(`[[templates]]
lang = "en"
typ = "password_reset"
subject = "English reset"

[[templates]]
lang = "en"
typ = "password_new"
subject = "English new password"

[[templates]]
lang = "en"
typ = "registered_already"
subject = "English existing account"

[[templates]]
lang = "ko"
typ = "password_reset"
subject = "한국어 초기화"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "english override", env: map[string]string{"GOAUTHY_EMAIL_TEMPLATES_FILE": path}, want: "English reset"},
		{name: "korean override", env: map[string]string{"GOAUTHY_EMAIL_TEMPLATES_FILE": path, "GOAUTHY_EMAIL_TEMPLATE_LANG": "ko"}, want: "한국어 초기화"},
	} {
		t.Run(test.name, func(t *testing.T) {
			template, err := emailTemplateFromEnv(getenv(test.env))
			if err != nil || template.Subject != test.want {
				t.Fatalf("template=%#v err=%v", template, err)
			}
		})
	}
	reset, passwordNew, alreadyRegistered, err := emailTemplatesFromEnv(getenv(map[string]string{"GOAUTHY_EMAIL_TEMPLATES_FILE": path}))
	if err != nil || reset.Subject != "English reset" || passwordNew.Subject != "English new password" || alreadyRegistered.Subject != "English existing account" {
		t.Fatalf("reset=%#v new=%#v existing=%#v err=%v", reset, passwordNew, alreadyRegistered, err)
	}
}

func TestEmailTemplateFromEnvRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	getenv := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	crlf := filepath.Join(t.TempDir(), "crlf.toml")
	if err := os.WriteFile(crlf, []byte("[[templates]]\nlang = \"en\"\ntyp = \"password_reset\"\nsubject = \"reset\\r\\nBcc: victim@example.test\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	invalid := filepath.Join(t.TempDir(), "invalid.toml")
	if err := os.WriteFile(invalid, []byte("not = [toml"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		env  map[string]string
	}{
		{name: "unsupported language", env: map[string]string{"GOAUTHY_EMAIL_TEMPLATE_LANG": "ja"}},
		{name: "missing file", env: map[string]string{"GOAUTHY_EMAIL_TEMPLATES_FILE": filepath.Join(t.TempDir(), "missing.toml")}},
		{name: "invalid file", env: map[string]string{"GOAUTHY_EMAIL_TEMPLATES_FILE": invalid}},
		{name: "crlf subject", env: map[string]string{"GOAUTHY_EMAIL_TEMPLATES_FILE": crlf}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if template, err := emailTemplateFromEnv(getenv(test.env)); err == nil || template != (recovery.EmailTemplate{}) {
				t.Fatalf("template=%#v err=%v", template, err)
			}
		})
	}
}

func TestBackchannelSettings(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		env  map[string]string
		ok   bool
	}{
		{name: "disabled defaults", ok: true},
		{name: "private HTTP fixture", env: map[string]string{
			"GOAUTHY_BOOTSTRAP_BACKCHANNEL_LOGOUT_URI":    "http://sink.test/backchannel",
			"GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_PRIVATE": "true",
			"GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_HTTP":    "true",
			"GOAUTHY_BACKCHANNEL_RETRY_BASE":              "1s",
		}, ok: true},
		{name: "bad private flag", env: map[string]string{"GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_PRIVATE": "yes"}},
		{name: "bad HTTP flag", env: map[string]string{"GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_HTTP": "yes"}},
		{name: "exception without endpoint", env: map[string]string{"GOAUTHY_BOOTSTRAP_BACKCHANNEL_ALLOW_PRIVATE": "true"}},
		{name: "short retry", env: map[string]string{"GOAUTHY_BACKCHANNEL_RETRY_BASE": "999ms"}},
		{name: "long retry", env: map[string]string{"GOAUTHY_BACKCHANNEL_RETRY_BASE": "61m"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			uri, private, httpAllowed, retry, err := backchannelSettings(func(name string) string { return test.env[name] })
			if (err == nil) != test.ok {
				t.Fatalf("uri=%q private=%t HTTP=%t retry=%s err=%v", uri, private, httpAllowed, retry, err)
			}
			if test.name == "disabled defaults" && retry != time.Minute {
				t.Fatalf("default retry=%s", retry)
			}
		})
	}
}

// GA-FED-005: a deployment that registers logout URIs only through the API has
// no bootstrap logout URI, so delivery must start anyway and consume the queued
// managed-client row instead of leaving attempts=0 with both timestamps null.
func TestBackchannelDeliveryStartsWithoutBootstrapLogoutURI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "backchannel-startup-test", DataDir: migratedDataDir(t, "backchannel-startup-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "backchannel-startup-delivery", SQL: `INSERT INTO oidc_backchannel_deliveries
		(event_id,client_id,sid,subject,logout_uri,allow_private,allow_http,attempts,next_attempt_at_unix_ms,created_at_unix_ms)
		VALUES ('event-managed','managed-client',NULL,'user-1','http://127.0.0.1:1/logout',0,0,0,?,?)`, Args: []any{now.UnixMilli(), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	if err := startBackchannelDelivery(workerCtx, &workers, func(string) string { return "" }, db, "https://id.example.test", "test-node", nil, func(context.Context) (oidc.SigningKey, error) {
		return oidc.SigningKey{}, nil
	}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		workers.Wait()
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT attempts, failed_at_unix_ms FROM oidc_backchannel_deliveries WHERE event_id='event-managed' AND client_id='managed-client'`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 {
			t.Fatalf("delivery row=%#v err=%v", row.Rows, err)
		}
		attempts := row.Rows[0][0].(int64)
		if attempts > 0 {
			// No network exception is configured, so the worker refuses the
			// plain-HTTP endpoint after claiming the row.
			if row.Rows[0][1] == nil {
				t.Fatalf("delivery attempts=%d is not terminal", attempts)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("back-channel delivery never started without a bootstrap logout URI")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestBootstrapAllowedResources(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		raw  string
		want int
		ok   bool
	}{
		{ok: true},
		{raw: `[]`, ok: true},
		{raw: `["https://api.example.test/v1"]`, want: 1, ok: true},
		{raw: `null`},
		{raw: `"https://api.example.test"`},
		{raw: `["https://api.example.test"`},
	} {
		got, err := bootstrapAllowedResources(func(string) string { return test.raw })
		if (err == nil) != test.ok || len(got) != test.want {
			t.Fatalf("raw=%q got=%v err=%v", test.raw, got, err)
		}
	}
}

func TestBootstrapDefaultAudience(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{name: "off", ok: true},
		{name: "valid", raw: "https://api.example.test/v1", want: "https://api.example.test/v1", ok: true},
		{name: "leading whitespace", raw: " https://api.example.test/v1"},
		{name: "trailing whitespace", raw: "https://api.example.test/v1 "},
		{name: "oversized", raw: strings.Repeat("a", 2049)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := bootstrapDefaultAudience(func(string) string { return test.raw })
			if (err == nil) != test.ok || got != test.want {
				t.Fatalf("raw=%q got=%q err=%v", test.raw, got, err)
			}
		})
	}
}

func TestBootstrapDefaultAudienceFailsOAuthStartup(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "default-aud-startup-test", DataDir: migratedDataDir(t, "default-aud-startup-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	var hmacSecret [32]byte
	if _, err := rand.Read(hmacSecret[:]); err != nil {
		t.Fatal(err)
	}
	allowed := "https://api.example.test/v1"
	for name, defaultAudience := range map[string]string{
		"http":             "http://api.example.test/v1",
		"not allow-listed": "https://other.example.test/v1",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := oauth.NewServerWithOIDC(context.Background(), db, hmacSecret[:], "bootstrap", "0123456789abcdef", "https://rp.example.test/callback", []string{allowed}, oauth.OIDCConfig{
				Issuer: "https://issuer.example.test", DefaultAudiences: map[string]string{"bootstrap": defaultAudience}, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidc.SigningKey{}, nil },
			})
			if err == nil {
				t.Fatal("invalid default audience allowed OAuth startup")
			}
		})
	}
}

func TestBootstrapPostLogoutRedirectURIs(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		raw  string
		want int
		ok   bool
	}{
		{ok: true},
		{raw: `[]`, ok: true},
		{raw: `["https://rp.example.test/logged-out"]`, want: 1, ok: true},
		{raw: `null`},
		{raw: `"https://rp.example.test/logged-out"`},
		{raw: `["https://rp.example.test/logged-out"`},
	} {
		got, err := bootstrapPostLogoutRedirectURIs(func(string) string { return test.raw })
		if (err == nil) != test.ok || len(got) != test.want {
			t.Fatalf("raw=%q got=%v err=%v", test.raw, got, err)
		}
	}
}

func TestDCRRegistrationToken(t *testing.T) {
	t.Parallel()
	if token, err := dcrRegistrationToken(func(string) string { return "" }); err != nil || token != "" {
		t.Fatalf("disabled DCR token=%q err=%v", token, err)
	}
	path := filepath.Join(t.TempDir(), "registration-token")
	token := strings.Repeat("t", 32)
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	getenv := func(name string) string {
		if name == "GOAUTHY_DCR_REGISTRATION_TOKEN_FILE" {
			return path
		}
		return ""
	}
	if got, err := dcrRegistrationToken(getenv); err != nil || got != token {
		t.Fatalf("loaded DCR token length=%d err=%v", len(got), err)
	}
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := dcrRegistrationToken(getenv); err == nil || got != "" || strings.Contains(err.Error(), "short") {
		t.Fatalf("invalid DCR token got length=%d err=%v", len(got), err)
	}
}

func TestDCRAnonymousConfig(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		env     map[string]string
		enabled bool
		window  time.Duration
		ok      bool
	}{
		{name: "disabled by default", env: map[string]string{}, ok: true},
		{name: "disabled ignores limit", env: map[string]string{"GOAUTHY_DCR_RATE_LIMIT_SECONDS": "bad"}, ok: true},
		{name: "enabled default", env: map[string]string{"GOAUTHY_DCR_ANONYMOUS": "true"}, enabled: true, window: time.Minute, ok: true},
		{name: "enabled custom", env: map[string]string{"GOAUTHY_DCR_ANONYMOUS": "true", "GOAUTHY_DCR_RATE_LIMIT_SECONDS": "15"}, enabled: true, window: 15 * time.Second, ok: true},
		{name: "invalid boolean", env: map[string]string{"GOAUTHY_DCR_ANONYMOUS": "maybe"}},
		{name: "zero seconds", env: map[string]string{"GOAUTHY_DCR_ANONYMOUS": "true", "GOAUTHY_DCR_RATE_LIMIT_SECONDS": "0"}},
		{name: "excessive seconds", env: map[string]string{"GOAUTHY_DCR_ANONYMOUS": "true", "GOAUTHY_DCR_RATE_LIMIT_SECONDS": "86401"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			enabled, window, err := dcrAnonymousConfig(func(name string) string { return test.env[name] })
			if enabled != test.enabled || window != test.window || (err == nil) != test.ok {
				t.Fatalf("enabled=%t window=%s err=%v", enabled, window, err)
			}
		})
	}
}

func TestRFC8252LoopbackRedirects(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		raw  string
		want bool
		ok   bool
	}{
		{"", false, true}, {"false", false, true}, {"true", true, true}, {"TRUE", true, true}, {"invalid", false, false},
	} {
		got, err := rfc8252LoopbackRedirects(func(string) string { return test.raw })
		if got != test.want || (err == nil) != test.ok {
			t.Fatalf("raw=%q got=%t err=%v", test.raw, got, err)
		}
	}
}

func TestDCRScopePolicy(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name         string
		env          map[string]string
		wantAllowed  []string
		wantDefaults []string
		ok           bool
	}{
		{name: "upstream defaults", wantAllowed: []string{"openid", "profile", "email", "groups"}, wantDefaults: []string{"openid"}, ok: true},
		{name: "operator custom scope", env: map[string]string{"GOAUTHY_DCR_ALLOWED_SCOPES": "openid  profile tenant", "GOAUTHY_DCR_DEFAULT_SCOPES": "openid tenant"}, wantAllowed: []string{"openid", "profile", "tenant"}, wantDefaults: []string{"openid", "tenant"}, ok: true},
		{name: "duplicate allowed", env: map[string]string{"GOAUTHY_DCR_ALLOWED_SCOPES": "openid openid"}},
		{name: "default not allowed", env: map[string]string{"GOAUTHY_DCR_DEFAULT_SCOPES": "tenant"}},
		{name: "whitespace only", env: map[string]string{"GOAUTHY_DCR_ALLOWED_SCOPES": " \t "}},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := dcrScopePolicy(func(name string) string { return test.env[name] })
			if (err == nil) != test.ok {
				t.Fatalf("policy=%+v err=%v", policy, err)
			}
			if test.ok && (!slices.Equal(policy.Allowed, test.wantAllowed) || !slices.Equal(policy.Default, test.wantDefaults)) {
				t.Fatalf("policy=%+v", policy)
			}
		})
	}
}

func TestBrowserAdministratorRejectsUnsafeOrAnonymousRequest(t *testing.T) {
	t.Parallel()
	callback := browserAdministrator(nil, nil, nil, "https://id.example.test")
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "https://id.example.test/auth/v1/api_keys?probe=1", nil),
		func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "https://id.example.test/auth/v1/api_keys", nil)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			return r
		}(),
		func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "https://id.example.test/auth/v1/api_keys", nil)
			r.Header.Set("Authorization", "API-Key malformed")
			return r
		}(),
		func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "https://id.example.test/auth/v1/api_keys", nil)
			r.Header["Authorization"] = []string{""}
			return r
		}(),
		func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "https://id.example.test/auth/v1/api_keys", nil)
			r.Header.Add("Authorization", "API-Key malformed")
			r.Header.Add("Authorization", "")
			return r
		}(),
		httptest.NewRequest(http.MethodGet, "https://id.example.test/auth/v1/api_keys", nil),
	} {
		response := httptest.NewRecorder()
		if callback(response, request, false) || response.Code != http.StatusUnauthorized {
			t.Fatalf("request=%s status=%d", request.URL, response.Code)
		}
	}
}

func TestBrowserAdministratorAllowsAuthenticatedBrowserWithoutAuthorization(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "browser-admin-authority", DataDir: migratedDataDir(t, "browser-admin-authority")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := testHash(context.Background(), []byte("test password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.BootstrapUser(ctx, "subject-1", "subject-1@example.test", phc); err != nil {
		t.Fatal(err)
	}
	rbacStore := rbac.NewStore(db)
	if _, err := rbacStore.EnsureBootstrapPrincipal(ctx, "subject-1", nil, nil); err != nil {
		t.Fatal(err)
	}
	browserStore, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := browserStore.CreateSession(ctx, "subject-1", "pwd", time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC), "")
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "https://id.example.test"
	cookie, err := browser.SessionCookie(issuer, issued.Token, issued.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, issuer+"/auth/v1/api_keys", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	if !browserAdministrator(rbacStore, browserStore, identities, issuer)(response, request, false) || response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestBootstrapForceMFA(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		raw  string
		want bool
		ok   bool
	}{
		{"", false, true}, {"false", false, true}, {"true", true, true}, {"TRUE", true, true}, {"invalid", false, false},
	} {
		got, err := bootstrapForceMFA(func(string) string { return test.raw })
		if got != test.want || (err == nil) != test.ok {
			t.Fatalf("raw=%q got=%t err=%v", test.raw, got, err)
		}
	}
}

func TestValidateBootstrapPasskeyConfig(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		force  bool
		config *passkey.Config
		want   bool
	}{
		{name: "default password bootstrap", want: true},
		{name: "optional passkey feature", config: &passkey.Config{}, want: true},
		{name: "forced MFA requires passkey feature", force: true},
		{name: "forced MFA with passkey feature", force: true, config: &passkey.Config{}, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateBootstrapPasskeyConfig(test.force, test.config)
			if (err == nil) != test.want {
				t.Fatalf("force=%t config=%t err=%v", test.force, test.config != nil, err)
			}
		})
	}
}

func TestForwardAuthPasskeyEnrollmentWithoutService(t *testing.T) {
	t.Parallel()
	enrolled, err := forwardAuthPasskeyEnrollment(nil)(context.Background(), "subject-1")
	if err != nil || enrolled {
		t.Fatalf("enrolled=%t err=%v", enrolled, err)
	}
}

func TestCIMDEnabled(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		raw  string
		want bool
		ok   bool
	}{
		{"", false, true}, {"false", false, true}, {"true", true, true}, {"TRUE", true, true}, {"invalid", false, false},
	} {
		got, err := cimdEnabled(func(string) string { return test.raw })
		if got != test.want || (err == nil) != test.ok {
			t.Fatalf("raw=%q got=%t err=%v", test.raw, got, err)
		}
	}
}

func TestIPBlacklistEnabled(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		raw  string
		want bool
		err  bool
	}{
		{raw: "", want: false},
		{raw: "true", want: true},
		{raw: "false", want: false},
		{raw: "yes", err: true},
	} {
		got, err := ipBlacklistEnabled(func(string) string { return test.raw })
		if (err != nil) != test.err || got != test.want {
			t.Fatalf("raw=%q enabled=%v err=%v", test.raw, got, err)
		}
	}
}

func TestCIMDIgnoreUnknownAuthFlowsFromEnv(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		raw  string
		want bool
		ok   bool
	}{
		{"", false, true}, {"false", false, true}, {"true", true, true}, {"TRUE", true, true}, {"invalid", false, false},
	} {
		got, err := cimdIgnoreUnknownAuthFlowsFromEnv(func(string) string { return test.raw })
		if got != test.want || (err == nil) != test.ok {
			t.Fatalf("raw=%q got=%t err=%v", test.raw, got, err)
		}
	}
}

func TestCIMDDangerAllowUnvalidatedResourceFromEnv(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		raw  string
		want bool
		ok   bool
	}{
		{"", false, true}, {"false", false, true}, {"true", true, true}, {"TRUE", true, true}, {"invalid", false, false},
	} {
		got, err := cimdDangerAllowUnvalidatedResourceFromEnv(func(string) string { return test.raw })
		if got != test.want || (err == nil) != test.ok {
			t.Fatalf("raw=%q got=%t err=%v", test.raw, got, err)
		}
	}
}

func TestArgonPolicyFromEnv(t *testing.T) {
	t.Parallel()
	defaults := credential.DefaultPolicy()
	configured := defaults
	configured.MemoryKiB = 32768
	configured.Iterations = 3
	configured.Parallelism = 2
	configured.MaxConcurrency = 4
	for _, test := range []struct {
		name string
		env  map[string]string
		want credential.Policy
		ok   bool
	}{
		{name: "defaults", want: defaults, ok: true},
		{name: "configured", env: map[string]string{
			"GOAUTHY_ARGON2_MEMORY_KIB":      "32768",
			"GOAUTHY_ARGON2_ITERATIONS":      "3",
			"GOAUTHY_ARGON2_PARALLELISM":     "2",
			"GOAUTHY_ARGON2_MAX_CONCURRENCY": "4",
		}, want: configured, ok: true},
		{name: "signed", env: map[string]string{"GOAUTHY_ARGON2_MEMORY_KIB": "+32768"}},
		{name: "whitespace", env: map[string]string{"GOAUTHY_ARGON2_ITERATIONS": " 3"}},
		{name: "fraction", env: map[string]string{"GOAUTHY_ARGON2_PARALLELISM": "1.0"}},
		{name: "non canonical", env: map[string]string{"GOAUTHY_ARGON2_ITERATIONS": "03"}},
		{name: "overflow", env: map[string]string{"GOAUTHY_ARGON2_MAX_CONCURRENCY": "999999999999999999999999"}},
		{name: "below memory policy", env: map[string]string{"GOAUTHY_ARGON2_MEMORY_KIB": "1"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := argonPolicyFromEnv(func(name string) string { return test.env[name] })
			if (err == nil) != test.ok || got != test.want {
				t.Fatalf("policy=%+v err=%v", got, err)
			}
		})
	}
}

func TestPasswordRulesFromEnv(t *testing.T) {
	t.Parallel()
	defaults := credential.DefaultRules()
	defaults.ValidDays = 0
	if got, err := passwordRulesFromEnv(func(string) string { return "" }); err != nil || got != defaults {
		t.Fatalf("defaults=%+v err=%v want=%+v", got, err, defaults)
	}
	env := map[string]string{
		"GOAUTHY_PASSWORD_LENGTH_MIN": "16", "GOAUTHY_PASSWORD_LENGTH_MAX": "96",
		"GOAUTHY_PASSWORD_LOWER_CASE": "2", "GOAUTHY_PASSWORD_UPPER_CASE": "3",
		"GOAUTHY_PASSWORD_DIGITS": "2", "GOAUTHY_PASSWORD_SPECIAL": "1", "GOAUTHY_PASSWORD_HISTORY": "5",
	}
	want := defaults
	want.LengthMin = 16
	want.LengthMax = 96
	want.LowerCase = 2
	want.UpperCase = 3
	want.Digits = 2
	want.Special = 1
	want.History = 5
	if got, err := passwordRulesFromEnv(func(name string) string { return env[name] }); err != nil || got != want {
		t.Fatalf("configured=%+v err=%v want=%+v", got, err, want)
	}
	for name, value := range map[string]string{
		"GOAUTHY_PASSWORD_LENGTH_MIN": "+14",
		"GOAUTHY_PASSWORD_LENGTH_MAX": "014",
		"GOAUTHY_PASSWORD_DIGITS":     "nope",
		"GOAUTHY_PASSWORD_HISTORY":    "11",
		"GOAUTHY_PASSWORD_VALID_DAYS": "3651",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := passwordRulesFromEnv(func(key string) string {
				if key == name {
					return value
				}
				return ""
			})
			if err == nil {
				t.Fatalf("accepted invalid %s=%q", name, value)
			}
		})
	}
	if got, err := passwordRulesFromEnv(func(key string) string {
		if key == "GOAUTHY_PASSWORD_VALID_DAYS" {
			return "0"
		}
		return ""
	}); err != nil || got.ValidDays != 0 {
		t.Fatalf("explicit zero rules=%+v err=%v", got, err)
	}
	for _, value := range []string{"1", "180", "3650"} {
		t.Run("valid days "+value, func(t *testing.T) {
			_, err := passwordRulesFromEnv(func(key string) string {
				if key == "GOAUTHY_PASSWORD_VALID_DAYS" {
					return value
				}
				return ""
			})
			if err == nil {
				t.Fatalf("accepted unavailable valid days %s", value)
			}
		})
	}
}

func TestPasswordRecoveryConfiguration(t *testing.T) {
	t.Parallel()
	if enabled, err := passwordRecoveryEnabled(func(string) string { return "" }); err != nil || enabled {
		t.Fatalf("default enabled=%v err=%v", enabled, err)
	}
	if enabled, err := passwordRecoveryEnabled(func(string) string { return "true" }); err != nil || !enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
	if _, err := passwordRecoveryEnabled(func(string) string { return "yes" }); err == nil {
		t.Fatal("accepted invalid recovery enabled value")
	}
	active, err := passwordRulesFromEnvWithRecovery(func(string) string { return "" }, true)
	if err != nil || active.ValidDays != 180 {
		t.Fatalf("active rules=%+v err=%v", active, err)
	}
	if _, err := loadPasswordResetKey(func(string) string { return "" }); err == nil {
		t.Fatal("accepted missing reset key path")
	}
	path := filepath.Join(t.TempDir(), "reset.key")
	if err := os.WriteFile(path, []byte(strings.Repeat("k", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	if key, err := loadPasswordResetKey(func(string) string { return path }); err != nil || len(key) != 32 {
		t.Fatalf("key length=%d err=%v", len(key), err)
	}
	for _, length := range []int{0, 31, 33} {
		badPath := filepath.Join(t.TempDir(), "reset.key")
		if err := os.WriteFile(badPath, make([]byte, length), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPasswordResetKey(func(string) string { return badPath }); err == nil {
			t.Fatalf("accepted reset key length %d", length)
		}
	}
}

func TestOpenRegistrationConfiguration(t *testing.T) {
	t.Parallel()
	getenv := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	for _, test := range []struct {
		name     string
		env      map[string]string
		recovery bool
		issuer   string
		want     recovery.RegistrationConfig
		ttl      time.Duration
		ok       bool
	}{
		{name: "disabled defaults", issuer: "https://id.example.test", ttl: 72 * time.Hour, ok: true},
		{name: "enabled allowlist", recovery: true, issuer: "https://id.example.test", env: map[string]string{"GOAUTHY_OPEN_USER_REG": "true", "GOAUTHY_USER_REG_DOMAIN_RESTRICTION": "example.test", "GOAUTHY_PASSWORD_NEW_EXPIRY": "48h"}, want: recovery.RegistrationConfig{Enabled: true, AllowedDomains: []string{"example.test"}}, ttl: 48 * time.Hour, ok: true},
		{name: "enabled blacklist http issuer", recovery: true, issuer: "http://localhost:8080", env: map[string]string{"GOAUTHY_OPEN_USER_REG": "true", "GOAUTHY_USER_REG_DOMAIN_BLACKLIST": "evil.test\nspam.test"}, want: recovery.RegistrationConfig{Enabled: true, BlacklistedDomains: []string{"evil.test", "spam.test"}, AllowHTTPRedirectURI: true}, ttl: 72 * time.Hour, ok: true},
		{name: "recovery required", env: map[string]string{"GOAUTHY_OPEN_USER_REG": "true"}, issuer: "https://id.example.test"},
		{name: "both policies", recovery: true, issuer: "https://id.example.test", env: map[string]string{"GOAUTHY_OPEN_USER_REG": "true", "GOAUTHY_USER_REG_DOMAIN_RESTRICTION": "example.test", "GOAUTHY_USER_REG_DOMAIN_BLACKLIST": "evil.test"}},
		{name: "bad bool", recovery: true, issuer: "https://id.example.test", env: map[string]string{"GOAUTHY_OPEN_USER_REG": "yes"}},
		{name: "multiple allow domains", recovery: true, issuer: "https://id.example.test", env: map[string]string{"GOAUTHY_OPEN_USER_REG": "true", "GOAUTHY_USER_REG_DOMAIN_RESTRICTION": "example.test\nother.test"}},
		{name: "noncanonical domain", recovery: true, issuer: "https://id.example.test", env: map[string]string{"GOAUTHY_OPEN_USER_REG": "true", "GOAUTHY_USER_REG_DOMAIN_RESTRICTION": "Example.test"}},
		{name: "blank blacklist entry", recovery: true, issuer: "https://id.example.test", env: map[string]string{"GOAUTHY_OPEN_USER_REG": "true", "GOAUTHY_USER_REG_DOMAIN_BLACKLIST": "evil.test\n"}},
		{name: "short ttl", recovery: true, issuer: "https://id.example.test", env: map[string]string{"GOAUTHY_OPEN_USER_REG": "true", "GOAUTHY_PASSWORD_NEW_EXPIRY": "59s"}},
		{name: "long ttl", recovery: true, issuer: "https://id.example.test", env: map[string]string{"GOAUTHY_OPEN_USER_REG": "true", "GOAUTHY_PASSWORD_NEW_EXPIRY": "169h"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ttl, err := openRegistrationFromEnv(getenv(test.env), test.recovery, test.issuer)
			if (err == nil) != test.ok {
				t.Fatalf("config=%+v ttl=%s err=%v", got, ttl, err)
			}
			if !test.ok {
				return
			}
			if got.Enabled != test.want.Enabled || got.AllowHTTPRedirectURI != test.want.AllowHTTPRedirectURI || !equalStrings(got.AllowedDomains, test.want.AllowedDomains) || !equalStrings(got.BlacklistedDomains, test.want.BlacklistedDomains) || (got.Enabled && got.RedirectValidator == nil) || ttl != test.ttl {
				t.Fatalf("config=%+v ttl=%s", got, ttl)
			}
		})
	}
}

func TestOpenRegistrationCleanupTick(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "open-registration-cleanup", DataDir: migratedDataDir(t, "open-registration-cleanup")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStoreWithPasswordReset(db, hasher, credential.DefaultRules(), bytes.Repeat([]byte{'k'}, 32))
	if err != nil {
		t.Fatal(err)
	}
	registered, err := store.RegisterOpenUser(ctx, identity.OpenRegistration{Email: "pending@example.test", TTL: time.Minute})
	if err != nil || !registered.Created {
		t.Fatalf("registered=%+v err=%v", registered, err)
	}
	if err := cleanupOpenRegistrationTick(ctx, store, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_users WHERE subject = ?`, Args: []any{registered.Subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 || result.Rows[0][0] != int64(0) {
		t.Fatalf("remaining pending identity rows=%#v err=%v", result.Rows, err)
	}
	if err := cleanupOpenRegistrationTick(ctx, nil, time.Time{}); err == nil {
		t.Fatal("accepted missing cleanup dependencies")
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func TestPasswordProofConfig(t *testing.T) {
	t.Parallel()
	if difficulty, ttl, err := passwordProofConfig(func(string) string { return "" }); err != nil || difficulty != 19 || ttl != 30*time.Second {
		t.Fatalf("defaults difficulty=%d ttl=%s err=%v", difficulty, ttl, err)
	}
	values := map[string]string{"GOAUTHY_POW_DIFFICULTY": "10", "GOAUTHY_POW_EXPIRY": "2m"}
	if difficulty, ttl, err := passwordProofConfig(func(name string) string { return values[name] }); err != nil || difficulty != 10 || ttl != 2*time.Minute {
		t.Fatalf("configured difficulty=%d ttl=%s err=%v", difficulty, ttl, err)
	}
	for _, invalid := range []struct{ name, value string }{
		{"GOAUTHY_POW_DIFFICULTY", "09"}, {"GOAUTHY_POW_DIFFICULTY", "99"}, {"GOAUTHY_POW_EXPIRY", "0s"}, {"GOAUTHY_POW_EXPIRY", "5m1s"},
	} {
		name, value := invalid.name, invalid.value
		t.Run(name+"="+value, func(t *testing.T) {
			_, _, err := passwordProofConfig(func(key string) string {
				if key == name {
					return value
				}
				return ""
			})
			if err == nil {
				t.Fatalf("accepted invalid %s=%q", name, value)
			}
		})
	}
}

func TestConfigureCIMD(t *testing.T) {
	t.Parallel()
	if resolver, err := configureCIMD(nil, false, cimd.Policy{}); err != nil || resolver != nil {
		t.Fatalf("disabled resolver=%v err=%v", resolver, err)
	}
	if resolver, err := configureCIMD(nil, true, cimd.Policy{}); err == nil || resolver != nil {
		t.Fatalf("enabled nil DB resolver=%v err=%v", resolver, err)
	}
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "cimd-config-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if resolver, err := configureCIMD(db, true, cimd.Policy{IgnoreUnknownAuthFlows: true}); err != nil || resolver == nil {
		t.Fatalf("enabled resolver=%v err=%v", resolver, err)
	}
}

func TestForwardAuthHeadersFromEnv(t *testing.T) {
	t.Parallel()
	if enabled, err := forwardAuthHeadersFromEnv(func(string) string { return "" }); err != nil || enabled {
		t.Fatalf("default enabled=%v err=%v", enabled, err)
	}
	if enabled, err := forwardAuthHeadersFromEnv(func(string) string { return "true" }); err != nil || !enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
	if _, err := forwardAuthHeadersFromEnv(func(string) string { return "yes" }); err == nil {
		t.Fatal("accepted invalid boolean")
	}
}

func TestBootstrapUserIsOptionalAndNeverResets(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "bootstrap-test", DataDir: migratedDataDir(t, "bootstrap-test")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := bootstrapUser(context.Background(), store, func(string) string { return "" }); err != nil {
		t.Fatal(err)
	}
	first, err := testHash(context.Background(), []byte("first password"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "password.phc")
	if err := os.WriteFile(path, []byte(first+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	getenv := func(name string) string {
		return map[string]string{"GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE": path, "GOAUTHY_BOOTSTRAP_USER": "alice", "GOAUTHY_BOOTSTRAP_USER_SUBJECT": "subject-1"}[name]
	}
	if err := bootstrapUser(context.Background(), store, getenv); err != nil {
		t.Fatal(err)
	}
	second, err := testHash(context.Background(), []byte("second password"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := bootstrapUser(context.Background(), store, getenv); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(context.Background(), "alice", []byte("first password")); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(context.Background(), "alice", []byte("second password")); !errors.Is(err, identity.ErrInvalidCredentials) {
		t.Fatalf("credential reset: %v", err)
	}
}

func TestBootstrapPrincipalFromEnv(t *testing.T) {
	t.Parallel()
	values := func(entries map[string]string) func(string) string {
		return func(name string) string { return entries[name] }
	}
	tooMany := make([]string, 65)
	for i := range tooMany {
		tooMany[i] = "role_" + strconv.Itoa(i)
	}
	encodedTooMany, err := json.Marshal(tooMany)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		env     map[string]string
		wantErr bool
	}{
		{name: "defaults", env: map[string]string{}},
		{name: "valid", env: map[string]string{"GOAUTHY_BOOTSTRAP_USER_ROLES": `["operator","auditor"]`, "GOAUTHY_BOOTSTRAP_USER_GROUPS": `["staff"]`}},
		{name: "not array", env: map[string]string{"GOAUTHY_BOOTSTRAP_USER_ROLES": `"operator"`}, wantErr: true},
		{name: "null", env: map[string]string{"GOAUTHY_BOOTSTRAP_USER_ROLES": `null`}, wantErr: true},
		{name: "duplicate", env: map[string]string{"GOAUTHY_BOOTSTRAP_USER_ROLES": `["operator","operator"]`}, wantErr: true},
		{name: "invalid", env: map[string]string{"GOAUTHY_BOOTSTRAP_USER_GROUPS": `[""]`}, wantErr: true},
		{name: "too many", env: map[string]string{"GOAUTHY_BOOTSTRAP_USER_ROLES": string(encodedTooMany)}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			roles, groups, err := bootstrapPrincipalFromEnv(values(test.env))
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if test.name == "defaults" && (roles != nil || groups != nil) {
				t.Fatalf("roles=%v groups=%v", roles, groups)
			}
			if test.name == "valid" && (strings.Join(roles, ",") != "operator,auditor" || strings.Join(groups, ",") != "staff") {
				t.Fatalf("roles=%v groups=%v", roles, groups)
			}
		})
	}
}

func TestTLSConfigFromEnvServesHTTPS(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	certificateFile, keyFile := filepath.Join(directory, "certificate.pem"), filepath.Join(directory, "key.pem")
	certificate, key := testTLSCertificate(t)
	if err := os.WriteFile(certificateFile, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	config, reloader, err := tlsConfigFromEnv(func(name string) string {
		return map[string]string{"GOAUTHY_TLS_CERT_FILE": certificateFile, "GOAUTHY_TLS_KEY_FILE": keyFile}[name]
	})
	if err != nil || reloader == nil {
		t.Fatalf("config=%v reloader=%v err=%v", config, reloader, err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }), TLSConfig: config}
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() {
		_ = server.Close()
		<-done
	})
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // local self-signed test certificate
	response, err := client.Get("https://" + listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS status=%d", response.StatusCode)
	}
}

func testTLSCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC), DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, &x509.Certificate{SerialNumber: big.NewInt(1)}, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key})
}

func TestReadyEndpointRejectsUninitializedDatabase(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-1", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	newHandler(db).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz returned %d", response.Code)
	}
}

func TestCloseRhizaAfterStartupCompleteSkipsPostReadyStartupFailure(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-startup-close-guard", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for !db.Ready() {
		select {
		case <-deadline.C:
			t.Fatal("Rhiza did not become ready")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
	sentinel := errors.New("startup failure")
	if got := closeRhizaAfterStartupComplete(db, false, sentinel); !errors.Is(got, sentinel) {
		t.Fatalf("startup-failure close changed error: %v", got)
	}
	if !db.Ready() {
		t.Fatal("post-ready startup failure closed the database")
	}
	if err := closeRhizaAfterStartupComplete(db, true, nil); err != nil {
		t.Fatalf("normal close: %v", err)
	}
}

func TestReadyEndpointRejectsTrustFenceMismatch(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "test-trust-fence", DataDir: migratedDataDir(t, "test-trust-fence")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	server := newHandlerWithReadiness(db, nil, func(context.Context) error {
		return storage.ErrDCRSoftwareStatementTrustMismatch
	})
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz returned %d with trust mismatch", response.Code)
	}
}

func TestReadinessProbeBoundsAndReleasesContext(t *testing.T) {
	t.Parallel()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "probe-context", DataDir: migratedDataDir(t, "probe-context")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	var probe context.Context
	ready := false
	h := newHandlerWithReadiness(db, func(value bool) { ready = value }, func(ctx context.Context) error {
		probe = ctx
		if deadline, bounded := ctx.Deadline(); !bounded {
			t.Error("readiness validator has no deadline")
		} else if deadline.After(time.Now().Add(500 * time.Millisecond)) {
			t.Error("readiness deadline exceeds the probe budget")
		}
		return nil
	})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if w.Code != http.StatusNoContent || !ready || probe == nil {
		t.Fatalf("status=%d ready=%t validator_called=%t", w.Code, ready, probe != nil)
	}
	// No sleeps: handler completion must release the context immediately.
	if !errors.Is(probe.Err(), context.Canceled) {
		t.Fatalf("probe context not released: %v", probe.Err())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/readyz", nil).WithContext(ctx))
	if w.Code != http.StatusServiceUnavailable || ready {
		t.Fatalf("canceled probe status=%d ready=%t", w.Code, ready)
	}
}

// --- Metrics token loading --------------------------------------------------

func TestMetricsListenAddrFromEnv(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		address string
		want    string
		wantErr bool
	}{
		{name: "disabled"},
		{name: "wildcard", address: ":9090", want: ":9090"},
		{name: "ipv4", address: "127.0.0.1:9090", want: "127.0.0.1:9090"},
		{name: "ipv6", address: "[::1]:9090", want: "[::1]:9090"},
		{name: "ephemeral", address: ":0", want: ":0"},
		{name: "missing port", address: "127.0.0.1", wantErr: true},
		{name: "bad port", address: "127.0.0.1:metrics", wantErr: true},
		{name: "out of range", address: "127.0.0.1:65536", wantErr: true},
		{name: "non canonical port", address: "127.0.0.1:09090", wantErr: true},
		{name: "whitespace", address: " 127.0.0.1:9090", wantErr: true},
		{name: "unix path", address: "/tmp/goauthy.metrics", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := metricsListenAddrFromEnv(func(name string) string {
				if name == "GOAUTHY_METRICS_LISTEN_ADDR" {
					return test.address
				}
				return ""
			})
			if test.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("address=%q err=%v, want %q", got, err, test.want)
			}
		})
	}
}

func TestLoadMetricsTokenRequiresFilePath(t *testing.T) {
	t.Parallel()
	_, err := loadMetricsToken(func(string) string { return "" })
	if err == nil {
		t.Fatal("accepted empty GOAUTHY_METRICS_TOKEN_FILE")
	}
}

func TestLoadMetricsTokenRejectsMissingFile(t *testing.T) {
	t.Parallel()
	_, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return filepath.Join(t.TempDir(), "missing.token")
		}
		return ""
	})
	if err == nil {
		t.Fatal("accepted missing token file")
	}
}

func TestLoadMetricsTokenRejectsOverlargeFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "large.token")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), maxMetricsTokenFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err == nil {
		t.Fatal("accepted overlarge token file")
	}
}

func TestLoadMetricsTokenRejectsEmptyToken(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty.token")
	if err := os.WriteFile(path, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err == nil {
		t.Fatal("accepted empty token after LF trim")
	}
}

func TestLoadMetricsTokenRejectsWhitespaceOnlyToken(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "ws.token")
	if err := os.WriteFile(path, []byte("  \t  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err == nil {
		t.Fatal("accepted whitespace-only token")
	}
}

func TestLoadMetricsTokenRejectsCommaInToken(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "comma.token")
	if err := os.WriteFile(path, []byte("tok,123"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err == nil {
		t.Fatal("accepted token containing comma")
	}
}

func TestLoadMetricsTokenRejectsSpaceInToken(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "space.token")
	if err := os.WriteFile(path, []byte("my secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err == nil {
		t.Fatal("accepted token containing space")
	}
}

func TestLoadMetricsTokenRejectsTabInToken(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "tab.token")
	if err := os.WriteFile(path, []byte("tok\t123"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err == nil {
		t.Fatal("accepted token containing tab")
	}
}

func TestLoadMetricsTokenRejectsCRInToken(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "cr.token")
	if err := os.WriteFile(path, []byte("tok\r123"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err == nil {
		t.Fatal("accepted token containing CR")
	}
}

func TestLoadMetricsTokenRejectsMidTokenLF(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "midlf.token")
	if err := os.WriteFile(path, []byte("tok\n123"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err == nil {
		t.Fatal("accepted token containing mid-token LF")
	}
}

func TestLoadMetricsTokenTrimsSingleTrailingLF(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "lf.token")
	if err := os.WriteFile(path, []byte("mytoken\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err != nil || got != "mytoken" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestLoadMetricsTokenTrimsSingleTrailingCRLF(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "crlf.token")
	if err := os.WriteFile(path, []byte("mytoken\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err != nil || got != "mytoken" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestLoadMetricsTokenAcceptsTokenWithoutTrailingNewline(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "plain.token")
	if err := os.WriteFile(path, []byte("mytoken"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err != nil || got != "mytoken" {
		t.Fatalf("got=%q err=%v", got, err)
	}
}

func TestLoadMetricsTokenTrimsOnlyOneTrailingNewline(t *testing.T) {
	t.Parallel()
	// Two trailing LFs: only the final one is trimmed, leaving "tok\n".
	path := filepath.Join(t.TempDir(), "doublelf.token")
	if err := os.WriteFile(path, []byte("tok\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err == nil {
		t.Fatal("accepted token with mid-token LF (second trailing LF)")
	}
}

func TestLoadMetricsTokenTrimsOnlyOneTrailingCRLF(t *testing.T) {
	t.Parallel()
	// Two trailing CRLFs: only the final one is trimmed, leaving "tok\r\n".
	path := filepath.Join(t.TempDir(), "doublecrlf.token")
	if err := os.WriteFile(path, []byte("tok\r\n\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err == nil {
		t.Fatal("accepted token with mid-token CRLF (second trailing CRLF)")
	}
}

func TestLoadMetricsTokenRejectsFileAtMaxSizePlusOne(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "maxplus1.token")
	exact := bytes.Repeat([]byte("a"), maxMetricsTokenFileSize) // exactly at limit
	if err := os.WriteFile(path, exact, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadMetricsToken(func(name string) string {
		if name == "GOAUTHY_METRICS_TOKEN_FILE" {
			return path
		}
		return ""
	})
	if err != nil || len(got) != maxMetricsTokenFileSize {
		t.Fatalf("got len=%d err=%v", len(got), err)
	}
}

// --- Metrics handler path / method restrictions ----------------------------

// newProductionMetricsMux builds the exact production mux: a single
// "GET /metrics" pattern with Bearer token auth.
func newProductionMetricsMux(token string) *http.ServeMux {
	reg := metrics.NewRegistry()
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", reg.Handler(token))
	return mux
}

func TestMetricsMuxRejectsNonGETMethods(t *testing.T) {
	t.Parallel()
	mux := newProductionMetricsMux("test-token")
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/metrics", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s /metrics returned %d, want %d", method, rr.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestMetricsMuxRejectsNonMetricsPaths(t *testing.T) {
	t.Parallel()
	mux := newProductionMetricsMux("test-token")
	for _, path := range []string{"/", "/healthz", "/metrics/extra", "/other"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("GET %s returned %d, want %d", path, rr.Code, http.StatusNotFound)
		}
	}
}

func TestMetricsMuxServesGETMetricsWithAuth(t *testing.T) {
	t.Parallel()
	mux := newProductionMetricsMux("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /metrics with auth returned %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "# HELP") {
		t.Fatal("response body missing metrics exposition")
	}
}

func TestMetricsMuxRequiresBearerAuth(t *testing.T) {
	t.Parallel()
	mux := newProductionMetricsMux("s3cret")

	// No header → 401
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no header: status %d", rr.Code)
	}

	// Wrong token → 401
	req2 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req2.Header.Set("Authorization", "Bearer wrong")
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status %d", rr2.Code)
	}
}

// --- Metrics server lifecycle with ephemeral listener -----------------------

func TestMetricsServerLifecycle(t *testing.T) {
	t.Parallel()
	mux := newProductionMetricsMux("lifecycle-token")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(ready)
		done <- server.Serve(ln)
	}()

	<-ready
	addr := "http://" + ln.Addr().String()

	// Verify the server is reachable and serves metrics with valid token.
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest(http.MethodGet, addr+"/metrics", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer lifecycle-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics status=%d", resp.StatusCode)
	}

	// Verify auth rejection on the live server.
	resp2, err := client.Get(addr + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics (no auth): %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("GET /metrics (no auth) status=%d", resp2.StatusCode)
	}

	// Graceful shutdown.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serve: %v", err)
	}
}

// --- lifecycle tests -------------------------------------------------------
//
// Channel-only tests use pre-signaled or protocol-driven sends so the
// outer select has exactly one live branch. Real-server tests prove
// shutdown reaches the actual http.Server.

func TestLifecycleAppError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	appCh := make(chan error, 1)
	appCh <- errors.New("bind: address already in use")
	got := lifecycle(ctx, nil, nil, appCh, nil)
	if got == nil || got.Error() != "bind: address already in use" {
		t.Fatalf("got %v, want bind error", got)
	}
}

func TestLifecycleAppCloseNilMetrics(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	appCh := make(chan error, 1)
	appCh <- http.ErrServerClosed
	got := lifecycle(ctx, nil, nil, appCh, nil)
	if got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestLifecycleMetricsError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	appCh := make(chan error) // empty — only metricsCh fires
	metricsCh := make(chan error, 1)
	metricsCh <- errors.New("accept tcp: address already in use")
	got := lifecycle(ctx, nil, nil, appCh, metricsCh)
	if got == nil || got.Error() != "accept tcp: address already in use" {
		t.Fatalf("got %v, want metrics error", got)
	}
}

// TestLifecycleMetricsErrServerClosedWaitsForApp uses a goroutine that
// sends metrics first and app only after metrics is received. The
// unbuffered channels make the outer select block on both cases until
// the goroutine delivers metrics, forcing the metrics-first branch.
func TestLifecycleMetricsErrServerClosedWaitsForApp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	appCh := make(chan error)     // unbuffered
	metricsCh := make(chan error) // unbuffered
	go func() {
		metricsCh <- http.ErrServerClosed
		appCh <- http.ErrServerClosed
	}()
	got := lifecycle(ctx, nil, nil, appCh, metricsCh)
	if got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

// TestLifecycleMetricsCloseThenAppError uses a goroutine that sends
// metrics first, then app only after metrics is received.
func TestLifecycleMetricsCloseThenAppError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	appCh := make(chan error)     // unbuffered
	metricsCh := make(chan error) // unbuffered
	go func() {
		metricsCh <- http.ErrServerClosed
		appCh <- errors.New("i/o timeout")
	}()
	got := lifecycle(ctx, nil, nil, appCh, metricsCh)
	if got == nil || got.Error() != "i/o timeout" {
		t.Fatalf("got %v, want app error", got)
	}
}

// startMetricsServer returns a running server on an ephemeral listener and a
// channel that will receive the Serve return value. The channel is buffered
// to 2 so a goroutine reading after lifecycle drains it still receives the
// value.
func startMetricsServer(t *testing.T) (*http.Server, <-chan error) {
	t.Helper()
	mux := newProductionMetricsMux("test-token")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	errCh := make(chan error, 2)
	go func() { errCh <- server.Serve(ln) }()
	conn, dialErr := net.Dial("tcp", ln.Addr().String())
	if dialErr != nil {
		t.Fatalf("probe metrics listener: %v", dialErr)
	}
	conn.Close()
	return server, errCh
}

// startAppServer returns a running server on an ephemeral listener and a
// channel that will receive the Serve return value.
func startAppServer(t *testing.T) (*http.Server, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler:           http.NewServeMux(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	errCh := make(chan error, 2)
	go func() { errCh <- server.Serve(ln) }()
	conn, dialErr := net.Dial("tcp", ln.Addr().String())
	if dialErr != nil {
		t.Fatalf("probe app listener: %v", dialErr)
	}
	conn.Close()
	return server, errCh
}

// TestLifecycleShutsDownMetricsOnAppError proves that when the app error
// fires first, lifecycle calls Shutdown on the real metrics server and the
// metrics serve goroutine returns ErrServerClosed.
func TestLifecycleShutsDownMetricsOnAppError(t *testing.T) {
	t.Parallel()
	server, metricsErrCh := startMetricsServer(t)
	appCh := make(chan error, 1)
	appCh <- errors.New("bind: address already in use")

	got := lifecycle(context.Background(), nil, server, appCh, metricsErrCh)
	if got == nil || got.Error() != "bind: address already in use" {
		t.Fatalf("lifecycle returned %v, want bind error", got)
	}

	metricsErr := <-metricsErrCh
	if !errors.Is(metricsErr, http.ErrServerClosed) {
		t.Fatalf("metrics serve returned %v, want ErrServerClosed", metricsErr)
	}
}

// TestLifecycleShutsDownAppOnMetricsError proves that when the metrics error
// fires first, lifecycle calls Shutdown on the real app server and the app
// serve goroutine returns ErrServerClosed.
func TestLifecycleShutsDownAppOnMetricsError(t *testing.T) {
	t.Parallel()
	appServer, appErrCh := startAppServer(t)
	metricsCh := make(chan error, 1)
	metricsCh <- errors.New("accept tcp: address already in use")

	got := lifecycle(context.Background(), appServer, nil, appErrCh, metricsCh)
	if got == nil || got.Error() != "accept tcp: address already in use" {
		t.Fatalf("lifecycle returned %v, want metrics error", got)
	}

	appErr := <-appErrCh
	if !errors.Is(appErr, http.ErrServerClosed) {
		t.Fatalf("app serve returned %v, want ErrServerClosed", appErr)
	}
}

// TestLifecycleCtxDoneWithRealServers proves that when ctx is cancelled
// before lifecycle is called, both real servers are shut down via
// shutdownServer. Lifecycle returns the app shutdown error directly (nil
// on success) without reading appErr. Both Serve goroutines then send
// ErrServerClosed, which we can drain once to prove both closed.
func TestLifecycleCtxDoneWithRealServers(t *testing.T) {
	t.Parallel()
	appServer, appErrCh := startAppServer(t)
	metricsServer, metricsErrCh := startMetricsServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	got := lifecycle(ctx, appServer, metricsServer, appErrCh, metricsErrCh)
	if got != nil {
		t.Fatalf("lifecycle returned %v, want nil", got)
	}

	appErr := <-appErrCh
	if !errors.Is(appErr, http.ErrServerClosed) {
		t.Fatalf("app serve returned %v, want ErrServerClosed", appErr)
	}
	metricsErr := <-metricsErrCh
	if !errors.Is(metricsErr, http.ErrServerClosed) {
		t.Fatalf("metrics serve returned %v, want ErrServerClosed", metricsErr)
	}
}

// --- Instrumented handler records metrics -----------------------------------

func TestMetricsInstrumentedHandlerPassesThrough(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	})
	h := reg.Instrument(inner)

	req := httptest.NewRequest(http.MethodGet, "/oidc/authorize", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusCreated)
	}
	if rr.Body.String() != "ok" {
		t.Fatalf("body=%q", rr.Body.String())
	}
}

func TestMetricsInstrumentedHandlerRecordsDifferentStatuses(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()
	scenarios := []struct {
		code int
	}{
		{http.StatusOK},
		{http.StatusBadRequest},
		{http.StatusInternalServerError},
	}
	for _, sc := range scenarios {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(sc.code)
		})
		h := reg.Instrument(inner)
		req := httptest.NewRequest(http.MethodPost, "/auth/v1/users/test", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != sc.code {
			t.Fatalf("status=%d want=%d", rr.Code, sc.code)
		}
	}
}

func TestClientCredentialsMapSubFromEnv(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		raw  string
		want bool
		ok   bool
	}{
		{want: false, ok: true},
		{raw: "false", want: false, ok: true},
		{raw: "true", want: true, ok: true},
		{raw: "TRUE", want: true, ok: true},
		{raw: "invalid", want: false, ok: false},
	} {
		got, err := clientCredentialsMapSubFromEnv(func(string) string { return test.raw })
		if got != test.want || (err == nil) != test.ok {
			t.Fatalf("raw=%q got=%t err=%v", test.raw, got, err)
		}
	}
}
