package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
)

// --- test clock -----------------------------------------------------------

type testClock struct {
	now time.Time
}

func (c *testClock) Now() time.Time { return c.now }

func (c *testClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// --- collect helpers ------------------------------------------------------

func collectCounter(t *testing.T, reg *Registry, name string) float64 {
	t.Helper()
	metrics, err := reg.reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range metrics {
		if mf.GetName() == name {
			return mf.GetMetric()[0].GetCounter().GetValue()
		}
	}
	t.Fatalf("metric %q not found", name)
	return 0
}

func collectCounterSum(t *testing.T, reg *Registry, name string) float64 {
	t.Helper()
	metrics, err := reg.reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range metrics {
		if mf.GetName() == name {
			var total float64
			for _, m := range mf.GetMetric() {
				total += m.GetCounter().GetValue()
			}
			return total
		}
	}
	t.Fatalf("metric %q not found", name)
	return 0
}

func collectGauge(t *testing.T, reg *Registry, name string) float64 {
	t.Helper()
	metrics, err := reg.reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range metrics {
		if mf.GetName() == name {
			return mf.GetMetric()[0].GetGauge().GetValue()
		}
	}
	t.Fatalf("metric %q not found", name)
	return 0
}

func collectHistogramCountSum(t *testing.T, reg *Registry, name string) uint64 {
	t.Helper()
	metrics, err := reg.reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range metrics {
		if mf.GetName() == name {
			var total uint64
			for _, m := range mf.GetMetric() {
				total += m.GetHistogram().GetSampleCount()
			}
			return total
		}
	}
	t.Fatalf("metric %q not found", name)
	return 0
}

func gatherText(t *testing.T, reg *Registry) string {
	t.Helper()
	handler := promhttp.HandlerFor(reg.reg, promhttp.HandlerOpts{})
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr.Body.String()
}

// compile-time assertions
var _ http.Handler = (*authHandler)(nil)

// --- Registry isolation ---------------------------------------------------

func TestNewRegistryCreatesPrivateRegistry(t *testing.T) {
	reg := NewRegistry()
	if reg.reg == prometheus.DefaultRegisterer {
		t.Fatal("Registry must not use the global prometheus registry")
	}
	defaultGatherer, ok := prometheus.DefaultRegisterer.(prometheus.Gatherer)
	if !ok {
		t.Skip("DefaultRegisterer is not a Gatherer")
	}
	before, err := defaultGatherer.Gather()
	if err != nil {
		t.Fatalf("default Gather: %v", err)
	}
	NewRegistry()
	after, err := defaultGatherer.Gather()
	if err != nil {
		t.Fatalf("default Gather after: %v", err)
	}
	if len(before) != len(after) {
		t.Fatalf("global registry mutated: had %d families, now %d", len(before), len(after))
	}
}

func TestTwoRegistriesAreIndependent(t *testing.T) {
	a := NewRegistry()
	b := NewRegistry()
	a.AuthSuccess()
	a.AuthSuccess()
	b.AuthFailure()

	if got := collectCounter(t, a, "goauthy_security_auth_success_total"); got != 2 {
		t.Fatalf("registry a auth_success: got %v, want 2", got)
	}
	if got := collectCounter(t, a, "goauthy_security_auth_failure_total"); got != 0 {
		t.Fatalf("registry a auth_failure: got %v, want 0", got)
	}
	if got := collectCounter(t, b, "goauthy_security_auth_success_total"); got != 0 {
		t.Fatalf("registry b auth_success: got %v, want 0", got)
	}
	if got := collectCounter(t, b, "goauthy_security_auth_failure_total"); got != 1 {
		t.Fatalf("registry b auth_failure: got %v, want 1", got)
	}
}

// --- Auth handler ---------------------------------------------------------

func TestHandlerNoAuthReturnsMetrics(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), "# HELP") {
		t.Fatalf("body missing metric exposition: %.100s", rr.Body.String())
	}
}

func TestHandlerRejectsMissingHeader(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("expected WWW-Authenticate header on 401")
	}
}

func TestHandlerRejectsWrongToken(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerRejectsBearerPrefixOnly(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerRejectsWhitespaceOnlyToken(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer   \t  ")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerRejectsNonBearerPrefix(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerAcceptsCorrectToken(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusOK)
	}
	if !strings.Contains(rr.Body.String(), "# HELP") {
		t.Fatal("authenticated response missing metrics")
	}
}

func TestHandlerRejectsShortHeader(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "B")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerRejectsTrailingWhitespaceInToken(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3cret ")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerRejectsLeadingWhitespaceInToken(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer  s3cret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerRejectsDoubleSpaceSeparator(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer  s3cret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerRejectsEmptyTokenAfterBearer(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer ")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerRejectsMultipleAuthorizationHeaders(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Add("Authorization", "Bearer s3cret")
	req.Header.Add("Authorization", "Bearer other")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerRejectsTabInToken(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer s3\tcret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerRejectsInternalSpaceInToken(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer abc def")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandlerRejectsCommaJoinedCredential(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("s3cret")
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer abc, Basic xyz")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestConfiguredTokenWithWhitespaceCannotAuthorize(t *testing.T) {
	reg := NewRegistry()
	const secretWithSpace = "my secret"
	h := reg.Handler(secretWithSpace)

	// Sending the exact configured secret as a Bearer token — the token
	// itself contains a space, so it must be rejected at the parser level
	// even though it matches the configured secret byte-for-byte.
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+secretWithSpace)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestConfiguredTokenWithCommaCannotAuthorize(t *testing.T) {
	reg := NewRegistry()
	const secretWithComma = "my,secret"
	h := reg.Handler(secretWithComma)

	// Sending the exact configured secret as a Bearer token — the token
	// itself contains a comma, so it must be rejected at the parser level.
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+secretWithComma)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// --- No secret in body / labels -------------------------------------------

func TestTokenNeverAppearsInResponseBody(t *testing.T) {
	reg := NewRegistry()
	secret := "my-super-secret-token-42"
	h := reg.Handler(secret)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if strings.Contains(rr.Body.String(), secret) {
		t.Fatal("secret token leaked into metrics body")
	}

	req2 := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req2.Header.Set("Authorization", "Bearer wrong")
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if strings.Contains(rr2.Body.String(), "wrong") {
		t.Fatal("rejected token leaked into 401 body")
	}
}

func TestLabelsAreLowCardinality(t *testing.T) {
	reg := NewRegistry()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := reg.Instrument(inner)

	paths := []string{
		"/auth/v1/users/user-abc-123",
		"/auth/v1/users/user-xyz-999",
		"/auth/v1/roles/admin",
		"/oauth/v2/token",
		"/oidc/v1/.well-known/openid-configuration",
		"/api/v1/users/secret-uuid-12345/profile",
	}
	for _, p := range paths {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
	}

	families, err := reg.reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != "goauthy_http_requests_total" {
			continue
		}
		allowedLabels := map[string]bool{
			"method": true, "route_class": true, "status_class": true,
		}
		for _, metric := range mf.GetMetric() {
			for _, lp := range metric.GetLabel() {
				if !allowedLabels[lp.GetName()] {
					t.Errorf("unexpected label %q", lp.GetName())
				}
			}
		}
		return
	}
	t.Fatal("goauthy_http_requests_total not found")
}

func TestNoSubjectClientIPPathLabelLeakage(t *testing.T) {
	reg := NewRegistry()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := reg.Instrument(inner)
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/users/secret-subject-123", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	families, err := reg.reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, mf := range families {
		for _, metric := range mf.GetMetric() {
			for _, lp := range metric.GetLabel() {
				val := lp.GetValue()
				if strings.Contains(val, "192.168.1.100") ||
					strings.Contains(val, "secret-subject-123") ||
					strings.Contains(val, "54321") {
					t.Errorf("leaked high-cardinality value %q in label %q", val, lp.GetName())
				}
			}
		}
	}
}

// --- Counter value correctness --------------------------------------------

func TestInstrumentRecordsCountsAndStatusClass(t *testing.T) {
	reg := NewRegistry()
	scenarios := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"2xx", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }},
		{"4xx", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadRequest) }},
		{"5xx", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusInternalServerError) }},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			h := reg.Instrument(sc.handler)
			req := httptest.NewRequest(http.MethodPost, "/auth/v1/users/anything", nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
		})
	}

	total := collectCounterSum(t, reg, "goauthy_http_requests_total")
	if total != 3 {
		t.Fatalf("http_requests_total: got %v, want 3", total)
	}
	count := collectHistogramCountSum(t, reg, "goauthy_http_request_duration_seconds")
	if count != 3 {
		t.Fatalf("http_request_duration count: got %v, want 3", count)
	}
}

func TestInstrumentDefaultRouteClass(t *testing.T) {
	reg := NewRegistry()
	h := reg.Instrument(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	}))

	req := httptest.NewRequest(http.MethodGet, "/unknown/path", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	body := gatherText(t, reg)
	if !strings.Contains(body, `route_class="/other"`) {
		t.Fatalf("expected /other route class, body:\n%s", body)
	}
	if !strings.Contains(body, `status_class="2xx"`) {
		t.Fatalf("expected 2xx status class, body:\n%s", body)
	}
}

func TestInstrumentNilNormalizer(t *testing.T) {
	reg := NewRegistry()
	h := reg.Instrument(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/oidc/jwks.json", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	body := gatherText(t, reg)
	if !strings.Contains(body, `route_class="/oidc/*"`) {
		t.Fatalf("expected /oidc/* route class, body:\n%s", body)
	}
}

// --- Method allowlist -----------------------------------------------------

func TestSanitizeMethodAllowlist(t *testing.T) {
	allowed := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
	for _, m := range allowed {
		if got := sanitizeMethod(m); got != m {
			t.Errorf("sanitizeMethod(%q) = %q, want %q", m, got, m)
		}
	}
	unknown := []string{"FOO", "CUSTOM", "PROPFIND", ""}
	for _, m := range unknown {
		if got := sanitizeMethod(m); got != "OTHER" {
			t.Errorf("sanitizeMethod(%q) = %q, want OTHER", m, got)
		}
	}
}

func TestInstrumentMethodAllowlist(t *testing.T) {
	reg := NewRegistry()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := reg.Instrument(inner)

	// Known method
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	body := gatherText(t, reg)
	if !strings.Contains(body, `method="GET"`) {
		t.Fatalf("expected method=GET, body:\n%s", body)
	}

	// Unknown method → OTHER
	req2 := httptest.NewRequest("PROPFIND", "/metrics", nil)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)

	body2 := gatherText(t, reg)
	if !strings.Contains(body2, `method="OTHER"`) {
		t.Fatalf("expected method=OTHER, body:\n%s", body2)
	}
}

// --- DB readiness & pool --------------------------------------------------

func TestDBReadinessSuccess(t *testing.T) {
	reg := NewRegistry()
	reg.DBReadiness(true)
	if got := collectCounter(t, reg, "goauthy_db_readiness_success_total"); got != 1 {
		t.Fatalf("got %v, want 1", got)
	}
	if got := collectCounter(t, reg, "goauthy_db_readiness_failure_total"); got != 0 {
		t.Fatalf("got %v, want 0", got)
	}
}

func TestDBReadinessFailure(t *testing.T) {
	reg := NewRegistry()
	reg.DBReadiness(false)
	if got := collectCounter(t, reg, "goauthy_db_readiness_failure_total"); got != 1 {
		t.Fatalf("got %v, want 1", got)
	}
	if got := collectCounter(t, reg, "goauthy_db_readiness_success_total"); got != 0 {
		t.Fatalf("got %v, want 0", got)
	}
}

func TestDBReadinessLastOKDeterministic(t *testing.T) {
	clk := &testClock{now: time.Unix(1700000000, 0)}
	reg := newRegistryForTesting(clk)

	reg.DBReadiness(false)
	got := collectGauge(t, reg, "goauthy_db_readiness_last_ok_unix_seconds")
	if got != 0 {
		t.Fatalf("last_ok after failure: got %v, want 0", got)
	}

	reg.DBReadiness(true)
	got = collectGauge(t, reg, "goauthy_db_readiness_last_ok_unix_seconds")
	if got != 1700000000 {
		t.Fatalf("last_ok: got %v, want 1700000000", got)
	}

	clk.advance(60 * time.Second)
	reg.DBReadiness(true)
	got = collectGauge(t, reg, "goauthy_db_readiness_last_ok_unix_seconds")
	if got != 1700000060 {
		t.Fatalf("last_ok after advance: got %v, want 1700000060", got)
	}
}

func TestDBPool(t *testing.T) {
	reg := NewRegistry()
	reg.DBPool(10, 3)
	if got := collectGauge(t, reg, "goauthy_db_pool_open_connections"); got != 10 {
		t.Fatalf("pool open: got %v, want 10", got)
	}
	if got := collectGauge(t, reg, "goauthy_db_pool_idle_connections"); got != 3 {
		t.Fatalf("pool idle: got %v, want 3", got)
	}
	reg.DBPool(0, 0)
	if got := collectGauge(t, reg, "goauthy_db_pool_open_connections"); got != 0 {
		t.Fatalf("pool open after reset: got %v, want 0", got)
	}
}

// --- Security counters ----------------------------------------------------

func TestAuthSuccessAndFailure(t *testing.T) {
	reg := NewRegistry()
	reg.AuthSuccess()
	reg.AuthSuccess()
	reg.AuthFailure()
	if got := collectCounter(t, reg, "goauthy_security_auth_success_total"); got != 2 {
		t.Fatalf("got %v, want 2", got)
	}
	if got := collectCounter(t, reg, "goauthy_security_auth_failure_total"); got != 1 {
		t.Fatalf("got %v, want 1", got)
	}
}

func TestTokenOKAndReject(t *testing.T) {
	reg := NewRegistry()
	reg.TokenOK()
	reg.TokenReject()
	reg.TokenReject()
	if got := collectCounter(t, reg, "goauthy_security_token_validation_success_total"); got != 1 {
		t.Fatalf("got %v, want 1", got)
	}
	if got := collectCounter(t, reg, "goauthy_security_token_validation_failure_total"); got != 2 {
		t.Fatalf("got %v, want 2", got)
	}
}

// --- Concurrency / race safety -------------------------------------------

func TestConcurrentInstrument(t *testing.T) {
	reg := NewRegistry()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := reg.Instrument(inner)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/oauth/v2/token", nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
		}()
	}
	wg.Wait()

	if got := collectCounterSum(t, reg, "goauthy_http_requests_total"); got != goroutines {
		t.Fatalf("got %v, want %d", got, goroutines)
	}
}

func TestConcurrentSecurityCounters(t *testing.T) {
	reg := NewRegistry()
	const n = 100
	var wg sync.WaitGroup
	wg.Add(4 * n)
	for i := 0; i < n; i++ {
		go func() { defer wg.Done(); reg.AuthSuccess() }()
		go func() { defer wg.Done(); reg.AuthFailure() }()
		go func() { defer wg.Done(); reg.TokenOK() }()
		go func() { defer wg.Done(); reg.TokenReject() }()
	}
	wg.Wait()

	if got := collectCounter(t, reg, "goauthy_security_auth_success_total"); got != n {
		t.Fatalf("auth_success: got %v, want %d", got, n)
	}
	if got := collectCounter(t, reg, "goauthy_security_auth_failure_total"); got != n {
		t.Fatalf("auth_failure: got %v, want %d", got, n)
	}
	if got := collectCounter(t, reg, "goauthy_security_token_validation_success_total"); got != n {
		t.Fatalf("token_ok: got %v, want %d", got, n)
	}
	if got := collectCounter(t, reg, "goauthy_security_token_validation_failure_total"); got != n {
		t.Fatalf("token_reject: got %v, want %d", got, n)
	}
}

func TestConcurrentHandlerAuth(t *testing.T) {
	reg := NewRegistry()
	h := reg.Handler("tok")

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			req.Header.Set("Authorization", "Bearer tok")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("valid token: status %d", rr.Code)
			}
		}()
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			req.Header.Set("Authorization", "Bearer wrong")
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("wrong token: status %d", rr.Code)
			}
		}()
	}
	wg.Wait()
}

// --- statusRecorder edge cases --------------------------------------------

func TestStatusRecorderImplicit200(t *testing.T) {
	reg := NewRegistry()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	h := reg.Instrument(inner)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	body := gatherText(t, reg)
	if !strings.Contains(body, `status_class="2xx"`) {
		t.Fatalf("expected 2xx, body:\n%s", body)
	}
}

func TestStatusRecorderExplicitCodes(t *testing.T) {
	reg := NewRegistry()
	tests := []struct {
		code  int
		class string
	}{
		{102, "1xx"},
		{201, "2xx"},
		{301, "3xx"},
		{404, "4xx"},
		{503, "5xx"},
	}
	for _, tt := range tests {
		inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tt.code)
		})
		h := reg.Instrument(inner)
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
	}
	body := gatherText(t, reg)
	for _, tt := range tests {
		want := `status_class="` + tt.class + `"`
		if !strings.Contains(body, want) {
			t.Errorf("status %d: expected %s", tt.code, want)
		}
	}
}

func TestStatusRecorderFirstWriteHeaderWins(t *testing.T) {
	reg := NewRegistry()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		w.WriteHeader(http.StatusInternalServerError) // second call ignored
	})
	h := reg.Instrument(inner)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	body := gatherText(t, reg)
	if !strings.Contains(body, `status_class="2xx"`) {
		t.Fatalf("expected 2xx from first WriteHeader, body:\n%s", body)
	}
	if strings.Contains(body, `status_class="5xx"`) {
		t.Fatalf("second WriteHeader should be ignored, body:\n%s", body)
	}
}

func TestStatusRecorderWriteAfterWriteHeader(t *testing.T) {
	reg := NewRegistry()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		w.Write([]byte("body"))
	})
	h := reg.Instrument(inner)
	req := httptest.NewRequest(http.MethodGet, "/auth/v1/roles/x", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status: got %d, want %d", rr.Code, http.StatusAccepted)
	}
}

func TestStatusRecorderUnwrap(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify Unwrap reaches the underlying ResponseWriter.
		uw, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			t.Fatal("statusRecorder does not implement Unwrap")
		}
		if uw.Unwrap() == nil {
			t.Fatal("Unwrap returned nil")
		}
		w.WriteHeader(http.StatusOK)
	})
	reg := NewRegistry()
	h := reg.Instrument(inner)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
}

func TestStatusRecorderResponseControllerFlush(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("data"))
		// Use ResponseController to access Flush via Unwrap chain.
		ctrl := http.NewResponseController(w)
		if err := ctrl.Flush(); err != nil {
			t.Errorf("Flush via ResponseController: %v", err)
		}
	})
	reg := NewRegistry()
	h := reg.Instrument(inner)
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
}

// --- Route classification -------------------------------------------------

func TestClassifyRoute(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", "/"},
		{"/", "/"},
		{"///", "/"},
		// Current production routes.
		{"/oidc/authorize", "/oidc/*"},
		{"/oidc/token", "/oidc/*"},
		{"/oidc/userinfo", "/oidc/*"},
		{"/oidc/device/verify", "/oidc/*"},
		{"/auth/login", "/auth/*"},
		{"/auth/v1/users/subject-123", "/auth/*"},
		{"/auth/v1/api_keys/key/secret", "/auth/*"},
		{"/auth/v1/clients/id/claims", "/auth/*"},
		{"/unknown", "/other"},
		{"/deep/nested/path", "/other"},
		// Prefixes must remain segment-exact.
		{"/oidc", "/other"},
		{"/auth", "/other"},
		{"/oidcanything/token", "/other"},
		{"/authanything/login", "/other"},
		{"/metrics", "/other"},
		{"/metrics/something", "/other"},
		{"/oidc/authorize/", "/oidc/*"},
		{"/auth/login/", "/auth/*"},
	}
	for _, tc := range cases {
		got := classifyRoute(tc.input)
		if got != tc.want {
			t.Errorf("classifyRoute(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestClassifyStatus(t *testing.T) {
	cases := []struct {
		code int
		want string
	}{
		{0, "1xx"},
		{100, "1xx"},
		{199, "1xx"},
		{200, "2xx"},
		{299, "2xx"},
		{300, "3xx"},
		{399, "3xx"},
		{400, "4xx"},
		{499, "4xx"},
		{500, "5xx"},
		{599, "5xx"},
		{999, "5xx"},
	}
	for _, tc := range cases {
		got := classifyStatus(tc.code)
		if got != tc.want {
			t.Errorf("classifyStatus(%d) = %q, want %q", tc.code, got, tc.want)
		}
	}
}

// --- Metric name stability -----------------------------------------------

func TestMetricNamesAreStable(t *testing.T) {
	reg := NewRegistry()
	expected := []string{
		"goauthy_db_readiness_success_total",
		"goauthy_db_readiness_failure_total",
		"goauthy_db_readiness_last_ok_unix_seconds",
		"goauthy_db_pool_open_connections",
		"goauthy_db_pool_idle_connections",
		"goauthy_security_auth_success_total",
		"goauthy_security_auth_failure_total",
		"goauthy_security_token_validation_success_total",
		"goauthy_security_token_validation_failure_total",
	}
	families, err := reg.reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := map[string]bool{}
	for _, mf := range families {
		got[mf.GetName()] = true
	}
	for _, name := range expected {
		if !got[name] {
			t.Errorf("metric %q not registered", name)
		}
	}

	// Labeled metrics appear after first sample.
	h := reg.Instrument(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	families, err = reg.reg.Gather()
	if err != nil {
		t.Fatalf("Gather after instrument: %v", err)
	}
	got = map[string]bool{}
	for _, mf := range families {
		got[mf.GetName()] = true
	}
	for _, name := range []string{
		"goauthy_http_requests_total",
		"goauthy_http_request_duration_seconds",
	} {
		if !got[name] {
			t.Errorf("metric %q not registered after use", name)
		}
	}
}

// --- No global prometheus metric leakage ----------------------------------

func TestNoGlobalMetricLeakage(t *testing.T) {
	reg := NewRegistry()
	reg.AuthSuccess()
	reg.DBReadiness(true)

	gatherer, ok := prometheus.DefaultRegisterer.(prometheus.Gatherer)
	if !ok {
		t.Skip("DefaultRegisterer is not a Gatherer")
	}
	families, err := gatherer.Gather()
	if err != nil {
		t.Fatalf("global Gather: %v", err)
	}
	for _, mf := range families {
		if strings.HasPrefix(mf.GetName(), "goauthy_") {
			t.Errorf("goauthy_ metric %q leaked to global registry", mf.GetName())
		}
	}
}

// --- dto import guard (ensures client_model is available) -----------------

var _ *dto.MetricFamily
