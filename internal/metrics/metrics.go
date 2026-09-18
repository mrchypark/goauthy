// Package metrics provides a bounded Prometheus metrics core for goauthy.
//
// All collectors are registered on a private prometheus.Registry so the
// process-wide default registry is never touched. Call NewRegistry to
// obtain an isolated instance.
package metrics

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ------------------------------------------------------------------
// Clock abstraction — production uses time.Now; tests inject a fake.
// ------------------------------------------------------------------

type clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// ------------------------------------------------------------------
// HTTP method allowlist — bounded, low-cardinality.
// ------------------------------------------------------------------

var allowedMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "HEAD": true, "OPTIONS": true,
}

// sanitizeMethod returns the HTTP method if it is in the bounded
// allowlist, otherwise "OTHER". This prevents unbounded cardinality
// from caller-supplied or exotic methods.
func sanitizeMethod(m string) string {
	if allowedMethods[m] {
		return m
	}
	return "OTHER"
}

// ------------------------------------------------------------------
// Route classification — bounded, low-cardinality.
// ------------------------------------------------------------------

// classifyRoute collapses a URL path into one of a fixed, finite set
// of route class labels. Unknown or user-influenced paths map to
// "/other", keeping cardinality constant regardless of input.
// Matching is segment-exact: /oidcanything does NOT match /oidc/, and
// /authanything does NOT match /auth/.
func classifyRoute(path string) string {
	path = strings.TrimRight(path, "/")
	if path == "" {
		return "/"
	}
	switch {
	case strings.HasPrefix(path, "/oidc/"):
		return "/oidc/*"
	case strings.HasPrefix(path, "/auth/"):
		return "/auth/*"
	default:
		return "/other"
	}
}

// classifyStatus maps an HTTP status code to a class label.
func classifyStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500:
		return "5xx"
	default:
		return "1xx"
	}
}

// ------------------------------------------------------------------
// Registry
// ------------------------------------------------------------------

// Registry is an isolated metrics collector set backed by its own
// prometheus.Registry. It is safe for concurrent use.
type Registry struct {
	reg *prometheus.Registry

	httpRequestsTotal   *prometheus.CounterVec
	httpRequestDuration *prometheus.HistogramVec

	dbReadinessSuccess prometheus.Counter
	dbReadinessFailure prometheus.Counter
	dbReadinessLastOK  prometheus.Gauge
	dbPoolOpenConns    prometheus.Gauge
	dbPoolIdleConns    prometheus.Gauge
	dbQueryDuration    *prometheus.HistogramVec

	securityAuthSuccess prometheus.Counter
	securityAuthFailure prometheus.Counter
	securityTokenOK     prometheus.Counter
	securityTokenReject prometheus.Counter

	cacheHits      *prometheus.CounterVec
	cacheMisses    *prometheus.CounterVec
	cacheEvictions *prometheus.CounterVec

	clk clock
}

// NewRegistry creates a new isolated Registry with the real clock.
// Callers that need deterministic timing should use newRegistryForTesting.
func NewRegistry() *Registry {
	return newRegistry(realClock{})
}

// newRegistryForTesting creates a Registry with an injected clock
// so histogram durations and DBReadiness timestamps are exact and
// deterministic. No sleeps or elapsed assertions are needed.
func newRegistryForTesting(clk clock) *Registry {
	return newRegistry(clk)
}

func newRegistry(clk clock) *Registry {
	reg := prometheus.NewRegistry()

	r := &Registry{
		reg: reg,
		clk: clk,
		httpRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "goauthy_http_requests_total",
				Help: "Total number of HTTP requests processed.",
			},
			[]string{"method", "route_class", "status_class"},
		),
		httpRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "goauthy_http_request_duration_seconds",
				Help:    "Histogram of HTTP request latency in seconds.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "route_class", "status_class"},
		),

		dbReadinessSuccess: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "goauthy_db_readiness_success_total",
				Help: "Total number of successful database readiness checks.",
			},
		),
		dbReadinessFailure: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "goauthy_db_readiness_failure_total",
				Help: "Total number of failed database readiness checks.",
			},
		),
		dbReadinessLastOK: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "goauthy_db_readiness_last_ok_unix_seconds",
				Help: "Unix timestamp of the last successful database readiness check.",
			},
		),
		dbPoolOpenConns: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "goauthy_db_pool_open_connections",
				Help: "Current number of open database pool connections.",
			},
		),
		dbPoolIdleConns: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: "goauthy_db_pool_idle_connections",
				Help: "Current number of idle database pool connections.",
			},
		),

		securityAuthSuccess: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "goauthy_security_auth_success_total",
				Help: "Total number of successful authentication attempts.",
			},
		),
		securityAuthFailure: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "goauthy_security_auth_failure_total",
				Help: "Total number of failed authentication attempts.",
			},
		),
		securityTokenOK: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "goauthy_security_token_validation_success_total",
				Help: "Total number of successful token validations.",
			},
		),
		securityTokenReject: prometheus.NewCounter(
			prometheus.CounterOpts{
				Name: "goauthy_security_token_validation_failure_total",
				Help: "Total number of failed token validations.",
			},
		),

		dbQueryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "goauthy_db_query_duration_seconds",
				Help:    "Histogram of database query latency in seconds.",
				Buckets: []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
			},
			[]string{"operation"},
		),

		cacheHits: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "goauthy_cache_hits_total",
				Help: "Total number of cache hits.",
			},
			[]string{"cache"},
		),
		cacheMisses: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "goauthy_cache_misses_total",
				Help: "Total number of cache misses.",
			},
			[]string{"cache"},
		),
		cacheEvictions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "goauthy_cache_evictions_total",
				Help: "Total number of cache evictions.",
			},
			[]string{"cache"},
		),
	}

	reg.MustRegister(
		r.httpRequestsTotal,
		r.httpRequestDuration,
		r.dbReadinessSuccess,
		r.dbReadinessFailure,
		r.dbReadinessLastOK,
		r.dbPoolOpenConns,
		r.dbPoolIdleConns,
		r.dbQueryDuration,
		r.securityAuthSuccess,
		r.securityAuthFailure,
		r.securityTokenOK,
		r.securityTokenReject,
		r.cacheHits,
		r.cacheMisses,
		r.cacheEvictions,
	)

	return r
}

// Handler returns an http.Handler that serves Prometheus metrics in the
// default text exposition format. If token is non-empty the handler
// requires a matching Bearer token in the Authorization header. The
// configured token is pre-hashed with SHA-256 and compared using
// constant-time comparison on fixed-size digests, preventing timing
// side-channels.
func (r *Registry) Handler(token string) http.Handler {
	if token == "" {
		return promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{})
	}
	return &authHandler{
		inner:  promhttp.HandlerFor(r.reg, promhttp.HandlerOpts{}),
		digest: sha256.Sum256([]byte(token)),
	}
}

type authHandler struct {
	inner  http.Handler
	digest [sha256.Size]byte
}

func (a *authHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	hdrs := req.Header.Values("Authorization")
	if len(hdrs) != 1 {
		rejectAuth(w)
		return
	}
	hdr := hdrs[0]
	const prefix = "Bearer "
	if len(hdr) <= len(prefix) || hdr[:len(prefix)] != prefix {
		rejectAuth(w)
		return
	}
	tok := hdr[len(prefix):]
	if len(tok) == 0 || containsInvalidBearerChar(tok) {
		rejectAuth(w)
		return
	}
	got := sha256.Sum256([]byte(tok))
	if subtle.ConstantTimeCompare(got[:], a.digest[:]) != 1 {
		rejectAuth(w)
		return
	}
	a.inner.ServeHTTP(w, req)
}

// containsInvalidBearerChar reports whether s contains any byte that is
// forbidden in a Bearer token: ASCII whitespace (space, tab, CR, LF) or
// comma. This prevents comma-joined credentials, whitespace-separated
// tokens, and other malformed bearer values from being accepted.
func containsInvalidBearerChar(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n', ',':
			return true
		}
	}
	return false
}

// rejectAuth sends a 401 with WWW-Authenticate but no secret leakage.
func rejectAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// Instrument wraps an http.Handler to record request count, latency,
// and status-class on the private registry. The route_class label is
// derived from the package-fixed classifyRoute classifier. Method
// labels are bounded to the fixed allowlist with OTHER fallback.
func (r *Registry) Instrument(next http.Handler) http.Handler {
	return &instrumentedHandler{
		next: next,
		reg:  r,
		clk:  r.clk,
	}
}

type instrumentedHandler struct {
	next http.Handler
	reg  *Registry
	clk  clock
}

func (h *instrumentedHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	start := h.clk.Now()
	sw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	h.next.ServeHTTP(sw, req)
	elapsed := h.clk.Now().Sub(start).Seconds()

	method := sanitizeMethod(req.Method)
	routeClass := classifyRoute(req.URL.Path)
	statusClass := classifyStatus(sw.status)

	h.reg.httpRequestsTotal.WithLabelValues(method, routeClass, statusClass).Inc()
	h.reg.httpRequestDuration.WithLabelValues(method, routeClass, statusClass).Observe(elapsed)
}

// ------------------------------------------------------------------
// statusRecorder — records only the first explicit WriteHeader,
// preserves implicit 200, and exposes Unwrap for ResponseController.
// ------------------------------------------------------------------

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (sr *statusRecorder) WriteHeader(code int) {
	if sr.wroteHeader {
		return // first call wins; subsequent calls silently ignored.
	}
	sr.wroteHeader = true
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Unwrap() http.ResponseWriter {
	return sr.ResponseWriter
}

// ------------------------------------------------------------------
// DB / pool / security counter methods
// ------------------------------------------------------------------

// DBReadiness records the outcome of a database readiness probe.
func (r *Registry) DBReadiness(ok bool) {
	if ok {
		r.dbReadinessSuccess.Inc()
		r.dbReadinessLastOK.Set(float64(r.clk.Now().Unix()))
	} else {
		r.dbReadinessFailure.Inc()
	}
}

// DBPool updates the connection pool gauges.
func (r *Registry) DBPool(open, idle int) {
	r.dbPoolOpenConns.Set(float64(open))
	r.dbPoolIdleConns.Set(float64(idle))
}

// AuthSuccess increments the successful authentication counter.
func (r *Registry) AuthSuccess() { r.securityAuthSuccess.Inc() }

// AuthFailure increments the failed authentication counter.
func (r *Registry) AuthFailure() { r.securityAuthFailure.Inc() }

// TokenOK increments the successful token-validation counter.
func (r *Registry) TokenOK() { r.securityTokenOK.Inc() }

// TokenReject increments the failed token-validation counter.
func (r *Registry) TokenReject() { r.securityTokenReject.Inc() }

// DBQueryDuration records a database query duration.
func (r *Registry) DBQueryDuration(operation string, seconds float64) {
	r.dbQueryDuration.WithLabelValues(operation).Observe(seconds)
}

// CacheHit increments the cache hit counter for the given cache name.
func (r *Registry) CacheHit(cache string) { r.cacheHits.WithLabelValues(cache).Inc() }

// CacheMiss increments the cache miss counter for the given cache name.
func (r *Registry) CacheMiss(cache string) { r.cacheMisses.WithLabelValues(cache).Inc() }

// CacheEviction increments the cache eviction counter for the given cache name.
func (r *Registry) CacheEviction(cache string) { r.cacheEvictions.WithLabelValues(cache).Inc() }

// ------------------------------------------------------------------
// Collector accessors — test-only read path via prometheus.Collector.
// ------------------------------------------------------------------

// AuthSuccessCounter returns the auth-success counter for test inspection.
func (r *Registry) AuthSuccessCounter() prometheus.Collector { return r.securityAuthSuccess }

// AuthFailureCounter returns the auth-failure counter for test inspection.
func (r *Registry) AuthFailureCounter() prometheus.Collector { return r.securityAuthFailure }

// TokenOKCounter returns the token-validation-success counter for test inspection.
func (r *Registry) TokenOKCounter() prometheus.Collector { return r.securityTokenOK }

// TokenRejectCounter returns the token-validation-failure counter for test inspection.
func (r *Registry) TokenRejectCounter() prometheus.Collector { return r.securityTokenReject }
