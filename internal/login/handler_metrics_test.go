package login

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/metrics"
	"github.com/mrchypark/goauthy/internal/tracing"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLoginMetricsAuthSuccessAndFailure(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	reg := metrics.NewRegistry()
	h.SetMetrics(reg)

	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	// Wrong password → AuthFailure.
	bad := httptest.NewRecorder()
	h.Login(bad, postLogin(init, interaction, "alice", "wrong password"))
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad login status=%d", bad.Code)
	}
	if got := testutil.ToFloat64(reg.AuthFailureCounter()); got != 1 {
		t.Fatalf("after bad login: AuthFailure=%v, want 1", got)
	}
	if got := testutil.ToFloat64(reg.AuthSuccessCounter()); got != 0 {
		t.Fatalf("after bad login: AuthSuccess=%v, want 0", got)
	}

	// Correct password → AuthSuccess.
	completed := httptest.NewRecorder()
	h.Login(completed, postLogin(init, interaction, "alice", "correct password"))
	if completed.Code != http.StatusSeeOther {
		t.Fatalf("good login status=%d", completed.Code)
	}
	if got := testutil.ToFloat64(reg.AuthSuccessCounter()); got != 1 {
		t.Fatalf("after good login: AuthSuccess=%v, want 1", got)
	}
	if got := testutil.ToFloat64(reg.AuthFailureCounter()); got != 1 {
		t.Fatalf("after good login: AuthFailure=%v, want 1", got)
	}
}

func TestLoginMetricsNoDoubleCountOnWrongThenCorrect(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	reg := metrics.NewRegistry()
	h.SetMetrics(reg)

	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	// Two wrong attempts then one correct.
	for range 2 {
		r := httptest.NewRecorder()
		h.Login(r, postLogin(init, interaction, "alice", "wrong password"))
	}
	if got := testutil.ToFloat64(reg.AuthFailureCounter()); got != 2 {
		t.Fatalf("AuthFailure=%v, want 2", got)
	}

	completed := httptest.NewRecorder()
	h.Login(completed, postLogin(init, interaction, "alice", "correct password"))
	if completed.Code != http.StatusSeeOther {
		t.Fatalf("status=%d", completed.Code)
	}
	if got := testutil.ToFloat64(reg.AuthFailureCounter()); got != 2 {
		t.Fatalf("AuthFailure after correct=%v, want 2", got)
	}
	if got := testutil.ToFloat64(reg.AuthSuccessCounter()); got != 1 {
		t.Fatalf("AuthSuccess=%v, want 1", got)
	}
}

func TestLoginMetricsConcurrentWrongPasswords(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	h.policy = nil
	reg := metrics.NewRegistry()
	h.SetMetrics(reg)

	const n = 50
	loginSlots := make(chan struct{}, 2)

	type attempt struct {
		cookie      *http.Cookie
		interaction string
	}

	attempts := make([]attempt, n)
	for i := range n {
		get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
		page := httptest.NewRecorder()
		h.Authorize(page, get)
		if page.Code != http.StatusOK {
			t.Fatalf("authorize[%d] status=%d", i, page.Code)
		}
		attempts[i] = attempt{
			cookie:      page.Result().Cookies()[0],
			interaction: interactionToken(t, page.Body.String()),
		}
	}

	ready := make(chan struct{}, n)
	start := make(chan struct{})
	errs := make(chan string, n)

	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(a attempt) {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			r := httptest.NewRecorder()
			loginSlots <- struct{}{}
			h.Login(r, postLogin(a.cookie, a.interaction, "alice", "wrong password"))
			<-loginSlots
			if r.Code != http.StatusUnauthorized {
				errs <- fmt.Sprintf("status=%d", r.Code)
			}
		}(attempts[i])
	}

	for range n {
		<-ready
	}
	close(start)
	wg.Wait()
	close(errs)

	for e := range errs {
		t.Fatalf("goroutine error: %s", e)
	}
	if got := testutil.ToFloat64(reg.AuthFailureCounter()); got != n {
		t.Fatalf("AuthFailure=%v, want %d", got, n)
	}
	if got := testutil.ToFloat64(reg.AuthSuccessCounter()); got != 0 {
		t.Fatalf("AuthSuccess=%v, want 0", got)
	}
}

func TestLoginMetricsAuthFailureCountsNewlyBlocking(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	reg := metrics.NewRegistry()
	h.SetMetrics(reg)

	ip := "198.51.100.50"
	now := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	h.now = func() time.Time { return now }

	for i := range 7 {
		get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
		get.RemoteAddr = ip + ":1234"
		page := httptest.NewRecorder()
		h.Authorize(page, get)
		if page.Code != http.StatusOK {
			t.Fatalf("authorize[%d] status=%d", i, page.Code)
		}
		init := page.Result().Cookies()[0]
		inter := interactionToken(t, page.Body.String())

		login := postLogin(init, inter, "alice", "wrong password")
		login.RemoteAddr = ip + ":1234"
		resp := httptest.NewRecorder()
		h.Login(resp, login)

		if i < 6 {
			if resp.Code != http.StatusUnauthorized {
				t.Fatalf("attempt %d: status=%d, want 401", i, resp.Code)
			}
		} else {
			if resp.Code != http.StatusTooManyRequests {
				t.Fatalf("attempt %d: status=%d, want 429", i, resp.Code)
			}
		}
	}

	if got := testutil.ToFloat64(reg.AuthFailureCounter()); got != 7 {
		t.Fatalf("AuthFailure=%v, want 7", got)
	}
}

func TestLoginMetricsNilRegistryNoPanic(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	// No SetMetrics call — metrics is nil.
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	// Wrong password with nil metrics must not panic.
	bad := httptest.NewRecorder()
	h.Login(bad, postLogin(init, interaction, "alice", "wrong password"))
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", bad.Code)
	}

	// Correct password with nil metrics must not panic.
	completed := httptest.NewRecorder()
	h.Login(completed, postLogin(init, interaction, "alice", "correct password"))
	if completed.Code != http.StatusSeeOther {
		t.Fatalf("status=%d", completed.Code)
	}
}

func TestLoginMetricsAuthStagesObservedAndBounded(t *testing.T) {
	t.Parallel()
	_, span := tracing.NewTracer("goauthy/login-metrics-test").Start(context.Background(), "non-recording")
	if span.IsRecording() {
		span.End()
		t.Fatal("test requires tracing to be off")
	}
	span.End()

	h := testHandler(t)
	if h.policy == nil {
		t.Fatal("test requires the real login policy store")
	}
	reg := metrics.NewRegistry()
	h.SetMetrics(reg)
	// Production wires the identity store to the same registry; the three
	// credential stages are recorded there, not on the handler.
	h.identity.SetMetrics(reg)

	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	if page.Code != http.StatusOK {
		t.Fatalf("authorize status=%d", page.Code)
	}
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())

	completed := httptest.NewRecorder()
	h.Login(completed, postLogin(init, interaction, "alice", "correct password"))
	if completed.Code != http.StatusSeeOther {
		t.Fatalf("login status=%d", completed.Code)
	}

	// Observation must not alter the login outcome. The real policy path reaches
	// Check, Allow, CheckAccountLock, and Success with tracing disabled.
	got := testutil.CollectAndCount(reg.AuthStageDurationCollector(), "goauthy_auth_stage_duration_seconds")
	if got != 12 {
		t.Fatalf("auth stage series=%d, want 12", got)
	}

	metricsRegistry := prometheus.NewRegistry()
	if err := metricsRegistry.Register(reg.AuthStageDurationCollector()); err != nil {
		t.Fatalf("register auth-stage collector: %v", err)
	}
	families, err := metricsRegistry.Gather()
	if err != nil {
		t.Fatalf("gather auth-stage metrics: %v", err)
	}
	policyStageCounts := map[string]uint64{
		"policy_check":        0,
		"policy_allow":        0,
		"policy_account_lock": 0,
		"policy_success":      0,
	}
	for _, family := range families {
		if family.GetName() != "goauthy_auth_stage_duration_seconds" {
			continue
		}
		for _, sample := range family.GetMetric() {
			labels := sample.GetLabel()
			if len(labels) != 1 || labels[0].GetName() != "stage" {
				t.Fatalf("auth-stage metric has non-stage labels: %v", labels)
			}
			if _, ok := policyStageCounts[labels[0].GetValue()]; ok {
				policyStageCounts[labels[0].GetValue()] = sample.GetHistogram().GetSampleCount()
			}
		}
	}
	for stage, count := range policyStageCounts {
		if count != 1 {
			t.Errorf("stage %q count=%d, want 1", stage, count)
		}
	}
}

func TestLoginMetricsCanceledStageCompletions(t *testing.T) {
	root, span := tracing.NewTracer("goauthy/canceled-stage-metrics-test").Start(context.Background(), "non-recording")
	defer span.End()
	if span.IsRecording() {
		t.Fatal("test requires tracing to be off")
	}

	h := &Handler{}
	reg := metrics.NewRegistry()
	h.SetMetrics(reg)

	canceled, cancel := context.WithCancel(root)
	cancel()
	h.recordAuthStage(canceled, metrics.AuthStagePolicyCheck, time.Now())
	h.recordAuthStage(canceled, metrics.AuthStagePolicyAllow, time.Now())
	h.recordAuthStage(root, metrics.AuthStagePolicySuccess, time.Now())

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	reg.Handler("").ServeHTTP(response, request)
	text := response.Body.String()
	for _, want := range []string{
		`goauthy_auth_stage_canceled_completions_total{stage="policy_check"} 1`,
		`goauthy_auth_stage_canceled_completions_total{stage="policy_allow"} 1`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics output missing %q", want)
		}
	}
	if strings.Contains(text, `goauthy_auth_stage_canceled_completions_total{stage="policy_success"}`) {
		t.Fatal("live-context stage emitted a cancellation completion")
	}

	metricsRegistry := prometheus.NewRegistry()
	if err := metricsRegistry.Register(reg.AuthStageDurationCollector()); err != nil {
		t.Fatal(err)
	}
	families, err := metricsRegistry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	durations := make(map[string]uint64)
	for _, family := range families {
		if family.GetName() != "goauthy_auth_stage_duration_seconds" {
			continue
		}
		for _, sample := range family.GetMetric() {
			for _, label := range sample.GetLabel() {
				if label.GetName() == "stage" {
					durations[label.GetValue()] = sample.GetHistogram().GetSampleCount()
				}
			}
		}
	}
	for _, stage := range []string{"policy_check", "policy_allow", "policy_success"} {
		if durations[stage] != 1 {
			t.Errorf("duration observations for %s=%d, want 1", stage, durations[stage])
		}
	}
}

func TestLoginMetricsAuthorizedSessionSkipsCounters(t *testing.T) {
	t.Parallel()
	h := testHandler(t)
	reg := metrics.NewRegistry()
	h.SetMetrics(reg)

	// Create an already-authenticated session.
	cookie := authenticatedCookie(t, h)
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil)
	get.AddCookie(cookie)
	page := httptest.NewRecorder()
	h.Authorize(page, get)
	// Session reuse — no Login call, so counters must stay zero.
	if got := testutil.ToFloat64(reg.AuthSuccessCounter()); got != 0 {
		t.Fatalf("AuthSuccess=%v, want 0", got)
	}
	if got := testutil.ToFloat64(reg.AuthFailureCounter()); got != 0 {
		t.Fatalf("AuthFailure=%v, want 0", got)
	}
}
