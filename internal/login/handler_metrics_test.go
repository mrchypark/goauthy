package login

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestLoginMetricsAuthSuccessAndFailure(t *testing.T) {
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

func TestLoginMetricsAuthorizedSessionSkipsCounters(t *testing.T) {
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
