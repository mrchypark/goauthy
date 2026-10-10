package login

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
)

const (
	e2eLoginSamples      = 64
	e2eLoginConcurrency  = 16
	e2eLoginPassword     = "synthetic-only-password"
	e2eLoginPeerPrefix   = "198.51.100."
	e2eLoginSubjectLabel = "e2e-cost-subject"
	e2eLoginUserLabel    = "e2e-cost-user"
)

// BEGIN_E2E_DIAGNOSTIC_HELPERS
// The test overlay copies this block into its virtual handler source. Each
// synthetic flow owns its context value; only bounded enum counters are kept.
type e2eDiagnosticStage uint8

const (
	e2eDiagnosticKDFWorkLimit e2eDiagnosticStage = iota
	e2eDiagnosticPolicyError
	e2eDiagnosticIdentityOther
	e2eDiagnosticSessionWriteError
	e2eDiagnosticStageCount
)

type e2eDiagnosticKey struct{}

type e2eDiagnosticRecorder struct {
	counts [e2eDiagnosticStageCount]uint16
}

func withE2EDiagnosticRecorder(ctx context.Context) (context.Context, *e2eDiagnosticRecorder) {
	recorder := &e2eDiagnosticRecorder{}
	return context.WithValue(ctx, e2eDiagnosticKey{}, recorder), recorder
}

func recordE2EDiagnostic(ctx context.Context, stage e2eDiagnosticStage) {
	recorder, _ := ctx.Value(e2eDiagnosticKey{}).(*e2eDiagnosticRecorder)
	if recorder != nil && stage < e2eDiagnosticStageCount {
		recorder.counts[stage]++
	}
}

func diagnosticsCounts(ctx context.Context) [e2eDiagnosticStageCount]uint16 {
	recorder, _ := ctx.Value(e2eDiagnosticKey{}).(*e2eDiagnosticRecorder)
	if recorder == nil {
		return [e2eDiagnosticStageCount]uint16{}
	}
	return recorder.counts
}

func (stage e2eDiagnosticStage) String() string {
	switch stage {
	case e2eDiagnosticKDFWorkLimit:
		return "kdf_work_limit"
	case e2eDiagnosticPolicyError:
		return "policy_error"
	case e2eDiagnosticIdentityOther:
		return "identity_other"
	case e2eDiagnosticSessionWriteError:
		return "session_write_error"
	default:
		return "invalid_stage"
	}
}

// END_E2E_DIAGNOSTIC_HELPERS

type e2eLoginCase struct {
	username     string
	subject      string
	state        string
	peerIP       string
	expectReject bool
}

type e2eLoginOutcome string

const (
	e2eLoginSuccess                 e2eLoginOutcome = "success"
	e2eCredentialRejected           e2eLoginOutcome = "credential_rejected"
	e2eUnexpectedCredentialAccepted e2eLoginOutcome = "unexpected_credential_accept"
	e2eAuthorizeHTTP503             e2eLoginOutcome = "authorize_http_503"
	e2eAuthorizeHTTPOther           e2eLoginOutcome = "authorize_http_other"
	e2eInitCookieMissing            e2eLoginOutcome = "init_cookie_missing"
	e2eInteractionMissing           e2eLoginOutcome = "interaction_missing"
	e2ePasswordHTTP401              e2eLoginOutcome = "password_http_401"
	e2ePasswordHTTP403              e2eLoginOutcome = "password_http_403"
	e2ePasswordHTTP429              e2eLoginOutcome = "password_http_429"
	e2ePasswordHTTP503              e2eLoginOutcome = "password_http_503"
	e2ePasswordHTTPOther            e2eLoginOutcome = "password_http_other"
	e2eResultRedirectInvalid        e2eLoginOutcome = "result_redirect_invalid"
	e2eRotatedCookieMissing         e2eLoginOutcome = "rotated_cookie_missing"
	e2eSessionLookupNotFound        e2eLoginOutcome = "session_lookup_not_found"
	e2eSessionLookupRevoked         e2eLoginOutcome = "session_lookup_revoked"
	e2eSessionLookupExpired         e2eLoginOutcome = "session_lookup_expired"
	e2eSessionLookupPeerMismatch    e2eLoginOutcome = "session_lookup_peer_mismatch"
	e2eSessionLookupOther           e2eLoginOutcome = "session_lookup_other"
	e2eSessionIdentityMismatch      e2eLoginOutcome = "session_identity_mismatch"
)

type e2eLoginObservation struct {
	duration       time.Duration
	responseAt     time.Time
	outcome        e2eLoginOutcome
	rotatedSession string
	expectReject   bool
	postCompleted  bool
	diagnostics    [e2eDiagnosticStageCount]uint16
}

type e2eLoginSummary struct {
	attempted        int
	postCompleted    int
	successes        int
	postLatencies    []time.Duration
	successLatency   []time.Duration
	responseSpan     time.Duration
	caseOutcomes     map[string]int
	diagnosticCounts map[string]int
	post503Causes    map[string]int
}

func defaultKDFLoginFixture(t *testing.T, label string, count int) (*Handler, []e2eLoginCase) {
	t.Helper()
	policy := credential.DefaultPolicy()
	wantPolicy := credential.Policy{MemoryKiB: 19 * 1024, Iterations: 2, Parallelism: 1, MaxConcurrency: 4, WaitTimeout: 250 * time.Millisecond}
	if policy != wantPolicy {
		t.Fatalf("default credential policy=%+v want=%+v", policy, wantPolicy)
	}
	hasher, err := credential.NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	h, db := testHandlerWithDB(t, false)
	store, err := identity.NewStoreWithHasher(db, hasher)
	if err != nil {
		t.Fatal(err)
	}
	// Both fixture registration and authentication use this private exact-default
	// hasher; no package-global policy or hasher is changed.
	h.identity = store
	phc, err := hasher.Hash(context.Background(), []byte(e2eLoginPassword))
	if err != nil {
		t.Fatal(err)
	}
	cases := make([]e2eLoginCase, count)
	for i := range cases {
		subject := fmt.Sprintf("%s-%s-%02d", e2eLoginSubjectLabel, label, i)
		username := fmt.Sprintf("%s-%s-%02d", e2eLoginUserLabel, label, i)
		if _, err := store.BootstrapUser(context.Background(), subject, username, phc); err != nil {
			t.Fatalf("seed synthetic account %d: %v", i, err)
		}
		values := authorizeValues()
		state := fmt.Sprintf("%032x", i+1)
		values.Set("state", state)
		cases[i] = e2eLoginCase{
			username:     username,
			subject:      subject,
			state:        state,
			peerIP:       fmt.Sprintf("%s%d", e2eLoginPeerPrefix, i+1),
			expectReject: i%8 == 7,
		}
	}
	// The shared unit-test fixture suppresses login delay waits. Restore the
	// production wait function, while keeping its real login-policy store and
	// durable policy.Success behavior active.
	h.wait = waitContext
	return h, cases
}

func collectE2ESessionCookie(h *Handler, cookies []*http.Cookie) *http.Cookie {
	name, err := browser.CookieName(h.issuer)
	if err != nil {
		return nil
	}
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func classifyE2ESessionError(err error) e2eLoginOutcome {
	switch {
	case errors.Is(err, browser.ErrNotFound):
		return e2eSessionLookupNotFound
	case errors.Is(err, browser.ErrRevoked):
		return e2eSessionLookupRevoked
	case errors.Is(err, browser.ErrExpired):
		return e2eSessionLookupExpired
	case errors.Is(err, browser.ErrPeerIPMismatch):
		return e2eSessionLookupPeerMismatch
	default:
		return e2eSessionLookupOther
	}
}

func e2e503Attribution(observation e2eLoginObservation) string {
	if observation.outcome != e2ePasswordHTTP503 {
		return "not_503"
	}
	var found e2eDiagnosticStage
	count := uint16(0)
	for stage, stageCount := range observation.diagnostics {
		if stageCount == 0 {
			continue
		}
		count += stageCount
		found = e2eDiagnosticStage(stage)
	}
	if count != 1 {
		return "unattributed"
	}
	return found.String()
}

// runMeasuredE2ELogin times only the in-process HTTP request path from the
// Authorize GET through the password POST response. Session readback is done
// after the cohort response makespan has been captured.
func runMeasuredE2ELogin(h *Handler, testCase e2eLoginCase) e2eLoginObservation {
	diagnosticContext, _ := withE2EDiagnosticRecorder(context.Background())
	values := authorizeValues()
	values.Set("state", testCase.state)
	get := httptest.NewRequest(http.MethodGet, authorizePath+"?"+values.Encode(), nil)
	get = get.WithContext(diagnosticContext)
	get.RemoteAddr = testCase.peerIP + ":1234"
	page := httptest.NewRecorder()
	started := time.Now()
	finish := func(outcome e2eLoginOutcome) e2eLoginObservation {
		return e2eLoginObservation{duration: time.Since(started), responseAt: time.Now(), outcome: outcome, expectReject: testCase.expectReject, diagnostics: diagnosticsCounts(diagnosticContext)}
	}
	h.Authorize(page, get)
	if page.Code != http.StatusOK {
		if page.Code == http.StatusServiceUnavailable {
			return finish(e2eAuthorizeHTTP503)
		}
		return finish(e2eAuthorizeHTTPOther)
	}
	initCookie := collectE2ESessionCookie(h, page.Result().Cookies())
	if initCookie == nil {
		return finish(e2eInitCookieMissing)
	}
	interactionMatch := interactionPattern.FindStringSubmatch(page.Body.String())
	if len(interactionMatch) != 2 {
		return finish(e2eInteractionMissing)
	}
	password := e2eLoginPassword
	if testCase.expectReject {
		password = "synthetic-only-incorrect-password"
	}
	post := postLogin(initCookie, interactionMatch[1], testCase.username, password)
	post = post.WithContext(diagnosticContext)
	post.RemoteAddr = testCase.peerIP + ":1234"
	completed := httptest.NewRecorder()
	h.Login(completed, post)
	responseAt := time.Now()
	responseDuration := responseAt.Sub(started)
	finishResponse := func(outcome e2eLoginOutcome) e2eLoginObservation {
		return e2eLoginObservation{duration: responseDuration, responseAt: responseAt, outcome: outcome, expectReject: testCase.expectReject, postCompleted: true, diagnostics: diagnosticsCounts(diagnosticContext)}
	}
	if completed.Code != http.StatusSeeOther {
		switch completed.Code {
		case http.StatusUnauthorized:
			if testCase.expectReject {
				return finishResponse(e2eCredentialRejected)
			}
			return finishResponse(e2ePasswordHTTP401)
		case http.StatusForbidden:
			return finishResponse(e2ePasswordHTTP403)
		case http.StatusTooManyRequests:
			return finishResponse(e2ePasswordHTTP429)
		case http.StatusServiceUnavailable:
			return finishResponse(e2ePasswordHTTP503)
		default:
			return finishResponse(e2ePasswordHTTPOther)
		}
	}
	if testCase.expectReject {
		return finishResponse(e2eUnexpectedCredentialAccepted)
	}
	location, err := url.Parse(completed.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" || location.Query().Get("state") != testCase.state {
		return finishResponse(e2eResultRedirectInvalid)
	}
	rotated := collectE2ESessionCookie(h, completed.Result().Cookies())
	if rotated == nil || rotated.Value == initCookie.Value {
		return finishResponse(e2eRotatedCookieMissing)
	}
	return e2eLoginObservation{
		duration:       responseDuration,
		responseAt:     responseAt,
		outcome:        e2eLoginSuccess,
		rotatedSession: rotated.Value,
		postCompleted:  true,
		diagnostics:    diagnosticsCounts(diagnosticContext),
	}
}

func verifyE2ELoginSessions(h *Handler, cases []e2eLoginCase, observations []e2eLoginObservation) {
	for i := range observations {
		observation := &observations[i]
		if observation.outcome != e2eLoginSuccess {
			continue
		}
		session, err := h.browser.LoadSessionForPeer(context.Background(), observation.rotatedSession, cases[i].peerIP)
		if err != nil {
			observation.outcome = classifyE2ESessionError(err)
		} else if !session.Authenticated() || session.Subject != cases[i].subject || session.AuthenticationMethod != "pwd" {
			observation.outcome = e2eSessionIdentityMismatch
		}
		observation.rotatedSession = ""
	}
}

func nearestRankE2E(samples []time.Duration, quantile float64) time.Duration {
	ordered := append([]time.Duration(nil), samples...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := (len(ordered)*int(quantile*100)+99)/100 - 1
	return ordered[index]
}

func summarizeE2ELogin(observations []e2eLoginObservation, cohortStart time.Time) e2eLoginSummary {
	summary := e2eLoginSummary{
		attempted:        len(observations),
		caseOutcomes:     make(map[string]int),
		diagnosticCounts: make(map[string]int),
		post503Causes:    make(map[string]int),
	}
	for _, observation := range observations {
		credentialCase := "correct_password"
		if observation.expectReject {
			credentialCase = "wrong_password"
		}
		summary.caseOutcomes[credentialCase+"/"+string(observation.outcome)]++
		for stage, count := range observation.diagnostics {
			if count > 0 {
				summary.diagnosticCounts[credentialCase+"/"+e2eDiagnosticStage(stage).String()] += int(count)
			}
		}
		if observation.outcome == e2ePasswordHTTP503 {
			summary.post503Causes[credentialCase+"/"+e2e503Attribution(observation)]++
		}
		if !observation.postCompleted {
			continue
		}
		summary.postCompleted++
		summary.postLatencies = append(summary.postLatencies, observation.duration)
		if elapsed := observation.responseAt.Sub(cohortStart); elapsed > summary.responseSpan {
			summary.responseSpan = elapsed
		}
		if observation.outcome == e2eLoginSuccess {
			summary.successes++
			summary.successLatency = append(summary.successLatency, observation.duration)
		}
	}
	return summary
}

func e2eLoginContractViolations(observations []e2eLoginObservation) []e2eLoginOutcome {
	violations := make([]e2eLoginOutcome, 0)
	for _, observation := range observations {
		switch observation.outcome {
		case e2eUnexpectedCredentialAccepted,
			e2eResultRedirectInvalid,
			e2eRotatedCookieMissing,
			e2eSessionLookupNotFound,
			e2eSessionLookupRevoked,
			e2eSessionLookupExpired,
			e2eSessionLookupPeerMismatch,
			e2eSessionLookupOther,
			e2eSessionIdentityMismatch:
			violations = append(violations, observation.outcome)
		}
	}
	return violations
}

func reportE2ELogin(t *testing.T, concurrency int, observations []e2eLoginObservation, makespan time.Duration) {
	t.Helper()
	summary := summarizeE2ELogin(observations, time.Time{})
	if summary.attempted == 0 {
		t.Fatal("empty end-to-end cohort")
	}
	formatCounts := func(values map[string]int) string {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		counts := make([]string, 0, len(keys))
		for _, key := range keys {
			counts = append(counts, fmt.Sprintf("%s=%d", key, values[key]))
		}
		return strings.Join(counts, ",")
	}
	completedRate, successRate := 0.0, 0.0
	if makespan > 0 {
		completedRate = float64(summary.postCompleted) / makespan.Seconds()
		successRate = float64(summary.successes) / makespan.Seconds()
	}
	t.Logf("login_e2e concurrency=%d attempts=%d post_completed=%d successes=%d post_makespan=%s completed_throughput=%.2f/s success_throughput=%.2f/s post_latency_n=%d success_latency_n=%d case_outcomes=[%s] post_503_causes=[%s] diagnostic_events=[%s]",
		concurrency, summary.attempted, summary.postCompleted, summary.successes, makespan,
		completedRate, successRate, len(summary.postLatencies), len(summary.successLatency),
		formatCounts(summary.caseOutcomes), formatCounts(summary.post503Causes), formatCounts(summary.diagnosticCounts))
	if len(summary.postLatencies) > 0 {
		t.Logf("login_e2e_post_latency concurrency=%d n=%d p50=%s p95=%s max=%s",
			concurrency, len(summary.postLatencies), nearestRankE2E(summary.postLatencies, .50), nearestRankE2E(summary.postLatencies, .95), nearestRankE2E(summary.postLatencies, 1))
	}
	if len(summary.successLatency) > 0 {
		t.Logf("login_e2e_success_latency concurrency=%d n=%d p50=%s p95=%s max=%s",
			concurrency, len(summary.successLatency), nearestRankE2E(summary.successLatency, .50), nearestRankE2E(summary.successLatency, .95), nearestRankE2E(summary.successLatency, 1))
	}
}

func TestE2EDiagnosticRecorderAndClassification(t *testing.T) {
	ctxA, _ := withE2EDiagnosticRecorder(context.Background())
	ctxB, _ := withE2EDiagnosticRecorder(context.Background())
	recordE2EDiagnostic(ctxA, e2eDiagnosticKDFWorkLimit)
	recordE2EDiagnostic(ctxB, e2eDiagnosticPolicyError)
	if got := diagnosticsCounts(ctxA); got[e2eDiagnosticKDFWorkLimit] != 1 || got[e2eDiagnosticPolicyError] != 0 {
		t.Fatalf("request A diagnostics=%v", got)
	}
	if got := diagnosticsCounts(ctxB); got[e2eDiagnosticPolicyError] != 1 || got[e2eDiagnosticKDFWorkLimit] != 0 {
		t.Fatalf("request B diagnostics=%v", got)
	}
	if got := e2e503Attribution(e2eLoginObservation{outcome: e2eCredentialRejected, diagnostics: [e2eDiagnosticStageCount]uint16{0, 0, 1, 0}}); got != "not_503" {
		t.Fatalf("credential rejection attribution=%q", got)
	}
	if got := e2e503Attribution(e2eLoginObservation{outcome: e2ePasswordHTTP503}); got != "unattributed" {
		t.Fatalf("empty diagnostic attribution=%q", got)
	}
	if got := e2e503Attribution(e2eLoginObservation{outcome: e2ePasswordHTTP503, diagnostics: [e2eDiagnosticStageCount]uint16{1}}); got != "kdf_work_limit" {
		t.Fatalf("typed diagnostic attribution=%q", got)
	}
	if got := e2e503Attribution(e2eLoginObservation{outcome: e2ePasswordHTTP503, diagnostics: [e2eDiagnosticStageCount]uint16{1, 1}}); got != "unattributed" {
		t.Fatalf("ambiguous diagnostic attribution=%q", got)
	}
}

func TestE2EPostCompletionAccounting(t *testing.T) {
	start := time.Now()
	observations := []e2eLoginObservation{
		{outcome: e2eAuthorizeHTTP503, expectReject: false},
		{outcome: e2eInitCookieMissing, expectReject: true},
		{outcome: e2ePasswordHTTP503, expectReject: false, postCompleted: true, duration: time.Millisecond, responseAt: start.Add(time.Millisecond)},
		{outcome: e2eCredentialRejected, expectReject: true, postCompleted: true, duration: 2 * time.Millisecond, responseAt: start.Add(2 * time.Millisecond)},
		{outcome: e2eLoginSuccess, postCompleted: true, duration: 3 * time.Millisecond, responseAt: start.Add(3 * time.Millisecond)},
	}
	summary := summarizeE2ELogin(observations, start)
	if summary.attempted != 5 || summary.postCompleted != 3 || summary.successes != 1 || len(summary.postLatencies) != 3 || len(summary.successLatency) != 1 {
		t.Fatalf("summary=%+v; early GET/cookie outcomes must not count as POST-completed", summary)
	}
	if summary.caseOutcomes["correct_password/authorize_http_503"] != 1 || summary.caseOutcomes["wrong_password/init_cookie_missing"] != 1 || summary.caseOutcomes["correct_password/password_http_503"] != 1 || summary.caseOutcomes["wrong_password/credential_rejected"] != 1 || summary.caseOutcomes["correct_password/success"] != 1 {
		t.Fatalf("case outcomes=%v", summary.caseOutcomes)
	}
}

func TestE2ELoginContractViolations(t *testing.T) {
	violations := []e2eLoginOutcome{
		e2eUnexpectedCredentialAccepted,
		e2eResultRedirectInvalid,
		e2eRotatedCookieMissing,
		e2eSessionLookupNotFound,
		e2eSessionLookupRevoked,
		e2eSessionLookupExpired,
		e2eSessionLookupPeerMismatch,
		e2eSessionLookupOther,
		e2eSessionIdentityMismatch,
	}
	for _, outcome := range violations {
		if got := e2eLoginContractViolations([]e2eLoginObservation{{outcome: outcome}}); len(got) != 1 || got[0] != outcome {
			t.Errorf("contract violation %q returned %v", outcome, got)
		}
	}
	for _, outcome := range []e2eLoginOutcome{e2eCredentialRejected, e2ePasswordHTTP503, e2eAuthorizeHTTP503} {
		if got := e2eLoginContractViolations([]e2eLoginObservation{{outcome: outcome}}); len(got) != 0 {
			t.Errorf("measured outcome %q was treated as a contract violation: %v", outcome, got)
		}
	}
}

func TestLoginEndToEndDefaultPolicyCost(t *testing.T) {
	var allObservations []e2eLoginObservation
	for _, concurrency := range []int{1, e2eLoginConcurrency} {
		label := fmt.Sprintf("c%d", concurrency)
		h, cases := defaultKDFLoginFixture(t, label, e2eLoginSamples)
		observations := make([]e2eLoginObservation, e2eLoginSamples)
		var cohortStart time.Time
		if concurrency == 1 {
			cohortStart = time.Now()
			for i, testCase := range cases {
				observations[i] = runMeasuredE2ELogin(h, testCase)
			}
		} else {
			start := make(chan struct{})
			jobs := make(chan int)
			ready := make(chan struct{}, concurrency)
			var workers sync.WaitGroup
			workers.Add(concurrency)
			for worker := 0; worker < concurrency; worker++ {
				go func() {
					defer workers.Done()
					ready <- struct{}{}
					<-start
					for i := range jobs {
						observations[i] = runMeasuredE2ELogin(h, cases[i])
					}
				}()
			}
			for worker := 0; worker < concurrency; worker++ {
				<-ready
			}
			cohortStart = time.Now()
			close(start)
			for i := range cases {
				jobs <- i
			}
			close(jobs)
			workers.Wait()
		}
		verifyE2ELoginSessions(h, cases, observations)
		summary := summarizeE2ELogin(observations, cohortStart)
		reportE2ELogin(t, concurrency, observations, summary.responseSpan)
		allObservations = append(allObservations, observations...)
	}
	if violations := e2eLoginContractViolations(allObservations); len(violations) > 0 {
		t.Errorf("login E2E authentication contract violations: %v", violations)
	}
}
