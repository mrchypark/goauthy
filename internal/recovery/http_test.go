package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/loginpolicy"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestRequestResetEnumerationDeliveryAndLimiter(t *testing.T) {
	service, sender := testService(t, "subject/one", "alice")
	if err := service.BindEmail(context.Background(), "subject/one", "Alice@Example.TEST"); err != nil {
		t.Fatal(err)
	}
	known := resetRequest(t, service, "alice@example.test", "192.0.2.10:1000", "")
	unknown := resetRequest(t, service, "nobody@example.test", "192.0.2.11:1000", "")
	if known.Code != http.StatusOK || unknown.Code != http.StatusOK || known.Body.String() != unknown.Body.String() || known.Body.Len() != 0 {
		t.Fatalf("enumeration responses known=%d/%q unknown=%d/%q", known.Code, known.Body.String(), unknown.Code, unknown.Body.String())
	}
	if len(sender.messages()) != 1 {
		t.Fatalf("messages=%+v", sender.messages())
	}
	message := sender.messages()[0]
	if message.To != "alice@example.test" || !strings.Contains(message.ResetURL, "/users/subject%2Fone/reset/") || strings.Contains(message.ResetURL, " ") || message.ExpiresAt.IsZero() {
		t.Fatalf("unsafe reset message=%+v", message)
	}
	for attempt := 0; attempt < loginpolicy.PasswordResetAttemptLimit+1; attempt++ {
		response := resetRequest(t, service, "alice@example.test", "192.0.2.12:1000", "")
		if response.Code != http.StatusOK || response.Body.Len() != 0 {
			t.Fatalf("limited response=%d body=%q", response.Code, response.Body.String())
		}
	}
	if got := len(sender.messages()); got != 1+loginpolicy.PasswordResetAttemptLimit {
		t.Fatalf("sender count=%d", got)
	}
}

func TestRequestResetSenderFailureAndCrossSite(t *testing.T) {
	service, sender := testService(t, "subject-1", "alice")
	if err := service.BindEmail(context.Background(), "subject-1", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	sender.err = errors.New("delivery failed")
	var reported error
	service.OnError = func(err error) { reported = err }
	response := resetRequest(t, service, "alice@example.test", "192.0.2.20:1000", "")
	if response.Code != http.StatusOK || response.Body.Len() != 0 || !errors.Is(reported, sender.err) {
		t.Fatalf("sender failure response=%d body=%q reported=%v", response.Code, response.Body.String(), reported)
	}
	crossSite := resetRequest(t, service, "alice@example.test", "192.0.2.21:1000", "cross-site")
	if crossSite.Code != http.StatusForbidden || len(sender.messages()) != 1 {
		t.Fatalf("cross-site status=%d messages=%d", crossSite.Code, len(sender.messages()))
	}
}

func TestProofOfWorkAndRequestResetProofBoundary(t *testing.T) {
	service, sender := testService(t, "subject-1", "alice")
	if err := service.BindEmail(context.Background(), "subject-1", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	challengeResponse := httptest.NewRecorder()
	service.ProofOfWork(challengeResponse, httptest.NewRequest(http.MethodPost, "/auth/v1/pow", nil))
	challenge := challengeResponse.Body.String()
	if challengeResponse.Code != http.StatusOK || challenge == "" || challengeResponse.Header().Get("Access-Control-Allow-Origin") != "*" || challengeResponse.Header().Get("Cache-Control") != "no-store" || challengeResponse.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("pow response=%d headers=%#v body=%q", challengeResponse.Code, challengeResponse.Header(), challenge)
	}
	solved := solveProof(t, challenge)
	success := resetRequestWithProof(t, service, "alice@example.test", "192.0.2.50:1000", "", solved)
	if success.Code != http.StatusOK || len(sender.messages()) != 1 {
		t.Fatalf("proved reset status=%d messages=%d", success.Code, len(sender.messages()))
	}
	replay := resetRequestWithProof(t, service, "alice@example.test", "192.0.2.51:1000", "", solved)
	if replay.Code != http.StatusForbidden {
		t.Fatalf("replayed proof status=%d", replay.Code)
	}
	if empty := resetRequestWithProof(t, service, "alice@example.test", "192.0.2.52:1000", "", ""); empty.Code != http.StatusBadRequest {
		t.Fatalf("empty proof status=%d", empty.Code)
	}
	if malformed := resetRequestWithProof(t, service, "alice@example.test", "192.0.2.53:1000", "", "not-a-proof"); malformed.Code != http.StatusForbidden {
		t.Fatalf("malformed proof status=%d", malformed.Code)
	}
	expiring, err := service.pow.Issue(context.Background(), service.powDifficulty, service.powTTL)
	if err != nil {
		t.Fatal(err)
	}
	service.pow.now = func() time.Time { return service.now().Add(2 * time.Minute) }
	if expired := resetRequestWithProof(t, service, "alice@example.test", "192.0.2.54:1000", "", solveProof(t, expiring)); expired.Code != http.StatusForbidden {
		t.Fatalf("expired proof status=%d", expired.Code)
	}
	malformedJSON := httptest.NewRequest(http.MethodPost, "/auth/v1/users/request_reset", strings.NewReader(`{"email":`))
	malformedJSON.Header.Set("Content-Type", "application/json")
	malformedJSON.RemoteAddr = "192.0.2.55:1000"
	malformedResponse := httptest.NewRecorder()
	service.RequestReset(malformedResponse, malformedJSON)
	if malformedResponse.Code != http.StatusBadRequest {
		t.Fatalf("malformed reset JSON status=%d", malformedResponse.Code)
	}
	method := httptest.NewRecorder()
	service.ProofOfWork(method, httptest.NewRequest(http.MethodGet, "/auth/v1/pow", nil))
	if method.Code != http.StatusMethodNotAllowed || method.Header().Get("Access-Control-Allow-Origin") != "*" || method.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("pow method status=%d headers=%#v", method.Code, method.Header())
	}
	service.pow.db = nil
	failedIssue := httptest.NewRecorder()
	service.ProofOfWork(failedIssue, httptest.NewRequest(http.MethodPost, "/auth/v1/pow", nil))
	if failedIssue.Code != http.StatusServiceUnavailable {
		t.Fatalf("pow storage failure status=%d", failedIssue.Code)
	}
}

func TestProofOfWorkHTTPAdmissionUsesDirectPeer(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	if _, err := NewService(service.db, service.identity, service.sender, service.issuer, service.rules, service.policy, service.pow, service.powDifficulty, MaxProofTTL+time.Second); err == nil {
		t.Fatal("accepted excessive PoW TTL")
	}
	for i := 0; i < proofIssueLimit; i++ {
		request := httptest.NewRequest(http.MethodPost, "/auth/v1/pow", nil)
		request.RemoteAddr = "192.0.2.90:" + strconv.Itoa(1000+i)
		request.Header.Add("Forwarded", "for=bad")
		request.Header.Add("Forwarded", "for=198.51.100.99")
		response := httptest.NewRecorder()
		service.ProofOfWork(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("issue %d status=%d", i, response.Code)
		}
	}
	limited := httptest.NewRequest(http.MethodPost, "/auth/v1/pow", nil)
	limited.RemoteAddr = "192.0.2.90:2000"
	limited.Header.Set("X-Forwarded-For", "198.51.100.99")
	limitedResponse := httptest.NewRecorder()
	service.ProofOfWork(limitedResponse, limited)
	if limitedResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("limited status=%d", limitedResponse.Code)
	}
	neighbor := httptest.NewRequest(http.MethodPost, "/auth/v1/pow", nil)
	neighbor.RemoteAddr = "192.0.2.91:2000"
	neighbor.Header.Set("X-Forwarded-For", "not-an-ip")
	neighborResponse := httptest.NewRecorder()
	service.ProofOfWork(neighborResponse, neighbor)
	if neighborResponse.Code != http.StatusOK {
		t.Fatalf("neighbor status=%d", neighborResponse.Code)
	}
	malformed := httptest.NewRequest(http.MethodPost, "/auth/v1/pow", nil)
	malformed.RemoteAddr = "not-a-peer"
	malformedResponse := httptest.NewRecorder()
	service.ProofOfWork(malformedResponse, malformed)
	if malformedResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("malformed peer status=%d", malformedResponse.Code)
	}
}

func TestResetBindingCSRFReplayAndHeaders(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	ctx := context.Background()
	token, _, err := service.identity.IssuePasswordReset(ctx, "subject-1", passwordResetLifetime)
	if err != nil {
		t.Fatal(err)
	}
	get := httptest.NewRequest(http.MethodGet, "/auth/v1/users/subject-1/reset/"+token, nil)
	get.SetPathValue("subject", "subject-1")
	get.SetPathValue("token", token)
	getResponse := httptest.NewRecorder()
	service.GetReset(getResponse, get)
	var document resetResponse
	if getResponse.Code != http.StatusOK || json.Unmarshal(getResponse.Body.Bytes(), &document) != nil || document.CSRFToken == "" || document.PasswordPolicy.ValidDays != 90 || getResponse.Header().Get("Cache-Control") != "no-store" || getResponse.Header().Get("Referrer-Policy") != "no-referrer" || getResponse.Header().Get("X-Content-Type-Options") != "nosniff" || getResponse.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("reset GET status=%d headers=%#v body=%q", getResponse.Code, getResponse.Header(), getResponse.Body.String())
	}
	cookies := getResponse.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != secureCookie || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Path != "/" {
		t.Fatalf("reset cookie=%#v", cookies)
	}
	payload := putReset{MagicLinkID: token, Password: "UpdatedPassword2"}
	missing := putResetRequest(t, service, "subject-1", payload, nil, "")
	if missing.Code != http.StatusUnauthorized {
		t.Fatalf("missing binding status=%d", missing.Code)
	}
	success := putResetRequest(t, service, "subject-1", payload, cookies[0], document.CSRFToken)
	if success.Code != http.StatusAccepted || len(success.Result().Cookies()) != 1 || success.Result().Cookies()[0].MaxAge != -1 {
		t.Fatalf("reset PUT status=%d cookies=%#v", success.Code, success.Result().Cookies())
	}
	replay := putResetRequest(t, service, "subject-1", payload, cookies[0], document.CSRFToken)
	if replay.Code != http.StatusBadRequest {
		t.Fatalf("replay status=%d body=%q", replay.Code, replay.Body.String())
	}
	if got, err := service.identity.Authenticate(ctx, "alice", []byte("UpdatedPassword2")); err != nil || got.Subject != "subject-1" {
		t.Fatalf("reset password authentication=%+v err=%v", got, err)
	}
}

func TestBindEmailRejectsAmbiguousOrForeignOwnership(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	for _, email := range []string{"Alice <alice@example.test>", " alice@example.test", "앨리스@example.test"} {
		if err := service.BindEmail(context.Background(), "subject-1", email); !errors.Is(err, ErrInvalidEmail) {
			t.Fatalf("email=%q err=%v", email, err)
		}
	}
	if err := service.BindEmail(context.Background(), "subject-1", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := service.BindEmail(context.Background(), "subject-2", "alice@example.test"); !errors.Is(err, ErrEmailBound) {
		t.Fatalf("foreign ownership err=%v", err)
	}
}

func TestRegisterOpenPolicyProofDuplicateAndActivation(t *testing.T) {
	service, sender := testService(t, "subject-1", "alice")
	enableOpenRegistration(t, service, ExactRedirectURIs([]string{"https://app.example.test/registered"}))
	callbackCalls := 0
	callbackSubjectExists := false
	service.OnUserCreated = func() {
		callbackCalls++
		rows, err := service.db.Query(context.Background(), rhiza.QueryRequest{
			SQL: `SELECT COUNT(*) FROM identity_users WHERE username=?`, Args: []any{"new@example.test"}, Consistency: rhiza.ConsistencyLinearizable,
		})
		callbackSubjectExists = err == nil && len(rows.Rows) == 1 && rows.Rows[0][0] == int64(1)
	}

	disabled := httptest.NewRecorder()
	plain := httptest.NewRequest(http.MethodPost, "/auth/v1/users/register", strings.NewReader(`{"email":"new@example.test","pow":"x"}`))
	plain.Header.Set("Content-Type", "application/json")
	plain.RemoteAddr = "192.0.2.80:1234"
	service.registration.config.Enabled = false
	service.RegisterOpen(disabled, plain)
	if disabled.Code != http.StatusForbidden || disabled.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("disabled registration=%d headers=%#v", disabled.Code, disabled.Header())
	}
	service.registration.config.Enabled = true

	invalid := openRegistrationRequest(t, service, `{"email":"new@not-allowed.test","given_name":"New","pow":"ignored"}`, "192.0.2.81:1234")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid domain status=%d", invalid.Code)
	}

	challenge, err := service.pow.Issue(context.Background(), service.powDifficulty, service.powTTL)
	if err != nil {
		t.Fatal(err)
	}
	proof := solveProof(t, challenge)
	body := `{"email":"New@Example.Test","given_name":"New","preferred_username":"new-user","user_values":{"city":"Seoul","tz":"Asia/Seoul"},"redirect_uri":"https://app.example.test/registered","pow":"` + proof + `"}`
	created := openRegistrationRequest(t, service, body, "192.0.2.82:1234")
	if created.Code != http.StatusNoContent || created.Body.Len() != 0 || created.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("created registration=%d headers=%#v body=%q", created.Code, created.Header(), created.Body.String())
	}
	messages := sender.messages()
	if len(messages) != 1 || messages[0].To != "new@example.test" || !strings.Contains(messages[0].ResetURL, "/auth/v1/users/") {
		t.Fatalf("registration messages=%#v", messages)
	}
	if callbackCalls != 1 || !callbackSubjectExists {
		t.Fatalf("created callback calls=%d committed=%t", callbackCalls, callbackSubjectExists)
	}
	if got := sender.passwordNewMessages(); len(got) != 1 {
		t.Fatalf("password-new messages=%#v", got)
	}

	replay := openRegistrationRequest(t, service, body, "192.0.2.83:1234")
	if replay.Code != http.StatusForbidden || len(sender.messages()) != 1 {
		t.Fatalf("proof replay=%d messages=%#v", replay.Code, sender.messages())
	}
	duplicateChallenge, err := service.pow.Issue(context.Background(), service.powDifficulty, service.powTTL)
	if err != nil {
		t.Fatal(err)
	}
	duplicateBody := strings.Replace(body, proof, solveProof(t, duplicateChallenge), 1)
	duplicate := openRegistrationRequest(t, service, duplicateBody, "192.0.2.84:1234")
	if duplicate.Code != http.StatusNoContent || duplicate.Body.Len() != 0 || len(sender.alreadyRegisteredRecipients()) != 1 || sender.alreadyRegisteredRecipients()[0] != "new@example.test" {
		t.Fatalf("duplicate registration=%d body=%q already-registered=%#v", duplicate.Code, duplicate.Body.String(), sender.alreadyRegisteredRecipients())
	}
	if callbackCalls != 1 {
		t.Fatalf("duplicate registration invoked callback %d times", callbackCalls)
	}

	parts := strings.Split(messages[0].ResetURL, "/")
	if len(parts) < 2 {
		t.Fatalf("bad new-password URL %q", messages[0].ResetURL)
	}
	subject, token := parts[len(parts)-3], parts[len(parts)-1]
	get := httptest.NewRequest(http.MethodGet, messages[0].ResetURL, nil)
	get.SetPathValue("subject", subject)
	get.SetPathValue("token", token)
	getResponse := httptest.NewRecorder()
	service.GetReset(getResponse, get)
	var document resetResponse
	if getResponse.Code != http.StatusOK || json.Unmarshal(getResponse.Body.Bytes(), &document) != nil {
		t.Fatalf("new password begin=%d %q", getResponse.Code, getResponse.Body.String())
	}
	cookies := getResponse.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("new password cookies=%#v", cookies)
	}
	finish := putResetRequest(t, service, subject, putReset{MagicLinkID: token, Password: "ActivatedPassword2"}, cookies[0], document.CSRFToken)
	if finish.Code != http.StatusAccepted || finish.Header().Get("Location") != "https://app.example.test/registered" {
		t.Fatalf("new password finish=%d location=%q", finish.Code, finish.Header().Get("Location"))
	}
	if got, err := service.identity.Authenticate(context.Background(), "new@example.test", []byte("ActivatedPassword2")); err != nil || got.Subject != subject {
		t.Fatalf("activated authentication=%+v err=%v", got, err)
	}
}

func TestRegisterOpenOptionsAndResponseShape(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	for _, method := range []string{http.MethodOptions, http.MethodGet} {
		request := httptest.NewRequest(method, "/auth/v1/users/register", nil)
		response := httptest.NewRecorder()
		service.RegisterOpen(response, request)
		want := http.StatusMethodNotAllowed
		if method == http.MethodOptions {
			want = http.StatusNoContent
		}
		if response.Code != want || response.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Fatalf("method=%s status=%d headers=%#v", method, response.Code, response.Header())
		}
	}
}

func TestRegisterOpenDeliveryFailureDoesNotDisclose(t *testing.T) {
	service, sender := testService(t, "subject-1", "alice")
	enableOpenRegistration(t, service, ExactRedirectURIs([]string{"https://app.example.test/registered"}))
	sender.err = errors.New("smtp unavailable")
	var reported error
	service.OnError = func(err error) { reported = err }
	challenge, err := service.pow.Issue(context.Background(), service.powDifficulty, service.powTTL)
	if err != nil {
		t.Fatal(err)
	}
	response := openRegistrationRequest(t, service, `{"email":"delivery@example.test","given_name":"New","pow":"`+solveProof(t, challenge)+`"}`, "192.0.2.90:1234")
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 || !errors.Is(reported, sender.err) {
		t.Fatalf("delivery response=%d body=%q reported=%v", response.Code, response.Body.String(), reported)
	}
}

func TestRegisterOpenConsumesProofBeforeDynamicRedirectLookup(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	lookups := 0
	option := WithOpenRegistration(RegistrationConfig{Enabled: true, AllowedDomains: []string{"example.test"}, RedirectValidator: ExactRedirectURIs([]string{"https://app.example.test/registered"})}, 72*time.Hour, func(_ context.Context, uri string) (bool, error) {
		lookups++
		return uri == "https://app.example.test/registered", nil
	})
	if err := option(service); err != nil {
		t.Fatal(err)
	}
	response := openRegistrationRequest(t, service, `{"email":"proof@example.test","given_name":"New","redirect_uri":"https://app.example.test/registered","pow":"invalid"}`, "192.0.2.91:1234")
	if response.Code != http.StatusForbidden || lookups != 0 {
		t.Fatalf("invalid proof response=%d redirect lookups=%d", response.Code, lookups)
	}
}

func enableOpenRegistration(t *testing.T, service *Service, validator RedirectValidator) {
	t.Helper()
	option := WithOpenRegistration(RegistrationConfig{Enabled: true, AllowedDomains: []string{"example.test"}, RedirectValidator: validator}, 72*time.Hour, func(_ context.Context, uri string) (bool, error) { return validator(uri), nil })
	if err := option(service); err != nil {
		t.Fatal(err)
	}
}

func TestRegisterOpenPreferredUsernameBeforeProof(t *testing.T) {
	custom, err := identity.NewPreferredUsernamePolicy("required", `^Team_[0-9]{2}$`, []string{"team_12"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                     string
		policy                   *identity.PreferredUsernamePolicy
		valid, reserved, invalid string
	}{{"default", nil, "alice_12", "root", "Alice.Name"}, {"custom", custom, "Team_34", "Team_12", "alice"}} {
		t.Run(tc.name, func(t *testing.T) {
			service, sender := testService(t, "subject-1", "alice")
			config := RegistrationConfig{Enabled: true, RedirectValidator: ExactRedirectURIs(nil), UserValuesPolicy: identity.UserValuesPolicy{PreferredUsername: tc.policy}}
			if err := WithOpenRegistration(config, time.Hour, func(context.Context, string) (bool, error) { return false, nil })(service); err != nil {
				t.Fatal(err)
			}
			challenge, err := service.pow.Issue(context.Background(), service.powDifficulty, service.powTTL)
			if err != nil {
				t.Fatal(err)
			}
			proof := solveProof(t, challenge)
			for _, rejected := range []struct {
				value any
				want  int
			}{{tc.invalid, 400}, {"", 400}, {tc.reserved, 406}} {
				body, _ := json.Marshal(map[string]any{"email": "preferred@example.test", "given_name": "Preferred", "pow": proof, "preferred_username": rejected.value})
				response := openRegistrationRequest(t, service, string(body), "192.0.2.93:1234")
				if response.Code != rejected.want || len(sender.messages()) != 0 {
					t.Fatalf("rejected status=%d want=%d mail=%d", response.Code, rejected.want, len(sender.messages()))
				}
			}
			if tc.policy != nil {
				for _, field := range []string{"", `,"preferred_username":null`} {
					response := openRegistrationRequest(t, service, `{"email":"preferred@example.test","given_name":"Preferred","pow":"`+proof+`"`+field+`}`, "192.0.2.93:1234")
					if response.Code != 400 {
						t.Fatalf("missing required username status=%d", response.Code)
					}
				}
			}
			rows, err := service.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_user_profiles WHERE email='preferred@example.test'`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
				t.Fatalf("rejected request persisted: %v %v", rows.Rows, err)
			}
			body, _ := json.Marshal(map[string]any{"email": "preferred@example.test", "given_name": "Preferred", "pow": proof, "preferred_username": tc.valid})
			response := openRegistrationRequest(t, service, string(body), "192.0.2.93:1234")
			if response.Code != 204 || len(sender.messages()) != 1 {
				t.Fatalf("same PoW retry status=%d mail=%d", response.Code, len(sender.messages()))
			}
			rows, err = service.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT preferred_username FROM identity_user_profiles WHERE email='preferred@example.test'`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != tc.valid {
				t.Fatalf("preferred username persistence: %v %v", rows.Rows, err)
			}
		})
	}
}

func TestRegisterOpenRequiredFieldsBeforeProof(t *testing.T) {
	service, sender := testService(t, "subject-1", "alice")
	enableOpenRegistration(t, service, ExactRedirectURIs(nil))
	challenge, err := service.pow.Issue(context.Background(), service.powDifficulty, service.powTTL)
	if err != nil {
		t.Fatal(err)
	}
	proof := solveProof(t, challenge)
	for _, field := range []string{"", `,"given_name":null`, `,"given_name":""`} {
		body := `{"email":"required@example.test","pow":"` + proof + `"` + field + `}`
		response := openRegistrationRequest(t, service, body, "192.0.2.92:1234")
		if response.Code != http.StatusBadRequest || len(sender.messages()) != 0 {
			t.Fatalf("field=%s status=%d", field, response.Code)
		}
	}
	rows, err := service.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM identity_user_profiles WHERE email='required@example.test'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
		t.Fatalf("rejected requests persisted a user: rows=%v err=%v", rows.Rows, err)
	}
	// All rejected requests used this exact one-use proof. Acceptance now
	// proves local validation did not consume it.
	response := openRegistrationRequest(t, service, `{"email":"required@example.test","given_name":"Required","pow":"`+proof+`"}`, "192.0.2.92:1234")
	if response.Code != http.StatusNoContent || len(sender.messages()) != 1 {
		t.Fatalf("same proof retry status=%d messages=%d", response.Code, len(sender.messages()))
	}
}

func openRegistrationRequest(t *testing.T, service *Service, body, remote string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/auth/v1/users/register", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = remote
	response := httptest.NewRecorder()
	service.RegisterOpen(response, request)
	return response
}

func testService(t *testing.T, subject, username string) (*Service, *fakeSender) {
	t.Helper()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "recovery-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	rules := credential.Rules{LengthMin: 8, LengthMax: 64, LowerCase: 1, UpperCase: 1, Digits: 1, History: 2, ValidDays: 90}
	policy := credential.DefaultPolicy()
	policy.MaxConcurrency = 1
	hasher, err := credential.NewHasher(policy)
	if err != nil {
		t.Fatal(err)
	}
	identities, err := identity.NewStoreWithPasswordReset(db, hasher, rules, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	password, err := hasher.Hash(ctx, []byte("CurrentPassword1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := identities.BootstrapUser(ctx, subject, username, password); err != nil {
		t.Fatal(err)
	}
	if subject != "subject-2" {
		if _, err := identities.BootstrapUser(ctx, "subject-2", "bob", password); err != nil {
			t.Fatal(err)
		}
	}
	sender := &fakeSender{}
	pow, err := NewProofOfWork(db, bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(db, identities, sender, "https://issuer.example.test", rules, loginpolicy.NewStore(db), pow, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC) }
	service.pow.now = service.now
	service.pow.random = &sequenceReader{}
	return service, sender
}

func resetRequest(t *testing.T, service *Service, email, remote, site string) *httptest.ResponseRecorder {
	t.Helper()
	challenge, err := service.pow.Issue(context.Background(), service.powDifficulty, service.powTTL)
	if err != nil {
		t.Fatal(err)
	}
	return resetRequestWithProof(t, service, email, remote, site, solveProof(t, challenge))
}

func resetRequestWithProof(t *testing.T, service *Service, email, remote, site, proof string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/auth/v1/users/request_reset", strings.NewReader(`{"email":"`+email+`","pow":"`+proof+`"}`))
	request.Header.Set("Content-Type", "application/json")
	request.RemoteAddr = remote
	if site != "" {
		request.Header.Set("Sec-Fetch-Site", site)
	}
	response := httptest.NewRecorder()
	service.RequestReset(response, request)
	return response
}

func putResetRequest(t *testing.T, service *Service, subject string, payload putReset, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/auth/v1/users/"+subject+"/reset", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.SetPathValue("subject", subject)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	request.Header.Set("X-Pwd-CSRF-Token", csrf)
	response := httptest.NewRecorder()
	service.PutReset(response, request)
	return response
}

type fakeSender struct {
	mu       sync.Mutex
	items    []Message
	newItems []Message
	already  []string
	changed  []EmailChangeMessage
	err      error
}

func (s *fakeSender) SendPasswordReset(_ context.Context, message Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, message)
	return s.err
}
func (s *fakeSender) SendPasswordNew(_ context.Context, message Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items = append(s.items, message)
	s.newItems = append(s.newItems, message)
	return s.err
}
func (s *fakeSender) SendAlreadyRegistered(_ context.Context, message Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.already = append(s.already, message.To)
	return s.err
}
func (s *fakeSender) SendEmailChange(_ context.Context, message EmailChangeMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.changed = append(s.changed, message)
	return s.err
}

func (s *fakeSender) messages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.items...)
}
func (s *fakeSender) passwordNewMessages() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Message(nil), s.newItems...)
}
func (s *fakeSender) alreadyRegisteredRecipients() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.already...)
}
