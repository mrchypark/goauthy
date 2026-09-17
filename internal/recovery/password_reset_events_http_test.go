package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/rhiza"
)

func resetHTTPChallenge(t *testing.T, service *Service) (string, http.Cookie, string) {
	t.Helper()
	token, _, err := service.identity.IssuePasswordReset(context.Background(), "subject-1", passwordResetLifetime)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/auth/v1/users/subject-1/reset/"+token, nil)
	request.SetPathValue("subject", "subject-1")
	request.SetPathValue("token", token)
	response := httptest.NewRecorder()
	service.GetReset(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("reset challenge status=%d body=%q", response.Code, response.Body.String())
	}
	var document resetResponse
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("reset challenge cookies=%#v", cookies)
	}
	return token, *cookies[0], document.CSRFToken
}

func putResetHTTP(t *testing.T, service *Service, token string, cookie http.Cookie, csrf, remote string, peer string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(putReset{MagicLinkID: token, Password: "ReplacementPassword2"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/auth/v1/users/subject-1/reset", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Pwd-CSRF-Token", csrf)
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	request.RemoteAddr = remote
	request.SetPathValue("subject", "subject-1")
	request.AddCookie(&cookie)
	if peer != "" {
		request = request.WithContext(browser.ContextWithPeerIP(request.Context(), peer))
	}
	response := httptest.NewRecorder()
	// Keep the request construction equivalent to the browser's reset form.
	if csrf == "" || cookie.Value == "" {
		t.Fatalf("missing reset binding csrf=%q cookie=%#v", csrf, cookie)
	}
	service.PutReset(response, request)
	return response
}

func resetEventIPs(t *testing.T, service *Service) []string {
	t.Helper()
	result, err := service.db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT ip FROM event_log WHERE typ=? ORDER BY id`, Args: []any{string(eventlog.UserPasswordReset)}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		t.Fatal(err)
	}
	ips := make([]string, len(result.Rows))
	for i, row := range result.Rows {
		if len(row) != 1 {
			t.Fatalf("event row=%#v", row)
		}
		var ok bool
		ips[i], ok = row[0].(string)
		if !ok {
			t.Fatalf("event ip=%#v", row[0])
		}
	}
	return ips
}

func TestPutResetPasswordEventUsesResolvedPeerIP(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	token, cookie, csrf := resetHTTPChallenge(t, service)
	response := putResetHTTP(t, service, token, cookie, csrf, "198.51.100.7:1234", "2001:db8::7")
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	ips := resetEventIPs(t, service)
	if len(ips) != 1 || ips[0] != "2001:db8::7" {
		t.Fatalf("event IPs=%#v", ips)
	}
}

func TestPutResetPasswordEventFallsBackToRemotePeer(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	token, cookie, csrf := resetHTTPChallenge(t, service)
	response := putResetHTTP(t, service, token, cookie, csrf, "198.51.100.8:1234", "")
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%q", response.Code, response.Body.String())
	}
	ips := resetEventIPs(t, service)
	if len(ips) != 1 || ips[0] != "198.51.100.8" {
		t.Fatalf("event IPs=%#v", ips)
	}
}

func TestPutResetInvalidPeerLeavesResetUnconsumed(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	token, cookie, challengeCSRF := resetHTTPChallenge(t, service)
	response := putResetHTTP(t, service, token, cookie, challengeCSRF, "not-an-ip", "")
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("invalid peer status=%d body=%q", response.Code, response.Body.String())
	}
	if ips := resetEventIPs(t, service); len(ips) != 0 {
		t.Fatalf("invalid peer emitted events=%#v", ips)
	}
	// The source-IP rejection occurs before ResetPassword, so the valid proof
	// remains usable and proves that neither the token nor password was changed.
	response = putResetHTTP(t, service, token, cookie, challengeCSRF, "198.51.100.9:1234", "")
	if response.Code != http.StatusAccepted {
		t.Fatalf("proof after invalid peer status=%d body=%q", response.Code, response.Body.String())
	}
	if ips := resetEventIPs(t, service); len(ips) != 1 || ips[0] != "198.51.100.9" {
		t.Fatalf("post-retry event IPs=%#v", ips)
	}
}
