package recovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResetHTMLNavigationDoesNotReplaceAPIBinding(t *testing.T) {
	t.Parallel()
	service, _ := testService(t, "subject-1", "alice")
	token, _, err := service.identity.IssuePasswordReset(context.Background(), "subject-1", passwordResetLifetime)
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewRecorder()
	apiRequest := httptest.NewRequest(http.MethodGet, "/auth/v1/users/subject-1/reset/"+token, nil)
	apiRequest.SetPathValue("subject", "subject-1")
	apiRequest.SetPathValue("token", token)
	service.GetReset(first, apiRequest)
	var bootstrap resetResponse
	if first.Code != 200 || json.Unmarshal(first.Body.Bytes(), &bootstrap) != nil {
		t.Fatal("JSON bootstrap failed")
	}
	request := httptest.NewRequest(http.MethodGet, service.issuer+"/auth/v1/users/subject-1/reset/"+token, nil)
	request.SetPathValue("subject", "subject-1")
	request.SetPathValue("token", token)
	request.Header.Set("Accept", "text/html")
	response := httptest.NewRecorder()
	service.GetReset(response, request)
	if response.Code != 200 || !strings.Contains(response.Body.String(), "reset-start") || len(response.Result().Cookies()) != 0 || strings.Contains(response.Body.String(), token) {
		t.Fatal("HTML navigation leaked or bound reset authority")
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("missing sensitive page headers")
	}
	// A scanner/navigation after JSON bootstrap must not invalidate its cookie.
	result := putResetRequest(t, service, "subject-1", putReset{MagicLinkID: token, Password: "UpdatedPassword2"}, first.Result().Cookies()[0], bootstrap.CSRFToken)
	if result.Code != http.StatusAccepted {
		t.Fatalf("binding replaced: %d", result.Code)
	}
	if _, err := service.identity.Authenticate(context.Background(), "alice", []byte("UpdatedPassword2")); err != nil {
		t.Fatal(err)
	}
}
