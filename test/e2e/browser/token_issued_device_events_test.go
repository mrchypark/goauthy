package browser

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestTokenIssuedDeviceEvents(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_TOKEN_EVENTS") != "1" {
		t.Skip("set GOAUTHY_E2E_TOKEN_EVENTS=1 to run device token event E2E")
	}
	primary, secondary, adminUsername, adminPassword, _ := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	nodes := []string{primary, secondary, tertiary}
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, adminUsername, adminPassword)
	headers := rbacMutationHeaders(csrf)
	userEmail := "token-event-device-" + randomManagedUIID(t) + "@goauthy.e2e"
	userPassword := "Token-Event-Device-Password-1A"
	userID := createCatalogSessionUser(t, admin, primary, headers, userEmail, userPassword)
	t.Cleanup(func() {
		response := do(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(userID), nil, headers)
		response.Body.Close()
	})
	clientID := createDeviceSessionsUIClient(t, admin, primary, headers, "token-events")
	t.Cleanup(func() { deleteDeviceSessionsUIClient(t, admin, primary, headers, clientID) })

	wantText := clientID + " (device_code) " + userEmail
	before := make(map[string]bool)
	for _, node := range nodes {
		for _, event := range queryLifecycleEvents(t, admin, node) {
			before[event.ID] = true
		}
	}

	want := 1
	if os.Getenv("GOAUTHY_E2E_EXPECT_TOKEN_EVENTS") == "false" {
		want = 0
	}
	ids := map[string]string{}
	assertDeviceEvents := func(stage string, want int) {
		var eventID string
		for _, node := range nodes {
			count := 0
			for _, event := range queryLifecycleEvents(t, admin, node) {
				if before[event.ID] || event.Type != eventlog.TokenIssued || event.Text == nil {
					continue
				}
				text := *event.Text
				if !strings.HasPrefix(text, clientID+" (") {
					continue
				}
				if text != wantText {
					t.Fatalf("%s device event text=%q want=%q node=%s", stage, text, wantText, node)
				}
				count++
				if event.Level != expectedTokenEventLevel(t) || event.IP != nil || event.Data != nil || event.Timestamp <= 0 {
					t.Fatalf("%s invalid device event node=%s event=%+v", stage, node, event)
				}
				if eventID != "" && eventID != event.ID {
					t.Fatalf("%s device event ID differs across nodes: %q vs %q", stage, eventID, event.ID)
				}
				eventID = event.ID
				ids["device_code"] = event.ID
			}
			if count != want {
				t.Fatalf("%s device events=%d want=%d node=%s", stage, count, want, node)
			}
		}
	}

	deviceClient := newBrowserClient(t)
	pending := startDeviceAuthorizationOffline(t, deviceClient, primary, clientID, "")
	assertPublicDeviceError(t, deviceClient, secondary, pending.DeviceCode, clientID, "authorization_pending")
	assertDeviceEvents("authorization_pending", 0)

	verify := newBrowserClient(t)
	approved := startDeviceAuthorizationOffline(t, deviceClient, primary, clientID, "")
	loginAndApproveDevice(t, verify, approved, primary, tertiary, userEmail, userPassword)

	denied := startDeviceAuthorizationOffline(t, deviceClient, primary, clientID, "")
	approveDevice(t, verify, secondary, primary, denied.UserCode, "deny")
	assertPublicDeviceError(t, deviceClient, tertiary, denied.DeviceCode, clientID, "access_denied")
	assertDeviceEvents("denied", 0)

	issued := publicDeviceToken(t, deviceClient, secondary, url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {approved.DeviceCode},
		"client_id":   {clientID},
	})
	if issued.AccessToken == "" || issued.RefreshToken == "" {
		t.Fatal("successful device token response is incomplete")
	}
	assertDeviceEvents("success", want)
	waitTokenEventNotifications(t, ids)
}
