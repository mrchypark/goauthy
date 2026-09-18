package browser

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestPasswordResetEventPersisted(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_RESET_EVENT_PERSISTENCE") != "1" {
		t.Skip("set GOAUTHY_E2E_RESET_EVENT_PERSISTENCE=1 to run reset-event persistence E2E")
	}
	primary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SECONDARY_URL"), "/")
	username := os.Getenv("GOAUTHY_E2E_BROWSER_USERNAME")
	email := os.Getenv("GOAUTHY_E2E_BROWSER_EMAIL")
	clientSecret := os.Getenv("GOAUTHY_E2E_CLIENT_SECRET")
	if primary == "" || secondary == "" || username == "" || email == "" || clientSecret == "" {
		t.Fatal("GOAUTHY_E2E_URL, GOAUTHY_E2E_SECONDARY_URL, browser username, target email, and client secret are required")
	}
	tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/")
	if tertiary == "" {
		tertiary = secondary
	}
	nodes := []string{primary, secondary, tertiary}
	client := newBrowserClient(t)
	verifier := pkceVerifier(t)
	// The reset fixture targets the configured bootstrap admin, whose password
	// is the deterministic value used by TestPasswordResetAcrossPods.
	loginForCode(t, client, primary, primary, defaultRedirectURI, pkceChallenge(verifier), username, "Reset-Password-1A", "reset-event-persistence")

	var expectedID string
	for _, base := range nodes {
		events := queryLifecycleEvents(t, client, base)
		matches := make([]eventlog.Event, 0, 1)
		for _, event := range events {
			if event.Type == eventlog.UserPasswordReset && event.Text != nil && *event.Text == "Reset via Password Reset Form: "+email {
				matches = append(matches, event)
			}
		}
		if len(matches) != 1 {
			t.Fatalf("persisted reset event count node=%s count=%d", base, len(matches))
		}
		event := matches[0]
		if event.Level != eventlog.Notice || event.Data != nil || event.Timestamp <= 0 || event.IP == nil {
			t.Fatalf("invalid persisted reset event node=%s event=%+v", base, event)
		}
		if _, err := netip.ParseAddr(*event.IP); err != nil {
			t.Fatalf("invalid persisted reset event IP node=%s ip=%q", base, *event.IP)
		}
		if expectedID == "" {
			expectedID = event.ID
		} else if expectedID != event.ID {
			t.Fatalf("persisted reset event ID differs node=%s", base)
		}
		stream := collectStreamEvents(t, client, base, "latest=100&level=notice", func(events []eventlog.Event) bool {
			return hasEvent(events, "Reset via Password Reset Form: "+email, eventlog.UserPasswordReset)
		})
		streamMatches := matchingEvents(stream, "Reset via Password Reset Form: "+email, eventlog.UserPasswordReset)
		if len(streamMatches) != 1 || streamMatches[0].ID != expectedID || streamMatches[0].Level != eventlog.Notice || streamMatches[0].Data != nil || streamMatches[0].Timestamp <= 0 {
			t.Fatalf("persisted reset SSE node=%s events=%+v", base, streamMatches)
		}
	}
}
