package eventlog_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestPasswordResetPreservesCallerTextAndUsesConfiguredContract(t *testing.T) {
	at := time.UnixMilli(1_800_004_000_123)
	e := eventlog.PasswordReset("reset-1", "reset requested for user", "127.0.0.1", at)
	other := eventlog.PasswordReset("reset-1", "different text", "127.0.0.1", at)
	if e.ID != other.ID || e.Type != eventlog.UserPasswordReset || e.Level != eventlog.Notice || e.Timestamp != at.UnixMilli() || e.Data != nil || e.Text == nil || *e.Text != "reset requested for user" || e.IP == nil || *e.IP != "127.0.0.1" {
		t.Fatalf("event=%#v other=%#v", e, other)
	}
	withoutIP := eventlog.PasswordReset("reset-2", "", "", at)
	if withoutIP.IP != nil || withoutIP.Text == nil || *withoutIP.Text != "" {
		t.Fatalf("empty optionals=%#v", withoutIP)
	}
	encoded, err := json.Marshal(withoutIP)
	if err != nil || !strings.Contains(string(encoded), `"ip":null`) || !strings.Contains(string(encoded), `"text":""`) || !strings.Contains(string(encoded), `"data":null`) {
		t.Fatalf("nullable JSON=%s err=%v", encoded, err)
	}
	tooLong := eventlog.PasswordReset("reset-3", strings.Repeat("x", 4097), "127.0.0.1", at)
	if _, err := tooLong.Statement("1=1"); err == nil {
		t.Fatal("oversize text accepted")
	}
	badIP := eventlog.PasswordReset("reset-4", "ok", strings.Repeat("x", 46), at)
	if _, err := badIP.Statement("1=1"); err == nil {
		t.Fatal("invalid IP accepted")
	}
}
