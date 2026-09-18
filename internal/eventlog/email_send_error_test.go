package eventlog_test

import (
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestEmailSendError(t *testing.T) {
	at := time.UnixMilli(1_800_005_000_123)
	e := eventlog.EmailSendErrorEvent("op-1", "password reset", "user@example.com", at)
	if e.Type != eventlog.EmailSendError || e.Level != eventlog.Critical || e.Timestamp != at.UnixMilli() || e.IP != nil || e.Data != nil || e.Text == nil || *e.Text != "password reset / user@example.com" {
		t.Fatalf("event=%+v", e)
	}
	s, err := e.Statement("1=1")
	if err != nil || len(s.Args) != 9 {
		t.Fatalf("statement=%+v err=%v", s, err)
	}
	same := eventlog.EmailSendErrorEvent("op-1", "new password", "other@example.com", at.Add(time.Hour))
	different := eventlog.EmailSendErrorEvent("op-2", "password reset", "user@example.com", at)
	if e.ID != same.ID || e.ID == different.ID {
		t.Fatal("identity must be stable per operation, distinct across operations")
	}
}
