package eventlog_test

import (
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestBackchannelFailureContract(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_123)
	for _, subject := range []string{"", "subject-1"} {
		e := eventlog.BackchannelFailure("delivery-1", "client-1", subject, 100, at)
		if e.Type != eventlog.BackchannelLogoutFailed || e.Level != eventlog.Critical || e.Timestamp != at.UnixMilli() || e.IP != nil || e.Data == nil || *e.Data != 100 || e.Text == nil || *e.Text != "client-1 / "+subject {
			t.Fatalf("event=%+v", e)
		}
		s, err := e.Statement("1=1")
		if err != nil || len(s.Args) != 9 || s.Args[5] != int64(100) {
			t.Fatalf("statement=%+v err=%v", s, err)
		}
		if e.ID != eventlog.BackchannelFailure("delivery-1", "client-1", subject, 100, at.Add(time.Hour)).ID || e.ID == eventlog.BackchannelFailure("delivery-2", "client-1", subject, 100, at).ID {
			t.Fatal("identity must be stable per delivery, distinct across deliveries")
		}
	}
}
