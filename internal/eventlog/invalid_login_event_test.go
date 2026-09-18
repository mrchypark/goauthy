package eventlog_test

import (
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestInvalidLoginContract(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_123)
	for _, tc := range []struct {
		count uint32
		level eventlog.Level
	}{
		{0, eventlog.Info}, {1, eventlog.Info}, {6, eventlog.Info}, {7, eventlog.Notice}, {9, eventlog.Notice},
		{10, eventlog.Warning}, {15, eventlog.Warning}, {19, eventlog.Warning}, {20, eventlog.Critical}, {25, eventlog.Critical}, {^uint32(0), eventlog.Critical},
	} {
		e := eventlog.InvalidLogin("failure-1", "2001:db8::1", tc.count, at)
		if e.Type != eventlog.InvalidLogins || e.Level != tc.level || e.Timestamp != at.UnixMilli() || e.IP == nil || *e.IP != "2001:db8::1" || e.Data == nil || *e.Data != int64(tc.count) || e.Text != nil {
			t.Fatalf("count=%d event=%+v", tc.count, e)
		}
		s, err := e.Statement("1=1")
		if err != nil || len(s.Args) != 9 || s.Args[2] != tc.level.Rank() || s.Args[5] != int64(tc.count) {
			t.Fatalf("binding count=%d statement=%+v err=%v", tc.count, s, err)
		}
	}
	a := eventlog.InvalidLogin("failure-1", "192.0.2.1", 1, at)
	if a.ID != eventlog.InvalidLogin("failure-1", "192.0.2.1", 1, at).ID || a.ID == eventlog.InvalidLogin("failure-2", "192.0.2.1", 1, at).ID {
		t.Fatal("event identity must distinguish independent failures from receipt replay")
	}
}
