package eventlog_test

import (
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestIPBlacklistedContract(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_321)
	e := eventlog.IPBlacklisted("failure-1", "2001:db8::1", at.Unix()+60, at)
	if e.Type != eventlog.IpBlacklisted || e.Level != eventlog.Warning || e.Timestamp != at.UnixMilli() || e.IP == nil || *e.IP != "2001:db8::1" || e.Data == nil || *e.Data != at.Unix()+60 || e.Text != nil {
		t.Fatalf("event=%+v", e)
	}
	if e.ID != eventlog.IPBlacklisted("failure-1", "2001:db8::1", at.Unix()+60, at).ID || e.ID == eventlog.IPBlacklisted("failure-2", "2001:db8::1", at.Unix()+60, at).ID {
		t.Fatal("receipt replay must preserve ID; distinct failures must not collapse")
	}
	statement, err := e.Statement("? IS NOT NULL", nil)
	if err != nil || len(statement.Args) != 10 || statement.Args[5] != at.Unix()+60 || statement.Args[9] != nil {
		t.Fatalf("event data/condition binding changed: %+v err=%v", statement, err)
	}
	if _, err := eventlog.IPBlacklisted("bad-ip", "2001:db8::/64", at.Unix()+60, at).Statement("1=1"); err == nil {
		t.Fatal("event accepted CIDR in host IP field")
	}
}
