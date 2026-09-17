package eventlog_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestLoginRevokeContract(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_123).In(time.FixedZone("fixture", 9*60*60))
	empty := ""
	for _, tc := range []struct {
		name     string
		ip       netip.Addr
		location *string
		wantText string
	}{
		{name: "ipv4 nil location", ip: netip.MustParseAddr("192.0.2.1"), wantText: "User `alice@example.test` revoked illegal login from 192.0.2.1 (Unknown Location)"},
		{name: "ipv6 empty location", ip: netip.MustParseAddr("2001:db8::1"), location: &empty, wantText: "User `alice@example.test` revoked illegal login from 2001:db8::1 ()"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := eventlog.LoginRevoke("operation-1", "alice@example.test", tc.ip, tc.location, at)
			if e.Type != eventlog.UserLoginRevoke || e.Level != eventlog.Warning || e.Timestamp != at.UnixMilli() || e.Data != nil || e.IP == nil || *e.IP != tc.ip.String() || e.Text == nil || *e.Text != tc.wantText {
				t.Fatalf("event=%+v", e)
			}

			statement, err := e.Statement("event_id = ?", "guard")
			if err != nil || statement.SQL != `INSERT INTO event_log(id,timestamp,level,typ,ip,data,text,prev_hash,integrity_hash) SELECT ?,?,?,?,?,?,?,?,? WHERE event_id = ?` || len(statement.Args) != 10 || statement.Args[0] != e.ID || statement.Args[1] != at.UnixMilli() || statement.Args[2] != eventlog.Warning.Rank() || statement.Args[3] != string(eventlog.UserLoginRevoke) || statement.Args[4] != tc.ip.String() || statement.Args[5] != nil || statement.Args[6] != tc.wantText || statement.Args[9] != "guard" {
				t.Fatalf("statement=%+v err=%v", statement, err)
			}
			if e.ID != eventlog.LoginRevoke("operation-1", "different@example.test", tc.ip, tc.location, at.Add(time.Hour)).ID || e.ID == eventlog.LoginRevoke("operation-2", "alice@example.test", tc.ip, tc.location, at).ID {
				t.Fatal("event identity must be idempotent for retries and distinct across operations")
			}
		})
	}
}
