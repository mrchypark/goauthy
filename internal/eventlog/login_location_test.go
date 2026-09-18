package eventlog_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestNewLoginLocationContract(t *testing.T) {
	empty, location := "", "Example City"
	for _, tc := range []struct {
		location *string
		text     string
	}{
		{nil, "alice@example.test / Browser"},
		{&empty, "alice@example.test / Browser / "},
		{&location, "alice@example.test / Browser / Example City"},
	} {
		e := eventlog.NewLoginLocation("login-1", "alice@example.test", "Browser", netip.MustParseAddr("2001:db8::1"), tc.location, time.UnixMilli(123))
		if e.Type != eventlog.LoginNewLocation || e.Level != eventlog.Warning || e.Timestamp != 123 || e.Data != nil || e.IP == nil || *e.IP != "2001:db8::1" || e.Text == nil || *e.Text != tc.text {
			t.Fatalf("event=%+v", e)
		}
		s, err := e.Statement("1=?", 1)
		if err != nil || len(s.Args) != 10 || s.Args[4] != "2001:db8::1" || s.Args[5] != nil || s.Args[6] != tc.text {
			t.Fatalf("invalid event statement: %v", err)
		}
	}
}
