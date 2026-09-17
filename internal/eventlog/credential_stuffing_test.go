package eventlog_test

import (
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestCredentialStuffingContract(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_123)
	accountHash := "abc123"
	ip := "2001:db8::1"
	var distinctIPs int64 = 7

	e := eventlog.CredentialStuffingEvent("stuff-1", accountHash, ip, distinctIPs, at)
	if e.Type != eventlog.CredentialStuffing {
		t.Fatalf("expected type CredentialStuffing, got %s", e.Type)
	}
	if e.Level != eventlog.Critical {
		t.Fatalf("expected level Critical, got %s", e.Level)
	}
	if e.Timestamp != at.UnixMilli() {
		t.Fatalf("expected timestamp %d, got %d", at.UnixMilli(), e.Timestamp)
	}
	if e.IP == nil || *e.IP != ip {
		t.Fatalf("expected IP %s, got %v", ip, e.IP)
	}
	if e.Data == nil || *e.Data != distinctIPs {
		t.Fatalf("expected data %d, got %v", distinctIPs, e.Data)
	}
	if e.Text == nil || *e.Text != accountHash {
		t.Fatalf("expected text %s, got %v", accountHash, e.Text)
	}

	stmt, err := e.Statement("1=1")
	if err != nil {
		t.Fatalf("unexpected error from Statement: %v", err)
	}
	if len(stmt.Args) != 9 {
		t.Fatalf("expected 9 args, got %d", len(stmt.Args))
	}
	if stmt.Args[2] != eventlog.Critical.Rank() {
		t.Fatalf("expected level rank %d, got %v", eventlog.Critical.Rank(), stmt.Args[2])
	}
	if stmt.Args[5] != distinctIPs {
		t.Fatalf("expected data arg %d, got %v", distinctIPs, stmt.Args[5])
	}
	if stmt.Args[6] != accountHash {
		t.Fatalf("expected text arg %s, got %v", accountHash, stmt.Args[6])
	}
}
