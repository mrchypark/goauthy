package eventlog_test

import (
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
)

func TestSuspiciousApiScan(t *testing.T) {
	at := time.UnixMilli(1_800_005_000_123)
	keyName := "svc-backend"
	ip := "192.168.1.10"

	e := eventlog.SuspiciousApiScanEvent("op-1", keyName, ip, at)
	if e.Type != eventlog.SuspiciousApiScan {
		t.Fatalf("expected type SuspiciousApiScan, got %s", e.Type)
	}
	if e.Level != eventlog.Warning {
		t.Fatalf("expected level Warning, got %s", e.Level)
	}
	if e.Timestamp != at.UnixMilli() {
		t.Fatalf("expected timestamp %d, got %d", at.UnixMilli(), e.Timestamp)
	}
	if e.IP == nil || *e.IP != ip {
		t.Fatalf("expected IP %s, got %v", ip, e.IP)
	}
	if e.Text == nil || *e.Text != keyName {
		t.Fatalf("expected text %s, got %v", keyName, e.Text)
	}
	if e.Data != nil {
		t.Fatalf("expected nil data, got %v", e.Data)
	}

	stmt, err := e.Statement("1=1")
	if err != nil {
		t.Fatalf("unexpected error from Statement: %v", err)
	}
	if len(stmt.Args) != 9 {
		t.Fatalf("expected 9 args, got %d", len(stmt.Args))
	}
	if stmt.Args[2] != eventlog.Warning.Rank() {
		t.Fatalf("expected level rank %d, got %v", eventlog.Warning.Rank(), stmt.Args[2])
	}
	if stmt.Args[4] != ip {
		t.Fatalf("expected ip arg %s, got %v", ip, stmt.Args[4])
	}
	if stmt.Args[6] != keyName {
		t.Fatalf("expected text arg %s, got %v", keyName, stmt.Args[6])
	}

	same := eventlog.SuspiciousApiScanEvent("op-1", keyName, ip, at)
	different := eventlog.SuspiciousApiScanEvent("op-2", keyName, ip, at)
	if e.ID != same.ID || e.ID == different.ID {
		t.Fatal("identity must be stable per operation, distinct across operations")
	}
}
