package eventlog_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestTestEventHasStablePublicPayload(t *testing.T) {
	at := time.UnixMilli(1_800_003_000_123)
	e := eventlog.TestEvent("operation-1", "127.0.0.1", at)
	if again := eventlog.TestEvent("operation-1", "127.0.0.1", at); e.ID != again.ID {
		t.Fatal("same operation did not reproduce event ID")
	}
	if e.ID == eventlog.Creation("operation-1", "u", "127.0.0.1", false, at).ID {
		t.Fatal("different event types reused ID")
	}
	other := eventlog.TestEvent("operation-2", "127.0.0.1", at)
	if e.Type != eventlog.Test || e.Level != eventlog.Info || e.Timestamp != at.UnixMilli() || e.Data != nil || e.Text == nil || *e.Text != "This is a Test-Event" || e.IP == nil || *e.IP != "127.0.0.1" || e.ID == other.ID || len(e.ID) != 43 {
		t.Fatalf("event=%#v other=%#v", e, other)
	}
	encoded, err := json.Marshal(e)
	if err != nil || !strings.Contains(string(encoded), `"data":null`) || !strings.Contains(string(encoded), `"text":"This is a Test-Event"`) {
		t.Fatalf("json=%s err=%v", encoded, err)
	}
	if _, err := e.Statement("1=1"); err != nil {
		t.Fatal(err)
	}
	bad := e
	ip := strings.Repeat("x", 46)
	bad.IP = &ip
	if _, err := bad.Statement("1=1"); err == nil {
		t.Fatal("invalid IP accepted")
	}
}

func TestTestEventConditionalInsertAndReplay(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "event-test-event", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	e := eventlog.TestEvent("conditional", "127.0.0.1", time.UnixMilli(1_800_003_000_000))
	falseStmt, err := e.Statement("0=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "test-event-false", Statements: []rhiza.SQLStatement{falseStmt}}); err != nil {
		t.Fatal(err)
	}
	count := func() int64 {
		result, queryErr := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log_order`, Consistency: rhiza.ConsistencyLinearizable})
		if queryErr != nil || len(result.Rows) != 1 {
			t.Fatalf("count query=%#v err=%v", result.Rows, queryErr)
		}
		n, ok := result.Rows[0][0].(int64)
		if !ok {
			t.Fatalf("count=%#v", result.Rows)
		}
		return n
	}
	if got := count(); got != 0 {
		t.Fatalf("false condition inserted sequence=%d", got)
	}
	trueStmt, err := e.Statement("1=1")
	if err != nil {
		t.Fatal(err)
	}
	req := rhiza.ExecuteRequest{RequestID: "test-event-true", Statements: []rhiza.SQLStatement{trueStmt}}
	if _, err = storage.Execute(ctx, db, req); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 1 {
		t.Fatalf("insert count=%d", got)
	}
	if _, err = storage.Execute(ctx, db, req); err != nil {
		t.Fatal(err)
	}
	if got := count(); got != 1 {
		t.Fatalf("replay count=%d", got)
	}
}
