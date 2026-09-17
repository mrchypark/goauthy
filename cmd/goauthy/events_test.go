package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestEventRetentionFromEnv(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  string
		want time.Duration
		err  bool
	}{
		{"default", "", 31 * 24 * time.Hour, false},
		{"minimum", "1", 24 * time.Hour, false},
		{"maximum", "3650", 3650 * 24 * time.Hour, false},
		{"zero", "0", 0, true},
		{"too large", "3651", 0, true},
		{"invalid", "days", 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := eventRetentionFromEnv(func(string) string { return tc.env })
			if (err != nil) != tc.err || got != tc.want {
				t.Fatalf("retention=%v err=%v, want=%v err=%t", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestRunEventCleanupCanceledBeforeStart(t *testing.T) {
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "event-worker-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "event-worker-schema", SQL: `CREATE TABLE event_log (id TEXT PRIMARY KEY, timestamp INTEGER, level INTEGER, typ TEXT, ip TEXT, data INTEGER, text TEXT)`}); err != nil {
		t.Fatal(err)
	}
	store, err := eventlog.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runEventCleanup(ctx, store, time.Hour, time.Hour, time.Now, nil); err != nil {
		t.Fatalf("canceled worker returned error: %v", err)
	}
}

func TestRunEventCleanupDrainsBoundedBatchesAtOneTick(t *testing.T) {
	ctx := context.Background()
	now := time.UnixMilli(2_000_000_000_000).UTC()
	retention := time.Hour
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "event-worker-drain-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-retention - time.Millisecond)
	cutoff := now.Add(-retention)
	for start := 0; start < 1001; start += 64 {
		end := start + 64
		if end > 1001 {
			end = 1001
		}
		statements := make([]rhiza.SQLStatement, 0, end-start)
		for i := start; i < end; i++ {
			event := eventlog.Creation(fmt.Sprintf("worker-old-%d", i), "", "", false, old)
			statement, err := event.Statement("1=1")
			if err != nil {
				t.Fatal(err)
			}
			statements = append(statements, statement)
		}
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("worker-seed-%d", start), Statements: statements}); err != nil {
			t.Fatal(err)
		}
	}
	sentinel := eventlog.Creation("worker-boundary", "", "", false, cutoff)
	statement, err := sentinel.Statement("1=1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "worker-seed-boundary", Statements: []rhiza.SQLStatement{statement}}); err != nil {
		t.Fatal(err)
	}
	store, err := eventlog.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var workerErrors []error
	done := make(chan error, 1)
	go func() {
		done <- runEventCleanup(workerCtx, store, time.Hour, retention, func() time.Time { return now }, func(err error) { workerErrors = append(workerErrors, err) })
	}()
	watchCtx, watchCancel := context.WithTimeout(ctx, 10*time.Second)
	defer watchCancel()
	for {
		result, err := db.Query(watchCtx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM event_log`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Rows) == 1 && len(result.Rows[0]) == 1 && result.Rows[0][0] == int64(1) {
			break
		}
		if err := watchCtx.Err(); err != nil {
			t.Fatalf("worker did not drain: %v", err)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("worker returned error: %v", err)
	}
	if len(workerErrors) != 0 {
		t.Fatalf("worker errors=%v", workerErrors)
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT timestamp FROM event_log`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != cutoff.UnixMilli() {
		t.Fatalf("boundary rows=%#v err=%v", result.Rows, err)
	}
}

func TestTokenIssuedConfigFromEnv(t *testing.T) {
	for _, tc := range []struct {
		generate, level string
		want            bool
		wantLevel       eventlog.Level
		invalid         bool
	}{
		{"", "", true, eventlog.Info, false},
		{"true", "notice", true, eventlog.Notice, false},
		{"false", "critical", false, eventlog.Critical, false},
		{"true", "warning", true, eventlog.Warning, false},
		{"TRUE", "", false, "", true},
		{"0", "", false, "", true},
		{"false", "INFO", false, "", true},
	} {
		t.Run(tc.generate+"/"+tc.level, func(t *testing.T) {
			enabled, level, err := tokenIssuedConfigFromEnv(func(key string) string {
				if key == "GOAUTHY_EVENT_GENERATE_TOKEN_ISSUED" {
					return tc.generate
				}
				return tc.level
			})
			if (err != nil) != tc.invalid || !tc.invalid && (enabled != tc.want || level != tc.wantLevel) {
				t.Fatalf("enabled=%v level=%q err=%v", enabled, level, err)
			}
		})
	}
}

func TestRecordTokenIssuedPersistenceFailure(t *testing.T) {
	ctx := t.Context()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "token-events-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	users, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := recordTokenIssued(ctx, db, users, eventlog.Warning, "client_credentials", "machine", ""); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT level,text,ip,data FROM event_log WHERE typ='TokenIssued'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(2) || rows.Rows[0][1] != "machine (client_credentials) " || rows.Rows[0][2] != nil || rows.Rows[0][3] != nil {
		t.Fatal("incorrect persisted token event")
	}
	if err := recordTokenIssued(ctx, db, users, eventlog.Info, "authorization_code", "client", "missing-user"); err == nil {
		t.Fatal("missing user was treated as machine")
	}
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "reject-token-event", Statements: []rhiza.SQLStatement{{SQL: "CREATE TRIGGER reject_token_event BEFORE INSERT ON event_log WHEN NEW.typ='TokenIssued' BEGIN SELECT RAISE(ABORT, 'test event failure'); END"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := recordTokenIssued(ctx, db, users, eventlog.Info, "client_credentials", "machine", ""); err == nil {
		t.Fatal("event persistence failure was swallowed")
	}
	rows, err = db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM event_log WHERE typ='TokenIssued'", Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) {
		t.Fatal("rejected event left an artifact")
	}
}
