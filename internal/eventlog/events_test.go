package eventlog_test

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestCreationIsDeterministicAndUsesPublicContract(t *testing.T) {
	at := time.UnixMilli(1_800_000_000_123)
	a := eventlog.Creation("request-1", "u@example.test", "127.0.0.1", false, at)
	b := eventlog.Creation("request-1", "u@example.test", "127.0.0.1", false, at)
	if a.ID != b.ID || a.Timestamp != b.Timestamp || *a.IP != *b.IP || *a.Text != *b.Text || len(a.ID) != 43 || a.Level != eventlog.Info || a.Type != eventlog.NewUserRegistered || a.Timestamp != at.UnixMilli() {
		t.Fatalf("creation mismatch: %#v %#v", a, b)
	}
	admin := eventlog.Creation("request-1", "u@example.test", "", true, at)
	if admin.Level != eventlog.Notice || admin.Type != eventlog.NewRauthyAdmin || admin.IP != nil {
		t.Fatalf("admin event=%#v", admin)
	}
	jsonBytes, err := json.Marshal(admin)
	if err != nil || !strings.Contains(string(jsonBytes), `"ip":null`) || !strings.Contains(string(jsonBytes), `"data":null`) {
		t.Fatalf("nullable JSON fields missing: %s (%v)", jsonBytes, err)
	}
}

func TestValidationAndStatement(t *testing.T) {
	q := eventlog.Query{From: 1_719_784_800, Level: eventlog.Info}
	if q.Validate() != nil || (eventlog.Level("INFO")).Valid() || eventlog.Type("bad").Valid() {
		t.Fatal("validation contract failed")
	}
	e := eventlog.Creation("r", "u@example.test", "", false, time.Unix(1_800_000_000, 0))
	s, err := e.Statement("request_id=?", "r")
	if err != nil || !strings.Contains(s.SQL, "INSERT INTO event_log") || len(s.Args) != 10 {
		t.Fatalf("statement=%#v err=%v", s, err)
	}
}

func TestValidationRejectsOverflowAndMalformedEventFields(t *testing.T) {
	base := eventlog.Creation("r", "u@example.test", "1.1.1.1", false, time.UnixMilli(1_800_000_000_000))
	if (&eventlog.Query{From: 1_719_784_800, Level: eventlog.Info, Until: ptr(9_223_372_036_854_776)}).Validate() == nil {
		t.Fatal("overflow until accepted")
	}
	for name, mutate := range map[string]func(*eventlog.Event){
		"id":    func(e *eventlog.Event) { e.ID = "short" },
		"level": func(e *eventlog.Event) { e.Level = "bogus" },
		"type":  func(e *eventlog.Event) { e.Type = "bogus" },
		"ip":    func(e *eventlog.Event) { v := strings.Repeat("x", 46); e.IP = &v },
		"text":  func(e *eventlog.Event) { v := strings.Repeat("x", 4097); e.Text = &v },
	} {
		e := base
		mutate(&e)
		if _, err := e.Statement("1=1"); err == nil {
			t.Errorf("%s malformed event accepted", name)
		}
	}
}

func TestListGuardedUsesFixedTimeAndDistinctDeniedMarker(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "eventlog-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, _ := eventlog.NewStore(db)
	e := eventlog.Creation("r", "u@example.test", "127.0.0.1", false, time.UnixMilli(1_800_000_000_000))
	stmt, _ := e.Statement("1=1")
	if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "eventlog-insert", Statements: []rhiza.SQLStatement{stmt}}); err != nil {
		t.Fatal(err)
	}
	q := eventlog.Query{From: 1_719_784_800, Level: eventlog.Info}
	rows, next, authorized, err := store.ListGuarded(ctx, q, time.UnixMilli(1_800_000_001_000), nil, eventlog.MaxPageSize, "1=1")
	if err != nil || !authorized || len(rows) != 1 || rows[0].ID != e.ID {
		t.Fatalf("rows=%#v authorized=%v err=%v", rows, authorized, err)
	}
	if next != nil {
		t.Fatalf("partial page returned a continuation: %#v", next)
	}
	rows, next, authorized, err = store.ListGuarded(ctx, q, time.UnixMilli(1_800_000_001_000), nil, eventlog.MaxPageSize, "0=1")
	if err != nil || authorized || rows == nil || len(rows) != 0 || next != nil {
		t.Fatalf("denied rows=%#v next=%#v authorized=%v err=%v", rows, next, authorized, err)
	}
}

func TestListGuardedBoundariesOrderingThresholdAndType(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "eventlog-query-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, _ := eventlog.NewStore(db)
	base := time.UnixMilli(1_800_000_000_000)
	items := []eventlog.Event{
		eventlog.Creation("old", "old", "1.1.1.1", false, base.Add(-1*time.Second)),
		eventlog.Creation("tie-a", "a", "1.1.1.1", false, base),
		eventlog.Creation("tie-b", "b", "1.1.1.1", false, base),
		eventlog.Creation("notice", "n", "1.1.1.1", true, base.Add(time.Second)),
		eventlog.Creation("fraction", "fraction", "1.1.1.1", false, base.Add(1500*time.Millisecond)),
		eventlog.Creation("fraction-late", "fraction-late", "1.1.1.1", false, base.Add(2500*time.Millisecond)),
	}
	for _, e := range items {
		s, _ := e.Statement("1=1")
		if _, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "insert-" + e.ID, Statements: []rhiza.SQLStatement{s}}); err != nil {
			t.Fatal(err)
		}
	}
	until := base.Unix()
	q := eventlog.Query{From: base.Unix(), Until: &until, Level: eventlog.Info}
	rows, _, ok, err := store.ListGuarded(ctx, q, base.Add(999*time.Millisecond), nil, eventlog.MaxPageSize, "1=1")
	ids := []string{items[1].ID, items[2].ID}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	if err != nil || !ok || len(rows) != 2 || rows[0].ID != ids[0] || rows[1].ID != ids[1] {
		t.Fatalf("inclusive/tie rows=%#v ok=%v err=%v", rows, ok, err)
	}
	q.Level = eventlog.Notice
	rows, _, ok, err = store.ListGuarded(ctx, q, base.Add(999*time.Millisecond), nil, eventlog.MaxPageSize, "1=1")
	if err != nil || !ok || len(rows) != 0 {
		t.Fatalf("threshold rows=%#v ok=%v err=%v", rows, ok, err)
	}
	q.Level = eventlog.Info
	typ := eventlog.NewRauthyAdmin
	q.Type = &typ
	rows, _, ok, err = store.ListGuarded(ctx, eventlog.Query{From: base.Unix() - 1, Until: ptr(base.Unix() + 1), Level: eventlog.Info, Type: &typ}, base.Add(999*time.Millisecond), nil, eventlog.MaxPageSize, "1=1")
	if err != nil || !ok || len(rows) != 1 || rows[0].Type != typ {
		t.Fatalf("exact type/time rows=%#v ok=%v err=%v", rows, ok, err)
	}
	rows, _, ok, err = store.ListGuarded(ctx, eventlog.Query{From: base.Unix(), Level: eventlog.Info}, base.Add(2999*time.Millisecond), nil, eventlog.MaxPageSize, "1=1")
	if err != nil || !ok || len(rows) != 4 {
		t.Fatalf("default until must truncate fractional second: rows=%#v ok=%v err=%v", rows, ok, err)
	}
	for _, row := range rows {
		if row.Text != nil && *row.Text == "fraction-late" {
			t.Fatal("event after truncated until returned")
		}
	}
}

func ptr(v int64) *int64 { return &v }
