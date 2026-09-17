package identity

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestUserCreationLifecycleEventsAreAtomicAndClassified(t *testing.T) {
	store := testResetStore(t, credential.DefaultRules())
	now := time.Unix(2_000_000_000, 123000000).UTC()
	store.now = func() time.Time { return now }
	ctx := context.Background()
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "event-role", SQL: `INSERT INTO rbac_roles(id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES('admin-role','rauthy_admin',NULL,1,0,0)`}); err != nil {
		t.Fatal(err)
	}
	_, err := store.CreateUserWithGuard(ctx, UserCreation{OpenRegistration: OpenRegistration{Email: "admin-event@example.test", TTL: time.Hour, SourceIP: "192.0.2.10"}, Roles: []string{"rauthy_admin"}}, "1=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.CreateUserWithGuard(ctx, UserCreation{OpenRegistration: OpenRegistration{Email: "ordinary-event@example.test", TTL: time.Hour, SourceIP: "198.51.100.4"}}, "1=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT typ,level,ip,text,timestamp,data FROM event_log ORDER BY id`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 3 {
		t.Fatalf("events=%#v err=%v", rows.Rows, err)
	}
	want := map[string]int{string(eventlog.NewRauthyAdmin): 1, string(eventlog.NewUserRegistered): 2}
	for _, row := range rows.Rows {
		if row[4] != now.UnixMilli() {
			t.Fatalf("timestamp=%v", row[4])
		}
		want[row[0].(string)]--
		level := int64(0)
		if row[0] == string(eventlog.NewRauthyAdmin) {
			level = 1
			if row[3] != "admin-event@example.test" {
				t.Fatalf("admin event attributed to ordinary user: %#v", row)
			}
		}
		ip := map[string]string{"admin-event@example.test": "192.0.2.10", "ordinary-event@example.test": "198.51.100.4"}[row[3].(string)]
		if row[1] != level || ip == "" || row[2] != ip || row[5] != nil {
			t.Fatalf("event payload=%#v", row)
		}
	}
	if want[string(eventlog.NewRauthyAdmin)] != 0 || want[string(eventlog.NewUserRegistered)] != 0 {
		t.Fatalf("event types=%v", want)
	}
}

func TestPublicDuplicateAndFailedCreationEmitNoExtraEvents(t *testing.T) {
	store := testResetStore(t, credential.DefaultRules())
	store.now = func() time.Time { return time.Unix(2_000_000_000, 0).UTC() }
	ctx := context.Background()
	first, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "duplicate-events@example.test", TTL: time.Hour, SourceIP: "192.0.2.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.RegisterOpenUser(ctx, OpenRegistration{Email: "duplicate-events@example.test", TTL: time.Hour, SourceIP: "192.0.2.2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUserWithGuard(ctx, UserCreation{OpenRegistration: OpenRegistration{Email: "denied-events@example.test", TTL: time.Hour}}, "0=1", nil); err == nil {
		t.Fatal("accepted denied creation")
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "rollback-event-role", SQL: `INSERT INTO rbac_roles(id,name,meta_json,revision,created_at_unix_ms,updated_at_unix_ms) VALUES('rollback-role','rollback',NULL,1,0,0)`}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUserWithGuard(ctx, UserCreation{OpenRegistration: OpenRegistration{Email: "rollback-events@example.test", TTL: time.Hour}, Roles: []string{"rollback", "rollback"}}, "1=1", nil); err == nil {
		t.Fatal("accepted constraint failure")
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT typ,text FROM event_log`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != string(eventlog.NewUserRegistered) || rows.Rows[0][1] != "duplicate-events@example.test" {
		t.Fatalf("events=%#v err=%v first=%#v", rows.Rows, err, first)
	}
}
