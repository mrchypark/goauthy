package main

import (
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestUserExpirySettingsFromEnv(t *testing.T) {
	t.Parallel()
	getenv := func(values map[string]string) func(string) string {
		return func(name string) string { return values[name] }
	}
	got, err := userExpirySettingsFromEnv(getenv(map[string]string{}))
	if err != nil || got.interval != 60*time.Minute || got.deleteAfter != 0 {
		t.Fatalf("defaults=%#v err=%v", got, err)
	}
	got, err = userExpirySettingsFromEnv(getenv(map[string]string{"GOAUTHY_USER_EXPIRY_INTERVAL_MINUTES": "2", "GOAUTHY_USER_EXPIRY_DELETE_AFTER_MINUTES": "7"}))
	if err != nil || got.interval != 2*time.Minute || got.deleteAfter != 7*time.Minute {
		t.Fatalf("configured=%#v err=%v", got, err)
	}
	for _, values := range []map[string]string{{"GOAUTHY_USER_EXPIRY_INTERVAL_MINUTES": "0"}, {"GOAUTHY_USER_EXPIRY_DELETE_AFTER_MINUTES": "0"}, {"GOAUTHY_USER_EXPIRY_INTERVAL_MINUTES": "525601"}} {
		key, value := "", ""
		for k, v := range values {
			key, value = k, v
		}
		if _, err := userExpirySettingsFromEnv(getenv(map[string]string{key: value})); err == nil {
			t.Fatalf("accepted %s=%s", key, value)
		}
	}
}

func TestRunUserExpiryImmediatelyExpiresAndDeletes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "expiry-runner-test", DataDir: migratedDataDir(t, "expiry-runner-test")})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "expiry-runner-seed", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users(subject,username,password_phc,user_expires_at_unix_ms) VALUES ('expire-now','expire-now','',?)`, Args: []any{now.Add(-time.Minute).UnixMilli()}},
		{SQL: `INSERT INTO identity_users(subject,username,password_phc,disabled,user_expires_at_unix_ms) VALUES ('delete-now','delete-now','',1,?)`, Args: []any{now.Add(-2 * time.Hour).UnixMilli()}},
		{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES ('expire-now','password',1,?)`, Args: []any{now.UnixMilli()}},
		{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES ('delete-now','password',1,?)`, Args: []any{now.UnixMilli()}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := runUserExpiryTick(ctx, store, userExpirySettings{deleteAfter: time.Hour}, now); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT (SELECT disabled FROM identity_users WHERE subject='expire-now'), (SELECT COUNT(*) FROM identity_users WHERE subject='delete-now')`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) || rows.Rows[0][1] != int64(0) {
		t.Fatalf("expiry result=%#v err=%v", rows.Rows, err)
	}
	canceled, stop := context.WithCancel(context.Background())
	nowCalls := 0
	if err := runUserExpiry(canceled, store, userExpirySettings{interval: time.Minute}, func() time.Time { nowCalls++; return time.Time{} }, func(error) { stop() }); err != nil || nowCalls != 1 {
		t.Fatalf("immediate cancellation err=%v nowCalls=%d", err, nowCalls)
	}
	preCanceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runUserExpiry(preCanceled, store, userExpirySettings{interval: time.Minute}, func() time.Time { t.Fatal("called now after cancellation"); return now }, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRunUserExpiryRejectsInvalidConfigurationAndCanceledContext(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runUserExpiry(ctx, nil, userExpirySettings{interval: time.Minute}, time.Now, nil); err == nil {
		t.Fatal("accepted nil store")
	}
}
