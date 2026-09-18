package main

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/scim"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAccountExpirySCIMProjectionDisablesExpiredRetainedUser(t *testing.T) {
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "cmd-expiry-scim-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}

	now := time.UnixMilli(2_000_000).UTC()
	_, err = storage.Execute(ctx, db, rhiza.ExecuteRequest{
		RequestID: "cmd-expiry-scim-seed",
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO identity_users(subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation,user_expires_at_unix_ms) VALUES(?,?,?,0,0,1,?)`, Args: []any{"expired-subject", "expired-user", "phc", now.Add(-time.Minute).UnixMilli()}},
			{SQL: `INSERT INTO identity_users(subject,username,password_phc,disabled,password_changed_at_unix_ms,password_generation,user_expires_at_unix_ms) VALUES(?,?,?,0,0,1,?)`, Args: []any{"future-subject", "future-user", "phc", now.Add(time.Minute).UnixMilli()}},
			{SQL: `INSERT INTO identity_authentication_modes(subject,mode,generation,updated_at_unix_ms) VALUES
				('expired-subject','password',1,0),('future-subject','password',1,0)`},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	before, err := store.ListSCIMUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 2 || !before[0].Active || !before[1].Active {
		t.Fatalf("before expiry=%#v", before)
	}
	if expired, err := store.ExpireUsers(ctx, now, 128); err != nil || expired != 1 {
		t.Fatalf("expired=%d err=%v", expired, err)
	}
	after, err := store.ListSCIMUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) || after[0].ExternalID != before[0].ExternalID || after[0].UserName != before[0].UserName || after[0].Active || after[1] != before[1] {
		t.Fatalf("projection changed unexpectedly: before=%#v after=%#v", before, after)
	}

	var projected []scim.User
	outbox := scim.NewOutbox(db, func(_ context.Context, _ string) (scim.Reconciler, error) {
		return reconcilerFunc(func(_ context.Context, request scim.Request) (scim.Result, error) {
			projected = append(projected, request.User)
			return scim.Result{Action: scim.ActionCreated, RemoteID: "remote-" + request.User.ExternalID}, nil
		}), nil
	}, scim.OutboxConfig{Random: bytes.NewReader(bytes.Repeat([]byte{7}, 512))})
	runtime := &scimRuntime{identities: store, outbox: outbox, providers: map[string]configuredSCIMProvider{"provider": {}}, providerIDs: []string{"provider"}, drainLimit: 128}
	if err := runtime.Step(ctx, now); err != nil {
		t.Fatal(err)
	}
	if len(projected) != 2 || projected[0].ExternalID != "expired-subject" || projected[0].UserName != "expired-user" || projected[0].Active || projected[1].ExternalID != "future-subject" || projected[1].UserName != "future-user" || !projected[1].Active {
		t.Fatalf("SCIM projection=%#v", projected)
	}
}
