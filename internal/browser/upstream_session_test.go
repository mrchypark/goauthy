package browser

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestCreateUpstreamSessionStoresExactBinding(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	binding := UpstreamSessionBinding{Issuer: "https://issuer.example.test", ClientID: "client-1", Subject: "upstream-user", SessionID: "upstream-sid"}

	issued, err := store.CreateUpstreamSession(ctx, "external-user", binding, "external", now.Add(time.Hour), "203.0.113.1")
	if err != nil {
		t.Fatal(err)
	}
	if issued.AuthenticationMethod != "external" || !issued.Authenticated() {
		t.Fatalf("issued=%#v", issued)
	}
	rows, err := store.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT session_digest,issuer,client_id,upstream_subject,upstream_sid,created_at_unix_ms FROM browser_upstream_session_bindings`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || len(rows.Rows[0]) != 6 {
		t.Fatalf("binding rows=%v err=%v", rows.Rows, err)
	}
	if got := rows.Rows[0]; got[0] != issued.ID || got[1] != binding.Issuer || got[2] != binding.ClientID || got[3] != binding.Subject || got[4] != binding.SessionID || got[5] != now.UnixMilli() {
		t.Fatalf("binding=%v", got)
	}
}

func TestCreateUpstreamSessionRejectsInvalidBindingAndDisabledUserWithoutRows(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	valid := UpstreamSessionBinding{Issuer: "https://issuer.example.test", ClientID: "client-1", Subject: "upstream-user"}
	invalid := []UpstreamSessionBinding{
		{},
		{Issuer: " https://issuer.example.test", ClientID: "client-1", Subject: "upstream-user"},
		{Issuer: valid.Issuer, ClientID: strings.Repeat("c", maxClientIDLength+1), Subject: valid.Subject},
		{Issuer: valid.Issuer, ClientID: valid.ClientID, Subject: valid.Subject, SessionID: strings.Repeat("s", maxUpstreamSIDLength+1)},
	}
	for _, binding := range invalid {
		if _, err := store.CreateUpstreamSession(ctx, "external-user", binding, "external", now.Add(time.Hour), ""); err == nil {
			t.Fatalf("invalid binding accepted: %#v", binding)
		}
	}
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "upstream-binding-disable", SQL: `UPDATE identity_users SET disabled=1 WHERE subject='external-user'`}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateUpstreamSession(ctx, "external-user", valid, "external", now.Add(time.Hour), ""); err == nil {
		t.Fatal("disabled user accepted")
	}
	assertUpstreamBindingAndSessionCount(t, store, 0, 0)
}

func TestCreateUpstreamSessionRollsBackSessionWhenBindingInsertFails(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }
	// The API validation accepts this issuer; the restrictive test table makes
	// the final statement fail after the guarded session insert has run.
	if _, err := storage.Execute(ctx, store.db, rhiza.ExecuteRequest{RequestID: "upstream-binding-restrict-table", Statements: []rhiza.SQLStatement{
		{SQL: `DROP TABLE browser_upstream_session_bindings`},
		{SQL: `CREATE TABLE browser_upstream_session_bindings (session_digest TEXT PRIMARY KEY NOT NULL, issuer TEXT NOT NULL CHECK(issuer='permitted'), client_id TEXT NOT NULL, upstream_subject TEXT NOT NULL, upstream_sid TEXT, created_at_unix_ms INTEGER NOT NULL) STRICT`},
	}}); err != nil {
		t.Fatal(err)
	}
	_, err := store.CreateUpstreamSession(ctx, "external-user", UpstreamSessionBinding{Issuer: "https://issuer.example.test", ClientID: "client-1", Subject: "upstream-user"}, "external", now.Add(time.Hour), "")
	if err == nil {
		t.Fatal("binding insert failure accepted")
	}
	assertUpstreamBindingAndSessionCount(t, store, 0, 0)
}

func TestCreateUpstreamSessionDoesNotRevealTokenBeforeAckDurability(t *testing.T) {
	ctx := context.Background()
	objectStoreDir := filepath.Join(t.TempDir(), "objects")
	db, err := rhiza.Open(ctx, rhiza.Config{
		NodeID: "browser-upstream-before-ack", DataDir: t.TempDir(),
		ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: objectStoreDir,
		ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	statements := []rhiza.SQLStatement{
		{SQL: `INSERT INTO identity_users(subject,username,password_phc) VALUES('external-user','external-user','phc')`},
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "browser-upstream-before-ack-schema", Statements: statements}); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	offlineDir := objectStoreDir + "-offline"
	if err := os.Rename(objectStoreDir, offlineDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectStoreDir, []byte("offline"), 0o600); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		if err := os.Remove(objectStoreDir); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := os.Rename(offlineDir, objectStoreDir); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		restored = true
	}
	t.Cleanup(restore)

	issued, err := store.CreateUpstreamSession(ctx, "external-user", UpstreamSessionBinding{Issuer: "https://issuer.example.test", ClientID: "client-1", Subject: "upstream-user", SessionID: "sid"}, "external", now.Add(time.Hour), "")
	if !errors.Is(err, rhiza.ErrCommitUnknown) || issued.Token != "" || issued.ID != "" {
		t.Fatalf("offline create issued=%#v err=%v", issued, err)
	}
	restore()
	assertUpstreamBindingAndSessionCount(t, store, 1, 1)
}

func assertUpstreamBindingAndSessionCount(t *testing.T, store *Store, wantBindings, wantSessions int64) {
	t.Helper()
	for _, tc := range []struct {
		table string
		want  int64
	}{{"browser_upstream_session_bindings", wantBindings}, {"browser_sessions", wantSessions}} {
		rows, err := store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM ` + tc.table, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != tc.want {
			t.Fatalf("%s rows=%v want=%d err=%v", tc.table, rows.Rows, tc.want, err)
		}
	}
}
