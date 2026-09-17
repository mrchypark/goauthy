package rbac

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestListSessionsStatesNullableAndGuard(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "u1")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "session-list-seed", SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,revoked_at_unix_ms,peer_ip) VALUES
		('init','', '',1,4000,3000,NULL,''),('auth','u1','pwd',1,3000,2000,NULL,'127.0.0.1'),('mfa','u1','mfa',1,2000,1000,NULL,''),('logged','u1','pwd',1,1000,500,900,''),('unknown','u1','',1,1000,500,NULL,'')`}); err != nil {
		t.Fatal(err)
	}
	items, count, _, err := store.listSessions(ctx, "1=1", nil, SessionListOptions{}, 1)
	if err != nil || count != 1 || len(items) != 2 {
		t.Fatalf("items=%#v count=%d err=%v", items, count, err)
	}
	got := map[string]Session{}
	for _, item := range items {
		got[item.ID] = item
	}
	for _, state := range []string{"Init", "LoggedOut", "Unknown"} {
		filtered, _, _, err := store.listSessions(ctx, "1=1", nil, SessionListOptions{State: state}, 1)
		if err != nil || len(filtered) != 1 || filtered[0].State != state {
			t.Fatalf("state=%s items=%+v err=%v", state, filtered, err)
		}
		got[filtered[0].ID] = filtered[0]
	}
	if got["init"].State != "Init" || got["init"].UserID != nil || got["init"].RemoteIP != nil || got["auth"].State != "Auth" || got["mfa"].State != "Auth" || !got["mfa"].IsMFA || got["logged"].State != "LoggedOut" {
		t.Fatalf("states=%#v", got)
	}
	if filtered, filteredCount, _, err := store.listSessions(ctx, "1=1", nil, SessionListOptions{State: "Init", PageSize: 1, Offset: 99, Cursor: ""}, 100); err != nil || filteredCount != 1 || len(filtered) != 1 || filtered[0].ID != "init" {
		t.Fatalf("below-threshold filter=%#v count=%d err=%v", filtered, filteredCount, err)
	}
	raw, err := json.Marshal(got["init"])
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := wire["user_id"]; ok {
		t.Fatal("init user_id must be omitted")
	}
	if value, ok := wire["remote_ip"]; !ok || value != nil {
		t.Fatal("remote_ip must be present and null")
	}
	if empty, emptyCount, _, err := store.listSessions(ctx, "1=1", nil, SessionListOptions{State: "Unknown", PageSize: 1, Offset: 1}, 1); err != nil || empty == nil || len(empty) != 0 || emptyCount != 1 {
		t.Fatalf("empty filter=%#v count=%d err=%v", empty, emptyCount, err)
	}
	if _, _, _, err := store.listSessions(ctx, "0=1", nil, SessionListOptions{}, 1); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("denied err=%v", err)
	}
}

func TestListSessionsThresholdAndTiedExpiryCursors(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	for i, id := range []string{"a", "b", "c"} {
		insertActive(t, db, "u"+string(rune('0'+i)))
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "session-list-user-" + id, SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) VALUES(?,?, 'pwd',1,4000,1)`, Args: []any{id, "u" + string(rune('0'+i))}}); err != nil {
			t.Fatal(err)
		}
	}
	items, count, token, err := store.listSessions(ctx, "1=1", nil, SessionListOptions{PageSize: 1}, 2)
	if err != nil || count != 3 || len(items) != 2 || token == "" {
		t.Fatalf("first items=%#v count=%d token=%q err=%v", items, count, token, err)
	}
	if items[0].ID != "c" || items[1].ID != "b" {
		t.Fatalf("forward order=%v", []string{items[0].ID, items[1].ID})
	}
	seen := map[string]bool{items[0].ID: true, items[1].ID: true}
	next, _, _, err := store.listSessions(ctx, "1=1", nil, SessionListOptions{PageSize: 1, Cursor: token}, 2)
	if err != nil || len(next) != 1 || seen[next[0].ID] {
		t.Fatalf("next=%#v err=%v", next, err)
	}
	if next[0].ID != "a" {
		t.Fatalf("forward continuation=%q", next[0].ID)
	}
	back, _, backToken, err := store.listSessions(ctx, "1=1", nil, SessionListOptions{PageSize: 1, Backwards: true}, 2)
	if err != nil || len(back) != 2 {
		t.Fatalf("back=%#v err=%v", back, err)
	}
	if back[0].ID != "b" || back[1].ID != "a" {
		t.Fatalf("backward order=%v", []string{back[0].ID, back[1].ID})
	}
	backNext, _, _, err := store.listSessions(ctx, "1=1", nil, SessionListOptions{PageSize: 1, Backwards: true, Cursor: backToken}, 2)
	if err != nil || len(backNext) != 1 || backNext[0].ID != "c" {
		t.Fatalf("backward continuation=%+v err=%v", backNext, err)
	}
	all, _, _, err := store.listSessions(ctx, "1=1", nil, SessionListOptions{}, 4)
	ignored, _, ignoredToken, ignoredErr := store.listSessions(ctx, "1=1", nil, SessionListOptions{PageSize: 1, Offset: 99, Backwards: true, Cursor: token}, 4)
	if err != nil || ignoredErr != nil || len(all) != 3 || !reflect.DeepEqual(all, ignored) || ignoredToken != "" {
		t.Fatalf("below threshold pagination was applied: all=%+v got=%+v errors=%v/%v", all, ignored, err, ignoredErr)
	}
}

func TestSessionListOptionsStrictCursor(t *testing.T) {
	for _, raw := range []string{"page_size=0", "page_size=+1", "page_size=%2B1", "page_size=65536", "backwards=yes", "session_state=Nope", "session_state=Auth&x=1", "page_size=1&page_size=2", "continuation_token=u1.bad", "continuation_token=s1.YQ", "offset=" + strings.Repeat("0", 2049)} {
		if _, err := parseSessionListOptions(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	token, err := encodeSessionCursor(sessionCursor{Exp: 4, ID: "session"})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"", "page_size=2&offset=1&backwards=true&continuation_token=" + url.QueryEscape(token) + "&session_state=Auth"} {
		if _, err := parseSessionListOptions(raw); err != nil {
			t.Fatalf("rejected %q: %v", raw, err)
		}
	}
	if _, err := decodeSessionCursor("u1.bad"); err == nil {
		t.Fatal("accepted user cursor")
	}
	for _, raw := range []string{token + "=", token + "\n", "s1." + strings.Repeat("a", 701), "s1." + base64.RawURLEncoding.EncodeToString(append([]byte{255, 0, 0, 0, 0, 0, 0, 0}, 'a')), "s1." + base64.RawURLEncoding.EncodeToString(append(make([]byte, 8), '\x00'))} {
		if _, err := decodeSessionCursor(raw); err == nil {
			t.Fatalf("accepted malformed cursor %q", raw)
		}
	}
}

func TestListSessionsDefaultPageSize(t *testing.T) {
	ctx, store, db := rbacTestStore(t)
	insertActive(t, db, "page-user")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "session-list-many", SQL: `WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<21) INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms) SELECT printf('page-%02d',x),'page-user','pwd',1,?,1 FROM n`, Args: []any{4102444800000}}); err != nil {
		t.Fatal(err)
	}
	items, _, _, err := store.listSessions(ctx, "1=1", nil, SessionListOptions{}, 1)
	if err != nil || len(items) != 20 {
		t.Fatalf("default page length=%d err=%v", len(items), err)
	}
}
