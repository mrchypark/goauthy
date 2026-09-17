package login

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestLoginMetadataUsesPersistedSessionTime(t *testing.T) {
	h, db := testHandlerWithDB(t, false)
	ctx := context.Background()
	// Fix only the persisted creation time; assertions never compare elapsed
	// wall time or wait for an expiry boundary. This also catches using the
	// in-memory CreateSession result instead of the durable session row.
	const created = int64(1_700_000_000_123)
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "login-metadata-fixed-session-time", SQL: `CREATE TRIGGER login_metadata_fixed_time AFTER INSERT ON browser_sessions WHEN NEW.subject <> '' BEGIN UPDATE browser_sessions SET created_at_unix_ms = 1700000000123 WHERE token_digest = NEW.token_digest; END`}); err != nil {
		t.Fatal(err)
	}
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if page.Code != http.StatusOK || len(page.Result().Cookies()) != 1 {
		t.Fatalf("authorize status=%d", page.Code)
	}
	init := page.Result().Cookies()[0]
	interaction := interactionToken(t, page.Body.String())
	assertLoginMetadata(t, db, nil)
	for _, attempt := range []struct{ username, password string }{
		{"alice", "wrong password"}, {"nobody", "wrong password"}, {"disabled", "correct password"},
	} {
		response := httptest.NewRecorder()
		h.Login(response, postLogin(init, interaction, attempt.username, attempt.password))
		if response.Code != http.StatusUnauthorized || response.Header().Get("Set-Cookie") != "" {
			t.Fatalf("rejected login %s status=%d", attempt.username, response.Code)
		}
		assertLoginMetadata(t, db, nil)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(last_login_at_unix_ms) FROM identity_users`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
		t.Fatalf("rejected authentication recorded metadata: %v err=%v", rows.Rows, err)
	}
	completed := httptest.NewRecorder()
	h.Login(completed, postLogin(init, interaction, "alice", "correct password"))
	if completed.Code != http.StatusSeeOther || len(completed.Result().Cookies()) != 1 {
		t.Fatalf("login status=%d body=%q", completed.Code, completed.Body.String())
	}
	assertLoginMetadata(t, db, created)
}

func TestLoginMetadataFailurePreservesOldSessionAndPublishesNoCookie(t *testing.T) {
	h, db := testHandlerWithDB(t, false)
	ctx := context.Background()
	page := httptest.NewRecorder()
	h.Authorize(page, httptest.NewRequest(http.MethodGet, authorizePath+"?"+authorizeValues().Encode(), nil))
	if page.Code != http.StatusOK || len(page.Result().Cookies()) != 1 {
		t.Fatalf("authorize status=%d", page.Code)
	}
	old := page.Result().Cookies()[0]
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "login-metadata-reject-update", SQL: `CREATE TRIGGER login_metadata_reject BEFORE UPDATE OF last_login_at_unix_ms ON identity_users BEGIN SELECT RAISE(ABORT, 'metadata fixture failure'); END`}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	if _, err := h.rotateBrowserSession(response, httptest.NewRequest(http.MethodPost, "/", nil), old.Value, "user-1", "pwd", ""); err == nil {
		t.Fatal("metadata failure accepted")
	}
	if response.Header().Get("Set-Cookie") != "" {
		t.Fatal("failed transition published a cookie")
	}
	assertLoginMetadata(t, db, nil)
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject, revoked_at_unix_ms IS NULL FROM browser_sessions ORDER BY subject`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 2 || rows.Rows[0][0] != "" || rows.Rows[0][1] != int64(1) || rows.Rows[1][0] != "user-1" || rows.Rows[1][1] != int64(0) {
		t.Fatalf("old/new session state=%v err=%v", rows.Rows, err)
	}
}

func assertLoginMetadata(t *testing.T, db *rhiza.DB, want any) {
	t.Helper()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT last_login_at_unix_ms FROM identity_users WHERE subject='user-1'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != want {
		t.Fatalf("login metadata=%v want=%v err=%v", rows.Rows, want, err)
	}
}
