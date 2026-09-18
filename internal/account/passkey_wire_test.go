package account

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/passkey"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestListPasskeysRauthyWireShape(t *testing.T) {
	h, db, _, cookie, csrf, _ := testPasskeyAccountHandler(t)
	assertBody := func(want string) {
		t.Helper()
		response := httptest.NewRecorder()
		h.ListPasskeys(response, passkeyBrowserRequest(cookie, csrf, "subject-1", http.MethodGet, nil))
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" || response.Body.String() != want+"\n" {
			t.Fatalf("status=%d body=%s want=%s", response.Code, response.Body.String(), want)
		}
	}
	assertBody(`[]`)
	seedAccountCredential(t, db, "wire-credential", "primary")
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "passkey-wire-fixed-timestamps",
		SQL:       `UPDATE identity_webauthn_credentials SET registered_at_unix_ms=?,last_used_at_unix_ms=? WHERE credential_id=?`,
		Args:      []any{int64(1700000000987), int64(1700000123456), "wire-credential"},
	}); err != nil {
		t.Fatal(err)
	}
	assertBody(`[{"name":"primary","registered":1700000000,"last_used":1700000123,"user_verified":true}]`)
}

func TestPasskeyResponsesRauthyWireShape(t *testing.T) {
	items := passkeyResponses([]passkey.Credential{{Name: "primary", Registered: time.Unix(1700000000, 0).UTC(), LastUsed: time.Unix(1700000123, 0).UTC(), UserVerified: true}, {Name: "legacy", Registered: time.Unix(0, 0).UTC(), LastUsed: time.Unix(0, 0).UTC()}})
	b, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `[{"name":"primary","registered":1700000000,"last_used":1700000123,"user_verified":true},{"name":"legacy","registered":0,"last_used":0}]`; got != want {
		t.Fatalf("wire=%s want=%s", got, want)
	}
	empty, err := json.Marshal(passkeyResponses(nil))
	if err != nil || string(empty) != "[]" {
		t.Fatalf("empty wire=%s err=%v", empty, err)
	}
}
