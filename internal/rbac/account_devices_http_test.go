package rbac

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAccountDevicesHTTPBrowserBoundary(t *testing.T) {
	t.Parallel()
	h, store, cookie, csrf := membershipHTTPFixture(t)
	if err := h.BindDeviceSessions(device.NewStore(store.db)); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "account-device-http-schema", Statements: []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS oauth_device_grants(token_request_id TEXT,client_id TEXT,scopes_json TEXT,created_at_unix_ms INTEGER,revoked_at_unix_ms INTEGER,subject TEXT,state TEXT)`},
		{SQL: `CREATE TABLE IF NOT EXISTS oauth_token_requests(signature TEXT,request_json TEXT)`},
		{SQL: `CREATE TABLE IF NOT EXISTS oauth_access_tokens(signature TEXT,revoked INTEGER)`},
	}}); err != nil {
		t.Fatal(err)
	}
	cols, _ := store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT name FROM pragma_table_info('oauth_device_grants')`, Consistency: rhiza.ConsistencyLinearizable})
	seen := map[string]bool{}
	for _, row := range cols.Rows {
		if len(row) == 1 {
			seen[row[0].(string)] = true
		}
	}
	var alters []rhiza.SQLStatement
	for _, column := range []string{"token_request_id TEXT", "revoked_at_unix_ms INTEGER"} {
		name := strings.Fields(column)[0]
		if !seen[name] {
			alters = append(alters, rhiza.SQLStatement{SQL: `ALTER TABLE oauth_device_grants ADD COLUMN ` + column})
		}
	}
	if len(alters) > 0 {
		if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "account-device-http-columns", Statements: alters}); err != nil {
			t.Fatal(err)
		}
	}
	for _, table := range []string{"oauth_token_requests", "oauth_access_tokens"} {
		rows, _ := store.db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT name FROM pragma_table_info('` + table + `')`, Consistency: rhiza.ConsistencyLinearizable})
		if table == "oauth_access_tokens" {
			hasRevoked := false
			for _, row := range rows.Rows {
				if len(row) == 1 && row[0] == "revoked" {
					hasRevoked = true
				}
			}
			if !hasRevoked {
				if _, err := storage.Execute(t.Context(), store.db, rhiza.ExecuteRequest{RequestID: "account-device-http-token-column", Statements: []rhiza.SQLStatement{{SQL: `ALTER TABLE oauth_access_tokens ADD COLUMN revoked INTEGER`}}}); err != nil {
					t.Fatal(err)
				}
			}
		}
	}

	w := httptest.NewRecorder()
	r := authCollectionRequest(http.MethodGet, "/auth/v1/account/devices", "", cookie, "")
	h.AccountDevices(w, r)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("list status=%d cache=%q body=%s", w.Code, w.Header().Get("Cache-Control"), w.Body.String())
	}
	var sessions []device.UserSession
	if err := json.Unmarshal(w.Body.Bytes(), &sessions); err != nil || len(sessions) != 0 {
		t.Fatalf("empty list=%s err=%v", w.Body.String(), err)
	}

	checks := []struct {
		name    string
		request func() *http.Request
		status  int
	}{
		{"query", func() *http.Request {
			q := authCollectionRequest(http.MethodGet, "/auth/v1/account/devices?x=1", "", cookie, "")
			return q
		}, http.StatusUnauthorized},
		{"cross-site", func() *http.Request {
			q := authCollectionRequest(http.MethodGet, "/auth/v1/account/devices", "", cookie, "")
			q.Header.Set("Sec-Fetch-Site", "cross-site")
			return q
		}, http.StatusUnauthorized},
		{"bearer", func() *http.Request {
			q := httptest.NewRequest(http.MethodGet, "/auth/v1/account/devices", nil)
			q.Header.Set("Authorization", "Bearer opaque")
			return q
		}, http.StatusUnauthorized},
		{"body", func() *http.Request {
			return authCollectionRequest(http.MethodGet, "/auth/v1/account/devices", "x", cookie, "")
		}, http.StatusBadRequest},
		{"delete csrf", func() *http.Request {
			return authCollectionRequestWithPath(http.MethodDelete, "/auth/v1/account/devices/device-1", "", cookie, "", map[string]string{"id": "device-1"})
		}, http.StatusUnauthorized},
		{"delete body", func() *http.Request {
			return authCollectionRequestWithPath(http.MethodDelete, "/auth/v1/account/devices/device-1", "x", cookie, csrf, map[string]string{"id": "device-1"})
		}, http.StatusBadRequest},
		{"unknown revoke", func() *http.Request {
			return authCollectionRequestWithPath(http.MethodDelete, "/auth/v1/account/devices/device-1", "", cookie, csrf, map[string]string{"id": "device-1"})
		}, http.StatusNotFound},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.AccountDevices(w, tc.request())
			if w.Code != tc.status {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.status, w.Body.String())
			}
		})
	}

	if err := h.BindDeviceSessions(nil); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("nil bind error=%v", err)
	}
}
