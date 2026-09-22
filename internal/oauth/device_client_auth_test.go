package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/rhiza"
)

func TestAuthenticateDeviceClientHTTPMethodsAndFailures(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name               string
		basic              bool
		clientID           string
		username, password string
		bodyClient         []string
		want               int
	}{
		{"bootstrap missing", false, testClientID, "", "", []string{testClientID}, http.StatusUnauthorized},
		{"bootstrap wrong basic", true, testClientID, testClientID, "wrong", []string{testClientID}, http.StatusUnauthorized},
		{"bootstrap correct basic", true, testClientID, testClientID, testClientSecret, []string{testClientID}, http.StatusOK},
		{"bootstrap basic without body id", true, testClientID, testClientID, testClientSecret, nil, http.StatusOK},
		{"bootstrap mixed mismatch", true, testClientID, testClientID, testClientSecret, []string{"other-client"}, http.StatusBadRequest},
		{"bootstrap duplicate body id", true, testClientID, testClientID, testClientSecret, []string{testClientID, testClientID}, http.StatusBadRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := oauthTestDB(t)
			server := oauthTestServer(t, db, randomSecret(t))
			response := deviceAuthRequest(t, server, tc.bodyClient, tc.username, tc.password, tc.basic)
			if response.Code != tc.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			if tc.want == http.StatusUnauthorized && (response.Header().Get("WWW-Authenticate") == "" || oauthErrorCode(t, response) != "invalid_client") {
				t.Fatal("missing authentication challenge or OAuth error")
			}
			assertDeviceGrantCount(t, db, tc.want == http.StatusOK)
		})
	}
}

func TestAuthenticateDeviceClientHTTPDynamicMethods(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, method string
		auth         bool
		want         int
	}{
		{"public none", dcr.TokenEndpointAuthNone, false, http.StatusOK},
		{"public none rejects basic", dcr.TokenEndpointAuthNone, true, http.StatusUnauthorized},
		{"basic accepts basic", dcr.TokenEndpointAuthClientBasic, true, http.StatusOK},
		{"basic rejects post", dcr.TokenEndpointAuthClientBasic, false, http.StatusUnauthorized},
		{"post accepts post", dcr.TokenEndpointAuthClientPost, false, http.StatusOK},
		{"post rejects basic", dcr.TokenEndpointAuthClientPost, true, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			db := oauthTestDB(t)
			server := oauthTestServer(t, db, randomSecret(t))
			id := "dynamic-" + strings.ReplaceAll(tc.name, " ", "-")
			registered, err := server.store.dynamicClients.Create(context.Background(), dcr.CreateRequest{ClientID: id, GrantTypes: []string{DeviceGrantType}, Scopes: []string{"goauthy.read"}, TokenEndpointAuthMethod: tc.method, Name: id})
			if err != nil {
				t.Fatal(err)
			}
			response := deviceAuthRequest(t, server, []string{registered.ClientID}, registered.ClientID, registered.ClientSecret, tc.auth)
			if response.Code != tc.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			assertDeviceGrantCount(t, db, tc.want == http.StatusOK)
		})
	}
}

func deviceAuthRequest(t *testing.T, server *Server, bodyIDs []string, user, pass string, basic bool) *httptest.ResponseRecorder {
	t.Helper()
	values := url.Values{"client_id": bodyIDs, "scope": {"goauthy.read"}}
	if !basic && pass != "" {
		values.Set("client_secret", pass)
	}
	r := httptest.NewRequest(http.MethodPost, "/oidc/device", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		r.SetBasicAuth(user, pass)
	}
	h, err := device.NewHandler(device.NewStore(server.store.db), "https://id.example.test", server.AuthenticateDeviceClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func assertDeviceGrantCount(t *testing.T, db *rhiza.DB, wantOne bool) {
	t.Helper()
	rows, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_device_grants`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 {
		t.Fatalf("grant count query rows=%#v err=%v", rows.Rows, err)
	}
	want := int64(0)
	if wantOne {
		want = 1
	}
	if rows.Rows[0][0] != want {
		t.Fatalf("grant count=%v want=%d", rows.Rows[0][0], want)
	}
}

func TestAuthenticateDeviceClientHTTPRejectsAmbiguousCredentials(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	h, err := device.NewHandler(device.NewStore(db), "https://id.example.test", server.AuthenticateDeviceClient, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mixed methods", "duplicate header", "duplicate secret", "malformed basic"} {
		t.Run(name, func(t *testing.T) {
			form := url.Values{"client_id": {testClientID}, "scope": {"goauthy.read"}}
			if name == "mixed methods" || name == "duplicate secret" {
				form["client_secret"] = []string{testClientSecret}
			}
			if name == "duplicate secret" {
				form.Add("client_secret", testClientSecret)
			}
			r := httptest.NewRequest(http.MethodPost, "/oidc/device", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if name != "duplicate secret" {
				r.SetBasicAuth(testClientID, testClientSecret)
			}
			if name == "duplicate header" {
				r.Header.Add("Authorization", r.Header.Get("Authorization"))
			}
			if name == "malformed basic" {
				r.Header.Set("Authorization", "Basic invalid")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || oauthErrorCode(t, w) != "invalid_request" {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			assertDeviceGrantCount(t, db, false)
		})
	}
}
