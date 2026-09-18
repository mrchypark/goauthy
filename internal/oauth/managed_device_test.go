package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"golang.org/x/crypto/bcrypt"
)

func seedManagedDeviceClient(t *testing.T, db *rhiza.DB, id, generation string, revision int64, confidential bool, secret string) {
	t.Helper()
	hash := []byte(nil)
	if confidential {
		var err error
		hash, err = bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
	}
	meta := `{"confidential":` + map[bool]string{true: "true", false: "false"}[confidential] + `,"redirect_uris":[],"scopes":["goauthy.read","goauthy.connections.read","offline_access"],"default_scopes":["goauthy.read"],"enabled_flows":["urn:ietf:params:oauth:grant-type:device_code","refresh_token"]}`
	_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "managed-device-seed-" + id, SQL: `INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json,secret_hash) VALUES(?,?,?,1,0,?,?)`, Args: []any{id, generation, revision, meta, hash}})
	if err != nil {
		t.Fatal(err)
	}
}

func TestManagedDeviceHTTPPublicAndConfidentialIssueRefreshAndRejectGenerationChange(t *testing.T) {
	for _, tc := range []struct {
		name, id, generation, secret string
		confidential                 bool
	}{
		{"public", "managed-device-public", "public-a", "", false},
		{"confidential", "managed-device-confidential", "conf-a", "secret", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := oauthTestDB(t)
			server := oauthTestServer(t, db, randomSecret(t))
			managed := clients.NewStore(db, (*oidc.Keyring)(nil))
			server.store.managedClients = managed
			seedManagedDeviceClient(t, db, tc.id, tc.generation, 1, tc.confidential, tc.secret)
			seedDeviceUser(t, db, "managed-device-user", nil)
			h, err := device.NewHandler(device.NewStore(db), "https://id.example.test", server.AuthenticateDeviceClient, nil)
			if err != nil {
				t.Fatal(err)
			}
			create := func() string {
				form := url.Values{"client_id": {tc.id}, "scope": {"goauthy.connections.read offline_access"}}
				r := httptest.NewRequest(http.MethodPost, "/oidc/device", strings.NewReader(form.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if tc.confidential {
					r.SetBasicAuth(tc.id, tc.secret)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != http.StatusOK {
					t.Fatalf("device status=%d body=%s", w.Code, w.Body.String())
				}
				var out struct {
					DeviceCode string `json:"device_code"`
					UserCode   string `json:"user_code"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
					t.Fatal(err)
				}
				return out.DeviceCode + "\x00" + out.UserCode
			}
			post := func(values url.Values) *httptest.ResponseRecorder {
				r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(values.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if tc.confidential {
					r.SetBasicAuth(tc.id, tc.secret)
				} else {
					values.Set("client_id", tc.id)
					r = httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(values.Encode()))
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				w := httptest.NewRecorder()
				server.TokenHandler().ServeHTTP(w, r)
				return w
			}
			parts := strings.Split(create(), "\x00")
			if err := device.NewStore(db).Approve(context.Background(), parts[1], "managed-device-user", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "managed-device-metadata-change-" + tc.id, SQL: `UPDATE managed_oauth_clients SET revision=revision+1 WHERE id=?`, Args: []any{tc.id}}); err != nil {
				t.Fatal(err)
			}
			first := post(url.Values{"grant_type": {DeviceGrantType}, "device_code": {parts[0]}})
			issued := decodeToken(t, first)
			if issued.RefreshToken == "" {
				t.Fatalf("refresh token missing: %s", first.Body.String())
			}
			resourceRequest := httptest.NewRequest(http.MethodGet, "/resource", nil)
			resourceRequest.Header.Set("Authorization", "Bearer "+issued.AccessToken)
			if _, _, authErr := server.AuthorizeUserResource(resourceRequest, "goauthy.connections.read", resourceAuthorizationAudience); authErr == nil {
				t.Fatal("managed device token without a resource audience was accepted")
			}
			refreshed := post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}})
			if refreshed.Code != http.StatusOK {
				t.Fatalf("refresh status=%d body=%s", refreshed.Code, refreshed.Body.String())
			}
			parts = strings.Split(create(), "\x00")
			if err := device.NewStore(db).Approve(context.Background(), parts[1], "managed-device-user", time.Now().UTC()); err != nil {
				t.Fatal(err)
			}
			_, err = storage.Execute(context.Background(), db, rhiza.ExecuteRequest{RequestID: "managed-device-generation-change-" + tc.id, SQL: `UPDATE managed_oauth_clients SET generation=?,revision=revision+1 WHERE id=?`, Args: []any{"changed-" + tc.generation, tc.id}})
			if err != nil {
				t.Fatal(err)
			}
			stale := post(url.Values{"grant_type": {DeviceGrantType}, "device_code": {parts[0]}})
			if stale.Code != http.StatusBadRequest || oauthErrorCode(t, stale) != "invalid_grant" {
				t.Fatalf("stale token status=%d body=%s", stale.Code, stale.Body.String())
			}
		})
	}
}

func TestManagedDevicePolicyChangesBetweenAuthenticationAndCreation(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	server.store.managedClients = clients.NewStore(db, nil)
	seedManagedDeviceClient(t, db, "managed-device-race", "generation-a", 1, false, "")
	h, err := device.NewHandler(device.NewStore(db), "https://id.example.test", func(r *http.Request, id string, scopes []string) error {
		if err := server.AuthenticateDeviceClient(r, id, scopes); err != nil {
			return err
		}
		// Deterministically interpose the policy commit after real authentication
		// but before the HTTP handler persists its pending grant. No sleeps.
		_, err := storage.Execute(r.Context(), db, rhiza.ExecuteRequest{RequestID: "managed-device-auth-interposition", SQL: `UPDATE managed_oauth_clients SET revision=revision+1 WHERE id=?`, Args: []any{id}})
		return err
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/oidc/device", strings.NewReader(url.Values{"client_id": {"managed-device-race"}, "scope": {"goauthy.read"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "device_code") {
		t.Fatalf("stale policy issued grant status=%d", w.Code)
	}
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_device_grants WHERE client_id='managed-device-race'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
		t.Fatalf("stale policy persisted grant rows=%v err=%v", rows.Rows, err)
	}
}
