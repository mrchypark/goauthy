package oauth

import (
	"context"
	"errors"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/rhiza"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTokenIssuedGrantSelection(t *testing.T) {
	t.Parallel()
	failure := errors.New("event sink unavailable")
	for _, tc := range []struct {
		flow, emitted string
		fail          bool
	}{
		{"authorization_code", "authorization_code", true},
		{"client_credentials", "client_credentials", true},
		{"password", "password", true},
		{TokenExchangeGrantType, TokenExchangeGrantType, true},
		{"urn:ietf:params:oauth:grant-type:device_code", "device_code", false},
		{"refresh_token", "", false},
		{"unknown", "", false},
	} {
		t.Run(tc.flow, func(t *testing.T) {
			s := &Server{}
			if err := s.emitTokenIssued(context.Background(), tc.flow, "client", "user"); err != nil {
				t.Fatal(err)
			}
			calls := 0
			s.SetTokenIssued(func(_ context.Context, flow, client, subject string) error {
				calls++
				if flow != tc.emitted || client != "client" || subject != "user" {
					t.Fatal("wrong event metadata")
				}
				return failure
			})
			err := s.emitTokenIssued(context.Background(), tc.flow, "client", "user")
			if (err != nil) != tc.fail || (tc.fail && !errors.Is(err, failure)) || (tc.emitted == "" && calls != 0) || (tc.emitted != "" && calls != 1) {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestTokenIssuedFailureHTTP(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	s, err := NewServer(t.Context(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	const privateError = "event-store-private-sentinel"
	s.SetTokenIssued(func(ctx context.Context, flow, clientID, subject string) error {
		calls++
		if flow != "client_credentials" || clientID != testClientID || subject != "" {
			t.Fatal("unexpected machine metadata")
		}
		rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM oauth_access_tokens", Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(1) {
			t.Fatal("event callback ran before token persistence")
		}
		return errors.New(privateError)
	})
	for _, valid := range []bool{false, true} {
		req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader("grant_type=client_credentials&scope=goauthy.read"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		secret := "invalid-secret"
		if valid {
			secret = testClientSecret
		}
		req.SetBasicAuth(testClientID, secret)
		response := httptest.NewRecorder()
		s.TokenHandler().ServeHTTP(response, req)
		want, wantCalls := http.StatusUnauthorized, 0
		if valid {
			want, wantCalls = http.StatusInternalServerError, 1
		}
		if response.Code != want || calls != wantCalls || strings.Contains(response.Body.String(), privateError) || strings.Contains(response.Body.String(), "access_token") {
			t.Fatalf("status=%d calls=%d", response.Code, calls)
		}
		if valid && !strings.Contains(response.Body.String(), "server_error") {
			t.Fatal("missing server_error")
		}
	}
}

func TestTokenIssuedDeviceFailureHTTP(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	seedDeviceUser(t, db, "device-event-user", nil)
	store := device.NewStore(db)
	now := time.Now().UTC()
	grant, err := store.Create(t.Context(), testClientID, []string{"goauthy.read", "offline_access"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Approve(t.Context(), grant.UserCode, "device-event-user", now); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server.SetTokenIssued(func(_ context.Context, flow, client, subject string) error {
		calls++
		if flow != "device_code" || client != testClientID || subject != "device-event-user" {
			t.Fatal("incorrect device event metadata")
		}
		return errors.New("event-storage-unavailable")
	})
	form := url.Values{"grant_type": {DeviceGrantType}, "device_code": {grant.DeviceCode}}
	issued := decodeToken(t, postToken(server, form))
	if issued.AccessToken == "" || issued.RefreshToken == "" || calls != 1 {
		t.Fatal("event failure prevented device tokens")
	}
	stored, err := server.store.GetAccessTokenSession(t.Context(), server.accessTokens.AccessTokenSignature(t.Context(), issued.AccessToken), nil)
	if err != nil || stored.GetSession().GetSubject() != "device-event-user" {
		t.Fatal("device token was not persisted")
	}
	replayed := postToken(server, form)
	if replayed.Code != http.StatusBadRequest || oauthErrorCode(t, replayed) != "expired_token" || calls != 1 {
		t.Fatal("device replay reissued token/event")
	}
}
