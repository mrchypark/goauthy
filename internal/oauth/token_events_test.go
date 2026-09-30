package oauth

import (
	"context"
	"errors"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/oidc"
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
	s, err := NewServerWithOIDC(t.Context(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{exchangeResource}, OIDCConfig{
		Issuer:         oidcTestIssuer,
		LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	code := issueExchangeCode(t, s)
	exchangeCode := issueExchangeCode(t, s)
	exchangeSource := decodeToken(t, postToken(s, url.Values{"grant_type": {"authorization_code"}, "code": {exchangeCode}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}})).AccessToken
	calls := 0
	expectedFlow := ""
	expectedCount := int64(0)
	const privateError = "event-store-private-sentinel"
	s.SetTokenIssued(func(ctx context.Context, flow, clientID, subject string) error {
		calls++
		if clientID != testClientID || flow != expectedFlow {
			t.Fatalf("unexpected event metadata flow=%q client=%q", flow, clientID)
		}
		rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM oauth_access_tokens", Consistency: rhiza.ConsistencyLinearizable})
		count, ok := int64(0), false
		if err == nil && len(rows.Rows) == 1 && len(rows.Rows[0]) == 1 {
			count, ok = rows.Rows[0][0].(int64)
		}
		if !ok || count != expectedCount {
			t.Fatal("event callback ran before token persistence")
		}
		if flow == "client_credentials" && subject != "" || flow != "client_credentials" && subject != "user-1" {
			t.Fatalf("unexpected event metadata flow=%q subject=%q", flow, subject)
		}
		return errors.New(privateError)
	})
	invalid := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader("grant_type=client_credentials&scope=goauthy.read"))
	invalid.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	invalid.SetBasicAuth(testClientID, "invalid-secret")
	denied := httptest.NewRecorder()
	s.TokenHandler().ServeHTTP(denied, invalid)
	if denied.Code != http.StatusUnauthorized || calls != 0 {
		t.Fatalf("invalid credentials status=%d calls=%d", denied.Code, calls)
	}
	for _, tc := range []struct {
		name, flow string
		form       url.Values
	}{
		{"client_credentials", "client_credentials", url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}},
		{"authorization_code", "authorization_code", url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("x", 43)}}},
		{"token_exchange", TokenExchangeGrantType, url.Values{"grant_type": {TokenExchangeGrantType}, "subject_token": {exchangeSource}, "subject_token_type": {accessTokenType}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expectedFlow = tc.flow
			rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: "SELECT COUNT(*) FROM oauth_access_tokens", Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(rows.Rows) != 1 {
				t.Fatalf("access token count rows=%#v err=%v", rows.Rows, err)
			}
			count, ok := rows.Rows[0][0].(int64)
			if !ok {
				t.Fatalf("access token count=%#v", rows.Rows[0][0])
			}
			expectedCount = count + 1
			response := postToken(s, tc.form)
			if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"access_token"`) || strings.Contains(response.Body.String(), privateError) || strings.Contains(response.Body.String(), "server_error") {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	if calls != 3 {
		t.Fatalf("event sink calls=%d, want one for each successful grant", calls)
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
