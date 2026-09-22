package recovery

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/oidc"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestExpiredPasswordGrantDeliversResetSMTP(t *testing.T) {
	t.Parallel()
	service, _ := testService(t, "subject-1", "alice")
	ctx := t.Context()
	if err := service.BindEmail(ctx, "subject-1", "alice@example.test"); err != nil {
		t.Fatal(err)
	}
	address, received := startSMTPFixture(t)
	host, port := splitSMTPAddress(t, address)
	sender, err := NewSMTPSender(SMTPConfig{Host: host, Port: port, From: "support@example.test", Timeout: time.Second, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	service.sender = sender
	service.OnError = func(err error) { t.Errorf("SMTP delivery: %v", err) }
	if _, err := storage.Execute(ctx, service.db, rhiza.ExecuteRequest{RequestID: "expire-password-smtp", SQL: `UPDATE identity_users SET password_changed_at_unix_ms=1 WHERE subject='subject-1'`}); err != nil {
		t.Fatal(err)
	}

	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	key := oidc.SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: private.Public(), KeyID: "reset-test", Algorithm: "EdDSA", Use: "sig"}}
	server, err := oauth.NewServerWithOIDC(ctx, service.db, bytes.Repeat([]byte{8}, 32), "bootstrap", "bootstrap-secret", "https://app.example.test/callback", nil, oauth.OIDCConfig{Issuer: service.issuer, PasswordUsers: service.identity, ValidateSubject: service.identity.ValidateSubject, PasswordExpired: service.IssueForSubject, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil }})
	if err != nil {
		t.Fatal(err)
	}
	client, err := dcr.NewStore(service.db).Create(ctx, dcr.CreateRequest{ClientID: "smtp-password", Name: "SMTP Password", TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone, GrantTypes: []string{"password", "refresh_token"}, Scopes: []string{"profile"}, DefaultScopes: []string{"profile"}})
	if err != nil {
		t.Fatal(err)
	}
	postPassword := func(password string) *httptest.ResponseRecorder {
		form := url.Values{"grant_type": {"password"}, "client_id": {client.ClientID}, "username": {"alice"}, "password": {password}}
		request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		server.TokenHandler().ServeHTTP(response, request)
		return response
	}
	expired := postPassword("CurrentPassword1")
	if expired.Code != http.StatusForbidden || strings.Contains(expired.Body.String(), "access_token") {
		t.Fatalf("expired token status=%d", expired.Code)
	}
	var resetURL string
	select {
	case raw := <-received:
		message, err := mail.ReadMessage(strings.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(message.Header.Get("To"), "alice@example.test") {
			t.Fatal("incorrect reset recipient")
		}
		plain, html := multipartBodies(t, message)
		resetURL = regexp.MustCompile(`https?://[^\s<>"\x27]+/auth/v1/users/subject-1/reset/[A-Za-z0-9_-]+`).FindString(plain)
		if resetURL == "" {
			t.Fatal("reset URL not found in delivered message")
		}
		if !strings.Contains(plain, "/auth/v1/users/subject-1/reset/") || !strings.Contains(html, "/auth/v1/users/subject-1/reset/") {
			t.Fatal("missing reset link")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reset message not received")
	}
	q, err := service.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT failed_login_attempts FROM identity_users WHERE subject='subject-1'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(1) {
		t.Fatalf("failure count: %+v %v", q, err)
	}

	token := resetURL[strings.LastIndex(resetURL, "/")+1:]
	get := httptest.NewRequest(http.MethodGet, resetURL, nil)
	get.SetPathValue("subject", "subject-1")
	get.SetPathValue("token", token)
	response := httptest.NewRecorder()
	service.GetReset(response, get)
	var document resetResponse
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &document) != nil {
		t.Fatalf("begin reset status=%d", response.Code)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("missing reset cookie")
	}
	finish := putResetRequest(t, service, "subject-1", putReset{MagicLinkID: token, Password: "ChangedPassword2"}, cookies[0], document.CSRFToken)
	if finish.Code != http.StatusAccepted {
		t.Fatalf("finish reset status=%d", finish.Code)
	}
	if _, err := service.identity.Authenticate(ctx, "alice", []byte("CurrentPassword1")); err != identity.ErrInvalidCredentials {
		t.Fatalf("old password error=%v", err)
	}

	issued := postPassword("ChangedPassword2")
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}
	if issued.Code != http.StatusOK || json.Unmarshal(issued.Body.Bytes(), &tokens) != nil || tokens.AccessToken == "" || tokens.RefreshToken == "" || tokens.IDToken == "" {
		t.Fatalf("reset password token status=%d", issued.Code)
	}
	claims, err := oidc.VerifyIDToken(tokens.IDToken, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, service.issuer, client.ClientID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "subject-1" || claims.SessionID != "" || claims.AuthTime.IsZero() || len(claims.AuthenticationMethods) != 1 || claims.AuthenticationMethods[0] != "pwd" {
		t.Fatal("incorrect recovered password identity claims")
	}
	q, err = service.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT failed_login_attempts,last_failed_login_at_unix_ms FROM identity_users WHERE subject='subject-1'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != nil || q.Rows[0][1] != nil {
		t.Fatalf("successful login did not clear failures: %+v %v", q, err)
	}
	replay := putResetRequest(t, service, "subject-1", putReset{MagicLinkID: token, Password: "ReplayPassword3"}, cookies[0], document.CSRFToken)
	if replay.Code < 400 {
		t.Fatalf("reset replay status=%d", replay.Code)
	}
}
