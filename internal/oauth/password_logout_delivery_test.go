package oauth

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/backchannel"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

func TestPasswordLoginDeletionDeliversSignedLogout(t *testing.T) {
	for _, mode := range []string{"original", "updated", "removed"} {
		t.Run(mode, func(t *testing.T) { testPasswordLogoutDelivery(t, mode) })
	}
}

func testPasswordLogoutDelivery(t *testing.T, mode string) {
	t.Helper()

	db := oauthTestDB(t)
	users, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = users.BootstrapUser(t.Context(), "logout-user", "alice", phc); err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	paths := make(chan string, 1)
	rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(400)
			return
		}
		paths <- r.URL.Path
		received <- r.Form.Get("logout_token")
		w.WriteHeader(204)
	}))
	defer rp.Close()
	endpoint := rp.URL + "/original"
	managed := clients.NewStore(db, &oidc.Keyring{})
	client, err := managed.CreateWithGuard(t.Context(), clients.NewRequest{ID: "logout-client", BackchannelLogoutURI: &endpoint, Scopes: []string{"profile"}, DefaultScopes: []string{"profile"}, GrantTypes: []string{"password"}}, func() (string, []any) { return "1", nil })
	if err != nil {
		t.Fatal(err)
	}
	key := oidcTestKey(t)
	load := func(context.Context) (oidc.SigningKey, error) { return key, nil }
	server, err := NewServerWithOIDC(t.Context(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{Issuer: oidcTestIssuer, LoadSigningKey: load, PasswordUsers: users, ManagedClients: managed, ValidateSubject: users.ValidateSubject, BackChannelLogoutURI: "https://bootstrap.example.test/logout", BackChannelLogoutAllowPrivate: true})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {"password"}, "client_id": {client.ID}, "username": {"alice"}, "password": {"correct password"}}
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("password status=%d", response.Code)
	}
	if mode != "original" {
		endpoint = rp.URL + "/updated"
		var nextURI *string
		if mode == "updated" {
			nextURI = &endpoint
		}
		client, err = managed.UpdateWithGuard(t.Context(), client.ID, client.Revision, clients.UpdateRequest{BackchannelLogoutURI: nextURI, Enabled: true, Scopes: client.Scopes, DefaultScopes: client.DefaultScopes, GrantTypes: client.GrantTypes}, func() (string, []any) { return "1", nil })
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := users.DeleteUser(t.Context(), "logout-user"); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rp.Certificate())
	worker := backchannel.Worker{DB: db, Issuer: oidcTestIssuer, LoadSigningKey: load, WorkerID: "password-logout", TickInterval: time.Second, RetryBase: time.Second, LeaseDuration: 10 * time.Second, RequestTimeout: time.Second, MaxAttempts: 3, TokenLifetime: time.Minute, RootCAs: roots, AllowPrivate: true}
	now := time.Now().UTC()
	if err := worker.Step(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	if mode == "removed" {
		rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oidc_backchannel_deliveries`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
			t.Fatal("removed URI queued delivery", err)
		}
		select {
		case <-received:
			t.Fatal("removed URI received logout")
		default:
		}
		return
	}
	select {
	case token := <-received:
		wantPath := "/original"
		if mode == "updated" {
			wantPath = "/updated"
		}
		if path := <-paths; path != wantPath {
			t.Fatalf("logout path=%q want=%q", path, wantPath)
		}
		claims, err := oidc.VerifyLogoutToken(token, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, oidcTestIssuer, client.ID, now)
		if err != nil || claims.Subject != "logout-user" || claims.SessionID != "" {
			t.Fatal("invalid subject logout token", err)
		}
	case <-time.After(time.Second):
		t.Fatal("no logout delivery")
	}
}
