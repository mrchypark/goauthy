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
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestDynamicPasswordLoginDeletionDeliversSignedLogout(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"original", "updated", "removed", "inflight-update", "inflight-remove"} {
		t.Run(mode, func(t *testing.T) { testDynamicPasswordLogoutDelivery(t, mode) })
	}
}

func testDynamicPasswordLogoutDelivery(t *testing.T, mode string) {
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
	if _, err = users.BootstrapUser(t.Context(), "dynamic-logout-user", "alice", phc); err != nil {
		t.Fatal(err)
	}
	received := make(chan struct {
		path  string
		token string
	}, 1)
	rp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- struct {
			path  string
			token string
		}{path: r.URL.Path, token: r.Form.Get("logout_token")}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer rp.Close()

	originalURI := rp.URL + "/original"
	updatedURI := rp.URL + "/updated"
	key := oidcTestKey(t)
	load := func(context.Context) (oidc.SigningKey, error) { return key, nil }
	server, err := NewServerWithOIDC(t.Context(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer:                        oidcTestIssuer,
		LoadSigningKey:                load,
		PasswordUsers:                 users,
		ValidateSubject:               users.ValidateSubject,
		BackChannelLogoutURI:          rp.URL + "/bootstrap",
		BackChannelLogoutAllowPrivate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := server.store.dynamicClients.Create(t.Context(), dcr.CreateRequest{
		ClientID:                "dynamic-password-logout",
		GrantTypes:              []string{"password"},
		Scopes:                  []string{"profile"},
		DefaultScopes:           []string{"profile"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic,
		Name:                    "Dynamic password logout",
		BackchannelLogoutURI:    originalURI,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mode == "inflight-update" || mode == "inflight-remove" {
		value := "'" + strings.ReplaceAll(updatedURI, "'", "''") + "'"
		if mode == "inflight-remove" {
			value = "NULL"
		}
		// Change metadata after the client snapshot, before association persistence.
		_, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "inflight-uri-update", SQL: `CREATE TRIGGER update_logout_uri AFTER INSERT ON oauth_access_tokens BEGIN UPDATE dynamic_oauth_clients SET backchannel_logout_uri=` + value + ` WHERE client_id='dynamic-password-logout'; END`})
		if err != nil {
			t.Fatal(err)
		}
	}
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {client.ClientID},
		"username":   {"alice"},
		"password":   {"correct password"},
	}
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(client.ClientID, client.ClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("password status=%d body=%s", response.Code, response.Body.String())
	}
	decodeOIDCToken(t, response)

	if mode == "updated" || mode == "removed" {
		uri := updatedURI
		if mode == "removed" {
			uri = ""
		}
		client, err = server.store.dynamicClients.Update(t.Context(), client.ClientID, client.RegistrationAccessToken, dcr.CreateRequest{
			ClientID:                client.ClientID,
			GrantTypes:              client.GrantTypes,
			ResponseTypes:           client.ResponseTypes,
			TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
			Name:                    client.Name,
			BackchannelLogoutURI:    uri,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	if err := users.DeleteUser(t.Context(), "dynamic-logout-user"); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(rp.Certificate())
	worker := backchannel.Worker{
		DB: db, Issuer: oidcTestIssuer, LoadSigningKey: load, WorkerID: "dynamic-password-logout",
		TickInterval: time.Second, RetryBase: time.Second, LeaseDuration: 10 * time.Second,
		RequestTimeout: time.Second, MaxAttempts: 3, TokenLifetime: time.Minute,
		RootCAs: roots, AllowPrivate: true,
	}
	now := time.Now().UTC()
	if err := worker.Step(t.Context(), now); err != nil {
		t.Fatal(err)
	}
	if mode == "removed" || mode == "inflight-remove" {
		rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oidc_backchannel_deliveries`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) {
			t.Fatalf("removed URI queued delivery: rows=%#v err=%v", rows.Rows, err)
		}
		select {
		case got := <-received:
			t.Fatalf("removed URI received logout at %s", got.path)
		default:
		}
		return
	}

	select {
	case got := <-received:
		wantPath := "/original"
		if mode == "updated" || mode == "inflight-update" {
			wantPath = "/updated"
		}
		if got.path != wantPath {
			t.Fatalf("logout path=%q want=%q", got.path, wantPath)
		}
		claims, err := oidc.VerifyLogoutToken(got.token, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, oidcTestIssuer, client.ClientID, now)
		if err != nil {
			t.Fatal(err)
		}
		if claims.Issuer != oidcTestIssuer || claims.Audience != client.ClientID || claims.Subject != "dynamic-logout-user" || claims.SessionID != "" {
			t.Fatalf("logout claims=%+v", claims)
		}
	case <-time.After(time.Second):
		t.Fatal("no logout delivery")
	}
}
