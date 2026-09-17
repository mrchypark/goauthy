package storage_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

func verifyNoPVCPasswordRefresh(t *testing.T, db *rhiza.DB, users *identity.Store, keyring *oidc.Keyring, root, issuer string, writing bool) {
	t.Helper()
	ctx := t.Context()
	server, err := oauth.NewServerWithOIDC(ctx, db, bytes.Repeat([]byte{9}, 32), "recovery-bootstrap", "disposable-client-secret", "https://app.example.test/callback", nil, oauth.OIDCConfig{Issuer: issuer, PasswordUsers: users, ValidateSubject: users.ValidateSubject, LoadSigningKey: func(ctx context.Context) (oidc.SigningKey, error) {
		return oidc.LoadActiveSigningKey(ctx, db, keyring, issuer)
	}})
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "recovery-password-client"
	const logoutURI = "https://rp.example.test/recovered-logout"
	if writing {
		_, err := dcr.NewStore(db).Create(ctx, dcr.CreateRequest{ClientID: clientID, BackchannelLogoutURI: logoutURI, Name: "Recovery Password", TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone, GrantTypes: []string{"password", "refresh_token"}, Scopes: []string{"profile"}, DefaultScopes: []string{"profile"}})
		if err != nil {
			t.Fatal(err)
		}
	}
	client, err := dcr.NewStore(db).GetClient(ctx, clientID)
	if err != nil {
		t.Fatal(err)
	}
	endpoint, ok := client.(interface{ GetBackchannelLogoutURI() string })
	if !ok || endpoint.GetBackchannelLogoutURI() != logoutURI {
		t.Fatal("recovered dynamic logout metadata changed")
	}
	form := url.Values{"client_id": {clientID}}
	path := filepath.Join(root, "password-refresh-token")
	if writing {
		form.Set("grant_type", "password")
		form.Set("username", "test@example.test")
		form.Set("password", "Disposable recovery test password 7!")
	} else {
		token, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(token)
		form.Set("grant_type", "refresh_token")
		form.Set("refresh_token", string(token))
	}
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	var tokens struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		ID      string `json:"id_token"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &tokens) != nil || tokens.Access == "" || tokens.Refresh == "" || tokens.ID == "" {
		t.Fatalf("password recovery token status=%d", response.Code)
	}
	association, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT logout_uri FROM oidc_user_clients WHERE subject=? AND client_id=?`, Args: []any{"test-user", clientID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(association.Rows) != 1 || association.Rows[0][0] != logoutURI {
		t.Fatal("recovered password login association changed", err)
	}
	key, err := oidc.LoadActiveSigningKey(ctx, db, keyring, issuer)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := oidc.VerifyIDToken(tokens.ID, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key.PublicJWK}}, issuer, clientID, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "test-user" || claims.SessionID != "" || len(claims.AuthenticationMethods) != 1 || claims.AuthenticationMethods[0] != "pwd" {
		t.Fatal("recovered password claims changed")
	}
	if writing {
		if err := os.WriteFile(path, []byte(tokens.Refresh), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
