package oauth_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/rbac"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestExchangedAccessTokenLifecycleAfterActorForcedLogout(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	db, err := rhiza.Open(ctx, rhiza.Config{NodeID: "actor-logout-lifecycle-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signingKey := oidc.SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: public, KeyID: "actor-logout-test", Algorithm: string(jose.EdDSA), Use: "sig"}}
	const clientID = "actor-logout-client"
	const clientSecret = "test-client-secret-for-actor-logout"
	const redirectURI = "http://localhost/callback"
	const resource = "https://resource.example.test/api"
	server, err := oauth.NewServerWithOIDC(ctx, db, []byte(strings.Repeat("Z", 32)), clientID, clientSecret, redirectURI, []string{resource}, oauth.OIDCConfig{
		Issuer:         "https://id.example.test",
		LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return signingKey, nil },
	})
	if err != nil {
		t.Fatal(err)
	}

	issue := func(subject string) string {
		t.Helper()
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "actor-logout-user-" + subject, SQL: `INSERT INTO identity_users(subject,username,password_phc) VALUES(?,?,?)`, Args: []any{subject, subject, "test-only-phc"}}); err != nil {
			t.Fatal(err)
		}
		verifier := strings.Repeat("x", 43)
		digest := sha256.Sum256([]byte(verifier))
		query := url.Values{
			"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
			"scope": {"goauthy.read"}, "resource": {resource}, "state": {strings.Repeat("s", 32)},
			"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
		}
		w := httptest.NewRecorder()
		server.WriteAuthorization(w, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+query.Encode(), nil), subject, []string{"goauthy.read"})
		location, err := url.Parse(w.Header().Get("Location"))
		if err != nil || location.Query().Get("code") == "" {
			t.Fatalf("authorization subject=%q status=%d location=%q err=%v", subject, w.Code, w.Header().Get("Location"), err)
		}
		form := url.Values{"grant_type": {"authorization_code"}, "code": {location.Query().Get("code")}, "redirect_uri": {redirectURI}, "code_verifier": {verifier}}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(clientID, clientSecret)
		response := httptest.NewRecorder()
		server.TokenHandler().ServeHTTP(response, r)
		var token struct {
			AccessToken string `json:"access_token"`
			Error       string `json:"error"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil || response.Code != http.StatusOK || token.AccessToken == "" {
			t.Fatalf("authorization-code exchange subject=%q status=%d body=%s err=%v", subject, response.Code, response.Body.String(), err)
		}
		return token.AccessToken
	}
	introspect := func(raw string) (int, struct {
		Active  bool           `json:"active"`
		Subject string         `json:"sub"`
		Actor   map[string]any `json:"act"`
	}) {
		t.Helper()
		form := url.Values{"token": {raw}}
		r := httptest.NewRequest(http.MethodPost, "/oidc/introspect", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.SetBasicAuth(clientID, clientSecret)
		response := httptest.NewRecorder()
		server.IntrospectionHandler().ServeHTTP(response, r)
		var payload struct {
			Active  bool           `json:"active"`
			Subject string         `json:"sub"`
			Actor   map[string]any `json:"act"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil || response.Code != http.StatusOK {
			t.Fatalf("introspection status=%d body=%s err=%v", response.Code, response.Body.String(), err)
		}
		return response.Code, payload
	}

	owner := issue("logout-owner")
	actor := issue("logout-actor")
	form := url.Values{
		"grant_type": {oauth.TokenExchangeGrantType}, "subject_token": {owner}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token": {actor}, "actor_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "scope": {"goauthy.read"}, "resource": {resource},
	}
	r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(clientID, clientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, r)
	var exchanged struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &exchanged); err != nil || response.Code != http.StatusOK || exchanged.AccessToken == "" || exchanged.RefreshToken != "" {
		t.Fatalf("actor exchange status=%d body=%s err=%v", response.Code, response.Body.String(), err)
	}

	if err := rbac.NewStore(db).ForceLogout(ctx, "exchange-actor-forced-logout", "logout-actor", "1=1"); err != nil {
		t.Fatal(err)
	}
	_, actorAfter := introspect(actor)
	_, targetAfter := introspect(exchanged.AccessToken)
	if actorAfter.Active || !targetAfter.Active || targetAfter.Subject != "logout-owner" || targetAfter.Actor["sub"] != "logout-actor" {
		t.Fatalf("after actor logout: actor_active=%t target_active=%t target_sub=%q target_act=%#v", actorAfter.Active, targetAfter.Active, targetAfter.Subject, targetAfter.Actor)
	}
	countTokens := func() int64 {
		t.Helper()
		rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM oauth_access_tokens`, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(rows.Rows) != 1 {
			t.Fatalf("access token count rows=%#v err=%v", rows.Rows, err)
		}
		count, ok := rows.Rows[0][0].(int64)
		if !ok {
			t.Fatalf("access token count=%#v", rows.Rows[0][0])
		}
		return count
	}
	before := countTokens()
	req := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	rejected := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(rejected, req)
	if rejected.Code == http.StatusOK || countTokens() != before {
		t.Fatalf("revoked actor created a new delegated token: status=%d", rejected.Code)
	}
}
