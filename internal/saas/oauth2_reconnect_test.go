package saas

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestOAuth2ReconnectReplacesRevokedCredentialAndFencesVersion(t *testing.T) {
	ctx, credentials, db, binding := credentialStoreFixture(t)
	if _, err := credentials.PrepareOAuth2Reconnect(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 1, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("draft prepare=%v", err)
	}
	if _, err := credentials.PrepareOAuth2Reconnect(ctx, "other", binding.CollectionID, binding.ConnectionID, 1, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("wrong owner=%v", err)
	}
	if _, err := credentials.PrepareOAuth2Reconnect(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 0, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("stale prepare=%v", err)
	}
	if err := credentials.Install(ctx, binding, credential{AccountID: "old-account", AccessToken: "old-access", RefreshToken: "old-refresh", Scopes: []string{"openid"}}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.PrepareOAuth2Reconnect(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 1, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("ready prepare=%v", err)
	}
	if _, err := credentials.PrepareOAuth2Reconnect(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 1, nil); !errors.Is(err, ErrCredentialUnauthorized) {
		t.Fatalf("nil authority prepare=%v", err)
	}
	if err := credentials.RevokeOAuth2(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 1, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	beforeCipher, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{binding.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(beforeCipher.Rows) != 1 {
		t.Fatalf("old ciphertext query=%v err=%v", beforeCipher.Rows, err)
	}
	reconnected, err := credentials.PrepareOAuth2Reconnect(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 1, credentialAuthority())
	if err != nil || reconnected.State != "reconnecting" || reconnected.Version != 1 || reconnected.AccountID != "" {
		t.Fatalf("reconnected=%+v err=%v", reconnected, err)
	}
	if _, err := credentials.PrepareOAuth2Reconnect(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 1, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("repeated prepare=%v", err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT revision,generation,metadata_json FROM auth_collection_connections WHERE id=?`, Args: []any{binding.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(2) || row.Rows[0][2] != "{}" {
		t.Fatalf("connection replacement row=%v err=%v", row.Rows, err)
	}
	newGeneration, _ := row.Rows[0][1].(string)
	if newGeneration == binding.Generation || newGeneration == "" {
		t.Fatal("reconnect did not fence generation")
	}
	afterCipher, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{binding.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(afterCipher.Rows) != 1 || !bytes.Equal(beforeCipher.Rows[0][0].([]byte), afterCipher.Rows[0][0].([]byte)) {
		t.Fatal("reconnect changed old ciphertext before callback")
	}

	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if err := r.ParseForm(); err != nil || r.Form.Get("code") == "" {
				t.Errorf("token form=%v err=%v", r.Form, err)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer"}`)
			return
		}
		if r.URL.Path == "/identity" {
			if r.Header.Get("Authorization") != "Bearer new-access" {
				t.Errorf("identity auth=%q", r.Header.Get("Authorization"))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"sub":"new-account"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer fixture.Close()
	providers, err := NewProviderStore(db, credentials.keys)
	if err != nil {
		t.Fatal(err)
	}
	input := ProviderInput{ID: "provider", Name: "Provider", Kind: "oauth2", Enabled: true, ClientID: "client", ClientSecret: "secret", CallbackURI: "https://auth.example/callback", AuthorizationURL: fixture.URL + "/authorize", TokenURL: fixture.URL + "/token", Scopes: []string{"openid"}, AuthStyle: "header", IdentityEndpoint: fixture.URL + "/identity", SubjectField: "sub"}
	if _, err := providers.Create(ctx, input, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	start, err := credentials.BeginOAuth2(ctx, providers, binding.Owner, binding.CollectionID, binding.ConnectionID, "provider", authorizationTestDigest("session"), input.CallbackURI, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(start.AuthorizationURL)
	p, guard, err := oauth2Provider(ctx, providers, "provider", input.CallbackURI, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	o, err := providers.LoadOAuth2(ctx, "provider", guard)
	if err != nil {
		t.Fatal(err)
	}
	o.client.Transport = fixture.Client().Transport
	status, err := credentials.completeOAuth2(ctx, o, p, binding.Owner, binding.CollectionID, binding.ConnectionID, authorizationTestDigest("session"), u.Query().Get("state"), "new-code", guard)
	if err != nil || !status.Connected || status.AccountID != "new-account" {
		t.Fatalf("replacement status=%+v err=%v", status, err)
	}
	ready, err := credentials.OAuth2Status(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, credentialAuthority())
	if err != nil || !ready.Connected || ready.State != "ready" || ready.Version != 2 {
		t.Fatalf("ready status=%+v err=%v", ready, err)
	}
	if err := credentials.RevokeOAuth2(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 1, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("old version revoke=%v", err)
	}
	if err := credentials.RevokeOAuth2(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 2, credentialAuthority()); err != nil {
		t.Fatalf("current revoke=%v", err)
	}
	third, err := credentials.PrepareOAuth2Reconnect(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 2, credentialAuthority())
	if err != nil || third.State != "reconnecting" || third.Version != 2 {
		t.Fatalf("third prepare=%+v err=%v", third, err)
	}
	start3, err := credentials.BeginOAuth2(ctx, providers, binding.Owner, binding.CollectionID, binding.ConnectionID, "provider", authorizationTestDigest("session-3"), input.CallbackURI, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	u3, _ := url.Parse(start3.AuthorizationURL)
	p3, guard3, err := oauth2Provider(ctx, providers, "provider", input.CallbackURI, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	o3, err := providers.LoadOAuth2(ctx, "provider", guard3)
	if err != nil {
		t.Fatal(err)
	}
	o3.client.Transport = fixture.Client().Transport
	if _, err := credentials.completeOAuth2(ctx, o3, p3, binding.Owner, binding.CollectionID, binding.ConnectionID, authorizationTestDigest("session-3"), u3.Query().Get("state"), "new-code-3", guard3); err != nil {
		t.Fatalf("third complete=%v", err)
	}
	final, err := credentials.OAuth2Status(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, credentialAuthority())
	if err != nil || !final.Connected || final.State != "ready" || final.Version != 3 {
		t.Fatalf("final status=%+v err=%v", final, err)
	}
	if err := credentials.RevokeOAuth2(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 2, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("stale version2 revoke=%v", err)
	}
	if err := credentials.RevokeOAuth2(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, 3, credentialAuthority()); err != nil {
		t.Fatalf("version3 revoke=%v", err)
	}
	if _, err := credentials.Load(ctx, binding, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("old binding load=%v", err)
	}
	if _, err := credentials.BeginOAuth2(ctx, providers, binding.Owner, binding.CollectionID, binding.ConnectionID, "provider", authorizationTestDigest("session"), input.CallbackURI, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("revoked current reconnect begin=%v", err)
	}
}
