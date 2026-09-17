package saas

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestOAuth2ConnectionBeginCompletePersistsBoundCredential(t *testing.T) {
	ctx, credentials, db, _ := credentialStoreFixture(t)
	var tokenCalls, identityCalls atomic.Int32
	var gotVerifier string
	fixture := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenCalls.Add(1)
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Basic Y2xpZW50OmNsaWVudC1zZWNyZXQ=" {
				t.Errorf("token auth=%q", r.Header.Get("Authorization"))
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			gotVerifier = r.Form.Get("code_verifier")
			if r.Form.Get("client_secret") != "" || r.Form.Get("code") == "" {
				t.Errorf("token form=%v", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			if r.Form.Get("code") == "scope-escalation" {
				_, _ = io.WriteString(w, `{"access_token":"access-escalation","token_type":"Bearer","scope":"openid admin"}`)
			} else if r.Form.Get("code") == "identity-fail" {
				_, _ = io.WriteString(w, `{"access_token":"access-fail","token_type":"Bearer"}`)
			} else if r.Form.Get("code") == "revoke-after-identity" {
				_, _ = io.WriteString(w, `{"access_token":"access-revoke","token_type":"Bearer"}`)
			} else {
				_, _ = io.WriteString(w, `{"access_token":"access","refresh_token":"refresh","token_type":"Bearer"}`)
			}
		case "/identity":
			identityCalls.Add(1)
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer access") {
				t.Errorf("identity auth=%q", r.Header.Get("Authorization"))
			}
			if r.Header.Get("Authorization") == "Bearer access-fail" {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if r.Header.Get("Authorization") == "Bearer access-revoke" {
				if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "oauth2-revoke-provider", SQL: `UPDATE saas_providers SET revision=revision+1 WHERE id=?`, Args: []any{"provider"}}); err != nil {
					t.Error(err)
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"sub":"account-1"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer fixture.Close()
	providers, err := NewProviderStore(db, credentials.keys)
	if err != nil {
		t.Fatal(err)
	}
	input := ProviderInput{ID: "provider", Name: "Provider", Kind: "oauth2", Enabled: true, ClientID: "client", ClientSecret: "client-secret", CallbackURI: "https://auth.example/callback", AuthorizationURL: fixture.URL + "/authorize", TokenURL: fixture.URL + "/token", Scopes: []string{"openid", "profile"}, AuthStyle: "header", IdentityEndpoint: fixture.URL + "/identity", SubjectField: "sub"}
	if _, err := providers.Create(ctx, input, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "oauth2-extra-connections", Statements: []rhiza.SQLStatement{
		{SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"connection-scope", "collection", "owner", "draft", 1, 1, "{}", "generation"}},
		{SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"connection-identity", "collection", "owner", "draft", 1, 1, "{}", "generation"}},
		{SQL: `INSERT INTO auth_collection_connections(id,collection_id,owner_subject,state,revision,definition_revision,metadata_json,generation) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"connection-revoke", "collection", "owner", "draft", 1, 1, "{}", "generation"}},
	}}); err != nil {
		t.Fatal(err)
	}
	callback := input.CallbackURI
	start, err := credentials.BeginOAuth2(ctx, providers, "owner", "collection", "connection", "provider", authorizationTestDigest("session"), callback, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := url.Parse(start.AuthorizationURL)
	if err != nil || authURL.Query().Get("state") == "" || authURL.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization URL=%q err=%v", start.AuthorizationURL, err)
	}
	p, guard, err := oauth2Provider(ctx, providers, "provider", callback, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	o, err := providers.LoadOAuth2(ctx, "provider", guard)
	if err != nil {
		t.Fatal(err)
	}
	o.client.Transport = fixture.Client().Transport
	for name, mutate := range map[string]func(*string, *string, *string){
		"wrong session":    func(_, _, session *string) { *session = authorizationTestDigest("other-session") },
		"wrong owner":      func(owner, _, _ *string) { *owner = "other-owner" },
		"wrong connection": func(_, connection, _ *string) { *connection = "other-connection" },
	} {
		owner, connection, session := "owner", "connection", authorizationTestDigest("session")
		mutate(&owner, &connection, &session)
		if _, err := credentials.completeOAuth2(ctx, o, p, owner, "collection", connection, session, authURL.Query().Get("state"), "code", guard); !errors.Is(err, ErrAuthorizationNotFound) && !errors.Is(err, ErrCredentialConflict) {
			t.Fatalf("%s err=%v", name, err)
		}
		if tokenCalls.Load() != 0 || identityCalls.Load() != 0 {
			t.Fatalf("%s made upstream calls", name)
		}
	}
	status, err := credentials.completeOAuth2(ctx, o, p, "owner", "collection", "connection", authorizationTestDigest("session"), authURL.Query().Get("state"), "code", guard)
	if err != nil || !status.Connected || status.AccountID != "account-1" || !sameStrings(status.Scopes, input.Scopes) {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if gotVerifier == "" || tokenCalls.Load() != 1 || identityCalls.Load() != 1 {
		t.Fatalf("calls token=%d identity=%d verifier=%q", tokenCalls.Load(), identityCalls.Load(), gotVerifier)
	}
	b := credentialBinding{"owner", "collection", "connection", "provider", "generation", 1}
	loaded, err := credentials.Load(ctx, b, credentialAuthority())
	if err != nil || loaded.AccountID != "account-1" || loaded.AccessToken != "access" || !sameStrings(loaded.Scopes, input.Scopes) {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	rows, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT credential FROM saas_connection_credentials`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || bytes.Contains(rows.Rows[0][0].([]byte), []byte("access")) || bytes.Contains(rows.Rows[0][0].([]byte), []byte("refresh")) {
		t.Fatalf("credential plaintext rows=%v err=%v", rows.Rows, err)
	}
	begin := func(connection string) string {
		started, err := credentials.BeginOAuth2(ctx, providers, "owner", "collection", connection, "provider", authorizationTestDigest("session"), callback, credentialAuthority())
		if err != nil {
			t.Fatal(err)
		}
		u, err := url.Parse(started.AuthorizationURL)
		if err != nil {
			t.Fatal(err)
		}
		return u.Query().Get("state")
	}
	complete := func(connection, state, code string) error {
		return func() error {
			_, guard, err := oauth2Provider(ctx, providers, "provider", callback, credentialAuthority())
			if err != nil {
				return err
			}
			o, err := providers.LoadOAuth2(ctx, "provider", guard)
			if err != nil {
				return err
			}
			o.client.Transport = fixture.Client().Transport
			_, err = credentials.completeOAuth2(ctx, o, p, "owner", "collection", connection, authorizationTestDigest("session"), state, code, guard)
			return err
		}()
	}
	scopeState := begin("connection-scope")
	beforeTokens := tokenCalls.Load()
	if err := complete("connection-scope", scopeState, "scope-escalation"); !errors.Is(err, ErrOAuth2Exchange) {
		t.Fatalf("scope escalation err=%v", err)
	}
	if tokenCalls.Load() != beforeTokens+1 || identityCalls.Load() != 1 {
		t.Fatalf("scope escalation calls token=%d identity=%d", tokenCalls.Load(), identityCalls.Load())
	}
	if err := complete("connection-scope", scopeState, "scope-escalation"); !errors.Is(err, ErrAuthorizationNotFound) && !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("scope replay err=%v", err)
	}
	if tokenCalls.Load() != beforeTokens+1 {
		t.Fatal("scope replay retried token exchange")
	}
	identityState := begin("connection-identity")
	beforeTokens, beforeIdentity := tokenCalls.Load(), identityCalls.Load()
	if err := complete("connection-identity", identityState, "identity-fail"); !errors.Is(err, ErrOAuth2Identity) {
		t.Fatalf("identity failure err=%v", err)
	}
	if tokenCalls.Load() != beforeTokens+1 || identityCalls.Load() != beforeIdentity+1 {
		t.Fatal("identity failure call count mismatch")
	}
	if err := complete("connection-identity", identityState, "identity-fail"); !errors.Is(err, ErrAuthorizationNotFound) && !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("identity replay err=%v", err)
	}
	revokeState := begin("connection-revoke")
	if err := complete("connection-revoke", revokeState, "revoke-after-identity"); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("revoked authority err=%v", err)
	}
	beforeReplayToken, beforeReplayIdentity := tokenCalls.Load(), identityCalls.Load()
	if _, err := credentials.completeOAuth2(ctx, o, p, "owner", "collection", "connection", authorizationTestDigest("session"), authURL.Query().Get("state"), "code", guard); !errors.Is(err, ErrAuthorizationNotFound) && !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("replay err=%v", err)
	}
	if tokenCalls.Load() != beforeReplayToken || identityCalls.Load() != beforeReplayIdentity {
		t.Fatal("replay made external calls")
	}
}

func sameStrings(a, b []string) bool {
	return len(a) == len(b) && strings.Join(a, "\x00") == strings.Join(b, "\x00")
}
