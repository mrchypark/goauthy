package saas

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

type refreshFixture struct {
	ctx                       context.Context
	s                         *CredentialStore
	b                         credentialBinding
	p                         *ProviderStore
	o                         *OAuth2
	guard                     func() (string, []any)
	server                    *httptest.Server
	tokenCalls, identityCalls atomic.Int32
	mode                      atomic.Value
	beforeTokenReply          func()
}

func newRefreshFixture(t *testing.T, account string) *refreshFixture {
	t.Helper()
	f := &refreshFixture{}
	f.mode.Store("success")
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			f.tokenCalls.Add(1)
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Basic Y2xpZW50OnNlY3JldA==" {
				t.Error("wrong token endpoint authentication or method")
			}
			if err := r.ParseForm(); err != nil || r.Form.Get("refresh_token") != "refresh-old" || r.Form.Get("grant_type") != "refresh_token" {
				t.Error("wrong refresh request form")
			}
			if f.beforeTokenReply != nil {
				f.beforeTokenReply()
			}
			if f.mode.Load() == "http-failure" {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			scope, refresh := "openid", `,"refresh_token":"refresh-new"`
			if f.mode.Load() == "scope-expansion" {
				scope = "openid admin"
			}
			if f.mode.Load() == "omit-refresh" {
				refresh = ""
			}
			expiry := `,"expires_in":100000000`
			if f.mode.Load() == "unknown-expiry" {
				expiry = ""
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"access-new","token_type":"Bearer","scope":"`+scope+`"`+expiry+refresh+`}`)
			return
		}
		if r.URL.Path == "/identity" {
			f.identityCalls.Add(1)
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer access-new" {
				t.Error("identity lookup did not use the new access token")
			}
			if f.mode.Load() == "identity-failure" {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if f.mode.Load() == "revoke-at-identity" {
				if _, err := storage.Execute(f.ctx, f.s.db, rhiza.ExecuteRequest{RequestID: "refresh-revoke-at-identity", SQL: `UPDATE saas_connection_credentials SET state='revoked',refresh_claim=NULL WHERE connection_id=?`, Args: []any{f.b.ConnectionID}}); err != nil {
					t.Errorf("revoke at identity: %v", err)
				}
			}
			account := "account-1"
			if f.mode.Load() == "identity-mismatch" {
				account = "account-2"
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"sub":"`+account+`"}`)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(f.server.Close)
	f.ctx, f.s, _, f.b = credentialStoreFixture(t)
	if err := f.s.Install(f.ctx, f.b, credential{AccountID: account, AccessToken: "access-old", RefreshToken: "refresh-old", ExpiresAtUnixMS: f.s.now() + 3600000, RefreshExpiresAtUnixMS: f.s.now() + 86400000, Scopes: []string{"openid", "profile"}}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	var err error
	f.p, err = NewProviderStore(f.s.db, f.s.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.p.Create(f.ctx, ProviderInput{ID: "provider", Name: "Provider", Kind: "oauth2", Enabled: true, ClientID: "client", ClientSecret: "secret", CallbackURI: "https://auth.example/callback", AuthorizationURL: f.server.URL + "/authorize", TokenURL: f.server.URL + "/token", Scopes: []string{"openid", "profile"}, AuthStyle: "header", IdentityEndpoint: f.server.URL + "/identity", SubjectField: "sub"}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	p, guard, err := oauth2Provider(f.ctx, f.p, "provider", "https://auth.example/callback", credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	f.o, err = f.p.LoadOAuth2(f.ctx, p.ID, guard)
	if err != nil {
		t.Fatal(err)
	}
	f.o.client.Transport = f.server.Client().Transport
	f.guard = guard
	return f
}

// Channels hold the provider response after it receives the refresh token. The
// timeout is only a deadlock watchdog, never the ordering mechanism.
func TestRefreshOAuth2InFlightFences(t *testing.T) {
	for _, mode := range []string{"competing-refresh", "canceled-after-send", "provider-revised"} {
		t.Run(mode, func(t *testing.T) {
			f := newRefreshFixture(t, "account-1")
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			request, cancelRequest := context.WithCancel(ctx)
			defer cancelRequest()
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			f.beforeTokenReply = func() {
				close(entered)
				select {
				case <-release:
				case <-ctx.Done():
				}
			}
			type result struct {
				status OAuth2Status
				err    error
			}
			done := make(chan result, 1)
			go func() {
				status, err := f.s.refreshOAuth2(request, f.o, f.b, f.guard)
				done <- result{status, err}
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("provider did not receive the refresh request")
			}
			if _, err := f.s.refreshOAuth2(ctx, f.o, f.b, f.guard); !errors.Is(err, ErrCredentialNotFound) || f.tokenCalls.Load() != 1 {
				t.Fatalf("competing refresh err=%v requests=%d", err, f.tokenCalls.Load())
			}
			if mode == "canceled-after-send" {
				cancelRequest()
			}
			if mode == "provider-revised" {
				if _, err := storage.Execute(ctx, f.s.db, rhiza.ExecuteRequest{RequestID: "refresh-revise-in-flight", SQL: `UPDATE saas_providers SET revision=revision+1 WHERE id=?`, Args: []any{f.b.ProviderID}}); err != nil {
					t.Fatal(err)
				}
			}
			unblock()
			var got result
			select {
			case got = <-done:
			case <-ctx.Done():
				t.Fatal("refresh did not finish")
			}
			wantState, wantVersion := "ready", int64(2)
			if mode == "competing-refresh" {
				if got.err != nil || !got.status.Connected || got.status.Version != 2 || f.identityCalls.Load() != 1 {
					t.Fatalf("winning refresh status=%+v err=%v", got.status, got.err)
				}
			} else {
				wantState, wantVersion = "uncertain", 1
				if !errors.Is(got.err, errRefreshUncertain) || got.status.Connected || got.status.Version != 0 {
					t.Fatalf("in-flight invalidation status=%+v err=%v", got.status, got.err)
				}
			}
			q, err := f.s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state,token_version,refresh_claim FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{f.b.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != wantState || q.Rows[0][1] != wantVersion || q.Rows[0][2] != nil {
				t.Fatalf("final state=%v err=%v", q.Rows, err)
			}
			if _, err := f.s.refreshOAuth2(ctx, f.o, f.b, f.guard); err == nil || f.tokenCalls.Load() != 1 {
				t.Fatalf("old token replay err=%v requests=%d", err, f.tokenCalls.Load())
			}
		})
	}
}

func TestRefreshOAuth2RegisteredTLSSuccessAndFences(t *testing.T) {
	f := newRefreshFixture(t, "account-1")
	t.Cleanup(f.server.Close)
	status, err := f.s.refreshOAuth2(f.ctx, f.o, f.b, f.guard)
	if err != nil || !status.Connected || status.Version != 2 || status.AccountID != "account-1" || f.tokenCalls.Load() != 1 || f.identityCalls.Load() != 1 {
		t.Fatalf("status=%+v err=%v token=%d identity=%d", status, err, f.tokenCalls.Load(), f.identityCalls.Load())
	}
	loaded, err := f.s.Load(f.ctx, credentialBinding{Owner: f.b.Owner, CollectionID: f.b.CollectionID, ConnectionID: f.b.ConnectionID, ProviderID: f.b.ProviderID, Generation: f.b.Generation, TokenVersion: 2}, credentialAuthority())
	if err != nil || loaded.AccessToken != "access-new" || loaded.RefreshToken != "refresh-new" || len(loaded.Scopes) != 1 || loaded.Scopes[0] != "openid" || loaded.RefreshExpiresAtUnixMS != f.s.now()+86400000 {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
}

func TestRefreshOAuth2RetainsOmittedRefreshAndRejectsMissingOrStale(t *testing.T) {
	f := newRefreshFixture(t, "")
	t.Cleanup(f.server.Close)
	if _, err := f.s.refreshOAuth2(f.ctx, f.o, f.b, f.guard); !errors.Is(err, ErrCredentialNotFound) || f.tokenCalls.Load() != 0 {
		t.Fatalf("missing account err=%v calls=%d", err, f.tokenCalls.Load())
	}
	if _, err := f.s.RefreshOAuth2(f.ctx, f.p, f.b.Owner, f.b.CollectionID, f.b.ConnectionID, 2, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) || f.tokenCalls.Load() != 0 {
		t.Fatalf("stale refresh err=%v calls=%d", err, f.tokenCalls.Load())
	}
	f = newRefreshFixture(t, "account-1")
	t.Cleanup(f.server.Close)
	f.mode.Store("omit-refresh")
	status, err := f.s.refreshOAuth2(f.ctx, f.o, f.b, f.guard)
	if err != nil || status.Version != 2 {
		t.Fatalf("omitted refresh status=%+v err=%v", status, err)
	}
	loaded, err := f.s.Load(f.ctx, credentialBinding{Owner: f.b.Owner, CollectionID: f.b.CollectionID, ConnectionID: f.b.ConnectionID, ProviderID: f.b.ProviderID, Generation: f.b.Generation, TokenVersion: 2}, credentialAuthority())
	if err != nil || loaded.RefreshToken != "refresh-old" {
		t.Fatalf("retained refresh=%q err=%v", loaded.RefreshToken, err)
	}
}

func TestRefreshOAuth2ExternalFailuresBecomeUncertainWithoutRetry(t *testing.T) {
	for _, mode := range []string{"scope-expansion", "identity-mismatch", "identity-failure", "http-failure", "revoke-at-identity"} {
		t.Run(mode, func(t *testing.T) {
			f := newRefreshFixture(t, "account-1")
			t.Cleanup(f.server.Close)
			f.mode.Store(mode)
			if _, err := f.s.refreshOAuth2(f.ctx, f.o, f.b, f.guard); !errors.Is(err, errRefreshUncertain) || f.tokenCalls.Load() != 1 {
				t.Fatalf("err=%v token calls=%d", err, f.tokenCalls.Load())
			}
			if _, err := f.s.refreshOAuth2(f.ctx, f.o, f.b, f.guard); err == nil || f.tokenCalls.Load() != 1 {
				t.Fatalf("retry err=%v token calls=%d", err, f.tokenCalls.Load())
			}
			q, err := f.s.db.Query(f.ctx, rhiza.QueryRequest{SQL: `SELECT token_version,state FROM saas_connection_credentials`, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(q.Rows) != 1 || q.Rows[0][0] != int64(1) {
				t.Fatalf("credential row err=%v", err)
			}
			if mode == "revoke-at-identity" && q.Rows[0][1] != "revoked" || mode != "revoke-at-identity" && q.Rows[0][1] != "uncertain" {
				t.Fatalf("state=%v", q.Rows[0][1])
			}
		})
	}
}

func TestRefreshOAuth2UnknownExpiryCannotBeDelivered(t *testing.T) {
	f := newRefreshFixture(t, "account-1")
	f.mode.Store("unknown-expiry")
	if _, err := f.s.refreshOAuth2(f.ctx, f.o, f.b, f.guard); err != nil {
		t.Fatal(err)
	}
	next := f.b
	next.TokenVersion++
	value, err := f.s.Load(f.ctx, next, credentialAuthority())
	if err != nil || value.ExpiresAtUnixMS != 0 {
		t.Fatal("unknown expiry was invented")
	}
	const resource = "https://consumer.example/resource"
	consumer, err := clients.NewStore(f.s.db, f.s.keys).CreateWithGuard(f.ctx, clients.NewRequest{ID: "refresh-consumer", Confidential: true, RedirectURIs: []string{"https://consumer.example/cb"}, Scopes: []string{"goauthy.connections.use"}, DefaultScopes: []string{"goauthy.connections.use"}, GrantTypes: []string{"authorization_code"}, Audiences: []string{resource}}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.s.CreateUseGrant(f.ctx, f.b.Owner, f.b.CollectionID, f.b.ConnectionID, resource, UseGrantInput{ConsumerClientID: consumer.ID, Mode: "credential_delivery", Purpose: "unknown expiry", ExpiresAt: f.s.now() + 60000}, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.s.DeliverOAuth2(f.ctx, f.b.Owner, consumer.ID, grant.ID, resource, credentialAuthority())
	if err == nil || got.AccessToken != "" || f.tokenCalls.Load() != 1 || f.identityCalls.Load() != 1 {
		t.Fatal("unknown expiry exported or retried")
	}
}
