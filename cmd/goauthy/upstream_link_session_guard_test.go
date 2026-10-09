package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/account"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

const externalLinkTestPeer = "192.0.2.44"

type gatedExternalLinkExchanger struct {
	entered chan struct{}
	release chan struct{}
}

func (e *gatedExternalLinkExchanger) ExchangeCode(ctx context.Context, _, _, _, _ string) (*upstreamprovider.TokenExchangeResult, error) {
	close(e.entered)
	select {
	case <-e.release:
		return &upstreamprovider.TokenExchangeResult{Subject: &upstreamprovider.SubjectResult{ProviderID: "google", Subject: "external-user"}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestExternalLinkRejectsSessionRevokedDuringExchange(t *testing.T) {
	for _, tc := range []struct {
		name               string
		revoke             bool
		changePeer         bool
		preexistingSubject string
		wantStatus         int
	}{
		{name: "revoked-during-exchange", revoke: true, wantStatus: http.StatusBadRequest},
		{name: "peer-changed-during-exchange", changePeer: true, wantStatus: http.StatusBadRequest},
		{name: "current-session", wantStatus: http.StatusNoContent},
		{name: "current-session-idempotent", preexistingSubject: "local-user", wantStatus: http.StatusNoContent},
		{name: "revoked-session-existing-map-is-not-success", revoke: true, preexistingSubject: "local-user", wantStatus: http.StatusBadRequest},
		{name: "different-owner-conflict", preexistingSubject: "other-user", wantStatus: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			db := coexistTestDB(t)
			browserStore, err := browser.NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			identityStore, err := identity.NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			passwordPHC, err := credential.Hash([]byte("CorrectPassword1"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := identityStore.BootstrapUser(ctx, "local-user", "local-user", passwordPHC); err != nil {
				t.Fatal(err)
			}
			if tc.preexistingSubject == "other-user" {
				if _, err := identityStore.BootstrapUser(ctx, "other-user", "other-user", passwordPHC); err != nil {
					t.Fatal(err)
				}
			}
			external := upstreamprovider.SubjectResult{ProviderID: "google", Subject: "external-user"}
			if tc.preexistingSubject != "" {
				if _, err := identityStore.LinkExternal(ctx, tc.preexistingSubject, external, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			accountHandler, err := account.New("https://goauthy.test", browserStore, identityStore, credential.DefaultRules())
			if err != nil {
				t.Fatal(err)
			}
			session, err := browserStore.CreateSession(ctx, "local-user", "pwd", time.Now().Add(time.Hour), externalLinkTestPeer)
			if err != nil {
				t.Fatal(err)
			}
			sessionCookie, err := browser.SessionCookie("https://goauthy.test", session.Token, session.ExpiresAt)
			if err != nil {
				t.Fatal(err)
			}

			exchanger := &gatedExternalLinkExchanger{entered: make(chan struct{}), release: make(chan struct{})}
			var releaseOnce sync.Once
			t.Cleanup(func() {
				releaseOnce.Do(func() { close(exchanger.release) })
			})
			transactionStore, err := upstreamprovider.NewRhizaStore(db, providerRegistryTestKeyring(t))
			if err != nil {
				t.Fatal(err)
			}
			config := upstreamprovider.Config{
				Kind: upstreamprovider.ProviderKindOIDC, Issuer: "https://google.example.test",
				AuthorizationEndpoint: "https://google.example.test/authorize",
				TokenEndpoint:         "https://google.example.test/token", JWKSURI: "https://google.example.test/jwks",
				ClientID: "link-test", Scopes: []string{"openid"},
			}
			localHooks := upstreamprovider.LocalLoginHooks{
				Prepare:  func(*http.Request, string) (string, string, string, error) { return "", "", "", nil },
				Current:  func(*http.Request) (string, string, error) { return "", "", nil },
				Resolve:  func(context.Context, upstreamprovider.SubjectResult) (string, error) { return "", nil },
				Complete: func(http.ResponseWriter, *http.Request, string, string, string, *upstreamprovider.OIDCSession) {},
			}
			var linkDecision upstreamprovider.LinkDecision
			var linkErr error
			linkHooks := upstreamprovider.LinkHooks{
				Current: accountHandler.CurrentExternalLinkSession,
				Link: func(ctx context.Context, proof upstreamprovider.LinkSession, external upstreamprovider.SubjectResult, now time.Time) (upstreamprovider.LinkDecision, error) {
					linkDecision, linkErr = accountHandler.LinkExternalWithSession(ctx, proof, external, now)
					return linkDecision, linkErr
				},
			}
			handler, err := upstreamprovider.NewLocalLoginAndLinkHandler(
				map[string]upstreamprovider.Config{"google": config}, transactionStore, exchanger, stubVerifier{}, nil,
				map[string]bool{"https://goauthy.test/upstream/google/callback": true}, localHooks,
				map[string]string{"google": "https://goauthy.test/upstream/google/callback"}, linkHooks,
			)
			if err != nil {
				t.Fatal(err)
			}

			start := httptest.NewRequest(http.MethodPost, "/upstream/google/link", nil)
			start = start.WithContext(browser.ContextWithPeerIP(start.Context(), externalLinkTestPeer))
			start.AddCookie(sessionCookie)
			started := httptest.NewRecorder()
			handler.LinkStartHandler().ServeHTTP(started, start)
			if started.Code != http.StatusOK {
				t.Fatalf("link start status=%d", started.Code)
			}
			var startBody struct {
				AuthorizationURL string `json:"authorization_url"`
			}
			if err := json.Unmarshal(started.Body.Bytes(), &startBody); err != nil {
				t.Fatal(err)
			}
			u, err := url.Parse(startBody.AuthorizationURL)
			if err != nil {
				t.Fatal(err)
			}
			state := u.Query().Get("state")
			if state == "" {
				t.Fatal("link start returned no state")
			}
			var stateCookie *http.Cookie
			for _, cookie := range started.Result().Cookies() {
				if cookie.Name == "__Host-goauthy_upstream_state" {
					stateCookie = cookie
				}
			}
			if stateCookie == nil {
				t.Fatal("link start returned no state cookie")
			}

			callback := httptest.NewRequest(http.MethodGet, "/upstream/google/callback?state="+url.QueryEscape(state)+"&code=exchange-code", nil)
			callback = callback.WithContext(browser.ContextWithPeerIP(callback.Context(), externalLinkTestPeer))
			callback.AddCookie(stateCookie)
			callback.AddCookie(sessionCookie)
			completed := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				response := httptest.NewRecorder()
				handler.LinkCallbackHandler().ServeHTTP(response, callback)
				completed <- response
			}()
			select {
			case <-exchanger.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("callback did not reach the gated token exchanger")
			}
			if tc.revoke {
				if err := browserStore.RevokeSession(ctx, session.Token); err != nil {
					t.Fatal(err)
				}
			}
			if tc.changePeer {
				if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{
					RequestID: "external-link-session-peer-change",
					SQL:       `UPDATE browser_sessions SET peer_ip=? WHERE token_digest=?`,
					Args:      []any{"192.0.2.99", session.ID},
				}); err != nil {
					t.Fatal(err)
				}
			}
			releaseOnce.Do(func() { close(exchanger.release) })
			select {
			case response := <-completed:
				linkedSubject, found, err := identityStore.FindExternalLink(ctx, external)
				if err != nil {
					t.Fatal(err)
				}
				if response.Code != tc.wantStatus {
					t.Fatalf("link status=%d want=%d found=%v subject=%q", response.Code, tc.wantStatus, found, linkedSubject)
				}
				if tc.revoke || tc.changePeer {
					if linkDecision != upstreamprovider.LinkDecisionNone || linkErr == nil {
						t.Fatalf("unauthorized proof decision=%v err=%v", linkDecision, linkErr)
					}
				} else if tc.preexistingSubject == "other-user" {
					if linkDecision != upstreamprovider.LinkDecisionConflict || !errors.Is(linkErr, identity.ErrExternalLinkConflict) {
						t.Fatalf("conflict decision=%v err=%v", linkDecision, linkErr)
					}
				} else if linkDecision != upstreamprovider.LinkDecisionLinked || linkErr != nil {
					t.Fatalf("authorized proof decision=%v err=%v", linkDecision, linkErr)
				}
				if tc.preexistingSubject == "" && (tc.revoke || tc.changePeer) {
					if found {
						t.Fatalf("unauthorized session created a link: subject=%q", linkedSubject)
					}
				} else {
					wantSubject := tc.preexistingSubject
					if wantSubject == "" {
						wantSubject = "local-user"
					}
					if !found || linkedSubject != wantSubject {
						t.Fatalf("link mapping found=%v subject=%q want=%q", found, linkedSubject, wantSubject)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("callback did not finish after exchanger release")
			}
		})
	}
}
