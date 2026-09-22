package login

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
)

// Only the external IdP is a fixture: local transaction persistence, token
// exchange, JWT verification, identity lookup and session completion are real.
func TestApprovalUpstreamRoundTrip(t *testing.T) {
	t.Parallel()
	for _, destination := range []string{"device", "handoff"} {
		for _, proof := range []string{"valid", "wrong-nonce", "missing-mfa", "reauth-valid", "reauth-stale", "reauth-missing", "reauth-future"} {
			t.Run(destination+"/"+proof, func(t *testing.T) {
				h, db := testHandlerWithDB(t, false)
				h.SetApprovalForceMFA(true)
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "fixture"))
				if err != nil {
					t.Fatal(err)
				}
				var nonce, challenge atomic.Value
				nonce.Store("")
				challenge.Store("")
				var exchanges atomic.Int32
				var issuer string
				callback := "https://localhost/upstream/fixture/callback"
				provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch r.URL.Path {
					case "/jwks":
						_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "fixture", Algorithm: "ES256", Use: "sig"}}})
					case "/token":
						exchanges.Add(1)
						if err := r.ParseForm(); err != nil {
							http.Error(w, "form", 400)
							return
						}
						id, secret, ok := r.BasicAuth()
						digest := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
						if !ok || id != "local-client" || secret != "fixture-secret" || r.Form.Get("code") != "fixture-code" || r.Form.Get("redirect_uri") != callback || base64.RawURLEncoding.EncodeToString(digest[:]) != challenge.Load().(string) {
							http.Error(w, "invalid exchange", 400)
							return
						}
						n := nonce.Load().(string)
						if proof == "wrong-nonce" {
							n = "wrong"
						}
						claimValues := map[string]any{"iss": issuer, "aud": "local-client", "sub": "external-owner", "sid": "external-session", "nonce": n, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "mfa": proof != "missing-mfa"}
						if strings.HasPrefix(proof, "reauth-") && proof != "reauth-missing" {
							at := time.Now().Unix()
							if proof == "reauth-stale" {
								at -= 3600
							}
							if proof == "reauth-future" {
								at += 3600
							}
							claimValues["auth_time"] = at
						}
						claims, _ := json.Marshal(claimValues)
						token, err := signer.Sign(claims)
						if err != nil {
							http.Error(w, "sign", 500)
							return
						}
						raw, err := token.CompactSerialize()
						if err != nil {
							http.Error(w, "serialize", 500)
							return
						}
						_ = json.NewEncoder(w).Encode(map[string]string{"id_token": raw, "access_token": "fixture-access", "token_type": "Bearer"})
					default:
						http.NotFound(w, r)
					}
				}))
				defer provider.Close()
				issuer = provider.URL
				claimPath, claimValue := "$.mfa", "true"
				configs := map[string]upstreamprovider.Config{"fixture": {Issuer: issuer, AuthorizationEndpoint: issuer + "/authorize", TokenEndpoint: issuer + "/token", JWKSURI: issuer + "/jwks", ClientID: "local-client", Scopes: []string{"openid"}, MFAClaimPath: &claimPath, MFAClaimValue: &claimValue}}
				store, err := upstreamprovider.NewRhizaStore(db, testOIDCKeyring(t))
				if err != nil {
					t.Fatal(err)
				}
				exchanger, err := upstreamprovider.NewOAuth2TokenExchanger(configs, map[string]string{"fixture": "fixture-secret"}, provider.Client())
				if err != nil {
					t.Fatal(err)
				}
				verifier, err := upstreamprovider.NewJWKSVerifier(configs, provider.Client())
				if err != nil {
					t.Fatal(err)
				}
				external := upstreamprovider.SubjectResult{ProviderID: "fixture", Subject: "external-owner"}
				if _, err := h.identity.LinkExternal(context.Background(), "user-1", external, time.Now()); err != nil {
					t.Fatal(err)
				}
				upstream, err := upstreamprovider.NewLocalLoginHandler(configs, store, exchanger, verifier, nil, map[string]bool{callback: true}, upstreamprovider.LocalLoginHooks{
					Prepare: h.PrepareExternalAuthentication, RequireFreshAuthentication: h.RequireFreshExternalAuthentication, Current: h.CurrentExternalInitSession,
					Resolve: func(ctx context.Context, s upstreamprovider.SubjectResult) (string, error) {
						subject, found, err := h.identity.FindExternalLink(ctx, s)
						if err != nil || !found {
							return "", fmt.Errorf("missing link: %w", err)
						}
						return subject, nil
					},
					Complete: func(w http.ResponseWriter, r *http.Request, token, interaction, subject string, s *upstreamprovider.OIDCSession) {
						if s == nil {
							t.Error("missing OIDC provenance")
							http.Error(w, "missing provenance", 500)
							return
						}
						h.CompleteUpstreamAuthentication(w, r, token, interaction, subject, &browser.UpstreamSessionBinding{Issuer: s.Issuer, ClientID: s.ClientID, Subject: s.Subject, SessionID: s.SessionID, MFAPassed: s.MFAPassed, AuthenticationTime: s.AuthenticationTime})
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				code := "AB12CD34"
				saved := approvalLoginInteraction{Purpose: approvalLoginPayload, HandoffID: testHandoffID}
				want := h.issuer + "/account/connection-handoffs/" + testHandoffID
				if destination == "device" {
					saved.HandoffID = ""
					saved.DeviceCode = &code
					want = h.issuer + "/oidc/device/verify?user_code=" + code
				}
				cookie, interaction := approvalInteraction(t, h, saved)
				var parentToken string
				if strings.HasPrefix(proof, "reauth-") {
					entry := httptest.NewRequest(http.MethodGet, "/account/connection-login?handoff_id="+testHandoffID, nil)
					peer, _ := h.resolvePeerIP(entry)
					parent, err := h.browser.CreateSession(context.Background(), "user-1", "pwd", h.now().Add(time.Hour), peer)
					if err != nil {
						t.Fatal(err)
					}
					parentToken = parent.Token
					parentCookie, err := browser.SessionCookie(h.issuer, parent.Token, parent.ExpiresAt)
					if err != nil {
						t.Fatal(err)
					}
					entry.AddCookie(parentCookie)
					page := httptest.NewRecorder()
					if destination == "device" {
						h.DeviceReviewReauthentication(page, entry, code)
					} else {
						h.ConnectionHandoffLoginHandler(true).ServeHTTP(page, entry)
					}
					if page.Code != http.StatusOK || len(page.Result().Cookies()) != 1 {
						t.Fatalf("reauth entry=%d %s", page.Code, page.Body.String())
					}
					cookie = page.Result().Cookies()[0]
					interaction = interactionToken(t, page.Body.String())
				}
				request := httptest.NewRequest(http.MethodGet, "/upstream/fixture/start?"+url.Values{"redirect_uri": {callback}, "interaction": {interaction}}.Encode(), nil)
				request.AddCookie(cookie)
				start := httptest.NewRecorder()
				upstream.LocalStartHandler().ServeHTTP(start, request)
				if start.Code != http.StatusFound {
					t.Fatalf("start=%d %s", start.Code, start.Body.String())
				}
				authURL, err := url.Parse(start.Header().Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				if strings.HasPrefix(proof, "reauth-") {
					if authURL.Query().Get("prompt") != "login" || authURL.Query().Get("max_age") != "0" {
						t.Fatal("reauthentication did not request fresh provider authentication")
					}
				} else if authURL.Query().Has("max_age") || authURL.Query().Has("prompt") {
					t.Fatal("ordinary SSO unexpectedly forced reauthentication")
				}
				nonce.Store(authURL.Query().Get("nonce"))
				challenge.Store(authURL.Query().Get("code_challenge"))
				if nonce.Load() == "" || challenge.Load() == "" {
					t.Fatal("missing nonce/PKCE")
				}
				finish := func(sessionCookie *http.Cookie) *httptest.ResponseRecorder {
					r := httptest.NewRequest(http.MethodGet, callback+"?"+url.Values{"state": {authURL.Query().Get("state")}, "code": {"fixture-code"}}.Encode(), nil)
					r.AddCookie(sessionCookie)
					for _, c := range start.Result().Cookies() {
						r.AddCookie(c)
					}
					w := httptest.NewRecorder()
					upstream.LocalCallbackHandler().ServeHTTP(w, r)
					return w
				}
				otherCookie, _ := approvalInteraction(t, h, saved)
				wrongBrowser := finish(otherCookie)
				if wrongBrowser.Code < 400 || exchanges.Load() != 0 {
					t.Fatalf("foreign browser callback=%d exchanges=%d", wrongBrowser.Code, exchanges.Load())
				}
				result := finish(cookie)
				if proof == "valid" || proof == "reauth-valid" {
					if result.Code != http.StatusSeeOther || result.Header().Get("Location") != want {
						t.Fatalf("callback=%d location=%q body=%s", result.Code, result.Header().Get("Location"), result.Body.String())
					}
					authenticated := false
					for _, c := range result.Result().Cookies() {
						s, err := h.browser.LoadSession(context.Background(), c.Value)
						if err == nil && s.Authenticated() {
							authenticated = true
							if s.Subject != "user-1" || s.AuthenticationMethod != "mfa" {
								t.Fatalf("session=%+v", s)
							}
						}
					}
					if !authenticated {
						t.Fatal("missing MFA session")
					}
				} else if result.Code < 400 || result.Header().Get("Location") != "" {
					t.Fatalf("invalid proof accepted: %d", result.Code)
				}
				if parentToken != "" {
					_, err := h.browser.LoadSession(context.Background(), parentToken)
					if (proof == "reauth-valid") != (err != nil) {
						t.Fatalf("parent retirement proof=%s err=%v", proof, err)
					}
				}
				replay := finish(cookie)
				if replay.Code < 400 || exchanges.Load() != 1 {
					t.Fatalf("replay=%d exchanges=%d", replay.Code, exchanges.Load())
				}
			})
		}
	}
}
