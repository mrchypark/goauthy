package oauth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/device"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
)

func TestDeviceMFAApprovalIssuanceAndRefresh(t *testing.T) {
	for _, confidential := range []bool{false, true} {
		for _, mfa := range []bool{false, true} {
			name := map[bool]string{false: "public", true: "confidential"}[confidential] + "/" + map[bool]string{false: "password", true: "mfa"}[mfa]
			t.Run(name, func(t *testing.T) {
				t.Parallel()
				db := oauthTestDB(t)
				server := oauthTestServer(t, db, randomSecret(t))
				server.store.managedClients = clients.NewStore(db, nil)
				const id, generation, subject = "device-mfa", "generation-1", "device-mfa-user"
				seedManagedDeviceClient(t, db, id, generation, 1, confidential, "secret")
				seedDeviceUser(t, db, subject, nil)
				store := device.NewStore(db)
				setPolicy := func(required bool) {
					t.Helper()
					_, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("mfa-policy/%x", randomSecret(t)[:8]), SQL: `UPDATE managed_oauth_clients SET force_mfa=?,revision=revision+1 WHERE id=?`, Args: []any{required, id}})
					if err != nil {
						t.Fatal(err)
					}
				}
				create := func() device.Grant {
					t.Helper()
					c, err := server.store.GetClient(t.Context(), id)
					if err != nil {
						t.Fatal(err)
					}
					client := c.(*clients.Client)
					g, err := store.CreateWithBinding(t.Context(), id, []string{"goauthy.read", "offline_access"}, device.ClientBinding{ID: id, Generation: generation, Revision: client.Revision}, time.Now())
					if err != nil {
						t.Fatal(err)
					}
					return g
				}
				post := func(form url.Values) *httptest.ResponseRecorder {
					form.Set("client_id", id)
					r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
					r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
					if confidential {
						r.SetBasicAuth(id, "secret")
					}
					w := httptest.NewRecorder()
					server.TokenHandler().ServeHTTP(w, r)
					return w
				}
				// A normal required-MFA approval must fail for a password session, while
				// an authenticated MFA session retains working Device and refresh support.
				setPolicy(true)
				first := create()
				err := store.ApproveWithMFA(t.Context(), first.UserCode, subject, mfa, time.Now())
				if !mfa {
					if err == nil {
						t.Fatal("password approval bypassed MFA")
					}
					assertNoDeviceTokenArtifacts(t, db)
				} else {
					if err != nil {
						t.Fatal(err)
					}
					issued := decodeToken(t, post(url.Values{"grant_type": {DeviceGrantType}, "device_code": {first.DeviceCode}}))
					if w := post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}}); w.Code != http.StatusOK {
						t.Fatalf("MFA refresh rejected: %s", w.Body.String())
					}
				}
				// Tightening policy while an already-approved device waits for polling
				// must be enforced using persisted evidence, not just the approval check.
				setPolicy(false)
				pending := create()
				if err := store.ApproveWithMFA(t.Context(), pending.UserCode, subject, mfa, time.Now()); err != nil {
					t.Fatal(err)
				}
				setPolicy(true)
				w := post(url.Values{"grant_type": {DeviceGrantType}, "device_code": {pending.DeviceCode}})
				if mfa {
					decodeToken(t, w)
				} else {
					if w.Code != http.StatusBadRequest || oauthErrorCode(t, w) != "invalid_grant" {
						t.Fatalf("pending MFA policy bypass: %d %s", w.Code, w.Body.String())
					}
					assertNoDeviceTokenArtifacts(t, db)
				}
				// The same policy applies to previously issued Device refresh tokens.
				setPolicy(false)
				old := create()
				if err := store.ApproveWithMFA(t.Context(), old.UserCode, subject, mfa, time.Now()); err != nil {
					t.Fatal(err)
				}
				issued := decodeToken(t, post(url.Values{"grant_type": {DeviceGrantType}, "device_code": {old.DeviceCode}}))

				if !mfa {
					strategy := server.accessTokens.(oauth2.RefreshTokenStrategy)
					signature := strategy.RefreshTokenSignature(t.Context(), issued.RefreshToken)
					request, err := server.store.GetRefreshTokenSession(t.Context(), signature, &fosite.DefaultSession{})
					if err != nil {
						t.Fatal(err)
					}
					ctx, err := server.store.BeginTX(t.Context())
					if err != nil {
						t.Fatal(err)
					}
					if err = server.store.RotateRefreshToken(ctx, request.GetID(), signature); err != nil {
						t.Fatal(err)
					}
					if err = server.store.CreateAccessTokenSession(ctx, "queued-mfa-access", request); err != nil {
						t.Fatal(err)
					}
					if err = server.store.CreateRefreshTokenSession(ctx, "queued-mfa-refresh", "queued-mfa-access", request); err != nil {
						t.Fatal(err)
					}
					accessSignature := server.accessTokens.AccessTokenSignature(t.Context(), issued.AccessToken)
					exchangeCtx, err := server.store.BeginTokenExchangeTX(t.Context(), accessSignature, request.GetSession().GetExpiresAt(fosite.AccessToken))
					if err != nil {
						t.Fatal(err)
					}
					if err = server.store.CreateAccessTokenSession(exchangeCtx, "queued-mfa-exchange", exchangeRequest(server.store, "queued-mfa-exchange")); err != nil {
						t.Fatal(err)
					}
					// No revision change: prove the MFA fence itself after all
					// rotation/issuance statements have already been queued.
					_, err = storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "mfa-before-refresh-commit", SQL: `UPDATE managed_oauth_clients SET force_mfa=1 WHERE id=?`, Args: []any{id}})
					if err != nil {
						t.Fatal(err)
					}
					if err = server.store.Commit(exchangeCtx); err == nil {
						t.Fatal("Device token exchange bypassed tightened MFA")
					}
					assertManagedExchangeInputNoArtifacts(t, db, "queued-mfa-exchange")
					if err = server.store.Commit(ctx); err == nil {
						t.Fatal("queued password refresh committed after MFA change")
					}
					rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT (SELECT count(*) FROM oauth_access_tokens WHERE signature='queued-mfa-access'), (SELECT count(*) FROM oauth_refresh_tokens WHERE signature='queued-mfa-refresh'), (SELECT active FROM oauth_refresh_tokens WHERE signature=?)`, Args: []any{signature}, Consistency: rhiza.ConsistencyLinearizable})
					if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != int64(0) || rows.Rows[0][1] != int64(0) || rows.Rows[0][2] != int64(1) {
						t.Fatalf("denied refresh changed artifacts: %v err=%v", rows.Rows, err)
					}
				}
				setPolicy(true)
				w = post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {issued.RefreshToken}})
				if mfa {
					if w.Code != http.StatusOK {
						t.Fatalf("verified MFA refresh rejected: %s", w.Body.String())
					}
				} else if w.Code == http.StatusOK || strings.Contains(w.Body.String(), `"access_token"`) {
					t.Fatalf("password refresh bypassed current MFA: %s", w.Body.String())
				}
			})
		}
	}
}

func TestDeviceMFAChangedAfterClaimCannotCommit(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	server.store.managedClients = clients.NewStore(db, nil)
	seedManagedDeviceClient(t, db, "device-mfa-commit", "generation-1", 1, false, "")
	seedDeviceUser(t, db, "device-mfa-user", nil)
	store := device.NewStore(db)
	grant, err := store.CreateWithBinding(t.Context(), "device-mfa-commit", []string{"goauthy.read", "offline_access"}, device.ClientBinding{ID: "device-mfa-commit", Generation: "generation-1", Revision: 1}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Approve(t.Context(), grant.UserCode, "device-mfa-user", time.Now()); err != nil {
		t.Fatal(err)
	}
	client, err := server.store.GetClient(t.Context(), "device-mfa-commit")
	if err != nil {
		t.Fatal(err)
	}
	request := fosite.NewAccessRequest(&fosite.DefaultSession{})
	request.Client = client
	request.GrantTypes = fosite.Arguments{DeviceGrantType}
	request.Form = url.Values{"device_code": {grant.DeviceCode}}
	handler := deviceGrantTokenHandler(t, server)
	if err = handler.HandleTokenEndpointRequest(t.Context(), request); err != nil {
		t.Fatal(err)
	}
	// Deliberately retain revision: this specifically proves the final MFA
	// predicate, independently of the normal managed revision fence.
	_, err = storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "mfa-after-claim", SQL: `UPDATE managed_oauth_clients SET force_mfa=1 WHERE id='device-mfa-commit'`})
	if err != nil {
		t.Fatal(err)
	}
	if err = handler.PopulateTokenEndpointResponse(t.Context(), request, fosite.NewAccessResponse()); err == nil {
		t.Fatal("stale password approval committed")
	}
	assertNoDeviceTokenArtifacts(t, db)
}

func TestManagedDeviceRevisionChangeCannotConsumeWithoutTokens(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	server.store.managedClients = clients.NewStore(db, nil)
	const id = "device-revision"
	seedManagedDeviceClient(t, db, id, "g1", 1, false, "")
	seedDeviceUser(t, db, "device-revision-user", nil)
	store := device.NewStore(db)
	g, err := store.CreateWithBinding(t.Context(), id, []string{"goauthy.read", "offline_access"}, device.ClientBinding{ID: id, Generation: "g1", Revision: 1}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Approve(t.Context(), g.UserCode, "device-revision-user", time.Now()); err != nil {
		t.Fatal(err)
	}
	server.beforeTokenIssue = func() {
		server.beforeTokenIssue = nil
		_, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "device-revision-change", SQL: `UPDATE managed_oauth_clients SET revision=revision+1 WHERE id=?`, Args: []any{id}})
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{"client_id": {id}, "grant_type": {DeviceGrantType}, "device_code": {g.DeviceCode}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(w, r)
	if w.Code == http.StatusOK || strings.Contains(w.Body.String(), `"access_token"`) {
		t.Fatalf("returned unpersisted tokens: %d %s", w.Code, w.Body.String())
	}
	assertNoDeviceTokenArtifacts(t, db)
	rows, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT state FROM oauth_device_grants WHERE client_id=?`, Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(rows.Rows) != 1 || rows.Rows[0][0] != "approved" {
		t.Fatalf("grant consumed despite failed inserts: %v err=%v", rows.Rows, err)
	}
}
