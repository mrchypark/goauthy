package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

const (
	managedMFAClientID    = "managed-force-mfa"
	managedMFARedirectURI = "https://rp.example.test/callback"
)

// TestManagedForceMFAPolicyUsesAuthorizationSnapshot covers finding GA-OAUTH-002.
// The MFA policy must be derived from the concrete client snapshot Fosite used
// for the authorization request, so failing the separate managed-client policy
// lookup cannot downgrade a force-MFA client to "MFA not required", and final
// issuance must refuse a password-only session for a force-MFA client revision.
func TestManagedForceMFAPolicyUsesAuthorizationSnapshot(t *testing.T) {
	for _, lookup := range []struct {
		name        string
		unavailable func(*testing.T, *Server)
	}{
		{"policy store unavailable", func(_ *testing.T, s *Server) { s.store.managedClients = nil }},
		{"policy lookup empty", func(t *testing.T, s *Server) { s.store.managedClients = clients.NewStore(oauthTestDB(t), nil) }},
	} {
		for _, tc := range []struct {
			name       string
			forceMFA   bool
			authMethod string
			wantCode   bool
		}{
			{name: "force mfa with password session", forceMFA: true, authMethod: oidcAuthMethodPwd},
			{name: "force mfa with mfa session", forceMFA: true, authMethod: oidcAuthMethodMFA, wantCode: true},
			{name: "unforced with password session", forceMFA: false, authMethod: oidcAuthMethodPwd, wantCode: true},
		} {
			t.Run(lookup.name+"/"+tc.name, func(t *testing.T) {
				server, ctx, db := managedMFAAuthorizationServer(t, tc.forceMFA, lookup.unavailable)
				values := managedMFAAuthorizeValues()
				sessionID := oidcTestSessionID(0x5f)
				ensureOIDCTestBrowserSession(t, server, sessionID)
				response := httptest.NewRecorder()
				server.CompleteAuthorizationWithSession(response, authorizeRequestWithContext(ctx, values), "user-1", []string{"goauthy.read", "offline_access"}, time.Unix(1_700_000_000, 0).UTC(), sessionID, tc.authMethod)
				location, err := url.Parse(response.Header().Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				if issued := location.Query().Get("code") != ""; issued != tc.wantCode {
					t.Fatalf("code issued=%t want %t status=%d location=%q", issued, tc.wantCode, response.Code, response.Header().Get("Location"))
				}
				if !tc.wantCode {
					if location.Query().Get("error") != "access_denied" {
						t.Fatalf("denial error=%q want access_denied", location.Query().Get("error"))
					}
					assertNoAuthorizationState(t, db)
				}
				// The same snapshot must still report the policy to the login layer.
				view, err := server.ValidateAuthorizationRequest(authorizeRequestWithContext(ctx, values))
				if err != nil || view.ForceMFA != tc.forceMFA {
					t.Fatalf("view force_mfa=%t want %t err=%v", view.ForceMFA, tc.forceMFA, err)
				}
			})
		}
	}
}

// managedMFAAuthorizationServer seeds one managed public client, resolves its
// authorization snapshot, then makes the separate MFA-policy lookup fail while
// every other read keeps succeeding.
func managedMFAAuthorizationServer(t *testing.T, forceMFA bool, unavailable func(*testing.T, *Server)) (*Server, context.Context, *rhiza.DB) {
	t.Helper()
	db := oauthTestDB(t)
	seedOAuthUser(t, db, "user-1")
	server := oidcTestServer(t, db, randomSecret(t), func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil })
	server.store.managedClients = clients.NewStore(db, nil)
	metadata, err := json.Marshal(map[string]any{
		"id": managedMFAClientID, "confidential": false, "redirect_uris": []string{managedMFARedirectURI},
		"scopes": []string{"goauthy.read", "offline_access"}, "default_scopes": []string{"goauthy.read"}, "enabled_flows": []string{"authorization_code"},
	})
	if err != nil {
		t.Fatal(err)
	}
	policy := int64(0)
	if forceMFA {
		policy = 1
	}
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{
		RequestID: "seed-managed-force-mfa",
		SQL:       "INSERT INTO managed_oauth_clients(id,generation,revision,enabled,deleted,metadata_json,secret_hash,force_mfa) VALUES(?,?,1,1,0,?,NULL,?)",
		Args:      []any{managedMFAClientID, "generation-managed-force-mfa", string(metadata), policy},
	}); err != nil {
		t.Fatal(err)
	}
	// This is the same snapshot Fosite attaches to the authorization request.
	snapshots := make(map[string]fosite.Client)
	ctx := context.WithValue(t.Context(), managedClientSnapshotsKey{}, snapshots)
	if _, err := server.store.GetClient(ctx, managedMFAClientID); err != nil {
		t.Fatal(err)
	}
	unavailable(t, server)
	return server, ctx, db
}

func managedMFAAuthorizeValues() url.Values {
	digest := sha256.Sum256([]byte(strings.Repeat("m", 43)))
	return url.Values{
		"response_type": {"code"}, "client_id": {managedMFAClientID}, "redirect_uri": {managedMFARedirectURI},
		"scope": {"goauthy.read offline_access"}, "state": {strings.Repeat("s", 32)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
}

func authorizeRequestWithContext(ctx context.Context, values url.Values) *http.Request {
	return httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil).WithContext(ctx)
}
