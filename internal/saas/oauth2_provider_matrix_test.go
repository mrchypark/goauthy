package saas

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"

	"golang.org/x/oauth2"
)

// These are synthetic response-shape checks, never requests to live providers.
// Keep expiry out of these fixtures: the existing expiry/refresh tests own that
// boundary. Public documentation supplies shapes, not real tokens or profiles.
func TestOAuth2ProviderMatrixSyntheticLifecycle(t *testing.T) {
	discord := ProviderInput{Name: "Synthetic Discord shape", Kind: "oauth2", Enabled: true,
		ClientID: "synthetic-client", ClientSecret: "synthetic-secret", CallbackURI: "https://auth.example/callback",
		AuthorizationURL: "https://discord.com/oauth2/authorize", TokenURL: "https://discord.com/api/oauth2/token",
		IdentityEndpoint: "https://discord.com/api/v10/users/@me", SubjectField: "id", Scopes: []string{"identify"}, AuthStyle: "header"}
	figma := discord
	figma.Name, figma.AuthorizationURL, figma.TokenURL = "Synthetic Figma shape", "https://www.figma.com/oauth", "https://api.figma.com/v1/oauth/token"
	figma.IdentityEndpoint, figma.Scopes = "https://api.figma.com/v1/me", []string{"current_user:read"}
	spotify := discord
	spotify.Name, spotify.AuthorizationURL, spotify.TokenURL = "Synthetic Spotify shape", "https://accounts.spotify.com/authorize", "https://accounts.spotify.com/api/token"
	spotify.IdentityEndpoint, spotify.SubjectField, spotify.Scopes = "https://api.spotify.com/v1/me", "account_id", []string{"user-read-private"}

	// Discord: docs.discord.com/developers/topics/oauth2 and /resources/user.
	// Figma: developers.figma.com/docs/rest-api/oauth-apps and /users-types.
	// Spotify: developer.spotify.com/documentation/web-api/reference/get-current-users-profile.
	// Array/comma/nested rows deliberately fail the generic contract; they do not
	// certify Twitch, Slack, or Linear as supported provider configurations.
	for _, tc := range []struct {
		name, media, tokenBody, identityBody, account string
		provider                                      ProviderInput
		wantErr                                       error
		identityCalls                                 int32
	}{
		{name: "figma_absent_scope_and_large_string_id", provider: figma, media: "application/json",
			tokenBody:    `{"access_token":"synthetic-access","token_type":"bearer","refresh_token":"synthetic-refresh","user_id_string":"18446744073709551616"}`,
			identityBody: `{"id":"18446744073709551616","handle":"synthetic"}`, account: "18446744073709551616", identityCalls: 1},
		{name: "spotify_immutable_account_id", provider: spotify, media: "application/json",
			tokenBody:    `{"access_token":"synthetic-access","token_type":"Bearer","scope":"user-read-private"}`,
			identityBody: `{"account_id":"synthetic-stable","id":"synthetic-mutable","display_name":null}`, account: "synthetic-stable", identityCalls: 1},
		{name: "generic_array_scope_rejected", provider: discord, media: "application/json",
			tokenBody: `{"access_token":"synthetic-access","token_type":"bearer","scope":["identify"]}`, wantErr: ErrOAuth2Exchange},
		{name: "generic_comma_scope_rejected", provider: discord, media: "application/json",
			tokenBody: `{"access_token":"synthetic-access","token_type":"Bearer","scope":"identify,email"}`, wantErr: ErrOAuth2Exchange},
		{name: "generic_form_absent_scope_rejected", provider: discord, media: "application/x-www-form-urlencoded",
			tokenBody: "access_token=synthetic-access&token_type=bearer", wantErr: ErrOAuth2Exchange},
		{name: "nested_identity_envelope_rejected", provider: discord, media: "application/json",
			tokenBody:    `{"access_token":"synthetic-access","token_type":"Bearer","scope":"identify"}`,
			identityBody: `{"data":{"viewer":{"id":"synthetic-user"}}}`, wantErr: ErrOAuth2Identity, identityCalls: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, credentials, db, binding := credentialStoreFixture(t)
			providers, err := NewProviderStore(db, credentials.keys)
			if err != nil {
				t.Fatal(err)
			}
			input := tc.provider
			input.ID = binding.ProviderID
			if _, err := providers.Create(ctx, input, credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			session := authorizationTestDigest("synthetic-matrix-session")
			start, err := credentials.BeginOAuth2(ctx, providers, binding.Owner, binding.CollectionID, binding.ConnectionID, binding.ProviderID, session, input.CallbackURI, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			authURL, err := url.Parse(start.AuthorizationURL)
			if err != nil {
				t.Fatal(err)
			}
			p, guard, err := oauth2Provider(ctx, providers, binding.ProviderID, input.CallbackURI, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			o, err := providers.LoadOAuth2(ctx, binding.ProviderID, guard)
			if err != nil {
				t.Fatal(err)
			}
			tokenURL, _ := url.Parse(input.TokenURL)
			identityURL, _ := url.Parse(input.IdentityEndpoint)
			var tokens, identities atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case tokenURL.Path:
					tokens.Add(1)
					client, secret, basic := r.BasicAuth()
					if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || !basic || client != input.ClientID || secret != "synthetic-secret" || r.ParseForm() != nil {
						t.Error("invalid synthetic token request")
					}
					if r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("code") != "synthetic-code" || r.Form.Get("redirect_uri") != input.CallbackURI || r.Form.Has("client_secret") || !validVerifier(r.Form.Get("code_verifier")) || authURL.Query().Get("code_challenge") != oauth2.S256ChallengeFromVerifier(r.Form.Get("code_verifier")) {
						t.Error("invalid bound code/PKCE request")
					}
					w.Header().Set("Content-Type", tc.media)
					_, _ = io.WriteString(w, tc.tokenBody)
				case identityURL.Path:
					identities.Add(1)
					if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer synthetic-access" || r.Header.Get("Accept") != "application/json" {
						t.Error("invalid synthetic identity request")
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, tc.identityBody)
				default:
					t.Error("unexpected synthetic endpoint")
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(server.Close)
			o.client.Transport = rewriteTransport{target: server.URL, base: server.Client().Transport}
			state := authURL.Query().Get("state")
			_, err = credentials.completeOAuth2(ctx, o, p, binding.Owner, binding.CollectionID, binding.ConnectionID, session, state, "synthetic-code", guard)
			if !errors.Is(err, tc.wantErr) || tokens.Load() != 1 || identities.Load() != tc.identityCalls {
				t.Fatalf("completion err=%v token calls=%d identity calls=%d", err, tokens.Load(), identities.Load())
			}
			status, err := credentials.OAuth2Status(ctx, binding.Owner, binding.CollectionID, binding.ConnectionID, guard)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != nil {
				if status.Connected || status.State != "draft" || status.Version != 0 {
					t.Fatal("unsupported response installed a credential")
				}
			} else {
				value, err := credentials.Load(ctx, binding, guard)
				if err != nil || !status.Connected || status.Version != 1 || status.AccountID != tc.account || value.AccountID != tc.account || !reflect.DeepEqual(status.Scopes, input.Scopes) || !reflect.DeepEqual(value.Scopes, input.Scopes) {
					t.Fatal("synthetic identity/scope roundtrip failed")
				}
			}
			if _, err := credentials.completeOAuth2(ctx, o, p, binding.Owner, binding.CollectionID, binding.ConnectionID, session, state, "synthetic-code", guard); !errors.Is(err, ErrAuthorizationNotFound) || tokens.Load() != 1 || identities.Load() != tc.identityCalls {
				t.Fatal("consumed callback replay made another request")
			}
		})
	}
}
