package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/cimd"
	"github.com/ory/fosite"
)

func TestCIMDResolvesOnlyAtAuthorizationAndPersistsSnapshot(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	seedOAuthUser(t, db, "user-1")
	server := oauthTestServer(t, db, randomSecret(t))
	const clientID = "https://client.example.test/metadata"
	const redirectURI = "https://client.example.test/callback"
	const resource = "https://resource.example.test/api"
	resolver := &fakeCIMDResolver{metadata: cimd.Metadata{ID: clientID, Name: "CIMD test", RedirectURIs: []string{redirectURI}, Scopes: []string{"goauthy.read"}, AllowedResources: []string{resource}, AllowedResourcesPresent: true}}
	server.store.cimd = resolver

	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	authorize := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "scope": {"goauthy.read"}, "state": {strings.Repeat("s", 32)},
		"resource":       {resource},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
	issued := httptest.NewRecorder()
	server.WriteAuthorization(issued, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+authorize.Encode(), nil), "user-1", []string{"goauthy.read"})
	location, err := url.Parse(issued.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorize status=%d location=%q err=%v", issued.Code, issued.Header().Get("Location"), err)
	}
	if resolve, lookup := resolver.calls(); resolve != 1 || lookup != 2 {
		t.Fatalf("authorize resolve=%d lookup=%d, want 1/2", resolve, lookup)
	}

	// A later cache view may be different, but the code's persisted snapshot
	// controls redemption and is never remotely resolved again.
	resolver.setMetadata(cimd.Metadata{ID: clientID, Name: "mutated", RedirectURIs: []string{"https://client.example.test/other"}, Scopes: []string{"openid"}, AllowedResources: []string{"https://other-resource.example.test/api"}, AllowedResourcesPresent: true})
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {location.Query().Get("code")}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("token status=%d body=%s", response.Code, response.Body.String())
	}
	if resolve, lookup := resolver.calls(); resolve != 1 || lookup != 3 {
		t.Fatalf("token unexpectedly resolved metadata: resolve=%d lookup=%d", resolve, lookup)
	}
	accessToken := struct {
		AccessToken string `json:"access_token"`
	}{}
	if err := json.NewDecoder(response.Body).Decode(&accessToken); err != nil || accessToken.AccessToken == "" {
		t.Fatalf("decode token=%#v err=%v", accessToken, err)
	}
	resolver.resetLookupCalls()
	if _, err := server.store.GetAccessTokenSession(context.Background(), server.accessTokens.AccessTokenSignature(context.Background(), accessToken.AccessToken), &fosite.DefaultSession{}); err != nil {
		t.Fatal(err)
	}
	if _, lookup := resolver.calls(); lookup != 0 {
		t.Fatalf("stored access request consulted mutable CIMD cache %d times", lookup)
	}
}

func TestCIMDResourceAllowListAndDangerPolicy(t *testing.T) {
	t.Parallel()
	const clientID = "https://client.example.test/metadata"
	const redirectURI = "https://client.example.test/callback"
	const allowed = "https://resource.example.test/api"
	client, err := newEphemeralClientRecord(ephemeralClientRecord{ID: clientID, RedirectURIs: []string{redirectURI}, Scopes: []string{"goauthy.read"}, AllowedResources: []string{allowed}, AllowedResourcesPresent: true})
	if err != nil {
		t.Fatal(err)
	}
	server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
	request := fosite.NewRequest()
	request.Client = client
	if err := server.applyResourceAudience(request, []string{allowed}); err != nil {
		t.Fatalf("allow-listed resource err=%v", err)
	}
	if err := server.applyResourceAudience(request, []string{"https://other.example.test/api"}); err == nil {
		t.Fatal("unlisted resource accepted")
	}
	emptyClient, err := newEphemeralClientRecord(ephemeralClientRecord{ID: clientID, RedirectURIs: []string{redirectURI}, Scopes: []string{"goauthy.read"}, AllowedResources: []string{}, AllowedResourcesPresent: true})
	if err != nil {
		t.Fatal(err)
	}
	emptyRequest := fosite.NewRequest()
	emptyRequest.Client = emptyClient
	if err := server.applyResourceAudience(emptyRequest, []string{allowed}); err == nil {
		t.Fatal("explicit empty allow-list accepted a resource")
	}
	if server.publicDynamicClient(client) {
		t.Fatal("ephemeral client received RFC8252 dynamic-client exemption")
	}
	if _, err := newEphemeralClientRecord(ephemeralClientRecord{ID: clientID, RedirectURIs: []string{redirectURI}, Scopes: []string{"admin"}}); err == nil {
		t.Fatal("snapshot gained an unsupported scope")
	}

	dangerClient, err := newEphemeralClientRecord(ephemeralClientRecord{ID: clientID, RedirectURIs: []string{redirectURI}, Scopes: []string{"goauthy.read"}})
	if err != nil {
		t.Fatal(err)
	}
	dangerRequest := fosite.NewRequest()
	dangerRequest.Client = dangerClient
	if err := server.applyResourceAudience(dangerRequest, []string{"https://arbitrary.example.test/api"}); err == nil {
		t.Fatal("default CIMD policy accepted an unvalidated resource")
	}
	server.ephemeralDangerAllowUnvalidatedResource = true
	if err := server.applyResourceAudience(dangerRequest, []string{"https://arbitrary.example.test/api"}); err != nil {
		t.Fatalf("danger policy rejected valid HTTPS resource: %v", err)
	}
	if err := server.applyResourceAudience(dangerRequest, []string{"http://arbitrary.example.test/api"}); err == nil {
		t.Fatal("danger policy accepted non-HTTPS resource")
	}
}

func TestCIMDEphemeralAudienceStrategyAllowsOnlyDangerMarker(t *testing.T) {
	t.Parallel()
	if err := ephemeralAudienceMatchingStrategy([]string{ephemeralAnyResourceAudience}, []string{"https://arbitrary.example.test/api"}); err != nil {
		t.Fatalf("danger marker rejected arbitrary audience: %v", err)
	}
	if err := ephemeralAudienceMatchingStrategy([]string{"https://resource.example.test/api"}, []string{"https://other.example.test/api"}); err == nil {
		t.Fatal("exact allow-list accepted an unlisted audience")
	}
}

func TestCIMDEphemeralClientIsAuthorizationCodeOnly(t *testing.T) {
	t.Parallel()
	client, err := newEphemeralClient(cimd.Metadata{
		ID: "https://client.example.test/metadata", RedirectURIs: []string{"https://client.example.test/callback"}, Scopes: []string{"goauthy.read"},
		GrantTypes: []string{"authorization_code", "client_credentials", "refresh_token"},
	})
	if err != nil {
		t.Fatal(err)
	}
	grants := client.GetGrantTypes()
	if len(grants) != 1 || grants[0] != "authorization_code" {
		t.Fatalf("CIMD grant types=%v, want only authorization_code", grants)
	}
	if !client.IsPublic() {
		t.Fatal("CIMD client is not public")
	}
	oidcClient, ok := client.(fosite.OpenIDConnectClient)
	if !ok {
		t.Fatal("CIMD client does not expose OIDC token authentication metadata")
	}
	if method := oidcClient.GetTokenEndpointAuthMethod(); method != "none" {
		t.Fatalf("CIMD token auth method=%q, want none", method)
	}
}

func TestCIMDDangerResourceAuthorizationUsesMarkerStrategy(t *testing.T) {
	t.Parallel()
	const clientID = "https://client.example.test/metadata"
	const redirectURI = "https://client.example.test/callback"
	const resource = "https://arbitrary.example.test/api"
	db := oauthTestDB(t)
	seedOAuthUser(t, db, "user-1")
	server := oauthTestServer(t, db, randomSecret(t))
	server.ephemeralDangerAllowUnvalidatedResource = true
	server.store.cimd = &fakeCIMDResolver{metadata: cimd.Metadata{ID: clientID, RedirectURIs: []string{redirectURI}, Scopes: []string{"goauthy.read"}}}
	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	authorize := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI}, "scope": {"goauthy.read"}, "resource": {resource}, "state": {strings.Repeat("s", 32)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
	issued := httptest.NewRecorder()
	server.WriteAuthorization(issued, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+authorize.Encode(), nil), "user-1", []string{"goauthy.read"})
	location, err := url.Parse(issued.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorize status=%d location=%q err=%v", issued.Code, issued.Header().Get("Location"), err)
	}
}

func TestCIMDPrefetchFailureStages(t *testing.T) {
	t.Parallel()
	const clientID = "https://client.example.test/metadata"
	metadata := cimd.Metadata{ID: clientID, RedirectURIs: []string{"https://client.example.test/callback"}, Scopes: []string{"goauthy.read"}}

	t.Run("dynamic client lookup", func(t *testing.T) {
		server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
		resolver := &fakeCIMDResolver{metadata: metadata}
		server.store.cimd = resolver
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := server.store.resolveCIMDAuthorizationClient(ctx, clientID)
		if !errors.Is(err, errCIMDDynamicClientLookup) || cimdPrefetchFailureStage(err) != cimdPrefetchStageDynamicClientLookup {
			t.Fatalf("dynamic lookup err=%v stage=%q", err, cimdPrefetchFailureStage(err))
		}
		if resolve, _ := resolver.calls(); resolve != 0 {
			t.Fatalf("dynamic lookup failure invoked metadata resolution %d times", resolve)
		}
	})

	t.Run("metadata resolution", func(t *testing.T) {
		server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
		resolver := &fakeCIMDResolver{metadata: metadata, resolveErr: errors.New("fixture resolver failure")}
		server.store.cimd = resolver
		err := server.store.resolveCIMDAuthorizationClient(context.Background(), clientID)
		if !errors.Is(err, errCIMDMetadataResolution) || cimdPrefetchFailureStage(err) != cimdPrefetchStageMetadataResolution {
			t.Fatalf("metadata resolution err=%v stage=%q", err, cimdPrefetchFailureStage(err))
		}
		if resolve, _ := resolver.calls(); resolve != 1 {
			t.Fatalf("metadata resolution calls=%d, want 1", resolve)
		}
	})
}

type fakeCIMDResolver struct {
	mu         sync.Mutex
	metadata   cimd.Metadata
	cached     bool
	resolveErr error
	resolve    int
	lookup     int
}

func (r *fakeCIMDResolver) Lookup(_ context.Context, id string) (cimd.Metadata, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookup++
	if !r.cached || id != r.metadata.ID {
		return cimd.Metadata{}, cimd.ErrNotFound
	}
	return cloneCIMDMetadata(r.metadata), nil
}

func (r *fakeCIMDResolver) Resolve(_ context.Context, id string) (cimd.Metadata, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.resolve++
	if r.resolveErr != nil {
		return cimd.Metadata{}, r.resolveErr
	}
	if id != r.metadata.ID {
		return cimd.Metadata{}, cimd.ErrNotFound
	}
	r.cached = true
	return cloneCIMDMetadata(r.metadata), nil
}

func (r *fakeCIMDResolver) setMetadata(metadata cimd.Metadata) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.metadata = cloneCIMDMetadata(metadata)
}

func (r *fakeCIMDResolver) resetLookupCalls() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookup = 0
}

func (r *fakeCIMDResolver) calls() (resolve, lookup int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resolve, r.lookup
}

func cloneCIMDMetadata(metadata cimd.Metadata) cimd.Metadata {
	metadata.RedirectURIs = append([]string(nil), metadata.RedirectURIs...)
	metadata.Scopes = append([]string(nil), metadata.Scopes...)
	if metadata.AllowedResources != nil {
		metadata.AllowedResources = append([]string{}, metadata.AllowedResources...)
	}
	return metadata
}
