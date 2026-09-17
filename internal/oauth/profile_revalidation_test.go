package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func seedUserProfile(t *testing.T, db *rhiza.DB, subject, email, preferredUsername, givenName, familyName, userValuesJSON string) {
	t.Helper()
	var preferred, given, family, values any
	if preferredUsername != "" {
		preferred = preferredUsername
	}
	if givenName != "" {
		given = givenName
	}
	if familyName != "" {
		family = familyName
	}
	if userValuesJSON != "" {
		values = userValuesJSON
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "seed-profile-" + subject,
		SQL:       `INSERT OR REPLACE INTO identity_user_profiles(subject,email,email_verified,preferred_username,given_name,family_name,user_values_json) VALUES(?,?,?,?,?,?,?)`,
		Args:      []any{subject, email, int64(1), preferred, given, family, values},
	}); err != nil {
		t.Fatal(err)
	}
}

func profileRevalidationIdentityStore(t *testing.T, db *rhiza.DB) *identity.Store {
	t.Helper()
	hasher, err := credential.NewHasher(credential.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	store, err := identity.NewStoreWithPolicies(db, hasher, credential.DefaultRules())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestSetUserValuesPolicy(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)

	t.Run("default zero accepted", func(t *testing.T) {
		if err := server.SetUserValuesPolicy(identity.UserValuesPolicy{}, nil); err != nil {
			t.Fatalf("zero policy: %v", err)
		}
		if server.userValuesPolicy.RevalidateDuringLogin {
			t.Fatal("expected default off")
		}
	})

	t.Run("true without resolver rejected", func(t *testing.T) {
		err := server.SetUserValuesPolicy(identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"}, nil)
		if err != identity.ErrUserValuesPolicy {
			t.Fatalf("expected ErrUserValuesPolicy, got %v", err)
		}
	})

	t.Run("true with resolver accepted", func(t *testing.T) {
		err := server.SetUserValuesPolicy(
			identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"},
			identityStore.NeedsProfileUpdate,
		)
		if err != nil {
			t.Fatalf("valid policy: %v", err)
		}
		if !server.userValuesPolicy.RevalidateDuringLogin {
			t.Fatal("expected RevalidateDuringLogin true")
		}
	})

	t.Run("invalid mode rejected", func(t *testing.T) {
		err := server.SetUserValuesPolicy(
			identity.UserValuesPolicy{GivenName: "BOGUS"},
			nil,
		)
		if err != identity.ErrUserValuesPolicy {
			t.Fatalf("expected ErrUserValuesPolicy, got %v", err)
		}
	})
}

func TestProfileRevalidationDisabledAllowsIssuance(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	seedOAuthUser(t, db, "user-1")
	seedUserProfile(t, db, "user-1", "user-1@example.test", "user1", "Given", "Family", `{}`)
	code := issueCode(t, server, strings.Repeat("d", 43))
	if code == "" {
		t.Fatal("disabled policy should allow code issuance")
	}
}

func TestProfileRevalidationValidProfileAllowsIssuance(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)
	seedOAuthUser(t, db, "user-1")
	seedUserProfile(t, db, "user-1", "user-1@example.test", "user1", "Given", "Family", `{}`)

	if err := server.SetUserValuesPolicy(
		identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required", FamilyName: "required"},
		identityStore.NeedsProfileUpdate,
	); err != nil {
		t.Fatal(err)
	}

	code := issueCode(t, server, strings.Repeat("v", 43))
	if code == "" {
		t.Fatal("valid profile should allow code issuance")
	}
}

func TestProfileRevalidationMissingGivenNameDeniesIssuance(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)
	seedOAuthUser(t, db, "user-1")
	seedUserProfile(t, db, "user-1", "user-1@example.test", "user1", "", "Family", `{}`)

	if err := server.SetUserValuesPolicy(
		identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"},
		identityStore.NeedsProfileUpdate,
	); err != nil {
		t.Fatal(err)
	}

	response := profileAuthorize(t, server)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code") != "" {
		t.Fatal("invalid profile must not issue a code")
	}
	if location.Query().Get("error") != "interaction_required" {
		t.Fatalf("expected interaction_required, got %q", location.Query().Get("error"))
	}
	assertNoAuthorizationState(t, db)
}

func TestProfileRevalidationInvalidPreferredUsernameDeniesIssuance(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)
	seedOAuthUser(t, db, "user-1")
	seedUserProfile(t, db, "user-1", "user-1@example.test", "Admin", "Given", "Family", `{}`)

	policy := identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"}
	puPolicy, err := identity.NewPreferredUsernamePolicy("required", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	policy.PreferredUsername = puPolicy

	if err := server.SetUserValuesPolicy(policy, identityStore.NeedsProfileUpdate); err != nil {
		t.Fatal(err)
	}

	response := profileAuthorize(t, server)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code") != "" {
		t.Fatal("blacklisted preferred_username must not issue a code")
	}
	if location.Query().Get("error") != "interaction_required" {
		t.Fatalf("expected interaction_required, got %q", location.Query().Get("error"))
	}
	assertNoAuthorizationState(t, db)
}

func TestProfileRevalidationMissingNestedBirthdateDeniesIssuance(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)
	seedOAuthUser(t, db, "user-1")
	seedUserProfile(t, db, "user-1", "user-1@example.test", "user1", "Given", "Family", `{"birthdate":null}`)

	if err := server.SetUserValuesPolicy(
		identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required", Birthdate: "required"},
		identityStore.NeedsProfileUpdate,
	); err != nil {
		t.Fatal(err)
	}

	response := profileAuthorize(t, server)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code") != "" {
		t.Fatal("missing required birthdate must not issue a code")
	}
	if location.Query().Get("error") != "interaction_required" {
		t.Fatalf("expected interaction_required, got %q", location.Query().Get("error"))
	}
	assertNoAuthorizationState(t, db)
}

func TestProfileRevalidationSessionReuseDeniesIssuance(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)
	seedOAuthUser(t, db, "user-1")
	seedUserProfile(t, db, "user-1", "user-1@example.test", "user1", "", "Family", `{}`)

	if err := server.SetUserValuesPolicy(
		identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"},
		identityStore.NeedsProfileUpdate,
	); err != nil {
		t.Fatal(err)
	}

	verifier := strings.Repeat("s", 43)
	digest := sha256.Sum256([]byte(verifier))
	values := url.Values{
		"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI},
		"scope": {"goauthy.read"}, "state": {strings.Repeat("x", 32)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
	ensureOIDCTestBrowserSession(t, server, oidcTestSessionID(0))
	response := httptest.NewRecorder()
	server.CompleteAuthorizationWithSession(
		response,
		httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil),
		"user-1",
		[]string{"goauthy.read"},
		oidcTestAuthTime,
		oidcTestSessionID(0),
		oidcAuthMethodPwd,
	)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code") != "" {
		t.Fatal("session-bound authorization must also gate on profile")
	}
	if location.Query().Get("error") != "interaction_required" {
		t.Fatalf("expected interaction_required, got %q", location.Query().Get("error"))
	}
	assertNoAuthorizationState(t, db)
}

func TestProfileRevalidationNoCodePersistedOnDenial(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)
	seedOAuthUser(t, db, "user-1")
	seedUserProfile(t, db, "user-1", "user-1@example.test", "user1", "", "", `{}`)

	if err := server.SetUserValuesPolicy(
		identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"},
		identityStore.NeedsProfileUpdate,
	); err != nil {
		t.Fatal(err)
	}

	for i := range 3 {
		response := profileAuthorize(t, server)
		location, err := url.Parse(response.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if location.Query().Get("code") != "" {
			t.Fatalf("attempt %d: must not issue code", i)
		}
	}
	assertNoAuthorizationState(t, db)
}

func TestProfileRevalidationConcurrentProfileMutationDeniesCode(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)
	seedOAuthUser(t, db, "user-1")
	seedUserProfile(t, db, "user-1", "user-1@example.test", "user1", "Given", "Family", `{}`)

	if err := server.SetUserValuesPolicy(
		identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"},
		identityStore.NeedsProfileUpdate,
	); err != nil {
		t.Fatal(err)
	}

	hookCalled := false
	server.beforeAuthorizationIssue = func() {
		hookCalled = true
		server.beforeAuthorizationIssue = nil
		if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
			RequestID: "profile-race-test",
			SQL:       `UPDATE identity_user_profiles SET given_name=NULL WHERE subject='user-1'`,
		}); err != nil {
			t.Fatal(err)
		}
	}

	response := profileAuthorize(t, server)
	if !hookCalled {
		t.Fatal("authorization did not reach snapshot hook")
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code") != "" {
		t.Fatal("concurrent profile mutation must not issue a code")
	}
	assertNoAuthorizationState(t, db)

	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "profile-race-restore",
		SQL:       `UPDATE identity_user_profiles SET given_name='Given' WHERE subject='user-1'`,
	}); err != nil {
		t.Fatal(err)
	}
	code := issueCode(t, server, strings.Repeat("r", 43))
	if code == "" {
		t.Fatal("restored profile should allow issuance")
	}
}

func TestProfileRevalidationRauthyClientExempt(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)
	seedOAuthUser(t, db, "user-1")

	const rauthyClientID = "rauthy"
	const rauthyRedirectURI = "https://rauthy.example.test/callback"
	_, err := server.store.dynamicClients.Create(context.Background(), dcr.CreateRequest{
		ClientID:                rauthyClientID,
		RedirectURIs:            []string{rauthyRedirectURI},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"goauthy.read"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthNone,
		Name:                    "Rauthy",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := server.SetUserValuesPolicy(
		identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"},
		identityStore.NeedsProfileUpdate,
	); err != nil {
		t.Fatal(err)
	}

	verifier := strings.Repeat("z", 43)
	digest := sha256.Sum256([]byte(verifier))
	values := url.Values{
		"response_type":         {"code"},
		"client_id":             {rauthyClientID},
		"redirect_uri":          {rauthyRedirectURI},
		"scope":                 {"goauthy.read"},
		"state":                 {strings.Repeat("x", 32)},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(digest[:])},
		"code_challenge_method": {"S256"},
	}
	response := httptest.NewRecorder()
	server.WriteAuthorization(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"goauthy.read"})
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code") == "" {
		t.Fatalf("rauthy client must bypass profile gate, got error=%q", location.Query().Get("error"))
	}
}

func TestProfileRevalidationMissingProfileReturnsInteractionRequired(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)
	seedOAuthUser(t, db, "user-1")

	if err := server.SetUserValuesPolicy(
		identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "required"},
		identityStore.NeedsProfileUpdate,
	); err != nil {
		t.Fatal(err)
	}

	response := profileAuthorize(t, server)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code") != "" {
		t.Fatal("missing profile must not issue a code")
	}
	if location.Query().Get("error") != "interaction_required" {
		t.Fatalf("expected interaction_required, got %q", location.Query().Get("error"))
	}
	assertNoAuthorizationState(t, db)
}

func TestProfileRevalidationDisabledWithCallbackAllowsCodeOnMissingProfile(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)
	seedOAuthUser(t, db, "user-1")

	if err := server.SetUserValuesPolicy(
		identity.UserValuesPolicy{RevalidateDuringLogin: false, GivenName: "required"},
		identityStore.NeedsProfileUpdate,
	); err != nil {
		t.Fatal(err)
	}

	code := issueCode(t, server, strings.Repeat("d", 43))
	if code == "" {
		t.Fatal("disabled flag must allow code issuance even with callback and missing profile")
	}
}

func TestProfileRevalidationEnabledOptionalFieldsAllowsCodeOnMissingProfile(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)
	seedOAuthUser(t, db, "user-1")

	if err := server.SetUserValuesPolicy(
		identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "optional"},
		identityStore.NeedsProfileUpdate,
	); err != nil {
		t.Fatal(err)
	}

	code := issueCode(t, server, strings.Repeat("o", 43))
	if code == "" {
		t.Fatal("enabled flag with optional fields must allow code issuance with no profile")
	}
}

func TestProfileRevalidationInsertAbsentProfileBeforeCommitDeniesCode(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	identityStore := profileRevalidationIdentityStore(t, db)
	seedOAuthUser(t, db, "user-1")

	if err := server.SetUserValuesPolicy(
		identity.UserValuesPolicy{RevalidateDuringLogin: true, GivenName: "optional"},
		identityStore.NeedsProfileUpdate,
	); err != nil {
		t.Fatal(err)
	}

	hookCalled := false
	server.beforeAuthorizationIssue = func() {
		hookCalled = true
		server.beforeAuthorizationIssue = nil
		seedUserProfile(t, db, "user-1", "user-1@example.test", "user1", "Given", "Family", `{}`)
	}

	response := profileAuthorize(t, server)
	if !hookCalled {
		t.Fatal("authorization did not reach snapshot hook")
	}
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if location.Query().Get("code") != "" {
		t.Fatal("concurrent profile insertion must not issue a code")
	}
	if location.Query().Get("error") == "" {
		t.Fatal("expected non-empty error")
	}
	assertNoAuthorizationState(t, db)
}

func profileAuthorize(t *testing.T, server *Server) *httptest.ResponseRecorder {
	t.Helper()
	verifier := strings.Repeat("p", 43)
	digest := sha256.Sum256([]byte(verifier))
	values := url.Values{
		"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI},
		"scope": {"goauthy.read"}, "state": {strings.Repeat("s", 32)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}, "code_challenge_method": {"S256"},
	}
	response := httptest.NewRecorder()
	server.WriteAuthorization(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"goauthy.read"})
	return response
}
