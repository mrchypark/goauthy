package browser

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

const (
	dpopContinuityPhaseEnv = "GOAUTHY_E2E_DPOP_CONTINUITY_PHASE"
	dpopContinuityFileEnv  = "GOAUTHY_E2E_DPOP_CONTINUITY_FILE"
	dpopContinuityMaxState = 64 << 10
)

type dpopContinuityState struct {
	Version                 int    `json:"version"`
	PrivateKey              string `json:"private_key"`
	AccessToken             string `json:"access_token"`
	RefreshToken            string `json:"refresh_token"`
	Subject                 string `json:"subject"`
	ClientID                string `json:"client_id,omitempty"`
	ClientSecret            string `json:"client_secret,omitempty"`
	RedirectURI             string `json:"redirect_uri,omitempty"`
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
}

// TestDynamicDPoPContinuityLive carries a required-DPoP confidential dynamic
// client through the same Kind fault sequence as the bootstrap fixture.
func TestDynamicDPoPContinuityLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_DCR_DPOP_CONTINUITY") != "1" {
		t.Skip("set GOAUTHY_E2E_DCR_DPOP_CONTINUITY=1 to run dynamic DPoP continuity E2E")
	}
	phase := os.Getenv(dpopContinuityPhaseEnv)
	if phase == "" {
		t.Skip("set GOAUTHY_E2E_DPOP_CONTINUITY_PHASE to run dynamic DPoP continuity E2E")
	}
	if phase != "prepare" && phase != "verify" && phase != "unavailable" && phase != "cleanup" {
		t.Fatal("invalid dynamic DPoP continuity phase")
	}
	statePath := os.Getenv(dpopContinuityFileEnv)
	if !filepath.IsAbs(statePath) {
		t.Fatal("dynamic DPoP continuity requires an absolute private fixture path")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	client := newBrowserClient(t)
	switch phase {
	case "prepare":
		prepareDynamicDPoPContinuity(t, client, statePath, primary, secondary, username, password)
	case "verify":
		verifyDynamicDPoPContinuity(t, client, statePath, primary, secondary, tertiary)
	case "unavailable":
		assertDynamicDPoPContinuityUnavailable(t, client, statePath, primary)
	case "cleanup":
		cleanupDynamicDPoPContinuity(t, client, statePath, tertiary)
	}
}

func prepareDynamicDPoPContinuity(t *testing.T, client *http.Client, statePath, primary, secondary, username, password string) {
	t.Helper()
	registrationToken := os.Getenv("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN")
	if registrationToken == "" {
		t.Fatal("GOAUTHY_E2E_DCR_REGISTRATION_TOKEN is required for dynamic DPoP continuity E2E")
	}
	registration := updateDCRDPoPClient(t, secondary, registerDCRDPoPClient(t, primary, registrationToken), true)
	if !strings.Contains(" "+registration.Scope+" ", " offline_access ") {
		t.Fatal("dynamic DPoP continuity requires configured offline_access scope")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantJKT := dpopContinuityJKT(t, public)
	verifier := pkceVerifier(t)
	code, _ := loginForAuthorizationURL(t, client, oidcAuthorizationURLForClient(t, primary, registration.ClientID, registration.RedirectURIs[0], pkceChallenge(verifier), "dynamic-dpop-continuity", "dynamic-dpop-continuity-nonce", "openid goauthy.read offline_access"), primary, secondary, username, password, "dynamic-dpop-continuity")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {registration.RedirectURIs[0]}, "code_verifier": {verifier}}
	challenge := postDCRDPoPToken(t, client, primary, registration, form, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	nonce := assertDPoPTokenNonce(t, challenge)
	challenge.Body.Close()
	issuedResponse := postDCRDPoPToken(t, client, secondary, registration, form, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", nonce, ""))
	issued := decodeDPoPToken(t, issuedResponse, wantJKT)
	issuedResponse.Body.Close()
	if issued.AccessToken == "" || issued.RefreshToken == "" {
		t.Fatal("dynamic DPoP authorization-code response is incomplete")
	}
	writeDPoPContinuityState(t, statePath, dpopContinuityState{Version: 1, PrivateKey: base64.RawStdEncoding.EncodeToString(private), AccessToken: issued.AccessToken, RefreshToken: issued.RefreshToken, Subject: "bootstrap-admin", ClientID: registration.ClientID, ClientSecret: registration.ClientSecret, RedirectURI: registration.RedirectURIs[0], RegistrationAccessToken: registration.RegistrationAccessToken})
}

func verifyDynamicDPoPContinuity(t *testing.T, client *http.Client, statePath, primary, secondary, tertiary string) {
	t.Helper()
	state, _ := readDynamicDPoPContinuityState(t, statePath)
	registration := dynamicContinuityRegistration(state)
	assertDCRDPoPRegistration(t, tertiary, registration, true)
	credentialsForm := url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}}
	assertDCRDPoPTokenError(t, postDCRDPoPToken(t, client, primary, registration, credentialsForm, ""), "invalid_request")
	private := dpopContinuityPrivateKey(t, state.PrivateKey)
	wantJKT := dpopContinuityJKT(t, private.Public().(ed25519.PublicKey))
	for _, node := range []string{primary, secondary, tertiary} {
		assertDPoPContinuityUserInfo(t, client, node, primary, private, state.AccessToken, state.Subject)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {state.RefreshToken}}
	assertDPoPContinuityTokenError(t, postDCRDPoPToken(t, client, primary, registration, refreshForm, dpopProof(t, wrongPrivate, http.MethodPost, primary+"/oidc/token", "", "")), "invalid_dpop_proof")
	challenge := postDCRDPoPToken(t, client, tertiary, registration, refreshForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	nonce := assertDPoPTokenNonce(t, challenge)
	challenge.Body.Close()
	refreshedResponse := postDCRDPoPToken(t, client, secondary, registration, refreshForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", nonce, ""))
	refreshed := decodeDPoPToken(t, refreshedResponse, wantJKT)
	refreshedResponse.Body.Close()
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" || refreshed.RefreshToken == state.RefreshToken {
		t.Fatal("dynamic DPoP refresh response is incomplete or did not rotate the refresh credential")
	}
	for _, node := range []string{primary, secondary, tertiary} {
		assertDPoPContinuityUserInfo(t, client, node, primary, private, refreshed.AccessToken, state.Subject)
	}
	state.AccessToken, state.RefreshToken = refreshed.AccessToken, refreshed.RefreshToken
	writeDPoPContinuityState(t, statePath, state)
}

func assertDynamicDPoPContinuityUnavailable(t *testing.T, client *http.Client, statePath, survivor string) {
	t.Helper()
	state, before := readDynamicDPoPContinuityState(t, statePath)
	registration := dynamicContinuityRegistration(state)
	private := dpopContinuityPrivateKey(t, state.PrivateKey)
	response := dpopUserInfo(t, client, survivor, state.AccessToken, dpopProof(t, private, http.MethodGet, survivor+"/oidc/userinfo", "", state.AccessToken), "DPoP")
	status, challenge, nonce := response.StatusCode, response.Header.Get("WWW-Authenticate"), response.Header.Get("DPoP-Nonce")
	response.Body.Close()
	if status != http.StatusUnauthorized || challenge != "Bearer" || nonce != "" {
		t.Fatalf("dynamic quorum-loss UserInfo status=%d bearer_challenge=%t nonce_present=%t", status, challenge == "Bearer", nonce != "")
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {state.RefreshToken}}
	response = postDCRDPoPToken(t, client, survivor, registration, form, dpopProof(t, private, http.MethodPost, survivor+"/oidc/token", "", ""))
	var body struct {
		Error string `json:"error"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&body)
	status, nonce = response.StatusCode, response.Header.Get("DPoP-Nonce")
	response.Body.Close()
	if status != http.StatusInternalServerError || decodeErr != nil || body.Error != "server_error" || nonce != "" {
		t.Fatalf("dynamic quorum-loss refresh status=%d server_error=%t nonce_present=%t", status, body.Error == "server_error", nonce != "")
	}
	_, after := readDynamicDPoPContinuityState(t, statePath)
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("unavailable phase changed the private dynamic DPoP continuity fixture")
	}
}

func cleanupDynamicDPoPContinuity(t *testing.T, client *http.Client, statePath, baseURL string) {
	t.Helper()
	state, _ := readDynamicDPoPContinuityState(t, statePath)
	registration := dynamicContinuityRegistration(state)
	response := do(t, client, http.MethodDelete, baseURL+"/oidc/register/"+url.PathEscape(registration.ClientID), nil, map[string]string{"Authorization": "Bearer " + registration.RegistrationAccessToken})
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("dynamic DPoP continuity cleanup status=%d", response.StatusCode)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal("remove private dynamic DPoP continuity fixture")
	}
}

func dynamicContinuityRegistration(state dpopContinuityState) dcrDPoPRegistration {
	return dcrDPoPRegistration{dynamicClientRegistration: dynamicClientRegistration{ClientID: state.ClientID, ClientSecret: state.ClientSecret, RegistrationAccessToken: state.RegistrationAccessToken, RedirectURIs: []string{state.RedirectURI}, TokenEndpointAuthMethod: "client_secret_basic"}, DPoPBoundAccessTokens: true}
}

func readDynamicDPoPContinuityState(t *testing.T, path string) (dpopContinuityState, []byte) {
	t.Helper()
	state, data := readDPoPContinuityState(t, path)
	if state.ClientID == "" || state.ClientSecret == "" || state.RedirectURI == "" || state.RegistrationAccessToken == "" {
		t.Fatal("invalid private dynamic DPoP continuity fixture")
	}
	return state, data
}

// TestDPoPContinuityLive carries one DPoP authorization-code session through
// the fault phases owned by the Kind test driver. It is intentionally opt-in:
// its fixture contains an authorization credential and an Ed25519 private key.
func TestDPoPContinuityLive(t *testing.T) {
	phase := os.Getenv(dpopContinuityPhaseEnv)
	if phase == "" {
		t.Skip("set GOAUTHY_E2E_DPOP_CONTINUITY_PHASE to run DPoP continuity E2E")
	}
	if phase != "prepare" && phase != "verify" && phase != "unavailable" {
		t.Fatal("invalid DPoP continuity phase")
	}
	statePath := os.Getenv(dpopContinuityFileEnv)
	if !filepath.IsAbs(statePath) {
		t.Fatal("DPoP continuity requires an absolute private fixture path")
	}

	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	client := newBrowserClient(t)

	switch phase {
	case "prepare":
		prepareDPoPContinuity(t, client, statePath, primary, secondary, username, password, clientSecret)
	case "verify":
		verifyDPoPContinuity(t, client, statePath, primary, secondary, tertiary, clientSecret)
	case "unavailable":
		assertDPoPContinuityUnavailable(t, client, statePath, primary, clientSecret)
	}
}

func prepareDPoPContinuity(t *testing.T, client *http.Client, statePath, primary, secondary, username, password, clientSecret string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wantJKT := dpopContinuityJKT(t, public)
	verifier := pkceVerifier(t)
	code, _ := loginForAuthorizationURL(t, client, oidcAuthorizationURL(t, primary, defaultRedirectURI, pkceChallenge(verifier), "dpop-continuity", "dpop-continuity-nonce"), primary, secondary, username, password, "dpop-continuity")
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {defaultRedirectURI}, "code_verifier": {verifier}}
	challenge := postDPoPToken(t, client, primary, clientSecret, form, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	nonce := assertDPoPTokenNonce(t, challenge)
	challenge.Body.Close()
	issuedResponse := postDPoPToken(t, client, secondary, clientSecret, form, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", nonce, ""))
	issued := decodeDPoPToken(t, issuedResponse, wantJKT)
	issuedResponse.Body.Close()
	if issued.AccessToken == "" || issued.RefreshToken == "" {
		t.Fatal("DPoP authorization-code response is incomplete")
	}

	writeDPoPContinuityState(t, statePath, dpopContinuityState{
		Version:      1,
		PrivateKey:   base64.RawStdEncoding.EncodeToString(private),
		AccessToken:  issued.AccessToken,
		RefreshToken: issued.RefreshToken,
		Subject:      "bootstrap-admin",
	})
}

func verifyDPoPContinuity(t *testing.T, client *http.Client, statePath, primary, secondary, tertiary, clientSecret string) {
	t.Helper()
	state, _ := readDPoPContinuityState(t, statePath)
	private := dpopContinuityPrivateKey(t, state.PrivateKey)
	wantJKT := dpopContinuityJKT(t, private.Public().(ed25519.PublicKey))
	for _, node := range []string{primary, secondary, tertiary} {
		assertDPoPContinuityUserInfo(t, client, node, primary, private, state.AccessToken, state.Subject)
	}

	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {state.RefreshToken}}
	wrong := postDPoPToken(t, client, primary, clientSecret, refreshForm, dpopProof(t, wrongPrivate, http.MethodPost, primary+"/oidc/token", "", ""))
	assertDPoPContinuityTokenError(t, wrong, "invalid_dpop_proof")

	challenge := postDPoPToken(t, client, tertiary, clientSecret, refreshForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", "", ""))
	nonce := assertDPoPTokenNonce(t, challenge)
	challenge.Body.Close()
	refreshedResponse := postDPoPToken(t, client, secondary, clientSecret, refreshForm, dpopProof(t, private, http.MethodPost, primary+"/oidc/token", nonce, ""))
	refreshed := decodeDPoPToken(t, refreshedResponse, wantJKT)
	refreshedResponse.Body.Close()
	if refreshed.AccessToken == "" || refreshed.RefreshToken == "" || refreshed.RefreshToken == state.RefreshToken {
		t.Fatal("DPoP refresh response is incomplete or did not rotate the refresh credential")
	}
	for _, node := range []string{primary, secondary, tertiary} {
		assertDPoPContinuityUserInfo(t, client, node, primary, private, refreshed.AccessToken, state.Subject)
	}
	state.AccessToken, state.RefreshToken = refreshed.AccessToken, refreshed.RefreshToken
	writeDPoPContinuityState(t, statePath, state)
}

func assertDPoPContinuityUnavailable(t *testing.T, client *http.Client, statePath, survivor, clientSecret string) {
	t.Helper()
	state, before := readDPoPContinuityState(t, statePath)
	private := dpopContinuityPrivateKey(t, state.PrivateKey)

	response := dpopUserInfo(t, client, survivor, state.AccessToken, dpopProof(t, private, http.MethodGet, survivor+"/oidc/userinfo", "", state.AccessToken), "DPoP")
	status, challenge, nonce := response.StatusCode, response.Header.Get("WWW-Authenticate"), response.Header.Get("DPoP-Nonce")
	response.Body.Close()
	if status != http.StatusUnauthorized || challenge != "Bearer" || nonce != "" {
		t.Fatalf("quorum-loss UserInfo status=%d bearer_challenge=%t nonce_present=%t", status, challenge == "Bearer", nonce != "")
	}

	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {state.RefreshToken}}
	response = postDPoPToken(t, client, survivor, clientSecret, form, dpopProof(t, private, http.MethodPost, survivor+"/oidc/token", "", ""))
	var body struct {
		Error string `json:"error"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&body)
	status, nonce = response.StatusCode, response.Header.Get("DPoP-Nonce")
	response.Body.Close()
	if status != http.StatusInternalServerError || decodeErr != nil || body.Error != "server_error" || nonce != "" {
		t.Fatalf("quorum-loss refresh status=%d server_error=%t nonce_present=%t", status, body.Error == "server_error", nonce != "")
	}
	_, after := readDPoPContinuityState(t, statePath)
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("unavailable phase changed the private DPoP continuity fixture")
	}
}

func assertDPoPContinuityUserInfo(t *testing.T, client *http.Client, node, issuer string, private ed25519.PrivateKey, accessToken, wantSubject string) {
	t.Helper()
	challenge := dpopUserInfo(t, client, node, accessToken, dpopProof(t, private, http.MethodGet, issuer+"/oidc/userinfo", "", accessToken), "DPoP")
	nonce := assertDPoPResourceNonce(t, challenge)
	challenge.Body.Close()
	response := dpopUserInfo(t, client, node, accessToken, dpopProof(t, private, http.MethodGet, issuer+"/oidc/userinfo", nonce, accessToken), "DPoP")
	defer response.Body.Close()
	var body struct {
		Subject string `json:"sub"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&body) != nil || body.Subject != wantSubject {
		t.Fatalf("DPoP UserInfo continuity status=%d subject_matches=%t", response.StatusCode, body.Subject == wantSubject)
	}
}

func assertDPoPContinuityTokenError(t *testing.T, response *http.Response, want string) {
	t.Helper()
	defer response.Body.Close()
	var body struct {
		Error string `json:"error"`
	}
	if response.StatusCode != http.StatusBadRequest || json.NewDecoder(io.LimitReader(response.Body, 16<<10)).Decode(&body) != nil || body.Error != want {
		t.Fatalf("DPoP token rejection status=%d expected_error=%q actual_matches=%t", response.StatusCode, want, body.Error == want)
	}
}

func dpopContinuityJKT(t *testing.T, public ed25519.PublicKey) string {
	t.Helper()
	jwk := jose.JSONWebKey{Key: public}
	thumbprint, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(thumbprint)
}

func dpopContinuityPrivateKey(t *testing.T, encoded string) ed25519.PrivateKey {
	t.Helper()
	private, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(private) != ed25519.PrivateKeySize {
		t.Fatal("invalid private DPoP continuity key")
	}
	return ed25519.PrivateKey(private)
}

func writeDPoPContinuityState(t *testing.T, path string, state dpopContinuityState) {
	t.Helper()
	if !filepath.IsAbs(path) {
		t.Fatal("DPoP continuity requires an absolute private fixture path")
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || !info.IsDir() {
		t.Fatal("DPoP continuity fixture directory is unavailable")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".goauthy-dpop-continuity-")
	if err != nil {
		t.Fatal("create DPoP continuity fixture")
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		t.Fatal("protect DPoP continuity fixture")
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(state); err != nil {
		file.Close()
		t.Fatal("encode DPoP continuity fixture")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal("sync DPoP continuity fixture")
	}
	if err := file.Close(); err != nil {
		t.Fatal("close DPoP continuity fixture")
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatal("replace DPoP continuity fixture")
	}
}

func readDPoPContinuityState(t *testing.T, path string) (dpopContinuityState, []byte) {
	t.Helper()
	if !filepath.IsAbs(path) {
		t.Fatal("DPoP continuity requires an absolute private fixture path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("invalid private DPoP continuity fixture")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("open DPoP continuity fixture")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, dpopContinuityMaxState+1))
	closeErr := file.Close()
	var state dpopContinuityState
	if readErr != nil || closeErr != nil || len(data) > dpopContinuityMaxState || json.Unmarshal(data, &state) != nil || state.Version != 1 || state.PrivateKey == "" || state.AccessToken == "" || state.RefreshToken == "" || state.Subject == "" {
		t.Fatal("invalid private DPoP continuity fixture")
	}
	return state, data
}
