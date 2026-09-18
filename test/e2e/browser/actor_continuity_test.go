package browser

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
)

const (
	actorContinuityPhaseEnv = "GOAUTHY_E2E_ACTOR_CONTINUITY_PHASE"
	actorContinuityFileEnv  = "GOAUTHY_E2E_ACTOR_CONTINUITY_FILE"
	actorContinuityMaxState = 64 << 10
)

type actorContinuityState struct {
	Version       int                   `json:"version"`
	ActorSubject  string                `json:"actor_subject"`
	NestedToken   string                `json:"nested_token"`
	SourceSubject string                `json:"source_subject"`
	MachineTokens []string              `json:"machine_tokens,omitempty"`
	MachineMapped bool                  `json:"machine_mapped,omitempty"`
	MachineClient *crossClientExchanger `json:"machine_client,omitempty"`
}

// TestActorContinuityLive carries a two-hop actor token through the Kind fault
// phases. Its private state deliberately outlives each individual go test run.
func TestActorContinuityLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_ACTOR_CONTINUITY") != "1" {
		t.Skip("set GOAUTHY_E2E_ACTOR_CONTINUITY=1 to run actor continuity E2E")
	}
	phase := os.Getenv(actorContinuityPhaseEnv)
	if phase == "" {
		t.Skip("set GOAUTHY_E2E_ACTOR_CONTINUITY_PHASE to run actor continuity E2E")
	}
	if phase != "prepare" && phase != "verify" && phase != "unavailable" && phase != "cleanup" {
		t.Fatal("actor continuity requires phase prepare, verify, unavailable, or cleanup")
	}
	statePath := os.Getenv(actorContinuityFileEnv)
	if !filepath.IsAbs(statePath) {
		t.Fatal("actor continuity requires an absolute private fixture path")
	}
	primary, secondary, username, password, clientSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	client := newBrowserClient(t)

	switch phase {
	case "prepare":
		prepareActorContinuity(t, client, statePath, primary, secondary, tertiary, username, password, clientSecret)
	case "verify":
		verifyActorContinuity(t, client, statePath, primary, secondary, tertiary, clientSecret)
	case "unavailable":
		assertActorContinuityUnavailable(t, client, statePath, primary, clientSecret)
	case "cleanup":
		cleanupActorContinuity(t, client, statePath, primary, secondary, tertiary, username, password, clientSecret)
	}
}

func prepareActorContinuity(t *testing.T, client *http.Client, statePath, primary, secondary, tertiary, username, password, clientSecret string) {
	t.Helper()
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	actorEmail := "actor-continuity-" + randomManagedUIID(t) + "@goauthy.e2e"
	const actorPassword = "Actor-Continuity-Password-1A"
	actorID := createCatalogSessionUser(t, admin, primary, rbacMutationHeaders(csrf), actorEmail, actorPassword)

	sourceClient := newBrowserClient(t)
	source := issueActorContinuityAccessToken(t, sourceClient, primary, secondary, username, password, "actor-continuity-source", clientSecret)
	actorClient := newBrowserClient(t)
	actor := issueActorContinuityAccessToken(t, actorClient, primary, secondary, actorEmail, actorPassword, "actor-continuity-actor", clientSecret)
	sourceSubject := tokenSubject(t, client, tertiary, clientSecret, source)
	actorSubject := tokenSubject(t, client, tertiary, clientSecret, actor)
	if sourceSubject == "" || actorSubject == "" || sourceSubject == actorSubject || actorSubject != actorID {
		t.Fatalf("actor continuity requires distinct persisted subjects source_set=%t actor_matches_created=%t", sourceSubject != "", actorSubject == actorID)
	}

	first := issueActorContinuityExchange(t, sourceClient, secondary, clientSecret, source, actor)
	nested := issueActorContinuityExchange(t, sourceClient, tertiary, clientSecret, source, first)
	state := actorContinuityState{
		Version:       1,
		ActorSubject:  actorSubject,
		NestedToken:   nested,
		SourceSubject: sourceSubject,
	}
	if os.Getenv("GOAUTHY_E2E_MACHINE_EXCHANGE") == "1" {
		state.MachineClient = createCrossClientExchanger(t, admin, primary, rbacMutationHeaders(csrf), "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange")
		response := tokenResponseForClient(t, client, primary, state.MachineClient.ID, state.MachineClient.Secret, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}})
		var machine crossClientTokenResponse
		err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&machine)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || machine.AccessToken == "" {
			t.Fatal("machine continuity source issuance failed")
		}
		state.MachineMapped = os.Getenv("GOAUTHY_CLIENT_CREDENTIALS_MAP_SUB") == "true"
		form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {machine.AccessToken}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}}
		if state.MachineMapped {
			form.Set("actor_token", machine.AccessToken)
			form.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
		}
		exchanged := crossClientExchange(t, client, secondary, state.MachineClient, form)
		form.Set("actor_token", actor)
		form.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
		mixed := crossClientExchange(t, client, tertiary, state.MachineClient, form).AccessToken
		state.MachineTokens = []string{machine.AccessToken, exchanged.AccessToken, mixed}
		claims, err := oidc.VerifyAccessToken(machine.AccessToken, publicJWKS(t, client, primary), primary, time.Now().UTC())
		if err != nil || time.Until(claims.ExpiresAt) < 10*time.Minute {
			t.Fatal("machine continuity requires a source lifetime covering all fault phases")
		}
	}
	assertActorContinuityActive(t, client, state, primary, secondary, tertiary, clientSecret)
	writeActorContinuityState(t, statePath, state)
}

func verifyActorContinuity(t *testing.T, client *http.Client, statePath, primary, secondary, tertiary, clientSecret string) {
	t.Helper()
	state, _ := readActorContinuityState(t, statePath)
	assertActorContinuityActive(t, client, state, primary, secondary, tertiary, clientSecret)
}

func assertActorContinuityActive(t *testing.T, client *http.Client, state actorContinuityState, primary, secondary, tertiary, clientSecret string) {
	t.Helper()
	claims, err := oidc.VerifyAccessToken(state.NestedToken, publicJWKS(t, client, primary), primary, time.Now().UTC())
	if err != nil || claims.Subject != state.SourceSubject || claims.Actor == nil || claims.Actor.Subject != state.SourceSubject || claims.Actor.Actor == nil || claims.Actor.Actor.Subject != state.ActorSubject || claims.Actor.Actor.Actor != nil {
		t.Fatalf("actor continuity signed chain valid=%t subject_matches=%t chain_matches=%t", err == nil, claims.Subject == state.SourceSubject, claims.Actor != nil && claims.Actor.Subject == state.SourceSubject && claims.Actor.Actor != nil && claims.Actor.Actor.Subject == state.ActorSubject && claims.Actor.Actor.Actor == nil)
	}
	for _, node := range []string{primary, secondary, tertiary} {
		assertNestedActorTokenExchangeIntrospection(t, client, node, clientSecret, state.NestedToken, state.SourceSubject, state.ActorSubject)
		for index, token := range state.MachineTokens {
			want := ""
			if state.MachineMapped {
				want = state.MachineClient.ID
			}
			machineClaims, err := oidc.VerifyAccessToken(token, publicJWKS(t, client, node), primary, time.Now().UTC())
			wantActor := ""
			if index == 1 && state.MachineMapped {
				wantActor = state.MachineClient.ID
			} else if index == 2 {
				wantActor = state.ActorSubject
			}
			if err != nil || machineClaims.Subject != want || machineClaims.AuthorizedParty != state.MachineClient.ID || (machineClaims.Actor != nil) != (wantActor != "") || (wantActor != "" && (machineClaims.Actor.Subject != wantActor || machineClaims.Actor.Actor != nil)) || len(machineClaims.Roles) != 0 || len(machineClaims.Groups) != 0 || len(machineClaims.CustomClaims.Values) != 0 {
				t.Fatal("machine continuity signed claims invalid")
			}
			assertMachineIntrospection(t, client, node, &crossClientExchanger{ID: "goauthy-dev", Secret: clientSecret}, token, want, wantActor)
		}
	}
}

func assertActorContinuityUnavailable(t *testing.T, client *http.Client, statePath, survivor, clientSecret string) {
	t.Helper()
	state, before := readActorContinuityState(t, statePath)
	for _, token := range append([]string{state.NestedToken}, state.MachineTokens...) {
		request, err := http.NewRequest(http.MethodPost, survivor+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.SetBasicAuth("goauthy-dev", clientSecret)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		var body struct {
			Error string `json:"error"`
		}
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&body)
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized || decodeErr != nil || body.Error != "request_unauthorized" {
			t.Fatalf("actor quorum-loss introspection status=%d request_unauthorized=%t", response.StatusCode, body.Error == "request_unauthorized")
		}
	}
	_, after := readActorContinuityState(t, statePath)
	if sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("unavailable phase changed the private actor continuity fixture")
	}
}

func cleanupActorContinuity(t *testing.T, client *http.Client, statePath, primary, secondary, tertiary, username, password, clientSecret string) {
	t.Helper()
	state, _ := readActorContinuityState(t, statePath)
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	response := do(t, admin, http.MethodDelete, primary+"/auth/v1/users/"+url.PathEscape(state.ActorSubject), nil, rbacMutationHeaders(csrf))
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("actor continuity cleanup deletion status=%d", response.StatusCode)
	}
	if len(state.MachineTokens) == 3 {
		for _, node := range []string{primary, secondary, tertiary} {
			assertActorContinuityInactive(t, client, node, clientSecret, state.MachineTokens[2])
			want := ""
			if state.MachineMapped {
				want = state.MachineClient.ID
			}
			assertMachineIntrospection(t, client, node, &crossClientExchanger{ID: "goauthy-dev", Secret: clientSecret}, state.MachineTokens[0], want, "")
			assertMachineIntrospection(t, client, node, &crossClientExchanger{ID: "goauthy-dev", Secret: clientSecret}, state.MachineTokens[1], want, want)
		}
	}
	for index, token := range append([]string{state.NestedToken}, state.MachineTokens...) {
		if index == 0 {
			revokeAccessToken(t, client, primary, clientSecret, token)
		} else {
			revokeAccessToken(t, client, primary, state.MachineClient.Secret, token, state.MachineClient.ID)
		}
		for _, node := range []string{primary, secondary, tertiary} {
			assertActorContinuityInactive(t, client, node, clientSecret, token)
		}
	}
	if state.MachineClient != nil {
		deleteCrossClientExchanger(t, admin, primary, rbacMutationHeaders(csrf), state.MachineClient)
	}
	if err := os.Remove(statePath); err != nil {
		t.Fatal("remove private actor continuity fixture")
	}
}

func issueActorContinuityAccessToken(t *testing.T, client *http.Client, primary, secondary, username, password, state, clientSecret string) string {
	t.Helper()
	verifier := pkceVerifier(t)
	code, _ := loginForResourceCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(verifier), username, password, state, defaultResourceIndicator)
	tokens := exchangeCode(t, client, primary, clientSecret, defaultRedirectURI, code, verifier)
	if tokens.AccessToken == "" {
		t.Fatal("actor continuity authorization-code exchange omitted an access token")
	}
	return tokens.AccessToken
}

func issueActorContinuityExchange(t *testing.T, client *http.Client, baseURL, clientSecret, source, actor string) string {
	t.Helper()
	form := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token":        {source},
		"subject_token_type":   {"urn:ietf:params:oauth:token-type:access_token"},
		"actor_token":          {actor},
		"actor_token_type":     {"urn:ietf:params:oauth:token-type:access_token"},
		"requested_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
		"scope":                {"goauthy.read"},
		"resource":             {defaultResourceIndicator},
	}
	response := tokenResponseFor(t, client, baseURL, clientSecret, form)
	var payload struct {
		AccessToken     string `json:"access_token"`
		RefreshToken    string `json:"refresh_token"`
		IDToken         string `json:"id_token"`
		TokenType       string `json:"token_type"`
		IssuedTokenType string `json:"issued_token_type"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || payload.AccessToken == "" || payload.RefreshToken != "" || payload.IDToken != "" || payload.TokenType != "bearer" || payload.IssuedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Fatalf("actor continuity exchange status=%d issued_access=%t expected_response=%t", response.StatusCode, payload.AccessToken != "", payload.RefreshToken == "" && payload.IDToken == "" && payload.TokenType == "bearer" && payload.IssuedTokenType == "urn:ietf:params:oauth:token-type:access_token")
	}
	return payload.AccessToken
}

func assertActorContinuityInactive(t *testing.T, client *http.Client, baseURL, clientSecret, token string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, baseURL+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth("goauthy-dev", clientSecret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body struct {
		Active bool `json:"active"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&body) != nil || body.Active {
		t.Fatalf("actor continuity revoked introspection status=%d inactive=%t", response.StatusCode, !body.Active)
	}
}

func writeActorContinuityState(t *testing.T, path string, state actorContinuityState) {
	t.Helper()
	if !filepath.IsAbs(path) {
		t.Fatal("actor continuity requires an absolute private fixture path")
	}
	if info, err := os.Stat(filepath.Dir(path)); err != nil || !info.IsDir() {
		t.Fatal("actor continuity fixture directory is unavailable")
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".goauthy-actor-continuity-")
	if err != nil {
		t.Fatal("create actor continuity fixture")
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		t.Fatal("protect actor continuity fixture")
	}
	if err := json.NewEncoder(file).Encode(state); err != nil {
		file.Close()
		t.Fatal("encode actor continuity fixture")
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatal("sync actor continuity fixture")
	}
	if err := file.Close(); err != nil {
		t.Fatal("close actor continuity fixture")
	}
	if err := os.Rename(temporary, path); err != nil {
		t.Fatal("replace actor continuity fixture")
	}
}

func readActorContinuityState(t *testing.T, path string) (actorContinuityState, []byte) {
	t.Helper()
	if !filepath.IsAbs(path) {
		t.Fatal("actor continuity requires an absolute private fixture path")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatal("invalid private actor continuity fixture")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal("open actor continuity fixture")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, actorContinuityMaxState+1))
	closeErr := file.Close()
	var state actorContinuityState
	if readErr != nil || closeErr != nil || len(data) > actorContinuityMaxState || json.Unmarshal(data, &state) != nil || state.Version != 1 || state.ActorSubject == "" || state.NestedToken == "" || state.SourceSubject == "" {
		t.Fatal("invalid private actor continuity fixture")
	}
	if os.Getenv("GOAUTHY_E2E_MACHINE_EXCHANGE") == "1" && (state.MachineClient == nil || state.MachineClient.ID == "" || state.MachineClient.Secret == "" || len(state.MachineTokens) != 3 || state.MachineTokens[0] == "" || state.MachineTokens[1] == "" || state.MachineTokens[2] == "" || state.MachineMapped != (os.Getenv("GOAUTHY_CLIENT_CREDENTIALS_MAP_SUB") == "true")) {
		t.Fatal("invalid private machine continuity fixture")
	}
	return state, data
}
