package browser

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
)

func TestMachineExchangeAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_MACHINE_EXCHANGE") != "1" {
		t.Skip("enable machine exchange E2E")
	}
	primary, secondary, username, password, secret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	exchanger := createCrossClientExchanger(t, admin, primary, headers)
	t.Cleanup(func() { deleteCrossClientExchanger(t, admin, primary, headers, exchanger) })
	client := newBrowserClient(t)
	response := tokenResponseForClient(t, client, primary, "goauthy-dev", secret, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}})
	var source crossClientTokenResponse
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&source)
	response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || source.AccessToken == "" {
		t.Fatal("machine source issuance failed")
	}
	token := source.AccessToken
	wantMachineSubject := ""
	if os.Getenv("GOAUTHY_CLIENT_CREDENTIALS_MAP_SUB") == "true" {
		wantMachineSubject = "goauthy-dev"
	}
	assertMachineIntrospection(t, client, secondary, exchanger, token, wantMachineSubject, "")
	for i := 0; i < 2; i++ {
		issued := crossClientExchange(t, client, secondary, exchanger, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {token}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}})
		claims, err := oidc.VerifyAccessToken(issued.AccessToken, publicJWKS(t, client, tertiary), primary, time.Now().UTC())
		want := ""
		if os.Getenv("GOAUTHY_CLIENT_CREDENTIALS_MAP_SUB") == "true" {
			want = exchanger.ID
		}
		if err != nil || claims.Subject != want || claims.AuthorizedParty != exchanger.ID || len(claims.Roles) != 0 || len(claims.Groups) != 0 || len(claims.CustomClaims.Values) != 0 {
			t.Fatal("machine exchange claims invalid")
		}
		assertMachineIntrospection(t, client, tertiary, exchanger, issued.AccessToken, want, "")
		token = issued.AccessToken
	}
	actorForm := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "subject_token": {source.AccessToken}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"}, "actor_token": {source.AccessToken}, "actor_token_type": {"urn:ietf:params:oauth:token-type:access_token"}}
	if os.Getenv("GOAUTHY_CLIENT_CREDENTIALS_MAP_SUB") == "true" {
		actorIssued := crossClientExchange(t, client, secondary, exchanger, actorForm)
		actorClaims, err := oidc.VerifyAccessToken(actorIssued.AccessToken, publicJWKS(t, client, tertiary), primary, time.Now().UTC())
		if err != nil || actorClaims.Actor == nil || actorClaims.Actor.Subject != "goauthy-dev" || len(actorClaims.Roles) != 0 || len(actorClaims.Groups) != 0 || len(actorClaims.CustomClaims.Values) != 0 {
			t.Fatal("mapped machine actor claims invalid")
		}
		assertMachineIntrospection(t, client, tertiary, exchanger, actorIssued.AccessToken, exchanger.ID, "goauthy-dev")
	} else {
		assertCrossClientExchangeRejected(t, client, secondary, exchanger, actorForm, "invalid_grant")
	}
}

func assertMachineIntrospection(t *testing.T, client *http.Client, base string, exchanger *crossClientExchanger, token, wantSubject, wantActor string) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, base+"/oidc/introspect", strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(exchanger.ID, exchanger.Secret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload struct {
		Active  bool   `json:"active"`
		Subject string `json:"sub"`
		Actor   struct {
			Subject string          `json:"sub"`
			Actor   json.RawMessage `json:"act"`
		} `json:"act"`
		Roles         []string                   `json:"roles"`
		Groups        []string                   `json:"groups"`
		Custom        map[string]json.RawMessage `json:"custom"`
		MachineMarker json.RawMessage            `json:"goauthy_machine_sub"`
		ActorMarker   json.RawMessage            `json:"goauthy_actor_machine"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload); err != nil || response.StatusCode != http.StatusOK || !payload.Active || payload.Subject != wantSubject || len(payload.Roles) != 0 || len(payload.Groups) != 0 || len(payload.Custom) != 0 || payload.Actor.Subject != wantActor || len(payload.Actor.Actor) != 0 {
		t.Fatalf("machine introspection status=%d active=%t subject=%q actor=%q roles=%d groups=%d custom=%d err=%v", response.StatusCode, payload.Active, payload.Subject, payload.Actor.Subject, len(payload.Roles), len(payload.Groups), len(payload.Custom), err)
	}
	if len(payload.MachineMarker) != 0 || len(payload.ActorMarker) != 0 {
		t.Fatal("introspection exposed private machine markers")
	}
}
