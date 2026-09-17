package browser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
)

const (
	crossClientDefaultAudienceA = "https://cross-client-default-a.example.test/v1"
	crossClientDefaultAudienceB = "https://cross-client-default-b.example.test/v1"
)

func TestCrossClientExchangeLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_CROSS_CLIENT_EXCHANGE") != "1" {
		t.Skip("set GOAUTHY_E2E_CROSS_CLIENT_EXCHANGE=1 to run cross-client token-exchange E2E")
	}
	primary, secondary, username, password, bootstrapSecret := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	redirectURI := os.Getenv("GOAUTHY_E2E_BROWSER_REDIRECT_URI")
	if redirectURI == "" {
		redirectURI = defaultRedirectURI
	}

	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	exchanger := createCrossClientExchanger(t, admin, primary, headers)
	t.Cleanup(func() { deleteCrossClientExchanger(t, admin, primary, headers, exchanger) })

	sourceClient := newBrowserClient(t)
	verifier := pkceVerifier(t)
	code, _ := loginForResourceCode(t, sourceClient, primary, secondary, redirectURI, pkceChallenge(verifier), username, password, "cross-client-exchange-source", defaultResourceIndicator)
	source := exchangeCode(t, sourceClient, primary, bootstrapSecret, redirectURI, code, verifier)
	if source.AccessToken == "" {
		t.Fatal("bootstrap authorization-code flow did not issue a source access token")
	}

	exchangeForm := func() url.Values {
		return url.Values{
			"grant_type":         {"urn:ietf:params:oauth:grant-type:token-exchange"},
			"subject_token":      {source.AccessToken},
			"subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
			"scope":              {"goauthy.read"},
		}
	}
	defaults := []string{exchanger.ID, crossClientDefaultAudienceA, crossClientDefaultAudienceB}
	issued := crossClientExchange(t, newBrowserClient(t), secondary, exchanger, exchangeForm())
	assertCrossClientExchangeToken(t, newBrowserClient(t), tertiary, primary, exchanger, issued.AccessToken, defaults)

	delegatedForm := exchangeForm()
	delegatedForm.Set("actor_token", source.AccessToken)
	delegatedForm.Set("actor_token_type", "urn:ietf:params:oauth:token-type:access_token")
	delegated := crossClientExchange(t, newBrowserClient(t), secondary, exchanger, delegatedForm)
	assertCrossClientExchangeToken(t, newBrowserClient(t), tertiary, primary, exchanger, delegated.AccessToken, defaults)
	delegatedClaims, err := oidc.VerifyAccessToken(delegated.AccessToken, publicJWKS(t, newBrowserClient(t), tertiary), primary, time.Now().UTC())
	if err != nil || delegatedClaims.Actor == nil || delegatedClaims.Actor.Subject != delegatedClaims.Subject || delegatedClaims.Actor.Actor != nil {
		t.Fatal("cross-client delegated JWT did not preserve its validated actor")
	}

	resource := exchangeForm()
	resource.Set("resource", defaultResourceIndicator)
	resourceIssued := crossClientExchange(t, newBrowserClient(t), secondary, exchanger, resource)
	assertCrossClientExchangeToken(t, newBrowserClient(t), tertiary, primary, exchanger, resourceIssued.AccessToken, append(append([]string{}, defaults...), defaultResourceIndicator))

	alias := exchangeForm()
	alias.Set("audience", defaultResourceIndicator)
	aliased := crossClientExchange(t, newBrowserClient(t), secondary, exchanger, alias)
	assertCrossClientExchangeToken(t, newBrowserClient(t), tertiary, primary, exchanger, aliased.AccessToken, append(append([]string{}, defaults...), defaultResourceIndicator))

	for _, tc := range []struct {
		name string
		form url.Values
		want string
	}{
		{"disallowed target", func() url.Values {
			form := exchangeForm()
			form.Set("resource", "https://cross-client-unallowed.example.test/v1")
			return form
		}(), "invalid_target"},
		{"resource and audience", func() url.Values {
			form := exchangeForm()
			form.Set("resource", defaultResourceIndicator)
			form.Set("audience", defaultResourceIndicator)
			return form
		}(), "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertCrossClientExchangeRejected(t, newBrowserClient(t), secondary, exchanger, tc.form, tc.want)
		})
	}

	updateCrossClientExchanger(t, admin, primary, headers, exchanger, []string{})
	assertCrossClientExchangeInactive(t, newBrowserClient(t), tertiary, exchanger, issued.AccessToken)
	reissued := crossClientExchange(t, newBrowserClient(t), secondary, exchanger, exchangeForm())
	assertCrossClientExchangeToken(t, newBrowserClient(t), tertiary, primary, exchanger, reissued.AccessToken, []string{exchanger.ID})
}

type crossClientExchanger struct {
	ID       string
	Secret   string
	Revision int64
}

func createCrossClientExchanger(t *testing.T, admin *http.Client, primary string, headers map[string]string, grants ...string) *crossClientExchanger {
	t.Helper()
	id := "cross-client-exchanger-" + randomManagedUIID(t)
	if len(grants) == 0 {
		grants = []string{"urn:ietf:params:oauth:grant-type:token-exchange"}
	}
	body, err := json.Marshal(map[string]any{
		"id":             id,
		"name":           "Cross-client exchange E2E",
		"confidential":   true,
		"redirect_uris":  []string{},
		"audience":       []string{defaultResourceIndicator},
		"default_aud":    []string{crossClientDefaultAudienceA, crossClientDefaultAudienceB},
		"scopes":         []string{"goauthy.read"},
		"default_scopes": []string{"goauthy.read"},
		"enabled_flows":  grants,
	})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, admin, http.MethodPost, primary+"/auth/v1/clients", bytes.NewReader(body), headers)
	var created struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&created)
	response.Body.Close()
	if response.StatusCode != http.StatusCreated || err != nil || created.ID != id || created.Revision <= 0 {
		t.Fatalf("cross-client exchanger create status=%d id_matches=%t revision=%d decode=%v", response.StatusCode, created.ID == id, created.Revision, err)
	}
	exchanger := &crossClientExchanger{ID: id, Revision: created.Revision}
	secretResponse := do(t, admin, http.MethodPost, primary+"/auth/v1/clients/"+url.PathEscape(id)+"/secret", nil, sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(exchanger.Revision, 10))))
	var secret struct {
		Secret string `json:"secret"`
	}
	err = json.NewDecoder(io.LimitReader(secretResponse.Body, 8<<10)).Decode(&secret)
	secretResponse.Body.Close()
	if secretResponse.StatusCode != http.StatusOK || err != nil || secret.Secret == "" {
		t.Fatalf("cross-client exchanger secret status=%d present=%t decode=%v", secretResponse.StatusCode, secret.Secret != "", err)
	}
	exchanger.Secret = secret.Secret
	exchanger.Revision = revisionFromETag(t, secretResponse.Header.Get("ETag"), exchanger.Revision)
	return exchanger
}

func updateCrossClientExchanger(t *testing.T, admin *http.Client, primary string, headers map[string]string, exchanger *crossClientExchanger, defaults []string) {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"name":           "Cross-client exchange E2E",
		"confidential":   true,
		"enabled":        true,
		"redirect_uris":  []string{},
		"audience":       []string{defaultResourceIndicator},
		"default_aud":    defaults,
		"scopes":         []string{"goauthy.read"},
		"default_scopes": []string{"goauthy.read"},
		"enabled_flows":  []string{"urn:ietf:params:oauth:grant-type:token-exchange"},
	})
	if err != nil {
		t.Fatal(err)
	}
	response := do(t, admin, http.MethodPut, primary+"/auth/v1/clients/"+url.PathEscape(exchanger.ID), bytes.NewReader(body), sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(exchanger.Revision, 10))))
	var updated struct {
		Revision int64 `json:"revision"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&updated)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || err != nil || updated.Revision <= exchanger.Revision {
		t.Fatalf("cross-client exchanger update status=%d revision=%d prior=%d decode=%v", response.StatusCode, updated.Revision, exchanger.Revision, err)
	}
	exchanger.Revision = updated.Revision
}

func deleteCrossClientExchanger(t *testing.T, admin *http.Client, primary string, headers map[string]string, exchanger *crossClientExchanger) {
	t.Helper()
	response := do(t, admin, http.MethodDelete, primary+"/auth/v1/clients/"+url.PathEscape(exchanger.ID), nil, sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(exchanger.Revision, 10))))
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Errorf("cross-client exchanger cleanup status=%d", response.StatusCode)
	}
}

type crossClientTokenResponse struct {
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	IDToken         string `json:"id_token"`
	TokenType       string `json:"token_type"`
	IssuedTokenType string `json:"issued_token_type"`
}

func crossClientExchange(t *testing.T, client *http.Client, base string, exchanger *crossClientExchanger, form url.Values) crossClientTokenResponse {
	t.Helper()
	response := tokenResponseForClient(t, client, base, exchanger.ID, exchanger.Secret, form)
	defer response.Body.Close()
	var issued crossClientTokenResponse
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&issued)
	if response.StatusCode != http.StatusOK || err != nil || issued.AccessToken == "" || issued.RefreshToken != "" || issued.IDToken != "" || issued.TokenType != "bearer" || issued.IssuedTokenType != "urn:ietf:params:oauth:token-type:access_token" {
		t.Fatalf("cross-client exchange status=%d access=%t refresh=%t id=%t type=%q issued_type=%q decode=%v", response.StatusCode, issued.AccessToken != "", issued.RefreshToken != "", issued.IDToken != "", issued.TokenType, issued.IssuedTokenType, err)
	}
	return issued
}

func assertCrossClientExchangeRejected(t *testing.T, client *http.Client, base string, exchanger *crossClientExchanger, form url.Values, want string) {
	t.Helper()
	response := tokenResponseForClient(t, client, base, exchanger.ID, exchanger.Secret, form)
	defer response.Body.Close()
	var payload struct {
		Error string `json:"error"`
	}
	err := json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload)
	if response.StatusCode != http.StatusBadRequest || err != nil || payload.Error != want {
		t.Fatalf("cross-client exchange rejection status=%d error=%q want=%q decode=%v", response.StatusCode, payload.Error, want, err)
	}
}

func assertCrossClientExchangeToken(t *testing.T, client *http.Client, introspectionBase, issuer string, exchanger *crossClientExchanger, token string, wantAudience []string) {
	t.Helper()
	if strings.Count(token, ".") != 2 {
		t.Fatal("cross-client access token is not a compact JWT")
	}
	claims, err := oidc.VerifyAccessToken(token, publicJWKS(t, client, introspectionBase), issuer, time.Now().UTC())
	if err != nil || claims.Issuer != issuer || claims.AuthorizedParty != exchanger.ID || !slices.Equal(claims.Audience, wantAudience) || !slices.Equal(claims.Scope, []string{"goauthy.read"}) || claims.Type != "Bearer" || claims.ConfirmationJKT != "" || claims.Subject == "" || claims.ID == "" {
		t.Fatalf("cross-client JWT valid=%t issuer=%t azp=%t audience=%t scope=%t bearer=%t unbound=%t subject=%t id=%t", err == nil, claims.Issuer == issuer, claims.AuthorizedParty == exchanger.ID, slices.Equal(claims.Audience, wantAudience), slices.Equal(claims.Scope, []string{"goauthy.read"}), claims.Type == "Bearer", claims.ConfirmationJKT == "", claims.Subject != "", claims.ID != "")
	}
	// Fosite introspection exposes granted resource audiences and client_id
	// separately; the signed JWT additionally includes that client ID in aud.
	assertCrossClientExchangeIntrospection(t, client, introspectionBase, exchanger, token, wantAudience[1:], true)
}

func assertCrossClientExchangeInactive(t *testing.T, client *http.Client, base string, exchanger *crossClientExchanger, token string) {
	t.Helper()
	assertCrossClientExchangeIntrospection(t, client, base, exchanger, token, nil, false)
}

func assertCrossClientExchangeIntrospection(t *testing.T, client *http.Client, base string, exchanger *crossClientExchanger, token string, wantAudience []string, active bool) {
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
		Active   bool     `json:"active"`
		ClientID string   `json:"client_id"`
		Subject  string   `json:"sub"`
		Scope    string   `json:"scope"`
		Audience []string `json:"aud"`
	}
	err = json.NewDecoder(io.LimitReader(response.Body, 8<<10)).Decode(&payload)
	if response.StatusCode != http.StatusOK || err != nil || payload.Active != active {
		t.Fatalf("cross-client introspection status=%d active=%t want_active=%t decode=%v", response.StatusCode, payload.Active, active, err)
	}
	slices.Sort(payload.Audience)
	wantAudience = slices.Clone(wantAudience)
	slices.Sort(wantAudience)
	if active && (payload.ClientID != exchanger.ID || payload.Subject == "" || payload.Scope != "goauthy.read" || !slices.Equal(payload.Audience, wantAudience)) {
		t.Fatalf("cross-client introspection client=%t subject=%t scope=%t audience=%t", payload.ClientID == exchanger.ID, payload.Subject != "", payload.Scope == "goauthy.read", slices.Equal(payload.Audience, wantAudience))
	}
}
