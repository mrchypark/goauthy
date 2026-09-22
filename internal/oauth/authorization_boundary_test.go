package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestValidateAuthorizationRequestReturnsSafeViewWithoutIssuingState(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	resource := "https://api.example.test/v1"
	server, err := NewServerWithResourceIndicators(context.Background(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, []string{resource})
	if err != nil {
		t.Fatal(err)
	}
	values := authorizationValues(strings.Repeat("c", 43), resource)
	values.Set("prompt", "login consent")
	request := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil)
	view, err := server.ValidateAuthorizationRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if view.ClientID != testClientID || view.RedirectURI != testRedirectURI || view.RequestID == "" || !sameStrings(view.RequestedScopes, []string{"goauthy.read", "offline_access"}) || !sameStrings(view.RequestedResources, []string{resource}) || !sameStrings(view.Prompt, []string{"login", "consent"}) || view.MaxAgeSeconds != nil {
		t.Fatalf("unsafe or incomplete authorize view: %#v", view)
	}
	assertNoAuthorizationState(t, db)
}

func TestValidateAuthorizationRequestPromptAndMaxAge(t *testing.T) {
	t.Parallel()
	server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
	valid := authorizationValues(strings.Repeat("f", 43), "")
	valid.Del("resource")
	valid.Set("prompt", "login consent")
	valid.Set("max_age", "60")
	view, err := server.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+valid.Encode(), nil))
	if err != nil || view.MaxAgeSeconds == nil || *view.MaxAgeSeconds != 60 || !sameStrings(view.Prompt, []string{"login", "consent"}) {
		t.Fatalf("view=%#v err=%v", view, err)
	}
	for name, values := range map[string]url.Values{
		"empty prompt":      withValue(valid, "prompt", "   "),
		"unknown prompt":    withValue(valid, "prompt", "select_account"),
		"duplicate prompt":  withValue(valid, "prompt", "login login"),
		"combined none":     withValue(valid, "prompt", "none consent"),
		"repeated prompt":   func() url.Values { v := cloneValues(valid); v["prompt"] = []string{"login", "consent"}; return v }(),
		"negative max age":  withValue(valid, "max_age", "-1"),
		"repeated max age":  func() url.Values { v := cloneValues(valid); v["max_age"] = []string{"1", "2"}; return v }(),
		"excessive max age": withValue(valid, "max_age", "31622401"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := server.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil)); err != ErrInvalidAuthorizationRequest {
				t.Fatalf("err=%v, want invalid authorization request", err)
			}
		})
	}
}

func TestValidateAuthorizationRequestRejectsMalformedInputsWithoutIssuingState(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	valid := authorizationValues(strings.Repeat("d", 43), "")
	valid.Del("resource")
	for name, values := range map[string]url.Values{
		"redirect": func() url.Values {
			v := cloneValues(valid)
			v.Set("redirect_uri", "https://attacker.example/callback")
			return v
		}(),
		"pkce": func() url.Values { v := cloneValues(valid); v.Del("code_challenge"); return v }(),
		"resource": func() url.Values {
			v := cloneValues(valid)
			v.Set("resource", "https://unknown.example.test")
			return v
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := server.ValidateAuthorizationRequest(httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil)); err != ErrInvalidAuthorizationRequest {
				t.Fatalf("err=%v, want invalid authorization request", err)
			}
			assertNoAuthorizationState(t, db)
		})
	}
}

func TestCompleteAuthorizationUsesOriginalRequestAndDeniesWithoutSubject(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	seedAccountExpiry(t, db, nil)
	server := oauthTestServer(t, db, randomSecret(t))
	values := authorizationValues(strings.Repeat("e", 43), "")
	values.Del("resource")
	original := httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil)
	if _, err := server.ValidateAuthorizationRequest(original); err != nil {
		t.Fatal(err)
	}
	denied := httptest.NewRecorder()
	server.CompleteAuthorization(denied, original, "", []string{"goauthy.read", "offline_access"})
	location, err := url.Parse(denied.Header().Get("Location"))
	if err != nil || location.Query().Get("error") != "access_denied" || location.Query().Get("code") != "" {
		t.Fatalf("denial status=%d location=%q err=%v", denied.Code, denied.Header().Get("Location"), err)
	}
	assertNoAuthorizationState(t, db)

	completed := httptest.NewRecorder()
	server.CompleteAuthorization(completed, original, "user-1", []string{"goauthy.read", "offline_access"})
	location, err = url.Parse(completed.Header().Get("Location"))
	if err != nil || location.Query().Get("error") != "" || location.Query().Get("code") == "" {
		t.Fatalf("completion status=%d location=%q err=%v", completed.Code, completed.Header().Get("Location"), err)
	}
}

func TestWriteLoginRequiredPreservesRedirectAndStateWithoutIssuingState(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	values := authorizationValues(strings.Repeat("g", 43), "")
	values.Del("resource")
	response := httptest.NewRecorder()
	server.WriteLoginRequired(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil))
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.String() == "" || location.Query().Get("error") != "login_required" || location.Query().Get("state") != values.Get("state") || location.Query().Get("code") != "" {
		t.Fatalf("login-required status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	assertNoAuthorizationState(t, db)
}

func assertNoAuthorizationState(t *testing.T, db *rhiza.DB) {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT (SELECT COUNT(*) FROM oauth_authorize_codes), (SELECT COUNT(*) FROM oauth_pkce_requests)`, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != int64(0) || result.Rows[0][1] != int64(0) {
		t.Fatalf("authorization state mutated: rows=%#v err=%v", result.Rows, err)
	}
}

func cloneValues(values url.Values) url.Values {
	copy := make(url.Values, len(values))
	for key, value := range values {
		copy[key] = append([]string(nil), value...)
	}
	return copy
}

func withValue(values url.Values, key, value string) url.Values {
	copy := cloneValues(values)
	copy.Set(key, value)
	return copy
}

func sameStrings(got, want []string) bool {
	return len(got) == len(want) && strings.Join(got, "\x00") == strings.Join(want, "\x00")
}
