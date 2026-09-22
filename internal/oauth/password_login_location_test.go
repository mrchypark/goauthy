package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/dcr"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
)

func TestPasswordLoginObserverHTTP(t *testing.T) {
	t.Parallel()
	db := oauthTestDB(t)
	users, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	phc, err := credential.Hash([]byte("correct password"))
	if err != nil {
		t.Fatal(err)
	}
	const subject = "password-observer-subject"
	if _, err := users.BootstrapUser(t.Context(), subject, "alice", phc); err != nil {
		t.Fatal(err)
	}
	server, err := NewServerWithOIDC(t.Context(), db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer:          oidcTestIssuer,
		PasswordUsers:   users,
		ValidateSubject: users.ValidateSubject,
		LoadSigningKey:  func(context.Context) (oidc.SigningKey, error) { return oidcTestKey(t), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := server.store.dynamicClients.Create(t.Context(), dcr.CreateRequest{
		ClientID:                "password-observer-client",
		GrantTypes:              []string{"password"},
		Scopes:                  []string{"profile"},
		DefaultScopes:           []string{"profile"},
		TokenEndpointAuthMethod: dcr.TokenEndpointAuthClientBasic,
		Name:                    "Password observer test client",
	})
	if err != nil {
		t.Fatal(err)
	}

	var calls int
	var gotMethod, gotPath, gotUsername, gotSubject string
	fail := false
	server.SetPasswordLoginObserver(func(w http.ResponseWriter, r *http.Request, observedSubject string) error {
		calls++
		gotMethod, gotPath, gotUsername, gotSubject = r.Method, r.URL.Path, r.PostForm.Get("username"), observedSubject
		w.Header().Set("X-Password-Observer", "called")
		if fail {
			return errors.New("observer failed")
		}
		return nil
	})
	postPassword := func(password string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type": {"password"},
			"client_id":  {client.ClientID},
			"username":   {"alice"},
			"password":   {password},
		}
		r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("X-Test-Request", "password-observer")
		r.SetBasicAuth(client.ClientID, client.ClientSecret)
		w := httptest.NewRecorder()
		server.TokenHandler().ServeHTTP(&passwordDeadlineRecorder{ResponseRecorder: w}, r)
		return w
	}

	success := postPassword("correct password")
	if success.Code != http.StatusOK || success.Header().Get("X-Password-Observer") != "called" {
		t.Fatalf("password success status=%d observer=%q", success.Code, success.Header().Get("X-Password-Observer"))
	}
	if calls != 1 || gotMethod != http.MethodPost || gotPath != "/oidc/token" || gotUsername != "alice" || gotSubject != subject {
		t.Fatalf("observer calls=%d method=%q path=%q username=%q subject=%q", calls, gotMethod, gotPath, gotUsername, gotSubject)
	}

	if wrong := postPassword("wrong password"); wrong.Code == http.StatusOK || calls != 1 {
		t.Fatalf("wrong password status=%d observer calls=%d", wrong.Code, calls)
	}
	if other := postToken(server, url.Values{"grant_type": {"client_credentials"}}); other.Code != http.StatusOK || calls != 1 {
		t.Fatalf("other grant status=%d observer calls=%d", other.Code, calls)
	}

	fail = true
	observerError := postPassword("correct password")
	if observerError.Code != http.StatusInternalServerError || strings.Contains(observerError.Body.String(), "access_token") || calls != 2 {
		t.Fatalf("observer error status=%d calls=%d", observerError.Code, calls)
	}
}
