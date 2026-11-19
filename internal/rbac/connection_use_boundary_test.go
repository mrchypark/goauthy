package rbac

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mrchypark/goauthy/internal/saas"
)

func TestWriteInvokeErrorMappings(t *testing.T) {
	t.Parallel()
	var h Handler
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{"unauthorized", saas.ErrCredentialUnauthorized, http.StatusInternalServerError},
		{"corrupted", saas.ErrCredentialCorrupted, http.StatusInternalServerError},
		{"not_found", saas.ErrCredentialNotFound, http.StatusNotFound},
		{"grant_not_found", saas.ErrUseGrantNotFound, http.StatusNotFound},
		{"conflict", saas.ErrUseGrantConflict, http.StatusConflict},
		{"invalid", saas.ErrUseGrantInvalid, http.StatusBadRequest},
		{"gateway_apikey", saas.ErrAPIKeyRequest, http.StatusBadGateway},
		{"gateway_refresh_uncertain", saas.ErrRefreshUncertain, http.StatusBadGateway},
		{"other", errors.New("backend down"), http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.writeInvokeError(w, tc.err)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
		})
	}
}

func TestInvokeConnectionGrantChecksIssuerBeforeMethod(t *testing.T) {
	t.Parallel()
	h, store, _, _ := membershipHTTPFixture(t)
	h.issuer = "http://insecure.example.test"
	if err := h.BindSaaSCredentials(oauthCredentialHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseResource("https://resource.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseAuthorizer(func(http.ResponseWriter, *http.Request) (string, string, func() (string, []any), bool) {
		return "owner", "consumer", func() (string, []any) { return "1", nil }, true
	}); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/auth/v1/connection-grants/g/invoke", nil)
	w := httptest.NewRecorder()
	h.InvokeConnectionGrant(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=%d", w.Code, http.StatusServiceUnavailable)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control=%q want=no-store", w.Header().Get("Cache-Control"))
	}
}
