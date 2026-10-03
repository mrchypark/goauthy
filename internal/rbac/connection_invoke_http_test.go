package rbac

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/saas"
	"github.com/mrchypark/rhiza"
)

func TestBindConnectionUseAuthorizerRejectsNil(t *testing.T) {
	t.Parallel()
	h, _, _, _ := membershipHTTPFixture(t)
	if err := h.BindConnectionUseAuthorizer(nil); err == nil {
		t.Fatal("nil authorizer accepted")
	}
	var nilHandler *Handler
	if err := nilHandler.BindConnectionUseAuthorizer(func(*http.Request) (string, string, func() (string, []any), error) {
		return "", "", nil, nil
	}); err == nil {
		t.Fatal("nil handler accepted")
	}
}

func TestConnectionUseFailureLogRedactsDetailsAndPreservesStatus(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	const secret = "synthetic-private-error-detail"
	logConnectionUseFailure("credential_preflight", errors.New(secret))
	if strings.Contains(output.String(), secret) || !strings.Contains(output.String(), "stage=credential_preflight") || !strings.Contains(output.String(), "error_class=unknown") {
		t.Fatalf("unsafe or incomplete diagnostic: %s", output.String())
	}

	var h Handler
	for _, tc := range []struct {
		err  error
		want int
	}{
		{saas.ErrAPIKeyRequest, http.StatusBadGateway},
		{errors.New(secret), http.StatusServiceUnavailable},
	} {
		w := httptest.NewRecorder()
		h.writeInvokeError(w, tc.err)
		if w.Code != tc.want {
			t.Errorf("error response status=%d want=%d", w.Code, tc.want)
		}
	}
}

func TestInvokeConnectionGrantAuthorizationFailureIsRedactedAndUnauthorized(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&output, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	h, store, _, _ := membershipHTTPFixture(t)
	if err := h.BindSaaSCredentials(oauthCredentialHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseResource("https://resource.example.test"); err != nil {
		t.Fatal(err)
	}
	const secret = "private-auth-storage-detail"
	if err := h.BindConnectionUseAuthorizer(func(*http.Request) (string, string, func() (string, []any), error) {
		return "", "", nil, fmt.Errorf("%s: %w", secret, rhiza.ErrDurabilityUnavailable)
	}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/auth/v1/connection-grants/grant/invoke", strings.NewReader(`{"operation":"read"}`))
	request.SetPathValue("grant_id", "grant")
	request.Header.Set("Authorization", "Bearer synthetic")
	response := httptest.NewRecorder()
	h.InvokeConnectionGrant(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want=%d", response.Code, http.StatusUnauthorized)
	}
	if got := output.String(); !strings.Contains(got, "stage=resource_authorization") || !strings.Contains(got, "error_class=durability_unavailable") || strings.Contains(got, secret) {
		t.Fatalf("unexpected authorization diagnostic: %s", got)
	}

	output.Reset()
	if err := h.BindConnectionUseAuthorizer(func(*http.Request) (string, string, func() (string, []any), error) {
		return "owner", "consumer", nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "/auth/v1/connection-grants/grant/invoke", strings.NewReader(`{"operation":"read"}`))
	request.SetPathValue("grant_id", "grant")
	request.Header.Set("Authorization", "Bearer synthetic")
	response = httptest.NewRecorder()
	h.InvokeConnectionGrant(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(output.String(), "stage=authorizer_contract") {
		t.Fatalf("contract denial status=%d diagnostics=%s", response.Code, output.String())
	}

	output.Reset()
	request = httptest.NewRequest(http.MethodPost, "/auth/v1/connection-grants/grant/invoke", strings.NewReader(`{"operation":"read"}`))
	request.SetPathValue("grant_id", "grant")
	request.Header.Set("Authorization", "Bearer synthetic")
	request.Header.Set("Cookie", secret)
	response = httptest.NewRecorder()
	h.InvokeConnectionGrant(response, request)
	if response.Code != http.StatusUnauthorized || !strings.Contains(output.String(), "stage=cookie_header") || strings.Contains(output.String(), secret) {
		t.Fatalf("pre-grant denial status=%d diagnostics=%s", response.Code, output.String())
	}
}

func TestInvokeConnectionGrantHTTPBoundary(t *testing.T) {
	t.Parallel()
	h, store, _, _ := membershipHTTPFixture(t)
	if err := h.BindSaaSCredentials(oauthCredentialHTTPStore(t, store)); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseResource("https://resource.example.test"); err != nil {
		t.Fatal(err)
	}
	if err := h.BindConnectionUseAuthorizer(func(*http.Request) (string, string, func() (string, []any), error) {
		return "owner", "consumer", func() (string, []any) { return "1", nil }, nil
	}); err != nil {
		t.Fatal(err)
	}
	request := func(path, body string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.SetPathValue("grant_id", "grant")
		r.Header.Set("Authorization", "Bearer test")
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	for name, alter := range map[string]func(*http.Request){
		"query":                   func(r *http.Request) { r.URL.RawQuery = "x=1" },
		"force query":             func(r *http.Request) { r.URL.ForceQuery = true },
		"empty cookie":            func(r *http.Request) { r.Header["Cookie"] = []string{""} },
		"duplicate authorization": func(r *http.Request) { r.Header.Add("Authorization", "Bearer second") },
		"missing authorization":   func(r *http.Request) { r.Header.Del("Authorization") },
		"unknown body field": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"operation":"read","owner":"x"}`))
		},
		"noncanonical operation": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"operation":"Read"}`))
		},
		"missing operation": func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{}`)) },
		"duplicate operation": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"operation":"read","operation":"read"}`))
		},
		"null operation": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"operation":null}`))
		},
		"oversize body": func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(`{"operation":"` + strings.Repeat("x", 8192) + `"}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := request("/auth/v1/connection-grants/grant/invoke", `{"operation":"read"}`)
			alter(r)
			w := httptest.NewRecorder()
			h.InvokeConnectionGrant(w, r)
			want := http.StatusUnauthorized
			if name == "unknown body field" || name == "noncanonical operation" || name == "missing operation" || name == "duplicate operation" || name == "null operation" || name == "oversize body" {
				want = http.StatusBadRequest
			}
			if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body.String())
			}
		})
	}
}
