package upstreamprovider

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/netsec"
)

func TestSafeHTTPClientBlocksLoopbackAndMetadataDial(t *testing.T) {
	t.Parallel()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	blocked := netsec.NewSafeHTTPClient(time.Second, false, nil)
	for _, target := range []string{srv.URL, "https://169.254.169.254/latest/meta-data/"} {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := blocked.Do(req)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("expected safe HTTP client to block %s", target)
		}
		if !errors.Is(err, netsec.ErrUnsafeHost) {
			t.Fatalf("target=%s expected ErrUnsafeHost, got %v", target, err)
		}
	}

	allowed := netsec.NewSafeHTTPClient(time.Second, true, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := allowed.Do(req)
	if err != nil {
		t.Fatalf("expected allowPrivate=true client to reach loopback TLS server, got %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want=200", resp.StatusCode)
	}
}

func TestOAuth2ExchangerIsolatesAllowPrivatePerProvider(t *testing.T) {
	t.Parallel()
	exchanger, err := NewOAuth2TokenExchanger(map[string]Config{
		"internal": {
			Issuer:                "https://internal.example.test",
			AuthorizationEndpoint: "https://internal.example.test/auth",
			TokenEndpoint:         "https://127.0.0.1:8443/token",
			ClientID:              "c1",
			AllowPrivate:          true,
		},
		"public": {
			Issuer:                "https://public.example.test",
			AuthorizationEndpoint: "https://public.example.test/auth",
			TokenEndpoint:         "https://127.0.0.1:8443/token",
			ClientID:              "c2",
			AllowPrivate:          false,
		},
	}, map[string]string{
		"internal": "secret-1",
		"public":   "secret-2",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if exchanger.httpClient(exchanger.configs["internal"]) == exchanger.httpClient(exchanger.configs["public"]) {
		t.Fatal("expected AllowPrivate=true and AllowPrivate=false providers to use distinct HTTP clients")
	}
	if _, err := exchanger.ExchangeCode(context.Background(), "public", "https://app.example.test/cb", "code", "verifier"); err == nil {
		t.Fatal("expected public provider with AllowPrivate=false to fail dialing loopback")
	}
}
