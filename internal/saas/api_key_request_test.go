package saas

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

func apiKeyTestClient(server *httptest.Server) *http.Client {
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	return &http.Client{Transport: &restrictedTransport{
		base:     &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		resolver: testResolver{addrs: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}, CheckRedirect: func(*http.Request, []*http.Request) error { return errSaaSHTTP }}
}

// apiKeyConnectorTLSClient is shared by the coordinator's integration tests.
func apiKeyConnectorTLSClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	return apiKeyTestClient(server)
}

func newAPIKeyTestConnector(server *httptest.Server, fields map[string]string) *APIKeyConnector {
	c, err := NewAPIKeyConnector(APIKeyConnectorConfig{ID: "billing", Header: "authorization", Prefix: "Bearer ", Operations: []APIKeyOperationConfig{{ID: "lookup", URL: "https://example.com/result", ResponseFields: fields}}})
	if err != nil {
		panic(err)
	}
	c.client = apiKeyTestClient(server)
	return c
}

func TestAPIKeyRequestReturnsConfiguredScalarsAndFixedRequest(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/result" || r.URL.RawQuery != "" {
			t.Errorf("request = %s %s?%s", r.Method, r.URL.Path, r.URL.RawQuery)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer synthetic-key-123" {
			t.Errorf("authorization = %q", got)
		}
		if r.Header.Get("Accept") != "application/json" || r.Header.Get("User-Agent") != "GoAuthy-SaaS/0.1" {
			t.Errorf("headers = accept %q user-agent %q", r.Header.Get("Accept"), r.Header.Get("User-Agent"))
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = io.WriteString(w, `{"name":"Ada\u0020Lovelace","count":42,"enabled":true,"ignored":{"secret":1}}`)
	}))
	defer server.Close()
	c := newAPIKeyTestConnector(server, map[string]string{"name": "string", "count": "integer", "enabled": "boolean"})
	got, err := c.request(context.Background(), "lookup", credential{APIKey: "synthetic-key-123", ConnectorDigest: c.digest})
	if err != nil {
		t.Fatal(err)
	}
	if string(got["name"]) != `"Ada Lovelace"` || string(got["count"]) != "42" || string(got["enabled"]) != "true" || len(got) != 3 {
		t.Fatalf("result = %#v", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestAPIKeyRequestRawAuthorization(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "synthetic-raw-key" || r.Method != http.MethodGet || r.URL.Path != "/result" {
			t.Error("raw-key request mismatch")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"account"}`)
	}))
	defer server.Close()
	c, err := NewAPIKeyConnector(APIKeyConnectorConfig{ID: "raw", Header: "Authorization", Prefix: "", Operations: []APIKeyOperationConfig{{ID: "lookup", URL: "https://example.com/result", ResponseFields: map[string]string{"id": "string"}}}})
	if err != nil {
		t.Fatal(err)
	}
	c.client = apiKeyTestClient(server)
	result, err := c.request(t.Context(), "lookup", credential{APIKey: "synthetic-raw-key", ConnectorDigest: c.Digest()})
	if err != nil || string(result["id"]) != `"account"` || calls.Load() != 1 {
		t.Fatalf("raw-key request failed: %v", err)
	}
}

func TestAPIKeyRequestRejectsInvalidResponsesAndNeverSendsUnboundCredential(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		body        string
		status      int
		contentType string
	}{
		{"status", `{"name":"Ada"}`, http.StatusBadGateway, "application/json"},
		{"content-type", `{"name":"Ada"}`, http.StatusOK, "text/plain"},
		{"duplicate", `{"name":"Ada","name":"Grace"}`, http.StatusOK, "application/json"},
		{"trailing", `{"name":"Ada"} {}`, http.StatusOK, "application/json"},
		{"missing", `{"other":"Ada"}`, http.StatusOK, "application/json"},
		{"null", `{"name":null}`, http.StatusOK, "application/json"},
		{"type", `{"name":7}`, http.StatusOK, "application/json"},
		{"integer-fraction", `{"name":"Ada","count":1.2}`, http.StatusOK, "application/json"},
		{"secret-reflection", `{"name":"prefix synthetic-key-123"}`, http.StatusOK, "application/json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			fields := map[string]string{"name": "string"}
			if tc.name == "integer-fraction" {
				fields = map[string]string{"name": "string", "count": "integer"}
			}
			c := newAPIKeyTestConnector(server, fields)
			if _, err := c.request(context.Background(), "lookup", credential{APIKey: "synthetic-key-123", ConnectorDigest: c.digest}); !errors.Is(err, ErrAPIKeyRequest) {
				t.Fatalf("err = %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls = %d", calls.Load())
			}
		})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unexpected request") }))
	defer server.Close()
	c := newAPIKeyTestConnector(server, map[string]string{"name": "string"})
	for _, value := range []credential{{APIKey: "synthetic-key-123"}, {APIKey: "synthetic-key-123", ConnectorDigest: "other"}} {
		if _, err := c.request(context.Background(), "lookup", value); !errors.Is(err, ErrAPIKeyRequest) {
			t.Fatalf("unbound err = %v", err)
		}
	}
}

func TestAPIKeyRequestHonorsCancellation(t *testing.T) {
	t.Parallel()
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	c := newAPIKeyTestConnector(server, map[string]string{"name": "string"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := c.request(ctx, "lookup", credential{APIKey: "synthetic-key-123", ConnectorDigest: c.digest})
		result <- err
	}()
	<-started
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}

func TestAPIKeyRequestRejectsRedirectAndResponseLimits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
	}{
		{"body-limit", `{"name":"` + strings.Repeat("x", maxAPIKeyResponseBody) + `"}`},
		{"string-limit", `{"name":"` + strings.Repeat("x", maxAPIKeyString+1) + `"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			c := newAPIKeyTestConnector(server, map[string]string{"name": "string"})
			if _, err := c.request(context.Background(), "lookup", credential{APIKey: "synthetic-key-123", ConnectorDigest: c.digest}); !errors.Is(err, ErrAPIKeyRequest) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://example.com/elsewhere")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	c := newAPIKeyTestConnector(server, map[string]string{"name": "string"})
	if _, err := c.request(context.Background(), "lookup", credential{APIKey: "synthetic-key-123", ConnectorDigest: c.digest}); !errors.Is(err, ErrAPIKeyRequest) {
		t.Fatalf("redirect err = %v", err)
	}
}

func TestAPIKeyRequestIntegerStrictness(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{"1e2", "1.0", "01", "-01", "9223372036854775808", "-9223372036854775809"} {
		if _, err := validateAPIKeyResponseValue(json.RawMessage(raw), "integer", "synthetic-key"); err == nil {
			t.Errorf("accepted integer %q", raw)
		}
	}
}
