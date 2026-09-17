package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fixtureState() *state {
	return newState(config{
		clientID:           "https://cimd.e2e.test/good",
		redirectURI:        "https://cimd.e2e.test/callback",
		privateRedirectURL: "https://127.0.0.1/sentinel",
	})
}

func TestFixtureDocumentsAndSynchronousAdminState(t *testing.T) {
	s := fixtureState()
	h := s.documentHandler()

	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/good", nil))
	if get.Code != http.StatusOK || get.Header().Get("Cache-Control") != "public, max-age=600" {
		t.Fatalf("good response = %d headers=%v", get.Code, get.Header())
	}
	var doc struct {
		ClientID     string   `json:"client_id"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &doc); err != nil || doc.ClientID != "https://cimd.e2e.test/good" || len(doc.RedirectURIs) != 1 || doc.RedirectURIs[0] != "https://cimd.e2e.test/callback" {
		t.Fatalf("document=%s err=%v", get.Body.String(), err)
	}

	head := httptest.NewRecorder()
	h.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/good", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") == "" {
		t.Fatalf("head response=%d body=%q headers=%v", head.Code, head.Body.String(), head.Header())
	}

	admin := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/document", strings.NewReader(`{"mode":"invalid"}`))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	s.adminHandler().ServeHTTP(admin, req)
	if admin.Code != http.StatusNoContent {
		t.Fatalf("admin document status=%d", admin.Code)
	}
	invalid := httptest.NewRecorder()
	h.ServeHTTP(invalid, httptest.NewRequest(http.MethodGet, "/good", nil))
	if invalid.Code != http.StatusOK || json.Valid(invalid.Body.Bytes()) {
		t.Fatalf("mutable invalid body=%q status=%d", invalid.Body.String(), invalid.Code)
	}

	reset := httptest.NewRecorder()
	s.adminHandler().ServeHTTP(reset, httptest.NewRequest(http.MethodPost, "/admin/reset", nil))
	if reset.Code != http.StatusNoContent {
		t.Fatalf("reset status=%d", reset.Code)
	}
	state := httptest.NewRecorder()
	s.adminHandler().ServeHTTP(state, httptest.NewRequest(http.MethodGet, "/admin/state", nil))
	var got struct {
		Requests int    `json:"requests"`
		Mode     string `json:"mode"`
		Version  int    `json:"document_version"`
	}
	if err := json.Unmarshal(state.Body.Bytes(), &got); err != nil || got.Requests != 0 || got.Mode != "valid" || got.Version != 1 {
		t.Fatalf("reset state=%s parsed=%+v err=%v", state.Body.String(), got, err)
	}
}

func TestPathBoundDocuments(t *testing.T) {
	s := fixtureState()
	h := s.documentHandler()
	for _, path := range []string{"/allow", "/deny", "/recovery"} {
		t.Run(path, func(t *testing.T) {
			response := httptest.NewRecorder()
			h.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			var doc struct {
				ClientID     string   `json:"client_id"`
				RedirectURIs []string `json:"redirect_uris"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &doc); response.Code != http.StatusOK || err != nil || doc.ClientID != "https://cimd.e2e.test"+path || len(doc.RedirectURIs) != 1 || doc.RedirectURIs[0] != "https://cimd.e2e.test/callback" {
				t.Fatalf("response=%d document=%s parsed=%+v err=%v", response.Code, response.Body.String(), doc, err)
			}
		})
	}
	state := httptest.NewRecorder()
	s.adminHandler().ServeHTTP(state, httptest.NewRequest(http.MethodGet, "/admin/state", nil))
	var got struct {
		Requests int `json:"requests"`
	}
	if err := json.Unmarshal(state.Body.Bytes(), &got); err != nil || got.Requests != 3 {
		t.Fatalf("state=%s parsed=%+v err=%v", state.Body.String(), got, err)
	}
}

func TestPrivateRedirectSentinelIsARealNoRedirectOracle(t *testing.T) {
	s := fixtureState()
	server := httptest.NewTLSServer(s.documentHandler())
	defer server.Close()
	address := strings.TrimPrefix(server.URL, "https://")
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // local fixture certificate
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return net.Dial("tcp", address)
		},
	}
	defer transport.CloseIdleConnections()

	noRedirect := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := noRedirect.Get(server.URL + "/redirect-private")
	if err != nil || response.StatusCode != http.StatusFound {
		t.Fatalf("no redirect response=%v err=%v", response, err)
	}
	_ = response.Body.Close()
	if s.negative.Sentinel != 0 {
		t.Fatalf("sentinel hit after no-redirect request=%d", s.negative.Sentinel)
	}

	follows := &http.Client{Transport: transport}
	response, err = follows.Get(server.URL + "/redirect-private")
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("follow response=%v err=%v", response, err)
	}
	_ = response.Body.Close()
	if s.negative.Sentinel != 1 {
		t.Fatalf("sentinel hits=%d want 1", s.negative.Sentinel)
	}
}

func TestFixtureRejectsInvalidRequestsAndConfig(t *testing.T) {
	s := fixtureState()
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/good", http.StatusMethodNotAllowed},
		{http.MethodGet, "/good?x=1", http.StatusBadRequest},
		{http.MethodGet, "/admin/document", http.StatusMethodNotAllowed},
		{http.MethodPost, "/admin/reset", http.StatusNoContent},
	} {
		response := httptest.NewRecorder()
		handler := s.documentHandler()
		if strings.HasPrefix(tc.path, "/admin/") {
			handler = s.adminHandler()
		}
		handler.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
		if response.Code != tc.want {
			t.Fatalf("%s %s = %d want %d", tc.method, tc.path, response.Code, tc.want)
		}
	}
	for _, private := range []string{"https://example.com/sentinel", "https://localhost/sentinel", "mailto:test@example.com"} {
		if privateHTTPURL(private) == nil {
			t.Fatalf("private redirect accepted %q", private)
		}
	}
	if err := loopbackAddr("0.0.0.0:8082"); err == nil {
		t.Fatal("public admin address accepted")
	}
	env := map[string]string{
		"CIMD_FIXTURE_TLS_CERT_FILE": "/cert",
		"CIMD_FIXTURE_TLS_KEY_FILE":  "/key",
		"CIMD_FIXTURE_CLIENT_ID":     "https://cimd.e2e.test/good",
		"CIMD_FIXTURE_REDIRECT_URI":  "https://cimd.e2e.test/callback",
	}
	if got, err := configFromEnv(func(key string) string { return env[key] }); err != nil || got.privateRedirectURL != "https://127.0.0.1/sentinel" || got.adminAddr != adminAddr {
		t.Fatalf("config=%+v err=%v", got, err)
	}
	env["CIMD_FIXTURE_REDIRECT_URI"] = "https://other.e2e.test/callback"
	if _, err := configFromEnv(func(key string) string { return env[key] }); err == nil {
		t.Fatal("cross-origin redirect URI accepted")
	}
}
