// Package favicon exercises the deployed favicon contract, including an
// issuer mounted below the public root and replacement-pod continuity.
package favicon

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type e2eConfig struct {
	issuer, secondary, origin string
	client                    *http.Client
	expected                  []byte
	stateFile                 string
}

type faviconResponse struct {
	body      []byte
	etag      string
	contentTy string
}

type faviconState struct {
	Body []byte `json:"body"`
	ETag string `json:"etag"`
}

func TestFaviconStateArtifactRoundTrip(t *testing.T) {
	c := e2eConfig{stateFile: filepath.Join(t.TempDir(), "favicon-state.json")}
	want := faviconResponse{body: []byte{0, 1, 2, 255}, etag: `"fixture-etag"`}
	writeState(t, c, want)
	got := readState(t, c)
	if !bytes.Equal(got.Body, want.body) || got.ETag != want.etag {
		t.Fatalf("state artifact changed response: etag=%q body=%v", got.ETag, got.Body)
	}
}

func TestFaviconContractAcrossPods(t *testing.T) {
	c := config(t)
	first := assertFavicon(t, c, c.issuer)
	second := assertFavicon(t, c, c.secondary)
	if !bytes.Equal(first.body, second.body) || first.etag != second.etag {
		t.Fatalf("favicon differs across pods: etag %q/%q body %d/%d", first.etag, second.etag, len(first.body), len(second.body))
	}
	if c.expected != nil && !bytes.Equal(first.body, c.expected) {
		t.Fatalf("favicon response differs from mounted fixture: got %d bytes want %d", len(first.body), len(c.expected))
	}

	for _, endpoint := range []string{c.issuer, c.secondary} {
		assertHead(t, c.client, endpoint+"/favicon.ico", first)
		assertNotModified(t, c.client, endpoint+"/favicon.ico", first)
		assertMethodNotAllowed(t, c.client, endpoint+"/favicon.ico")
	}
	assertRootIsolation(t, c)
	writeState(t, c, first)
}

// TestFaviconPostReplacement is run by the Kind harness after replacing
// goauthy-0. The fixture and immutable ETag must survive the pod change.
func TestFaviconPostReplacement(t *testing.T) {
	c := config(t)
	saved := readState(t, c)
	first := assertFavicon(t, c, c.issuer)
	second := assertFavicon(t, c, c.secondary)
	if first.etag != saved.ETag || !bytes.Equal(first.body, saved.Body) {
		t.Fatalf("replacement favicon differs from pre-replacement state: etag %q/%q body %d/%d", first.etag, saved.ETag, len(first.body), len(saved.Body))
	}
	if second.etag != saved.ETag || !bytes.Equal(second.body, saved.Body) {
		t.Fatalf("replacement secondary favicon differs from pre-replacement state: etag %q/%q body %d/%d", second.etag, saved.ETag, len(second.body), len(saved.Body))
	}
	assertHead(t, c.client, c.issuer+"/favicon.ico", first)
	assertNotModified(t, c.client, c.issuer+"/favicon.ico", first)
	assertMethodNotAllowed(t, c.client, c.issuer+"/favicon.ico")
	assertRootIsolation(t, c)
}

func config(t *testing.T) e2eConfig {
	t.Helper()
	issuer := strings.TrimRight(os.Getenv("GOAUTHY_E2E_FAVICON_URL"), "/")
	secondary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_FAVICON_SECONDARY_URL"), "/")
	caFile := os.Getenv("GOAUTHY_E2E_CA_FILE")
	if issuer == "" || secondary == "" || caFile == "" {
		t.Skip("set GOAUTHY_E2E_FAVICON_URL, GOAUTHY_E2E_FAVICON_SECONDARY_URL, and GOAUTHY_E2E_CA_FILE to run favicon E2E")
	}
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Path == "" || u.Path == "/" {
		t.Fatalf("favicon issuer must be HTTPS and include a base path: %q", issuer)
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("favicon CA file contains no certificate")
	}
	expectedFile := os.Getenv("GOAUTHY_E2E_FAVICON_FILE")
	var expected []byte
	if expectedFile != "" {
		expected, err = os.ReadFile(expectedFile)
		if err != nil {
			t.Fatal(err)
		}
	}
	return e2eConfig{
		issuer: issuer, secondary: secondary, origin: u.Scheme + "://" + u.Host,
		client: &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
			Timeout:   10 * time.Second,
		},
		expected:  expected,
		stateFile: os.Getenv("GOAUTHY_E2E_FAVICON_STATE_FILE"),
	}
}

func writeState(t *testing.T, c e2eConfig, response faviconResponse) {
	t.Helper()
	path := c.stateFile
	if path == "" {
		return
	}
	data, err := json.Marshal(faviconState{Body: response.body, ETag: response.etag})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readState(t *testing.T, c e2eConfig) faviconState {
	t.Helper()
	if c.stateFile == "" {
		t.Fatal("GOAUTHY_E2E_FAVICON_STATE_FILE is required for post-replacement verification")
	}
	data, err := os.ReadFile(c.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	var state faviconState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Body) == 0 || state.ETag == "" {
		t.Fatal("pre-replacement favicon state is incomplete")
	}
	return state
}

func assertFavicon(t *testing.T, c e2eConfig, endpoint string) faviconResponse {
	t.Helper()
	r := request(t, c.client, http.MethodGet, endpoint+"/favicon.ico")
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, (256<<10)+1))
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status=%d body=%q", endpoint+"/favicon.ico", r.StatusCode, body)
	}
	if len(body) == 0 {
		t.Fatal("favicon response is empty")
	}
	assertHeaders(t, r, http.StatusOK, len(body))
	return faviconResponse{body: body, etag: r.Header.Get("ETag"), contentTy: r.Header.Get("Content-Type")}
}

func assertHead(t *testing.T, client *http.Client, endpoint string, want faviconResponse) {
	t.Helper()
	r := request(t, client, http.MethodHead, endpoint)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusOK || len(body) != 0 {
		t.Fatalf("HEAD %s status=%d body=%d", endpoint, r.StatusCode, len(body))
	}
	assertHeaders(t, r, http.StatusOK, len(want.body))
	if r.Header.Get("ETag") != want.etag || r.Header.Get("Content-Type") != want.contentTy {
		t.Fatalf("HEAD headers etag=%q content-type=%q", r.Header.Get("ETag"), r.Header.Get("Content-Type"))
	}
}

func assertNotModified(t *testing.T, client *http.Client, endpoint string, want faviconResponse) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("If-None-Match", want.etag)
	r, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if r.StatusCode != http.StatusNotModified || len(body) != 0 {
		t.Fatalf("conditional GET %s status=%d body=%d", endpoint, r.StatusCode, len(body))
	}
	if r.Header.Get("ETag") != want.etag {
		t.Fatalf("conditional GET ETag=%q want=%q", r.Header.Get("ETag"), want.etag)
	}
	if r.Header.Get("Cache-Control") != "public, max-age=300, must-revalidate" {
		t.Fatalf("conditional GET Cache-Control=%q", r.Header.Get("Cache-Control"))
	}
	assertSecurityHeaders(t, r)
}

func assertMethodNotAllowed(t *testing.T, client *http.Client, endpoint string) {
	t.Helper()
	r := request(t, client, http.MethodPost, endpoint)
	defer r.Body.Close()
	if r.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST %s status=%d want=%d", endpoint, r.StatusCode, http.StatusMethodNotAllowed)
	}
	if r.Header.Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST %s Allow=%q", endpoint, r.Header.Get("Allow"))
	}
}

func assertRootIsolation(t *testing.T, c e2eConfig) {
	t.Helper()
	r := request(t, c.client, http.MethodGet, c.origin+"/favicon.ico")
	defer r.Body.Close()
	if r.StatusCode != http.StatusNotFound {
		t.Fatalf("root favicon status=%d want=%d", r.StatusCode, http.StatusNotFound)
	}
}

func assertHeaders(t *testing.T, r *http.Response, status, length int) {
	t.Helper()
	if r.StatusCode != status {
		t.Fatalf("status=%d want=%d", r.StatusCode, status)
	}
	wantLength := strconv.Itoa(length)
	if r.Header.Get("Content-Length") != wantLength {
		t.Fatalf("Content-Length=%q want=%q", r.Header.Get("Content-Length"), wantLength)
	}
	if r.Header.Get("ETag") == "" {
		t.Fatal("ETag is empty")
	}
	if contentType := r.Header.Get("Content-Type"); contentType != "image/png" && contentType != "image/x-icon" {
		t.Fatalf("Content-Type=%q", contentType)
	}
	if r.Header.Get("Cache-Control") != "public, max-age=300, must-revalidate" {
		t.Fatalf("Cache-Control=%q", r.Header.Get("Cache-Control"))
	}
	assertSecurityHeaders(t, r)
}

func assertSecurityHeaders(t *testing.T, r *http.Response) {
	t.Helper()
	if r.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("X-Content-Type-Options=%q", r.Header.Get("X-Content-Type-Options"))
	}
	if r.Header.Get("Content-Security-Policy") != "default-src 'none'" {
		t.Fatalf("Content-Security-Policy=%q", r.Header.Get("Content-Security-Policy"))
	}
}

func request(t *testing.T, client *http.Client, method, endpoint string) *http.Response {
	t.Helper()
	r, err := http.NewRequest(method, endpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
