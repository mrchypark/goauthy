package oauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/mrchypark/goauthy/internal/metrics"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestTokenMetricsClientCredentialsSuccessAndFailure(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	reg := metrics.NewRegistry()
	server.SetMetrics(reg)

	// Valid client credentials → TokenOK.
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"}, "scope": {"goauthy.read"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(testClientID, testClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if got := testutil.ToFloat64(reg.TokenOKCounter()); got != 1 {
		t.Fatalf("TokenOK=%v, want 1", got)
	}
	if got := testutil.ToFloat64(reg.TokenRejectCounter()); got != 0 {
		t.Fatalf("TokenReject=%v, want 0", got)
	}

	// Wrong secret → TokenReject.
	bad := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"}, "scope": {"goauthy.read"},
	}.Encode()))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad.SetBasicAuth(testClientID, "wrong-secret-value!!!")
	badResp := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(badResp, bad)
	if badResp.Code == http.StatusOK {
		t.Fatal("wrong secret accepted")
	}
	if got := testutil.ToFloat64(reg.TokenRejectCounter()); got != 1 {
		t.Fatalf("TokenReject=%v, want 1", got)
	}
	if got := testutil.ToFloat64(reg.TokenOKCounter()); got != 1 {
		t.Fatalf("TokenOK=%v, want 1 (unchanged)", got)
	}
}

func TestTokenMetricsMalformedContentType(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	reg := metrics.NewRegistry()
	server.SetMetrics(reg)

	// Wrong content type → TokenReject.
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader("--boundary--"))
	request.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
	request.SetBasicAuth(testClientID, testClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code == http.StatusOK {
		t.Fatal("multipart accepted")
	}
	if got := testutil.ToFloat64(reg.TokenRejectCounter()); got != 1 {
		t.Fatalf("TokenReject=%v, want 1", got)
	}
}

func TestTokenMetricsOversizedForm(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	reg := metrics.NewRegistry()
	server.SetMetrics(reg)

	// Oversized form body → TokenReject.
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader("grant_type=client_credentials&padding="+strings.Repeat("x", 17<<10)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(testClientID, testClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code == http.StatusOK {
		t.Fatal("oversized accepted")
	}
	if got := testutil.ToFloat64(reg.TokenRejectCounter()); got != 1 {
		t.Fatalf("TokenReject=%v, want 1", got)
	}
}

func TestTokenMetricsNilRegistryNoPanic(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	// No SetMetrics — metrics is nil.
	request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{
		"grant_type": {"client_credentials"}, "scope": {"goauthy.read"},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(testClientID, testClientSecret)
	response := httptest.NewRecorder()
	server.TokenHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestTokenMetricsConcurrentTokenRequests(t *testing.T) {
	db := oauthTestDB(t)
	server := oauthTestServer(t, db, randomSecret(t))
	reg := metrics.NewRegistry()
	server.SetMetrics(reg)

	const n = 50
	ready := make(chan struct{}, 2*n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2 * n)
	for range n {
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{
				"grant_type": {"client_credentials"}, "scope": {"goauthy.read"},
			}.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.SetBasicAuth(testClientID, testClientSecret)
			response := httptest.NewRecorder()
			server.TokenHandler().ServeHTTP(response, request)
		}()
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			request := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(url.Values{
				"grant_type": {"client_credentials"}, "scope": {"goauthy.read"},
			}.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.SetBasicAuth(testClientID, "wrong-secret-value!!!")
			response := httptest.NewRecorder()
			server.TokenHandler().ServeHTTP(response, request)
		}()
	}
	for range 2 * n {
		<-ready
	}
	close(start)
	wg.Wait()

	if got := testutil.ToFloat64(reg.TokenOKCounter()); got != n {
		t.Fatalf("TokenOK=%v, want %d", got, n)
	}
	if got := testutil.ToFloat64(reg.TokenRejectCounter()); got != n {
		t.Fatalf("TokenReject=%v, want %d", got, n)
	}
}

func TestForwardAuthMetricsValidAndInvalidTokens(t *testing.T) {
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, nil)
	valid := issueUserInfoToken(t, server)
	// Clear counters from token issuance before forward-auth assertions.
	reg := metrics.NewRegistry()
	server.SetMetrics(reg)

	// Valid token → TokenOK.
	response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, valid, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
	if got := testutil.ToFloat64(reg.TokenOKCounter()); got != 1 {
		t.Fatalf("TokenOK=%v, want 1", got)
	}

	// Invalid token → TokenReject.
	response = forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, "not-a-token", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
	if got := testutil.ToFloat64(reg.TokenRejectCounter()); got != 1 {
		t.Fatalf("TokenReject=%v, want 1", got)
	}
}

func TestForwardAuthMetricsMissingBearerScheme(t *testing.T) {
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, nil)
	reg := metrics.NewRegistry()
	server.SetMetrics(reg)

	// DPoP scheme (not Bearer) → TokenReject.
	valid := issueUserInfoToken(t, server)
	req := forwardAuthRequest(http.MethodGet, valid, nil)
	req.Header.Set("Authorization", "DPoP "+valid)
	response := forwardAuthResponse(server, req)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
	if got := testutil.ToFloat64(reg.TokenRejectCounter()); got != 1 {
		t.Fatalf("TokenReject=%v, want 1", got)
	}
}

func TestForwardAuthMetricsRevokedToken(t *testing.T) {
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, nil)
	reg := metrics.NewRegistry()
	server.SetMetrics(reg)

	token := issueUserInfoToken(t, server)
	// Delete the token to simulate revocation.
	signature := server.accessTokens.AccessTokenSignature(context.Background(), token)
	if err := server.store.DeleteAccessTokenSession(context.Background(), signature); err != nil {
		t.Fatal(err)
	}
	response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, token, nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
	if got := testutil.ToFloat64(reg.TokenRejectCounter()); got != 1 {
		t.Fatalf("TokenReject=%v, want 1", got)
	}
}

func TestForwardAuthMetricsDisabledSubject(t *testing.T) {
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, assertError("disabled"))
	reg := metrics.NewRegistry()
	server.SetMetrics(reg)

	token := issueUserInfoToken(t, server)
	response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, token, nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d", response.Code)
	}
	if got := testutil.ToFloat64(reg.TokenRejectCounter()); got != 1 {
		t.Fatalf("TokenReject=%v, want 1", got)
	}
}

func TestForwardAuthMetricsNilRegistryNoPanic(t *testing.T) {
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, nil)
	// No SetMetrics.
	valid := issueUserInfoToken(t, server)
	response := forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, valid, nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestForwardAuthMetricsConcurrentRequests(t *testing.T) {
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, nil)
	valid := issueUserInfoToken(t, server)
	// Clear counters from token issuance before forward-auth assertions.
	reg := metrics.NewRegistry()
	server.SetMetrics(reg)

	const n = 50
	ready := make(chan struct{}, 2*n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2 * n)
	for range n {
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, valid, nil))
		}()
		go func() {
			defer wg.Done()
			ready <- struct{}{}
			<-start
			forwardAuthResponse(server, forwardAuthRequest(http.MethodGet, "bad-token", nil))
		}()
	}
	for range 2 * n {
		<-ready
	}
	close(start)
	wg.Wait()

	if got := testutil.ToFloat64(reg.TokenOKCounter()); got != n {
		t.Fatalf("TokenOK=%v, want %d", got, n)
	}
	if got := testutil.ToFloat64(reg.TokenRejectCounter()); got != n {
		t.Fatalf("TokenReject=%v, want %d", got, n)
	}
}

func TestForwardAuthMetricsMethodNotAllowed(t *testing.T) {
	db := oauthTestDB(t)
	server := userInfoTestServer(t, db, nil)
	reg := metrics.NewRegistry()
	server.SetMetrics(reg)

	// POST is not allowed → no token counters incremented (method guard is pre-token).
	response := forwardAuthResponse(server, forwardAuthRequest(http.MethodPost, "", nil))
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", response.Code)
	}
	if got := testutil.ToFloat64(reg.TokenOKCounter()); got != 0 {
		t.Fatalf("TokenOK=%v, want 0", got)
	}
	if got := testutil.ToFloat64(reg.TokenRejectCounter()); got != 0 {
		t.Fatalf("TokenReject=%v, want 0", got)
	}
}
