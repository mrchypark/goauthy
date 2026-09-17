package recovery

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/rhiza"
)

func TestLoginRevokeHandlerUsesTypedQueryIPAndCore(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	keyring := loginRevokeTestKeyring(t)
	ctx := context.Background()
	code, err := service.identity.FindOrCreateLoginRevokeCode(ctx, keyring, "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	handler := NewLoginRevokeHandler(service.identity, keyring)

	wrong := loginRevokeRequest(http.MethodGet, "/auth/v1/users/subject-1/revoke/wrong?ip=198.51.100.7", "203.0.113.8:4321")
	wrongResponse := httptest.NewRecorder()
	handler.ServeHTTP(wrongResponse, wrong)
	if wrongResponse.Code != http.StatusOK || wrongResponse.Header().Get("Content-Type") != "text/html; charset=utf-8" || !strings.Contains(wrongResponse.Body.String(), "Code not found") {
		t.Fatalf("wrong code response=%d content-type=%q body=%q", wrongResponse.Code, wrongResponse.Header().Get("Content-Type"), wrongResponse.Body.String())
	}

	malformed := loginRevokeRequest(http.MethodGet, "/auth/v1/users/subject-1/revoke/"+code+"?ip=not-an-ip", "203.0.113.8:4321")
	malformedResponse := httptest.NewRecorder()
	handler.ServeHTTP(malformedResponse, malformed)
	if malformedResponse.Code != http.StatusBadRequest {
		t.Fatalf("malformed IP response=%d body=%q", malformedResponse.Code, malformedResponse.Body.String())
	}

	valid := loginRevokeRequest(http.MethodGet, "/auth/v1/users/subject-1/revoke/"+code+"?ip=198.51.100.7", "203.0.113.8:4321")
	validResponse := httptest.NewRecorder()
	handler.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusOK || validResponse.Header().Get("Cache-Control") != "no-store" || validResponse.Header().Get("Referrer-Policy") != "no-referrer" || !strings.Contains(validResponse.Body.String(), "All Logins and Sessions have been revoked") {
		t.Fatalf("valid response=%d headers=%#v body=%q", validResponse.Code, validResponse.Header(), validResponse.Body.String())
	}
	if strings.Contains(validResponse.Body.String(), "subject-1") || strings.Contains(validResponse.Body.String(), code) || strings.Contains(validResponse.Body.String(), "198.51.100.7") || strings.Contains(validResponse.Body.String(), "203.0.113.8") {
		t.Fatalf("valid response reflected request data: %q", validResponse.Body.String())
	}

	replay := loginRevokeRequest(http.MethodGet, "/auth/v1/users/subject-1/revoke/"+code+"?ip=198.51.100.7", "203.0.113.8:4321")
	replayResponse := httptest.NewRecorder()
	handler.ServeHTTP(replayResponse, replay)
	if replayResponse.Code != http.StatusOK || !strings.Contains(replayResponse.Body.String(), "Code not found") {
		t.Fatalf("replay response=%d body=%q", replayResponse.Code, replayResponse.Body.String())
	}

	event, err := service.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT ip FROM event_log WHERE typ='UserLoginRevoke'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(event.Rows) != 1 || len(event.Rows[0]) != 1 || event.Rows[0][0] != "198.51.100.7" {
		t.Fatalf("revoke event=%v err=%v", event.Rows, err)
	}
}

func TestLoginRevokeHandlerLocationLookupUsesQueryIP(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	keyring := loginRevokeTestKeyring(t)
	code, err := service.identity.FindOrCreateLoginRevokeCode(context.Background(), keyring, "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	var lookedUp netip.Addr
	location := "Seoul"
	lookup := func(ip netip.Addr) (*string, error) {
		lookedUp = ip
		return &location, nil
	}
	request := loginRevokeRequest(http.MethodGet, "/auth/v1/users/subject-1/revoke/"+code+"?ip=198.51.100.7", "203.0.113.8:4321")
	request.Header.Set("X-Forwarded-For", "192.0.2.9")
	response := httptest.NewRecorder()
	NewLoginRevokeHandler(service.identity, keyring, lookup).ServeHTTP(response, request)
	if response.Code != http.StatusOK || lookedUp != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("response=%d looked up IP=%s", response.Code, lookedUp)
	}

	event, err := service.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT ip,text FROM event_log WHERE typ='UserLoginRevoke'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(event.Rows) != 1 || event.Rows[0][0] != "198.51.100.7" || event.Rows[0][1] != "User `alice` revoked illegal login from 198.51.100.7 (Seoul)" {
		t.Fatalf("revoke event=%v err=%v", event.Rows, err)
	}
}

func TestLoginRevokeHandlerLocationLookupFailureFallsBackToNil(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	keyring := loginRevokeTestKeyring(t)
	code, err := service.identity.FindOrCreateLoginRevokeCode(context.Background(), keyring, "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	lookup := func(netip.Addr) (*string, error) { return nil, errors.New("lookup failed") }
	request := loginRevokeRequest(http.MethodGet, "/auth/v1/users/subject-1/revoke/"+code+"?ip=198.51.100.8", "203.0.113.8:4321")
	response := httptest.NewRecorder()
	NewLoginRevokeHandler(service.identity, keyring, lookup).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("response=%d body=%q", response.Code, response.Body.String())
	}

	event, err := service.db.Query(context.Background(), rhiza.QueryRequest{SQL: `SELECT text FROM event_log WHERE typ='UserLoginRevoke'`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(event.Rows) != 1 || event.Rows[0][0] != "User `alice` revoked illegal login from 198.51.100.8 (Unknown Location)" {
		t.Fatalf("revoke event=%v err=%v", event.Rows, err)
	}
}

func TestLoginRevokeHandlerMethodAndMissingIP(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	handler := NewLoginRevokeHandler(service.identity, loginRevokeTestKeyring(t))
	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/auth/v1/users/subject-1/revoke/code", nil),
		httptest.NewRequest(http.MethodGet, "/auth/v1/users/subject-1/revoke/code?ip=", nil),
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("missing IP response=%d body=%q", response.Code, response.Body.String())
		}
	}

	request := httptest.NewRequest(http.MethodPost, "/auth/v1/users/subject-1/revoke/code?ip=198.51.100.7", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("method response=%d allow=%q", response.Code, response.Header().Get("Allow"))
	}
}

func TestLoginRevokeHandlerUsesPinnedLanguageCopy(t *testing.T) {
	service, _ := testService(t, "subject-1", "alice")
	keyring := loginRevokeTestKeyring(t)
	code, err := service.identity.FindOrCreateLoginRevokeCode(context.Background(), keyring, "subject-1")
	if err != nil {
		t.Fatal(err)
	}
	request := loginRevokeRequest(http.MethodGet, "/auth/v1/users/subject-1/revoke/"+code+"?ip=198.51.100.7", "203.0.113.8:4321")
	request.Header.Set("Accept-Language", "fr")
	response := httptest.NewRecorder()
	NewLoginRevokeHandler(service.identity, keyring).ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `lang="fr"`) || !strings.Contains(response.Body.String(), "Révoquer les connexions") || !strings.Contains(response.Body.String(), "Vous devez immédiatement renouveler tous vos mots de passe !") {
		t.Fatalf("French response=%d body=%q", response.Code, response.Body.String())
	}
}

func loginRevokeRequest(method, target, remoteAddr string) *http.Request {
	request := httptest.NewRequest(method, target, nil)
	request.RemoteAddr = remoteAddr
	request.SetPathValue("subject", "subject-1")
	code := strings.TrimPrefix(target, "/auth/v1/users/subject-1/revoke/")
	if query := strings.IndexByte(code, '?'); query >= 0 {
		code = code[:query]
	}
	request.SetPathValue("code", code)
	return request
}

func loginRevokeTestKeyring(t *testing.T) *oidc.Keyring {
	t.Helper()
	directory := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "test-1"), []byte(base64.RawURLEncoding.EncodeToString(key)), 0o600); err != nil {
		t.Fatal(err)
	}
	keyring, err := oidc.LoadKeyring(directory, "test-1")
	if err != nil {
		t.Fatal(err)
	}
	return keyring
}
