package upstreamprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testPID = "AbCdEfGhIjKlMnOpQrStUvWx"

func testOAuthUserInfoConfig(tokenURL, userinfoURL string) Config {
	return Config{
		Kind:                  ProviderKindOAuthUserInfo,
		Issuer:                "https://issuer.example.test",
		AuthorizationEndpoint: "https://issuer.example.test/auth",
		TokenEndpoint:         tokenURL,
		UserInfoEndpoint:      userinfoURL,
		ClientID:              "test-client",
		Scopes:                []string{"openid", "profile"},
		Protocol: ProviderProtocol{
			UsePKCE:           boolPtr(true),
			ClientSecretBasic: boolPtr(true),
			ClientSecretPost:  boolPtr(false),
		},
		ProviderSource: "registry",
		RuntimeVersion: "v1",
		}
}

// --- TLS cert helpers ---

func freshCA(t *testing.T) (*x509.CertPool, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, cert, key
}

func signCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{host},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: key}
}

func newCertServer(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{signCert(t, ca, caKey, "localhost")}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func newClientWithCA(t *testing.T, pool *x509.CertPool) *http.Client {
	t.Helper()
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
		},
	}
}

// --- Test pair helper ---

type srvPair struct {
	token    *httptest.Server
	userinfo *httptest.Server
	client   *http.Client
	cfg      Config
}

func newSrvPair(t *testing.T, tokenH, userinfoH http.Handler) *srvPair {
	t.Helper()
	ts := httptest.NewTLSServer(tokenH)
	us := httptest.NewTLSServer(userinfoH)
	t.Cleanup(ts.Close)
	t.Cleanup(us.Close)
	return &srvPair{
		token:    ts,
		userinfo: us,
		client:   ts.Client(),
		cfg:      testOAuthUserInfoConfig(ts.URL, us.URL),
	}
}

func (p *srvPair) exchanger(t *testing.T) *OAuth2TokenExchanger {
	t.Helper()
	ex, err := NewOAuth2TokenExchanger(
		map[string]Config{testPID: p.cfg},
		map[string]string{testPID: ""},
		p.client,
	)
	if err != nil {
		t.Fatal(err)
	}
	return ex
}

// --- token response helper ---

func tokenJSON(at, tt string) string {
	b, _ := json.Marshal(map[string]string{"access_token": at, "token_type": tt})
	return string(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ===================== Integration tests =====================

func TestOAuthUserInfoExchangePositiveNoIDNoJWKS(t *testing.T) {
	t.Parallel()
	const sub = "user-123"
	var userinfoHits atomic.Int32
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "valid-at", "token_type": "Bearer"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userinfoHits.Add(1)
			if got := r.Header.Get("Authorization"); got != "Bearer valid-at" {
				t.Errorf("userinfo auth = %q, want Bearer valid-at", got)
			}
			writeJSON(w, map[string]string{"sub": sub, "name": "Test"})
		}),
	)
	result, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "auth-code", "pkce-v")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if result == nil || result.Subject == nil {
		t.Fatal("nil result or subject")
	}
	if result.Subject.Subject != sub {
		t.Errorf("subject = %q, want %q", result.Subject.Subject, sub)
	}
	if result.Subject.ProviderID != testPID {
		t.Errorf("providerID = %q, want %q", result.Subject.ProviderID, testPID)
	}
	if got := userinfoHits.Load(); got != 1 {
		t.Errorf("userinfo hits = %d, want 1", got)
	}
}

func TestOAuthUserInfoExchangeGarbageIDTokenIgnored(t *testing.T) {
	t.Parallel()
	const (
		sub       = "user-456"
		at        = "access-token-garbage-idtest"
		garbageID = "not.a.valid.jwt.at.all"
	)
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": at, "token_type": "Bearer", "id_token": garbageID})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"sub": sub})
		}),
	)
	result, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "verifier")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if result == nil || result.Subject == nil {
		t.Fatal("nil result or subject")
	}
	if result.Subject.Subject != sub {
		t.Errorf("subject = %q, want %q", result.Subject.Subject, sub)
	}
	if result.IDToken != "" {
		t.Errorf("IDToken = %q, want empty", result.IDToken)
	}
}

func TestOAuthUserInfoExchangeRejectsMissingToken(t *testing.T) {
	t.Parallel()
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"token_type": "Bearer"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("userinfo must not be called")
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "verifier")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("missing access_token: err = %v, want errTokenExchange", err)
	}
}

func TestOAuthUserInfoExchangeRejectsInvalidTokenType(t *testing.T) {
	t.Parallel()
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "at", "token_type": "mac"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("userinfo must not be called")
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "verifier")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("token_type=mac: err = %v, want errTokenExchange", err)
	}
}

func TestOAuthUserInfoExchangeAcceptsBearerCaseInsensitive(t *testing.T) {
	t.Parallel()
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "at-case", "token_type": "BEARER"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"sub": "user-case"})
		}),
	)
	result, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "ver")
	if err != nil {
		t.Fatalf("BEARER accepted: err = %v", err)
	}
	if result == nil || result.Subject == nil || result.Subject.Subject != "user-case" {
		t.Errorf("unexpected result: %#v", result)
	}
}

func TestOAuthUserInfoExchangeRejectsEmptyTokenType(t *testing.T) {
	t.Parallel()
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "at-nottype"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("userinfo must not be called")
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "ver")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("empty token_type: err = %v, want errTokenExchange", err)
	}
}

func TestOAuthUserInfoExchangeRejectsOAuthError(t *testing.T) {
	t.Parallel()
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "at-err", "error": "invalid_grant"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("userinfo must not be called on OAuth error")
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "ver")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("oauth error: err = %v, want errTokenExchange", err)
	}
}

func TestOAuthUserInfoExchangeRejectsNon2xx(t *testing.T) {
	t.Parallel()
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "upstream error", http.StatusBadGateway)
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("userinfo must not be called")
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "verifier")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("non-2xx token: err = %v, want errTokenExchange", err)
	}
}

func TestOAuthUserInfoExchangeRejectsTrailingData(t *testing.T) {
	t.Parallel()
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "at", "token_type": "Bearer"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"u"}{"extra":true}`))
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "ver")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("trailing userinfo: err = %v, want errTokenExchange", err)
	}
}

func TestOAuthUserInfoExchangeRejectsDuplicateSub(t *testing.T) {
	t.Parallel()
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "at", "token_type": "Bearer"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"a","sub":"b"}`))
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "ver")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("duplicate sub: err = %v, want errTokenExchange", err)
	}
}

func TestOAuthUserInfoExchangeRejectsMissingSub(t *testing.T) {
	t.Parallel()
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "at", "token_type": "Bearer"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"email": "u@example.test"})
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "ver")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("missing sub: err = %v, want errTokenExchange", err)
	}
}

func TestOAuthUserInfoExchangeRejectsNonStringSub(t *testing.T) {
	t.Parallel()
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "at", "token_type": "Bearer"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":123}`))
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "ver")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("non-string sub: err = %v, want errTokenExchange", err)
	}
}

func TestOAuthUserInfoExchangeRejectsEmptySub(t *testing.T) {
	t.Parallel()
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "at", "token_type": "Bearer"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":""}`))
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "ver")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("empty sub: err = %v, want errTokenExchange", err)
	}
}

func TestOAuthUserInfoExchangeRejectsOversizeUserinfo(t *testing.T) {
	t.Parallel()
	bigSub := strings.Repeat("x", userinfoMaxBytes+100)
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "at", "token_type": "Bearer"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"` + bigSub + `"}`))
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "ver")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("oversize userinfo: err = %v, want errTokenExchange", err)
	}
}

func TestOAuthUserInfoExchangeRejectsUserinfoRedirect(t *testing.T) {
	t.Parallel()
	var destHits atomic.Int32
	dest := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		destHits.Add(1)
		t.Error("redirect destination must not be called")
	}))
	t.Cleanup(dest.Close)

	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "at", "token_type": "Bearer"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", dest.URL+"/stolen")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "ver")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("userinfo redirect: err = %v, want errTokenExchange", err)
	}
	if got := destHits.Load(); got != 0 {
		t.Errorf("redirect destination hits = %d, want 0", got)
	}
}

func TestOAuthUserInfoExchangeRejectsTLSReject(t *testing.T) {
	t.Parallel()
	// Token endpoint signed by trustedCA; userinfo signed by untrustedCA.
	trustedPool, trustedCA, trustedKey := freshCA(t)
	untrustedPool, untrustedCA, untrustedKey := freshCA(t)
	_ = untrustedPool // explicitly untrusted

	var tokenHits, userinfoHits atomic.Int32

	tokenSrv := newCertServer(t, trustedCA, trustedKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenHits.Add(1)
		writeJSON(w, map[string]string{"access_token": "at-tls", "token_type": "Bearer"})
	}))
	userinfoSrv := newCertServer(t, untrustedCA, untrustedKey, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userinfoHits.Add(1)
		writeJSON(w, map[string]string{"sub": "never"})
	}))

	client := newClientWithCA(t, trustedPool)
	cfg := testOAuthUserInfoConfig(tokenSrv.URL, userinfoSrv.URL)
	ex, err := NewOAuth2TokenExchanger(
		map[string]Config{testPID: cfg},
		map[string]string{testPID: ""},
		client,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ex.ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "ver")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("TLS reject: err = %v, want errTokenExchange", err)
	}
	if got := tokenHits.Load(); got != 1 {
		t.Errorf("token hits = %d, want 1", got)
	}
	if got := userinfoHits.Load(); got != 0 {
		t.Errorf("userinfo hits = %d, want 0", got)
	}
}

func TestOAuthUserInfoExchangeRejectsInvalidUTF8(t *testing.T) {
	t.Parallel()
	s := newSrvPair(t,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, map[string]string{"access_token": "at", "token_type": "Bearer"})
		}),
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			// Actual invalid UTF-8 bytes 0xFF 0xFE, not unicode U+00FF U+00FE.
			_, _ = w.Write([]byte(`{"sub":"` + "\xff\xfe" + `valid"}`))
		}),
	)
	_, err := s.exchanger(t).ExchangeCode(context.Background(), testPID, "https://app.example.test/cb", "code", "ver")
	if !errors.Is(err, errTokenExchange) {
		t.Errorf("invalid UTF-8: err = %v, want errTokenExchange", err)
	}
}

// ===================== parseUserInfoSub unit table =====================

func TestParseUserInfoSubUnit(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		body    string
		wantSub string
		wantErr bool
	}{
		// --- error cases ---
		{"not-object", `[]`, "", true},
		{"empty-body", ``, "", true},
		{"missing-sub", `{"email":"a@b.c"}`, "", true},
		{"empty-sub", `{"sub":""}`, "", true},
		{"non-string-sub", `{"sub":42}`, "", true},
		{"duplicate-sub", `{"sub":"a","sub":"b"}`, "", true},
		{"trailing-json", `{"sub":"a"}{"x":1}`, "", true},
		{"trailing-text", `{"sub":"a"}garbage`, "", true},
		{"invalid-utf8-bytes", `{"sub":"` + "\xff\xfe" + `"}`, "", true},
		{"lone-surrogate-escape", `{"sub":"\uD800"}`, "", true},
		// --- success cases ---
		{"valid", `{"sub":"u1","email":"a@b.c"}`, "u1", false},
		{"sub-only", `{"sub":"only"}`, "only", false},
		{"valid-surrogate-pair", `{"sub":"\uD83D\uDE00"}`, "\U0001F600", false},
		{"literal-fffd-in-other-field", `{"sub":"valid","note":"has \uFFFD"}`, "valid", false},
		{"literal-fffd-in-sub", `{"sub":"\uFFFD"}`, "\uFFFD", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sub, err := parseUserInfoSub([]byte(tc.body))
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if sub != tc.wantSub {
				t.Errorf("sub = %q, want %q", sub, tc.wantSub)
			}
		})
	}
}
