package oauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime/pprof"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/oidc"
)

func BenchmarkIntrospectionHTTP(b *testing.B) {
	db := oauthTestDB(b)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	key := oidc.SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: public, KeyID: "issue106-bench", Algorithm: string(jose.EdDSA), Use: "sig"}}
	server, err := NewServerWithOIDC(context.Background(), db, bytes.Repeat([]byte{1}, 32), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
		Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil },
		LoadVerificationKeys: func(context.Context) ([]jose.JSONWebKey, error) { return []jose.JSONWebKey{key.PublicJWK}, nil },
	})
	if err != nil {
		b.Fatal(err)
	}
	verifier := strings.Repeat("b", 43)
	issued := decodeToken(b, postToken(server, url.Values{
		"grant_type": {"authorization_code"}, "code": {issueCode(b, server, verifier)},
		"redirect_uri": {testRedirectURI}, "code_verifier": {verifier},
	}))
	strategy := server.accessTokens.(*signedAccessTokenStrategy)
	originalVerify := strategy.verifyToken
	originalLoadKeys := strategy.loadKeys

	for _, tc := range []struct {
		name  string
		reuse bool
	}{{"baseline", false}, {"candidate", true}} {
		b.Run(tc.name, func(b *testing.B) {
			verifyCalls, keyLoads := 0, 0
			strategy.verifyToken = func(token string, keys jose.JSONWebKeySet, issuer string, now time.Time) (oidc.AccessTokenClaims, error) {
				verifyCalls++
				return originalVerify(token, keys, issuer, now)
			}
			strategy.loadKeys = func(ctx context.Context) ([]jose.JSONWebKey, error) {
				keyLoads++
				return originalLoadKeys(ctx)
			}
			handler := server.introspectionHandler(tc.reuse)
			latency := make([]int64, b.N)
			cpuProfile := startIssue106CPUProfile(b, tc.name)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				req := httptest.NewRequest("POST", "/oidc/introspect", strings.NewReader(url.Values{"token": {issued.AccessToken}}.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				req.SetBasicAuth(testClientID, testClientSecret)
				response := httptest.NewRecorder()
				started := time.Now()
				handler.ServeHTTP(response, req)
				latency[i] = time.Since(started).Nanoseconds()
				if response.Code != 200 || !strings.Contains(response.Body.String(), `"active":true`) {
					b.Fatalf("introspection status=%d body=%s", response.Code, response.Body.String())
				}
			}
			b.StopTimer()
			stopIssue106CPUProfile(b, cpuProfile)
			sort.Slice(latency, func(i, j int) bool { return latency[i] < latency[j] })
			b.ReportMetric(float64(percentileIssue106(latency, 95)), "p95-ns")
			b.ReportMetric(float64(percentileIssue106(latency, 99)), "p99-ns")
			b.ReportMetric(float64(verifyCalls)/float64(b.N), "crypto-verifies/op")
			b.ReportMetric(float64(keyLoads)/float64(b.N), "key-loads/op")
		})
	}
}

func percentileIssue106(sorted []int64, percentile int) int64 {
	return sorted[(len(sorted)*percentile+99)/100-1]
}

func startIssue106CPUProfile(b *testing.B, name string) *os.File {
	directory := os.Getenv("ISSUE106_CPU_PROFILE_DIR")
	if directory == "" {
		return nil
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		b.Fatal(err)
	}
	file, err := os.Create(filepath.Join(directory, name+".cpu"))
	if err != nil {
		b.Fatal(err)
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		_ = file.Close()
		b.Fatal(err)
	}
	return file
}

func stopIssue106CPUProfile(b *testing.B, file *os.File) {
	if file == nil {
		return
	}
	pprof.StopCPUProfile()
	if err := file.Close(); err != nil {
		b.Fatal(err)
	}
}
