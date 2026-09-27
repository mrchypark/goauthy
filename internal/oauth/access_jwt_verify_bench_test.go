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
	// This is a serial, in-process httptest benchmark of the real introspection
	// handler, Fosite chain, and local Rhiza session store. The test package sets
	// bcryptHashCost to bcrypt.MinCost; signing verification keys come from an
	// in-memory loader. It does not include network, production key-database, or
	// deployment costs. Both controls run in this same binary and fixture.
	// ns/op, B/op, and allocs/op include request/recorder setup in the timed loop;
	// p95/p99 timestamps bracket ServeHTTP only, excluding that setup and checks.
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
	}{{"serial-in-process-httptest/bcrypt-min-cost/in-memory-key-loader/real-rhiza-store/baseline-no-reuse", false}, {"serial-in-process-httptest/bcrypt-min-cost/in-memory-key-loader/real-rhiza-store/candidate-request-local-reuse", true}} {
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
			cpuProfile := startIntrospectionCPUProfile(b, tc.name)
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
			stopIntrospectionCPUProfile(b, cpuProfile)
			sort.Slice(latency, func(i, j int) bool { return latency[i] < latency[j] })
			b.ReportMetric(float64(percentileLatency(latency, 95)), "p95-ns")
			b.ReportMetric(float64(percentileLatency(latency, 99)), "p99-ns")
			b.ReportMetric(float64(verifyCalls)/float64(b.N), "crypto-verifies/op")
			b.ReportMetric(float64(keyLoads)/float64(b.N), "key-loads/op")
		})
	}
}

func percentileLatency(sorted []int64, percentile int) int64 {
	return sorted[(len(sorted)*percentile+99)/100-1]
}

func startIntrospectionCPUProfile(b *testing.B, name string) *os.File {
	directory := os.Getenv("ISSUE117_CPU_PROFILE_DIR")
	if directory == "" {
		return nil
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		b.Fatal(err)
	}
	file, err := os.Create(filepath.Join(directory, strings.ReplaceAll(name, "/", "_")+".cpu"))
	if err != nil {
		b.Fatal(err)
	}
	if err := pprof.StartCPUProfile(file); err != nil {
		_ = file.Close()
		b.Fatal(err)
	}
	return file
}

func stopIntrospectionCPUProfile(b *testing.B, file *os.File) {
	if file == nil {
		return
	}
	pprof.StopCPUProfile()
	if err := file.Close(); err != nil {
		b.Fatal(err)
	}
}
