//go:build integration

package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/credential"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const reviewHTTPSamples = 200

type reviewHTTPMetric struct {
	Stage             string         `json:"stage"`
	Records           int            `json:"unrelated_records"`
	Concurrency       int            `json:"concurrency"`
	Samples           int            `json:"samples"`
	Errors            int            `json:"errors"`
	ProfileReads      int64          `json:"profile_resolver_calls"`
	StatusCodes       map[string]int `json:"status_codes"`
	RequestBodyBytes  int64          `json:"request_body_bytes"`
	AuthHeaderBytes   int64          `json:"authorization_header_bytes"`
	ResponseBodyBytes int64          `json:"response_body_bytes"`
	ElapsedMillis     int64          `json:"elapsed_ms"`
	RequestsPerSec    float64        `json:"requests_per_second"`
	P50Millis         float64        `json:"p50_ms"`
	P95Millis         float64        `json:"p95_ms"`
	P99Millis         float64        `json:"p99_ms"`
}

type reviewHTTPSample struct {
	status                  int
	requestBytes, authBytes int64
	responseBytes           int64
	elapsed                 time.Duration
	err                     error
}

type reviewHTTPToken struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

func TestReviewHTTPRuntimeMeasurement(t *testing.T) {
	if os.Getenv("GOAUTHY_HTTP_MEASURE") != "1" {
		t.Skip("set GOAUTHY_HTTP_MEASURE=1 to run the bounded synthetic HTTP measurement")
	}
	output, label := os.Getenv("GOAUTHY_HTTP_OUTPUT"), os.Getenv("GOAUTHY_HTTP_LABEL")
	if output == "" || !validReviewHTTPLabel(label) {
		t.Fatal("set a fresh output directory and label baseline-1..3 or fixed-1..3")
	}
	if err := os.Mkdir(output, 0700); err != nil {
		t.Fatal(err)
	}
	passwordPHC, err := credential.Hash([]byte("review-only-password"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	started := time.Now()
	manifest := map[string]any{
		"label": label, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH,
		"gomaxprocs": runtime.GOMAXPROCS(0), "samples_per_cell": reviewHTTPSamples,
		"unrelated_records": []int{0, 1000}, "concurrency": []int{1, 8},
		"transport": "loopback TCP; production net/http TokenHandler and UserInfoHandler",
		"hardware":  os.Getenv("GOAUTHY_HTTP_HARDWARE"), "fixture": "private synthetic OAuth database and tokens only",
		"started_utc": started.UTC(),
	}
	results := make([]reviewHTTPMetric, 0, 14)
	controls := make([]map[string]any, 0, 2)
	for _, records := range []int{0, 1000} {
		records := records
		t.Run(fmt.Sprintf("records-%d", records), func(t *testing.T) {
			db := oauthTestDB(t)
			users, err := identity.NewStore(db)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := users.BootstrapUser(ctx, "user-1", "user-1", passwordPHC); err != nil {
				t.Fatal(err)
			}
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "review-http-profile", SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified,preferred_username,given_name,family_name,user_values_json) VALUES(?,?,?,?,?,?,?)`, Args: []any{"user-1", "review@example.test", int64(1), "review-user", "Review", "Runner", `{"birthdate":"1985-01-02","phone":"+12025550123","street":"1 Main","zip":"94105","city":"Test City","country":"US","tz":"UTC","lang":"en"}`}}); err != nil {
				t.Fatal(err)
			}
			var profileReads atomic.Int64
			key := oidcTestKey(t)
			server, err := NewServerWithOIDC(ctx, db, randomSecret(t), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{
				Issuer: oidcTestIssuer, ValidateSubject: users.ValidateSubject,
				LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil },
				ResolveProfile: func(ctx context.Context, subject string) (oidc.ProfileClaims, error) {
					profileReads.Add(1)
					profile, err := users.ProfileClaimsBySubject(ctx, subject)
					if err != nil {
						return oidc.ProfileClaims{}, err
					}
					return reviewHTTPProfileClaims(profile), nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for batch, first := 0, 0; first < records; batch, first = batch+1, first+64 {
				statements := make([]rhiza.SQLStatement, 0, min(64, records-first))
				for i := first; i < min(first+64, records); i++ {
					id := fmt.Sprintf("review-unrelated-%05d", i)
					statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO identity_users(subject,username,password_phc) VALUES(?,?,?)`, Args: []any{id, id, "synthetic-phc"}})
				}
				if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: fmt.Sprintf("review-http-seed-%d", batch), Statements: statements}); err != nil {
					t.Fatal(err)
				}
			}
			counts := snapshotQuery(t, db, `SELECT COUNT(*) FROM identity_users`)
			if len(counts) != 1 || counts[0][0] != int64(records+1) {
				t.Fatalf("synthetic identity count=%v; want %d", counts, records+1)
			}
			httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/oidc/token":
					server.TokenHandler().ServeHTTP(w, r)
				case "/oidc/userinfo":
					server.UserInfoHandler().ServeHTTP(w, r)
				default:
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(httpServer.Close)
			transport := &http.Transport{MaxIdleConnsPerHost: 8, MaxConnsPerHost: 8}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport, Timeout: 20 * time.Second}

			chains := make([]reviewHTTPToken, 8)
			for i := range chains {
				code := reviewHTTPIssueCode(t, server, strings.Repeat("v", 43))
				_, chains[i] = reviewHTTPPostToken(client, httpServer.URL, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("v", 43)}})
				if chains[i].AccessToken == "" || chains[i].RefreshToken == "" {
					t.Fatalf("seed token chain %d missing access or refresh token", i)
				}
				if !strings.Contains(" "+chains[i].Scope+" ", " offline_access ") {
					t.Fatalf("refresh setup lacks offline_access scope: %q", chains[i].Scope)
				}
			}
			accessToken := chains[0].AccessToken
			profileReads.Store(0)
			wantGrantProfileReads := int64(2)
			if strings.HasPrefix(label, "fixed-") {
				wantGrantProfileReads = 1
			}
			controlCode := reviewHTTPIssueCode(t, server, strings.Repeat("v", 43))
			before := profileReads.Load()
			control, controlToken := reviewHTTPPostToken(client, httpServer.URL, url.Values{"grant_type": {"authorization_code"}, "code": {controlCode}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("v", 43)}})
			codeProfileReads := profileReads.Load() - before
			if control.status != http.StatusOK || codeProfileReads != wantGrantProfileReads {
				t.Fatalf("authorization-code control status=%d profile reads=%d, want %d", control.status, codeProfileReads, wantGrantProfileReads)
			}
			before = profileReads.Load()
			userinfoControl := reviewHTTPUserInfo(client, httpServer.URL, controlToken.AccessToken)
			userinfoProfileReads := profileReads.Load() - before
			if userinfoControl.status != http.StatusOK || userinfoProfileReads != 1 {
				t.Fatalf("UserInfo control status=%d profile reads=%d, want 1", userinfoControl.status, userinfoProfileReads)
			}
			before = profileReads.Load()
			refreshControl, refreshedControl := reviewHTTPPostToken(client, httpServer.URL, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {controlToken.RefreshToken}})
			refreshProfileReads := profileReads.Load() - before
			if refreshControl.status != http.StatusOK || refreshProfileReads != wantGrantProfileReads || refreshedControl.RefreshToken == "" {
				t.Fatalf("refresh control status=%d profile reads=%d, want %d", refreshControl.status, refreshProfileReads, wantGrantProfileReads)
			}
			chains[0].RefreshToken = refreshedControl.RefreshToken
			invalidUserInfo := reviewHTTPUserInfo(client, httpServer.URL, "invalid-token")
			invalidCode, _ := reviewHTTPPostToken(client, httpServer.URL, url.Values{"grant_type": {"authorization_code"}, "code": {"invalid-code"}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("v", 43)}})
			if invalidUserInfo.status != http.StatusUnauthorized || invalidCode.status == http.StatusOK {
				t.Fatalf("invalid-token controls: UserInfo=%d token=%d", invalidUserInfo.status, invalidCode.status)
			}
			controls = append(controls, map[string]any{"records": records, "auth_code_profile_reads": codeProfileReads, "refresh_profile_reads": refreshProfileReads, "userinfo_profile_reads": userinfoProfileReads, "invalid_userinfo_status": invalidUserInfo.status, "invalid_code_status": invalidCode.status, "refresh_scope": chains[0].Scope})
			for _, concurrency := range []int{1, 8} {
				codes := make([]string, reviewHTTPSamples)
				for i := range codes {
					codes[i] = reviewHTTPIssueCode(t, server, strings.Repeat("v", 43))
				}
				before = profileReads.Load()
				metric := reviewHTTPRun(ctx, "authorization_code_token", records, concurrency, func(_ int, index int) reviewHTTPSample {
					sample, _ := reviewHTTPPostToken(client, httpServer.URL, url.Values{"grant_type": {"authorization_code"}, "code": {codes[index]}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("v", 43)}})
					return sample
				})
				metric.ProfileReads = profileReads.Load() - before
				wantReads := int64(reviewHTTPSamples) * wantGrantProfileReads
				if metric.ProfileReads != wantReads {
					t.Fatalf("authorization-code samples made %d profile reads; want %d", metric.ProfileReads, wantReads)
				}
				results = append(results, metric)
				before = profileReads.Load()
				metric = reviewHTTPRun(ctx, "userinfo", records, concurrency, func(_ int, _ int) reviewHTTPSample {
					return reviewHTTPUserInfo(client, httpServer.URL, accessToken)
				})
				metric.ProfileReads = profileReads.Load() - before
				if metric.ProfileReads != reviewHTTPSamples {
					t.Fatalf("UserInfo samples made %d profile reads; want %d", metric.ProfileReads, reviewHTTPSamples)
				}
				results = append(results, metric)
				before = profileReads.Load()
				metric = reviewHTTPRun(ctx, "refresh_grant", records, concurrency, func(worker, _ int) reviewHTTPSample {
					sample, token := reviewHTTPPostToken(client, httpServer.URL, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {chains[worker].RefreshToken}})
					if token.RefreshToken != "" {
						chains[worker].RefreshToken = token.RefreshToken
					}
					return sample
				})
				metric.ProfileReads = profileReads.Load() - before
				if metric.ProfileReads != wantReads {
					t.Fatalf("refresh samples made %d profile reads; want %d", metric.ProfileReads, wantReads)
				}
				results = append(results, metric)
			}
		})
	}
	for _, concurrency := range []int{1, 8} {
		results = append(results, reviewHTTPRun(ctx, "argon2_verify", 0, concurrency, func(_ int, _ int) reviewHTTPSample {
			started := time.Now()
			valid, _, err := credential.Verify([]byte("review-only-password"), passwordPHC)
			status := http.StatusOK
			if err != nil || !valid {
				status = http.StatusInternalServerError
				if errors.Is(err, credential.ErrWorkLimit) {
					status = http.StatusTooManyRequests
				}
			}
			return reviewHTTPSample{status: status, elapsed: time.Since(started), err: err}
		}))
	}
	for _, result := range results {
		if result.Samples != reviewHTTPSamples {
			t.Fatalf("incomplete %s records=%d concurrency=%d: got %d samples, want %d", result.Stage, result.Records, result.Concurrency, result.Samples, reviewHTTPSamples)
		}
	}
	manifest["counterexample_controls"] = controls
	manifest["elapsed_seconds"] = time.Since(started).Seconds()
	manifest["result_count"] = len(results)
	snapshotLog(t, "http_runtime", map[string]any{"label": label, "metrics": results})
	if err := writeReviewHTTPJSON(filepath.Join(output, "manifest.json"), manifest); err != nil {
		t.Fatal(err)
	}
	if err := writeReviewHTTPJSON(filepath.Join(output, "results.json"), results); err != nil {
		t.Fatal(err)
	}
}

func reviewHTTPPostToken(client *http.Client, base string, values url.Values) (reviewHTTPSample, reviewHTTPToken) {
	body := values.Encode()
	started := time.Now()
	request, err := http.NewRequest(http.MethodPost, base+"/oidc/token", bytes.NewBufferString(body))
	if err != nil {
		return reviewHTTPSample{err: err}, reviewHTTPToken{}
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(testClientID, testClientSecret)
	response, err := client.Do(request)
	if err != nil {
		return reviewHTTPSample{requestBytes: int64(len(body)), authBytes: int64(len(request.Header.Get("Authorization"))), elapsed: time.Since(started), err: err}, reviewHTTPToken{}
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	sample := reviewHTTPSample{status: response.StatusCode, requestBytes: int64(len(body)), authBytes: int64(len(request.Header.Get("Authorization"))), responseBytes: int64(len(data)), elapsed: time.Since(started), err: err}
	var token reviewHTTPToken
	if response.StatusCode == http.StatusOK && err == nil {
		sample.err = json.Unmarshal(data, &token)
	}
	return sample, token
}

// reviewHTTPIssueCode keeps the measurement harness independent of helpers
// added by OAuth regression tests after the archived v0.3.8 baseline.
func reviewHTTPIssueCode(t *testing.T, server *Server, verifier string) string {
	t.Helper()
	sessionID := oidcTestSessionID(0)
	ensureOIDCTestBrowserSession(t, server, sessionID)
	values := oidcAuthorizationValues(verifier, "review-http-profile")
	values.Set("scope", "openid profile offline_access")
	response := httptest.NewRecorder()
	server.CompleteAuthorizationWithSession(response, httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+values.Encode(), nil), "user-1", []string{"openid", "profile", "offline_access"}, oidcTestAuthTime, sessionID, oidcAuthMethodPwd)
	location, err := url.Parse(response.Header().Get("Location"))
	if err != nil || location.Query().Get("code") == "" {
		t.Fatalf("authorization failed: status=%d location=%q err=%v", response.Code, response.Header().Get("Location"), err)
	}
	return location.Query().Get("code")
}

// reviewHTTPProfileClaims mirrors cmd/goauthy/oidcProfileClaims so the
// measured resolver does the same current identity read and field projection.
func reviewHTTPProfileClaims(p identity.ProfileClaims) oidc.ProfileClaims {
	out := oidc.ProfileClaims{
		Email: p.Email, EmailVerified: p.EmailVerified, PreferredUsername: p.PreferredUsername,
		GivenName: p.GivenName, FamilyName: p.FamilyName, Birthdate: p.Birthdate,
		PhoneNumber: p.Phone, Zoneinfo: p.Timezone, Locale: p.Language,
	}
	if p.Phone != nil {
		verified := false
		out.PhoneNumberVerified = &verified
	}
	if p.Street != nil || p.ZIP != nil || p.Country != nil {
		out.Address = make(map[string]string)
		var formatted strings.Builder
		if p.GivenName != nil {
			formatted.WriteString(*p.GivenName)
		}
		if p.FamilyName != nil {
			formatted.WriteString(" " + *p.FamilyName)
		}
		formatted.WriteByte('\n')
		if p.Street != nil {
			out.Address["street_address"] = *p.Street
			formatted.WriteString(*p.Street + "\n")
		}
		if p.ZIP != nil {
			out.Address["postal_code"] = *p.ZIP
			formatted.WriteString(*p.ZIP)
			if p.City != nil {
				out.Address["locality"] = *p.City
				formatted.WriteString(", " + *p.City)
			}
			formatted.WriteByte('\n')
		}
		if p.Country != nil {
			out.Address["country"] = *p.Country
			formatted.WriteString(*p.Country + "\n")
		}
		out.Address["formatted"] = formatted.String()
	}
	return out
}

func reviewHTTPUserInfo(client *http.Client, base, token string) reviewHTTPSample {
	started := time.Now()
	request, err := http.NewRequest(http.MethodGet, base+"/oidc/userinfo", nil)
	if err != nil {
		return reviewHTTPSample{err: err}
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(request)
	if err != nil {
		return reviewHTTPSample{authBytes: int64(len(request.Header.Get("Authorization"))), elapsed: time.Since(started), err: err}
	}
	defer response.Body.Close()
	count, err := io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	return reviewHTTPSample{status: response.StatusCode, authBytes: int64(len(request.Header.Get("Authorization"))), responseBytes: count, elapsed: time.Since(started), err: err}
}

func reviewHTTPRun(ctx context.Context, stage string, records, concurrency int, request func(worker, sample int) reviewHTTPSample) reviewHTTPMetric {
	result := reviewHTTPMetric{Stage: stage, Records: records, Concurrency: concurrency, StatusCodes: make(map[string]int)}
	durations := make([]time.Duration, 0, reviewHTTPSamples)
	var mu sync.Mutex
	jobs := make(chan int)
	started := time.Now()
	var workers sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for sampleIndex := range jobs {
				if ctx.Err() != nil {
					return
				}
				at := time.Now()
				sample := request(worker, sampleIndex)
				elapsed := sample.elapsed
				if elapsed == 0 {
					elapsed = time.Since(at)
				}
				mu.Lock()
				durations = append(durations, elapsed)
				result.RequestBodyBytes += sample.requestBytes
				result.AuthHeaderBytes += sample.authBytes
				result.ResponseBodyBytes += sample.responseBytes
				result.StatusCodes[fmt.Sprint(sample.status)]++
				if sample.err != nil || sample.status != http.StatusOK {
					result.Errors++
				}
				mu.Unlock()
			}
		}(worker)
	}
send:
	for i := 0; i < reviewHTTPSamples; i++ {
		select {
		case jobs <- i:
		case <-ctx.Done():
			break send
		}
	}
	close(jobs)
	workers.Wait()
	elapsed := time.Since(started)
	result.Samples = len(durations)
	result.ElapsedMillis = elapsed.Milliseconds()
	if elapsed > 0 {
		result.RequestsPerSec = float64(result.Samples) / elapsed.Seconds()
	}
	slices.Sort(durations)
	result.P50Millis = reviewHTTPPercentile(durations, .50)
	result.P95Millis = reviewHTTPPercentile(durations, .95)
	result.P99Millis = reviewHTTPPercentile(durations, .99)
	return result
}

func reviewHTTPPercentile(values []time.Duration, quantile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	index := int(float64(len(values))*quantile+0.999999) - 1
	return float64(values[index]) / float64(time.Millisecond)
}

func validReviewHTTPLabel(label string) bool {
	return label == "baseline-1" || label == "baseline-2" || label == "baseline-3" || label == "fixed-1" || label == "fixed-2" || label == "fixed-3"
}

func writeReviewHTTPJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}
