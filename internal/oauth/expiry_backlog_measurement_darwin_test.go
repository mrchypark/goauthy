//go:build integration

package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/claims"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
)

// A fixed experiment, not a load generator. Each child owns one fresh DB.
var expiry65Operations = []string{"session", "interaction", "code", "redemption", "client_credentials"}
var expiry65States = []string{"empty", "live", "expired"}

func expiry65JSON(t *testing.T, kind string, value any) {
	t.Helper()
	b, err := json.Marshal(struct {
		Kind  string `json:"kind"`
		Value any    `json:"value"`
	}{kind, value})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("EXPIRY65 " + string(b))
}

func expiry65Disk(root string) (int64, error) {
	var size int64
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		size += info.Size()
		return nil
	})
	return size, err
}

// The parent accounts for setup, validation, child close, and raw evidence I/O.
// Compilation and separately labelled correctness checks are outside this run.
func TestExpiry65Campaign(t *testing.T) {
	root := os.Getenv("GOAUTHY_EXPIRY65_OUTPUT")
	if root == "" {
		t.Skip("opt-in: requires a new evidence directory")
	}
	started := time.Now()
	// Reserve five seconds of the total cap for final failure/evidence accounting.
	ctx, cancel := context.WithTimeout(t.Context(), 595*time.Second)
	defer cancel()
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("expiry_backlog_measurement_darwin_test.go")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(source)
	manifest := map[string]any{"base": "5769e91f366fc4e047b4f666efa18711b5580fa0", "source_sha256": hex.EncodeToString(hash[:]), "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "gomaxprocs": runtime.GOMAXPROCS(0), "operations": expiry65Operations, "states": expiry65States, "repetitions": 3, "bundles": 1000, "maximum_cases": 45, "maximum_timed_operations": 90, "aggregate_seconds": 600, "case_seconds": 60, "disk_limit_bytes": 256 << 20, "disk_stop_bytes": 240 << 20, "checkpoint_interval": "1h", "checkpoint_tail_bytes": 512 << 20, "sqlite_checkpoint_treatment": expiry65SQLiteCheckpointTreatment, "object_gc_interval": 0, "durability": "before_ack", "client_credentials": "bootstrap machine; ClientCredentialsMapSub=false; stored claims revision=1", "followup": "distinct input, after read-only validation; not independent", "wire": "unmeasured single-node", "started_utc": started.UTC()}
	reducer, err := os.ReadFile("expiry_backlog_report_darwin_test.go")
	if err != nil {
		t.Fatal(err)
	}
	reducerHash := sha256.Sum256(reducer)
	manifest["reducer_source_sha256"] = hex.EncodeToString(reducerHash[:])
	finalizer, err := os.ReadFile("expiry_backlog_finalization_darwin_test.go")
	if err != nil {
		t.Fatal(err)
	}
	finalizerHash := sha256.Sum256(finalizer)
	manifest["finalizer_source_sha256"] = hex.EncodeToString(finalizerHash[:])
	b, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(root, "manifest.json"), b, 0600); err != nil {
		t.Fatal(err)
	}
	completed := 0
	var peak int64
	defer func() {
		if err := expiry65Summarize(root); err != nil {
			t.Error(err)
		}
		if err := expiry65Finalize(root, started, time.Now, completed, peak, t.Failed()); err != nil {
			t.Error(err)
		}
	}()
	for rep := 1; rep <= 3; rep++ {
		for _, op := range expiry65Operations {
			for _, state := range expiry65States {
				if ctx.Err() != nil {
					t.Fatal("aggregate deadline: remaining cases not run")
				}
				name := fmt.Sprintf("%d-%s-%s", rep, op, state)
				active := filepath.Join(root, "active")
				if err := os.Mkdir(active, 0700); err != nil {
					t.Fatal(err)
				}
				log, err := os.Create(filepath.Join(root, name+".log"))
				if err != nil {
					t.Fatal(err)
				}
				caseCtx, stop := context.WithTimeout(ctx, 60*time.Second)
				cmd := exec.CommandContext(caseCtx, executable, "-test.run=^TestExpiry65Case$", "-test.v", "-test.timeout=60s")
				cmd.Env = append(os.Environ(), "GOAUTHY_EXPIRY65_CASE="+op+"/"+state, "GOAUTHY_EXPIRY65_ACTIVE="+active)
				cmd.Stdout, cmd.Stderr = log, log
				if err := cmd.Start(); err != nil {
					stop()
					log.Close()
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- cmd.Wait() }()
				ticker := time.NewTicker(50 * time.Millisecond)
				var runErr error
			waiting:
				for {
					select {
					case runErr = <-done:
						break waiting
					case <-ticker.C:
						n, err := expiry65Disk(root)
						peak = max(peak, n)
						if err != nil || n > 240<<20 {
							stop()
							<-done
							runErr = fmt.Errorf("disk safety stop bytes=%d error=%v", n, err)
							break waiting
						}
					}
				}
				ticker.Stop()
				stop()
				if err := log.Close(); err != nil {
					t.Fatal(err)
				}
				n, err := expiry65Disk(root)
				peak = max(peak, n)
				if err != nil || n > 256<<20 {
					t.Fatalf("disk cap bytes=%d error=%v", n, err)
				}
				if runErr != nil {
					t.Fatalf("STOP %s: %v; raw failure retained, no replacement", name, runErr)
				}
				// Only this experiment's completed disposable fixture is removed.
				if err := os.RemoveAll(active); err != nil {
					t.Fatal(err)
				}
				completed++
				t.Logf("completed %s (%d/45), aggregate %.1fs", name, completed, time.Since(started).Seconds())
			}
		}
	}
	if ctx.Err() != nil {
		t.Fatal("aggregate deadline including evidence handling")
	}
}

type expiry65Sample struct {
	Phase                    string
	StartUTC, EndUTC         time.Time
	WallNS, UserUS, SystemUS int64
	TotalAlloc, Mallocs      uint64
}

func expiry65Measure(phase string, operation func()) expiry65Sample {
	var before, after runtime.MemStats
	var first, last syscall.Rusage
	runtime.ReadMemStats(&before)
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &first); err != nil {
		panic(err)
	}
	start := time.Now()
	operation()
	end := time.Now()
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &last); err != nil {
		panic(err)
	}
	runtime.ReadMemStats(&after)
	micros := func(v syscall.Timeval) int64 { return v.Sec*1000000 + int64(v.Usec) }
	return expiry65Sample{phase, start.UTC(), end.UTC(), end.Sub(start).Nanoseconds(), micros(last.Utime) - micros(first.Utime), micros(last.Stime) - micros(first.Stime), after.TotalAlloc - before.TotalAlloc, after.Mallocs - before.Mallocs}
}

type expiry65Fixture struct {
	t                                                *testing.T
	ctx                                              context.Context
	db                                               *rhiza.DB
	server                                           *Server
	browser                                          *browser.Store
	parent, sentinelSession                          browser.IssuedSession
	sentinelInteraction                              browser.IssuedAuthorizationInteraction
	code                                             string
	token                                            tokenResponse
	codeSignature, accessSignature, refreshSignature string
	root                                             string
}

func newExpiry65Fixture(t *testing.T, root string) *expiry65Fixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 55*time.Second)
	t.Cleanup(cancel)
	cfg := rhiza.Config{ClusterID: "expiry65", NodeID: "node", DataDir: filepath.Join(root, "data"), ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: filepath.Join(root, "objects"), ObjStorePrefix: "experiment", ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck, CheckpointInterval: time.Hour, CheckpointTailBytes: 512 << 20, ObjStoreGCInterval: 0}
	db, err := rhiza.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f := &expiry65Fixture{t: t, ctx: ctx, db: db, root: root}
	t.Cleanup(func() {
		if f.db != nil {
			if err := f.db.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	seedOAuthUser(t, db, "user-1")
	f.execute("claims", rhiza.SQLStatement{SQL: `INSERT INTO bootstrap_client_credentials_claims(client_id,claims_json,claims_at_root,revision,updated_at_unix_ms) VALUES(?,?,0,1,0)`, Args: []any{testClientID, `{"department":"synthetic"}`}})
	users, err := identity.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	key := oidcTestKey(t)
	f.server, err = NewServerWithOIDC(ctx, db, bytes.Repeat([]byte{7}, 32), testClientID, testClientSecret, testRedirectURI, nil, OIDCConfig{Issuer: oidcTestIssuer, LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return key, nil }, ValidateSubject: users.ValidateSubject, ClientCredentialsMapSub: false, ResolveClientCredentialsClaims: claims.NewStore(db).BootstrapClientCredentialsClaims, ResolvePrincipal: func(ctx context.Context, subject string) (PrincipalClaims, error) {
		// Frozen fixture has no memberships. Resolve current authority from the
		// same DB, never an unconditional success callback. rbac imports oauth.
		r, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COALESCE((SELECT revision FROM rbac_principal_versions WHERE subject=?),1) FROM identity_users WHERE subject=? AND disabled=0`, Args: []any{subject, subject}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return PrincipalClaims{}, err
		}
		if len(r.Rows) != 1 {
			return PrincipalClaims{}, errors.New("inactive measurement principal")
		}
		return PrincipalClaims{Revision: r.Rows[0][0].(int64)}, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	f.browser, err = browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	f.parent, err = f.browser.CreateInitSession(ctx, time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	// Fixture age only: parent predates expired children, but remains recently
	// seen and live. This setup mutation precedes both inputs and backlog seed.
	f.execute("parent-age", rhiza.SQLStatement{SQL: `UPDATE browser_sessions SET created_at_unix_ms=? WHERE token_digest=?`, Args: []any{time.Now().Add(-3 * time.Hour).UnixMilli(), f.parent.ID}})
	f.sentinelSession, err = f.browser.CreateUpstreamSession(ctx, "user-1", expiry65Binding(), "external", time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	f.sentinelInteraction, err = f.browser.CreateAuthorizationInteraction(ctx, f.parent.Token, "sentinel", []byte("synthetic-payload"), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.code = f.authorize("template-pending", strings.Repeat("p", 43))
	f.codeSignature = f.server.authorizeCodes.AuthorizeCodeSignature(ctx, f.code)
	code := f.authorize("template-consumed", strings.Repeat("q", 43))
	f.token = f.tokenResult(f.post(expiry65Redeem(code, strings.Repeat("q", 43))))
	f.accessSignature = f.server.accessTokens.AccessTokenSignature(ctx, f.token.AccessToken)
	f.refreshSignature = f.server.accessTokens.(interface {
		RefreshTokenSignature(context.Context, string) string
	}).RefreshTokenSignature(ctx, f.token.RefreshToken)
	return f
}

func expiry65Binding() browser.UpstreamSessionBinding {
	return browser.UpstreamSessionBinding{Issuer: "https://issuer.invalid", ClientID: "synthetic", Subject: "external-subject", SessionID: "external-session"}
}

func (f *expiry65Fixture) execute(id string, statements ...rhiza.SQLStatement) {
	f.t.Helper()
	req := rhiza.ExecuteRequest{RequestID: "expiry65-" + id, Statements: statements}
	b, err := json.Marshal(req) // Fixture accounting only; never in an operation timer.
	if err != nil || len(b) > 64<<10 {
		f.t.Fatalf("seed request bound bytes=%d error=%v", len(b), err)
	}
	if _, err := storage.Execute(f.ctx, f.db, req); err != nil {
		f.t.Fatal(err)
	}
}

func (f *expiry65Fixture) query(sql string, args ...any) [][]any {
	f.t.Helper()
	r, err := f.db.Query(f.ctx, rhiza.QueryRequest{SQL: sql, Args: args, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		f.t.Fatal(err)
	}
	return r.Rows
}

func expiry65AuthorizeRequest(ctx context.Context, id, verifier string) *http.Request {
	d := sha256.Sum256([]byte(verifier))
	v := url.Values{"response_type": {"code"}, "client_id": {testClientID}, "redirect_uri": {testRedirectURI}, "scope": {"goauthy.read offline_access"}, "state": {strings.Repeat("s", 32) + id}, "code_challenge": {base64.RawURLEncoding.EncodeToString(d[:])}, "code_challenge_method": {"S256"}}
	return httptest.NewRequest(http.MethodGet, "/oidc/authorize?"+v.Encode(), nil).WithContext(ctx)
}

func (f *expiry65Fixture) authorize(id, verifier string) string {
	w := httptest.NewRecorder()
	f.server.WriteAuthorization(w, expiry65AuthorizeRequest(f.ctx, id, verifier), "user-1", []string{"goauthy.read", "offline_access"})
	return f.codeResult(w)
}

func (f *expiry65Fixture) codeResult(w *httptest.ResponseRecorder) string {
	f.t.Helper()
	u, err := url.Parse(w.Header().Get("Location"))
	if err != nil || u.Query().Get("error") != "" || u.Query().Get("code") == "" {
		f.t.Fatalf("authorization failed status=%d (payload omitted)", w.Code)
	}
	return u.Query().Get("code")
}

func expiry65Redeem(code, verifier string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}}
}
func expiry65TokenRequest(ctx context.Context, v url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/oidc/token", strings.NewReader(v.Encode())).WithContext(ctx)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(testClientID, testClientSecret)
	return r
}
func (f *expiry65Fixture) post(v url.Values) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.server.TokenHandler().ServeHTTP(w, expiry65TokenRequest(f.ctx, v))
	return w
}
func (f *expiry65Fixture) tokenResult(w *httptest.ResponseRecorder) tokenResponse {
	f.t.Helper()
	var token tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &token); err != nil || w.Code != http.StatusOK || token.AccessToken == "" {
		f.t.Fatalf("token failed status=%d (payload omitted)", w.Code)
	}
	return token
}

var expiry65Tables = []struct{ name, key string }{
	{"browser_sessions", "token_digest"}, {"browser_upstream_session_bindings", "session_digest"}, {"browser_authorization_interactions", "token_digest"},
	{"oauth_authorize_codes", "signature"}, {"oauth_pkce_requests", "signature"}, {"oauth_access_tokens", "signature"}, {"oauth_token_requests", "signature"}, {"oauth_refresh_tokens", "signature"},
}

func expiry65Digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type expiry65TableState struct {
	Rows, SeedRows, TextBytes  int
	SeedSHA256, SentinelSHA256 string
}

func (f *expiry65Fixture) state() map[string]expiry65TableState {
	out := map[string]expiry65TableState{}
	interactionDigest, err := browser.CanonicalTokenDigest(f.sentinelInteraction.Token)
	if err != nil {
		f.t.Fatal(err)
	}
	sentinels := []string{f.sentinelSession.ID, f.sentinelSession.ID, interactionDigest, f.codeSignature, f.codeSignature, f.accessSignature, f.accessSignature, f.refreshSignature}
	for i, table := range expiry65Tables {
		rows := f.query("SELECT * FROM " + table.name + " ORDER BY " + table.key)
		seeds := f.query("SELECT * FROM " + table.name + " WHERE " + table.key + " LIKE 'expiry65-seed-%' ORDER BY " + table.key)
		sentinel := f.query("SELECT * FROM "+table.name+" WHERE "+table.key+"=?", sentinels[i])
		if len(sentinel) != 1 {
			f.t.Fatalf("sentinel lookup %s returned %d rows, want exactly one", table.name, len(sentinel))
		}
		textBytes := 0
		for _, row := range rows {
			for _, v := range row {
				if s, ok := v.(string); ok {
					textBytes += len(s)
				}
			}
		}
		out[table.name] = expiry65TableState{len(rows), len(seeds), textBytes, expiry65Digest(seeds), expiry65Digest(sentinel)}
	}
	return out
}
func (f *expiry65Fixture) observe(phase string) {
	files := map[string]int64{}
	if err := filepath.WalkDir(f.root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(f.root, path)
		if err != nil {
			return err
		}
		files[rel] = info.Size()
		return nil
	}); err != nil {
		f.t.Fatal(err)
	}
	stats, ok := f.db.ObjectStoreStats()
	if !ok && phase != "postclose" {
		f.t.Fatal("object counters unavailable")
	}
	var counters any
	if ok {
		counters = stats
	}
	// Names are hashes/relative local storage paths only, never row contents or credentials.
	expiry65JSON(f.t, phase, map[string]any{"files": files, "object_stats_available": ok, "object_stats": counters})
}

// Backlogs clone valid production projections independently for each table;
// code and PKCE snapshots deliberately retain their different forms.
func (f *expiry65Fixture) seed(op, state string, n int) {
	if state == "empty" {
		n = 0
	}
	expiry := time.Now().Add(time.Hour).UnixMilli()
	if state == "expired" {
		expiry = time.Now().Add(-time.Hour).UnixMilli()
	}
	created := expiry - time.Hour.Milliseconds()
	projection := func(table, key string) requestRecord {
		var r requestRecord
		rows := f.query("SELECT request_json FROM "+table+" WHERE signature=?", key)
		if len(rows) != 1 {
			f.t.Fatal("template missing")
		}
		if err := json.Unmarshal([]byte(rows[0][0].(string)), &r); err != nil {
			f.t.Fatal(err)
		}
		for typ := range r.ExpiresAt {
			r.ExpiresAt[typ] = expiry
		}
		r.RequestedAt = created
		return r
	}
	code := projection("oauth_authorize_codes", f.codeSignature)
	pkce := projection("oauth_pkce_requests", f.codeSignature)
	access := projection("oauth_token_requests", f.accessSignature)
	refresh := projection("oauth_refresh_tokens", f.refreshSignature)
	if reflect.DeepEqual(code.Form, pkce.Form) {
		f.t.Fatal("code/PKCE template forms unexpectedly equal")
	}
	encode := func(r requestRecord, id string) string {
		r.ID = id
		b, err := json.Marshal(r)
		if err != nil {
			f.t.Fatal(err)
		}
		return string(b)
	}
	for start := 0; start < n; start += 10 {
		var statements []rhiza.SQLStatement
		for j := start; j < min(start+10, n); j++ {
			id := fmt.Sprintf("expiry65-seed-%04d", j)
			switch op {
			case "session":
				statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO browser_sessions(token_digest,subject,auth_method,created_at_unix_ms,expires_at_unix_ms,last_seen_at_unix_ms,peer_ip) SELECT ?,subject,auth_method,?,?,?,peer_ip FROM browser_sessions WHERE token_digest=?`, Args: []any{id, created, expiry, created, f.sentinelSession.ID}}, rhiza.SQLStatement{SQL: `INSERT INTO browser_upstream_session_bindings SELECT ?,issuer,client_id,upstream_subject,upstream_sid,? FROM browser_upstream_session_bindings WHERE session_digest=?`, Args: []any{id, created, f.sentinelSession.ID}})
			case "interaction":
				statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO browser_authorization_interactions(token_digest,request_id,session_digest,payload,created_at_unix_ms,expires_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{id, id, f.parent.ID, base64.RawURLEncoding.EncodeToString([]byte("synthetic-payload")), created, expiry}})
			case "code":
				statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO oauth_authorize_codes(signature,request_json,expires_at_unix_ms) VALUES(?,?,?)`, Args: []any{id, encode(code, id), expiry}}, rhiza.SQLStatement{SQL: `INSERT INTO oauth_pkce_requests(signature,request_json,expires_at_unix_ms) VALUES(?,?,?)`, Args: []any{id, encode(pkce, id), expiry}})
			case "redemption", "client_credentials":
				statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO oauth_access_tokens SELECT ?,?,client_id,?,?,requested_scopes,granted_scopes,requested_audience,granted_audience FROM oauth_access_tokens WHERE signature=?`, Args: []any{id, id, created, expiry, f.accessSignature}}, rhiza.SQLStatement{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES(?,?)`, Args: []any{id, encode(access, id)}})
				if op == "redemption" {
					statements = append(statements, rhiza.SQLStatement{SQL: `INSERT INTO oauth_refresh_tokens(signature,access_signature,request_id,request_json,expires_at_unix_ms) VALUES(?,?,?,?,?)`, Args: []any{id, id, id, encode(refresh, id), expiry}})
				}
			}
		}
		f.execute("seed-"+op+"-"+state+"-"+strconv.Itoa(start), statements...)
	}
}

func expiry65Affected(op string) []string {
	switch op {
	case "session":
		return []string{"browser_sessions", "browser_upstream_session_bindings"}
	case "interaction":
		return []string{"browser_authorization_interactions"}
	case "code":
		return []string{"oauth_authorize_codes", "oauth_pkce_requests"}
	case "redemption":
		return []string{"oauth_access_tokens", "oauth_token_requests", "oauth_refresh_tokens"}
	default:
		return []string{"oauth_access_tokens", "oauth_token_requests"}
	}
}

func (f *expiry65Fixture) assertSeedExpiryState(op, state string, bundles int) {
	f.t.Helper()
	want := bundles
	if state == "empty" {
		want = 0
	}
	now := time.Now().UnixMilli()
	for _, table := range expiry65Affected(op) {
		if table == "browser_upstream_session_bindings" {
			continue // Binding rows follow the session expiry and have no expiry column.
		}
		checkExpiry := func(expiry int64) {
			f.t.Helper()
			if state == "live" && expiry <= now || state == "expired" && expiry > now {
				f.t.Fatalf("%s %s seed in %s has unexpected expiry %d at %d", state, op, table, expiry, now)
			}
		}
		if table == "oauth_token_requests" {
			rows := f.query(`SELECT request_json FROM oauth_token_requests WHERE signature LIKE 'expiry65-seed-%' ORDER BY signature`)
			if len(rows) != want {
				f.t.Fatalf("%s %s seeds in %s=%d, want %d", state, op, table, len(rows), want)
			}
			for _, row := range rows {
				var request requestRecord
				if err := json.Unmarshal([]byte(row[0].(string)), &request); err != nil {
					f.t.Fatal(err)
				}
				if len(request.ExpiresAt) == 0 {
					f.t.Fatalf("seed request in %s has no expiry", table)
				}
				for _, expiry := range request.ExpiresAt {
					checkExpiry(expiry)
				}
			}
		} else {
			key := "signature"
			if table == "browser_sessions" || table == "browser_authorization_interactions" {
				key = "token_digest"
			}
			rows := f.query("SELECT expires_at_unix_ms FROM " + table + " WHERE " + key + " LIKE 'expiry65-seed-%' ORDER BY " + key)
			if len(rows) != want {
				f.t.Fatalf("%s %s seeds in %s=%d, want %d", state, op, table, len(rows), want)
			}
			for _, row := range rows {
				checkExpiry(row[0].(int64))
			}
		}
	}
}

func TestExpiry65Case(t *testing.T) {
	which := os.Getenv("GOAUTHY_EXPIRY65_CASE")
	if which == "" {
		t.Skip("child of bounded campaign")
	}
	parts := strings.Split(which, "/")
	if len(parts) != 2 || !slices.Contains(expiry65Operations, parts[0]) || !slices.Contains(expiry65States, parts[1]) {
		t.Fatal("invalid frozen case")
	}
	op, state := parts[0], parts[1]
	root := os.Getenv("GOAUTHY_EXPIRY65_ACTIVE")
	if root == "" {
		t.Fatal("active directory required")
	}
	runExpiry65Case(t, op, state, 1000, root)
}

// Two-bundle correctness smoke checks are not primary samples. No load matrix.
func TestExpiry65FixtureShapes(t *testing.T) {
	for _, op := range expiry65Operations {
		for _, state := range expiry65States {
			t.Run(op+"/"+state, func(t *testing.T) { runExpiry65Case(t, op, state, 2, t.TempDir()) })
		}
	}
}

func runExpiry65Case(t *testing.T, op, state string, bundles int, root string) {
	f := newExpiry65Fixture(t, root)
	verifiers := []string{strings.Repeat("a", 43), strings.Repeat("b", 43)}
	codes := make([]string, 2)
	requests := make([]*http.Request, 2)
	responses := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder()}
	sessions := make([]browser.IssuedSession, 2)
	interactions := make([]browser.IssuedAuthorizationInteraction, 2)
	tokens := make([]tokenResponse, 2)
	inputExpiry := time.Now().Add(time.Hour)
	payload := []byte("synthetic-payload")
	binding := expiry65Binding()
	ids := []string{"operation-0", "operation-1"}
	for i := range 2 {
		switch op {
		case "code":
			requests[i] = expiry65AuthorizeRequest(f.ctx, fmt.Sprintf("operation-%d", i), verifiers[i])
		case "redemption":
			codes[i] = f.authorize(fmt.Sprintf("operation-%d", i), verifiers[i])
			requests[i] = expiry65TokenRequest(f.ctx, expiry65Redeem(codes[i], verifiers[i]))
		case "client_credentials":
			requests[i] = expiry65TokenRequest(f.ctx, url.Values{"grant_type": {"client_credentials"}, "scope": {"goauthy.read"}})
		}
	}
	baseline := f.state()
	f.seed(op, state, bundles)
	before := f.state()
	f.assertSeedExpiryState(op, state, bundles)
	for table, b := range baseline {
		want := 0
		if state != "empty" && slices.Contains(expiry65Affected(op), table) {
			want = bundles
		}
		if before[table].Rows != b.Rows+want || before[table].SeedRows != want || before[table].SentinelSHA256 != b.SentinelSHA256 {
			t.Fatalf("seed oracle table=%s", table)
		}
	}
	expiry65JSON(t, "case", map[string]any{"operation": op, "state": state, "backlog_bundles": map[bool]int{true: 0, false: bundles}[state == "empty"], "before": before, "checkpoint_history": expiry65CheckpointHistory, "sqlite_checkpoint_treatment": expiry65SQLiteCheckpointTreatment})
	f.observe("before")
	expiry65JSON(t, "empty_bracket", expiry65Measure("empty", func() {}))
	for i := range 2 {
		var opErr error
		id := ids[i]
		f.observe(fmt.Sprintf("before_operation_%d", i))
		sample := expiry65Measure([]string{"first", "post_validation_followup"}[i], func() {
			switch op {
			case "session":
				sessions[i], opErr = f.browser.CreateUpstreamSession(f.ctx, "user-1", binding, "external", inputExpiry, "")
			case "interaction":
				interactions[i], opErr = f.browser.CreateAuthorizationInteraction(f.ctx, f.parent.Token, id, payload, inputExpiry)
			case "code":
				f.server.WriteAuthorization(responses[i], requests[i], "user-1", []string{"goauthy.read", "offline_access"})
			default:
				f.server.TokenHandler().ServeHTTP(responses[i], requests[i])
			}
		})
		expiry65JSON(t, "sample", sample)
		if opErr != nil {
			t.Fatalf("operation error: %v", opErr)
		}
		f.observe(fmt.Sprintf("after_operation_%d", i))
		// Everything through the next timer is read-only validation.
		switch op {
		case "session":
			got, err := f.browser.LoadSessionReadOnly(f.ctx, sessions[i].Token)
			if err != nil || got.Subject != "user-1" || got.AuthenticationMethod != "external" {
				t.Fatal("session artifact")
			}
			if len(f.query(`SELECT 1 FROM browser_upstream_session_bindings WHERE session_digest=? AND issuer=? AND client_id=? AND upstream_subject=? AND upstream_sid=?`, got.ID, binding.Issuer, binding.ClientID, binding.Subject, binding.SessionID)) != 1 {
				t.Fatal("new binding")
			}
		case "interaction":
			got, err := f.browser.LoadAuthorizationInteractionReadOnly(f.ctx, f.parent.Token, interactions[i].Token)
			if err != nil || got.RequestID != id || string(got.Payload) != string(payload) {
				t.Fatal("interaction artifact")
			}
		case "code":
			codes[i] = f.codeResult(responses[i])
			sig := f.server.authorizeCodes.AuthorizeCodeSignature(f.ctx, codes[i])
			for _, table := range []string{"oauth_authorize_codes", "oauth_pkce_requests"} {
				if len(f.query("SELECT 1 FROM "+table+" WHERE signature=?", sig)) != 1 {
					t.Fatal("missing code/PKCE artifact")
				}
			}
			codeRequest, err := f.server.store.GetAuthorizeCodeSession(f.ctx, sig, &fosite.DefaultSession{})
			if err != nil || codeRequest.GetRequestForm().Get("redirect_uri") != testRedirectURI || !codeRequest.GetGrantedScopes().Has("offline_access") {
				t.Fatal("code projection/binding")
			}
			pkceRequest, err := f.server.store.GetPKCERequestSession(f.ctx, sig, &fosite.DefaultSession{})
			digest := sha256.Sum256([]byte(verifiers[i]))
			if err != nil || pkceRequest.GetRequestForm().Get("code_challenge") != base64.RawURLEncoding.EncodeToString(digest[:]) || pkceRequest.GetRequestForm().Get("code_challenge_method") != "S256" {
				t.Fatal("PKCE projection/binding")
			}
		default:
			tokens[i] = f.tokenResult(responses[i])
			f.validateToken(tokens[i], op == "redemption")
			if op == "redemption" {
				sig := f.server.authorizeCodes.AuthorizeCodeSignature(f.ctx, codes[i])
				if len(f.query(`SELECT 1 FROM oauth_authorize_codes WHERE signature=? AND invalidated=1 AND used_attempt IS NOT NULL`, sig)) != 1 || len(f.query(`SELECT 1 FROM oauth_pkce_requests WHERE signature=?`, sig)) != 0 {
					t.Fatal("code consumption proof")
				}
			}
		}
		after := f.state()
		for table, b := range baseline {
			seed := before[table].SeedRows
			if state == "expired" {
				seed = 0
			}
			want := b.Rows + seed
			if slices.Contains(expiry65Affected(op), table) {
				want += i + 1
			}
			if op == "redemption" && table == "oauth_pkce_requests" {
				want -= i + 1
			}
			if after[table].Rows != want || after[table].SeedRows != seed || after[table].SentinelSHA256 != before[table].SentinelSHA256 {
				t.Fatalf("after %d table=%s rows=%d want=%d seed=%d want=%d or sentinel changed", i, table, after[table].Rows, want, after[table].SeedRows, seed)
			}
			if state == "live" && after[table].SeedSHA256 != before[table].SeedSHA256 {
				t.Fatal("live seed fields changed")
			}
			if state == "empty" && after[table].SeedRows != 0 || state == "expired" && after[table].SeedRows != 0 {
				t.Fatalf("%s control seed cardinality in %s=%d, want 0", state, table, after[table].SeedRows)
			}
		}
		expiry65JSON(t, fmt.Sprintf("validated_%d", i), after)
	}
	// Consumptive checks are deliberately after BOTH timers.
	if op == "interaction" {
		for _, in := range interactions {
			if _, err := f.browser.ConsumeAuthorizationInteraction(f.ctx, f.parent.Token, in.Token); err != nil {
				t.Fatal(err)
			}
			if _, err := f.browser.ConsumeAuthorizationInteraction(f.ctx, f.parent.Token, in.Token); !errors.Is(err, browser.ErrConsumed) {
				t.Fatal("interaction replay accepted")
			}
		}
	}
	if op == "code" {
		for i, code := range codes {
			tokens[i] = f.tokenResult(f.post(expiry65Redeem(code, verifiers[i])))
			f.validateToken(tokens[i], true)
		}
	}
	if op == "code" || op == "redemption" {
		// Rotation exercises the actual HTTP path; inspect staged SQL separately below.
		rotated := f.tokenResult(f.post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens[1].RefreshToken}}))
		f.validateToken(rotated, true)
		old := f.server.accessTokens.(interface {
			RefreshTokenSignature(context.Context, string) string
		}).RefreshTokenSignature(f.ctx, tokens[1].RefreshToken)
		if len(f.query(`SELECT 1 FROM oauth_refresh_tokens WHERE signature=? AND active=0 AND rotated_attempt IS NOT NULL`, old)) != 1 {
			t.Fatal("rotation winner missing")
		}
		if f.post(expiry65Redeem(codes[0], verifiers[0])).Code == http.StatusOK {
			t.Fatal("code replay accepted")
		}
	}
	f.observe("final_preclose")
	expiry65JSON(t, "final_tables", f.state())
	closeStart := time.Now()
	if err := f.db.Close(); err != nil {
		t.Fatal(err)
	}
	// Close may checkpoint. Never mix these counters/files with issuance deltas.
	expiry65JSON(t, "close", map[string]any{"wall_ns": time.Since(closeStart).Nanoseconds()})
	f.observe("postclose")
	f.db = nil
	if n, err := expiry65Disk(root); err != nil || n > 240<<20 {
		t.Fatalf("final disk bound bytes=%d err=%v", n, err)
	}
}

func (f *expiry65Fixture) validateToken(token tokenResponse, refresh bool) {
	f.t.Helper()
	a := f.server.accessTokens.AccessTokenSignature(f.ctx, token.AccessToken)
	rows := f.query(`SELECT a.request_id FROM oauth_access_tokens a JOIN oauth_token_requests r ON r.signature=a.signature WHERE a.signature=? AND a.client_id=? AND a.expires_at_unix_ms>?`, a, testClientID, time.Now().UnixMilli())
	if len(rows) != 1 {
		f.t.Fatal("access/request artifact linkage")
	}
	request, err := f.server.store.GetAccessTokenSession(f.ctx, a, &fosite.DefaultSession{})
	if err != nil || request.GetID() != rows[0][0] || request.GetClient().GetID() != testClientID {
		f.t.Fatal("access request authority/binding")
	}
	if refresh {
		if token.RefreshToken == "" {
			f.t.Fatal("offline_access did not issue refresh token")
		}
		r := f.server.accessTokens.(interface {
			RefreshTokenSignature(context.Context, string) string
		}).RefreshTokenSignature(f.ctx, token.RefreshToken)
		if len(f.query(`SELECT 1 FROM oauth_refresh_tokens WHERE signature=? AND access_signature=? AND request_id=? AND active=1 AND expires_at_unix_ms>?`, r, a, rows[0][0], time.Now().UnixMilli())) != 1 {
			f.t.Fatal("refresh artifact linkage")
		}
	} else if token.RefreshToken != "" {
		f.t.Fatal("machine unexpectedly issued refresh")
	}
}

func TestExpiry65TransactionBoundaries(t *testing.T) {
	f := newExpiry65Fixture(t, t.TempDir())
	before := f.state()
	f.seed("session", "expired", 2)
	f.execute("abort", rhiza.SQLStatement{SQL: `CREATE TRIGGER expiry65_abort AFTER INSERT ON browser_sessions BEGIN SELECT RAISE(ABORT,'synthetic late abort'); END`})
	if _, err := f.browser.CreateSession(f.ctx, "user-1", "pwd", time.Now().Add(time.Hour), ""); err == nil {
		t.Fatal("late abort succeeded")
	}
	after := f.state()
	for _, table := range expiry65Affected("session") {
		if after[table].Rows != before[table].Rows+2 || after[table].SeedRows != 2 {
			t.Fatal("SQL abort did not roll back cleanup")
		}
	}
	f.execute("drop-abort", rhiza.SQLStatement{SQL: `DROP TRIGGER expiry65_abort`})
	// A missing conditional INSERT is confirmed after Execute, not rolled back.
	if _, err := f.browser.CreateSession(f.ctx, "missing-user", "pwd", time.Now().Add(time.Hour), ""); err == nil {
		t.Fatal("missing subject succeeded")
	}
	after = f.state()
	for _, table := range expiry65Affected("session") {
		if after[table].Rows != before[table].Rows || after[table].SeedRows != 0 {
			t.Fatal("postconfirmation cleanup contract")
		}
	}
	f.seed("client_credentials", "expired", 2)
	f.server.beforeTokenIssue = func() {
		f.server.beforeTokenIssue = nil
		f.execute("revision", rhiza.SQLStatement{SQL: `UPDATE bootstrap_client_credentials_claims SET revision=revision+1 WHERE client_id=?`, Args: []any{testClientID}})
	}
	if f.post(url.Values{"grant_type": {"client_credentials"}}).Code == http.StatusOK {
		t.Fatal("stale CC policy issued")
	}
	after = f.state()
	for _, table := range expiry65Affected("client_credentials") {
		if after[table].Rows != before[table].Rows || after[table].SeedRows != 0 {
			t.Fatal("separate cleanup or rejected issuance contract")
		}
	}
	// Pre-existing orphan control is separate from the linked expiry matrix.
	f.execute("orphan", rhiza.SQLStatement{SQL: `INSERT INTO oauth_token_requests(signature,request_json) VALUES('orphan','{}')`})
	f.tokenResult(f.post(url.Values{"grant_type": {"client_credentials"}}))
	if len(f.query(`SELECT 1 FROM oauth_token_requests WHERE signature='orphan'`)) != 0 {
		t.Fatal("pre-existing orphan retained")
	}
	// Inspect the actual staging callbacks without committing/replaying them.
	request, err := f.server.store.GetRefreshTokenSession(f.ctx, f.refreshSignature, &fosite.DefaultSession{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := f.server.store.BeginTX(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.server.store.RotateRefreshToken(ctx, request.GetID(), f.refreshSignature); err != nil {
		t.Fatal(err)
	}
	if err = f.server.store.CreateAccessTokenSession(ctx, "diagnostic-only", request); err != nil {
		t.Fatal(err)
	}
	if err = f.server.store.CreateRefreshTokenSession(ctx, "diagnostic-refresh", "diagnostic-only", request); err != nil {
		t.Fatal(err)
	}
	var sequence []string
	for _, stmt := range txFrom(ctx).statements {
		if strings.HasPrefix(stmt.SQL, "DELETE FROM") {
			sequence = append(sequence, strings.Fields(stmt.SQL)[2])
		}
	}
	want := []string{"oauth_access_tokens", "oauth_token_requests", "oauth_access_tokens", "oauth_token_requests", "oauth_refresh_tokens"}
	if !slices.Equal(sequence, want) {
		t.Fatalf("rotation delete sequence=%v", sequence)
	}
	if err = f.server.store.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	rotated := f.tokenResult(f.post(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {f.token.RefreshToken}}))
	f.validateToken(rotated, true)
	if len(f.query(`SELECT 1 FROM oauth_refresh_tokens WHERE signature=? AND active=0 AND rotated_attempt IS NOT NULL`, f.refreshSignature)) != 1 {
		t.Fatal("actual rotation did not consume")
	}
}
