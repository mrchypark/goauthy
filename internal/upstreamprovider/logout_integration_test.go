package upstreamprovider_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/mrchypark/goauthy/internal/backchannel"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/oauth"
	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

// copyDirTree copies the directory tree rooted at source into destination.
func copyDirTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, content, 0o644)
	})
}

type logoutTemplateResult struct {
	dir string
	err error
}

var (
	logoutTemplateDirs sync.Map
	logoutTemplateOnce sync.Map
)

func logoutMigratedTemplate(t *testing.T, nodeID string) string {
	t.Helper()
	once, _ := logoutTemplateOnce.LoadOrStore(nodeID, &sync.Once{})
	once.(*sync.Once).Do(func() {
		directory, err := os.MkdirTemp("", "goauthy-logout-template-"+nodeID+"-")
		if err != nil {
			logoutTemplateDirs.Store(nodeID, logoutTemplateResult{err: err})
			return
		}
		db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: nodeID, DataDir: directory})
		if err != nil {
			os.RemoveAll(directory)
			logoutTemplateDirs.Store(nodeID, logoutTemplateResult{err: fmt.Errorf("open template for %s: %w", nodeID, err)})
			return
		}
		if err := storage.Migrate(context.Background(), db); err != nil {
			db.Close()
			os.RemoveAll(directory)
			logoutTemplateDirs.Store(nodeID, logoutTemplateResult{err: fmt.Errorf("migrate template for %s: %w", nodeID, err)})
			return
		}
		db.Close()
		logoutTemplateDirs.Store(nodeID, logoutTemplateResult{dir: directory})
	})
	result, ok := logoutTemplateDirs.Load(nodeID)
	if !ok {
		t.Fatalf("template for %s not in cache", nodeID)
	}
	r := result.(logoutTemplateResult)
	if r.err != nil {
		t.Fatal(r.err)
	}
	return r.dir
}

func logoutOpenTestDB(t *testing.T, nodeID string) *rhiza.DB {
	t.Helper()
	directory := t.TempDir()
	if err := copyDirTree(logoutMigratedTemplate(t, nodeID), directory); err != nil {
		t.Fatal(err)
	}
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: nodeID, DataDir: directory})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db
}

// This test crosses the public HTTP boundary, remote JWKS verification, and
// the replicated session/outbox transaction.  Unit tests cover malformed
// input; this ensures a verified upstream token reaches that transaction.
func TestBackchannelLogoutHTTPRevokesOnlyExactUpstreamSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "upstream-key", Algorithm: "RS256", Use: "sig"}}})
	}))
	defer jwks.Close()

	issuer, clientID := "https://upstream.example.test", "upstream-client"
	configs := map[string]upstreamprovider.Config{"upstream": {
		Issuer: issuer, ClientID: clientID, JWKSURI: jwks.URL,
		AuthorizationEndpoint: jwks.URL + "/authorize", TokenEndpoint: jwks.URL + "/token",
	}}
	verifier, err := upstreamprovider.NewJWKSVerifier(configs, jwks.Client())
	if err != nil {
		t.Fatal(err)
	}

	db := logoutOpenTestDB(t, "upstream-logout-http")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "upstream-logout-http-user", SQL: `INSERT INTO identity_users(subject,username,password_phc) VALUES('external-user','external-user','phc')`}); err != nil {
		t.Fatal(err)
	}
	browserStore, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	create := func(name, bindingIssuer, bindingClient, subject, sid string) browser.IssuedSession {
		t.Helper()
		issued, err := browserStore.CreateUpstreamSession(ctx, "external-user", browser.UpstreamSessionBinding{
			Issuer: bindingIssuer, ClientID: bindingClient, Subject: subject, SessionID: sid,
		}, "external", now.Add(time.Hour), "203.0.113.8")
		if err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
		return issued
	}
	target := create("target", issuer, clientID, "alice", "upstream-sid")
	sameSubject := create("same subject", issuer, clientID, "alice", "other-sid")
	sameSID := create("same sid", issuer, clientID, "bob", "upstream-sid")
	unrelated := create("unrelated", "https://other.example.test", "other-client", "mallory", "other-sid")
	var received struct {
		sync.Mutex
		token string
	}
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || len(r.PostForm["logout_token"]) != 1 {
			http.Error(w, "invalid logout request", http.StatusBadRequest)
			return
		}
		received.Lock()
		received.token = r.PostForm.Get("logout_token")
		received.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer rp.Close()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "upstream-logout-http-downstream-client", SQL: `INSERT INTO oidc_session_clients(sid,client_id,logout_uri,allow_private,allow_http,created_at_unix_ms) VALUES(?,?,?,?,?,?)`, Args: []any{target.ID, "downstream-rp", rp.URL, int64(1), int64(1), now.UnixMilli()}}); err != nil {
		t.Fatal(err)
	}

	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	downstreamKey := oidc.SigningKey{Private: private, PublicJWK: jose.JSONWebKey{Key: public, KeyID: "local-logout-key", Algorithm: "EdDSA", Use: "sig"}, CreatedAt: now}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	oauthServer, err := oauth.NewServerWithOIDC(ctx, db, secret, "browser-client", "correct-horse-battery-staple", "http://localhost/callback", nil, oauth.OIDCConfig{
		Issuer: "https://goauthy.example.test", LoadSigningKey: func(context.Context) (oidc.SigningKey, error) {
			return downstreamKey, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := signedUpstreamLogoutToken(t, key, "upstream-key", issuer, clientID, "alice", "upstream-sid", "logout-http-1", now, now.Add(time.Minute))
	h, err := upstreamprovider.NewHandler(configs, logoutHTTPStore{}, logoutHTTPExchanger{}, verifier, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("POST /upstream/{providerID}/backchannel-logout", h.BackchannelLogoutHandler(func(ctx context.Context, client string, claims *upstreamprovider.LogoutTokenClaims, digest string) error {
		return oauthServer.RevokeUpstreamSessions(ctx, oauth.UpstreamLogout{
			Issuer: claims.Issuer, ClientID: client, Subject: claims.Subject, SessionID: claims.SessionID,
			JTI: claims.JTI, TokenDigest: digest, ExpiresAt: claims.ReplayUntil,
		})
	}))
	server := httptest.NewServer(mux)
	defer server.Close()
	post := func() *http.Response {
		t.Helper()
		response, err := server.Client().Post(server.URL+"/upstream/upstream/backchannel-logout", "application/x-www-form-urlencoded", strings.NewReader(url.Values{"logout_token": {raw}}.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	for attempt := 0; attempt < 2; attempt++ {
		response := post()
		if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
			response.Body.Close()
			t.Fatalf("attempt=%d status=%d headers=%v", attempt, response.StatusCode, response.Header)
		}
		body := make([]byte, 128)
		n, _ := response.Body.Read(body)
		response.Body.Close()
		if strings.Contains(string(body[:n]), raw) {
			t.Fatal("logout response leaked raw token")
		}
	}

	for _, check := range []struct {
		name    string
		issued  browser.IssuedSession
		revoked bool
	}{
		{"target", target, true},
		{"same subject, wrong sid", sameSubject, false},
		{"same sid, wrong subject", sameSID, false},
		{"unrelated issuer/client/subject", unrelated, false},
	} {
		row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT revoked_at_unix_ms FROM browser_sessions WHERE token_digest=?`, Args: []any{check.issued.ID}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || (row.Rows[0][0] != nil) != check.revoked {
			t.Fatalf("%s revoked=%v rows=%v err=%v", check.name, check.revoked, row.Rows, err)
		}
	}
	for _, query := range []struct {
		name string
		sql  string
		args []any
	}{
		{"receipt", `SELECT COUNT(*) FROM upstream_logout_receipts`, nil},
		{"durable downstream event", `SELECT COUNT(*) FROM oidc_backchannel_deliveries WHERE sid=?`, []any{target.ID}},
	} {
		row, err := db.Query(ctx, rhiza.QueryRequest{SQL: query.sql, Args: query.args, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(1) {
			t.Fatalf("%s rows=%v err=%v", query.name, row.Rows, err)
		}
	}

	deliveryNow := time.Now().UTC().Add(time.Second)
	worker := backchannel.Worker{
		DB: db, Issuer: "https://goauthy.example.test", LoadSigningKey: func(context.Context) (oidc.SigningKey, error) { return downstreamKey, nil },
		WorkerID: "upstream-logout-http", TickInterval: time.Second, RetryBase: time.Second, LeaseDuration: time.Minute,
		RequestTimeout: time.Second, MaxAttempts: 3, TokenLifetime: time.Minute, AllowPrivate: true, AllowHTTP: true,
	}
	if err := worker.Step(ctx, deliveryNow); err != nil {
		t.Fatal(err)
	}
	received.Lock()
	delivered := received.token
	received.Unlock()
	claims, err := oidc.VerifyLogoutToken(delivered, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{downstreamKey.PublicJWK}}, "https://goauthy.example.test", "downstream-rp", deliveryNow)
	if err != nil || claims.SessionID != target.ID || claims.JTI == "" {
		t.Fatalf("downstream logout claims=%#v err=%v", claims, err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT COUNT(*),COUNT(delivered_at_unix_ms) FROM oidc_backchannel_deliveries`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 || row.Rows[0][0] != int64(1) || row.Rows[0][1] != int64(1) {
		t.Fatalf("delivery rows=%v err=%v", row.Rows, err)
	}
}

func signedUpstreamLogoutToken(t *testing.T, key *rsa.PrivateKey, kid, issuer, audience, subject, sid, jti string, issuedAt, expiresAt time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]any{
		"iss": issuer, "aud": audience, "sub": subject, "sid": sid, "jti": jti,
		"iat": issuedAt.Unix(), "exp": expiresAt.Unix(), "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// These are unused by the mounted logout endpoint but NewHandler deliberately
// requires the same complete dependencies as callback routes.
type logoutHTTPStore struct{}

func (logoutHTTPStore) Save(context.Context, upstreamprovider.Transaction) error { return nil }
func (logoutHTTPStore) Consume(context.Context, string, string, string, time.Time) (upstreamprovider.Transaction, error) {
	return upstreamprovider.Transaction{}, nil
}

type logoutHTTPExchanger struct{}

func (logoutHTTPExchanger) ExchangeCode(context.Context, string, string, string, string) (*upstreamprovider.TokenExchangeResult, error) {
	return nil, nil
}
