package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/rand/v2"

	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/mrchypark/goauthy/internal/backup"
	"github.com/mrchypark/goauthy/internal/browser"
	"github.com/mrchypark/goauthy/internal/clients"
	"github.com/mrchypark/goauthy/internal/oidc"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"github.com/ory/fosite"
	"github.com/thanos-io/objstore/providers/filesystem"
)

// Opt-in, synthetic baseline only. No representation or persistence change.
var snapshotShapes = []struct {
	name                          string
	scopes, claims, form, payload int
}{
	{"small", 2, 256, 256, 256}, {"medium", 8, 2048, 2048, 4096}, {"large", 32, 16384, 8192, 65536},
}

func snapshotRequest(client fosite.Client, shape int) *fosite.Request {
	s := snapshotShapes[shape]
	r := fosite.NewRequest()
	r.ID = "synthetic-request"
	r.Client = client
	r.RequestedAt = time.Now().UTC()
	r.Form = url.Values{"redirect_uri": {testRedirectURI}, "code_challenge": {strings.Repeat("c", 43)}, "code_challenge_method": {"S256"}, "scope": {strings.Repeat("f", s.form)}}
	for i := 0; i < s.scopes; i++ {
		scope := fmt.Sprintf("synthetic.scope.%02d", i)
		r.AppendRequestedScope(scope)
		r.GrantScope(scope)
	}
	r.Session = &fosite.DefaultSession{Extra: map[string]interface{}{"synthetic_claim": strings.Repeat("x", s.claims)}}
	r.Session.SetExpiresAt(fosite.AuthorizeCode, time.Now().Add(time.Hour))
	return r
}

func BenchmarkSnapshot112(b *testing.B) {
	store, _ := benchOAuthStore(b)
	for shape, s := range snapshotShapes {
		b.Run(s.name, func(b *testing.B) {
			r := snapshotRequest(store.client, shape)
			encoded, err := encodeRequest(r)
			if err != nil {
				b.Fatal(err)
			}
			b.Run("Encode", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := encodeRequest(r); err != nil {
						b.Fatal(err)
					}
				}
				b.ReportMetric(float64(len(encoded)), "json-B")
			})
			b.Run("JSONOnlyDecode", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					var record requestRecord
					if err := json.Unmarshal([]byte(encoded), &record); err != nil {
						b.Fatal(err)
					}
				}
			})
			b.Run("FullStaticAuthorityDecode", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := store.decodeRequest(b.Context(), encoded, nil); err != nil {
						b.Fatal(err)
					}
				}
			})
			payload := bytes.Repeat([]byte("u"), s.payload)
			text := base64.RawURLEncoding.EncodeToString(payload)
			b.Run("InteractionEncode", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					_ = base64.RawURLEncoding.EncodeToString(payload)
				}
				b.ReportMetric(float64(len(text)), "text-B")
			})
			b.Run("InteractionDecode", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if _, err := base64.RawURLEncoding.DecodeString(text); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
}

// Keep explicit credential inputs independent of the production exclusion map.
func TestSnapshot112Sentinels(t *testing.T) {
	r := snapshotRequest(&fosite.DefaultClient{ID: "synthetic"}, 0)
	fields := []string{"password", "client_secret", "client_assertion", "assertion", "subject_token", "actor_token", "code", "code_verifier", "device_code", "refresh_token", "id_token_hint", "request", "request_uri"}
	for _, field := range fields {
		r.Form[field] = []string{"SECRET_SENTINEL_" + field}
	}
	before, _ := json.Marshal(r.Form)
	encoded, err := encodeRequest(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, "SECRET_SENTINEL_") {
		t.Fatal("credential persisted")
	}
	after, _ := json.Marshal(r.Form)
	if !bytes.Equal(before, after) {
		t.Fatal("input form mutated")
	}
	var record requestRecord
	if err := json.Unmarshal([]byte(encoded), &record); err != nil {
		t.Fatal(err)
	}
	if record.Form.Get("code_challenge") == "" || record.Form.Get("redirect_uri") == "" {
		t.Fatal("binding removed")
	}
}

func snapshotLog(t *testing.T, kind string, value any) {
	t.Helper()
	data, err := json.Marshal(map[string]any{"kind": kind, "value": value})
	if err != nil {
		t.Fatal(err)
	}
	t.Log("SNAPSHOT112 " + string(data))
}
func snapshotFiles(t *testing.T, root string) map[string]int64 {
	t.Helper()
	files := map[string]int64{}
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
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
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files[rel] = info.Size()
		total += info.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if total > 256<<20 {
		t.Fatalf("measurement disk budget exceeded: %d", total)
	}
	return files
}
func snapshotQuery(t *testing.T, db *rhiza.DB, sql string) [][]any {
	t.Helper()
	q, err := db.Query(t.Context(), rhiza.QueryRequest{SQL: sql, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		t.Fatal(err)
	}
	return q.Rows
}
func snapshotPhase(t *testing.T, db *rhiza.DB, root, phase string) {
	t.Helper()
	stats, ok := db.ObjectStoreStats()
	snapshotLog(t, phase, map[string]any{"files": snapshotFiles(t, root), "object_stats_available": ok, "object_stats": stats})
}

func TestSnapshot112Storage(t *testing.T) {
	name := os.Getenv("GOAUTHY_SNAPSHOT112_SHAPE")
	if name == "" {
		t.Skip("opt-in bounded measurement")
	}
	shape := -1
	for i, s := range snapshotShapes {
		if s.name == name {
			shape = i
		}
	}
	if shape < 0 {
		t.Fatal("invalid shape")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	root := t.TempDir()
	cfg := rhiza.Config{ClusterID: "snapshot112", NodeID: "source", DataDir: filepath.Join(root, "data"), ObjStoreProvider: rhiza.ObjectStoreProviderFilesystem, ObjStoreDir: filepath.Join(root, "objects"), ObjStorePrefix: "source", ObjStoreDurability: rhiza.ObjectStoreDurabilityBeforeAck, CheckpointInterval: time.Hour}
	db, err := rhiza.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	if err := storage.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	server := oauthTestServer(t, db, bytes.Repeat([]byte{7}, 32))
	store := server.store
	bs, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	session, err := bs.CreateInitSession(ctx, time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := bs.CreateInitSession(ctx, time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	snapshotLog(t, "provenance", map[string]any{"shape": name, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH, "gomaxprocs": runtime.GOMAXPROCS(0), "operations": 100, "mode": "storage-stress plus one HTTP-valid flow", "durability": "before_ack", "checkpoint": "1h", "replication_wire": "unmeasured single-node"})
	snapshotPhase(t, db, root, "control")
	var commandBytes int
	var issueNS, consumeNS []int64
	tokens := make([]string, 100)
	var allocated runtime.MemStats
	runtime.ReadMemStats(&allocated)
	allocStart := allocated.TotalAlloc
	started := time.Now()
	for i := 0; i < 100; i++ {
		if ctx.Err() != nil {
			t.Fatal(ctx.Err())
		}
		signature := fmt.Sprintf("synthetic-%03d", i)
		r := snapshotRequest(store.client, shape)
		r.ID = signature
		// Match the distinct Fosite allowlists, rather than inventing identical forms.
		code := r.Sanitize([]string{"code", "redirect_uri"})
		pkce := r.Sanitize([]string{"code_challenge", "code_challenge_method"})
		txctx, err := store.BeginTX(ctx)
		if err != nil {
			t.Fatal(err)
		}
		begin := time.Now()
		if err := store.CreateAuthorizeCodeSession(txctx, signature, code); err != nil {
			t.Fatal(err)
		}
		if err := store.CreatePKCERequestSession(txctx, signature, pkce); err != nil {
			t.Fatal(err)
		}
		tx := txFrom(txctx)
		command, err := json.Marshal(rhiza.ExecuteRequest{RequestID: tx.requestID, Statements: tx.statements})
		if err != nil {
			t.Fatal(err)
		}
		commandBytes += len(command)
		if err := store.Commit(txctx); err != nil {
			t.Fatal(err)
		}
		issueNS = append(issueNS, time.Since(begin).Nanoseconds())
		c, err := store.GetAuthorizeCodeSession(ctx, signature, nil)
		if err != nil {
			t.Fatal(err)
		}
		p, err := store.GetPKCERequestSession(ctx, signature, nil)
		if err != nil {
			t.Fatal(err)
		}
		if c.GetRequestForm().Get("redirect_uri") == "" || p.GetRequestForm().Get("code_challenge") == "" || c.GetRequestForm().Get("code_challenge") != "" || p.GetRequestForm().Get("redirect_uri") != "" {
			t.Fatal("nonidentical form binding changed")
		}
		// HTTP parsing is deliberately not claimed for these synthetic scope/claim sizes.
		payload := snapshotPayload(snapshotShapes[shape].payload, i)
		interaction, err := bs.CreateAuthorizationInteraction(ctx, session.Token, signature, payload, time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = interaction.Token
		if _, err := bs.LoadAuthorizationInteractionReadOnly(ctx, other.Token, interaction.Token); !errors.Is(err, browser.ErrNotFound) {
			t.Fatalf("cross-session load: %v", err)
		}
		loaded, err := bs.LoadAuthorizationInteractionReadOnly(ctx, session.Token, interaction.Token)
		if err != nil || !bytes.Equal(loaded.Payload, payload) {
			t.Fatalf("load: %v", err)
		}
		if i%2 == 0 {
			begin = time.Now()
			consume, err := store.BeginTX(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := store.InvalidateAuthorizeCodeSession(consume, signature); err != nil {
				t.Fatal(err)
			}
			if err := store.Commit(consume); err != nil {
				t.Fatal(err)
			}
			consumeNS = append(consumeNS, time.Since(begin).Nanoseconds())
			if _, err := bs.ConsumeAuthorizationInteraction(ctx, session.Token, interaction.Token); err != nil {
				t.Fatal(err)
			}
		}
	}
	runtime.ReadMemStats(&allocated)
	snapshotLog(t, "workload", map[string]any{"elapsed_ns": time.Since(started).Nanoseconds(), "allocated_bytes": allocated.TotalAlloc - allocStart, "issue_ns": issueNS, "consume_ns": consumeNS, "issue_execute_request_json_bytes": commandBytes, "wire_bytes": nil})
	snapshotLog(t, "logical", snapshotQuery(t, db, `SELECT 'code',count(*),sum(length(CAST(request_json AS BLOB))) FROM oauth_authorize_codes UNION ALL SELECT 'pkce',count(*),sum(length(CAST(request_json AS BLOB))) FROM oauth_pkce_requests UNION ALL SELECT 'interaction',count(*),sum(length(CAST(payload AS BLOB))) FROM browser_authorization_interactions`))
	snapshotPhase(t, db, root, "after_workload")
	// One genuine HTTP-valid code flow, measured independently of storage stress.
	startHTTP := time.Now()
	verifier := strings.Repeat("v", 43)
	code := issueCode(t, server, verifier)
	wrong := postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {strings.Repeat("w", 43)}})
	if wrong.Code == http.StatusOK {
		t.Fatal("wrong verifier accepted")
	}
	right := postToken(server, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirectURI}, "code_verifier": {verifier}})
	if right.Code != http.StatusOK {
		t.Fatalf("HTTP redemption: %d %s", right.Code, right.Body.String())
	}
	snapshotLog(t, "http_valid", map[string]any{"elapsed_ns": time.Since(startHTTP).Nanoseconds(), "wrong_status": wrong.Code, "success_status": right.Code, "count": 1})
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db = nil
	snapshotLog(t, "closed_files", snapshotFiles(t, root))
	if os.Getenv("GOAUTHY_SNAPSHOT112_RECOVERY") != "1" {
		return
	}
	bucket, err := filesystem.NewBucket(cfg.ObjStoreDir)
	if err != nil {
		t.Fatal(err)
	}
	defer bucket.Close()
	key, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	limits := backup.Limits{MaxFiles: 4096, MaxFileBytes: 64 << 20, MaxTotalBytes: 128 << 20}
	var archive bytes.Buffer
	begin := time.Now()
	manifest, err := backup.Export(ctx, bucket, "source/snapshot112", "snapshot112", &archive, []age.Recipient{key.Recipient()}, root, limits)
	if err != nil {
		t.Fatal(err)
	}
	exportNS := time.Since(begin).Nanoseconds()
	// Export-only mode prepares immutable synthetic inputs for fresh-process
	// phase measurements. Fixture creation is outside all restore timings.
	if dest := os.Getenv("GOAUTHY_SNAPSHOT112_BUNDLE"); dest != "" {
		if err := os.MkdirAll(dest, 0700); err != nil {
			t.Fatal(err)
		}
		metadata, err := json.Marshal(map[string]any{"key": key.String(), "session": session.Token, "other": other.Token, "tokens": tokens, "shape": shape})
		if err != nil {
			t.Fatal(err)
		}
		for name, data := range map[string][]byte{"bundle.age": archive.Bytes(), "metadata.json": metadata} {
			if err := os.WriteFile(filepath.Join(dest, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	begin = time.Now()
	extracted, err := backup.Extract(bytes.NewReader(archive.Bytes()), []age.Identity{key}, root, limits)
	if err != nil {
		t.Fatal(err)
	}
	extractNS := time.Since(begin).Nanoseconds()
	begin = time.Now()
	if _, err := backup.Restore(ctx, bucket, "target/snapshot112", "snapshot112", extracted, root); err != nil {
		t.Fatal(err)
	}
	restoreNS := time.Since(begin).Nanoseconds()
	cfg.DataDir = filepath.Join(root, "restored")
	cfg.ObjStorePrefix = "target"
	begin = time.Now()
	db, err = rhiza.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	openNS := time.Since(begin).Nanoseconds()
	restored := oauthTestServer(t, db, bytes.Repeat([]byte{7}, 32))
	browserRestored, err := browser.NewStore(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, i := range []int{0, 1} {
		signature := fmt.Sprintf("synthetic-%03d", i)
		r, err := restored.store.GetAuthorizeCodeSession(ctx, signature, nil)
		if i == 0 {
			if !errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) || r == nil {
				t.Fatalf("consumed code restore: %v", err)
			}
		} else if err != nil || r.GetID() != signature {
			t.Fatalf("live code restore: %v", err)
		}
		_, err = restored.store.GetPKCERequestSession(ctx, signature, nil)
		if i == 0 && !errors.Is(err, fosite.ErrNotFound) || i == 1 && err != nil {
			t.Fatalf("PKCE restore: %v", err)
		}
		loaded, err := browserRestored.LoadAuthorizationInteractionReadOnly(ctx, session.Token, tokens[i])
		if i == 0 && !errors.Is(err, browser.ErrConsumed) || i == 1 && (err != nil || loaded.RequestID != signature) {
			t.Fatalf("interaction restore: %v", err)
		}
	}
	snapshotLog(t, "recovery", map[string]any{"mode": manifest.RecoveryMode, "archive_bytes": archive.Len(), "export_ns": exportNS, "extract_ns": extractNS, "restore_ns": restoreNS, "open_ns": openNS, "bindings_checked": true})
	snapshotPhase(t, db, root, "restored")
}

func BenchmarkSnapshot112Authority(b *testing.B) {
	store, db := benchOAuthStore(b)
	store.managedClients = clients.NewStore(db, &oidc.Keyring{})
	managed, err := store.managedClients.CreateWithGuard(b.Context(), clients.NewRequest{ID: "measurement-public", RedirectURIs: []string{testRedirectURI}}, func() (string, []any) { return "1", nil })
	if err != nil {
		b.Fatal(err)
	}
	ephemeral, err := newEphemeralClientRecord(ephemeralClientRecord{ID: "https://client.example.test/metadata", Name: "synthetic", RedirectURIs: []string{"https://client.example.test/callback"}, Scopes: []string{"goauthy.read"}})
	if err != nil {
		b.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		client fosite.Client
	}{{"ManagedMedium", &managed}, {"EphemeralMedium", ephemeral}} {
		b.Run(tc.name, func(b *testing.B) {
			encoded, err := encodeRequest(snapshotRequest(tc.client, 1))
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := store.decodeRequest(b.Context(), encoded, nil); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(len(encoded)), "json-B")
		})
	}
}

// Rotate URL, continuation JSON and opaque storage payloads, with both repeated
// and varied synthetic bytes. These are storage fixtures, not HTTP-size claims.
func snapshotPayload(size, variant int) []byte {
	prefix, suffix := "", ""
	switch variant % 3 {
	case 0:
		prefix = "/oidc/authorize?state="
	case 1:
		prefix = `{"continuation":"`
		suffix = `"}`
	}
	body := bytes.Repeat([]byte("u"), size-len(prefix)-len(suffix))
	if variant%2 == 1 {
		r := rand.New(rand.NewPCG(112, uint64(size)))
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
		for i := range body {
			body[i] = alphabet[r.IntN(len(alphabet))]
		}
	}
	return append(append([]byte(prefix), body...), suffix...)
}

func TestSnapshot112LegacyRecord(t *testing.T) {
	server := oauthTestServer(t, oauthTestDB(t), bytes.Repeat([]byte{7}, 32))
	// Legacy-shaped JSON deliberately has no managed/ephemeral record or optional
	// Extra claims. This is a decode fixture, not an old-binary migration test.
	const legacy = `{"id":"legacy","client_id":"browser-client","requested_at_unix_ms":1700000000000,"requested_scopes":["goauthy.read"],"granted_scopes":["goauthy.read"],"form":{"redirect_uri":["http://localhost/callback"]},"expires_at_unix_ms":{"authorize_code":4000000000000}}`
	r, err := server.store.decodeRequest(t.Context(), legacy, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.GetID() != "legacy" || r.GetClient().GetID() != testClientID || r.GetRequestForm().Get("redirect_uri") != testRedirectURI || !r.GetGrantedScopes().Has("goauthy.read") {
		t.Fatal("legacy binding changed")
	}
	for _, invalid := range []string{`{`, `{}`, `{"id":"legacy"}`} {
		if _, err := server.store.decodeRequest(t.Context(), invalid, nil); err == nil {
			t.Fatal("invalid record accepted")
		}
	}
}

// Replay handling needs the original request identity even on invalidation.
func TestSnapshot112InvalidatedCodeRetainsRequest(t *testing.T) {
	t.Parallel()
	server := oauthTestServer(t, oauthTestDB(t), randomSecret(t))
	code := issueCode(t, server, strings.Repeat("v", 43))
	signature := server.authorizeCodes.AuthorizeCodeSignature(t.Context(), code)
	before, err := server.store.GetAuthorizeCodeSession(t.Context(), signature, nil)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := server.store.BeginTX(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := server.store.InvalidateAuthorizeCodeSession(tx, signature); err != nil {
		t.Fatal(err)
	}
	if err := server.store.Commit(tx); err != nil {
		t.Fatal(err)
	}
	after, err := server.store.GetAuthorizeCodeSession(t.Context(), signature, nil)
	if !errors.Is(err, fosite.ErrInvalidatedAuthorizeCode) || after == nil {
		t.Fatalf("request=%v error=%v", after, err)
	}
	if after.GetID() != before.GetID() || after.GetClient().GetID() != before.GetClient().GetID() || after.GetRequestForm().Get("redirect_uri") != testRedirectURI {
		t.Fatal("invalidated request binding changed")
	}
}
