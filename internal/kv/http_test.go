package kv

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func newHTTPStore(t *testing.T) (*Store, *http.ServeMux) {
	t.Helper()
	db, err := rhiza.Open(context.Background(), rhiza.Config{NodeID: "kv-http", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err = storage.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(d, "master-1"), []byte(base64.RawURLEncoding.EncodeToString(b)), 0600); err != nil {
		t.Fatal(err)
	}
	k, err := oidc.LoadKeyring(d, "master-1")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewStore(db, k)
	if err != nil {
		t.Fatal(err)
	}
	m := http.NewServeMux()
	NewHandler(s, func(w http.ResponseWriter, r *http.Request, mut bool) bool { return true }).Routes(m)
	return s, m
}
func req(t *testing.T, m http.Handler, method, path, body string, h map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range h {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	m.ServeHTTP(w, r)
	return w
}
func TestHTTPKVFullExternalFlowAndBoundaries(t *testing.T) {
	s, m := newHTTPStore(t)
	ct := map[string]string{"Content-Type": "application/json"}
	w := req(t, m, "POST", "/auth/v1/kv/ns", `{"name":"public-ns","public":true}`, ct)
	if w.Code != 200 {
		t.Fatalf("namespace=%d", w.Code)
	}
	a, e := s.CreateAccess(context.Background(), "public-ns", true, nil)
	if e != nil {
		t.Fatal(e)
	}
	auth := map[string]string{"Authorization": "Bearer " + a.ID + "$" + a.Secret}
	w = req(t, m, "PUT", "/auth/v1/kv/keys", `{"key":"hello","value":"world"}`, merge(ct, auth))
	if w.Code != 200 {
		t.Fatalf("put=%d", w.Code)
	}
	w = req(t, m, "GET", "/auth/v1/kv/keys/hello", "", auth)
	if w.Code != 200 || w.Body.String() != "\"world\"" {
		t.Fatalf("get=%d %q", w.Code, w.Body.String())
	}
	w = req(t, m, "GET", "/auth/v1/kv/pub/public-ns/hello", "", nil)
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("public=%d %q", w.Code, w.Body.String())
	}
	w = req(t, m, "GET", "/auth/v1/kv/keys/hello", "", map[string]string{"Authorization": "Bearer bad"})
	if w.Code != 401 {
		t.Fatalf("bad auth=%d", w.Code)
	}
	w = req(t, m, "GET", "/auth/v1/kv/keys?bad=x", "", auth)
	if w.Code != 400 {
		t.Fatalf("query=%d", w.Code)
	}
}
func merge(a, b map[string]string) map[string]string {
	r := map[string]string{}
	for k, v := range a {
		r[k] = v
	}
	for k, v := range b {
		r[k] = v
	}
	return r
}

func TestHTTPKVAdminLifecycle(t *testing.T) {
	s, m := newHTTPStore(t)
	ct := map[string]string{"Content-Type": "application/json"}
	if w := req(t, m, "POST", "/auth/v1/kv/ns", `{"name":"tenant-one"}`, ct); w.Code != 200 {
		t.Fatalf("create namespace=%d", w.Code)
	}
	w := req(t, m, "GET", "/auth/v1/kv/ns", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "tenant-one") {
		t.Fatalf("list namespaces=%d %s", w.Code, w.Body)
	}
	w = req(t, m, "POST", "/auth/v1/kv/ns/tenant-one/access", `{"enabled":true}`, ct)
	if w.Code != 201 || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("create access=%d headers=%v", w.Code, w.Header())
	}
	var a Access
	if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil || a.ID == "" || a.Secret == "" {
		t.Fatalf("access body=%q err=%v", w.Body, err)
	}
	w = req(t, m, "PUT", "/auth/v1/kv/ns/tenant-one/access/"+a.ID, `{"enabled":false}`, ct)
	if w.Code != 200 {
		t.Fatalf("disable=%d", w.Code)
	}
	w = req(t, m, "PUT", "/auth/v1/kv/ns/tenant-one/access/"+a.ID, `{"enabled":true}`, ct)
	if w.Code != 200 {
		t.Fatalf("enable=%d", w.Code)
	}
	w = req(t, m, "POST", "/auth/v1/kv/ns/tenant-one/access/"+a.ID+"/secret", "", nil)
	if w.Code != 200 {
		t.Fatalf("rotate=%d", w.Code)
	}
	var rotated Access
	_ = json.Unmarshal(w.Body.Bytes(), &rotated)
	auth := map[string]string{"Authorization": "Bearer " + rotated.ID + "$" + rotated.Secret}
	w = req(t, m, "PUT", "/auth/v1/kv/keys", `{"key":"alpha","encrypted":true,"value":{"x":1}}`, merge(ct, auth))
	if w.Code != 200 {
		t.Fatalf("set=%d", w.Code)
	}
	w = req(t, m, "GET", "/auth/v1/kv/values?search=alp", "", auth)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "alpha") {
		t.Fatalf("values=%d %s", w.Code, w.Body)
	}
	w = req(t, m, "DELETE", "/auth/v1/kv/keys/alpha", "", auth)
	if w.Code != 200 {
		t.Fatalf("delete value=%d", w.Code)
	}
	w = req(t, m, "DELETE", "/auth/v1/kv/ns/tenant-one/access/"+a.ID, "", ct)
	if w.Code != 200 {
		t.Fatalf("delete access=%d", w.Code)
	}
	w = req(t, m, "DELETE", "/auth/v1/kv/ns/tenant-one", "", nil)
	if w.Code != 200 {
		t.Fatalf("delete ns=%d", w.Code)
	}
	_ = s
}

func TestHTTPKVStrictNegativeAndCallbackBoundary(t *testing.T) {
	s, _ := newHTTPStore(t)
	calls := 0
	m := http.NewServeMux()
	NewHandler(s, func(w http.ResponseWriter, r *http.Request, mut bool) bool {
		calls++
		if r.Header.Get("X-CSRF-Token") == "ok" || !mut {
			return true
		}
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}).Routes(m)
	ct := map[string]string{"Content-Type": "application/json"}
	if w := req(t, m, "POST", "/auth/v1/kv/ns", `{"name":"strict-ns"}`, ct); w.Code != 401 {
		t.Fatalf("csrf=%d", w.Code)
	}
	if w := req(t, m, "POST", "/auth/v1/kv/ns", `{"name":"strict-ns"}`, merge(ct, map[string]string{"X-CSRF-Token": "ok"})); w.Code != 200 {
		t.Fatalf("create=%d", w.Code)
	}
	before := calls
	if w := req(t, m, "GET", "/auth/v1/kv/ns", "", map[string]string{"Authorization": "Bearer hostile"}); w.Code != 401 || calls != before {
		t.Fatalf("auth fallback status=%d calls=%d", w.Code, calls)
	}
	for _, tc := range []struct {
		path string
		want int
	}{{"/auth/v1/kv/ns?x=1", 400}, {"/auth/v1/kv/ns?limit=1&limit=2", 400}, {"/auth/v1/kv/keys?%zz", 401}} {
		w := req(t, m, "GET", tc.path, "", nil)
		if w.Code != tc.want {
			t.Errorf("%s=%d want %d", tc.path, w.Code, tc.want)
		}
	}
	// GA80-KV-001: the namespace and access listings have no search filter, so
	// a nonempty term must be rejected rather than silently discarded.
	for _, path := range []string{"/auth/v1/kv/ns?search=alpha", "/auth/v1/kv/ns/strict-ns/access?search=alpha"} {
		if w := req(t, m, "GET", path, "", map[string]string{"X-CSRF-Token": "ok"}); w.Code != 400 {
			t.Errorf("%s=%d want 400", path, w.Code)
		}
	}
	if w := req(t, m, "POST", "/auth/v1/kv/ns", strings.Repeat("x", int(bodyLimit+1)), merge(ct, map[string]string{"X-CSRF-Token": "ok"})); w.Code != 400 {
		t.Fatalf("oversize=%d", w.Code)
	}
	if w := req(t, m, "HEAD", "/auth/v1/kv/ns", "", nil); w.Code != 405 || w.Header().Get("Allow") == "" {
		t.Fatalf("head=%d allow=%q", w.Code, w.Header().Get("Allow"))
	}
}
