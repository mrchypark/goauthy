package browser

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	browsersession "github.com/mrchypark/goauthy/internal/browser"
)

func TestAuthCollectionsAcrossPods(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_AUTH_COLLECTIONS") != "1" {
		t.Skip("set GOAUTHY_E2E_AUTH_COLLECTIONS=1 to run auth-collections E2E")
	}
	chaosContext := ""
	if os.Getenv("GOAUTHY_E2E_AUTH_COLLECTIONS_CHAOS") == "1" {
		chaosContext = authCollectionsChaosConfig(t)
	}
	for _, name := range []string{"GOAUTHY_E2E_URL", "GOAUTHY_E2E_SECONDARY_URL", "GOAUTHY_E2E_TERTIARY_URL", "GOAUTHY_E2E_BROWSER_USERNAME", "GOAUTHY_E2E_BROWSER_PASSWORD", "GOAUTHY_E2E_CLIENT_SECRET"} {
		if os.Getenv(name) == "" {
			t.Fatalf("%s is required when GOAUTHY_E2E_AUTH_COLLECTIONS=1", name)
		}
	}
	primary, secondary, adminUser, adminPassword, _ := browserE2EConfig(t)
	apiBase := primary
	tertiary := logoutTertiaryURL(t)
	client := newBrowserClient(t)
	sink := strings.TrimRight(os.Getenv("GOAUTHY_E2E_SMTP_SINK_URL"), "/")
	if sink == "" {
		t.Fatal("GOAUTHY_E2E_SMTP_SINK_URL is required when GOAUTHY_E2E_AUTH_COLLECTIONS=1")
	}
	mailbox := newBrowserClient(t)
	_, adminCookie := loginForCode(t, client, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), adminUser, adminPassword, "auth-collections-admin")
	csrf, err := browsersession.DeriveCSRFToken(adminCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	adminHeaders := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": csrf}
	id := uniqueCollectionID(t)
	definition := []byte(`{"id":"` + id + `","name":"E2E Workspace","auth_method":"oauth2","enabled":true,"fields":[{"name":"workspace","type":"string","required":true,"max_length":80}]}`)
	r := do(t, client, http.MethodPost, primary+"/auth/v1/auth-collections", bytes.NewReader(definition), adminHeaders)
	created, rev := readCollection(t, r, http.StatusCreated)
	if created["id"] != id {
		t.Fatalf("created collection id=%v", created["id"])
	}
	current := rev
	collectionDeleted := false
	t.Cleanup(func() {
		if collectionDeleted {
			return
		}
		h := cloneCollectionHeaders(adminHeaders, current)
		x := do(t, client, http.MethodDelete, apiBase+"/auth/v1/auth-collections/"+url.PathEscape(id), nil, h)
		if x.StatusCode != http.StatusNoContent {
			t.Errorf("collection cleanup status=%d", x.StatusCode)
		}
		x.Body.Close()
	})
	for _, base := range []string{primary, secondary, tertiary} {
		x := do(t, client, http.MethodGet, base+"/auth/v1/auth-collections", nil, adminHeaders)
		if x.StatusCode != http.StatusOK {
			x.Body.Close()
			t.Fatalf("list status=%d node=%s", x.StatusCode, base)
		}
		x.Body.Close()
	}
	bad := cloneCollectionHeaders(adminHeaders, current)
	bad["X-CSRF-Token"] = "bad"
	x := do(t, client, http.MethodPut, primary+"/auth/v1/auth-collections/"+url.PathEscape(id), bytes.NewReader(definition), bad)
	x.Body.Close()
	if x.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad CSRF status=%d want=%d", x.StatusCode, http.StatusUnauthorized)
	}
	update := []byte(`{"name":"E2E Workspace Updated","auth_method":"oauth2","enabled":true,"fields":[{"name":"workspace","type":"string","required":true,"max_length":80}]}`)
	h := cloneCollectionHeaders(adminHeaders, current)
	x = do(t, client, http.MethodPut, primary+"/auth/v1/auth-collections/"+url.PathEscape(id), bytes.NewReader(update), h)
	_, current = readCollection(t, x, http.StatusOK)
	stale := cloneCollectionHeaders(adminHeaders, rev)
	x = do(t, client, http.MethodPut, primary+"/auth/v1/auth-collections/"+url.PathEscape(id), bytes.NewReader(update), stale)
	x.Body.Close()
	if x.StatusCode != http.StatusConflict {
		t.Fatalf("stale update status=%d", x.StatusCode)
	}
	// Create and authenticate an ordinary user through the existing admin HTTP boundary.
	email := "auth-collections-" + strings.ToLower(id) + "@goauthy.e2e"
	password := "Auth-Collections-Initial-1A"
	userBody := []byte(`{"email":"` + email + `","language":"en","roles":[] ,"groups":[]}`)
	x = do(t, client, http.MethodPost, primary+"/auth/v1/users", bytes.NewReader(userBody), adminHeaders)
	var u struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(io.LimitReader(x.Body, 16<<10)).Decode(&u)
	x.Body.Close()
	if x.StatusCode != http.StatusOK || u.ID == "" {
		t.Fatalf("user create status=%d", x.StatusCode)
	}
	t.Cleanup(func() {
		z := do(t, client, http.MethodDelete, apiBase+"/auth/v1/users/"+url.PathEscape(u.ID), nil, adminHeaders)
		if z.StatusCode != http.StatusNoContent {
			t.Errorf("user cleanup status=%d", z.StatusCode)
		}
		z.Body.Close()
	})
	mail := waitForResetMail(t, mailbox, sink, email)
	parsed, err := url.Parse(mail.resetURL)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(strings.Trim(parsed.EscapedPath(), "/"), "/")
	if len(parts) != 6 {
		t.Fatalf("invalid reset path=%q", parsed.Path)
	}
	activation := newBrowserClient(t)
	x = do(t, activation, http.MethodGet, primary+parsed.EscapedPath(), nil, nil)
	var challenge struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.NewDecoder(x.Body).Decode(&challenge)
	cookies := x.Cookies()
	x.Body.Close()
	if x.StatusCode != http.StatusOK || challenge.CSRFToken == "" {
		t.Fatal("activation start failed")
	}
	secondaryURL, _ := url.Parse(secondary)
	activation.Jar.SetCookies(secondaryURL, cookies)
	activationBody := []byte(`{"magic_link_id":"` + parts[5] + `","password":"` + password + `"}`)
	x = do(t, activation, http.MethodPut, secondary+"/auth/v1/users/"+url.PathEscape(u.ID)+"/reset", bytes.NewReader(activationBody), map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-Pwd-CSRF-Token": challenge.CSRFToken})
	x.Body.Close()
	if x.StatusCode != http.StatusAccepted {
		t.Fatalf("user activation status=%d", x.StatusCode)
	}
	ordinary := newBrowserClient(t)
	_, ordinaryCookie := loginForCode(t, ordinary, primary, secondary, defaultRedirectURI, pkceChallenge(pkceVerifier(t)), email, password, "auth-collections-user")
	ordinaryCSRF, err := browsersession.DeriveCSRFToken(ordinaryCookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	userHeaders := map[string]string{"Content-Type": "application/json", "Sec-Fetch-Site": "same-origin", "X-CSRF-Token": ordinaryCSRF}
	path := primary + "/auth/v1/account/connections/" + url.PathEscape(id)
	record := []byte(`{"definition_revision":` + strconv.FormatInt(current, 10) + `,"metadata":{"workspace":"acme"}}`)
	disable := []byte(`{"name":"E2E Workspace Updated","auth_method":"oauth2","enabled":false,"fields":[{"name":"workspace","type":"string","required":true,"max_length":80}]}`)
	dh := cloneCollectionHeaders(adminHeaders, current)
	z := do(t, client, http.MethodPut, primary+"/auth/v1/auth-collections/"+url.PathEscape(id), bytes.NewReader(disable), dh)
	_, current = readCollection(t, z, http.StatusOK)
	record = []byte(`{"definition_revision":` + strconv.FormatInt(current, 10) + `,"metadata":{"workspace":"acme"}}`)
	z = do(t, ordinary, http.MethodPost, path, bytes.NewReader(record), userHeaders)
	z.Body.Close()
	if z.StatusCode != http.StatusConflict {
		t.Fatalf("disabled collection status=%d want=%d", z.StatusCode, http.StatusConflict)
	}
	dh = cloneCollectionHeaders(adminHeaders, current)
	z = do(t, client, http.MethodPut, primary+"/auth/v1/auth-collections/"+url.PathEscape(id), bytes.NewReader(update), dh)
	_, current = readCollection(t, z, http.StatusOK)
	record = []byte(`{"definition_revision":` + strconv.FormatInt(current, 10) + `,"metadata":{"workspace":"acme"}}`)
	invalid := []byte(`{"definition_revision":` + strconv.FormatInt(current, 10) + `,"metadata":{}}`)
	z = do(t, ordinary, http.MethodPost, path, bytes.NewReader(invalid), userHeaders)
	z.Body.Close()
	if z.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid metadata status=%d want=%d", z.StatusCode, http.StatusBadRequest)
	}
	x = do(t, ordinary, http.MethodPost, path, bytes.NewReader(record), userHeaders)
	conn, connRev := readCollection(t, x, http.StatusCreated)
	connID, _ := conn["id"].(string)
	if connID == "" {
		t.Fatal("connection id missing")
	}
	connectionDeleted := false
	t.Cleanup(func() {
		if connectionDeleted {
			return
		}
		ch := cloneCollectionHeaders(userHeaders, connRev)
		z := do(t, ordinary, http.MethodDelete, apiBase+"/auth/v1/account/connections/"+url.PathEscape(id)+"/"+url.PathEscape(connID), nil, ch)
		if z.StatusCode != http.StatusNoContent {
			t.Errorf("connection cleanup status=%d", z.StatusCode)
		}
		z.Body.Close()
	})
	readBases := []string{primary, secondary, tertiary}
	if chaosContext != "" {
		chaosCtx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
		defer cancel()
		oldUID := authCollectionsChaosPodUID(t, chaosCtx, chaosContext)
		// Cleanup must also use a survivor if a later readiness assertion fails.
		apiBase = secondary
		authCollectionsChaosKubectl(t, chaosCtx, chaosContext, "delete", "pod", "goauthy-0", "--wait=true")
		authCollectionsChaosKubectl(t, chaosCtx, chaosContext, "wait", "--for=condition=Ready", "pod/goauthy-0", "--timeout=180s")
		newUID := authCollectionsChaosPodUID(t, chaosCtx, chaosContext)
		if newUID == oldUID {
			t.Fatalf("auth-collections chaos pod UID did not change: %s", oldUID)
		}
		// The original primary forward may be gone; use the surviving secondary.
		readBases = []string{secondary, tertiary}
		z := do(t, ordinary, http.MethodGet, apiBase+"/auth/v1/account/connections/"+url.PathEscape(id)+"/"+url.PathEscape(connID), nil, nil)
		got, gotRev := readCollection(t, z, http.StatusOK)
		if gotRev != connRev || got["id"] != connID {
			t.Fatalf("connection changed across pod replacement: id=%v revision=%d want id=%s revision=%d", got["id"], gotRev, connID, connRev)
		}
		metadata, ok := got["metadata"].(map[string]any)
		if !ok || metadata["workspace"] != "acme" {
			t.Fatalf("connection metadata changed across pod replacement: %v", got["metadata"])
		}
		t.Logf("same connection ID/revision/metadata survived pod replacement %s -> %s", oldUID, newUID)
	}
	for _, base := range readBases {
		z := do(t, ordinary, http.MethodGet, base+"/auth/v1/account/auth-collections", nil, nil)
		if z.StatusCode != http.StatusOK {
			z.Body.Close()
			t.Fatalf("account collections status=%d node=%s", z.StatusCode, base)
		}
		z.Body.Close()
		z = do(t, ordinary, http.MethodGet, base+"/auth/v1/account/connections/"+url.PathEscape(id)+"/"+url.PathEscape(connID), nil, nil)
		got, _ := readCollection(t, z, http.StatusOK)
		if got["state"] != "draft" || got["owner_subject"] != u.ID {
			t.Fatalf("connection ownership/state node=%s owner=%v state=%v", base, got["owner_subject"], got["state"])
		}
		metadata, ok := got["metadata"].(map[string]any)
		if !ok || metadata["workspace"] != "acme" {
			t.Fatalf("connection metadata node=%s metadata=%v", base, got["metadata"])
		}
	}
	z = do(t, client, http.MethodGet, apiBase+"/auth/v1/account/connections/"+url.PathEscape(id)+"/"+url.PathEscape(connID), nil, nil)
	z.Body.Close()
	if z.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-owner connection status=%d want=%d", z.StatusCode, http.StatusNotFound)
	}
	wrong := cloneCollectionHeaders(userHeaders, connRev)
	wrong["If-Match"] = `"999999"`
	z = do(t, ordinary, http.MethodPut, apiBase+"/auth/v1/account/connections/"+url.PathEscape(id)+"/"+url.PathEscape(connID), bytes.NewReader(record), wrong)
	z.Body.Close()
	if z.StatusCode != http.StatusConflict {
		t.Fatalf("stale connection status=%d", z.StatusCode)
	}
	connUpdate := []byte(`{"definition_revision":` + strconv.FormatInt(current, 10) + `,"metadata":{"workspace":"updated"}}`)
	ch := cloneCollectionHeaders(userHeaders, connRev)
	z = do(t, ordinary, http.MethodPut, apiBase+"/auth/v1/account/connections/"+url.PathEscape(id)+"/"+url.PathEscape(connID), bytes.NewReader(connUpdate), ch)
	_, connRev = readCollection(t, z, http.StatusOK)
	// A definition with a live connection cannot be deleted; clean records first.
	delh := cloneCollectionHeaders(adminHeaders, current)
	z = do(t, client, http.MethodDelete, apiBase+"/auth/v1/auth-collections/"+url.PathEscape(id), nil, delh)
	z.Body.Close()
	if z.StatusCode != http.StatusConflict {
		t.Fatalf("definition delete with record status=%d want=%d", z.StatusCode, http.StatusConflict)
	}
	ch = cloneCollectionHeaders(userHeaders, connRev)
	z = do(t, ordinary, http.MethodDelete, apiBase+"/auth/v1/account/connections/"+url.PathEscape(id)+"/"+url.PathEscape(connID), nil, ch)
	z.Body.Close()
	if z.StatusCode != http.StatusNoContent {
		t.Fatalf("connection delete status=%d", z.StatusCode)
	}
	connectionDeleted = true
	delh = cloneCollectionHeaders(adminHeaders, current)
	z = do(t, client, http.MethodDelete, apiBase+"/auth/v1/auth-collections/"+url.PathEscape(id), nil, delh)
	z.Body.Close()
	if z.StatusCode != http.StatusNoContent {
		t.Fatalf("definition delete status=%d", z.StatusCode)
	}
	collectionDeleted = true
}

func uniqueCollectionID(t *testing.T) string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return "e2e-" + hex.EncodeToString(b[:])
}

func authCollectionsChaosConfig(t *testing.T) string {
	t.Helper()
	contextName := os.Getenv("GOAUTHY_E2E_CHAOS_CONTEXT")
	namespace := os.Getenv("GOAUTHY_E2E_CHAOS_NAMESPACE")
	pod := os.Getenv("GOAUTHY_E2E_CHAOS_DELETE_POD")
	prefix := os.Getenv("GOAUTHY_E2E_CHAOS_POD_PREFIX")
	if contextName == "" || pod == "" || prefix == "" {
		t.Fatal("GOAUTHY_E2E_CHAOS_CONTEXT, GOAUTHY_E2E_CHAOS_DELETE_POD, and GOAUTHY_E2E_CHAOS_POD_PREFIX are required when GOAUTHY_E2E_AUTH_COLLECTIONS_CHAOS=1")
	}
	if namespace == "" {
		namespace = "goauthy"
	}
	if namespace != "goauthy" || !strings.HasPrefix(contextName, "kind-goauthy-") || pod != "goauthy-0" || prefix != "goauthy-" {
		t.Fatalf("refusing unowned auth-collections chaos target context=%q namespace=%q pod=%q prefix=%q", contextName, namespace, pod, prefix)
	}
	return contextName
}

func authCollectionsChaosPodUID(t *testing.T, ctx context.Context, contextName string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "kubectl", "--context", contextName, "-n", "goauthy", "get", "pod", "goauthy-0", "-o", "jsonpath={.metadata.uid}")
	out, err := cmd.Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		t.Fatalf("get owned auth-collections chaos pod UID: %v", err)
	}
	return strings.TrimSpace(string(out))
}

func authCollectionsChaosKubectl(t *testing.T, ctx context.Context, contextName string, args ...string) {
	t.Helper()
	base := []string{"--context", contextName, "-n", "goauthy"}
	cmd := exec.CommandContext(ctx, "kubectl", append(base, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("kubectl %s: %v (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

func cloneCollectionHeaders(in map[string]string, rev int64) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	out["If-Match"] = strconv.Quote(strconv.FormatInt(rev, 10))
	return out
}
func readCollection(t *testing.T, r *http.Response, want int) (map[string]any, int64) {
	defer r.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(r.Body, 32<<10))
	if r.StatusCode != want {
		t.Fatalf("status=%d want=%d body=%s", r.StatusCode, want, b)
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		t.Fatal("invalid collection JSON")
	}
	var rev int64
	if n, ok := v["revision"].(float64); ok {
		rev = int64(n)
	}
	if rev <= 0 {
		rev, _ = strconv.ParseInt(strings.Trim(r.Header.Get("ETag"), `"`), 10, 64)
	}
	if rev <= 0 {
		t.Fatal("missing collection revision")
	}
	return v, rev
}
