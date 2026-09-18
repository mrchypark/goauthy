package browser

import (
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testBeesuhDeliveryBridge(t *testing.T, owner *http.Client, base string, headers map[string]string, collection, firstConnection, consumer, token, firstGrant, provider, digest, firstGeneration string, firstExpiry int64) {
	t.Helper()
	project := os.Getenv("GOAUTHY_E2E_BEESUH_DELIVERY_PROJECT_DIR")
	if project == "" || !filepath.IsAbs(project) {
		t.Fatal("GOAUTHY_E2E_BEESUH_DELIVERY_PROJECT_DIR must be absolute")
	}
	if _, err := os.Stat(project); err != nil {
		t.Fatal("Beesuh delivery project is unavailable")
	}

	var calls, personalCalls, workCalls atomic.Int32
	providerServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/chat/completions" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		key := r.Header.Get("Authorization")
		var text string
		switch key {
		case "Bearer e2e-rotated-key":
			personalCalls.Add(1)
			text = "personal"
		case "Bearer beesuh-work-key":
			workCalls.Add(1)
			text = "work"
		default:
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": text}, "finish_reason": "stop"}}, "usage": map[string]int{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
	}))
	defer providerServer.Close()

	fixtureDir := t.TempDir()
	if err := os.Chmod(fixtureDir, 0700); err != nil {
		t.Fatal(err)
	}
	providerCA := filepath.Join(fixtureDir, "provider-ca.pem")
	cert := providerServer.Certificate()
	if err := os.WriteFile(providerCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	issuerCA := filepath.Join(fixtureDir, "issuer-ca.pem")
	issuerSource := os.Getenv("SSL_CERT_FILE")
	if issuerSource == "" || !filepath.IsAbs(issuerSource) {
		t.Fatal("SSL_CERT_FILE must identify the issuer CA")
	}
	issuerPEM, err := os.ReadFile(issuerSource)
	if err != nil || len(issuerPEM) == 0 {
		t.Fatal("issuer CA is unavailable")
	}
	if err := os.WriteFile(issuerCA, issuerPEM, 0600); err != nil {
		t.Fatal(err)
	}

	connectionURL := base + "/auth/v1/account/connections/" + url.PathEscape(collection)
	second := do(t, owner, http.MethodPost, connectionURL, strings.NewReader(`{"definition_revision":1,"metadata":{}}`), headers)
	var secondDoc struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	err = json.NewDecoder(io.LimitReader(second.Body, 8192)).Decode(&secondDoc)
	second.Body.Close()
	if second.StatusCode != http.StatusCreated || err != nil || secondDoc.ID == "" || secondDoc.Revision < 1 {
		t.Fatalf("second connection create status=%d", second.StatusCode)
	}
	secondBase := connectionURL + "/" + url.PathEscape(secondDoc.ID)
	revokedSecond := false
	t.Cleanup(func() {
		r := do(t, owner, http.MethodDelete, secondBase, nil, sessionHeader(headers, "If-Match", strconv.Quote(strconv.FormatInt(secondDoc.Revision, 10))))
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Errorf("second connection cleanup status=%d", r.StatusCode)
		}
	})
	key := do(t, owner, http.MethodGet, secondBase+"/api-key/connector", nil, headers)
	var connector struct {
		Digest string `json:"digest"`
	}
	err = json.NewDecoder(io.LimitReader(key.Body, 4096)).Decode(&connector)
	key.Body.Close()
	if key.StatusCode != http.StatusOK || err != nil || connector.Digest != digest {
		t.Fatal("second connector digest mismatch")
	}
	bound := do(t, owner, http.MethodPut, secondBase+"/api-key", strings.NewReader(`{"api_key":"beesuh-work-key","version":0,"connector_digest":"`+digest+`"}`), headers)
	bound.Body.Close()
	if bound.StatusCode != http.StatusOK {
		t.Fatalf("second API key bind status=%d", bound.StatusCode)
	}
	grantBody := `{"consumer_client_id":"` + consumer + `","mode":"credential_delivery","purpose":"Beesuh delivery bridge","expires_at_unix_ms":` + strconv.FormatInt(time.Now().Add(time.Hour).UnixMilli(), 10) + `,"connector_digest":"` + digest + `"}`
	grant := do(t, owner, http.MethodPost, secondBase+"/grants", strings.NewReader(grantBody), headers)
	var grantDoc struct {
		ID         string `json:"id"`
		Provider   string `json:"provider_id"`
		Generation string `json:"generation"`
		Expires    int64  `json:"expires_at_unix_ms"`
	}
	err = json.NewDecoder(io.LimitReader(grant.Body, 8192)).Decode(&grantDoc)
	grant.Body.Close()
	if grant.StatusCode != http.StatusCreated || err != nil || grantDoc.ID == "" || grantDoc.Provider != provider || grantDoc.Generation == "" || grantDoc.Expires <= 0 || firstExpiry <= 0 {
		t.Fatalf("second credential grant status=%d", grant.StatusCode)
	}
	t.Cleanup(func() {
		if revokedSecond {
			return
		}
		r := do(t, owner, http.MethodDelete, secondBase+"/grants/"+url.PathEscape(grantDoc.ID), nil, sessionHeader(headers, "If-Match", `"1"`))
		r.Body.Close()
		if r.StatusCode != http.StatusNoContent {
			t.Errorf("second grant cleanup status=%d", r.StatusCode)
		}
	})

	fixture := map[string]any{
		"issuer": base, "issuer_ca_file": issuerCA, "provider_ca_file": providerCA,
		"profiles": []map[string]any{
			{"connection_id": firstConnection, "token_file": filepath.Join(fixtureDir, "personal.token"), "binding": map[string]any{"grant_id": firstGrant, "provider_id": provider, "connection_generation": firstGeneration, "credential_version": int64(2), "connector_digest": digest, "header": "Authorization", "prefix": "Bearer ", "endpoint": providerServer.URL + "/v1/chat/completions"}, "expected_text": "personal"},
			{"connection_id": secondDoc.ID, "token_file": filepath.Join(fixtureDir, "work.token"), "binding": map[string]any{"grant_id": grantDoc.ID, "provider_id": grantDoc.Provider, "connection_generation": grantDoc.Generation, "credential_version": int64(1), "connector_digest": digest, "header": "Authorization", "prefix": "Bearer ", "endpoint": providerServer.URL + "/v1/chat/completions"}, "expected_text": "work"},
		},
	}
	for _, name := range []string{"personal.token", "work.token"} {
		if err := os.WriteFile(filepath.Join(fixtureDir, name), []byte(token+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fixtureFile := filepath.Join(fixtureDir, "delivery.json")
	raw, err := json.Marshal(fixture)
	if err != nil || os.WriteFile(fixtureFile, append(raw, '\n'), 0600) != nil {
		t.Fatal("write Beesuh delivery fixture")
	}
	runChild := func() {
		cmd := exec.CommandContext(t.Context(), "go", "test", "-mod=readonly", "-count=1", ".", "-run", "^TestGoAuthyDeliveryLiveE2E$")
		cmd.Dir = project
		env := make([]string, 0, 2)
		for _, value := range os.Environ() {
			if !strings.HasPrefix(value, "BEESUH_E2E_GOAUTHY_DELIVERY") {
				env = append(env, value)
			}
		}
		env = append(env, "BEESUH_E2E_GOAUTHY_DELIVERY=1", "BEESUH_E2E_GOAUTHY_DELIVERY_FIXTURE_FILE="+fixtureFile)
		cmd.Env = env
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		if err := cmd.Run(); err != nil {
			t.Fatal("Beesuh delivery harness failed")
		}
	}
	runChild()
	if calls.Load() != 4 || personalCalls.Load() != 2 || workCalls.Load() != 2 {
		t.Fatal("Beesuh selected profiles did not each dispatch twice")
	}
	t.Log("Beesuh two-profile delivery passed: personal=2, work=2")
	revoke := do(t, owner, http.MethodDelete, base+"/auth/v1/account/connections/"+url.PathEscape(collection)+"/"+url.PathEscape(secondDoc.ID)+"/grants/"+url.PathEscape(grantDoc.ID), nil, sessionHeader(headers, "If-Match", `"1"`))
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusNoContent {
		t.Fatalf("second grant revoke status=%d", revoke.StatusCode)
	}
	revokedSecond = true
	check := do(t, newBrowserClient(t), http.MethodPost, base+"/auth/v1/connection-grants/"+url.PathEscape(grantDoc.ID)+"/credential", nil, map[string]string{"Authorization": "Bearer " + token})
	check.Body.Close()
	if check.StatusCode != http.StatusNotFound {
		t.Fatalf("revoked second delivery status=%d", check.StatusCode)
	}
	fixture["profiles"].([]map[string]any)[1]["expected_error"] = true
	raw, err = json.Marshal(fixture)
	if err != nil || os.WriteFile(fixtureFile, append(raw, '\n'), 0600) != nil {
		t.Fatal("rewrite Beesuh delivery fixture")
	}
	runChild()
	if calls.Load() != 6 || personalCalls.Load() != 4 || workCalls.Load() != 2 {
		t.Fatal("Beesuh delivery provider dispatch counts did not validate")
	}
	t.Log("Beesuh revoked work profile blocked; personal dispatched twice more")
}
