package browser

import (
	_ "embed"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

//go:embed testdata/beesuh_oauth_live_test.go
var beesuhOAuthLiveHarness []byte

// oauthConsumerBridge uses Go's overlay to add only the harness to the selected
// consumer checkout. Its Runtime, adapter and dependencies are not copied here.
func oauthConsumerBridge(t *testing.T, issuer, endpoint, token string, binding map[string]any, fixture *http.Client) func(bool) {
	t.Helper()
	project := os.Getenv("GOAUTHY_E2E_BEESUH_OAUTH_PROJECT_DIR")
	if project == "" {
		return func(bool) {}
	}
	if !filepath.IsAbs(project) {
		t.Fatal("consumer checkout must be absolute")
	}
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if os.WriteFile(path, data, 0600) != nil {
			t.Fatal("write private consumer fixture")
		}
		return path
	}
	ca, err := os.ReadFile(os.Getenv("SSL_CERT_FILE"))
	if err != nil {
		t.Fatal("issuer/provider CA unavailable")
	}
	caFile := write("ca.pem", ca)
	tokenFile := write("human.token", []byte(token))
	source := write("bridge_test.go", beesuhOAuthLiveHarness)
	target := filepath.Join(project, "goauthy_oauth_live_bridge_test.go")
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("consumer harness path already exists")
	}
	overlay, _ := json.Marshal(map[string]any{"Replace": map[string]string{target: source}})
	overlayFile := write("overlay.json", overlay)
	fixtureFile := filepath.Join(dir, "fixture.json")
	modelCalls := func() int {
		r := do(t, fixture, http.MethodGet, strings.TrimSuffix(endpoint, "/v1/chat/completions")+"/stats", nil, nil)
		defer r.Body.Close()
		var stats struct{ Model int }
		if r.StatusCode != 200 || json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&stats) != nil {
			t.Fatal("read model count")
		}
		return stats.Model
	}
	return func(denied bool) {
		raw, _ := json.Marshal(map[string]any{"issuer": issuer, "ca_file": caFile, "token_file": tokenFile, "binding": binding, "denied": denied})
		write("fixture.json", raw)
		args := []string{"test", "-mod=readonly", "-overlay=" + overlayFile, "-count=1", "-run", "^TestGoAuthyOAuthLiveBridge$", "."}
		if mod := os.Getenv("GOAUTHY_E2E_BEESUH_OAUTH_MODFILE"); mod != "" {
			if !filepath.IsAbs(mod) {
				t.Fatal("consumer modfile must be absolute")
			}
			args = append([]string{"test", "-modfile=" + mod}, args[1:]...)
		}
		cmd := exec.CommandContext(t.Context(), "go", args...)
		cmd.Dir = project
		for _, v := range os.Environ() {
			if !strings.HasPrefix(v, "BEESUH_E2E_GOAUTHY_OAUTH_FIXTURE=") {
				cmd.Env = append(cmd.Env, v)
			}
		}
		cmd.Env = append(cmd.Env, "BEESUH_E2E_GOAUTHY_OAUTH_FIXTURE="+fixtureFile)
		cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
		before := modelCalls()
		if cmd.Run() != nil {
			t.Fatal("real Beesuh OAuth consumer failed")
		}
		want := 2
		if denied {
			want = 0
		}
		if modelCalls()-before != want {
			t.Fatal("unexpected consumer provider dispatch count")
		}
		t.Logf("real Beesuh OAuth consumer: denied=%t model calls=%d", denied, want)
	}
}
