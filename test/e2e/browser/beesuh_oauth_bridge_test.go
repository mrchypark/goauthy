package browser

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	raw, _ := json.Marshal(map[string]any{"issuer": issuer, "ca_file": caFile, "token_file": tokenFile, "binding": binding})
	write("fixture.json", raw)
	binary := filepath.Join(dir, "consumer.test")
	args := []string{"test", "-mod=readonly", "-overlay=" + overlayFile, "-c", "-o", binary, "."}
	if mod := os.Getenv("GOAUTHY_E2E_BEESUH_OAUTH_MODFILE"); mod != "" {
		if !filepath.IsAbs(mod) {
			t.Fatal("consumer modfile must be absolute")
		}
		args = append([]string{"test", "-modfile=" + mod}, args[1:]...)
	}
	build := exec.CommandContext(t.Context(), "go", args...)
	build.Dir, build.Env = project, oauthConsumerEnvironment(fixtureFile)
	build.Stdout, build.Stderr = io.Discard, io.Discard
	if build.Run() != nil {
		t.Fatal("compile real consumer harness")
	}
	ack, childAck, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ack.Close(); childAck.Close() })
	// The test context is cancelled before Cleanup. Cleanup owns shutdown.
	cmd := exec.Command(binary, "-test.run=^TestGoAuthyOAuthLiveBridge$", "-test.timeout=5m")
	cmd.Dir, cmd.Env = project, oauthConsumerEnvironment(fixtureFile)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.ExtraFiles = []*os.File{childAck}
	commands, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Start() != nil {
		commands.Close()
		t.Fatal("start real consumer harness")
	}
	childAck.Close()
	t.Cleanup(func() {
		if err := stopOAuthConsumer(cmd, commands, 5*time.Second); err != nil && !t.Failed() {
			t.Error("consumer harness did not exit cleanly")
		}
	})
	encoder, decoder := json.NewEncoder(commands), json.NewDecoder(ack)
	return func(denied bool) {
		before := modelCalls()
		if encoder.Encode(denied) != nil {
			t.Fatal("send consumer checkpoint")
		}
		done := make(chan bool, 1)
		go func() { var ok bool; err := decoder.Decode(&ok); done <- err == nil && ok }()
		select {
		case ok := <-done:
			if !ok {
				t.Fatal("real consumer checkpoint failed")
			}
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatal("real consumer checkpoint timed out")
		case <-t.Context().Done():
			_ = cmd.Process.Kill()
			t.Fatal("consumer checkpoint cancelled")
		}
		want := 2
		if denied {
			want = 0
		}
		if modelCalls()-before != want {
			t.Fatal("unexpected consumer provider dispatch count")
		}
		t.Logf("persistent Beesuh consumer: denied=%t model calls=%d", denied, want)
	}
}

// Keep issuer/provider credentials and ambient workspace settings out of the
// consumer. Runtime dependencies must already be present in the runner cache.
func oauthConsumerEnvironment(fixtureFile string) []string {
	env := []string{"GOWORK=off", "GOENV=off", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "BEESUH_E2E_GOAUTHY_OAUTH_FIXTURE=" + fixtureFile}
	for _, name := range []string{"PATH", "HOME", "TMPDIR", "TMP", "TEMP", "GOCACHE", "GOPATH", "GOROOT", "CGO_ENABLED", "CC", "CXX", "PKG_CONFIG", "LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"} {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

func TestOAuthConsumerEnvironmentIsolation(t *testing.T) {
	if os.Getenv("GOAUTHY_TEST_ENV_CHILD") == "1" {
		for _, name := range []string{"GOAUTHY_E2E_OAUTH2_CLIENT_SECRET", "GOAUTHY_E2E_BROWSER_PASSWORD", "GOAUTHY_E2E_CLIENT_SECRET", "GOFLAGS"} {
			if _, exists := os.LookupEnv(name); exists {
				t.Fatalf("parent variable inherited: %s", name)
			}
		}
		for _, name := range []string{"GOWORK", "GOENV", "GOPROXY", "GOSUMDB"} {
			if os.Getenv(name) != "off" {
				t.Fatalf("%s not disabled", name)
			}
		}
		if os.Getenv("BEESUH_E2E_GOAUTHY_OAUTH_FIXTURE") != "fixture-only" {
			t.Fatal("missing fixture reference")
		}
		return
	}
	for _, name := range []string{"GOAUTHY_E2E_OAUTH2_CLIENT_SECRET", "GOAUTHY_E2E_BROWSER_PASSWORD", "GOAUTHY_E2E_CLIENT_SECRET", "GOFLAGS", "GOWORK", "GOENV"} {
		t.Setenv(name, "must-not-inherit")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestOAuthConsumerEnvironmentIsolation$")
	cmd.Env = append(oauthConsumerEnvironment("fixture-only"), "GOAUTHY_TEST_ENV_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child environment: %v: %s", err, output)
	}
}

func TestOAuthConsumerIgnoresAmbientWorkspace(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":      "module example.test/consumer\n\ngo 1.24.0\n",
		"consumer.go": "package consumer\n",
		// If workspace discovery is enabled this missing module prevents build.
		"go.work":     "go 1.24.0\n\nuse ./missing-module\n",
		"go.work.sum": "preserve-user-workspace-checksums\n",
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOWORK", filepath.Join(dir, "go.work"))
	cmd := exec.CommandContext(t.Context(), "go", "test", "-mod=readonly", "-run=^$", ".")
	cmd.Dir, cmd.Env = dir, oauthConsumerEnvironment("")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated module build: %v: %s", err, output)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(files) {
		t.Fatal("consumer tree entries changed")
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(got) != want {
			t.Fatalf("consumer file changed: %s", name)
		}
	}
}

// Exactly one caller reaps the process, including timeout and early-exit cases.
func stopOAuthConsumer(cmd *exec.Cmd, commands io.Closer, timeout time.Duration) error {
	_ = commands.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		_ = cmd.Process.Kill()
		<-done
		return context.DeadlineExceeded
	}
}

func TestOAuthConsumerLifetime(t *testing.T) {
	if mode := os.Getenv("GOAUTHY_TEST_LIFETIME_CHILD"); mode != "" {
		ack := os.NewFile(3, "ack")
		defer ack.Close()
		if mode == "exit" {
			os.Exit(2)
		}
		if mode == "hang" {
			_, _ = ack.Write([]byte("!"))
			time.Sleep(time.Hour)
			return
		}
		if _, err := io.Copy(ack, os.Stdin); err != nil {
			t.Fatal(err)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	start := func(t *testing.T, mode string) (*exec.Cmd, io.WriteCloser, *os.File) {
		t.Helper()
		ack, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ack.Close(); writer.Close() })
		cmd := exec.Command(executable, "-test.run=^TestOAuthConsumerLifetime$")
		cmd.Env = append(oauthConsumerEnvironment(""), "GOAUTHY_TEST_LIFETIME_CHILD="+mode)
		cmd.ExtraFiles = []*os.File{writer}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			stdin.Close()
			t.Fatal(err)
		}
		writer.Close()
		return cmd, stdin, ack
	}
	for _, count := range []int{1, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			for i := 0; i < count; i++ {
				cmd, stdin, ack := start(t, "echo")
				t.Cleanup(func() {
					if t.Context().Err() == nil {
						t.Error("test cancellation ordering not exercised")
					}
					if err := stopOAuthConsumer(cmd, stdin, 5*time.Second); err != nil {
						t.Errorf("normal shutdown: %v", err)
					}
				})
				for j := 0; j < 3; j++ {
					if _, err := stdin.Write([]byte("!")); err != nil {
						t.Fatal(err)
					}
					var response [1]byte
					if _, err := io.ReadFull(ack, response[:]); err != nil || response[0] != '!' {
						t.Fatal("checkpoint failed")
					}
				}
			}
		})
	}
	t.Run("premature-exit", func(t *testing.T) {
		cmd, stdin, _ := start(t, "exit")
		if err := stopOAuthConsumer(cmd, stdin, time.Second); err == nil {
			t.Fatal("early exit accepted")
		}
	})
	t.Run("shutdown-timeout", func(t *testing.T) {
		cmd, stdin, ack := start(t, "hang")
		var ready [1]byte
		if _, err := io.ReadFull(ack, ready[:]); err != nil {
			t.Fatal(err)
		}
		if err := stopOAuthConsumer(cmd, stdin, 20*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("shutdown result: %v", err)
		}
		if cmd.ProcessState == nil || cmd.ProcessState.Success() {
			t.Fatal("hung child not killed and reaped")
		}
	})
}
