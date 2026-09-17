package browser

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestTernalDeviceCLILive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_TERNAL_DEVICE") != "1" {
		t.Skip("set GOAUTHY_E2E_TERNAL_DEVICE=1 to run Ternal device CLI E2E")
	}
	// os.UserConfigDir ignores XDG_CONFIG_HOME on macOS and Windows. Refuse
	// before starting any child that could overwrite the operator's session.
	if err := requireTernalXDGIsolation(runtime.GOOS); err != nil {
		t.Fatal(err)
	}
	apiBin := os.Getenv("GOAUTHY_E2E_TERNAL_API_BIN")
	cliBin := os.Getenv("GOAUTHY_E2E_TERNAL_CLI_BIN")
	if apiBin == "" || cliBin == "" {
		t.Fatal("GOAUTHY_E2E_TERNAL_API_BIN and GOAUTHY_E2E_TERNAL_CLI_BIN are required")
	}
	primary, _, username, password, clientSecret := browserE2EConfig(t)
	apiAddr := reserveTernalLoopback(t)
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		t.Fatal(err)
	}

	apiEnv := sanitizedTernalEnv()
	apiEnv = append(apiEnv,
		"TERNAL_BIND="+apiAddr,
		"TERNAL_DATA_DIR="+dataDir,
		"TERNAL_SESSION_KEY="+randomTernalSecret(t),
		"TERNAL_RELAY_ACCESS_TOKEN="+randomTernalSecret(t),
		"TERNAL_OIDC_ISSUER="+primary,
		"TERNAL_OIDC_CLIENT_ID=goauthy-dev",
		"TERNAL_OIDC_CLIENT_SECRET="+clientSecret,
		"TERNAL_OIDC_REDIRECT_URL=http://"+apiAddr+"/auth/callback",
		"TERNAL_OIDC_ADMIN_GROUP=ternal-admins",
		"TERNAL_OIDC_GROUPS_CLAIM=groups",
	)
	apiCtx, cancelAPI := context.WithCancel(t.Context())
	defer cancelAPI()
	api := exec.CommandContext(apiCtx, apiBin)
	api.Env = apiEnv
	apiStdout, err := api.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	apiStderr, err := api.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := api.Start(); err != nil {
		t.Fatal(err)
	}
	registerTernalCleanup(t, api)
	go drainTernalOutput(apiStderr)
	ready := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(apiStdout)
		readySent := false
		for scanner.Scan() {
			if !readySent && scanner.Text() == "ternal-api listening on http://"+apiAddr {
				readySent = true
				ready <- nil
			}
		}
		if readySent {
			return
		}
		if err := scanner.Err(); err != nil {
			ready <- err
		} else {
			ready <- errors.New("ternal-api exited before readiness")
		}
	}()
	select {
	case err := <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("ternal-api readiness timeout")
	}

	cliEnv := sanitizedTernalEnv()
	cliEnv = append(cliEnv, "TERNAL_API_URL=http://"+apiAddr, "XDG_CONFIG_HOME="+configDir)
	loginCtx, cancelLogin := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancelLogin()
	login := exec.CommandContext(loginCtx, cliBin, "login")
	login.Env = cliEnv
	stdout, err := login.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := login.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := login.Start(); err != nil {
		t.Fatal(err)
	}
	registerTernalCleanup(t, login)
	go drainTernalOutput(stderr)
	visit, code, err := readTernalDevicePrompt(stdout, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if visit != primary+"/oidc/device/verify" || len(code) < 4 || len(code) > 64 || strings.IndexFunc(code, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-')
	}) >= 0 {
		t.Fatal("Ternal device prompt did not contain the expected verification endpoint")
	}
	complete := visit + "?" + url.Values{"user_code": {code}}.Encode()
	loginAndApproveDevice(t, newBrowserClient(t), deviceLoginGrant{VerificationURIComplete: complete, UserCode: code}, primary, primary, username, password)
	if err := login.Wait(); err != nil {
		t.Fatal("ternalctl login failed")
	}

	sessionPath := filepath.Join(configDir, "ternal", "session.json")
	info, err := os.Stat(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("session mode=%#o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(sessionPath)
	var session map[string]json.RawMessage
	if err != nil || json.Unmarshal(data, &session) != nil || len(session) != 3 {
		t.Fatal("session file is incomplete")
	}
	for _, key := range []string{"cookie", "csrf_token", "expires_at"} {
		if _, ok := session[key]; !ok {
			t.Fatal("session file is incomplete")
		}
	}
	var cookie, csrf string
	var expiry int64
	if json.Unmarshal(session["cookie"], &cookie) != nil || json.Unmarshal(session["csrf_token"], &csrf) != nil || json.Unmarshal(session["expires_at"], &expiry) != nil || cookie == "" || csrf == "" || expiry <= time.Now().Unix() {
		t.Fatal("session file is incomplete")
	}

	runTernalCLI(t, cliBin, cliEnv, "whoami", true, func(output string) bool {
		return strings.Contains(output, "User: bootstrap-admin") && strings.Contains(output, "ternal-admins") && strings.Contains(output, "operators")
	})
	runTernalCLI(t, cliBin, cliEnv, "logout", true, nil)
	if _, err := os.Stat(sessionPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("logout did not remove the session file")
	}
	runTernalCLI(t, cliBin, cliEnv, "whoami", false, nil)
	// Local file removal alone does not prove the server invalidated the session.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+apiAddr+"/auth/session", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "ternal_session", Value: cookie})
	res, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatal("check logged-out Ternal session failed")
	}
	defer res.Body.Close()
	var state struct {
		Authenticated bool `json:"authenticated"`
	}
	if res.StatusCode != http.StatusOK || json.NewDecoder(res.Body).Decode(&state) != nil || state.Authenticated {
		t.Fatal("Ternal server retained the logged-out session")
	}
}

func requireTernalXDGIsolation(goos string) error {
	if goos != "linux" {
		return errors.New("Ternal CLI fixture requires Linux with a private XDG_CONFIG_HOME; native execution is disabled on this platform")
	}
	return nil
}

func TestTernalXDGIsolationGuard(t *testing.T) {
	for _, goos := range []string{"darwin", "windows", "", "linux"} {
		if (requireTernalXDGIsolation(goos) == nil) != (goos == "linux") {
			t.Fatalf("unexpected isolation decision for %q", goos)
		}
	}
}

func reserveTernalLoopback(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func randomTernalSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func sanitizedTernalEnv() []string {
	env := make([]string, 0, len(os.Environ()))
	for _, value := range os.Environ() {
		if strings.HasPrefix(value, "TERNAL_") || strings.HasPrefix(value, "GOAUTHY_") || strings.HasPrefix(value, "XDG_CONFIG_HOME=") {
			continue
		}
		env = append(env, value)
	}
	return env
}

func registerTernalCleanup(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	t.Cleanup(func() {
		if cmd.Process == nil || cmd.ProcessState != nil {
			return
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		wait := make(chan struct{})
		go func() { _ = cmd.Wait(); close(wait) }()
		select {
		case <-wait:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
			<-wait
		}
	})
}

func drainTernalOutput(r interface{ Read([]byte) (int, error) }) {
	b := make([]byte, 4096)
	for {
		if _, err := r.Read(b); err != nil {
			return
		}
	}
}

func readTernalDevicePrompt(r interface{ Read([]byte) (int, error) }, timeout time.Duration) (string, string, error) {
	lines := make(chan string, 32)
	go func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			default:
			}
		}
		close(lines)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var visit, code string
	for visit == "" || code == "" {
		select {
		case line, ok := <-lines:
			if !ok {
				return "", "", errors.New("ternalctl exited before device prompt")
			}
			if value, ok := strings.CutPrefix(line, "Visit: "); ok {
				visit = value
			}
			if value, ok := strings.CutPrefix(line, "Enter code: "); ok {
				code = value
			}
		case <-timer.C:
			return "", "", errors.New("ternalctl device prompt timeout")
		}
	}
	return visit, code, nil
}

func runTernalCLI(t *testing.T, bin string, env []string, command string, wantSuccess bool, valid func(string) bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, command)
	cmd.Env = env
	output, err := cmd.Output()
	if (err == nil) != wantSuccess {
		t.Fatalf("ternalctl %s success=%v, want %v", command, err == nil, wantSuccess)
	}
	if valid != nil && !valid(string(output)) {
		t.Fatalf("ternalctl %s returned an unexpected identity", command)
	}
}
