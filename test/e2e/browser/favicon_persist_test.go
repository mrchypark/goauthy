package browser

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nativewebp "github.com/HugoSmits86/nativewebp"
)

type clientFaviconPersistState struct {
	ClientID    string `json:"client_id"`
	Revision    int64  `json:"revision"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
}

func TestClientFaviconPersistPrepare(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_LOGO") != "1" {
		t.Skip("set GOAUTHY_E2E_LOGO=1 to run client-favicon persistence E2E")
	}
	statePath := clientFaviconPersistStatePath(t)
	primary, secondary, username, password, _ := browserE2EConfig(t)

	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	managed := createThemeUIClient(t, admin, primary, headers)

	putClientFavicon(t, admin, primary, managed.ID, "favicon.png", "image/png", clientLogoPNG(t), headers)
	public := readClientFavicon(t, newBrowserClient(t), primary, managed.ID, "updated=1")
	if public.Status != http.StatusOK || public.ContentType != "image/webp" || len(public.Body) == 0 || public.Cache != clientLogoCacheControl {
		t.Fatalf("persisted public favicon status=%d content-type=%q cache=%q bytes=%d", public.Status, public.ContentType, public.Cache, len(public.Body))
	}
	assertFaviconWebP32(t, public.Body)

	data, err := json.Marshal(clientFaviconPersistState{
		ClientID:    managed.ID,
		Revision:    managed.Revision,
		Status:      public.Status,
		ContentType: public.ContentType,
		Body:        public.Body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(statePath, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("favicon persistence state mode=%#o, want 0600", info.Mode().Perm())
	}
}

func TestClientFaviconPersistVerify(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_LOGO") != "1" {
		t.Skip("set GOAUTHY_E2E_LOGO=1 to run client-favicon persistence E2E")
	}
	statePath := clientFaviconPersistStatePath(t)
	state := readClientFaviconPersistState(t, statePath)
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := []string{primary, secondary, logoutTertiaryURL(t)}

	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	for _, node := range nodes {
		got := readClientFavicon(t, newBrowserClient(t), node, state.ClientID, "updated=1")
		if got.Status != state.Status || got.ContentType != state.ContentType || !bytes.Equal(got.Body, state.Body) {
			t.Fatalf("persisted favicon node=%s status/content/body changed: got=(%d,%q,%d) want=(%d,%q,%d)", node, got.Status, got.ContentType, len(got.Body), state.Status, state.ContentType, len(state.Body))
		}
		if got.Cache != clientLogoCacheControl {
			t.Fatalf("persisted favicon node=%s Cache-Control=%q", node, got.Cache)
		}
		assertFaviconWebP32(t, got.Body)
	}

	deleteThemeUIClient(t, admin, primary, headers, &themeUIClient{ID: state.ClientID, Revision: state.Revision})
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
}

func clientFaviconPersistStatePath(t *testing.T) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("GOAUTHY_E2E_FAVICON_STATE_FILE"))
	if path == "" {
		t.Skip("set GOAUTHY_E2E_FAVICON_STATE_FILE for client-favicon persistence E2E")
	}
	return filepath.Clean(path)
}

func readClientFaviconPersistState(t *testing.T, path string) clientFaviconPersistState {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("favicon persistence state mode=%#o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state clientFaviconPersistState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("invalid favicon persistence state: %v", err)
	}
	if state.ClientID == "" || state.Revision <= 0 || state.Status != http.StatusOK || state.ContentType != "image/webp" || len(state.Body) == 0 {
		t.Fatal("invalid persisted client-favicon state")
	}
	assertFaviconWebP32(t, state.Body)
	return state
}

func assertFaviconWebP32(t *testing.T, body []byte) {
	t.Helper()
	decoded, err := nativewebp.Decode(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("favicon is not decodable WebP: %v", err)
	}
	if decoded.Bounds().Dx() != 32 || decoded.Bounds().Dy() != 32 {
		t.Fatalf("favicon dimensions=%dx%d want=32x32", decoded.Bounds().Dx(), decoded.Bounds().Dy())
	}
}
