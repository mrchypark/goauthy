package browser

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type clientLogoPersistState struct {
	ClientID    string `json:"client_id"`
	Revision    int64  `json:"revision"`
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        []byte `json:"body"`
}

func TestClientLogoPersistPrepare(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_LOGO") != "1" {
		t.Skip("set GOAUTHY_E2E_LOGO=1 to run client-logo persistence E2E")
	}
	statePath := clientLogoPersistStatePath(t)
	primary, secondary, username, password, _ := browserE2EConfig(t)

	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	managed := createThemeUIClient(t, admin, primary, headers)

	put := uploadClientLogo(t, admin, primary, managed.ID, "logo.svg", "image/svg+xml", clientLogoPersistSVG(), headers)
	putBody := readClientLogoBody(t, put)
	if put.StatusCode != http.StatusOK || len(putBody) != 0 {
		t.Fatalf("logo persistence PUT status=%d body=%q", put.StatusCode, putBody)
	}

	public := readClientLogo(t, newBrowserClient(t), primary, managed.ID, "updated=1")
	if public.Status != http.StatusOK || public.ContentType != "image/svg+xml" || len(public.Body) == 0 {
		t.Fatalf("persisted public logo status=%d content-type=%q bytes=%d", public.Status, public.ContentType, len(public.Body))
	}

	data, err := json.Marshal(clientLogoPersistState{
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
		t.Fatalf("logo persistence state mode=%#o, want 0600", info.Mode().Perm())
	}
}

func TestClientLogoPersistVerify(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_LOGO") != "1" {
		t.Skip("set GOAUTHY_E2E_LOGO=1 to run client-logo persistence E2E")
	}
	statePath := clientLogoPersistStatePath(t)
	state := readClientLogoPersistState(t, statePath)
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := []string{primary, secondary, logoutTertiaryURL(t)}

	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	for _, node := range nodes {
		got := readClientLogo(t, newBrowserClient(t), node, state.ClientID, "updated=1")
		if got.Status != state.Status || got.ContentType != state.ContentType || !bytes.Equal(got.Body, state.Body) {
			t.Fatalf("persisted logo node=%s status/content/body changed: got=(%d,%q,%d) want=(%d,%q,%d)", node, got.Status, got.ContentType, len(got.Body), state.Status, state.ContentType, len(state.Body))
		}
		if got.Cache != clientLogoCacheControl {
			t.Fatalf("persisted logo node=%s Cache-Control=%q", node, got.Cache)
		}
	}

	deleteThemeUIClient(t, admin, primary, headers, &themeUIClient{ID: state.ClientID, Revision: state.Revision})
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
}

func clientLogoPersistStatePath(t *testing.T) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("GOAUTHY_E2E_LOGO_STATE_FILE"))
	if path == "" {
		t.Skip("set GOAUTHY_E2E_LOGO_STATE_FILE for client-logo persistence E2E")
	}
	return filepath.Clean(path)
}

func readClientLogoPersistState(t *testing.T, path string) clientLogoPersistState {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("logo persistence state mode=%#o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state clientLogoPersistState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("invalid logo persistence state: %v", err)
	}
	if state.ClientID == "" || state.Revision <= 0 || state.Status != http.StatusOK || state.ContentType != "image/svg+xml" || len(state.Body) == 0 {
		t.Fatal("invalid persisted client-logo state")
	}
	return state
}

func clientLogoPersistSVG() []byte {
	return []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10" fill="#2a6"/></svg>`)
}
