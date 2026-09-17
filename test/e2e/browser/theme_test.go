package browser

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/mrchypark/goauthy/internal/branding"
)

func TestThemeLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_THEME") != "1" {
		t.Skip("set GOAUTHY_E2E_THEME=1 to run theme E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	nodes := []string{primary, secondary, tertiary}

	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	managed := createCrossClientExchanger(t, admin, primary, headers, "client_credentials")
	t.Cleanup(func() { deleteCrossClientExchanger(t, admin, primary, headers, managed) })

	want := branding.DefaultTheme(managed.ID)
	want.BorderRadius = "17px"
	want.Light.Action = []uint16{210, 80, 45}
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	putHeaders := cloneThemeHeaders(headers)
	putHeaders["Content-Type"] = "application/json"
	response := do(t, admin, http.MethodPut, primary+"/auth/v1/theme/"+url.PathEscape(managed.ID), bytes.NewReader(body), putHeaders)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("theme PUT status=%d", response.StatusCode)
	}

	for _, node := range nodes {
		got := readThemeJSON(t, admin, node, managed.ID, headers)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("theme POST node=%s did not preserve custom override", node)
		}
		assertThemeCSS(t, node, managed.ID, "gzip", "gzip", want.CSS())
		assertThemeCSS(t, node, managed.ID, "br, gzip", "br", want.CSS())
	}

	response = do(t, admin, http.MethodDelete, primary+"/auth/v1/theme/"+url.PathEscape(managed.ID), nil, headers)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("theme DELETE status=%d", response.StatusCode)
	}
	defaultTheme := branding.DefaultTheme("rauthy")
	for _, node := range nodes {
		got := readThemeJSON(t, admin, node, managed.ID, headers)
		if !reflect.DeepEqual(got, defaultTheme) {
			t.Fatalf("theme default fallback node=%s returned a non-default theme", node)
		}
		assertThemeCSS(t, node, managed.ID, "identity", "none", defaultTheme.CSS())
	}
}

type themePersistState struct {
	ClientID string         `json:"client_id"`
	Revision int64          `json:"revision"`
	Theme    branding.Theme `json:"theme"`
}

func TestThemePersistPrepare(t *testing.T) {
	statePath := themePersistStatePath(t)
	primary, secondary, username, password, _ := browserE2EConfig(t)

	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	managed := createCrossClientExchanger(t, admin, primary, headers, "client_credentials")

	want := branding.DefaultTheme(managed.ID)
	want.BorderRadius = "19px"
	want.Light.Action = []uint16{72, 66, 49}
	body, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	putHeaders := cloneThemeHeaders(headers)
	putHeaders["Content-Type"] = "application/json"
	response := do(t, admin, http.MethodPut, primary+"/auth/v1/theme/"+url.PathEscape(managed.ID), bytes.NewReader(body), putHeaders)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("theme persistence PUT status=%d", response.StatusCode)
	}
	if got := readThemeJSON(t, admin, primary, managed.ID, headers); !reflect.DeepEqual(got, want) {
		t.Fatal("theme persistence PUT did not store the expected override")
	}

	data, err := json.Marshal(themePersistState{
		ClientID: managed.ID,
		Revision: managed.Revision,
		Theme:    want,
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
		t.Fatalf("theme persistence state mode=%#o, want 0600", info.Mode().Perm())
	}
}

func TestThemePersistVerify(t *testing.T) {
	statePath := themePersistStatePath(t)
	state := readThemePersistState(t, statePath)
	primary, secondary, username, password, _ := browserE2EConfig(t)
	tertiary := logoutTertiaryURL(t)
	nodes := []string{primary, secondary, tertiary}

	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	for _, node := range nodes {
		got := readThemeJSON(t, admin, node, state.ClientID, headers)
		if !reflect.DeepEqual(got, state.Theme) {
			t.Fatalf("persisted theme JSON node=%s changed across replacement", node)
		}
		assertThemeCSS(t, node, state.ClientID, "gzip", "gzip", state.Theme.CSS())
		assertThemeCSS(t, node, state.ClientID, "br, gzip", "br", state.Theme.CSS())
	}

	deleteCrossClientExchanger(t, admin, primary, headers, &crossClientExchanger{
		ID:       state.ClientID,
		Revision: state.Revision,
	})
	if err := os.Remove(statePath); err != nil {
		t.Fatal(err)
	}
}

func themePersistStatePath(t *testing.T) string {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("GOAUTHY_E2E_THEME_STATE_FILE"))
	if path == "" {
		t.Skip("set GOAUTHY_E2E_THEME_STATE_FILE for theme persistence E2E")
	}
	return filepath.Clean(path)
}

func readThemePersistState(t *testing.T, path string) themePersistState {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("theme persistence state mode=%#o, want 0600", info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state themePersistState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("invalid theme persistence state: %v", err)
	}
	if state.ClientID == "" || state.Revision <= 0 {
		t.Fatal("invalid theme persistence client metadata")
	}
	return state
}

func cloneThemeHeaders(headers map[string]string) map[string]string {
	copy := make(map[string]string, len(headers)+1)
	for key, value := range headers {
		copy[key] = value
	}
	return copy
}

func readThemeJSON(t *testing.T, client *http.Client, node, clientID string, headers map[string]string) branding.Theme {
	t.Helper()
	response := do(t, client, http.MethodPost, node+"/auth/v1/theme/"+url.PathEscape(clientID), nil, headers)
	defer response.Body.Close()
	var theme branding.Theme
	err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&theme)
	if response.StatusCode != http.StatusOK || err != nil {
		t.Fatalf("theme POST node=%s status=%d decode=%v", node, response.StatusCode, err)
	}
	return theme
}

func assertThemeCSS(t *testing.T, node, clientID, acceptEncoding, wantEncoding, want string) {
	t.Helper()
	requestHeaders := map[string]string{"Accept-Encoding": acceptEncoding}
	client := newBrowserClient(t)
	response := do(t, client, http.MethodGet, node+"/auth/v1/theme/"+url.PathEscape(clientID)+"/4102444800", nil, requestHeaders)
	defer response.Body.Close()
	encoding := response.Header.Get("Content-Encoding")
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if response.StatusCode != http.StatusOK || err != nil || response.Header.Get("Content-Type") != "text/css" || encoding != wantEncoding {
		t.Fatalf("theme CSS node=%s encoding=%q status=%d content-type=%q content-encoding=%q read=%v", node, acceptEncoding, response.StatusCode, response.Header.Get("Content-Type"), encoding, err)
	}
	decoded, err := decodeThemeCSS(encoding, body)
	if err != nil || string(decoded) != want {
		t.Fatalf("theme CSS node=%s encoding=%q roundtrip=%t err=%v", node, acceptEncoding, string(decoded) == want, err)
	}
}

func decodeThemeCSS(encoding string, body []byte) ([]byte, error) {
	switch encoding {
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		decoded, readErr := io.ReadAll(reader)
		closeErr := reader.Close()
		if readErr != nil {
			return nil, readErr
		}
		return decoded, closeErr
	case "br":
		return io.ReadAll(brotli.NewReader(bytes.NewReader(body)))
	case "none":
		return body, nil
	default:
		return nil, io.ErrUnexpectedEOF
	}
}
