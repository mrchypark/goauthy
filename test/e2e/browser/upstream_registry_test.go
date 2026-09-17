package browser

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"strings"
	"testing"

	nativewebp "github.com/HugoSmits86/nativewebp"
)

func TestUpstreamRegistryLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_UPSTREAM_REGISTRY") != "1" {
		t.Skip("set GOAUTHY_E2E_UPSTREAM_REGISTRY=1 to run upstream-registry E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := []string{primary, secondary}
	if tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/"); tertiary != "" {
		nodes = append(nodes, tertiary)
	}
	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	uniqueSuffix := func() string {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(b[:])
	}
	suffix := uniqueSuffix()
	issuer := "https://" + suffix + ".e2e.example.com"
	createBody := providerRequestBody(t, "e2e-reg-"+suffix, issuer)
	created := do(t, admin, http.MethodPost, primary+"/auth/v1/providers/create", marshalJSON(t, createBody), headers)
	if created.StatusCode != http.StatusOK {
		t.Fatalf("create status=%d", created.StatusCode)
	}
	var createdResp providerResponse
	if err := json.NewDecoder(io.LimitReader(created.Body, 64<<10)).Decode(&createdResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	created.Body.Close()
	if createdResp.ID == "" {
		t.Fatal("created provider has empty ID")
	}
	providerID := createdResp.ID
	t.Cleanup(func() {
		r := do(t, admin, http.MethodDelete, primary+"/auth/v1/providers/"+providerID, nil, headers)
		if r.StatusCode != http.StatusOK && r.StatusCode != http.StatusNotFound {
			t.Errorf("cleanup delete provider %s status=%d", providerID, r.StatusCode)
		}
		r.Body.Close()
	})
	listed := do(t, admin, http.MethodPost, primary+"/auth/v1/providers", nil, headers)
	if listed.StatusCode != http.StatusOK {
		t.Fatalf("list status=%d", listed.StatusCode)
	}
	var allProviders []providerResponse
	if err := json.NewDecoder(io.LimitReader(listed.Body, 256<<10)).Decode(&allProviders); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	listed.Body.Close()
	foundInList := false
	for _, p := range allProviders {
		if p.ID == providerID {
			foundInList = true
			break
		}
	}
	if !foundInList {
		t.Fatalf("created provider %s not in list (%d providers)", providerID, len(allProviders))
	}
	for _, node := range nodes {
		minimalResp := do(t, newBrowserClient(t), http.MethodGet, node+"/auth/v1/providers/minimal", nil, nil)
		if minimalResp.StatusCode != http.StatusOK {
			t.Fatalf("minimal node=%s status=%d", node, minimalResp.StatusCode)
		}
		var minimalRaw []map[string]json.RawMessage
		if err := json.NewDecoder(io.LimitReader(minimalResp.Body, 64<<10)).Decode(&minimalRaw); err != nil {
			t.Fatalf("decode minimal node=%s: %v", node, err)
		}
		minimalResp.Body.Close()
		foundMinimal := false
		for _, entry := range minimalRaw {
			var id string
			if idRaw, ok := entry["id"]; ok {
				json.Unmarshal(idRaw, &id)
			}
			if id == providerID {
				foundMinimal = true
				for _, forbidden := range []string{"client_secret", "secret"} {
					if _, leak := entry[forbidden]; leak {
						t.Fatalf("minimal node=%s provider %s leaked field %q", node, providerID, forbidden)
					}
				}
				break
			}
		}
		if !foundMinimal {
			t.Fatalf("created provider %s not in minimal node=%s", providerID, node)
		}
	}
	disabledBody := providerRequestBody(t, "e2e-reg-"+suffix, issuer)
	disabledBody.Enabled = false
	updateDisabled := do(t, admin, http.MethodPut, primary+"/auth/v1/providers/"+providerID, marshalJSON(t, disabledBody), headers)
	updateDisabled.Body.Close()
	if updateDisabled.StatusCode != http.StatusOK {
		t.Fatalf("disable status=%d", updateDisabled.StatusCode)
	}
	for _, node := range nodes {
		minimalResp := do(t, newBrowserClient(t), http.MethodGet, node+"/auth/v1/providers/minimal", nil, nil)
		if minimalResp.StatusCode != http.StatusOK {
			t.Fatalf("disabled minimal node=%s status=%d", node, minimalResp.StatusCode)
		}
		var minimal []providerMinimalResponse
		if err := json.NewDecoder(io.LimitReader(minimalResp.Body, 64<<10)).Decode(&minimal); err != nil {
			t.Fatalf("decode disabled minimal node=%s: %v", node, err)
		}
		minimalResp.Body.Close()
		for _, p := range minimal {
			if p.ID == providerID {
				t.Fatalf("disabled provider %s still in minimal node=%s", providerID, node)
			}
		}
	}
	enabledBody := providerRequestBody(t, "e2e-reg-"+suffix, issuer)
	enabledBody.Enabled = true
	updateEnabled := do(t, admin, http.MethodPut, primary+"/auth/v1/providers/"+providerID, marshalJSON(t, enabledBody), headers)
	updateEnabled.Body.Close()
	if updateEnabled.StatusCode != http.StatusOK {
		t.Fatalf("re-enable status=%d", updateEnabled.StatusCode)
	}
	for _, node := range nodes {
		minResp := do(t, newBrowserClient(t), http.MethodGet, node+"/auth/v1/providers/minimal", nil, nil)
		if minResp.StatusCode != http.StatusOK {
			t.Fatalf("reenable minimal node=%s status=%d", node, minResp.StatusCode)
		}
		var minAfter []providerMinimalResponse
		if err := json.NewDecoder(io.LimitReader(minResp.Body, 64<<10)).Decode(&minAfter); err != nil {
			t.Fatalf("decode reenable minimal node=%s: %v", node, err)
		}
		minResp.Body.Close()
		foundReenable := false
		for _, p := range minAfter {
			if p.ID == providerID {
				foundReenable = true
				break
			}
		}
		if !foundReenable {
			t.Fatalf("reenabled provider %s not in minimal node=%s", providerID, node)
		}
	}
	secretClearBody := providerRequestBody(t, "e2e-reg-"+suffix, issuer)
	secretClearBody.ClientSecret = nil
	secretClearBody.UsePKCE = true
	clearResp := do(t, admin, http.MethodPut, primary+"/auth/v1/providers/"+providerID, marshalJSON(t, secretClearBody), headers)
	clearResp.Body.Close()
	if clearResp.StatusCode != http.StatusOK {
		t.Fatalf("secret clear status=%d", clearResp.StatusCode)
	}
	clearList := do(t, admin, http.MethodPost, primary+"/auth/v1/providers", nil, headers)
	if clearList.StatusCode != http.StatusOK {
		t.Fatalf("secret clear list status=%d", clearList.StatusCode)
	}
	var clearAll []providerResponse
	if err := json.NewDecoder(io.LimitReader(clearList.Body, 256<<10)).Decode(&clearAll); err != nil {
		t.Fatalf("decode secret clear list: %v", err)
	}
	clearList.Body.Close()
	clearFound := false
	for _, p := range clearAll {
		if p.ID == providerID {
			clearFound = true
			if p.ClientSecret != nil {
				t.Fatalf("client_secret not nil after clear: %q", *p.ClientSecret)
			}
			break
		}
	}
	if !clearFound {
		t.Fatalf("provider %s not found in list after secret clear", providerID)
	}
	safeResp := do(t, admin, http.MethodGet, primary+"/auth/v1/providers/"+providerID+"/delete_safe", nil, headers)
	if safeResp.StatusCode != http.StatusOK {
		t.Fatalf("delete_safe status=%d", safeResp.StatusCode)
	}
	var linked []any
	if err := json.NewDecoder(io.LimitReader(safeResp.Body, 8<<10)).Decode(&linked); err != nil {
		t.Fatalf("decode delete_safe: %v", err)
	}
	safeResp.Body.Close()
	if len(linked) != 0 {
		t.Fatalf("delete_safe expected empty array, got %d entries", len(linked))
	}
	uploadProviderLogo(t, admin, primary, providerID, "logo.png", "image/png", clientLogoPNG(t), headers)
	for _, node := range nodes {
		logoResp := do(t, newBrowserClient(t), http.MethodGet, node+"/auth/v1/providers/"+providerID+"/img", nil, nil)
		if logoResp.StatusCode != http.StatusOK {
			t.Fatalf("PNG logo node=%s status=%d", node, logoResp.StatusCode)
		}
		ct := logoResp.Header.Get("Content-Type")
		if ct != "image/webp" {
			t.Fatalf("PNG logo node=%s content-type=%q want=image/webp", node, ct)
		}
		body := readClientLogoBody(t, logoResp)
		decoded, err := nativewebp.Decode(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("PNG logo node=%s not decodable WebP: %v", node, err)
		}
		if decoded.Bounds().Dx() != 20 || decoded.Bounds().Dy() != 20 {
			t.Fatalf("PNG logo node=%s dimensions=%dx%d want=20x20", node, decoded.Bounds().Dx(), decoded.Bounds().Dy())
		}
	}
	uploadProviderLogo(t, admin, primary, providerID, "logo.svg", "image/svg+xml", clientLogoSVG(), headers)
	for _, node := range nodes {
		logoResp := do(t, newBrowserClient(t), http.MethodGet, node+"/auth/v1/providers/"+providerID+"/img", nil, nil)
		if logoResp.StatusCode != http.StatusOK {
			t.Fatalf("SVG logo node=%s status=%d", node, logoResp.StatusCode)
		}
		body := readClientLogoBody(t, logoResp)
		lower := strings.ToLower(string(body))
		for _, bad := range []string{"<script", "<foreignobject", "javascript:", "onload=", "onerror="} {
			if strings.Contains(lower, bad) {
				t.Fatalf("SVG logo node=%s retained executable %q", node, bad)
			}
		}
		if !strings.Contains(lower, "<rect") {
			t.Fatalf("SVG logo node=%s lost valid rectangle", node)
		}
	}
	svgSnap := do(t, newBrowserClient(t), http.MethodGet, primary+"/auth/v1/providers/"+providerID+"/img", nil, nil)
	if svgSnap.StatusCode != http.StatusOK {
		t.Fatalf("SVG snapshot status=%d", svgSnap.StatusCode)
	}
	svgSnapBody := readClientLogoBody(t, svgSnap)
	var invalidBuf bytes.Buffer
	invalidWriter := multipart.NewWriter(&invalidBuf)
	invalidH := make(textproto.MIMEHeader)
	invalidH.Set("Content-Disposition", `form-data; name="logo"; filename="bad.exe"`)
	invalidH.Set("Content-Type", "application/octet-stream")
	invalidPart, _ := invalidWriter.CreatePart(invalidH)
	invalidPart.Write([]byte("not-a-logo"))
	invalidWriter.Close()
	invalidHeaders := cloneThemeHeaders(headers)
	invalidHeaders["Content-Type"] = invalidWriter.FormDataContentType()
	invalidResp := do(t, admin, http.MethodPut, primary+"/auth/v1/providers/"+providerID+"/img", &invalidBuf, invalidHeaders)
	invalidResp.Body.Close()
	if invalidResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid upload status=%d (expected 400)", invalidResp.StatusCode)
	}
	for _, node := range nodes {
		logoResp := do(t, newBrowserClient(t), http.MethodGet, node+"/auth/v1/providers/"+providerID+"/img", nil, nil)
		if logoResp.StatusCode != http.StatusOK {
			t.Fatalf("logo after invalid upload node=%s status=%d", node, logoResp.StatusCode)
		}
		body := readClientLogoBody(t, logoResp)
		if !bytes.Equal(body, svgSnapBody) {
			t.Fatalf("logo after invalid upload node=%s bytes differ (got %d, want %d)", node, len(body), len(svgSnapBody))
		}
		logoResp.Body.Close()
	}
	unauth := do(t, newBrowserClient(t), http.MethodPost, primary+"/auth/v1/providers/create",
		marshalJSON(t, providerRequestBody(t, "should-fail-"+uniqueSuffix(), "https://fail.e2e.example.com")), nil)
	unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized && unauth.StatusCode != http.StatusForbidden {
		t.Fatalf("unauth create status=%d", unauth.StatusCode)
	}
	suffix2 := uniqueSuffix()
	issuer2 := "https://" + suffix2 + ".e2e.example.com"
	create2 := do(t, admin, http.MethodPost, primary+"/auth/v1/providers/create",
		marshalJSON(t, providerRequestBody(t, "e2e-reg-"+suffix2, issuer2)), headers)
	if create2.StatusCode != http.StatusOK {
		t.Fatalf("second create status=%d", create2.StatusCode)
	}
	var resp2 providerResponse
	if err := json.NewDecoder(io.LimitReader(create2.Body, 64<<10)).Decode(&resp2); err != nil {
		t.Fatalf("decode second create: %v", err)
	}
	create2.Body.Close()
	if resp2.ID == "" {
		t.Fatal("second provider has empty ID")
	}
	t.Cleanup(func() {
		r := do(t, admin, http.MethodDelete, primary+"/auth/v1/providers/"+resp2.ID, nil, headers)
		if r.StatusCode != http.StatusOK && r.StatusCode != http.StatusNotFound {
			t.Errorf("cleanup delete provider %s status=%d", resp2.ID, r.StatusCode)
		}
		r.Body.Close()
	})
	delete2 := do(t, admin, http.MethodDelete, primary+"/auth/v1/providers/"+resp2.ID, nil, headers)
	delete2.Body.Close()
	if delete2.StatusCode != http.StatusOK {
		t.Fatalf("delete second provider status=%d", delete2.StatusCode)
	}
	check := do(t, admin, http.MethodGet, primary+"/auth/v1/providers/"+providerID+"/delete_safe", nil, headers)
	check.Body.Close()
	if check.StatusCode != http.StatusOK {
		t.Fatalf("first provider gone after deleting second: status=%d", check.StatusCode)
	}
	// Explicit delete of main provider; verify logo 404 and list/minimal absent across nodes.
	deleteMain := do(t, admin, http.MethodDelete, primary+"/auth/v1/providers/"+providerID, nil, headers)
	deleteMain.Body.Close()
	if deleteMain.StatusCode != http.StatusOK {
		t.Fatalf("delete main provider status=%d", deleteMain.StatusCode)
	}
	postDeleteList := do(t, admin, http.MethodPost, primary+"/auth/v1/providers", nil, headers)
	if postDeleteList.StatusCode != http.StatusOK {
		t.Fatalf("post delete list status=%d", postDeleteList.StatusCode)
	}
	var postDeleteAll []providerResponse
	if err := json.NewDecoder(io.LimitReader(postDeleteList.Body, 256<<10)).Decode(&postDeleteAll); err != nil {
		t.Fatalf("decode post delete list: %v", err)
	}
	postDeleteList.Body.Close()
	for _, p := range postDeleteAll {
		if p.ID == providerID {
			t.Fatalf("deleted provider %s still in admin list", providerID)
		}
	}
	for _, node := range nodes {
		logoAfter := do(t, newBrowserClient(t), http.MethodGet, node+"/auth/v1/providers/"+providerID+"/img", nil, nil)
		logoAfter.Body.Close()
		if logoAfter.StatusCode != http.StatusNotFound {
			t.Fatalf("logo after delete node=%s status=%d want=404", node, logoAfter.StatusCode)
		}
		minimalAfter := do(t, newBrowserClient(t), http.MethodGet, node+"/auth/v1/providers/minimal", nil, nil)
		if minimalAfter.StatusCode != http.StatusOK {
			t.Fatalf("minimal after delete node=%s status=%d", node, minimalAfter.StatusCode)
		}
		var minimalAfterList []providerMinimalResponse
		if err := json.NewDecoder(io.LimitReader(minimalAfter.Body, 64<<10)).Decode(&minimalAfterList); err != nil {
			t.Fatalf("decode minimal after delete node=%s: %v", node, err)
		}
		minimalAfter.Body.Close()
		for _, p := range minimalAfterList {
			if p.ID == providerID {
				t.Fatalf("deleted provider %s still in minimal node=%s", providerID, node)
			}
		}
	}
}

type providerRequest struct {
	Name                  string  `json:"name"`
	Typ                   string  `json:"typ"`
	Enabled               bool    `json:"enabled"`
	Issuer                string  `json:"issuer"`
	AuthorizationEndpoint string  `json:"authorization_endpoint"`
	TokenEndpoint         string  `json:"token_endpoint"`
	UserinfoEndpoint      string  `json:"userinfo_endpoint"`
	ClientID              string  `json:"client_id"`
	ClientSecret          *string `json:"client_secret"`
	Scope                 string  `json:"scope"`
	UsePKCE               bool    `json:"use_pkce"`
	ClientSecretBasic     bool    `json:"client_secret_basic"`
	ClientSecretPost      bool    `json:"client_secret_post"`
	AutoOnboarding        bool    `json:"auto_onboarding"`
	AutoLink              bool    `json:"auto_link"`
}

type providerResponse struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Enabled      bool    `json:"enabled"`
	ClientID     string  `json:"client_id"`
	ClientSecret *string `json:"client_secret,omitempty"`
}

type providerMinimalResponse struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Updated int64  `json:"updated"`
}

func providerRequestBody(t *testing.T, name, issuer string) providerRequest {
	t.Helper()
	secret := "test-client-secret-value"
	return providerRequest{
		Name:                  name,
		Typ:                   "oidc",
		Enabled:               true,
		Issuer:                issuer,
		AuthorizationEndpoint: issuer + "/authorize",
		TokenEndpoint:         issuer + "/token",
		UserinfoEndpoint:      issuer + "/userinfo",
		ClientID:              "e2e-client-" + name,
		ClientSecret:          &secret,
		Scope:                 "openid profile",
		UsePKCE:               false,
		ClientSecretBasic:     true,
		ClientSecretPost:      false,
	}
}

func marshalJSON(t *testing.T, v any) io.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(b)
}

func uploadProviderLogo(t *testing.T, client *http.Client, base, providerID, filename, contentType string, data []byte, headers map[string]string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", `form-data; name="logo"; filename="`+filename+`"`)
	header.Set("Content-Type", contentType)
	part, err := writer.CreatePart(header)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	reqHeaders := cloneThemeHeaders(headers)
	reqHeaders["Content-Type"] = writer.FormDataContentType()
	resp := do(t, client, http.MethodPut, base+"/auth/v1/providers/"+providerID+"/img", &body, reqHeaders)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload provider logo filename=%s status=%d", filename, resp.StatusCode)
	}
}
