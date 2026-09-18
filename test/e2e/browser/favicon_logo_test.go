package browser

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"testing"

	nativewebp "github.com/HugoSmits86/nativewebp"
)

func TestClientFaviconLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_LOGO") != "1" {
		t.Skip("set GOAUTHY_E2E_LOGO=1 to run client-favicon E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := []string{primary, secondary, logoutTertiaryURL(t)}

	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	managed := createThemeUIClient(t, admin, primary, headers)
	t.Cleanup(func() { deleteThemeUIClient(t, admin, primary, headers, managed) })

	for _, node := range nodes {
		missing := readClientFavicon(t, newBrowserClient(t), node, managed.ID, "")
		if missing.Status != http.StatusNotFound {
			t.Fatalf("missing favicon node=%s status=%d content-type=%q", node, missing.Status, missing.ContentType)
		}
	}

	regularPut := uploadClientLogo(t, admin, primary, managed.ID, "logo.png", "image/png", clientLogoPNG(t), headers)
	regularPutBody := readClientLogoBody(t, regularPut)
	if regularPut.StatusCode != http.StatusOK || len(regularPutBody) != 0 {
		t.Fatalf("regular logo PUT status=%d body=%q", regularPut.StatusCode, regularPutBody)
	}
	regular := readClientLogo(t, newBrowserClient(t), primary, managed.ID, "updated=1")
	if regular.Status != http.StatusOK || regular.ContentType != "image/webp" || len(regular.Body) == 0 {
		t.Fatalf("regular logo status=%d content-type=%q bytes=%d", regular.Status, regular.ContentType, len(regular.Body))
	}
	assertRegularLogoEverywhere(t, nodes, managed.ID, regular)

	putClientFavicon(t, admin, primary, managed.ID, "favicon.png", "image/png", clientLogoPNG(t), headers)
	assertFaviconEverywhere(t, nodes, managed.ID, "image/webp", func(body []byte) {
		t.Helper()
		decoded, err := nativewebp.Decode(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("PNG favicon is not WebP: %v", err)
		}
		if decoded.Bounds().Dx() != 32 || decoded.Bounds().Dy() != 32 {
			t.Fatalf("PNG favicon dimensions=%dx%d want=32x32", decoded.Bounds().Dx(), decoded.Bounds().Dy())
		}
	})
	assertRegularLogoEverywhere(t, nodes, managed.ID, regular)

	putClientFavicon(t, admin, primary, managed.ID, "favicon.jpg", "image/jpeg", clientFaviconJPEG(t), headers)
	assertFaviconEverywhere(t, nodes, managed.ID, "image/webp", func(body []byte) {
		t.Helper()
		decoded, err := nativewebp.Decode(bytes.NewReader(body))
		if err != nil {
			t.Fatalf("JPEG favicon is not WebP: %v", err)
		}
		if decoded.Bounds().Dx() != 32 || decoded.Bounds().Dy() != 32 {
			t.Fatalf("JPEG favicon dimensions=%dx%d want=32x32", decoded.Bounds().Dx(), decoded.Bounds().Dy())
		}
	})
	assertRegularLogoEverywhere(t, nodes, managed.ID, regular)

	putClientFavicon(t, admin, primary, managed.ID, "favicon.svg", "image/svg+xml", clientLogoSVG(), headers)
	assertFaviconEverywhere(t, nodes, managed.ID, "image/svg+xml", func(body []byte) {
		t.Helper()
		lower := strings.ToLower(string(body))
		for _, executable := range []string{"<script", "<foreignobject", "javascript:", "onload=", "onerror="} {
			if strings.Contains(lower, executable) {
				t.Fatalf("sanitized favicon retained executable marker %q: %q", executable, body)
			}
		}
		if !strings.Contains(lower, "<rect") {
			t.Fatalf("sanitized favicon lost valid rectangle: %q", body)
		}
	})
	assertRegularLogoEverywhere(t, nodes, managed.ID, regular)

	cached := readClientFavicon(t, newBrowserClient(t), primary, managed.ID, url.Values{"updated": {"1"}}.Encode())
	if cached.Status != http.StatusOK || cached.Cache != clientLogoCacheControl {
		t.Fatalf("updated favicon status=%d cache-control=%q", cached.Status, cached.Cache)
	}

	deleted := do(t, admin, http.MethodDelete, clientFaviconURL(primary, managed.ID, ""), nil, headers)
	deletedBody := readClientLogoBody(t, deleted)
	if deleted.StatusCode != http.StatusOK || len(deletedBody) != 0 {
		t.Fatalf("favicon DELETE status=%d body=%q", deleted.StatusCode, deletedBody)
	}
	for _, node := range nodes {
		missing := readClientFavicon(t, newBrowserClient(t), node, managed.ID, "")
		if missing.Status != http.StatusNotFound {
			t.Fatalf("deleted favicon node=%s status=%d", node, missing.Status)
		}
	}
	assertRegularLogoEverywhere(t, nodes, managed.ID, regular)
}

type clientFaviconHTTPResponse struct {
	Status      int
	ContentType string
	Cache       string
	CSP         string
	Body        []byte
}

func clientFaviconURL(base, clientID, query string) string {
	endpoint := base + "/auth/v1/clients/" + url.PathEscape(clientID) + "/favicon"
	if query != "" {
		endpoint += "?" + query
	}
	return endpoint
}

func readClientFavicon(t *testing.T, client *http.Client, base, clientID, query string) clientFaviconHTTPResponse {
	t.Helper()
	response := do(t, client, http.MethodGet, clientFaviconURL(base, clientID, query), nil, nil)
	return clientFaviconHTTPResponse{
		Status:      response.StatusCode,
		ContentType: response.Header.Get("Content-Type"),
		Cache:       response.Header.Get("Cache-Control"),
		CSP:         response.Header.Get("Content-Security-Policy"),
		Body:        readClientLogoBody(t, response),
	}
}

func putClientFavicon(t *testing.T, client *http.Client, base, clientID, filename, contentType string, data []byte, headers map[string]string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipartWriter(t, &body, filename, contentType, data)
	requestHeaders := cloneThemeHeaders(headers)
	requestHeaders["Content-Type"] = writer
	response := do(t, client, http.MethodPut, clientFaviconURL(base, clientID, ""), &body, requestHeaders)
	responseBody := readClientLogoBody(t, response)
	if response.StatusCode != http.StatusOK || len(responseBody) != 0 {
		t.Fatalf("favicon PUT filename=%s status=%d body=%q", filename, response.StatusCode, responseBody)
	}
}

func multipartWriter(t *testing.T, body *bytes.Buffer, filename, contentType string, data []byte) string {
	t.Helper()
	writer := multipart.NewWriter(body)
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
	return writer.FormDataContentType()
}

func assertFaviconEverywhere(t *testing.T, nodes []string, clientID, contentType string, assertBody func([]byte)) {
	t.Helper()
	for _, node := range nodes {
		got := readClientFavicon(t, newBrowserClient(t), node, clientID, "")
		if got.Status != http.StatusOK || got.ContentType != contentType || got.Cache != "" || len(got.Body) == 0 {
			t.Fatalf("favicon node=%s status=%d content-type=%q cache-control=%q bytes=%d", node, got.Status, got.ContentType, got.Cache, len(got.Body))
		}
		assertBody(got.Body)
	}
}

func assertRegularLogoEverywhere(t *testing.T, nodes []string, clientID string, want clientLogoHTTPResponse) {
	t.Helper()
	for _, node := range nodes {
		got := readClientLogo(t, newBrowserClient(t), node, clientID, "updated=1")
		assertClientLogoResponseEqual(t, got, want, node+" regular logo mutual preservation")
	}
}

func clientFaviconJPEG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 160, 96))
	for y := 0; y < img.Bounds().Dy(); y++ {
		for x := 0; x < img.Bounds().Dx(); x++ {
			img.SetRGBA(x, y, color.RGBA{R: uint8(x + 40), G: uint8(y + 80), B: 180, A: 255})
		}
	}
	var body bytes.Buffer
	if err := jpeg.Encode(&body, img, &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}
