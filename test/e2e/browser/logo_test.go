package browser

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"strings"
	"testing"

	nativewebp "github.com/HugoSmits86/nativewebp"
)

const clientLogoCacheControl = "max-age=31104000, stale-while-revalidate=2592000, public"

// TestClientLogoLive exercises the pinned /clients/{id}/logo contract against
// the live primary and replacement nodes. It is opt-in because it mutates a
// deployed database and needs the endpoint mounted by the runner.
func TestClientLogoLive(t *testing.T) {
	if os.Getenv("GOAUTHY_E2E_LOGO") != "1" {
		t.Skip("set GOAUTHY_E2E_LOGO=1 to run client-logo E2E")
	}
	primary, secondary, username, password, _ := browserE2EConfig(t)
	nodes := []string{primary, secondary}
	if tertiary := strings.TrimRight(os.Getenv("GOAUTHY_E2E_TERTIARY_URL"), "/"); tertiary != "" {
		nodes = append(nodes, tertiary)
	}

	admin, csrf := rbacAuthenticatedClient(t, primary, secondary, username, password)
	headers := rbacMutationHeaders(csrf)
	managed := createThemeUIClient(t, admin, primary, headers)
	t.Cleanup(func() { deleteThemeUIClient(t, admin, primary, headers, managed) })

	global := make(map[string]clientLogoHTTPResponse, len(nodes))
	for _, node := range nodes {
		global[node] = readClientLogo(t, newBrowserClient(t), node, "rauthy", "")
		if global[node].Status != http.StatusOK && global[node].Status != http.StatusNotFound {
			t.Fatalf("global logo node=%s status=%d", node, global[node].Status)
		}
	}

	// A new client has no custom logo, so its public response must be the
	// global logo when one is installed, or the same missing result otherwise.
	for _, node := range nodes {
		assertClientLogoResponseEqual(t, readClientLogo(t, newBrowserClient(t), node, managed.ID, ""), global[node], node+" initial fallback")
	}

	put := uploadClientLogo(t, admin, primary, managed.ID, "logo.png", "image/png", clientLogoPNG(t), headers)
	putBody := readClientLogoBody(t, put)
	if put.StatusCode != http.StatusOK {
		t.Fatalf("PNG logo PUT status=%d body=%q", put.StatusCode, putBody)
	}

	for _, node := range nodes {
		got := readClientLogo(t, newBrowserClient(t), node, managed.ID, "updated=1")
		assertClientLogoHeaders(t, got, http.StatusOK, "image/webp", node+" PNG")
		decoded, err := nativewebp.Decode(bytes.NewReader(got.Body))
		if err != nil {
			t.Fatalf("PNG logo node=%s is not decodable WebP: %v", node, err)
		}
		if decoded.Bounds().Dx() != 84 || decoded.Bounds().Dy() != 84 {
			t.Fatalf("PNG logo node=%s dimensions=%dx%d want=84x84", node, decoded.Bounds().Dx(), decoded.Bounds().Dy())
		}
	}

	// The upload is deliberately hostile but still contains a valid rectangle;
	// the response must retain the graphic while removing executable content.
	put = uploadClientLogo(t, admin, primary, managed.ID, "logo.svg", "image/svg+xml", clientLogoSVG(), headers)
	putBody = readClientLogoBody(t, put)
	if put.StatusCode != http.StatusOK {
		t.Fatalf("SVG logo PUT status=%d body=%q", put.StatusCode, putBody)
	}
	for _, node := range nodes {
		got := readClientLogo(t, newBrowserClient(t), node, managed.ID, "updated=1")
		assertClientLogoHeaders(t, got, http.StatusOK, "image/svg+xml", node+" SVG")
		lower := strings.ToLower(string(got.Body))
		for _, executable := range []string{"<script", "<foreignobject", "javascript:", "onload=", "onerror="} {
			if strings.Contains(lower, executable) {
				t.Fatalf("SVG logo node=%s retained executable marker %q: %q", node, executable, got.Body)
			}
		}
		if !strings.Contains(lower, "<rect") {
			t.Fatalf("SVG logo node=%s lost the valid rectangle: %q", node, got.Body)
		}
	}

	unauthorized := uploadClientLogo(t, newBrowserClient(t), primary, managed.ID, "unauthorized.png", "image/png", clientLogoPNG(t), nil)
	unauthorizedBody := readClientLogoBody(t, unauthorized)
	if unauthorized.StatusCode != http.StatusUnauthorized && unauthorized.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthorized logo PUT status=%d body=%q", unauthorized.StatusCode, unauthorizedBody)
	}

	deleted := do(t, admin, http.MethodDelete, clientLogoURL(primary, managed.ID, ""), nil, headers)
	deletedBody := readClientLogoBody(t, deleted)
	if deleted.StatusCode != http.StatusOK {
		t.Fatalf("logo DELETE status=%d body=%q", deleted.StatusCode, deletedBody)
	}
	for _, node := range nodes {
		assertClientLogoResponseEqual(t, readClientLogo(t, newBrowserClient(t), node, managed.ID, ""), global[node], node+" post-delete fallback")
		assertClientLogoResponseEqual(t, readClientLogo(t, newBrowserClient(t), node, "rauthy", ""), global[node], node+" global logo changed")
	}
}

type clientLogoHTTPResponse struct {
	Status      int
	ContentType string
	Cache       string
	CSP         string
	Body        []byte
}

func clientLogoURL(base, clientID, query string) string {
	endpoint := base + "/auth/v1/clients/" + url.PathEscape(clientID) + "/logo"
	if query != "" {
		endpoint += "?" + query
	}
	return endpoint
}

func readClientLogo(t *testing.T, client *http.Client, base, clientID, query string) clientLogoHTTPResponse {
	t.Helper()
	response := do(t, client, http.MethodGet, clientLogoURL(base, clientID, query), nil, nil)
	return clientLogoHTTPResponse{
		Status:      response.StatusCode,
		ContentType: response.Header.Get("Content-Type"),
		Cache:       response.Header.Get("Cache-Control"),
		CSP:         response.Header.Get("Content-Security-Policy"),
		Body:        readClientLogoBody(t, response),
	}
}

func readClientLogoBody(t *testing.T, response *http.Response) []byte {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, (16<<20)+1))
	if err != nil {
		t.Fatalf("read client logo response: %v", err)
	}
	if len(body) > 16<<20 {
		t.Fatalf("client logo response exceeds 16 MiB")
	}
	return body
}

func assertClientLogoResponseEqual(t *testing.T, got, want clientLogoHTTPResponse, label string) {
	t.Helper()
	if got.Status != want.Status || got.ContentType != want.ContentType || !bytes.Equal(got.Body, want.Body) {
		t.Fatalf("%s status/content/body differ: got=(%d,%q,%d) want=(%d,%q,%d)", label, got.Status, got.ContentType, len(got.Body), want.Status, want.ContentType, len(want.Body))
	}
}

func assertClientLogoHeaders(t *testing.T, got clientLogoHTTPResponse, wantStatus int, wantContentType, label string) {
	t.Helper()
	if got.Status != wantStatus || got.ContentType != wantContentType {
		t.Fatalf("%s status=%d content-type=%q", label, got.Status, got.ContentType)
	}
	if got.Cache != clientLogoCacheControl {
		t.Fatalf("%s Cache-Control=%q", label, got.Cache)
	}
	if got.CSP != "connect-src 'none'; script-src 'none'; frame-ancestors 'none'; object-src 'none';" {
		t.Fatalf("%s Content-Security-Policy=%q", label, got.CSP)
	}
}

func uploadClientLogo(t *testing.T, client *http.Client, base, clientID, filename, contentType string, data []byte, headers map[string]string) *http.Response {
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
	requestHeaders := cloneThemeHeaders(headers)
	requestHeaders["Content-Type"] = writer.FormDataContentType()
	return do(t, client, http.MethodPut, clientLogoURL(base, clientID, ""), &body, requestHeaders)
}

func clientLogoPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 180, 100))
	for y := 0; y < img.Bounds().Dy(); y++ {
		for x := 0; x < img.Bounds().Dx(); x++ {
			var pixel color.RGBA
			switch {
			case x < 60:
				pixel = color.RGBA{R: 232, G: 66, B: 66, A: 255}
			case x < 120:
				pixel = color.RGBA{R: 66, G: 196, B: 96, A: 255}
			default:
				pixel = color.RGBA{R: 66, G: 96, B: 232, A: 255}
			}
			img.SetRGBA(x, y, pixel)
		}
	}
	var body bytes.Buffer
	if err := png.Encode(&body, img); err != nil {
		t.Fatal(err)
	}
	return body.Bytes()
}

func clientLogoSVG() []byte {
	return []byte(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10" onload="alert(1)"><script>alert(1)</script><foreignObject><iframe src="https://evil.example"></iframe></foreignObject><a href="javascript:alert(1)" onerror="alert(1)"><rect width="10" height="10" fill="#2a6"/></a></svg>`)
}
