package ui

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ely "github.com/mrchypark/ely-htmx"
	"golang.org/x/net/html"
)

func TestHeadLocalCSSAndIssuerPaths(t *testing.T) {
	tpl := template.Must(NewTemplates("page"))
	for _, prefix := range []string{"", "/", "/tenant", "/tenant/nested/"} {
		t.Run(prefix, func(t *testing.T) {
			var out bytes.Buffer
			if err := tpl.ExecuteTemplate(&out, "goauthy-head", prefix); err != nil {
				t.Fatal(err)
			}
			z := html.NewTokenizer(&out)
			links := 0
			for z.Next() != html.ErrorToken {
				token := z.Token()
				if token.Type != html.StartTagToken {
					continue
				}
				if token.Data != "link" {
					t.Fatalf("head contains active content: %v", token)
				}
				for _, attr := range token.Attr {
					switch attr.Key {
					case "rel":
						if attr.Val != "stylesheet" {
							t.Fatalf("unexpected link: %v", token)
						}
					case "href":
						if links >= len(stylesheets) {
							t.Fatal("unexpected extra stylesheet")
						}
						want := strings.TrimRight(prefix, "/") + AssetPath + stylesheets[links]
						if attr.Val != want {
							t.Fatalf("href %q, want %q", attr.Val, want)
						}
					default:
						t.Fatalf("unexpected head attribute: %v", attr)
					}
				}
				links++
			}
			if links != len(stylesheets) {
				t.Fatalf("got %d stylesheet links", links)
			}
		})
	}
	for _, prefix := range []string{"https://cdn.example", "//cdn.example", "//", "/../tenant", "/tenant?x", "/tenant#x", "/%2f/", "/tenant\\x", "/tenant\nx"} {
		if err := tpl.ExecuteTemplate(&bytes.Buffer{}, "goauthy-head", prefix); err == nil {
			t.Errorf("accepted unsafe issuer prefix %q", prefix)
		}
	}
}

func TestElyComponentsEscapeUntrustedValues(t *testing.T) {
	tpl := template.Must(NewTemplates("page"))
	tpl = template.Must(tpl.Parse(`{{template "button" .}}`))
	var out bytes.Buffer
	if err := tpl.Execute(&out, map[string]any{"Label": `<img src=x onerror=alert(1)>`, "Href": "javascript:alert(1)"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `data-slot="button"`) || !strings.Contains(out.String(), "&lt;img") || !strings.Contains(out.String(), "#ZgotmplZ") || strings.Contains(out.String(), "<img") {
		t.Fatalf("unsafe component rendering: %s", &out)
	}
	if err := tpl.Execute(&bytes.Buffer{}, map[string]any{"Label": "Save", "Attrs": map[string]string{"onclick": "alert(1)"}}); err == nil {
		t.Fatal("component accepted inline event handler")
	}
}

func TestAssetsEmbeddedContentCachingAndMethods(t *testing.T) {
	mux := http.NewServeMux()
	if err := BindAssets(mux); err != nil {
		t.Fatal(err)
	}
	names := append(append([]string(nil), stylesheets...), "geist.woff2", "geist-mono.woff2", "pretendard.woff2")
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest("GET", AssetPath+name, nil))
			if w.Code != 200 || w.Body.Len() == 0 || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "public, no-cache" || w.Header().Get("ETag") == "" {
				t.Fatalf("asset response: %d %v", w.Code, w.Header())
			}
			want := brandCSS
			if name != "brand.css" {
				var err error
				want, err = ely.Files.ReadFile("assets/" + name)
				if err != nil {
					t.Fatal(err)
				}
			}
			mime := "font/woff2"
			if strings.HasSuffix(name, ".css") {
				want = bytes.ReplaceAll(want, []byte("/assets/"), nil)
				mime = "text/css; charset=utf-8"
			}
			if !bytes.Equal(w.Body.Bytes(), want) || w.Header().Get("Content-Type") != mime {
				t.Fatal("asset differs from embedded source or has incorrect MIME type")
			}
			for _, method := range []string{"HEAD", "GET"} {
				r := httptest.NewRequest(method, AssetPath+name, nil)
				code := 200
				if method == "GET" {
					r.Header.Set("If-None-Match", w.Header().Get("ETag"))
					code = 304
				}
				cached := httptest.NewRecorder()
				mux.ServeHTTP(cached, r)
				if cached.Code != code || cached.Body.Len() != 0 {
					t.Fatalf("%s response %d, body size %d", method, cached.Code, cached.Body.Len())
				}
			}
			post := httptest.NewRecorder()
			mux.ServeHTTP(post, httptest.NewRequest("POST", AssetPath+name, nil))
			if post.Code != 405 {
				t.Fatalf("POST: %d", post.Code)
			}
		})
	}
	for _, name := range []string{"", "missing.css", "ui.go", "templates/shadcn-button.html", "theme.js", "htmx.min.js", "input.css", "%2e%2e%2fgo.mod"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest("GET", AssetPath+name, nil))
		if w.Code != 404 {
			t.Errorf("unexpected asset %q status %d", name, w.Code)
		}
	}
}

func TestEmbeddedFontURLsAreRelative(t *testing.T) {
	mux := http.NewServeMux()
	if err := BindAssets(mux); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", AssetPath+"app.css", nil))
	for _, name := range []string{"geist.woff2", "geist-mono.woff2", "pretendard.woff2"} {
		if !strings.Contains(w.Body.String(), "url("+name+")") {
			t.Errorf("font %s is not issuer-relative", name)
		}
	}
	if strings.Contains(w.Body.String(), "/assets/") {
		t.Fatal("root asset URL remains")
	}
}
