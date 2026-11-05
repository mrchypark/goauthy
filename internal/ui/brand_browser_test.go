package ui

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/chromedp"
)

// This focused browser check needs Chrome, but no running GoAuthy or database.
func TestBrandColorsUnderStrictCSP(t *testing.T) {
	if os.Getenv("GOAUTHY_UI_BROWSER_TESTS") != "1" {
		t.Skip("set GOAUTHY_UI_BROWSER_TESTS=1 to check computed Ely brand colors in Chrome")
	}
	tpl := template.Must(NewTemplates("page"))
	tpl = template.Must(tpl.Parse(`<!doctype html><html><head>{{template "goauthy-head" .}}<link rel="stylesheet" href="/tenant/theme.css"></head><body>{{template "button" (dict "ID" "save" "Label" "Save" "Type" "submit")}}{{template "button" (dict "ID" "remove" "Label" "Remove" "Variant" "destructive")}}</body></html>`))
	mux := http.NewServeMux()
	assets := http.NewServeMux()
	if err := BindAssets(assets); err != nil {
		t.Fatal(err)
	}
	mux.Handle("GET /tenant/auth/v1/ui/", http.StripPrefix("/tenant", assets))
	mux.HandleFunc("GET /tenant/theme.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte(`body{--action:120 100 25;--bg:240 100 25;--error:0 100 50;--btn-text:yellow;--border-radius:3px}@media(prefers-color-scheme:dark){body{--action:240 100 50;--bg:0 0 0;--error:300 100 50;--btn-text:white}}`))
	})
	mux.HandleFunc("GET /tenant/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; font-src 'self'; script-src 'none'; base-uri 'none'")
		if err := tpl.Execute(w, "/tenant"); err != nil {
			t.Error(err)
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 30*time.Second)
	defer timeout()
	for _, tc := range []struct{ mode, primary, foreground, danger, background string }{
		{"light", "rgb(0, 128, 0)", "rgb(255, 255, 0)", "rgb(255, 0, 0)", "rgb(0, 0, 128)"},
		{"dark", "rgb(0, 0, 255)", "rgb(255, 255, 255)", "rgb(255, 0, 255)", "rgb(0, 0, 0)"},
	} {
		var colors []string
		err := chromedp.Run(ctx,
			emulation.SetEmulatedMedia().WithFeatures([]*emulation.MediaFeature{{Name: "prefers-color-scheme", Value: tc.mode}}),
			chromedp.Navigate(server.URL+"/tenant/"),
			chromedp.WaitVisible("#save"),
			chromedp.Evaluate(`(()=>{const save=getComputedStyle(document.querySelector('#save')), remove=getComputedStyle(document.querySelector('#remove'));return [save.backgroundColor,save.color,remove.color,remove.borderTopColor,getComputedStyle(document.body).backgroundColor,save.borderTopLeftRadius]})()`, &colors),
		)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{tc.primary, tc.foreground, tc.danger, tc.danger, tc.background, "3px"}
		for i := range want {
			if len(colors) != len(want) || colors[i] != want[i] {
				t.Fatalf("%s colors %v, want %v", tc.mode, colors, want)
			}
		}
	}
}
