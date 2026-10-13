package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/ui"
)

// Opt-in visual smoke of the real page and scripts; no database or product auth changes.
func TestElyBrandingBrowser(t *testing.T) {
	if os.Getenv("GOAUTHY_UI_BROWSER_TESTS") != "1" {
		t.Skip("set GOAUTHY_UI_BROWSER_TESTS=1 and GOAUTHY_UI_ARTIFACT_DIR to capture admin branding")
	}
	artifacts := os.Getenv("GOAUTHY_UI_ARTIFACT_DIR")
	if !filepath.IsAbs(artifacts) {
		t.Fatal("GOAUTHY_UI_ARTIFACT_DIR must be an absolute artifact directory")
	}
	if err := os.MkdirAll(artifacts, 0700); err != nil {
		t.Fatal(err)
	}
	console, err := NewUI(func(_ http.ResponseWriter, _ *http.Request, mutation bool) bool { return !mutation })
	if err != nil {
		t.Fatal(err)
	}
	console.SetIssuer("https://fixture.test/tenant")
	console.SetCSRFTokenProvider(func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"visual-fixture-only"}`))
		return true
	})
	theme := branding.DefaultTheme("goauthy")
	theme.BrandName = "GoAuthy"
	mux := http.NewServeMux()
	if err := ui.BindAssets(mux); err != nil {
		t.Fatal(err)
	}
	mux.Handle("GET /auth/v1/branding/{name}", branding.BrandAssetHandler())
	mux.Handle("GET /auth/v1/theme/global.css", branding.GlobalCSSHandler())
	mux.Handle("GET /auth/v1/admin/", console)
	// This existing POST endpoint reads theme data; fixture mutations are rejected.
	mux.HandleFunc("POST /auth/v1/theme/goauthy", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(theme)
	})
	mux.Handle("GET /auth/v1/clients/goauthy/logo", branding.DefaultFaviconHandler())
	mux.Handle("GET /favicon.ico", branding.DefaultFaviconHandler())
	root := http.NewServeMux()
	root.Handle("/tenant/", http.StripPrefix("/tenant", mux))
	root.Handle("GET /favicon.ico", branding.DefaultFaviconHandler())
	server := httptest.NewServer(root)
	defer server.Close()
	chrome := os.Getenv("GOAUTHY_CHROME_PATH")
	if chrome == "" {
		chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	options := append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chrome))
	alloc, stop := chromedp.NewExecAllocator(context.Background(), options...)
	defer stop()
	ctx, closeBrowser := chromedp.NewContext(alloc)
	defer closeBrowser()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var mu sync.Mutex
	var failures []string
	seen := map[string]bool{}
	chromedp.ListenTarget(ctx, func(event any) {
		if response, ok := event.(*network.EventResponseReceived); ok && strings.HasPrefix(response.Response.URL, server.URL) {
			mu.Lock()
			defer mu.Unlock()
			seen[response.Response.URL] = true
			if response.Response.Status >= 400 {
				failures = append(failures, fmt.Sprintf("%d %s", response.Response.Status, response.Response.URL))
			}
		}
	})
	for _, width := range []int64{1440, 375} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			var screenshot []byte
			var state struct {
				Complete, Controls, Preview, Overflow bool
				Language, Heading                     string
			}
			err := chromedp.Run(ctx,
				network.Enable(),
				network.SetExtraHTTPHeaders(network.Headers{"Accept-Language": "ko"}),
				chromedp.EmulateViewport(width, 1000),
				chromedp.Navigate(server.URL+"/tenant/auth/v1/admin/branding"),
				chromedp.WaitVisible("[data-theme-copy=title]"),
				chromedp.Poll(`document.querySelector('#theme-preview-frame')?.contentDocument?.querySelector('#theme-sample-button') && document.querySelector('#theme-logo-image')?.complete && document.fonts.status === 'loaded'`, nil),
				chromedp.Evaluate(`(()=>{const visible=s=>{const e=document.querySelector(s),r=e?.getBoundingClientRect();return !!r&&r.width>0&&r.height>0&&getComputedStyle(e).visibility!=='hidden'};const frame=document.querySelector('#theme-preview-frame');return {Complete:document.readyState==='complete'&&!!document.querySelector('script[src$="/admin/app.js"]')&&!!document.querySelector('#theme-logo-status'),Controls:['#theme-save','#theme-reload','#theme-reset','[data-theme-copy=title]','[data-language-select]'].every(visible),Preview:!!frame.contentDocument.querySelector('#theme-sample-button'),Overflow:document.documentElement.scrollWidth>innerWidth+1,Language:document.documentElement.lang,Heading:document.querySelector('#app h1')?.textContent}})()`, &state),
				chromedp.FullScreenshot(&screenshot, 90),
			)
			if err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(artifacts, fmt.Sprintf("admin-branding-ko-%d.png", width))
			if err := os.WriteFile(name, screenshot, 0600); err != nil {
				t.Fatal(err)
			}
			t.Logf("screenshot: %s; state: %+v", name, state)
			if !state.Complete || !state.Controls || !state.Preview || state.Overflow || state.Language != "ko" || state.Heading == "Common brand" {
				t.Fatalf("invalid branding screen: %+v", state)
			}
			if width == 375 {
				var expanded bool
				if err := chromedp.Run(ctx, chromedp.Click("#admin-menu-toggle"), chromedp.Evaluate(`document.querySelector('#admin-menu-toggle').getAttribute('aria-expanded')==='true'&&document.querySelector('#admin-navigation').getBoundingClientRect().width>0&&document.documentElement.scrollWidth<=innerWidth+1`, &expanded)); err != nil || !expanded {
					t.Fatalf("mobile menu unavailable or overflowing: expanded=%v err=%v", expanded, err)
				}
			}
		})
	}
	mu.Lock()
	defer mu.Unlock()
	for _, suffix := range []string{"/auth/v1/ui/app.css", "/auth/v1/ui/brand.css", "/auth/v1/admin/admin.css", "/auth/v1/admin/app.js", "/auth/v1/branding/locale.js"} {
		if !seen[server.URL+"/tenant"+suffix] {
			t.Errorf("asset not requested: %s", suffix)
		}
	}
	if len(failures) != 0 {
		t.Fatalf("failed fixture responses: %v", failures)
	}
}
