package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/ui"
)

func TestAdminAllScreensResizeAndTheme(t *testing.T) {
	if os.Getenv("GOAUTHY_UI_BROWSER_TESTS") != "1" {
		t.Skip("set GOAUTHY_UI_BROWSER_TESTS=1")
	}
	console, err := NewUI(func(_ http.ResponseWriter, _ *http.Request, mutation bool) bool { return !mutation })
	if err != nil {
		t.Fatal(err)
	}
	console.SetCSRFTokenProvider(func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"sweep-csrf"}`))
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
	mux.HandleFunc("GET /auth/v1/users", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":"sub-1","email":"admin@example.com","last_login":1700000000}],"count":1}`))
	})
	mux.HandleFunc("GET /auth/v1/clients", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"client-1","name":"App One","confidential":true,"enabled":true}]`))
	})
	mux.HandleFunc("GET /auth/v1/roles", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"role-1","name":"goauthy_admin"}]`))
	})
	mux.HandleFunc("GET /auth/v1/groups", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"grp-1","name":"staff"}]`))
	})
	mux.HandleFunc("GET /auth/v1/api_keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[{"name":"ci-key"}]}`))
	})
	mux.HandleFunc("GET /auth/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sessions":[{"id":"sess-1","user_id":"sub-1","state":"auth","exp":1900000000}]}`))
	})
	mux.HandleFunc("GET /auth/v1/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"events":[{"id":"ev-1","timestamp":1700000000,"level":"info","typ":"Login","text":"ok"}]}`))
	})
	mux.HandleFunc("POST /auth/v1/branding/theme", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(theme)
	})
	mux.Handle("GET /auth/v1/branding/logo", branding.DefaultFaviconHandler())
	mux.Handle("GET /favicon.ico", branding.DefaultFaviconHandler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	chrome := os.Getenv("GOAUTHY_CHROME_PATH")
	if chrome == "" {
		chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
	}
	alloc, stop := chromedp.NewExecAllocator(context.Background(), append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chrome))...)
	defer stop()
	ctx, closeBrowser := chromedp.NewContext(alloc)
	defer closeBrowser()
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	var jsErrors []string
	chromedp.ListenTarget(ctx, func(ev any) {
		if ex, ok := ev.(*runtime.EventExceptionThrown); ok {
			jsErrors = append(jsErrors, ex.ExceptionDetails.Text)
		}
	})

	routes := []string{
		"/auth/v1/admin/dashboard",
		"/auth/v1/admin/users",
		"/auth/v1/admin/clients",
		"/auth/v1/admin/branding",
		"/auth/v1/admin/sessions",
		"/auth/v1/admin/events",
		"/auth/v1/admin/providers",
		"/auth/v1/admin/api-keys",
		"/auth/v1/admin/roles",
		"/auth/v1/admin/templates",
	}
	viewports := []struct{ w, h int64 }{{1440, 900}, {1000, 900}, {768, 1024}, {540, 800}, {375, 812}, {1440, 900}}

	for _, mode := range []string{"light", "dark"} {
		for _, route := range routes {
			t.Run(fmt.Sprintf("%s%s", mode, route), func(t *testing.T) {
				if err := chromedp.Run(ctx,
					emulation.SetEmulatedMedia().WithFeatures([]*emulation.MediaFeature{{Name: "prefers-color-scheme", Value: mode}}),
					chromedp.EmulateViewport(1440, 900),
					chromedp.Navigate(server.URL+route),
					chromedp.WaitVisible("#app h1"),
				); err != nil {
					t.Fatal(err)
				}
				for _, vp := range viewports {
					var res struct {
						Overflow    bool   `json:"overflow"`
						BadSelects  int    `json:"badSelects"`
						SymbolColor string `json:"symbolColor"`
						NavVisible  bool   `json:"navVisible"`
					}
					err := chromedp.Run(ctx,
						chromedp.EmulateViewport(vp.w, vp.h),
						chromedp.Evaluate(`(() => {
							const overflow = document.documentElement.scrollWidth > window.innerWidth + 1;
							const selects = [...document.querySelectorAll('select')];
							const badSelects = selects.filter(s => {
								const st = getComputedStyle(s);
								return st.appearance !== 'none' || st.backgroundImage === 'none';
							}).length;
							const sym = document.querySelector('.brand-symbol');
							const symbolColor = sym ? getComputedStyle(sym).color : '';
							const nav = document.querySelector('#admin-navigation');
							const navVisible = !!nav && getComputedStyle(nav).display !== 'none';
							return {overflow, badSelects, symbolColor, navVisible};
						})()`, &res),
					)
					if err != nil {
						t.Fatal(err)
					}
					if res.Overflow {
						t.Fatalf("%s %s at %dx%d has horizontal overflow", mode, route, vp.w, vp.h)
					}
					if res.BadSelects > 0 {
						t.Fatalf("%s %s at %dx%d has %d select(s) with native arrow or missing chevron", mode, route, vp.w, vp.h, res.BadSelects)
					}
					if mode == "dark" && res.SymbolColor == "rgb(23, 63, 53)" {
						t.Fatalf("%s %s at %dx%d .brand-symbol stuck at light #173f35", mode, route, vp.w, vp.h)
					}
					if vp.w > 540 && !res.NavVisible {
						t.Fatalf("%s %s at %dx%d #admin-navigation should be visible", mode, route, vp.w, vp.h)
					}
					if vp.w == 375 {
						var toggled bool
						if err := chromedp.Run(ctx,
							chromedp.Click("#admin-menu-toggle"),
							chromedp.Evaluate(`document.querySelector('#admin-menu-toggle').getAttribute('aria-expanded') === 'true' && getComputedStyle(document.querySelector('#admin-navigation')).display !== 'none' && document.documentElement.scrollWidth <= window.innerWidth + 1`, &toggled),
							chromedp.Click("#admin-menu-toggle"),
						); err != nil || !toggled {
							t.Fatalf("%s %s mobile toggle failed: toggled=%v err=%v", mode, route, toggled, err)
						}
					}
				}
			})
		}
	}
	if len(jsErrors) > 0 {
		t.Fatalf("unexpected JS errors: %v", jsErrors)
	}
}
