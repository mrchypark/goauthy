package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/testbrowser"
	sharedUI "github.com/mrchypark/goauthy/internal/ui"
)

func TestElysduiDynamicAdminInBrowser(t *testing.T) {
	ui, err := NewUI(func(http.ResponseWriter, *http.Request, bool) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := sharedUI.BindAssets(mux); err != nil {
		t.Fatal(err)
	}
	mux.Handle("/auth/v1/admin/", ui)
	mux.Handle("/auth/v1/branding/{name}", branding.BrandAssetHandler())
	mux.HandleFunc("/auth/v1/admin/csrf", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"test"}`))
	})
	mux.HandleFunc("/auth/v1/users", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"users":[{"id":"u1","email":"user@example.test"}]}`))
	})
	locale := httptest.NewRecorder()
	mux.ServeHTTP(locale, httptest.NewRequest(http.MethodGet, "/auth/v1/branding/locale.js", nil))
	if locale.Code != http.StatusOK || !strings.HasPrefix(locale.Header().Get("Content-Type"), "text/javascript") || !strings.Contains(locale.Body.String(), "GoAuthyI18n") {
		t.Fatalf("shared locale script unavailable: status=%d content-type=%q", locale.Code, locale.Header().Get("Content-Type"))
	}
	server := httptest.NewServer(mux)
	defer server.Close()
	missingLocale := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/v1/branding/locale.js" {
			http.NotFound(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	defer missingLocale.Close()
	ctx := testbrowser.Start(t)
	chromedp.ListenTarget(ctx, func(event any) {
		if e, ok := event.(*runtime.EventExceptionThrown); ok {
			t.Logf("browser exception: %s", e.ExceptionDetails)
		}
	})
	var result, mobile, missingLocaleReproduced bool
	err = chromedp.Run(ctx,
		chromedp.Navigate(missingLocale.URL+"/auth/v1/admin/users"),
		chromedp.Evaluate(`typeof globalThis.GoAuthyI18n === 'undefined' && !!document.querySelector('#app .state') && !document.querySelector('#table')`, &missingLocaleReproduced),
		chromedp.Navigate(server.URL+"/auth/v1/admin/users"),
		chromedp.WaitVisible(`#table table.ui-table`, chromedp.ByQuery),
		chromedp.Navigate(server.URL+"/auth/v1/admin/users/new"),
		chromedp.WaitVisible(`#user input[data-slot=input]`, chromedp.ByQuery),
		chromedp.Evaluate(`new Promise(resolve => {
      const form = document.querySelector('#user');
      const input = document.createElement('input'); input.value = 'preserved'; input.required = true;
      let clicked = 0; const button = document.createElement('button'); button.type = 'button'; button.onclick = () => clicked++;
      const select = document.createElement('select'); const textarea = document.createElement('textarea');
      const table = document.createElement('table'); table.innerHTML = '<thead><tr><th>Name</th></tr></thead><tbody><tr><td>One</td></tr></tbody>';
      const theme = document.createElement('div'); theme.className = 'theme-mode'; theme.innerHTML = '<button type="button" aria-pressed="true">Light</button>';
      form.append(input, button, select, textarea, table, theme);
      requestAnimationFrame(() => { button.click(); resolve(input.isConnected && input.value === 'preserved' && input.required && clicked === 1 && input.dataset.slot === 'input' && button.dataset.slot === 'button' && select.dataset.slot === 'select' && textarea.dataset.slot === 'textarea' && table.classList.contains('ui-table') && table.parentElement.classList.contains('ui-table-wrap') && table.parentElement.tabIndex === 0 && !theme.firstElementChild.dataset.slot && getComputedStyle(table.querySelector('td')).paddingTop === '8px'); });
    })`, &result, chromedp.EvalAsValue, func(p *runtime.EvaluateParams) *runtime.EvaluateParams { return p.WithAwaitPromise(true) }),
		chromedp.EmulateViewport(390, 844),
		chromedp.Evaluate(`getComputedStyle(document.querySelector('#user')).gridTemplateColumns.split(' ').length === 1 && document.documentElement.scrollWidth <= innerWidth`, &mobile),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !missingLocaleReproduced {
		t.Fatal("missing locale fixture did not reproduce the stalled administration page")
	}
	if !result {
		t.Fatal("dynamic components lost their elysdui contract or native behavior")
	}
	if !mobile {
		t.Fatal("mobile form layout overflowed or did not use one column")
	}
}

// Exercise the actual stylesheet cascade: theme --accent is HSL channels,
// whereas --color-accent is a resolved color usable by background and outline.
func TestAdminAccentComputedStylesInBrowser(t *testing.T) {
	mux := http.NewServeMux()
	customTheme := branding.DefaultTheme(branding.GlobalBrandID)
	customTheme.Dark.Action = []uint16{210, 80, 20}
	customTheme.Dark.BtnText = "#ffffff"
	if err := sharedUI.BindAssets(mux); err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc("GET /admin.css", func(w http.ResponseWriter, _ *http.Request) {
		css, err := uiFS.ReadFile("admin.css")
		if err != nil {
			t.Error(err)
			http.Error(w, "stylesheet unavailable", 500)
			return
		}
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write(css)
	})
	mux.HandleFunc("GET /theme.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		theme := branding.DefaultTheme(branding.GlobalBrandID)
		if r.URL.Query().Get("custom") == "1" {
			theme = customTheme
		}
		_, _ = w.Write([]byte(theme.CSS()))
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		themeURL := "/theme.css"
		if r.URL.Query().Get("custom") == "1" {
			themeURL += "?custom=1"
		}
		_, _ = w.Write([]byte(`<!doctype html><html><head>
<link rel="stylesheet" href="/auth/v1/ui/app.css"><link rel="stylesheet" href="/auth/v1/ui/brand.css">
<link rel="stylesheet" href="/admin.css"><link rel="stylesheet" href="` + themeURL + `"></head><body class="common-brand">
<div id="app"><button data-slot="button" data-variant="primary">Save</button>
<input data-slot="input"><select data-slot="select"><option>One</option></select><textarea data-slot="textarea"></textarea></div>
<div id="resolved" style="background-color:var(--color-accent)"></div></body></html>`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx := testbrowser.Start(t)
	if err := chromedp.Run(ctx, chromedp.Navigate(server.URL), chromedp.KeyEvent("\t")); err != nil {
		t.Fatal(err)
	}
	for _, scheme := range []string{"light", "dark"} {
		t.Run(scheme, func(t *testing.T) {
			var observed struct {
				Raw, Expected, Background, Ink, Paper, PrimaryText string
				TextContrast, PrimaryContrast, FocusContrast       float64
				Focus                                              []struct {
					Slot, Color, Style, Width string
					Visible                   bool
				}
			}
			if err := chromedp.Run(ctx,
				chromedp.ActionFunc(func(ctx context.Context) error {
					return emulation.SetEmulatedMedia().WithFeatures([]*emulation.MediaFeature{{Name: "prefers-color-scheme", Value: scheme}}).Do(ctx)
				}),
				chromedp.Evaluate(`new Promise(resolve => requestAnimationFrame(() => {
const rgb = value => value.match(/[\d.]+/g).slice(0, 3).map(Number);
const luminance = value => rgb(value).map(component => { component /= 255; return component <= .04045 ? component / 12.92 : ((component + .055) / 1.055) ** 2.4; }).reduce((sum, component, index) => sum + component * [.2126, .7152, .0722][index], 0);
const contrast = (a, b) => { const first = luminance(a), second = luminance(b); return (Math.max(first, second) + .05) / (Math.min(first, second) + .05); };
const expected = getComputedStyle(document.querySelector('#resolved')).backgroundColor;
const button = document.querySelector('#app button'), body = getComputedStyle(document.body);
const result = {Raw:getComputedStyle(button).getPropertyValue('--accent').trim(), Expected:expected, Background:getComputedStyle(button).backgroundColor, Ink:body.color, Paper:body.backgroundColor, PrimaryText:getComputedStyle(button).color, TextContrast:contrast(body.color, body.backgroundColor), PrimaryContrast:contrast(getComputedStyle(button).color, getComputedStyle(button).backgroundColor), FocusContrast:contrast(expected, body.backgroundColor), Focus:[]};
for (const element of document.querySelectorAll('#app [data-slot]')) {
  element.focus(); const style = getComputedStyle(element);
  result.Focus.push({Slot:element.dataset.slot, Color:style.outlineColor, Style:style.outlineStyle, Width:style.outlineWidth, Visible:element.matches(':focus-visible')});
}
resolve(result);
}))`, &observed, chromedp.EvalAsValue, func(p *runtime.EvaluateParams) *runtime.EvaluateParams { return p.WithAwaitPromise(true) })); err != nil {
				t.Fatal(err)
			}
			if observed.Raw == "" || strings.Contains(observed.Raw, "(") || observed.Expected == "rgba(0, 0, 0, 0)" || observed.Background != observed.Expected || observed.Ink == "" || observed.Ink == observed.Paper {
				t.Errorf("%s resolved theme colors: %+v", scheme, observed)
			}
			if observed.TextContrast < 4.5 || observed.FocusContrast < 3 {
				t.Errorf("%s contrast text=%.2f primary=%.2f focus=%.2f", scheme, observed.TextContrast, observed.PrimaryContrast, observed.FocusContrast)
			}
			if len(observed.Focus) != 4 {
				t.Fatalf("%s missing focus controls: %+v", scheme, observed)
			}
			for _, focus := range observed.Focus {
				if !focus.Visible || focus.Color != observed.Expected || focus.Style != "solid" || focus.Width != "2px" {
					t.Errorf("%s focus outline %s: %+v; want color=%s solid 2px", scheme, focus.Slot, focus, observed.Expected)
				}
			}
		})
	}
	var custom struct {
		PrimaryText, Background string
		Contrast                float64
	}
	if err := chromedp.Run(ctx,
		chromedp.Navigate(server.URL+"?custom=1"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return emulation.SetEmulatedMedia().WithFeatures([]*emulation.MediaFeature{{Name: "prefers-color-scheme", Value: "dark"}}).Do(ctx)
		}),
		chromedp.Evaluate(`new Promise(resolve => requestAnimationFrame(() => {
const rgb = value => value.match(/[\d.]+/g).slice(0, 3).map(Number);
const luminance = value => rgb(value).map(component => { component /= 255; return component <= .04045 ? component / 12.92 : ((component + .055) / 1.055) ** 2.4; }).reduce((sum, component, index) => sum + component * [.2126, .7152, .0722][index], 0);
const button = getComputedStyle(document.querySelector('#app button'));
const first = luminance(button.color), second = luminance(button.backgroundColor);
resolve({PrimaryText:button.color, Background:button.backgroundColor, Contrast:(Math.max(first, second) + .05) / (Math.min(first, second) + .05)});
}))`, &custom, chromedp.EvalAsValue, func(p *runtime.EvaluateParams) *runtime.EvaluateParams { return p.WithAwaitPromise(true) })); err != nil {
		t.Fatal(err)
	}
	if custom.PrimaryText != "rgb(255, 255, 255)" || custom.Background != "rgb(10, 51, 92)" || custom.Contrast < 4.5 {
		t.Fatalf("custom dark primary palette=%+v", custom)
	}
}
