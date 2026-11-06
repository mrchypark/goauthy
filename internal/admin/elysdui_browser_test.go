package admin

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
      requestAnimationFrame(() => { button.click(); resolve(input.isConnected && input.value === 'preserved' && input.required && clicked === 1 && input.dataset.slot === 'input' && button.dataset.slot === 'button' && select.dataset.slot === 'select' && textarea.dataset.slot === 'textarea' && table.classList.contains('ui-table') && table.parentElement.classList.contains('ui-table-wrap') && !theme.firstElementChild.dataset.slot && getComputedStyle(table.querySelector('td')).paddingTop === '8px'); });
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
	mux.HandleFunc("GET /theme.css", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		_, _ = w.Write([]byte(branding.DefaultTheme(branding.GlobalBrandID).CSS()))
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(`<!doctype html><html><head>
<link rel="stylesheet" href="/auth/v1/ui/app.css"><link rel="stylesheet" href="/auth/v1/ui/brand.css">
<link rel="stylesheet" href="/admin.css"><link rel="stylesheet" href="/theme.css"></head><body>
<div id="app"><button data-slot="button" data-variant="primary">Save</button>
<input data-slot="input"><select data-slot="select"><option>One</option></select><textarea data-slot="textarea"></textarea></div>
<div id="resolved" style="background-color:var(--color-accent)"></div></body></html>`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx := testbrowser.Start(t)
	var observed struct {
		Raw, Expected, Background string
		Focus                     []struct {
			Slot, Color, Style, Width string
			Visible                   bool
		}
	}
	if err := chromedp.Run(ctx, chromedp.Navigate(server.URL), chromedp.KeyEvent("\t"), chromedp.Evaluate(`(() => {
const expected = getComputedStyle(document.querySelector('#resolved')).backgroundColor;
const button = document.querySelector('#app button');
const result = {Raw:getComputedStyle(button).getPropertyValue('--accent').trim(), Expected:expected, Background:getComputedStyle(button).backgroundColor, Focus:[]};
for (const element of document.querySelectorAll('#app [data-slot]')) {
  element.focus(); const style = getComputedStyle(element);
  result.Focus.push({Slot:element.dataset.slot, Color:style.outlineColor, Style:style.outlineStyle, Width:style.outlineWidth, Visible:element.matches(':focus-visible')});
}
return result;
})()`, &observed)); err != nil {
		t.Fatal(err)
	}
	if observed.Raw == "" || strings.Contains(observed.Raw, "(") || observed.Expected == "rgba(0, 0, 0, 0)" || observed.Background != observed.Expected {
		t.Errorf("primary button computed colors: %+v", observed)
	}
	if len(observed.Focus) != 4 {
		t.Fatalf("missing focus controls: %+v", observed)
	}
	for _, focus := range observed.Focus {
		if !focus.Visible || focus.Color != observed.Expected || focus.Style != "solid" || focus.Width != "2px" {
			t.Errorf("focus outline %s: %+v; want color=%s solid 2px", focus.Slot, focus, observed.Expected)
		}
	}
}
