package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/mrchypark/goauthy/internal/branding"
)

func TestElysduiDynamicAdminInBrowser(t *testing.T) {
	chrome, err := exec.LookPath("chromium")
	if err != nil {
		chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
		if _, err := os.Stat(chrome); err != nil {
			t.Skip("Chrome unavailable")
		}
	}
	ui, err := NewUI(func(http.ResponseWriter, *http.Request, bool) bool { return true })
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
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
	alloc, cancelAlloc := chromedp.NewExecAllocator(context.Background(), append(chromedp.DefaultExecAllocatorOptions[:], chromedp.ExecPath(chrome), chromedp.Flag("headless", true))...)
	defer cancelAlloc()
	ctx, cancel := chromedp.NewContext(alloc)
	defer cancel()
	chromedp.ListenTarget(ctx, func(event any) {
		if e, ok := event.(*runtime.EventExceptionThrown); ok {
			t.Logf("browser exception: %s", e.ExceptionDetails)
		}
	})
	ctx, timeout := context.WithTimeout(ctx, 30*time.Second)
	defer timeout()
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
