package account

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/testbrowser"
	"github.com/mrchypark/goauthy/internal/ui"
)

func TestAccountBrowserLayoutAndKeyboard(t *testing.T) {
	h, _, _, cookie, _ := testPasswordHandler(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/account", h.Dashboard)
	mux.HandleFunc("/account/", h.Dashboard)
	mux.Handle("/auth/v1/branding/{name}", branding.BrandAssetHandler())
	if err := ui.BindAssets(mux); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.AddCookie(cookie)
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()
	ctx := testbrowser.Start(t)
	for _, viewport := range []struct{ width, height int64 }{{1280, 800}, {390, 844}, {320, 640}} {
		var valid bool
		if err := chromedp.Run(ctx, chromedp.EmulateViewport(viewport.width, viewport.height), chromedp.Navigate(server.URL+"/account"), chromedp.WaitVisible(`#preferred-username`), chromedp.Evaluate(`document.documentElement.scrollWidth <= innerWidth && !!document.querySelector('#username-form button[data-slot=button]') && getComputedStyle(document.querySelector('#username-form button')).backgroundColor !== 'rgba(0, 0, 0, 0)' && getComputedStyle(document.querySelector('[data-language-select]')).backgroundImage !== 'none'`, &valid)); err != nil || !valid {
			t.Fatalf("viewport %dx%d: valid=%v err=%v", viewport.width, viewport.height, valid, err)
		}
	}
	var focused bool
	if err := chromedp.Run(ctx, chromedp.Navigate(server.URL+"/account"), input.DispatchKeyEvent(input.KeyDown).WithKey("Tab").WithCode("Tab"), input.DispatchKeyEvent(input.KeyUp).WithKey("Tab").WithCode("Tab"), chromedp.Evaluate(`document.activeElement.matches('.skip-link') && getComputedStyle(document.activeElement).top !== '-100px'`, &focused)); err != nil || !focused {
		t.Fatalf("skip link focus=%v err=%v", focused, err)
	}
	var submitFocused bool
	if err := chromedp.Run(ctx, chromedp.Focus(`#preferred-username`), input.DispatchKeyEvent(input.KeyDown).WithKey("Tab").WithCode("Tab"), input.DispatchKeyEvent(input.KeyUp).WithKey("Tab").WithCode("Tab"), chromedp.Evaluate(`document.activeElement.matches('#username-form button[type=submit]')`, &submitFocused)); err != nil || !submitFocused {
		t.Fatalf("username submit focus=%v err=%v", submitFocused, err)
	}
}
