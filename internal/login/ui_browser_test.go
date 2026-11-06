package login

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

func TestLoginBrowserLayoutAndKeyboard(t *testing.T) {
	h := testHandler(t)
	mux := http.NewServeMux()
	mux.Handle("/account/login", h.AccountLoginHandler(false))
	mux.Handle("/auth/v1/theme/global.css", branding.GlobalCSSHandler())
	mux.Handle("/auth/v1/branding/{name}", branding.BrandAssetHandler())
	if err := ui.BindAssets(mux); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(mux)
	defer server.Close()
	ctx := testbrowser.Start(t)
	for _, viewport := range []struct{ width, height int64 }{{1280, 800}, {390, 844}, {320, 640}} {
		var valid bool
		if err := chromedp.Run(ctx, chromedp.EmulateViewport(viewport.width, viewport.height), chromedp.Navigate(server.URL+"/account/login"), chromedp.WaitVisible(`input[name=username]`), chromedp.Evaluate(`document.documentElement.scrollWidth <= innerWidth && !!document.querySelector('#login-form button[data-slot=button]') && getComputedStyle(document.querySelector('#login-form button')).display !== 'none'`, &valid)); err != nil || !valid {
			t.Fatalf("viewport %dx%d: valid=%v err=%v", viewport.width, viewport.height, valid, err)
		}
	}
	var focused bool
	if err := chromedp.Run(ctx, chromedp.Navigate(server.URL+"/account/login"), input.DispatchKeyEvent(input.KeyDown).WithKey("Tab").WithCode("Tab"), input.DispatchKeyEvent(input.KeyUp).WithKey("Tab").WithCode("Tab"), chromedp.Evaluate(`document.activeElement.matches('select, a, input, button') && document.activeElement !== document.body`, &focused)); err != nil || !focused {
		t.Fatalf("keyboard focus=%v err=%v", focused, err)
	}
	var passwordFocused, submitFocused bool
	if err := chromedp.Run(ctx, chromedp.Focus(`input[name=username]`), input.DispatchKeyEvent(input.KeyDown).WithKey("Tab").WithCode("Tab"), input.DispatchKeyEvent(input.KeyUp).WithKey("Tab").WithCode("Tab"), chromedp.Evaluate(`document.activeElement.matches('input[name=password]')`, &passwordFocused), input.DispatchKeyEvent(input.KeyDown).WithKey("Tab").WithCode("Tab"), input.DispatchKeyEvent(input.KeyUp).WithKey("Tab").WithCode("Tab"), chromedp.Evaluate(`document.activeElement.matches('#login-form button[type=submit]')`, &submitFocused)); err != nil || !passwordFocused || !submitFocused {
		t.Fatalf("keyboard password=%v submit=%v err=%v", passwordFocused, submitFocused, err)
	}
}
