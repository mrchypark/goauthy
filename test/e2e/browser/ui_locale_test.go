package browser

import (
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// English assertions must not depend on the host browser's preferred language.
func englishUILocale(base string) chromedp.Action {
	return network.SetCookie("goauthy_ui_locale", "en").WithURL(base).WithPath("/")
}
