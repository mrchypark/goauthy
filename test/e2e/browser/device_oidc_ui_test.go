package browser

import (
	"os"
	"strings"
	"testing"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/mrchypark/goauthy/internal/device"
)

// loginAndApproveDeviceUI drives a cold browser through the complete device
// verification flow. It deliberately does not seed the browser cookie jar.
func loginAndApproveDeviceUI(t *testing.T, grant deviceLoginGrant, primary, username, password string, manual bool) {
	t.Helper()
	ctx, cancel := newCollectionUIContext(t, nil, primary)
	defer cancel()
	approvalStatus := make(chan int64, 1)
	var approvalRequest network.RequestID
	chromedp.ListenTarget(ctx, func(event any) {
		if request, ok := event.(*network.EventRequestWillBeSent); ok && request.Request.Method == "POST" && request.Request.URL == primary+"/oidc/device/verify" {
			approvalRequest = request.RequestID
		}
		if response, ok := event.(*network.EventResponseReceived); ok && approvalRequest != "" && response.RequestID == approvalRequest {
			select {
			case approvalStatus <- response.Response.Status:
			default:
			}
		}
	})

	startURL := grant.VerificationURIComplete
	if manual {
		startURL = primary + "/oidc/device/verify"
	}
	if err := chromedp.Run(ctx,
		chromedp.Navigate(startURL),
		chromedp.WaitVisible(`input[name="username"]`),
		chromedp.SetValue(`input[name="username"]`, username),
		chromedp.SetValue(`input[name="password"]`, password),
		chromedp.Click(`button[type="submit"]`),
		chromedp.WaitVisible(`input[name="user_code"]`),
	); err != nil {
		t.Fatal("open device verification login failed")
	}
	if manual {
		var entered string
		var approveButtons []*cdp.Node
		if err := chromedp.Run(ctx,
			chromedp.Value(`input[name="user_code"]`, &entered),
			chromedp.Nodes(`button[name="action"]`, &approveButtons, chromedp.AtLeast(0)),
		); err != nil || entered != "" || len(approveButtons) != 0 {
			t.Fatal("manual code entry must not expose an approval action")
		}
		if err := chromedp.Run(ctx,
			chromedp.SetValue(`input[name="user_code"]`, grant.UserCode),
			chromedp.Click(`form[method="get"] button[type="submit"]`),
			chromedp.WaitVisible(`input[name="user_code"][readonly]`),
		); err != nil {
			t.Fatal("manual code lookup failed")
		}
	}

	var displayedCode string
	if err := chromedp.Run(ctx, chromedp.Value(`input[name="user_code"]`, &displayedCode)); err != nil {
		t.Fatal("read device verification code failed")
	}
	if device.NormalizeUserCode(displayedCode) == "" || device.NormalizeUserCode(displayedCode) != device.NormalizeUserCode(grant.UserCode) {
		t.Fatal("device verification page displayed the wrong user code")
	}
	var client, scopes string
	if err := chromedp.Run(ctx,
		chromedp.Text(`#device-client`, &client),
		chromedp.Text(`#device-scopes`, &scopes),
		chromedp.WaitVisible(`input[name="user_code"][readonly]`),
	); err != nil || client != "goauthy-dev" || strings.Join(strings.Fields(scopes), " ") != grant.Scope {
		t.Fatal("device verification page did not show the requesting client and exact permissions")
	}

	if screenshot := os.Getenv("GOAUTHY_E2E_DEVICE_OIDC_SCREENSHOT"); screenshot != "" {
		var image []byte
		if err := chromedp.Run(ctx, chromedp.FullScreenshot(&image, 90)); err != nil {
			t.Fatal("capture device verification screenshot failed")
		}
		if err := os.WriteFile(screenshot, image, 0600); err != nil {
			t.Fatalf("write device verification screenshot: %v", err)
		}
	}

	if err := chromedp.Run(ctx, chromedp.Click(`button[name="action"][value="approve"]`)); err != nil {
		t.Fatal("submit device approval failed")
	}
	select {
	case status := <-approvalStatus:
		if status != 200 {
			t.Fatalf("device approval HTTP status=%d", status)
		}
	case <-ctx.Done():
		t.Fatal("device approval response was not observed")
	}
	if err := chromedp.Run(ctx,
		// Approval navigates to a text/plain document. A selector wait survives
		// that navigation; a JS promise in the previous document does not.
		chromedp.WaitVisible(`//pre[normalize-space(.)='Device approved']`, chromedp.BySearch),
	); err != nil {
		t.Fatal("approve device verification failed")
	}
}
