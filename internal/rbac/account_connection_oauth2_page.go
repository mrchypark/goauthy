package rbac

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/mrchypark/goauthy/internal/saas"
)

var oauth2CompletionPage = template.Must(template.New("oauth2-complete").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Connection saved · GoAuthy</title><link rel="stylesheet" href="{{.CSS}}"></head>
<body><main id="oauth2-complete"><h1>Connection saved</h1><p>Your connection was saved. Using this service requires separate explicit approval.</p><p>Return to the original tab, or continue to your account.</p><a id="oauth2-account-link" class="button" rel="noreferrer" href="{{.Account}}">Return to account</a></main></body></html>`))

type oauth2CompletionPageData struct {
	CSS, Account string
}

func wantsOAuth2CompletionPage(r *http.Request) bool {
	return len(r.Header.Values("Sec-Fetch-Mode")) == 1 && r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
		len(r.Header.Values("Sec-Fetch-Dest")) == 1 && r.Header.Get("Sec-Fetch-Dest") == "document"
}

func (h *Handler) renderOAuth2CompletionPage(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	_ = oauth2CompletionPage.Execute(w, oauth2CompletionPageData{CSS: h.issuer + "/account/account.css", Account: h.issuer + "/account"})
}

func (h *Handler) writeOAuth2Completion(w http.ResponseWriter, r *http.Request, status saas.OAuth2ConnectionStatus) {
	if wantsOAuth2CompletionPage(r) {
		h.renderOAuth2CompletionPage(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
