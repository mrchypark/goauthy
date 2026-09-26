package rbac

import (
	"encoding/json"
	"html/template"
	"net/http"

	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/saas"
)

var oauth2CompletionPage = template.Must(template.New("oauth2-complete").Parse(`<!doctype html>
<html lang="{{.Language}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{{if eq .Language "ko"}}연결 저장됨{{else}}Connection saved{{end}} · GoAuthy</title><link rel="stylesheet" href="{{.CSS}}"></head>
<body><main id="oauth2-complete"><h1>{{if eq .Language "ko"}}연결 저장됨{{else}}Connection saved{{end}}</h1><p>{{if eq .Language "ko"}}연결이 저장되었습니다. 이 서비스를 사용하려면 별도의 명시적 승인이 필요합니다.{{else}}Your connection was saved. Using this service requires separate explicit approval.{{end}}</p><p>{{if eq .Language "ko"}}원래 탭으로 돌아가거나 계정으로 계속하세요.{{else}}Return to the original tab, or continue to your account.{{end}}</p><a id="oauth2-account-link" class="button" rel="noreferrer" href="{{.Account}}">{{if eq .Language "ko"}}계정으로 돌아가기{{else}}Return to account{{end}}</a></main></body></html>`))

type oauth2CompletionPageData struct {
	CSS, Account, Language string
}

func wantsOAuth2CompletionPage(r *http.Request) bool {
	return len(r.Header.Values("Sec-Fetch-Mode")) == 1 && r.Header.Get("Sec-Fetch-Mode") == "navigate" &&
		len(r.Header.Values("Sec-Fetch-Dest")) == 1 && r.Header.Get("Sec-Fetch-Dest") == "document"
}

func (h *Handler) renderOAuth2CompletionPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	language := i18n.UILanguageFromRequest(r)
	w.Header().Set("Content-Language", language)
	w.Header().Add("Vary", "Accept-Language")
	w.Header().Add("Vary", "Cookie")
	_ = oauth2CompletionPage.Execute(w, oauth2CompletionPageData{CSS: h.issuer + "/account/account.css", Account: h.issuer + "/account", Language: language})
}

func (h *Handler) writeOAuth2Completion(w http.ResponseWriter, r *http.Request, status saas.OAuth2ConnectionStatus) {
	if wantsOAuth2CompletionPage(r) {
		h.renderOAuth2CompletionPage(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(status)
}
