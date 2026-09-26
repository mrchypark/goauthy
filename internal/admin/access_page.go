package admin

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/mrchypark/goauthy/internal/i18n"
)

var accessPage = template.Must(template.New("admin-access").Parse(`<!doctype html><html lang="{{.Language}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GoAuthy</title><link rel="stylesheet" href="{{.Base}}/auth/v1/theme/global.css"></head><body class="auth-page"><header><a class="auth-brand" href="{{.Base}}/"><span class="brand-symbol" aria-hidden="true"></span>GoAuthy</a></header><main class="auth-panel"><h1>{{if eq .Language "ko"}}관리자 접근 확인{{else}}Administrator access required{{end}}</h1><p>{{if eq .Language "ko"}}관리자 계정으로 로그인하세요. 이미 로그인했다면 계정 권한을 확인하거나 다른 계정으로 로그인하세요.{{else}}Sign in with an administrator account. If already signed in, check your permissions or sign out to use another account.{{end}}</p><nav class="home-links"><a href="{{.Base}}/account/login">{{if eq .Language "ko"}}로그인 / 내 계정{{else}}Sign in / My account{{end}}</a><a href="{{.Base}}/oidc/logout">{{if eq .Language "ko"}}다른 계정으로 로그인하기 위해 로그아웃{{else}}Sign out to use another account{{end}}</a><a href="{{.Base}}/">{{if eq .Language "ko"}}홈으로{{else}}Home{{end}}</a></nav></main></body></html>`))

func renderAccessPage(w http.ResponseWriter, r *http.Request, base string) {
	_ = accessPage.Execute(w, struct{ Base, Language string }{base, i18n.UILanguageFromRequest(r)})
}

func wantsHTML(r *http.Request) bool { return strings.Contains(r.Header.Get("Accept"), "text/html") }
