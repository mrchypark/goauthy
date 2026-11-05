package admin

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/ui"
)

var accessPage = template.Must(template.Must(ui.NewTemplates("admin-access")).Parse(`<!doctype html>
<html lang="{{.Language}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GoAuthy</title>
{{template "goauthy-head" .Base}}<link rel="stylesheet" href="{{.Base}}/auth/v1/theme/global.css"><link rel="stylesheet" href="{{.Base}}/auth/v1/branding/brand.css">
</head><body class="auth-page"><header><a class="auth-brand" href="{{.Base}}/"><span class="brand-symbol" aria-hidden="true"></span>GoAuthy</a></header><main class="auth-panel">
<h1>{{if eq .Language "ko"}}관리자 접근 확인{{else}}Administrator access required{{end}}</h1><p>{{if eq .Language "ko"}}관리자 계정으로 로그인하세요. 이미 로그인했다면 계정 권한을 확인하거나 다른 계정으로 로그인하세요.{{else}}Sign in with an administrator account. If already signed in, check your permissions or sign out to use another account.{{end}}</p>
{{$signIn := "Sign in / My account"}}{{$signOut := "Sign out to use another account"}}{{$home := "Home"}}
{{if eq .Language "ko"}}{{$signIn = "로그인 / 내 계정"}}{{$signOut = "다른 계정으로 로그인하기 위해 로그아웃"}}{{$home = "홈으로"}}{{end}}
<nav class="home-links">
{{template "button" (dict "Href" (printf "%s/account/login" .Base) "Label" $signIn "Size" "sm")}}
{{template "button" (dict "Href" (printf "%s/oidc/logout" .Base) "Label" $signOut "Variant" "outline" "Size" "sm")}}
{{template "button" (dict "Href" (printf "%s/" .Base) "Label" $home "Variant" "ghost" "Size" "sm")}}
</nav></main></body></html>`))

func renderAccessPage(w http.ResponseWriter, r *http.Request, base string) {
	_ = accessPage.Execute(w, struct{ Base, Language string }{base, i18n.UILanguageFromRequest(r)})
}

func wantsHTML(r *http.Request) bool { return strings.Contains(r.Header.Get("Accept"), "text/html") }
