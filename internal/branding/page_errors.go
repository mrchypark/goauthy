package branding

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"github.com/mrchypark/goauthy/internal/i18n"
)

var errorPage = template.Must(template.New("page-error").Parse(`<!doctype html><html lang="{{.Language}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GoAuthy</title><link rel="stylesheet" href="{{.Base}}/auth/v1/theme/global.css"></head><body class="auth-page"><header><a class="auth-brand" href="{{.Base}}/"><span class="brand-symbol" aria-hidden="true"></span>GoAuthy</a></header><main class="auth-panel"><p class="auth-eyebrow">{{.Status}}</p><h1>{{if eq .Language "ko"}}계속할 수 없습니다{{else}}Unable to continue{{end}}</h1><p>{{if eq .Language "ko"}}입력 내용과 로그인 상태를 확인하세요. 요청이 만료되었다면 시작한 앱에서 다시 진행하세요. 이미 제출한 작업은 결과를 확인한 뒤 다시 시도하세요.{{else}}Check your details and sign-in status. If the request expired, restart from the app where you began. Check the outcome before repeating an action already submitted.{{end}}</p><nav class="home-links"><a href="{{.Base}}/account/login">{{if eq .Language "ko"}}계정 로그인{{else}}Account sign-in{{end}}</a><a href="{{.Base}}/">{{if eq .Language "ko"}}홈으로{{else}}Home{{end}}</a></nav></main></body></html>`))

// BrowserPageErrors gives plain authentication errors a safe exit. API clients,
// redirects and existing HTML errors retain their original responses.
func BrowserPageErrors(issuer string, next http.Handler) http.Handler {
	u, _ := url.Parse(issuer)
	base := strings.TrimRight(u.EscapedPath(), "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth/login", "/auth/profile", "/account/login", "/account", "/oidc/authorize", "/oidc/logout", "/oidc/device/login", "/oidc/device/verify", "/account/connection-login":
		default:
			next.ServeHTTP(w, r)
			return
		}
		if !strings.Contains(r.Header.Get("Accept"), "text/html") {
			next.ServeHTTP(w, r)
			return
		}
		out := &pageErrorWriter{ResponseWriter: w}
		next.ServeHTTP(out, r)
		if out.status == 0 {
			return
		}
		language := i18n.UILanguageFromRequest(r)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Del("Content-Length")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Language", language)
		w.Header().Add("Vary", "Cookie")
		w.Header().Add("Vary", "Accept-Language")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.WriteHeader(out.status)
		_ = errorPage.Execute(w, struct {
			Base, Language string
			Status         int
		}{base, language, out.status})
	})
}

type pageErrorWriter struct {
	http.ResponseWriter
	status  int
	written bool
}

// Preserve response-controller capabilities used by delayed login failures.
func (w *pageErrorWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *pageErrorWriter) WriteHeader(status int) {
	if w.written {
		return
	}
	w.written = true
	if status >= 400 && !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		w.status = status
		return
	}
	w.ResponseWriter.WriteHeader(status)
}
func (w *pageErrorWriter) Write(data []byte) (int, error) {
	if !w.written {
		w.WriteHeader(http.StatusOK)
	}
	if w.status != 0 {
		return len(data), nil
	}
	return w.ResponseWriter.Write(data)
}
