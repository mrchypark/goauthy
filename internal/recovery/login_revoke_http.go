package recovery

import (
	"bytes"
	"html/template"
	"net/http"
	"net/netip"

	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/oidc"
)

var loginRevokePage = template.Must(template.New("login-revoke").Parse(`<!doctype html><html lang="{{.Language}}"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>{{.Title}}</title></head><body><main><h1>{{.Title}}</h1><p>{{.Description}}</p>{{if .Warning}}<p>{{.Warning}}</p>{{end}}</main></body></html>`))

type loginRevokePageData struct {
	Language    string
	Title       string
	Description string
	Warning     string
}

// NewLoginRevokeHandler serves the public unknown-login revocation link.
func NewLoginRevokeHandler(identities *identity.Store, keyring *oidc.Keyring, lookups ...func(netip.Addr) (*string, error)) http.Handler {
	var lookup func(netip.Addr) (*string, error)
	if len(lookups) > 0 {
		lookup = lookups[0]
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		securityHeaders(w)
		if r.Method != http.MethodGet {
			methodNotAllowed(w, http.MethodGet)
			return
		}

		ip, ok := loginRevokeQueryIP(r)
		if !ok {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		data := loginRevokeCopy(r, false)
		if identities != nil && keyring != nil {
			var location *string
			if lookup != nil {
				if candidate, err := lookup(ip); err == nil {
					location = candidate
				}
			}
			if err := identities.RevokeLogin(r.Context(), keyring, r.PathValue("subject"), r.PathValue("code"), ip, location); err == nil {
				data = loginRevokeCopy(r, true)
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		var body bytes.Buffer
		_ = loginRevokePage.Execute(&body, data)
		_, _ = w.Write(body.Bytes())
	})
}

var (
	loginRevokeCopies = map[string]loginRevokePageData{
		"en":     {Language: "en", Title: "Revoke Logins", Description: "All Logins and Sessions have been revoked for this user as much as possible.", Warning: "You should immediately renew all your passwords!"},
		"de":     {Language: "de", Title: "Logins widerrufen", Description: "Sämtliche Logins und Sessions für diesen Benutzer wurden soweit wie möglich widerrufen.", Warning: "Passwörter sollten auf der Stelle erneuert werden!"},
		"fr":     {Language: "fr", Title: "Révoquer les connexions", Description: "Toutes les connexions et sessions ont été révoquées pour cet utilisateur autant que possible.", Warning: "Vous devez immédiatement renouveler tous vos mots de passe !"},
		"ko":     {Language: "ko", Title: "Revoke Logins", Description: "All Logins and Sessions have been revoked for this user as much as possible.", Warning: "You should immediately renew all your passwords!"},
		"nb":     {Language: "nb", Title: "Tilbakekalling av pålogginger", Description: "Alle pålogginger og økter for denne brukeren har blitt tilbakekalt så langt det er mulig.", Warning: "Passord bør umiddelbart tilbakestilles!"},
		"nl":     {Language: "nl", Title: "Logins intrekken", Description: "Alle logins en sessies voor deze gebruiker zijn zoveel mogelijk ingetrokken.", Warning: "U moet onmiddellijk al uw wachtwoorden vernieuwen!"},
		"ru":     {Language: "ru", Title: "Отзыв входов", Description: "Все входы и сеансы были отозваны для этого пользователя насколько это возможно.", Warning: "Вам следует немедленно обновить все свои пароли!"},
		"uk":     {Language: "uk", Title: "Відкликати сесії", Description: "Усі входи та сесії для цього користувача було відкликано, наскільки це можливо.", Warning: "Вам слід негайно оновити всі ваші паролі!"},
		"zhhans": {Language: "zhhans", Title: "撤销登录", Description: "已尽可能撤销此用户的所有登录和会话。", Warning: "您应立即更新所有密码！"},
	}
)

func loginRevokeCopy(r *http.Request, success bool) loginRevokePageData {
	language := i18n.UserLanguageFromRequest(r)
	if success {
		if copy, ok := loginRevokeCopies[language]; ok {
			return copy
		}
	}
	return loginRevokePageData{Language: language, Title: "Code not found", Description: "The requested code could not be found."}
}

func loginRevokeQueryIP(r *http.Request) (netip.Addr, bool) {
	values, ok := r.URL.Query()["ip"]
	if !ok || len(values) != 1 {
		return netip.Addr{}, false
	}
	ip, err := netip.ParseAddr(values[0])
	return ip, err == nil && ip.Zone() == ""
}
