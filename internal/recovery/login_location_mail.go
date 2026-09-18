package recovery

import (
	"context"
	"errors"
	"html/template"
	"net"
	"net/url"
	"strings"
	texttemplate "text/template"

	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/i18n"
)

// LoginLocationMessage is a warning about a login from a new location. The
// revoke URL is a bearer action link and must never be logged.
type LoginLocationMessage struct {
	To, Language, IP, UserAgent, RevokeURL, AccountURL string
	// SubjectPrefix is supplied by the parent configuration/wiring for the
	// Rauthy-compatible subject.
	SubjectPrefix string
	Theme         *branding.Theme
	Location      *string
}

type loginLocationCopy struct {
	Subject, UnknownLocation, IfInvalid, RevokeLink, AccountLink string
}

type loginLocationData struct {
	Language, IP, UserAgent, Location, RevokeURL, AccountURL string
	ThemeVars                                                template.CSS
	loginLocationCopy
}

var loginLocationText = texttemplate.Must(texttemplate.New("login-location.txt").Parse(`{{.UnknownLocation}}

IP: {{.IP}}{{if .Location}} ({{.Location}}){{end}}
{{.UserAgent}}

{{.IfInvalid}}

{{.RevokeLink}}: {{.RevokeURL}}

{{.AccountLink}}: {{.AccountURL}}
`))

var loginLocationHTML = template.Must(template.New("login-location.html").Parse(`<!doctype html>
<html lang="{{.Language}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>E-Mail Reset</title></head>
<style>
body {
{{.ThemeVars}}
}
</style><body>
<h1>{{.UnknownLocation}}</h1>
<p>IP: <b>{{.IP}}</b>{{if .Location}} ({{.Location}}){{end}}<br>{{.UserAgent}}<br></p>
<p>{{.IfInvalid}}</p>
<a href="{{.RevokeURL}}">{{.RevokeLink}}</a>
<br><br>
<a href="{{.AccountURL}}" data-faded="true">{{.AccountLink}}</a>
</body></html>`))

// SendLoginLocation sends the fixed Rauthy v0.36.2 login-location warning.
func (s *SMTPSender) SendLoginLocation(ctx context.Context, message LoginLocationMessage) error {
	if s == nil || s.send == nil {
		return errors.New("SMTP sender unavailable")
	}
	to, err := canonicalEmail(message.To)
	if err != nil {
		return ErrInvalidEmail
	}
	language := message.Language
	if language == "" {
		language = "en"
	}
	copy, err := loginLocationLanguage(language)
	if err != nil {
		return err
	}
	if err := s.validLoginLocationMessage(message); err != nil {
		return err
	}
	location := ""
	if message.Location != nil {
		location = *message.Location
	}
	var themeVars template.CSS
	if message.Theme != nil {
		themeVars = template.CSS(message.Theme.EmailCSS())
	}
	data := loginLocationData{
		Language:          language,
		IP:                message.IP,
		UserAgent:         message.UserAgent,
		Location:          location,
		RevokeURL:         message.RevokeURL,
		AccountURL:        message.AccountURL,
		ThemeVars:         themeVars,
		loginLocationCopy: copy,
	}
	if language == "zhhans" {
		data.Language = "zh_hans"
	}
	var text, html strings.Builder
	if err := loginLocationText.Execute(&text, data); err != nil {
		return err
	}
	if err := loginLocationHTML.Execute(&html, data); err != nil {
		return err
	}
	subject := message.SubjectPrefix + " - " + copy.Subject
	return s.sendRenderedMessage(ctx, to, EmailTemplate{Subject: subject}, text.String(), html.String())
}

func loginLocationLanguage(language string) (loginLocationCopy, error) {
	if language == "" {
		language = "en"
	}
	if !i18n.ValidUserLanguage(language) {
		return loginLocationCopy{}, errors.New("invalid user language")
	}
	if language == "zhhans" {
		language = "zh_hans"
	}
	copy, ok := loginLocationCopies[language]
	if !ok {
		return loginLocationCopy{}, errors.New("invalid login location template")
	}
	return copy, nil
}

func (s *SMTPSender) validLoginLocationMessage(message LoginLocationMessage) error {
	if message.Theme != nil {
		if err := message.Theme.Validate(); err != nil {
			return err
		}
	}
	if hasCRLF(message.SubjectPrefix) {
		return errors.New("invalid login location subject prefix")
	}
	ip := net.ParseIP(message.IP)
	if ip == nil {
		return errors.New("invalid login location IP")
	}
	account, err := s.parseLoginLocationURL(message.AccountURL)
	if err != nil || account.User != nil || account.RawPath != "" || account.RawQuery != "" || account.ForceQuery || account.Fragment != "" || account.Opaque != "" {
		return errors.New("invalid login location URL")
	}
	const accountSuffix = "/auth/v1/account"
	if !strings.HasSuffix(account.Path, accountSuffix) {
		return errors.New("invalid login location URL")
	}
	base := strings.TrimSuffix(account.Path, accountSuffix)
	if !validIssuerBasePath(base) {
		return errors.New("invalid login location URL")
	}

	revoke, err := s.parseLoginLocationURL(message.RevokeURL)
	if err != nil || revoke.User != nil || revoke.Opaque != "" || revoke.Fragment != "" {
		return errors.New("invalid login location URL")
	}
	if !sameLoginLocationOrigin(account, revoke) {
		return errors.New("invalid login location URL")
	}
	parts := strings.Split(revoke.Path, "/")
	if len(parts) < 7 || strings.Join(parts[:len(parts)-3], "/") != base+"/auth/v1/users" || parts[len(parts)-2] != "revoke" || parts[len(parts)-3] == "" || parts[len(parts)-3] == "." || parts[len(parts)-3] == ".." || !loginLocationCode(parts[len(parts)-1]) {
		return errors.New("invalid login location URL")
	}
	query, err := url.ParseQuery(revoke.RawQuery)
	queriedIP := net.ParseIP(query.Get("ip"))
	if err != nil || len(query) != 1 || len(query["ip"]) != 1 || queriedIP == nil || !queriedIP.Equal(ip) {
		return errors.New("invalid login location URL")
	}
	return nil
}

func (s *SMTPSender) parseLoginLocationURL(value string) (*url.URL, error) {
	if err := s.validPasswordURL(value, "login location"); err != nil {
		return nil, err
	}
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return nil, errors.New("invalid login location URL")
	}
	return u, nil
}

func sameLoginLocationOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func validIssuerBasePath(path string) bool {
	if path == "" || path == "/" {
		return path == ""
	}
	if !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") || strings.Contains(path, "//") || strings.ContainsAny(path, `\\{}`) {
		return false
	}
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func loginLocationCode(value string) bool {
	if len(value) != 48 {
		return false
	}
	for _, c := range []byte(value) {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}

// Copy adapted from Rauthy v0.36.2, src/data/src/email/i18n/login_location.rs
// (Apache-2.0). Korean and Simplified Chinese intentionally match that source.
var loginLocationCopies = map[string]loginLocationCopy{
	"de":      {"Sicherheitswarnung", "Login von unbekannter Adresse", "Sollte es sicher hierbei um einen ungültigen Login handeln, sollte dieser sofort widerrufen werden und Login-Daten erneuert werden!", "Zugriff Entziehen", "Account Dashboard"},
	"en":      {"Security Warning", "Login from unknown location", "If this is an invalid login, you should revoke it immediately and update your credentials!", "Revoke Access", "Account Dashboard"},
	"fr":      {"Avertissement de sécurité", "Connexion depuis un emplacement inconnu", "Si cette connexion est invalide, vous devez la révoquer immédiatement et mettre à jour vos identifiants !", "Révoquer l’accès", "Tableau de bord du compte"},
	"ko":      {"Security Warning", "Login from unknown location", "If this is an invalid login, you should revoke it immediately and update your credentials!", "Revoke Access", "Account Dashboard"},
	"nb":      {"Sikkerhetsvarsel", "Innlogging fra ukjent adresse", "Hvis dette er en ugyldig innlogging, bør du tilbakekalle den umiddelbart og oppdatere dine påloggingsopplysninger!", "Tilbakekall tilgang", "Kontodashboard"},
	"nl":      {"Beveiligingswaarschuwing", "Inloggen vanaf onbekende locatie", "Als dit een ongeldige login is, moet u deze onmiddellijk intrekken en uw inloggegevens bijwerken!", "Toegang intrekken", "Account Dashboard"},
	"ru":      {"Предупреждение безопасности", "Вход с неизвестного местоположения", "Если это был несанкционированный вход, вам следует немедленно отозвать доступ и обновить свои учётные данные!", "Отозвать доступ", "Панель аккаунта"},
	"uk":      {"Попередження безпеки", "Вхід з невідомого місця", "Якщо це були не ви, вам слід негайно відкликати доступ та оновити свої облікові дані!", "Відкликати доступ", "Панель акаунта"},
	"zh_hans": {"Security Warning", "Login from unknown location", "If this is an invalid login, you should revoke it immediately and update your credentials!", "Revoke Access", "Account Dashboard"},
}
