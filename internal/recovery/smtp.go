package recovery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/mrchypark/goauthy/internal/i18n"
	mail "github.com/wneessen/go-mail"
)

var (
	otpText = texttemplate.Must(texttemplate.New("otp.txt").Parse(`{{.Header}}

{{.Text}}

{{.OTP}}

{{.Validity}}
{{.Expires}} {{.ExpiresAt}}

{{.Footer}}
`))
	otpHTML = template.Must(template.New("otp.html").Parse(`<!doctype html>
<html><head><meta charset="utf-8"></head><body>
<h1>{{.Header}}</h1>
<p>{{.Text}}</p>
<p style="font-size:2em;font-weight:bold;letter-spacing:0.1em;margin:1em 0">{{.OTP}}</p>
<p>{{.Validity}}</p>
<p>{{.Expires}} <strong>{{.ExpiresAt}}</strong></p>
<footer><p>{{.Footer}}</p></footer>
</body></html>`))
	passwordResetText = texttemplate.Must(texttemplate.New("password-reset.txt").Parse(`{{.Header}}

{{.Text}}

{{.ClickLink}}

{{.Validity}}
{{.Expires}} {{.ExpiresAt}}

{{.ResetURL}}

{{.Footer}}
`))
	passwordResetHTML = template.Must(template.New("password-reset.html").Parse(`<!doctype html>
<html><head><meta charset="utf-8"></head><body>
<h1>{{.Header}}</h1>
<p>{{.Text}}</p>
<p>{{.ClickLink}}</p>
<p>{{.Validity}}</p>
<p>{{.Expires}} <strong>{{.ExpiresAt}}</strong></p>
<p><a href="{{.ResetURL}}">{{.Button}}</a></p>
<footer><p>{{.Footer}}</p></footer>
</body></html>`))
	registeredAlreadyText = texttemplate.Must(texttemplate.New("registered-already.txt").Parse(`{{.Header}}

{{.Text}}

{{.Footer}}
`))
	registeredAlreadyHTML = template.Must(template.New("registered-already.html").Parse(`<!doctype html>
<html><head><meta charset="utf-8"></head><body>
<h1>{{.Header}}</h1>
<p>{{.Text}}</p>
<footer><p>{{.Footer}}</p></footer>
</body></html>`))
)

// SMTPConfig configures password delivery. Template remains the reset template
// for backwards compatibility. AllowInsecure is intended
// only for local test SMTP fixtures; production delivery requires TLS.
type SMTPConfig struct {
	Host                      string
	Port                      int
	From                      string
	Username                  string
	Password                  string
	ImplicitTLS               bool
	Timeout                   time.Duration
	AllowInsecure             bool
	Template                  EmailTemplate
	PasswordNewTemplate       EmailTemplate
	AlreadyRegisteredTemplate EmailTemplate
	Templates                 EmailTemplates
}

// SMTPSender delivers password-reset messages through SMTP.
type SMTPSender struct {
	config           SMTPConfig
	send             func(context.Context, *mail.Msg) error
	OnDeliveryFailure func(recipient, mailType, subject, textBody, htmlBody string, err error)
}

// NewSMTPSender creates a Sender that requires verified TLS unless explicitly
// configured for an insecure local test fixture.
func NewSMTPSender(config SMTPConfig) (*SMTPSender, error) {
	if strings.TrimSpace(config.Host) == "" || strings.TrimSpace(config.Host) != config.Host || hasCRLF(config.Host) {
		return nil, errors.New("invalid SMTP host")
	}
	if config.Port < 1 || config.Port > 65535 {
		return nil, errors.New("invalid SMTP port")
	}
	if config.Timeout <= 0 {
		return nil, errors.New("invalid SMTP timeout")
	}
	if (config.Username == "") != (config.Password == "") {
		return nil, errors.New("SMTP username and password must be configured together")
	}
	from, err := canonicalEmail(config.From)
	if err != nil {
		return nil, errors.New("invalid SMTP from address")
	}
	config.From = from
	if config.Templates.passwordReset == nil && config.Templates.passwordNew == nil && config.Templates.registeredAlready == nil {
		config.Templates = defaultEmailTemplates()
	}
	if config.Templates.emailChangeConfirm == nil {
		config.Templates.emailChangeConfirm = defaultEmailChangeTemplates()
	}
	for _, catalog := range []map[string]EmailTemplate{config.Templates.passwordReset, config.Templates.passwordNew, config.Templates.registeredAlready, config.Templates.emailChangeConfirm} {
		for _, language := range []string{"de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zh_hans"} {
			if !validEmailTemplate(catalog[language]) {
				return nil, errors.New("invalid email template")
			}
		}
	}
	if config.Template == (EmailTemplate{}) {
		config.Template = defaultEmailTemplates().PasswordReset("en")
	}
	if !validEmailTemplate(config.Template) {
		return nil, errors.New("invalid password reset subject")
	}
	if config.PasswordNewTemplate == (EmailTemplate{}) {
		config.PasswordNewTemplate = defaultEmailTemplates().PasswordNew("en")
	}
	if !validEmailTemplate(config.PasswordNewTemplate) {
		return nil, errors.New("invalid new password subject")
	}
	if config.AlreadyRegisteredTemplate == (EmailTemplate{}) {
		config.AlreadyRegisteredTemplate = defaultEmailTemplates().AlreadyRegistered("en")
	}
	if !validEmailTemplate(config.AlreadyRegisteredTemplate) {
		return nil, errors.New("invalid registered already subject")
	}
	sender := &SMTPSender{config: config}
	sender.send = sender.deliver
	return sender, nil
}

// SendPasswordReset implements Sender.
func (s *SMTPSender) SendPasswordReset(ctx context.Context, message Message) error {
	if s == nil {
		return errors.New("SMTP sender unavailable")
	}
	template, err := s.template(message.Language, "reset")
	if err != nil {
		return err
	}
	return s.sendPasswordMessage(ctx, message, template, "password reset")
}

// SendPasswordNew implements Sender.
func (s *SMTPSender) SendPasswordNew(ctx context.Context, message Message) error {
	if s == nil {
		return errors.New("SMTP sender unavailable")
	}
	template, err := s.template(message.Language, "new")
	if err != nil {
		return err
	}
	return s.sendPasswordMessage(ctx, message, template, "new password")
}

// SendAlreadyRegistered sends a privacy-preserving notification to an
// existing account after an otherwise indistinguishable registration attempt.
func (s *SMTPSender) SendAlreadyRegistered(ctx context.Context, message Message) error {
	if s == nil || s.send == nil {
		return errors.New("SMTP sender unavailable")
	}
	template, err := s.template(message.Language, "already")
	if err != nil {
		return err
	}
	body := registeredAlreadyData{EmailTemplate: template}
	text, err := renderRegisteredAlreadyText(body)
	if err != nil {
		return err
	}
	html, err := renderRegisteredAlreadyHTML(body)
	if err != nil {
		return err
	}
	return s.sendRenderedMessage(ctx, message.To, template, text, html)
}

// SendOTP sends a one-time password via email for 2FA verification.
func (s *SMTPSender) SendOTP(ctx context.Context, email, code string, lang string, expiresAt time.Time) error {
	if s == nil || s.send == nil {
		return errors.New("SMTP sender unavailable")
	}
	if lang != "" && !i18n.ValidUserLanguage(lang) {
		lang = "en"
	}
	if lang == "" {
		lang = "en"
	}
	template := otpTemplateFor(lang)
	body := otpData{EmailTemplate: template, OTP: code, ExpiresAt: expiresAt.UTC().Format(time.RFC3339)}
	text, err := renderOTPText(body)
	if err != nil {
		return err
	}
	html, err := renderOTPHTML(body)
	if err != nil {
		return err
	}
	return s.sendRenderedMessage(ctx, email, template, text, html)
}

func (s *SMTPSender) template(language, event string) (EmailTemplate, error) {
	if language != "" && !i18n.ValidUserLanguage(language) {
		return EmailTemplate{}, errors.New("invalid user language")
	}
	if language == "zhhans" {
		language = "zh_hans"
	}
	if language == "" {
		switch event {
		case "reset":
			return s.config.Template, nil
		case "new":
			return s.config.PasswordNewTemplate, nil
		default:
			return s.config.AlreadyRegisteredTemplate, nil
		}
	}
	var out EmailTemplate
	var err error
	switch event {
	case "reset":
		out, err = s.config.Templates.PasswordResetExact(language)
	case "new":
		out, err = s.config.Templates.PasswordNewExact(language)
	default:
		out, err = s.config.Templates.AlreadyRegisteredExact(language)
	}
	return out, err
}

func (s *SMTPSender) sendPasswordMessage(ctx context.Context, message Message, emailTemplate EmailTemplate, event string) error {
	if s == nil || s.send == nil {
		return errors.New("SMTP sender unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	to, err := canonicalEmail(message.To)
	if err != nil {
		return ErrInvalidEmail
	}
	if err := s.validPasswordURL(message.ResetURL, event); err != nil {
		return err
	}
	if message.ExpiresAt.IsZero() {
		return fmt.Errorf("invalid %s expiry", event)
	}
	body := passwordMessageData{EmailTemplate: emailTemplate, ResetURL: message.ResetURL, ExpiresAt: message.ExpiresAt.UTC().Format(time.RFC3339)}
	text, err := renderPasswordText(body)
	if err != nil {
		return err
	}
	html, err := renderPasswordHTML(body)
	if err != nil {
		return err
	}
	return s.sendRenderedMessage(ctx, to, emailTemplate, text, html)
}

type smtpRecipientKey struct{}
type smtpMailTypeKey struct{}
type smtpSubjectKey struct{}
type smtpTextBodyKey struct{}
type smtpHTMLBodyKey struct{}

func (s *SMTPSender) sendRenderedMessage(ctx context.Context, recipient string, emailTemplate EmailTemplate, text, html string) error {
	ctx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	to, err := canonicalEmail(recipient)
	if err != nil {
		return ErrInvalidEmail
	}
	msg := mail.NewMsg()
	if err := msg.From(s.config.From); err != nil {
		return errors.New("invalid SMTP from address")
	}
	if err := msg.To(to); err != nil {
		return ErrInvalidEmail
	}
	msg.Subject(emailTemplate.Subject)
	msg.SetBodyString(mail.TypeTextPlain, text)
	msg.AddAlternativeString(mail.TypeTextHTML, html)
	ctx = context.WithValue(ctx, smtpRecipientKey{}, to)
	ctx = context.WithValue(ctx, smtpMailTypeKey{}, emailTemplate.Subject)
	ctx = context.WithValue(ctx, smtpSubjectKey{}, emailTemplate.Subject)
	ctx = context.WithValue(ctx, smtpTextBodyKey{}, text)
	ctx = context.WithValue(ctx, smtpHTMLBodyKey{}, html)
	return s.send(ctx, msg)
}

type passwordMessageData struct {
	EmailTemplate
	ResetURL  string
	ExpiresAt string
}

type passwordResetData = passwordMessageData
type passwordNewData = passwordMessageData
type registeredAlreadyData struct{ EmailTemplate }
type otpData struct {
	EmailTemplate
	OTP       string
	ExpiresAt string
}

func renderPasswordText(data passwordMessageData) (string, error) {
	var out strings.Builder
	if err := passwordResetText.Execute(&out, data); err != nil {
		return "", fmt.Errorf("render password reset text: %w", err)
	}
	return out.String(), nil
}

func renderPasswordHTML(data passwordMessageData) (string, error) {
	var out strings.Builder
	if err := passwordResetHTML.Execute(&out, data); err != nil {
		return "", fmt.Errorf("render password reset HTML: %w", err)
	}
	return out.String(), nil
}

func renderPasswordResetText(data passwordResetData) (string, error) { return renderPasswordText(data) }
func renderPasswordResetHTML(data passwordResetData) (string, error) { return renderPasswordHTML(data) }
func renderPasswordNewText(data passwordNewData) (string, error)     { return renderPasswordText(data) }
func renderPasswordNewHTML(data passwordNewData) (string, error)     { return renderPasswordHTML(data) }

func renderOTPText(data otpData) (string, error) {
	var out strings.Builder
	if err := otpText.Execute(&out, data); err != nil {
		return "", fmt.Errorf("render OTP text: %w", err)
	}
	return out.String(), nil
}

func renderOTPHTML(data otpData) (string, error) {
	var out strings.Builder
	if err := otpHTML.Execute(&out, data); err != nil {
		return "", fmt.Errorf("render OTP HTML: %w", err)
	}
	return out.String(), nil
}

var otpTemplates = map[string]EmailTemplate{
	"en": {Subject: "Your One-Time Password", Header: "One-Time Password", Text: "Use the following code to complete your login:", Validity: "This code expires in:", Expires: "Expires at:", Footer: "If you did not request this code, you can safely ignore this email."},
	"de": {Subject: "Ihr Einmalpasswort", Header: "Einmalpasswort", Text: "Verwenden Sie den folgenden Code, um Ihren Login abzuschließen:", Validity: "Dieser Code läuft ab in:", Expires: "Gültig bis:", Footer: "Wenn Sie diesen Code nicht angefordert haben, können Sie diese E-Mail sicher ignorieren."},
	"fr": {Subject: "Votre mot de passe à usage unique", Header: "Mot de passe à usage unique", Text: "Utilisez le code suivant pour terminer votre connexion:", Validity: "Ce code expire dans:", Expires: "Expire le:", Footer: "Si vous n'avez pas demandé ce code, vous pouvez ignorer cet e-mail."},
	"ko": {Subject: "일회용 비밀번호", Header: "일회용 비밀번호", Text: "로그인을 완료하려면 다음 코드를 사용하세요:", Validity: "이 코드는 다음 시간 후 만료됩니다:", Expires: "만료일:", Footer: "이 코드를 요청하지 않았다면 이 이메일을 무시해도 됩니다."},
	"nb": {Subject: "Engangspassord", Header: "Engangspassord", Text: "Bruk følgende kode for å fullføre påloggingen:", Validity: "Denne koden utløper om:", Expires: "Utløper:", Footer: "Hvis du ikke ba om denne koden, kan du trygt ignorere denne e-posten."},
	"nl": {Subject: "Uw eenmalig wachtwoord", Header: "Eenmalig wachtwoord", Text: "Gebruik de volgende code om uw aanmelding te voltooien:", Validity: "Deze code verloopt over:", Expires: "Verloopt:", Footer: "Als u deze code niet heeft aangevraagd, kunt u deze e-mail veilig negeren."},
	"ru": {Subject: "Ваш одноразовый пароль", Header: "Одноразовый пароль", Text: "Используйте следующий код для завершения входа:", Validity: "Срок действия этого кода:", Expires: "Истекает:", Footer: "Если вы не запрашивали этот код, можете безопасно игнорировать это письмо."},
	"uk": {Subject: "Ваш одноразовий пароль", Header: "Одноразовий пароль", Text: "Використайте наступний код для завершення входу:", Validity: "Термін дії цього коду:", Expires: "Закінчується:", Footer: "Якщо ви не запитували цей код, можете безпечно ігнорувати цей лист."},
	"zh_hans": {Subject: "您的动态验证码", Header: "动态验证码", Text: "请使用以下代码完成登录:", Validity: "此代码将在以下时间后过期:", Expires: "过期时间:", Footer: "如果您没有请求此代码，可以安全地忽略此邮件。"},
}

func otpTemplateFor(lang string) EmailTemplate {
	if t, ok := otpTemplates[lang]; ok {
		return t
	}
	return otpTemplates["en"]
}

func renderRegisteredAlreadyText(data registeredAlreadyData) (string, error) {
	var out strings.Builder
	if err := registeredAlreadyText.Execute(&out, data); err != nil {
		return "", fmt.Errorf("render registered already text: %w", err)
	}
	return out.String(), nil
}

func renderRegisteredAlreadyHTML(data registeredAlreadyData) (string, error) {
	var out strings.Builder
	if err := registeredAlreadyHTML.Execute(&out, data); err != nil {
		return "", fmt.Errorf("render registered already HTML: %w", err)
	}
	return out.String(), nil
}

func (s *SMTPSender) validPasswordURL(value, event string) error {
	if hasCRLF(value) {
		return fmt.Errorf("invalid %s URL", event)
	}
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() || u.Host == "" || (u.Scheme != "https" && !(s.config.AllowInsecure && u.Scheme == "http")) {
		return fmt.Errorf("invalid %s URL", event)
	}
	return nil
}

func (s *SMTPSender) deliver(ctx context.Context, msg *mail.Msg) error {
	opts := []mail.Option{
		mail.WithPort(s.config.Port),
		mail.WithTimeout(s.config.Timeout),
		mail.WithTLSConfig(&tls.Config{ServerName: s.config.Host, MinVersion: tls.VersionTLS12}),
	}
	if s.config.ImplicitTLS {
		opts = append(opts, mail.WithSSL())
	} else if s.config.AllowInsecure {
		opts = append(opts, mail.WithTLSPolicy(mail.NoTLS))
	} else {
		opts = append(opts, mail.WithTLSPolicy(mail.TLSMandatory))
	}
	if s.config.Username != "" || s.config.Password != "" {
		opts = append(opts, mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover), mail.WithUsername(s.config.Username), mail.WithPassword(s.config.Password))
	}
	client, err := mail.NewClient(s.config.Host, opts...)
	if err != nil {
		return errors.New("SMTP client configuration failed")
	}
	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		if s.OnDeliveryFailure != nil {
			recipient, _ := ctx.Value(smtpRecipientKey{}).(string)
			mailType, _ := ctx.Value(smtpMailTypeKey{}).(string)
			subject, _ := ctx.Value(smtpSubjectKey{}).(string)
			textBody, _ := ctx.Value(smtpTextBodyKey{}).(string)
			htmlBody, _ := ctx.Value(smtpHTMLBodyKey{}).(string)
			s.OnDeliveryFailure(recipient, mailType, subject, textBody, htmlBody, err)
		}
		return err
	}
	return nil
}

func hasCRLF(value string) bool {
	return strings.ContainsAny(value, "\r\n")
}
