package recovery

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/pelletier/go-toml/v2"
)

const maxEmailTemplatesFileSize = 64 << 10

// EmailTemplate contains copy inserted into GoAuthy's fixed password layouts.
// It intentionally does not accept user-authored template programs.
type EmailTemplate struct {
	Subject              string
	Header               string
	Text                 string
	ClickLink            string
	Validity             string
	Expires              string
	Button               string
	Footer               string
	ButtonTextRequestNew string
}

// EmailTemplates contains password-event copy indexed by Rauthy language.
type EmailTemplates struct {
	passwordReset      map[string]EmailTemplate
	passwordNew        map[string]EmailTemplate
	registeredAlready  map[string]EmailTemplate
	emailChangeConfirm map[string]EmailTemplate
}

// PasswordReset returns the selected reset copy, falling back to English.
func (t EmailTemplates) PasswordReset(lang string) EmailTemplate {
	if template, err := t.PasswordResetExact(lang); err == nil {
		return template
	}
	return defaultEmailTemplates().passwordReset["en"]
}

// PasswordResetExact returns copy only for a configured Rauthy language.
// Use it at startup where an unsupported configured language must fail closed.
func (t EmailTemplates) PasswordResetExact(lang string) (EmailTemplate, error) {
	template, ok := t.passwordReset[lang]
	if !ok {
		return EmailTemplate{}, fmt.Errorf("unsupported email template language %q", lang)
	}
	return template, nil
}

// PasswordNew returns selected new-password copy, falling back to English.
func (t EmailTemplates) PasswordNew(lang string) EmailTemplate {
	if template, err := t.PasswordNewExact(lang); err == nil {
		return template
	}
	return defaultEmailTemplates().passwordNew["en"]
}

// PasswordNewExact returns copy only for a configured Rauthy language.
func (t EmailTemplates) PasswordNewExact(lang string) (EmailTemplate, error) {
	template, ok := t.passwordNew[lang]
	if !ok {
		return EmailTemplate{}, fmt.Errorf("unsupported email template language %q", lang)
	}
	return template, nil
}

// AlreadyRegistered returns selected existing-account notice copy, falling
// back to English.
func (t EmailTemplates) AlreadyRegistered(lang string) EmailTemplate {
	if template, err := t.AlreadyRegisteredExact(lang); err == nil {
		return template
	}
	return defaultEmailTemplates().registeredAlready["en"]
}

// AlreadyRegisteredExact returns copy only for a configured Rauthy language.
func (t EmailTemplates) AlreadyRegisteredExact(lang string) (EmailTemplate, error) {
	template, ok := t.registeredAlready[lang]
	if !ok {
		return EmailTemplate{}, fmt.Errorf("unsupported email template language %q", lang)
	}
	return template, nil
}

func (t EmailTemplates) EmailChangeConfirm(lang string) EmailTemplate {
	if template, err := t.EmailChangeConfirmExact(lang); err == nil {
		return template
	}
	return defaultEmailChangeTemplates()["en"]
}

func (t EmailTemplates) EmailChangeConfirmExact(lang string) (EmailTemplate, error) {
	template, ok := t.emailChangeConfirm[lang]
	if !ok {
		return EmailTemplate{}, fmt.Errorf("unsupported email template language %q", lang)
	}
	return template, nil
}

func (t EmailTemplates) TemplateTypes() []string {
	return []string{"password_reset", "password_new", "registered_already", "email_change_confirm"}
}

func (t EmailTemplates) TemplateLanguages(typ string) []string {
	var source map[string]EmailTemplate
	switch typ {
	case "password_reset":
		source = t.passwordReset
	case "password_new":
		source = t.passwordNew
	case "registered_already":
		source = t.registeredAlready
	case "email_change_confirm":
		source = t.emailChangeConfirm
	default:
		return nil
	}
	langs := make([]string, 0, len(source))
	for lang := range source {
		langs = append(langs, lang)
	}
	return langs
}

// LoadEmailTemplates loads strict Rauthy-compatible password-event copy
// overrides. An empty path returns built-in defaults.
func LoadEmailTemplates(path string) (EmailTemplates, error) {
	templates := defaultEmailTemplates()
	if path == "" {
		return templates, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return EmailTemplates{}, fmt.Errorf("open email templates: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxEmailTemplatesFileSize+1))
	if err != nil {
		return EmailTemplates{}, fmt.Errorf("read email templates: %w", err)
	}
	if len(data) > maxEmailTemplatesFileSize {
		return EmailTemplates{}, fmt.Errorf("email templates file exceeds %d bytes", maxEmailTemplatesFileSize)
	}

	var config emailTemplatesFile
	decoder := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return EmailTemplates{}, fmt.Errorf("decode email templates: %w", err)
	}
	seen := make(map[string]struct{}, len(config.Templates))
	for _, override := range config.Templates {
		var target map[string]EmailTemplate
		switch override.Type {
		case "password_reset":
			target = templates.passwordReset
		case "password_new":
			target = templates.passwordNew
		case "registered_already":
			target = templates.registeredAlready
		case "email_change_confirm":
			target = templates.emailChangeConfirm
		default:
			return EmailTemplates{}, errors.New("unsupported email template type")
		}
		if _, ok := target[override.Language]; !ok {
			return EmailTemplates{}, fmt.Errorf("unsupported email template language %q", override.Language)
		}
		key := override.Type + "\x00" + override.Language
		if _, ok := seen[key]; ok {
			return EmailTemplates{}, fmt.Errorf("duplicate email template %s/%s", override.Type, override.Language)
		}
		seen[key] = struct{}{}
		template := target[override.Language]
		override.apply(&template)
		if hasCRLF(template.Subject) {
			return EmailTemplates{}, errors.New("email template subject must not contain a newline")
		}
		target[override.Language] = template
	}
	return templates, nil
}

type emailTemplatesFile struct {
	Templates []emailTemplateOverride `toml:"templates"`
}

type emailTemplateOverride struct {
	Language             string  `toml:"lang"`
	Type                 string  `toml:"typ"`
	Subject              *string `toml:"subject"`
	Header               *string `toml:"header"`
	Text                 *string `toml:"text"`
	ClickLink            *string `toml:"click_link"`
	Validity             *string `toml:"validity"`
	Expires              *string `toml:"expires"`
	Footer               *string `toml:"footer"`
	ButtonTextRequestNew *string `toml:"button_text_request_new"`
}

func (o emailTemplateOverride) apply(template *EmailTemplate) {
	if o.Subject != nil {
		template.Subject = *o.Subject
	}
	if o.Header != nil {
		template.Header = *o.Header
	}
	if o.Text != nil {
		template.Text = *o.Text
	}
	if o.ClickLink != nil {
		template.ClickLink = *o.ClickLink
	}
	if o.Validity != nil {
		template.Validity = *o.Validity
	}
	if o.Expires != nil {
		template.Expires = *o.Expires
	}
	if o.Footer != nil {
		template.Footer = *o.Footer
	}
	if o.ButtonTextRequestNew != nil {
		template.ButtonTextRequestNew = *o.ButtonTextRequestNew
	}
}

func defaultEmailTemplates() EmailTemplates {
	return EmailTemplates{emailChangeConfirm: defaultEmailChangeTemplates(), passwordReset: map[string]EmailTemplate{
		"de":      {"Passwort Reset angefordert", "Passwort Reset angefordert für", "", "Klicken Sie auf den unten stehenden Link für den Passwort Reset.", "Dieser Link ist aus Sicherheitsgründen nur für kurze Zeit gültig.", "Link gültig bis:", "Passwort Zurücksetzen", "Sollte der Link abgelaufen sein, kann ein neuer angefordert werden.", "Neuen Link Anfordern"},
		"en":      {"Password Reset Request", "Password reset request for", "", "Click the link below to get forwarded to the password request form.", "This link is only valid for a short period of time for security reasons.", "Link expires:", "Reset Password", "If this link has expired, you can request a new one.", "Request New Link"},
		"fr":      {"Demande de réinitialisation du mot de passe", "Demande de réinitialisation du mot de passe pour", "", "Cliquez sur le lien ci-dessous pour être redirigé vers le formulaire de demande de mot de passe.", "Ce lien n'est valable que pendant une courte période pour des raisons de sécurité.", "Le lien expire :", "Réinitialiser le mot de passe", "Si ce lien a expiré, vous pouvez en demander un nouveau.", "Demander un nouveau lien"},
		"ko":      {"비밀번호 초기화 요청", "비밀번호 초기화 요청:", "", "비밀번호 초기화 요청 창으로 이동하려면, 아래의 링크를 클릭해 주세요.", "이 링크는 보안상의 이유로 짧은 시간 동안에만 유효합니다.", "링크 만료일:", "비밀번호 초기화", "If this link has expired, you can request a new one.", "Request New Link"},
		"nb":      {"Passordtilbakestilling etterspurt", "Passordtilbakestilling etterspurt for", "", "Klikk på lenken under for å tilbakestille passordet.", "Denne lenken er kun gyldig i en kort periode av sikkerhetsgrunner.", "Lenken utløper:", "Tilbakestill passord", "Hvis lenken har utløpt, kan du be om en ny.", "Be om ny lenke"},
		"nl":      {"Wachtwoordreset aangevraagd", "Wachtwoordreset aangevraagd voor", "", "Klik op de onderstaande link om uw wachtwoord te resetten.", "Deze link is om veiligheidsredenen slechts korte tijd geldig.", "Link vervalt:", "Wachtwoord resetten", "Als deze link is verlopen, kunt u een nieuwe aanvragen.", "Nieuwe link aanvragen"},
		"ru":      {"Запрос на сброс пароля", "Запрос на сброс пароля для", "", "Нажмите на ссылку ниже, чтобы перейти к форме сброса пароля.", "Из соображений безопасности эта ссылка действительна только в течение короткого времени.", "Ссылка действительна до:", "Сбросить пароль", "Если срок действия ссылки истёк, вы можете запросить новую.", "Запросить новую ссылку"},
		"uk":      {"Запит на скидання пароля", "Запит на скидання пароля для", "", "Натисніть посилання нижче, щоб перейти до форми скидання пароля.", "З міркувань безпеки це посилання дійсне лише протягом короткого часу.", "Посилання дійсне до:", "Скинути пароль", "Якщо термін дії посилання минув, ви можете запросити нове.", "Запросити нове посилання"},
		"zh_hans": {"密码重置请求", "密码重置请求：", "", "点击下方链接以打开密码重置表单。", "出于安全考虑，此链接仅在短时间内有效。", "链接过期时间", "重置密码", "If this link has expired, you can request a new one.", "Request New Link"},
	}, passwordNew: map[string]EmailTemplate{
		"de":      {"Neues Passwort", "Neues Passwort für", "", "Klicken Sie auf den unten stehenden Link um ein neues Passwort zu setzen.", "Dieser Link ist aus Sicherheitsgründen nur für kurze Zeit gültig.", "Link gültig bis:", "Passwort Setzen", "", ""},
		"en":      {"New Password", "New password for", "", "Click the link below to get forwarded to the password form.", "This link is only valid for a short period of time for security reasons.", "Link expires:", "Set Password", "", ""},
		"fr":      {"Nouveau mot de passe", "Nouveau mot de passe pour", "", "Cliquez sur le lien ci-dessous pour être redirigé vers le formulaire de mot de passe.", "Ce lien n'est valable que pendant une courte période pour des raisons de sécurité.", "Le lien expire :", "Définir le mot de passe", "", ""},
		"ko":      {"새 비밀번호", "새 비밀번호를 설정해 주세요:", "", "비밀번호 입력창으로 이동하려면, 아래의 링크를 클릭해 주세요.", "이 링크는 보안상의 이유로 짧은 시간 동안에만 유효합니다.", "링크 만료일:", "비밀번호 설정", "", ""},
		"nb":      {"Ny passord", "Ny passord for", "", "Klikk på lenken under for å sette et nytt passord.", "Denne lenken er kun gyldig i en kort periode av sikkerhetsgrunner.", "Lenken gyldig til:", "Sett passord", "", ""},
		"nl":      {"Nieuw wachtwoord", "Nieuw wachtwoord voor", "", "Klik op de onderstaande link om een nieuw wachtwoord in te stellen.", "Deze link is om veiligheidsredenen slechts korte tijd geldig.", "Link geldig tot:", "Wachtwoord instellen", "", ""},
		"ru":      {"Новый пароль", "Новый пароль для", "", "Нажмите на ссылку ниже, чтобы перейти к форме установки пароля.", "Из соображений безопасности эта ссылка действительна только в течение короткого времени.", "Ссылка действительна до:", "Установить пароль", "", ""},
		"uk":      {"Новий пароль", "Новий пароль для", "", "Натисніть посилання нижче, щоб перейти до форми встановлення пароля.", "З міркувань безпеки це посилання дійсне лише протягом короткого часу.", "Посилання дійсне до:", "Встановити пароль", "", ""},
		"zh_hans": {"新密码", "新密码", "", "点击下方链接以打开密码设置表单。", "出于安全考虑，此链接仅在短时间内有效。", "链接过期时间：", "设置密码", "", ""},
	}, registeredAlready: map[string]EmailTemplate{
		"de":      {"E-Mail bereits registriert", "E-Mail bereits registriert - ", "Es wurde versucht einen neuen Account mit dieser E-Mail Adresse zu registrieren,\nwährend diese Adresse bereits registriert war. Falls dies ein Fehler war, kann diese\nE-Mail ignoriert werden. Sollte jedoch das Passwort verloren gegangen sein und ein\nneues wird benötigt, so kann der unten stehende Link dafür genutzt werden.\nFalls diese Nachricht durch jemand Anderen ausgelöst wurde - keine Sorge, der Account\nis sicher und es gab keinerlei Datenlecks.", "", "", "", "", "", "Passwort-Zurücksetzen Link anfordern"},
		"en":      {"E-Mail registered already", "E-Mail registered already - ", "Someone tried to register a new account with your E-Mail address\nwhile an account exists already. If that was you, and it was a mistake, you\ncan ignore this message. However, if you forgot your password, you can use\nthe link below to reset it.\nIf it was not you trying to register the new account - no need to worry.\nYour account has not been compromised and no data was leaked.", "", "", "", "", "", "Request password reset Link"},
		"fr":      {"e-mail déjà enregistré", "e-mail déjà enregistré - ", "Quelqu'un a essayé d'enregistrer un nouveau compte avec votre adresse e-mail\nalors qu'un compte existe déjà. Si c'était vous et que c'était une erreur, vous pouvez ignorer ce message.\nCependant, si vous avez oublié votre mot de passe,\nvous pouvez utiliser le lien ci-dessous pour le réinitialiser.\nSi ce n'est pas vous qui essayez d'enregistrer le nouveau compte, ne vous inquiétez pas.\nVotre compte n'a pas été compromis et aucune donnée n'a été divulguée.", "", "", "", "", "", "Demander un lien de réinitialisation du mot de passe"},
		"ko":      {"E-Mail registered already", "E-Mail registered already - ", "Someone tried to register a new account with your E-Mail address\nwhile an account exists already. If that was you, and it was a mistake, you\ncan ignore this message. However, if you forgot your password, you can use\nthe link below to reset it.\nIf it was not you trying to register the new account - no need to worry.\nYour account has not been compromised and no data was leaked.", "", "", "", "", "", "Request password reset Link"},
		"nb":      {"E-Mail registered already", "E-Mail registered already - ", "Someone tried to register a new account with your E-Mail address\nwhile an account exists already. If that was you, and it was a mistake, you\ncan ignore this message. However, if you forgot your password, you can use\nthe link below to reset it.\nIf it was not you trying to register the new account - no need to worry.\nYour account has not been compromised and no data was leaked.", "", "", "", "", "", "Request password reset Link"},
		"nl":      {"E-Mail al geregistreerd", "E-Mail al geregistreerd - ", "Iemand heeft geprobeerd een nieuw account te registreren met uw e-mailadres,\nterwijl er al een account bestaat. Als u dat zelf was en het een vergissing was, kunt u\ndit bericht negeren. Als u echter uw wachtwoord bent vergeten, kunt u\nde onderstaande link gebruiken om het te resetten.\nAls u zelf niet probeerde een nieuw account te registreren - geen zorgen.\nUw account is niet gecompromitteerd en er zijn geen gegevens gelekt.", "", "", "", "", "", "Wachtwoordreset link aanvragen"},
		"ru":      {"E-Mail уже зарегистрирован", "E-Mail уже зарегистрирован - ", "Кто-то попытался зарегистрировать новый аккаунт с вашим адресом E-Mail,\nв то время как аккаунт уже существует. Если это были вы и произошла ошибка,\nможете проигнорировать это сообщение. Однако если вы забыли пароль, вы можете\nвоспользоваться ссылкой ниже для его сброса.\nЕсли регистрацию пытался выполнить кто-то другой — не беспокойтесь.\nВаш аккаунт не был скомпрометирован и утечки данных не произошло.", "", "", "", "", "", "Запросить ссылку для сброса пароля"},
		"uk":      {"E-Mail registered already", "E-Mail registered already - ", "Someone tried to register a new account with your E-Mail address\nwhile an account exists already. If that was you, and it was a mistake, you\ncan ignore this message. However, if you forgot your password, you can use\nthe link below to reset it.\nIf it was not you trying to register the new account - no need to worry.\nYour account has not been compromised and no data was leaked.", "", "", "", "", "", "Request password reset Link"},
		"zh_hans": {"E-Mail registered already", "E-Mail registered already - ", "Someone tried to register a new account with your E-Mail address\nwhile an account exists already. If that was you, and it was a mistake, you\ncan ignore this message. However, if you forgot your password, you can use\nthe link below to reset it.\nIf it was not you trying to register the new account - no need to worry.\nYour account has not been compromised and no data was leaked.", "", "", "", "", "", "Request password reset Link"},
	}}
}

func validEmailTemplate(template EmailTemplate) bool {
	return template.Subject != "" && !hasCRLF(template.Subject)
}
