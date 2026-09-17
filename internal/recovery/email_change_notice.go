package recovery

import (
	"context"
	"errors"
	"html/template"
	"strings"
	texttemplate "text/template"

	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/identity"
)

// EmailChangeMessage is a notice of a committed administrator action, not a
// self-service confirmation challenge. No bearer token or action link is sent.
type EmailChangeMessage struct{ To, NewEmail, Language string }

// NotifyUserUpdate runs only after the caller has committed the update. Mail
// failures cannot undo that mutation or suppress an attempt to the other address.
// Like other recovery notices, delivery is best effort, not a durable outbox.
func (s *Service) NotifyUserUpdate(ctx context.Context, result identity.UserUpdateResult) {
	if s == nil || !result.EmailChanged || result.OldEmail == result.Email {
		return
	}
	for _, address := range []string{result.Email, result.OldEmail} {
		if address == "" {
			continue
		} // A legacy user may not have had an email.
		if err := s.sender.SendEmailChange(ctx, EmailChangeMessage{To: address, NewEmail: result.Email, Language: result.Language}); err != nil && s.OnError != nil {
			s.OnError(errors.New("email change notification delivery failed"))
		}
	}
}

var emailChangeText = texttemplate.Must(texttemplate.New("email-change.txt").Parse("{{.Header}}\n\n{{.Text}}\n{{.NewEmail}}\n\n{{.Footer}}\n"))
var emailChangeHTML = template.Must(template.New("email-change.html").Parse(`<!doctype html><html><head><meta charset="utf-8"></head><body><h1>{{.Header}}</h1><p>{{.Text}}</p><p>{{.NewEmail}}</p><p>{{.Footer}}</p></body></html>`))

func (s *SMTPSender) SendEmailChange(ctx context.Context, message EmailChangeMessage) error {
	if s == nil || s.send == nil {
		return errors.New("SMTP sender unavailable")
	}
	email, err := canonicalEmail(message.NewEmail)
	if err != nil || email != message.NewEmail {
		return ErrInvalidEmail
	}
	lang := message.Language
	if lang == "" {
		lang = "en"
	}
	if !i18n.ValidUserLanguage(lang) {
		return errors.New("invalid user language")
	}
	if lang == "zhhans" {
		lang = "zh_hans"
	}
	copy, ok := s.config.Templates.emailChangeConfirm[lang]
	if !ok || !validEmailTemplate(copy) {
		return errors.New("invalid email change template")
	}
	data := struct {
		EmailTemplate
		NewEmail string
	}{copy, email}
	var text, html strings.Builder
	if err := emailChangeText.Execute(&text, data); err != nil {
		return err
	}
	if err := emailChangeHTML.Execute(&html, data); err != nil {
		return err
	}
	return s.sendRenderedMessage(ctx, message.To, copy, text.String(), html.String())
}

// Copy adapted from Rauthy v0.36.2, src/data/src/email/i18n/confirm_change.rs
// (Apache-2.0). Text is msg and Footer is msg_from_admin in the upstream layout.
func defaultEmailChangeTemplates() map[string]EmailTemplate {
	return map[string]EmailTemplate{
		"de":      {Subject: "E-Mail Wechsel bestätigt für", Header: "E-Mail Wechsel bestätigt für", Text: "Ihre E-Mail Adresse wurde erfolgreich geändert zu:", Footer: "Diese Änderung wurde durch einen Administrator durchgeführt."},
		"en":      {Subject: "E-Mail Change confirmed for", Header: "E-Mail Change confirmed for", Text: "Your E-Mail address has been changed successfully to:", Footer: "This action was done by an Administrator."},
		"fr":      {Subject: "Changement d'adresse e-mail confirmé pour", Header: "Changement d'adresse e-mail confirmé pour", Text: "Votre adresse e-mail a été modifiée avec succès et est désormais :", Footer: "Cette action a été effectuée par un administrateur."},
		"nb":      {Subject: "Epostbytte bekreftet for", Header: "Epostbytte bekreftet for", Text: "Din epostadresse har blitt endret til:", Footer: "Denne endringen ble gjort av en administrator."},
		"nl":      {Subject: "E-Mail wijziging bevestigd voor", Header: "E-Mail wijziging bevestigd voor", Text: "Uw e-mailadres is succesvol gewijzigd naar:", Footer: "Deze actie is uitgevoerd door een beheerder."},
		"ko":      {Subject: "이메일 변경이 승인되었습니다:", Header: "이메일 변경이 승인되었습니다:", Text: "이메일 주소가 다음 주소로 성공적으로 변경되었습니다:", Footer: "이 작업은 관리자가 수행했습니다."},
		"uk":      {Subject: "Зміну E-mail підтверджено для", Header: "Зміну E-mail підтверджено для", Text: "Вашу адресу E-mail було успішно змінено на:", Footer: "Цю дію було виконано адміністратором."},
		"ru":      {Subject: "Смена E-Mail подтверждена для", Header: "Смена E-Mail подтверждена для", Text: "Ваш адрес E-Mail был успешно изменён на:", Footer: "Это действие было выполнено администратором."},
		"zh_hans": {Subject: "电子邮件地址已更新：", Header: "电子邮件地址已更新：", Text: "您的电子邮件地址已成功更新为：", Footer: "此操作由管理员完成。"},
	}
}
