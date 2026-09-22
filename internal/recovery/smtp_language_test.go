package recovery

import (
	"context"
	"html"
	"mime"
	stdmail "net/mail"
	"strings"
	"testing"
	"time"

	mail "github.com/wneessen/go-mail"
)

func TestSMTPSenderLanguageCatalogRenderedSubjects(t *testing.T) {
	t.Parallel()
	s, err := NewSMTPSender(SMTPConfig{Host: "smtp.example.test", Port: 587, From: "support@example.test", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	langs := []string{"de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans"}
	for _, lang := range langs {
		for _, event := range []string{"reset", "new", "already"} {
			var got *stdmail.Message
			s.send = func(_ context.Context, msg *mail.Msg) error {
				var b strings.Builder
				if _, e := msg.WriteTo(&b); e != nil {
					return e
				}
				parsed, e := stdmail.ReadMessage(strings.NewReader(b.String()))
				got = parsed
				return e
			}
			m := Message{To: "user@example.test", Language: lang, ResetURL: "https://auth.example.test/reset/token", ExpiresAt: time.Unix(1700000000, 0)}
			var e error
			switch event {
			case "reset":
				e = s.SendPasswordReset(context.Background(), m)
			case "new":
				e = s.SendPasswordNew(context.Background(), m)
			default:
				e = s.SendAlreadyRegistered(context.Background(), m)
			}
			if e != nil || got == nil {
				t.Fatalf("%s/%s send=%v got=%v", lang, event, e, got)
			}
			catalogLang := lang
			if catalogLang == "zhhans" {
				catalogLang = "zh_hans"
			}
			catalog := defaultEmailTemplates()
			want := catalog.PasswordReset(catalogLang).Subject
			if event == "new" {
				want = catalog.PasswordNew(catalogLang).Subject
			}
			if event == "already" {
				want = catalog.AlreadyRegistered(catalogLang).Subject
			}
			decoded, _ := new(mime.WordDecoder).DecodeHeader(got.Header.Get("Subject"))
			if decoded != want {
				t.Fatalf("%s/%s subject=%q want=%q", lang, event, got.Header.Get("Subject"), want)
			}
			plain, markup := multipartBodies(t, got)
			plain = strings.ReplaceAll(plain, "\r\n", "\n")
			markup = strings.ReplaceAll(markup, "\r\n", "\n")
			selected := catalog.PasswordReset(catalogLang)
			if event == "new" {
				selected = catalog.PasswordNew(catalogLang)
			}
			if event == "already" {
				selected = catalog.AlreadyRegistered(catalogLang)
			}
			if !strings.Contains(plain, selected.Header) || !strings.Contains(markup, html.EscapeString(selected.Header)) || !strings.Contains(plain, selected.Text) || !strings.Contains(markup, html.EscapeString(selected.Text)) {
				t.Fatalf("%s/%s selected body missing template copy", lang, event)
			}
		}
	}
}

func TestSMTPSenderLanguageFallbackOverrideAndReject(t *testing.T) {
	t.Parallel()
	config := SMTPConfig{Host: "smtp.example.test", Port: 587, From: "support@example.test", Timeout: time.Second, Templates: defaultEmailTemplates()}
	copyFor := func(label string) EmailTemplate {
		return EmailTemplate{Subject: label + " subject", Header: label + " header", Text: label + " body"}
	}
	config.Template = copyFor("legacy reset")
	config.PasswordNewTemplate = copyFor("legacy new")
	config.AlreadyRegisteredTemplate = copyFor("legacy already")
	config.Templates.passwordReset["en"] = copyFor("override reset")
	config.Templates.passwordNew["en"] = copyFor("override new")
	config.Templates.registeredAlready["en"] = copyFor("override already")
	s, err := NewSMTPSender(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range []struct {
		name string
		send func(context.Context, Message) error
	}{
		{"reset", s.SendPasswordReset}, {"new", s.SendPasswordNew}, {"already", s.SendAlreadyRegistered},
	} {
		for _, language := range []string{"", "en", "xx", "zh_hans"} {
			var got *stdmail.Message
			sends := 0
			s.send = func(_ context.Context, msg *mail.Msg) error {
				sends++
				var b strings.Builder
				if _, err := msg.WriteTo(&b); err != nil {
					return err
				}
				var err error
				got, err = stdmail.ReadMessage(strings.NewReader(b.String()))
				return err
			}
			err := event.send(context.Background(), Message{To: "user@example.test", Language: language, ResetURL: "https://auth.example.test/reset/token", ExpiresAt: time.Unix(1700000000, 0)})
			if language == "xx" || language == "zh_hans" {
				if err == nil || sends != 0 {
					t.Fatalf("%s/%s invalid language sent=%d err=%v", event.name, language, sends, err)
				}
				continue
			}
			if err != nil || sends != 1 || got == nil {
				t.Fatalf("%s/%s sends=%d err=%v", event.name, language, sends, err)
			}
			prefix := "override "
			if language == "" {
				prefix = "legacy "
			}
			want := copyFor(prefix + event.name)
			subject, err := new(mime.WordDecoder).DecodeHeader(got.Header.Get("Subject"))
			plain, markup := multipartBodies(t, got)
			if err != nil || subject != want.Subject || !strings.Contains(plain, want.Text) || !strings.Contains(markup, want.Text) || !strings.Contains(plain, want.Header) || !strings.Contains(markup, want.Header) {
				t.Fatalf("%s/%s wrong rendered template", event.name, language)
			}
		}
	}
	delete(config.Templates.passwordReset, "de")
	if _, err := NewSMTPSender(config); err == nil {
		t.Fatal("missing catalogue language accepted")
	}
}
