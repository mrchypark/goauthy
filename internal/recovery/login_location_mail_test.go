package recovery

import (
	"context"
	"errors"
	"html"
	"mime"
	stdmail "net/mail"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/branding"
	mail "github.com/wneessen/go-mail"
)

func TestSendLoginLocationUsesSMTPFixtureAndEscapesDynamicHTML(t *testing.T) {
	t.Parallel()
	address, received := startSMTPFixture(t)
	host, port := splitSMTPAddress(t, address)
	sender, err := NewSMTPSender(SMTPConfig{Host: host, Port: port, From: "support@example.test", Timeout: time.Second, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	ua := `<img src=x onerror="alert(1)"> &`
	if err := sender.SendLoginLocation(context.Background(), validLoginLocationMessage("en", ua, nil)); err != nil {
		t.Fatalf("SendLoginLocation() error = %v", err)
	}
	raw := <-received
	message, err := stdmail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := message.Header.Get("To"), "<user@example.test>"; got != want {
		t.Fatalf("To = %q, want %q", got, want)
	}
	if got, want := message.Header.Get("Subject"), "- Security Warning"; got != want {
		t.Fatalf("Subject = %q, want %q", got, want)
	}
	plain, markup := multipartBodies(t, message)
	if !strings.Contains(plain, "IP: 203.0.113.7") || !strings.Contains(plain, ua) || !strings.Contains(plain, "Revoke Access:") || !strings.Contains(plain, "Account Dashboard:") || strings.Contains(strings.ToLower(plain), "expir") {
		t.Fatal("unexpected plain login-location body")
	}
	if strings.Contains(markup, "<img src=x") || strings.Contains(markup, ua) || !strings.Contains(markup, html.EscapeString(ua)) || strings.Contains(markup, "()") {
		t.Fatal("unsafe or incorrect HTML login-location body")
	}
}

func TestSendLoginLocationMIMEUsesSubjectPrefixAndPinnedTemplate(t *testing.T) {
	t.Parallel()
	address, received := startSMTPFixture(t)
	host, port := splitSMTPAddress(t, address)
	sender, err := NewSMTPSender(SMTPConfig{Host: host, Port: port, From: "support@example.test", Timeout: time.Second, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	message := validLoginLocationMessage("en", "Mozilla/5.0", nil)
	message.SubjectPrefix = " GoAuthy "
	if err := sender.SendLoginLocation(context.Background(), message); err != nil {
		t.Fatalf("SendLoginLocation() error = %v", err)
	}
	raw := <-received
	parsed, err := stdmail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := parsed.Header.Get("Subject"), "GoAuthy  - Security Warning"; got != want {
		t.Fatalf("Subject = %q, want %q", got, want)
	}
	_, markup := multipartBodies(t, parsed)
	if !strings.Contains(markup, "<style>") || !strings.Contains(markup, "<title>E-Mail Reset</title>") {
		t.Fatal("delivered HTML did not contain the pinned base template")
	}
}

func TestSendLoginLocationRejectsInvalidTypedThemeBeforeSMTP(t *testing.T) {
	t.Parallel()
	sender := testSMTPSender(t)
	sender.send = func(context.Context, *mail.Msg) error {
		t.Fatal("invalid typed theme reached SMTP send hook")
		return nil
	}
	theme := branding.DefaultTheme("client-1")
	theme.Light.BtnText = "white;body{display:none}"
	message := validLoginLocationMessage("en", "Mozilla/5.0", nil)
	message.Theme = &theme
	if err := sender.SendLoginLocation(context.Background(), message); !errors.Is(err, branding.ErrInvalidTheme) {
		t.Fatalf("invalid typed theme error=%v, want %v", err, branding.ErrInvalidTheme)
	}
}

func TestSendLoginLocationRendersLocationAndAllLanguages(t *testing.T) {
	t.Parallel()
	sender := testSMTPSender(t)
	location := `Seoul <&>`
	for _, language := range []string{"de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans"} {
		var got *stdmail.Message
		var wire strings.Builder
		message := validLoginLocationMessage(language, "Mozilla/5.0", &location)
		message.SubjectPrefix = "GoAuthy"
		sender.send = func(_ context.Context, msg *mail.Msg) error {
			_, err := msg.WriteTo(&wire)
			return err
		}
		if err := sender.SendLoginLocation(context.Background(), message); err != nil {
			t.Fatalf("language %s: %v", language, err)
		}
		got, err := stdmail.ReadMessage(strings.NewReader(wire.String()))
		if err != nil {
			t.Fatal(err)
		}
		copy := loginLocationCopies[language]
		if language == "zhhans" {
			copy = loginLocationCopies["zh_hans"]
		}
		subject, err := new(mime.WordDecoder).DecodeHeader(got.Header.Get("Subject"))
		wantSubject := "GoAuthy - " + copy.Subject
		if err != nil || subject != wantSubject {
			t.Fatalf("language %s subject = %q, want %q", language, subject, wantSubject)
		}
		plain, markup := multipartBodies(t, got)
		if !strings.Contains(plain, copy.UnknownLocation) || !strings.Contains(plain, copy.RevokeLink) || !strings.Contains(markup, html.EscapeString(location)) {
			t.Fatalf("language %s missing rendered copy", language)
		}
	}
}

func TestSendLoginLocationRejectsInvalidLinksWithoutLeakingCode(t *testing.T) {
	t.Parallel()
	sender := testSMTPSender(t)
	sends := 0
	sender.send = func(_ context.Context, _ *mail.Msg) error {
		sends++
		return nil
	}
	code := strings.Repeat("A", 48)
	for _, tc := range []struct {
		name    string
		message LoginLocationMessage
		needle  string
	}{
		{"short code", validLoginLocationMessage("en", "ua", nil), code[:47]},
		{"non alphanumeric code", validLoginLocationMessage("en", "ua", nil), ""},
		{"wrong query IP", validLoginLocationMessage("en", "ua", nil), "203.0.113.8"},
		{"wrong issuer base", validLoginLocationMessage("en", "ua", nil), ""},
		{"account query", validLoginLocationMessage("en", "ua", nil), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			message := tc.message
			switch tc.name {
			case "short code":
				message.RevokeURL = strings.Replace(message.RevokeURL, code, tc.needle, 1)
			case "non alphanumeric code":
				message.RevokeURL = strings.Replace(message.RevokeURL, code, strings.Repeat("A", 47)+"!", 1)
			case "wrong query IP":
				message.RevokeURL = strings.Replace(message.RevokeURL, "203.0.113.7", tc.needle, 1)
			case "wrong issuer base":
				message.RevokeURL = strings.Replace(message.RevokeURL, "/base/auth/", "/other/auth/", 1)
			case "account query":
				message.AccountURL += "?next=https://evil.example"
			}
			before := sends
			err := sender.SendLoginLocation(context.Background(), message)
			if err == nil || sends != before || strings.Contains(err.Error(), code) {
				t.Fatalf("accepted or leaked invalid login-location message: sends=%d err=%v", sends-before, err)
			}
		})
	}
}

func validLoginLocationMessage(language, userAgent string, location *string) LoginLocationMessage {
	code := strings.Repeat("A", 48)
	return LoginLocationMessage{
		To:         "USER@Example.Test",
		Language:   language,
		IP:         "203.0.113.7",
		UserAgent:  userAgent,
		Location:   location,
		RevokeURL:  "https://auth.example.test/base/auth/v1/users/alice/revoke/" + code + "?ip=203.0.113.7",
		AccountURL: "https://auth.example.test/base/auth/v1/account",
	}
}
