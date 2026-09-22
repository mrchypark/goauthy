package recovery

import (
	"context"
	"errors"
	"mime"
	"net"
	stdmail "net/mail"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/identity"
	mail "github.com/wneessen/go-mail"
)

func TestNotifyUserUpdateBothAddressesAndFailures(t *testing.T) {
	t.Parallel()
	s, sender := testService(t, "notice-user", "notice-user")
	ctx := context.Background()
	if err := s.BindEmail(ctx, "notice-user", "old@example.test"); err != nil {
		t.Fatal(err)
	}
	lang := "ko"
	result, err := s.identity.UpdateUserWithGuard(ctx, "notice-user", identity.UserUpdate{Email: "new@example.test", Language: &lang, Enabled: true, EmailVerified: true}, func() (string, []any) { return "1=1", nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(sender.changed) != 0 {
		t.Fatal("store sent mail before caller's post-commit notification")
	}
	sender.err = errors.New("private SMTP error")
	failures := 0
	s.OnError = func(err error) {
		failures++
		if err.Error() != "email change notification delivery failed" {
			t.Fatal("sender details leaked")
		}
	}
	s.NotifyUserUpdate(ctx, result)
	want := []EmailChangeMessage{{To: "new@example.test", NewEmail: "new@example.test", Language: "ko"}, {To: "old@example.test", NewEmail: "new@example.test", Language: "ko"}}
	if !reflect.DeepEqual(sender.changed, want) || failures != 2 {
		t.Fatalf("wrong recipients or suppressed second attempt: messages=%d failures=%d", len(sender.changed), failures)
	}
	result.EmailChanged = false
	s.NotifyUserUpdate(ctx, result)
	if len(sender.changed) != 2 {
		t.Fatal("unchanged email produced notice")
	}
	// Delivery failure does not undo the committed profile.
	sender.err = nil
	if err := s.IssueForSubject(ctx, "notice-user"); err != nil {
		t.Fatal(err)
	}
	if sent := sender.messages(); len(sent) != 1 || sent[0].To != "new@example.test" {
		t.Fatal("committed recovery address lost")
	}
}

func TestEmailChangeSMTPNineLanguagesAndEscaping(t *testing.T) {
	t.Parallel()
	s := testSMTPSender(t)
	for _, lang := range []string{"de", "en", "fr", "ko", "nb", "nl", "ru", "uk", "zhhans"} {
		s.send = func(_ context.Context, msg *mail.Msg) error {
			var raw strings.Builder
			if _, err := msg.WriteTo(&raw); err != nil {
				return err
			}
			parsed, err := stdmail.ReadMessage(strings.NewReader(raw.String()))
			if err != nil {
				return err
			}
			plain, html := multipartBodies(t, parsed)
			catalogLang := lang
			if lang == "zhhans" {
				catalogLang = "zh_hans"
			}
			copy := defaultEmailChangeTemplates()[catalogLang]
			subject, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
			if err != nil || subject != copy.Subject || !strings.Contains(plain, copy.Text) || !strings.Contains(plain, copy.Footer) || !strings.Contains(plain, "a&b@example.test") {
				t.Fatalf("incorrect %s notice", lang)
			}
			if !strings.Contains(html, "a&amp;b@example.test") || strings.Contains(html, "href=") || strings.Contains(plain, "/reset/") {
				t.Fatal("unsafe or actionable email-change notice")
			}
			if parsed.Header.Get("To") != "<old@example.test>" && parsed.Header.Get("To") != "old@example.test" {
				t.Fatalf("unexpected recipient header %q", parsed.Header.Get("To"))
			}
			return nil
		}
		if err := s.SendEmailChange(context.Background(), EmailChangeMessage{To: "old@example.test", NewEmail: "a&b@example.test", Language: lang}); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	s.send = func(context.Context, *mail.Msg) error { calls++; return nil }
	for _, bad := range []EmailChangeMessage{{To: "old@example.test", NewEmail: "new@example.test", Language: "unknown"}, {To: "old@example.test", NewEmail: "not an email", Language: "en"}, {To: "not an email", NewEmail: "new@example.test", Language: "en"}} {
		if err := s.SendEmailChange(context.Background(), bad); err == nil {
			t.Fatal("accepted invalid notice")
		}
	}
	if calls != 0 {
		t.Fatal("invalid notice reached SMTP")
	}
}

func TestEmailChangeTemplatesOverrideAndLocalSMTP(t *testing.T) {
	t.Parallel()
	path := writeEmailTemplates(t, "[[templates]]\ntyp = 'email_change_confirm'\nlang = 'en'\nsubject = 'Changed address'\nheader = '<header>'\ntext = 'Changed to:'\nfooter = 'Administrator action'\n")
	copy, err := LoadEmailTemplates(path)
	if err != nil {
		t.Fatal(err)
	}
	address, received := startSMTPFixture(t)
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSMTPSender(SMTPConfig{Host: host, Port: port, From: "support@example.test", Timeout: 5 * time.Second, AllowInsecure: true, Templates: copy})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.SendEmailChange(context.Background(), EmailChangeMessage{To: "old@example.test", NewEmail: "new@example.test", Language: "en"}); err != nil {
		t.Fatal(err)
	}
	parsed, err := stdmail.ReadMessage(strings.NewReader(<-received))
	if err != nil {
		t.Fatal(err)
	}
	plain, html := multipartBodies(t, parsed)
	if parsed.Header.Get("Subject") != "Changed address" || !strings.Contains(plain, "new@example.test") || !strings.Contains(html, "&lt;header&gt;") || !strings.Contains(html, "Administrator action") {
		t.Fatal("SMTP notice did not preserve escaped custom copy")
	}
}
