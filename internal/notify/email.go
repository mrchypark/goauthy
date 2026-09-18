package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	gomail "github.com/wneessen/go-mail"
)

type EmailConfig struct {
	Host                         string
	Port                         int
	From, To, Username, Password string
	Timeout                      time.Duration
	ImplicitTLS, AllowInsecure   bool
}
type EmailSender struct {
	cfg  EmailConfig
	send func(context.Context, *gomail.Msg) error
}

func NewEmailSender(c EmailConfig) (*EmailSender, error) {
	if strings.TrimSpace(c.Host) == "" || strings.TrimSpace(c.Host) != c.Host || strings.ContainsAny(c.Host, "\r\n") || c.Port < 1 || c.Port > 65535 || c.Timeout <= 0 {
		return nil, errors.New("invalid notification SMTP configuration")
	}
	if (c.Username == "") != (c.Password == "") || c.ImplicitTLS && c.AllowInsecure {
		return nil, errors.New("inconsistent notification SMTP security settings")
	}
	for _, v := range []string{c.From, c.To} {
		a, e := mail.ParseAddress(v)
		if e != nil || a.Address != v || strings.ContainsAny(v, "\r\n") {
			return nil, errors.New("invalid notification email address")
		}
	}
	s := &EmailSender{cfg: c}
	s.send = s.deliver
	return s, nil
}
func (s *EmailSender) Send(ctx context.Context, e eventlog.Event) error {
	if ctx == nil || s == nil || s.send == nil {
		return errors.New("email sender unavailable")
	}
	if err := ctx.Err(); err != nil {
		return errors.New("SMTP delivery cancelled")
	}
	m := gomail.NewMsg()
	if err := m.From(s.cfg.From); err != nil {
		return errors.New("email sender unavailable")
	}
	if err := m.To(s.cfg.To); err != nil {
		return errors.New("email sender unavailable")
	}
	m.Subject("Goauthy event: " + string(e.Type))
	text := eventText(e)
	m.SetBodyString(gomail.TypeTextPlain, text)
	if err := s.send(ctx, m); err != nil {
		return errors.New("SMTP delivery failed")
	}
	return nil
}
func (s *EmailSender) deliver(ctx context.Context, m *gomail.Msg) error {
	opts := []gomail.Option{gomail.WithPort(s.cfg.Port), gomail.WithTimeout(s.cfg.Timeout), gomail.WithTLSConfig(&tls.Config{ServerName: s.cfg.Host, MinVersion: tls.VersionTLS12})}
	if s.cfg.ImplicitTLS {
		opts = append(opts, gomail.WithSSL())
	} else if s.cfg.AllowInsecure {
		opts = append(opts, gomail.WithTLSPolicy(gomail.NoTLS))
	} else {
		opts = append(opts, gomail.WithTLSPolicy(gomail.TLSMandatory))
	}
	if s.cfg.Username != "" || s.cfg.Password != "" {
		opts = append(opts, gomail.WithSMTPAuth(gomail.SMTPAuthAutoDiscover), gomail.WithUsername(s.cfg.Username), gomail.WithPassword(s.cfg.Password))
	}
	c, err := gomail.NewClient(s.cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("SMTP delivery failed")
	}
	defer c.Close()
	if err := c.DialWithContext(ctx); err != nil {
		return fmt.Errorf("SMTP delivery failed")
	}
	if err := c.Send(m); err != nil {
		return fmt.Errorf("SMTP delivery failed")
	}
	return nil
}
