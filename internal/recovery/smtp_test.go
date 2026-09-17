package recovery

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net"
	stdmail "net/mail"
	"strings"
	"testing"
	"time"

	mail "github.com/wneessen/go-mail"
)

func TestNewSMTPSenderValidatesConfig(t *testing.T) {
	valid := SMTPConfig{Host: "smtp.example.test", Port: 587, From: "Support@Example.Test", Timeout: time.Second}
	sender, err := NewSMTPSender(valid)
	if err != nil {
		t.Fatalf("NewSMTPSender() error = %v", err)
	}
	if sender.config.From != "support@example.test" {
		t.Fatalf("canonical From = %q", sender.config.From)
	}

	for _, config := range []SMTPConfig{
		{Host: "smtp\r\nBcc: victim@example.test", Port: 587, From: valid.From, Timeout: time.Second},
		{Host: valid.Host, Port: 0, From: valid.From, Timeout: time.Second},
		{Host: valid.Host, Port: 587, From: "bad\r\nBcc: victim@example.test", Timeout: time.Second},
		{Host: valid.Host, Port: 587, From: valid.From},
		{Host: valid.Host, Port: 587, From: valid.From, Timeout: time.Second, Username: "user"},
		{Host: valid.Host, Port: 587, From: valid.From, Timeout: time.Second, Template: EmailTemplate{Subject: "bad\r\nBcc: victim@example.test"}},
		{Host: valid.Host, Port: 587, From: valid.From, Timeout: time.Second, PasswordNewTemplate: EmailTemplate{Subject: "bad\r\nBcc: victim@example.test"}},
		{Host: valid.Host, Port: 587, From: valid.From, Timeout: time.Second, AlreadyRegisteredTemplate: EmailTemplate{Subject: "bad\r\nBcc: victim@example.test"}},
	} {
		if _, err := NewSMTPSender(config); err == nil {
			t.Fatalf("NewSMTPSender(%+v) succeeded", config)
		}
	}
}

func TestSMTPSenderComposesCanonicalMultipartMessage(t *testing.T) {
	sender := testSMTPSender(t)
	var got *mail.Msg
	var bounded bool
	sender.send = func(ctx context.Context, msg *mail.Msg) error {
		got = msg
		_, bounded = ctx.Deadline()
		return nil
	}
	resetURL := "https://auth.example.test/auth/v1/users/alice/reset/token"
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	if err := sender.SendPasswordReset(context.Background(), Message{To: "USER@Example.Test", ResetURL: resetURL, ExpiresAt: expires}); err != nil {
		t.Fatalf("SendPasswordReset() error = %v", err)
	}
	if got == nil {
		t.Fatal("sender was not called")
	}
	if !bounded {
		t.Fatal("send context has no deadline")
	}
	var wire bytes.Buffer
	if _, err := got.WriteTo(&wire); err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	parsed, err := stdmail.ReadMessage(&wire)
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if got, want := parsed.Header.Get("From"), "<support@example.test>"; got != want {
		t.Fatalf("From = %q, want %q", got, want)
	}
	if got, want := parsed.Header.Get("To"), "<user@example.test>"; got != want {
		t.Fatalf("To = %q, want %q", got, want)
	}
	if got, want := parsed.Header.Get("Subject"), "Password Reset Request"; got != want {
		t.Fatalf("Subject = %q, want %q", got, want)
	}
	plain, html := multipartBodies(t, parsed)
	if !strings.Contains(plain, resetURL) || !strings.Contains(plain, expires.Format(time.RFC3339)) || !strings.Contains(plain, "Password reset request for") {
		t.Fatalf("unexpected plain message: %q", plain)
	}
	if !strings.Contains(html, `href="`+resetURL+`"`) || !strings.Contains(html, "Reset Password") {
		t.Fatalf("unexpected HTML message: %q", html)
	}
}

func TestSMTPSenderComposesPasswordNewMessage(t *testing.T) {
	sender := testSMTPSender(t)
	var got *mail.Msg
	sender.send = func(_ context.Context, msg *mail.Msg) error { got = msg; return nil }
	expires := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	if err := sender.SendPasswordNew(context.Background(), Message{To: "USER@Example.Test", ResetURL: "https://auth.example.test/new/token", ExpiresAt: expires}); err != nil {
		t.Fatalf("SendPasswordNew() error = %v", err)
	}
	var wire bytes.Buffer
	if _, err := got.WriteTo(&wire); err != nil {
		t.Fatal(err)
	}
	message, err := stdmail.ReadMessage(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if subject := message.Header.Get("Subject"); subject != "New Password" {
		t.Fatalf("Subject = %q", subject)
	}
	plain, html := multipartBodies(t, message)
	if !strings.Contains(plain, "https://auth.example.test/new/token") || !strings.Contains(plain, "New password for") || !strings.Contains(html, `href="https://auth.example.test/new/token"`) || !strings.Contains(html, "Set Password") {
		t.Fatalf("unexpected new-password bodies plain=%q html=%q", plain, html)
	}
}

func TestSMTPSenderComposesAlreadyRegisteredMessage(t *testing.T) {
	sender := testSMTPSender(t)
	var got *mail.Msg
	sender.send = func(_ context.Context, msg *mail.Msg) error { got = msg; return nil }
	if err := sender.SendAlreadyRegistered(context.Background(), Message{To: "USER@Example.Test"}); err != nil {
		t.Fatalf("SendAlreadyRegistered() error = %v", err)
	}
	var wire bytes.Buffer
	if _, err := got.WriteTo(&wire); err != nil {
		t.Fatal(err)
	}
	message, err := stdmail.ReadMessage(&wire)
	if err != nil {
		t.Fatal(err)
	}
	if subject := message.Header.Get("Subject"); subject != "E-Mail registered already" {
		t.Fatalf("Subject = %q", subject)
	}
	plain, html := multipartBodies(t, message)
	if !strings.Contains(plain, "Someone tried to register") || !strings.Contains(html, "Someone tried to register") || strings.Contains(html, "href=") {
		t.Fatalf("unexpected registered-already bodies plain=%q html=%q", plain, html)
	}
}

func multipartBodies(t *testing.T, message *stdmail.Message) (string, string) {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/alternative" {
		t.Fatalf("Content-Type = %q, err=%v", message.Header.Get("Content-Type"), err)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	var plain, html string
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(part)
		if err != nil {
			t.Fatal(err)
		}
		partType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			t.Fatal(err)
		}
		switch partType {
		case "text/plain":
			plain = string(body)
		case "text/html":
			html = string(body)
		}
	}
	if plain == "" || html == "" {
		t.Fatalf("multipart bodies plain=%q html=%q", plain, html)
	}
	return plain, html
}

func TestSMTPSenderRejectsUnsafeInputAndCancelledContext(t *testing.T) {
	sender := testSMTPSender(t)
	calls := 0
	sender.send = func(_ context.Context, _ *mail.Msg) error { calls++; return nil }
	expires := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	for _, message := range []Message{
		{To: "user@example.test\r\nBcc: victim@example.test", ResetURL: "https://auth.example.test/reset", ExpiresAt: expires},
		{To: "user@example.test", ResetURL: "https://auth.example.test/reset\r\nBcc: victim@example.test", ExpiresAt: expires},
		{To: "user@example.test", ResetURL: "http://auth.example.test/reset", ExpiresAt: expires},
		{To: "user@example.test", ResetURL: "https://auth.example.test/reset"},
	} {
		if err := sender.SendPasswordReset(context.Background(), message); err == nil {
			t.Fatalf("SendPasswordReset(%+v) succeeded", message)
		}
	}
	if err := sender.SendPasswordNew(context.Background(), Message{To: "user@example.test", ResetURL: "https://auth.example.test/new\r\nBcc: victim@example.test", ExpiresAt: expires}); err == nil {
		t.Fatal("SendPasswordNew() accepted unsafe URL")
	}
	if err := sender.SendAlreadyRegistered(context.Background(), Message{To: "user@example.test\r\nBcc: victim@example.test"}); err == nil {
		t.Fatal("SendAlreadyRegistered() accepted unsafe recipient")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sender.SendPasswordReset(ctx, Message{To: "user@example.test", ResetURL: "https://auth.example.test/reset", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled SendPasswordReset() error = %v", err)
	}
	if calls != 0 {
		t.Fatalf("send called %d times", calls)
	}
}

func TestSMTPSenderRequiresTLSUnlessExplicitlyAllowed(t *testing.T) {
	address := startNoStartTLSFixture(t)
	host, port := splitSMTPAddress(t, address)

	sender, err := NewSMTPSender(SMTPConfig{Host: host, Port: port, From: "support@example.test", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	err = sender.SendPasswordReset(context.Background(), Message{To: "user@example.test", ResetURL: "https://auth.example.test/reset", ExpiresAt: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("TLS-required send error = %v", err)
	}
}

func TestSMTPSenderSendsToLocalInsecureFixture(t *testing.T) {
	address, received := startSMTPFixture(t)
	host, port := splitSMTPAddress(t, address)
	sender, err := NewSMTPSender(SMTPConfig{Host: host, Port: port, From: "support@example.test", Timeout: time.Second, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	expires := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)
	if err := sender.SendPasswordReset(context.Background(), Message{To: "user@example.test", ResetURL: "http://auth.example.test/reset", ExpiresAt: expires}); err != nil {
		t.Fatalf("SendPasswordReset() error = %v", err)
	}
	got := <-received
	message, err := stdmail.ReadMessage(strings.NewReader(got))
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if subject := message.Header.Get("Subject"); subject != "Password Reset Request" {
		t.Fatalf("Subject = %q", subject)
	}
	plain, html := multipartBodies(t, message)
	if !strings.Contains(plain, "http://auth.example.test/reset") || !strings.Contains(plain, expires.Format(time.RFC3339)) || !strings.Contains(html, `href="http://auth.example.test/reset"`) {
		t.Fatalf("fixture bodies plain=%q html=%q", plain, html)
	}
}

func testSMTPSender(t *testing.T) *SMTPSender {
	t.Helper()
	sender, err := NewSMTPSender(SMTPConfig{Host: "smtp.example.test", Port: 587, From: "Support@Example.Test", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return sender
}

func startSMTPFixture(t *testing.T) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	go func() {
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			received <- ""
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		_, _ = writer.WriteString("220 fixture ESMTP\r\n")
		_ = writer.Flush()
		var data string
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				received <- ""
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO "), strings.HasPrefix(line, "HELO "):
				_, _ = writer.WriteString("250 fixture\r\n")
			case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"), line == "NOOP\r\n":
				_, _ = writer.WriteString("250 OK\r\n")
			case line == "RSET\r\n":
				_, _ = writer.WriteString("250 OK\r\n")
				received <- data
			case line == "DATA\r\n":
				_, _ = writer.WriteString("354 send data\r\n")
				_ = writer.Flush()
				var body strings.Builder
				for {
					line, err = reader.ReadString('\n')
					if err != nil || line == ".\r\n" {
						break
					}
					body.WriteString(line)
				}
				_, _ = writer.WriteString("250 queued\r\n")
				_ = writer.Flush()
				data = body.String()
			case line == "QUIT\r\n":
				_, _ = writer.WriteString("221 bye\r\n")
				_ = writer.Flush()
				return
			default:
				_, _ = writer.WriteString("500 unsupported\r\n")
			}
			_ = writer.Flush()
		}
	}()
	return listener.Addr().String(), received
}

func startNoStartTLSFixture(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer listener.Close()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("220 fixture ESMTP\r\n"))
		_, _ = bufio.NewReader(conn).ReadString('\n')
		_, _ = conn.Write([]byte("250 fixture\r\n"))
	}()
	return listener.Addr().String()
}

func splitSMTPAddress(t *testing.T, address string) (string, int) {
	t.Helper()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	var value int
	if _, err := fmt.Sscanf(port, "%d", &value); err != nil {
		t.Fatal(err)
	}
	return host, value
}
