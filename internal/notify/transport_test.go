package notify

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/eventlog"
	mail "github.com/wneessen/go-mail"
)

func TestNotificationTransportSlackAndMatrix(t *testing.T) {
	type capture struct {
		method, path, auth string
		body               []byte
	}
	captures := make(chan capture, 2)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		captures <- capture{r.Method, r.URL.EscapedPath(), r.Header.Get("Authorization"), b}
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()
	client := s.Client()
	e := eventlog.TestEvent("transport", "", time.Unix(2_000_000_000, 0))
	if err := (webhookSender{s.URL, client}).Send(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	slack := <-captures
	var slackBody map[string]string
	if json.Unmarshal(slack.body, &slackBody) != nil || slack.method != "POST" || slack.path != "/" || slackBody["text"] == "" || !strings.Contains(slackBody["text"], e.ID) {
		t.Fatalf("slack=%+v", slack)
	}
	m := matrixSender{Base: mustURL(t, s.URL), Room: "!room:example.org", Token: "secret", Client: client}
	if err := m.Send(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	matrix := <-captures
	var matrixBody map[string]string
	if json.Unmarshal(matrix.body, &matrixBody) != nil || matrix.method != "PUT" || matrix.auth != "Bearer secret" || matrix.path != "/_matrix/client/v3/rooms/%21room:example.org/send/m.room.message/"+e.ID || matrixBody["body"] == "" || !strings.Contains(matrixBody["body"], e.ID) {
		t.Fatalf("matrix=%+v", matrix)
	}
}
func mustURL(t *testing.T, s string) *url.URL {
	u, e := url.Parse(s)
	if e != nil {
		t.Fatal(e)
	}
	return u
}
func TestNotificationTransportFailuresRedacted(t *testing.T) {
	r := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("token-secret-body"))
	}))
	defer r.Close()
	err := (webhookSender{r.URL, r.Client()}).Send(context.Background(), eventlog.TestEvent("fail", "", time.Unix(2_000_000_000, 0)))
	if err == nil || strings.Contains(err.Error(), r.URL) || strings.Contains(err.Error(), "token-secret-body") {
		t.Fatalf("error leaked: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (webhookSender{r.URL, r.Client()}).Send(ctx, eventlog.TestEvent("cancel", "", time.Unix(2_000_000_000, 0))); err == nil {
		t.Fatal("cancellation accepted")
	}
}

func TestNotificationTransportRedirectAndTLS(t *testing.T) {
	called := make(chan struct{}, 1)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called <- struct{}{}; w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	if err := (webhookSender{target.URL, HTTPClient(time.Second)}).Send(t.Context(), eventlog.TestEvent("untrusted-tls", "", time.Unix(2_000_000_000, 0))); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	}
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer redirect.Close()
	err := (webhookSender{redirect.URL, redirect.Client()}).Send(context.Background(), eventlog.TestEvent("redirect", "", time.Unix(2_000_000_000, 0)))
	if err == nil {
		t.Fatal("redirect accepted")
	}
	select {
	case <-called:
		t.Fatal("redirect followed")
	default:
	}
	plain := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer plain.Close()
	if _, err := (HTTPFactory{SlackWebhook: plain.URL}).Sender(Target{Kind: "slack"}); err == nil {
		t.Fatal("plain HTTP endpoint accepted")
	}
}
func TestHTTPFactorySenderValidation(t *testing.T) {
	f := HTTPFactory{Client: HTTPClient(time.Second)}
	if _, err := f.Sender(Target{Kind: "slack"}); err == nil {
		t.Fatal("slack without webhook accepted")
	}
	f.SlackWebhook = "https://hooks.slack.example.test/x"
	if _, err := f.Sender(Target{Kind: "slack"}); err != nil {
		t.Fatalf("slack with webhook rejected: %v", err)
	}
	if _, err := f.Sender(Target{Kind: "matrix"}); err == nil {
		t.Fatal("matrix without homeserver accepted")
	}
	f.MatrixHomeserver = "https://matrix.example.test"
	if _, err := f.Sender(Target{Kind: "matrix"}); err == nil {
		t.Fatal("matrix without room accepted")
	}
	f.MatrixRoom = "!room:example.test"
	if _, err := f.Sender(Target{Kind: "matrix"}); err == nil {
		t.Fatal("matrix without token accepted")
	}
	f.MatrixToken = "syt_token"
	if _, err := f.Sender(Target{Kind: "matrix"}); err != nil {
		t.Fatalf("matrix fully configured rejected: %v", err)
	}
	if _, err := f.Sender(Target{Kind: "unknown"}); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

func TestNotificationEmail(t *testing.T) {
	var got bytes.Buffer
	s, e := NewEmailSender(EmailConfig{Host: "smtp.example.test", Port: 587, From: "from@example.test", To: "to@example.test", Timeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	s.send = func(_ context.Context, m *mail.Msg) error { _, err := m.WriteTo(&got); return err }
	if e := s.Send(context.Background(), eventlog.TestEvent("email", "", time.Unix(2_000_000_000, 0))); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(got.String(), "Subject: Goauthy event: Test") || !strings.Contains(got.String(), `"typ":"Test"`) || !strings.Contains(got.String(), "from@example.test") || !strings.Contains(got.String(), "to@example.test") {
		t.Fatalf("mime=%s", got.String())
	}
}

func TestNotificationEmailClosesStalledGreeting(t *testing.T) {
	for _, test := range []struct {
		name    string
		timeout time.Duration
		cancel  bool
	}{
		{name: "cancel", timeout: 3 * time.Second, cancel: true},
		{name: "deadline", timeout: 150 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			accepted := make(chan net.Conn, 1)
			closed := make(chan struct{})
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					close(closed)
					return
				}
				accepted <- conn
				_, _ = io.Copy(io.Discard, conn)
				_ = conn.Close()
				close(closed)
			}()

			address := listener.Addr().String()
			host, rawPort, err := net.SplitHostPort(address)
			if err != nil {
				t.Fatal(err)
			}
			port, err := strconv.Atoi(rawPort)
			if err != nil {
				t.Fatal(err)
			}
			sender, err := NewEmailSender(EmailConfig{Host: host, Port: port, From: "from@example.test", To: "to@example.test", Timeout: test.timeout, AllowInsecure: true})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- sender.Send(ctx, eventlog.TestEvent("smtp", "", time.Now())) }()
			var conn net.Conn
			select {
			case conn = <-accepted:
			case <-time.After(time.Second):
				cancel()
				t.Fatal("SMTP connection was not accepted")
			}
			if test.cancel {
				cancel()
			}
			select {
			case <-closed:
			case <-time.After(400 * time.Millisecond):
				_ = conn.Close()
				cancel()
				<-done
				t.Fatal("SMTP connection stayed open after cancellation or deadline")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("SMTP send did not return after the connection closed")
			}
		})
	}
}

func TestNotificationEmailCompletesLocalSMTPDelivery(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		write := func(response string) bool {
			_, err := writer.WriteString(response)
			return err == nil && writer.Flush() == nil
		}
		if !write("220 fixture ESMTP\r\n") {
			return
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO "):
				if !write("250-fixture\r\n250-8BITMIME\r\n250 SIZE 100000\r\n") {
					return
				}
			case strings.HasPrefix(line, "HELO "), strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"), line == "NOOP\r\n", line == "RSET\r\n":
				if !write("250 fixture\r\n") {
					return
				}
			case line == "DATA\r\n":
				if !write("354 continue\r\n") {
					return
				}
				for {
					line, err = reader.ReadString('\n')
					if err != nil {
						return
					}
					if line == ".\r\n" {
						break
					}
				}
				close(received)
				if !write("250 queued\r\n") {
					return
				}
			case line == "QUIT\r\n":
				_ = write("221 bye\r\n")
				return
			default:
				if !write("500 unexpected command\r\n") {
					return
				}
			}
		}
	}()

	host, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	sender, err := NewEmailSender(EmailConfig{Host: host, Port: port, From: "from@example.test", To: "to@example.test", Timeout: time.Second, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background(), eventlog.TestEvent("smtp", "", time.Now())); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("SMTP fixture did not receive DATA")
	}
}
