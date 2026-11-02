package smtptransport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	mail "github.com/wneessen/go-mail"
	"github.com/wneessen/go-mail/smtp"
)

func TestImplicitTLSAutoAuthDelivery(t *testing.T) {
	certServer := httptest.NewTLSServer(nil)
	transport := certServer.Client().Transport.(*http.Transport)
	tlsConfig := &tls.Config{ServerName: "example.com", RootCAs: transport.TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
	certificate := certServer.TLS.Certificates
	certServer.Close()

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(rawListener, &tls.Config{Certificates: certificate, MinVersion: tls.VersionTLS12})
	defer listener.Close()
	gotAuth := make(chan string, 1)
	gotData := make(chan struct{}, 1)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		write := func(value string) error {
			if _, err := writer.WriteString(value); err != nil {
				return err
			}
			return writer.Flush()
		}
		if err := write("220 fixture ESMTP\r\n"); err != nil {
			serverDone <- err
			return
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				serverDone <- err
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO "):
				err = write("250-fixture\r\n250 AUTH PLAIN LOGIN\r\n")
			case strings.HasPrefix(line, "AUTH "):
				fields := strings.Fields(line)
				if len(fields) != 3 || fields[1] != "PLAIN" {
					serverDone <- io.ErrUnexpectedEOF
					return
				}
				decoded, decodeErr := base64.StdEncoding.DecodeString(fields[2])
				if decodeErr != nil || string(decoded) != "\x00user\x00password" {
					serverDone <- io.ErrUnexpectedEOF
					return
				}
				gotAuth <- fields[1]
				err = write("235 authenticated\r\n")
			case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"), line == "NOOP\r\n", line == "RSET\r\n":
				err = write("250 accepted\r\n")
			case line == "DATA\r\n":
				err = write("354 continue\r\n")
				if err == nil {
					for {
						line, err = reader.ReadString('\n')
						if err != nil || line == ".\r\n" {
							break
						}
					}
				}
				if err == nil {
					gotData <- struct{}{}
					err = write("250 queued\r\n")
				}
			case line == "QUIT\r\n":
				err = write("221 bye\r\n")
				serverDone <- err
				return
			default:
				err = io.ErrUnexpectedEOF
			}
			if err != nil {
				serverDone <- err
				return
			}
		}
	}()

	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dial, authOption := Dialer(ctx, true, tlsConfig)
	client, err := mail.NewClient("localhost",
		mail.WithPort(port), mail.WithTimeout(2*time.Second), mail.WithSSL(),
		mail.WithTLSConfig(tlsConfig), mail.WithDialContextFunc(dial),
		mail.WithUsername("user"), mail.WithPassword("password"), authOption("user", "password"),
	)
	if err != nil {
		t.Fatal(err)
	}
	message := mail.NewMsg()
	if err := message.From("from@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := message.To("to@example.test"); err != nil {
		t.Fatal(err)
	}
	message.Subject("fixture")
	message.SetBodyString(mail.TypeTextPlain, "test")
	if err := client.DialAndSendWithContext(ctx, message); err != nil {
		t.Fatalf("implicit TLS delivery failed: %v", err)
	}
	select {
	case auth := <-gotAuth:
		if auth != "PLAIN" {
			t.Fatalf("authentication mechanism = %q", auth)
		}
	case <-time.After(time.Second):
		t.Fatal("SMTP fixture did not authenticate")
	}
	select {
	case <-gotData:
	case <-time.After(time.Second):
		t.Fatal("SMTP fixture did not receive DATA")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("SMTP fixture: %v", err)
	}
}

func TestSTARTTLSAutoAuthWaitsForVerifiedTLS(t *testing.T) {
	certificateServer := httptest.NewTLSServer(nil)
	transport := certificateServer.Client().Transport.(*http.Transport)
	tlsConfig := &tls.Config{
		ServerName: "example.com", RootCAs: transport.TLSClientConfig.RootCAs,
		MinVersion: tls.VersionTLS12,
	}
	certificates := certificateServer.TLS.Certificates
	certificateServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	authenticated := make(chan string, 1)
	preTLSAuth := make(chan string, 1)
	dataReceived := make(chan struct{}, 1)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		write := func(value string) error {
			if _, err := writer.WriteString(value); err != nil {
				return err
			}
			return writer.Flush()
		}
		if err := write("220 fixture ESMTP\r\n"); err != nil {
			serverDone <- err
			return
		}
		command, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(command, "EHLO ") {
			serverDone <- errors.New("expected initial EHLO")
			return
		}
		if err := write("250-fixture\r\n250-STARTTLS\r\n250 SIZE 100000\r\n"); err != nil {
			serverDone <- err
			return
		}
		command, err = reader.ReadString('\n')
		if err != nil || command != "STARTTLS\r\n" {
			if err == nil && strings.HasPrefix(command, "AUTH ") {
				preTLSAuth <- command
			}
			serverDone <- errors.New("client did not negotiate STARTTLS before authentication")
			return
		}
		if err := write("220 begin TLS\r\n"); err != nil {
			serverDone <- err
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{Certificates: certificates, MinVersion: tls.VersionTLS12})
		if err := tlsConn.Handshake(); err != nil {
			serverDone <- err
			return
		}
		reader = bufio.NewReader(tlsConn)
		writer = bufio.NewWriter(tlsConn)
		command, err = reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(command, "EHLO ") {
			serverDone <- errors.New("expected EHLO after STARTTLS")
			return
		}
		if err := write("250-fixture\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 100000\r\n"); err != nil {
			serverDone <- err
			return
		}
		command, err = reader.ReadString('\n')
		if err != nil {
			serverDone <- err
			return
		}
		fields := strings.Fields(command)
		if len(fields) < 2 || fields[0] != "AUTH" || fields[1] != "PLAIN" {
			serverDone <- errors.New("expected authenticated STARTTLS with AUTH PLAIN")
			return
		}
		var response string
		if len(fields) == 3 {
			response = fields[2]
		} else {
			if err := write("334 \r\n"); err != nil {
				serverDone <- err
				return
			}
			response, err = reader.ReadString('\n')
			if err != nil {
				serverDone <- err
				return
			}
			response = strings.TrimSpace(response)
		}
		decoded, err := base64.StdEncoding.DecodeString(response)
		if err != nil || string(decoded) != "\x00user\x00password" {
			serverDone <- errors.New("invalid STARTTLS credentials")
			return
		}
		authenticated <- fields[1]
		if err := write("235 authenticated\r\n"); err != nil {
			serverDone <- err
			return
		}
		for {
			command, err = reader.ReadString('\n')
			if err != nil {
				serverDone <- err
				return
			}
			switch {
			case strings.HasPrefix(command, "MAIL FROM:"), strings.HasPrefix(command, "RCPT TO:"), command == "RSET\r\n", command == "NOOP\r\n":
				err = write("250 accepted\r\n")
			case command == "DATA\r\n":
				err = write("354 continue\r\n")
				if err == nil {
					for {
						command, err = reader.ReadString('\n')
						if err != nil || command == ".\r\n" {
							break
						}
					}
				}
				if err == nil {
					dataReceived <- struct{}{}
					err = write("250 queued\r\n")
				}
			case command == "QUIT\r\n":
				err = write("221 bye\r\n")
				serverDone <- err
				return
			default:
				err = errors.New("unexpected SMTP command after authentication")
			}
			if err != nil {
				serverDone <- err
				return
			}
		}
	}()

	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dial, _ := Dialer(ctx, false, tlsConfig)
	client, err := mail.NewClient("localhost", mail.WithPort(port), mail.WithTimeout(3*time.Second),
		mail.WithTLSConfig(tlsConfig), mail.WithTLSPolicy(mail.TLSMandatory), mail.WithDialContextFunc(dial),
		mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover), mail.WithUsername("user"), mail.WithPassword("password"))
	if err != nil {
		t.Fatal(err)
	}
	message := mail.NewMsg()
	if err := message.From("from@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := message.To("to@example.test"); err != nil {
		t.Fatal(err)
	}
	message.Subject("STARTTLS fixture")
	message.SetBodyString(mail.TypeTextPlain, "test")
	if err := client.DialAndSendWithContext(ctx, message); err != nil {
		t.Fatalf("authenticated STARTTLS delivery failed: %v", err)
	}
	select {
	case auth := <-authenticated:
		if auth != "PLAIN" {
			t.Fatalf("authentication mechanism=%q", auth)
		}
	case <-time.After(time.Second):
		t.Fatal("SMTP fixture did not authenticate after STARTTLS")
	}
	select {
	case command := <-preTLSAuth:
		t.Fatalf("credentials were sent before STARTTLS: %q", command)
	default:
	}
	select {
	case <-dataReceived:
	case <-time.After(time.Second):
		t.Fatal("SMTP fixture did not receive DATA after verified STARTTLS authentication")
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("SMTP fixture: %v", err)
	}
}

func TestSTARTTLSRejectsUntrustedCertificateBeforeAuthOrData(t *testing.T) {
	certificateServer := httptest.NewTLSServer(nil)
	certificates := certificateServer.TLS.Certificates
	certificateServer.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		write := func(value string) error {
			if _, err := writer.WriteString(value); err != nil {
				return err
			}
			return writer.Flush()
		}
		if err := write("220 fixture ESMTP\r\n"); err != nil {
			serverDone <- err
			return
		}
		command, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(command, "EHLO ") {
			serverDone <- errors.New("expected initial EHLO")
			return
		}
		if err := write("250-fixture\r\n250-STARTTLS\r\n250 SIZE 100000\r\n"); err != nil {
			serverDone <- err
			return
		}
		command, err = reader.ReadString('\n')
		if err != nil || command != "STARTTLS\r\n" {
			serverDone <- errors.New("client did not start TLS before authentication or DATA")
			return
		}
		if err := write("220 begin TLS\r\n"); err != nil {
			serverDone <- err
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{Certificates: certificates, MinVersion: tls.VersionTLS12})
		serverDone <- tlsConn.Handshake()
	}()

	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	tlsConfig := &tls.Config{ServerName: "example.com", MinVersion: tls.VersionTLS12}
	dial, _ := Dialer(ctx, false, tlsConfig)
	client, err := mail.NewClient("localhost", mail.WithPort(port), mail.WithTimeout(3*time.Second),
		mail.WithTLSConfig(tlsConfig), mail.WithTLSPolicy(mail.TLSMandatory), mail.WithDialContextFunc(dial),
		mail.WithSMTPAuth(mail.SMTPAuthAutoDiscover), mail.WithUsername("user"), mail.WithPassword("password"))
	if err != nil {
		t.Fatal(err)
	}
	message := mail.NewMsg()
	if err := message.From("from@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := message.To("to@example.test"); err != nil {
		t.Fatal(err)
	}
	message.Subject("untrusted STARTTLS fixture")
	message.SetBodyString(mail.TypeTextPlain, "test")
	if err := client.DialAndSendWithContext(ctx, message); err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("untrusted STARTTLS delivery error=%v, want certificate verification failure", err)
	}
	select {
	case err := <-serverDone:
		if err == nil {
			t.Fatal("SMTP server completed TLS handshake with an untrusted certificate")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("SMTP TLS fixture did not finish after client rejected its certificate")
	}
}

func TestAutoAuthMechanismPreference(t *testing.T) {
	certificateServer := httptest.NewTLSServer(nil)
	defer certificateServer.Close()
	transport := certificateServer.Client().Transport.(*http.Transport)
	parsed, err := http.NewRequest("GET", certificateServer.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{ServerName: "example.com", RootCAs: transport.TLSClientConfig.RootCAs, MinVersion: tls.VersionTLS12}
	conn, err := tls.Dial("tcp", parsed.URL.Host, tlsConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	tests := []struct {
		name       string
		tls        bool
		auth       []string
		want       string
		wantNoAuth bool
		wantPlus   bool
	}{
		{name: "TLS prefers channel-bound SCRAM PLUS", tls: true, auth: []string{"PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"}, want: "SCRAM-SHA-256-PLUS", wantPlus: true},
		{name: "TLS prefers SCRAM over PLAIN", tls: true, auth: []string{"PLAIN", "SCRAM-SHA-256"}, want: "SCRAM-SHA-256"},
		{name: "TLS falls back to PLAIN", tls: true, auth: []string{"LOGIN", "PLAIN"}, want: "PLAIN"},
		{name: "cleartext rejects PLAIN and LOGIN", auth: []string{"PLAIN", "LOGIN"}, wantNoAuth: true},
		{name: "cleartext prefers SCRAM", auth: []string{"PLAIN", "SCRAM-SHA-256"}, want: "SCRAM-SHA-256"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tlsConn := conn
			auth := autoAuth{username: "user", password: "password", tlsConn: &tlsConn}
			mechanism, _, err := auth.Start(&smtp.ServerInfo{Name: "example.com", TLS: test.tls, Auth: test.auth})
			if test.wantNoAuth {
				if !errors.Is(err, mail.ErrNoSupportedAuthDiscovered) {
					t.Fatalf("Start() error=%v, want no supported auth", err)
				}
				return
			}
			if err != nil || mechanism != test.want {
				t.Fatalf("Start() mechanism=%q err=%v, want %q", mechanism, err, test.want)
			}
			if test.wantPlus {
				initial, err := auth.Next(nil, true)
				if err != nil || !strings.HasPrefix(string(initial), "p=tls-exporter,,") && !strings.HasPrefix(string(initial), "p=tls-unique,,") {
					t.Fatalf("SCRAM-PLUS initial response=%q err=%v", initial, err)
				}
			}
		})
	}
}
