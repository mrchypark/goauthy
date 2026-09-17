package main

import (
	"bufio"
	"context"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	stdmail "net/mail"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/branding"
	"github.com/mrchypark/goauthy/internal/identity"
	"github.com/mrchypark/goauthy/internal/recovery"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestLoginLocationObserverRevokeFlowAndBrowserIdentity(t *testing.T) {
	address, received := startLoginLocationSMTPFixture(t)
	host, port := splitLoginLocationSMTPAddress(t, address)
	sender, err := recovery.NewSMTPSender(recovery.SMTPConfig{
		Host: host, Port: port, From: "support@example.test", Timeout: time.Second, AllowInsecure: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("fresh location can revoke and consumes code", func(t *testing.T) {
		ctx := context.Background()
		db := retirementCmdDB(t, true)
		users, err := identity.NewStore(db)
		if err != nil {
			t.Fatal(err)
		}
		keyring := retirementCmdKeyring(t, "key-a")
		subject, email := "login-location-revoke", "login-location-revoke@example.test"
		seedLoginLocationUser(t, db, subject, email)
		themes, err := branding.NewThemeStore(db)
		if err != nil {
			t.Fatal(err)
		}
		theme := branding.DefaultTheme("rauthy")
		theme.BorderRadius = "13px"
		if err := themes.Put(ctx, theme); err != nil {
			t.Fatal(err)
		}

		observer := loginLocationObserver(db, users, keyring, sender, "http://localhost:8080", "Rauthy IAM", nil)
		observer(ctx, subject, "browser-a", "198.51.100.10", "Mozilla/5.0")
		message := waitLoginLocationMessage(t, received)
		if !strings.Contains(loginLocationMailText(t, message), "--border-radius:13px;") {
			t.Fatal("persisted email theme missing")
		}
		if !strings.Contains(message, "Subject: Rauthy IAM - Security Warning") {
			t.Fatal("configured subject prefix missing")
		}
		revokeURL, code := extractLoginLocationRevokeURL(t, message)

		if got := loginLocationCount(t, db, subject); got != 1 {
			t.Fatalf("fresh location rows=%d, want 1", got)
		}
		if got := loginRevokeCodeCount(t, db, subject); got != 1 {
			t.Fatalf("stored revoke codes=%d, want 1", got)
		}
		if got := loginLocationEventText(t, db, "LoginNewLocation"); got != "login-location-revoke@example.test / Mozilla/5.0" {
			t.Fatalf("new-location event text=%q", got)
		}

		req := httptest.NewRequest(http.MethodGet, revokeURL, nil)
		req.SetPathValue("subject", subject)
		req.SetPathValue("code", code)
		response := httptest.NewRecorder()
		recovery.NewLoginRevokeHandler(users, keyring).ServeHTTP(response, req)
		if response.Code != http.StatusOK {
			t.Fatalf("revoke response status=%d, want %d", response.Code, http.StatusOK)
		}
		if got := loginLocationCount(t, db, subject); got != 0 {
			t.Fatalf("locations after revoke=%d, want 0", got)
		}
		if got := loginRevokeCodeCount(t, db, subject); got != 0 {
			t.Fatalf("revoke codes after consume=%d, want 0", got)
		}
		if got := loginLocationEventText(t, db, "UserLoginRevoke"); got != "User `login-location-revoke@example.test` revoked illegal login from 198.51.100.10 (Unknown Location)" {
			t.Fatalf("revoke event text=%q", got)
		}
	})

	t.Run("lookup location reaches storage event and mail", func(t *testing.T) {
		ctx := context.Background()
		db := retirementCmdDB(t, true)
		users, err := identity.NewStore(db)
		if err != nil {
			t.Fatal(err)
		}
		keyring := retirementCmdKeyring(t, "key-a")
		subject, email := "login-location-lookup", "login-location-lookup@example.test"
		seedLoginLocationUser(t, db, subject, email)
		const ip = "198.51.100.15"
		lookupCalled := false
		lookup := func(got netip.Addr) (*string, error) {
			lookupCalled = true
			if got.String() != ip {
				t.Fatalf("lookup IP=%s, want %s", got, ip)
			}
			location := "Seoul"
			return &location, nil
		}

		observer := loginLocationObserver(db, users, keyring, sender, "http://localhost:8080", "Rauthy IAM", lookup)
		observer(ctx, subject, "browser-a", ip, "Mozilla/5.0")
		message := waitLoginLocationMessage(t, received)
		if !lookupCalled {
			t.Fatal("location lookup was not called")
		}
		if got := loginLocationStoredLocation(t, db, subject); got != "Seoul" {
			t.Fatalf("stored location=%q, want Seoul", got)
		}
		if got := loginLocationEventText(t, db, "LoginNewLocation"); got != "login-location-lookup@example.test / Mozilla/5.0 / Seoul" {
			t.Fatalf("new-location event text=%q", got)
		}
		mailText := loginLocationMailText(t, message)
		if !strings.Contains(mailText, "IP: 198.51.100.15 (Seoul)") || !strings.Contains(mailText, "IP: <b>198.51.100.15</b> (Seoul)") {
			t.Fatal("captured mail did not contain the looked-up location in plain and HTML bodies")
		}
	})

	t.Run("browser identity controls notification", func(t *testing.T) {
		ctx := context.Background()
		db := retirementCmdDB(t, true)
		users, err := identity.NewStore(db)
		if err != nil {
			t.Fatal(err)
		}
		keyring := retirementCmdKeyring(t, "key-a")
		subject, email := "login-location-browser", "login-location-browser@example.test"
		seedLoginLocationUser(t, db, subject, email)

		observer := loginLocationObserver(db, users, keyring, sender, "http://localhost:8080", "Rauthy IAM", nil)
		observer(ctx, subject, "browser-a", "198.51.100.20", "Mozilla/5.0")
		_ = waitLoginLocationMessage(t, received)

		observer(ctx, subject, "browser-a", "198.51.100.21", "Mozilla/5.0")
		waitLoginLocationIP(t, db, subject, "198.51.100.21")
		assertNoLoginLocationMessage(t, received)

		observer(ctx, subject, "browser-b", "198.51.100.21", "Mozilla/5.0")
		message := waitLoginLocationMessage(t, received)
		if !strings.Contains(loginLocationMailText(t, message), "198.51.100.21") {
			t.Fatal("different browser notification did not contain the new IP")
		}
	})
}

func seedLoginLocationUser(t *testing.T, db *rhiza.DB, subject, email string) {
	t.Helper()
	_, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: "login-location-seed-" + subject,
		Statements: []rhiza.SQLStatement{
			{SQL: `INSERT INTO identity_users(subject,username,password_phc) VALUES(?,?,?)`, Args: []any{subject, subject, ""}},
			{SQL: `INSERT INTO identity_user_profiles(subject,email,email_verified) VALUES(?,?,1)`, Args: []any{subject, email}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func loginLocationCount(t *testing.T, db *rhiza.DB, subject string) int64 {
	t.Helper()
	return loginLocationScalar(t, db, `SELECT COUNT(*) FROM identity_login_locations WHERE subject=?`, subject)
}

func loginLocationStoredLocation(t *testing.T, db *rhiza.DB, subject string) string {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT location FROM identity_login_locations WHERE subject=? AND browser_id=?`, Args: []any{subject, "browser-a"}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("location query rows=%v err=%v", result.Rows, err)
	}
	location, ok := result.Rows[0][0].(string)
	if !ok {
		t.Fatalf("stored location type=%T", result.Rows[0][0])
	}
	return location
}

func loginRevokeCodeCount(t *testing.T, db *rhiza.DB, subject string) int64 {
	t.Helper()
	return loginLocationScalar(t, db, `SELECT COUNT(*) FROM identity_login_revoke WHERE subject=?`, subject)
}

func loginLocationScalar(t *testing.T, db *rhiza.DB, query, subject string) int64 {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{SQL: query, Args: []any{subject}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("scalar query rows=%v err=%v", result.Rows, err)
	}
	value, ok := result.Rows[0][0].(int64)
	if !ok {
		t.Fatalf("scalar type=%T", result.Rows[0][0])
	}
	return value
}

func loginLocationEventText(t *testing.T, db *rhiza.DB, typ string) string {
	t.Helper()
	result, err := db.Query(context.Background(), rhiza.QueryRequest{
		SQL: `SELECT text FROM event_log WHERE typ=? ORDER BY timestamp DESC LIMIT 1`, Args: []any{typ}, Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("event query rows=%v err=%v", result.Rows, err)
	}
	text, ok := result.Rows[0][0].(string)
	if !ok {
		t.Fatalf("event text type=%T", result.Rows[0][0])
	}
	return text
}

func waitLoginLocationIP(t *testing.T, db *rhiza.DB, subject, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		result, err := db.Query(context.Background(), rhiza.QueryRequest{
			SQL: `SELECT ip_address FROM identity_login_locations WHERE subject=? AND browser_id=?`, Args: []any{subject, "browser-a"}, Consistency: rhiza.ConsistencyLinearizable,
		})
		if err == nil && len(result.Rows) == 1 && len(result.Rows[0]) == 1 && result.Rows[0][0] == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("same-browser location update did not complete")
}

func waitLoginLocationMessage(t *testing.T, received <-chan string) string {
	t.Helper()
	select {
	case message := <-received:
		if message == "" {
			t.Fatal("SMTP fixture returned an empty message")
		}
		return message
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for login-location email")
		return ""
	}
}

func assertNoLoginLocationMessage(t *testing.T, received <-chan string) {
	t.Helper()
	select {
	case <-received:
		t.Fatal("same-browser IP change sent an unexpected email")
	case <-time.After(250 * time.Millisecond):
	}
}

var loginLocationRevokeURL = regexp.MustCompile(`https?://[^\s"<>]+/auth/v1/users/[^/\s"<>]+/revoke/[A-Za-z0-9]{48}\?ip=[^\s"<>]+`)

func extractLoginLocationRevokeURL(t *testing.T, raw string) (string, string) {
	t.Helper()
	text := loginLocationMailText(t, raw)
	match := loginLocationRevokeURL.FindString(text)
	if match == "" {
		t.Fatal("captured email did not contain a revoke URL")
	}
	parsed, err := url.Parse(match)
	if err != nil || parsed.Path == "" {
		t.Fatal("captured revoke URL was not parseable")
	}
	parts := strings.Split(parsed.Path, "/")
	code := parts[len(parts)-1]
	if len(code) != 48 || parsed.Query().Get("ip") == "" {
		t.Fatal("captured revoke URL had invalid code or IP")
	}
	return match, code
}

func loginLocationMailText(t *testing.T, raw string) string {
	t.Helper()
	message, err := stdmail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	mediaType, params, err := mime.ParseMediaType(message.Header.Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	if mediaType != "multipart/alternative" {
		body, err := io.ReadAll(message.Body)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	reader := multipart.NewReader(message.Body, params["boundary"])
	var text strings.Builder
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
		text.Write(body)
	}
	return text.String()
}

func startLoginLocationSMTPFixture(t *testing.T) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go captureLoginLocationSMTPConnection(conn, received)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		<-done
	})
	return listener.Addr().String(), received
}

func captureLoginLocationSMTPConnection(conn net.Conn, received chan<- string) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	_, _ = writer.WriteString("220 fixture ESMTP\r\n")
	_ = writer.Flush()
	var data string
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		switch {
		case strings.HasPrefix(line, "EHLO "), strings.HasPrefix(line, "HELO "):
			_, _ = writer.WriteString("250 fixture\r\n")
		case strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"), line == "NOOP\r\n":
			_, _ = writer.WriteString("250 OK\r\n")
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
			data = body.String()
			_, _ = writer.WriteString("250 queued\r\n")
		case line == "RSET\r\n":
			_, _ = writer.WriteString("250 OK\r\n")
			received <- data
		case line == "QUIT\r\n":
			_, _ = writer.WriteString("221 bye\r\n")
			_ = writer.Flush()
			return
		default:
			_, _ = writer.WriteString("500 unsupported\r\n")
		}
		_ = writer.Flush()
	}
}

func splitLoginLocationSMTPAddress(t *testing.T, address string) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}
