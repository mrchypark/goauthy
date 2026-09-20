package recovery

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const outboxTestBody = `text body https://auth.example.test/reset`

func TestEmailOutboxRetryableFailureStaysPendingUntilExhausted(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	transient := errors.New("dial tcp 127.0.0.1:25: connect: connection refused")
	sent := 0
	outbox := testEmailOutbox(t, func(context.Context, string, string, string, string) error {
		sent++
		return transient
	})
	outbox.Now = func() time.Time { return now }
	seedOutboxRow(t, outbox, "retry-row", "pending", 0, now)

	for attempt := int64(1); attempt <= outboxMaxAttempts; attempt++ {
		if err := outbox.Step(t.Context()); err != nil {
			t.Fatalf("step %d: %v", attempt, err)
		}
		row := readOutboxRow(t, outbox, "retry-row")
		if row.attempts != attempt {
			t.Fatalf("step %d attempts=%d", attempt, row.attempts)
		}
		if attempt == outboxMaxAttempts {
			continue
		}
		if row.status != "pending" || row.nextRetry <= now.UnixMilli() || row.lease != "" {
			t.Fatalf("transient failure %d must stay pending with a future retry: %+v", attempt, row)
		}
		if row.lastError != transient.Error() {
			t.Fatalf("attempt %d last_error=%q", attempt, row.lastError)
		}
		now = time.UnixMilli(row.nextRetry).Add(time.Second)
	}

	final := readOutboxRow(t, outbox, "retry-row")
	if final.status != "failed" || final.attempts != outboxMaxAttempts || final.lease != "" {
		t.Fatalf("exhausted row=%+v", final)
	}
	if sent != outboxMaxAttempts {
		t.Fatalf("delivery attempts=%d want=%d", sent, outboxMaxAttempts)
	}
}

func TestEmailOutboxPermanentSMTPFailureIsTerminal(t *testing.T) {
	host, port := splitSMTPAddress(t, startRejectingSMTPFixture(t))
	sender, err := NewSMTPSender(SMTPConfig{Host: host, Port: port, From: "support@example.test", Timeout: time.Second, AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	outbox := testEmailOutbox(t, SMTPSendFunc(sender))
	outbox.Now = func() time.Time { return now }
	seedOutboxRow(t, outbox, "permanent-row", "pending", 0, now)

	if err := outbox.Step(t.Context()); err != nil {
		t.Fatalf("step: %v", err)
	}
	row := readOutboxRow(t, outbox, "permanent-row")
	if row.status != "failed" || row.attempts != 1 {
		t.Fatalf("permanent SMTP failure must be terminal on the first attempt: %+v", row)
	}
	if row.lastError == "" {
		t.Fatal("permanent failure recorded no error")
	}
}

func TestEmailOutboxCompletionIDsAreLeaseScoped(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	first := errors.New("first SMTP failure")
	second := errors.New("second SMTP failure")
	calls := 0
	outbox := testEmailOutbox(t, func(context.Context, string, string, string, string) error {
		calls++
		if calls == 1 {
			return first
		}
		return second
	})
	outbox.Now = func() time.Time { return now }
	seedOutboxRow(t, outbox, "lease-row", "pending", 0, now)

	if err := outbox.Step(t.Context()); err != nil {
		t.Fatalf("first step: %v", err)
	}
	now = time.UnixMilli(readOutboxRow(t, outbox, "lease-row").nextRetry).Add(time.Second)
	if err := outbox.Step(t.Context()); err != nil {
		t.Fatalf("second attempt reused the first attempt request ID: %v", err)
	}
	row := readOutboxRow(t, outbox, "lease-row")
	if row.attempts != 2 || row.lastError != second.Error() || row.status != "pending" {
		t.Fatalf("second attempt row=%+v", row)
	}
	if row.nextRetry != now.Add(2*time.Minute).UnixMilli() {
		t.Fatalf("second attempt next_retry=%d want=%d", row.nextRetry, now.Add(2*time.Minute).UnixMilli())
	}
}

func TestEmailOutboxStaleOwnerCannotAcknowledgeReclaimedRow(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	var outbox *EmailOutbox
	outbox = testEmailOutbox(t, func(ctx context.Context, _, _, _, _ string) error {
		// Another owner re-claims the row while this attempt is delivering.
		_, err := storage.Execute(ctx, outbox.DB, rhiza.ExecuteRequest{
			RequestID: "outbox-test-steal-lease",
			SQL:       `UPDATE email_outbox SET lease_token='stolen-lease', attempts=attempts+1 WHERE id=?`,
			Args:      []any{"stale-row"},
		})
		return err
	})
	outbox.Now = func() time.Time { return now }
	seedOutboxRow(t, outbox, "stale-row", "pending", 0, now)

	if err := outbox.Step(t.Context()); err == nil {
		t.Fatal("stale owner acknowledged a row it no longer owns")
	}
	row := readOutboxRow(t, outbox, "stale-row")
	if row.status != "pending" || row.lease != "stolen-lease" {
		t.Fatalf("re-claimed row was overwritten by its previous owner: %+v", row)
	}
}

func TestEmailOutboxSealsPayloadsAndRefusesPlaintextWithoutKeyring(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	keyring := loginRevokeTestKeyring(t)
	secret := "live-secret-token"
	url := "https://auth.example.test/reset?token=" + secret
	text := "click " + url
	html := `<a href="` + url + `">reset</a>`
	var delivered []string
	outbox := testEmailOutbox(t, func(_ context.Context, recipient, subject, textBody, htmlBody string) error {
		delivered = append(delivered, recipient+"|"+subject+"|"+textBody+"|"+htmlBody)
		return nil
	}, WithEnvelopeKeyring(keyring))
	outbox.Now = func() time.Time { return now }

	if err := outbox.Enqueue(t.Context(), "user@example.test", "password reset", "Reset", html, text); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	id := onlyOutboxID(t, outbox)
	storedText, storedHTML := storedOutboxBodies(t, outbox, id)
	if !strings.HasPrefix(storedText, outboxSealedPrefix) || !strings.HasPrefix(storedHTML, outboxSealedPrefix) {
		t.Fatalf("queued payload is not sealed: text=%q html=%q", storedText, storedHTML)
	}
	if strings.Contains(storedText, secret) || strings.Contains(storedHTML, secret) {
		t.Fatal("replicated outbox row holds the live recovery token in clear")
	}

	// A pod without the sealing key cannot deliver the row and must not send
	// ciphertext in its place.
	outbox.keyring = loginRevokeTestKeyring(t)
	if err := outbox.Step(t.Context()); err != nil {
		t.Fatalf("step with a foreign keyring: %v", err)
	}
	if len(delivered) != 0 {
		t.Fatalf("foreign keyring delivered %q", delivered)
	}
	row := readOutboxRow(t, outbox, id)
	if row.status != "pending" || !strings.Contains(row.lastError, "email outbox") {
		t.Fatalf("foreign keyring row=%+v", row)
	}

	outbox.keyring = keyring
	now = time.UnixMilli(row.nextRetry).Add(time.Second)
	if err := outbox.Step(t.Context()); err != nil {
		t.Fatalf("step with the sealing key: %v", err)
	}
	want := "user@example.test|Reset|" + text + "|" + html
	if len(delivered) != 1 || delivered[0] != want {
		t.Fatalf("delivered=%q want=%q", delivered, want)
	}
	if row := readOutboxRow(t, outbox, id); row.status != "sent" {
		t.Fatalf("row after delivery=%+v", row)
	}
}

func TestEmailOutboxEnqueueRequiresKeyringForSensitivePayloads(t *testing.T) {
	outbox := testEmailOutbox(t, nil)
	err := outbox.Enqueue(t.Context(), "user@example.test", "password reset", "Reset", `<p>html</p>`, `https://auth.example.test/reset?token=live-secret`)
	if err == nil {
		t.Fatal("enqueue without a keyring accepted a live recovery URL")
	}
	if rows := outboxRowCount(t, outbox); rows != 0 {
		t.Fatalf("rows=%d want=0", rows)
	}
}

func TestEmailOutboxDeliversLegacyPlaintextRow(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	var delivered []string
	outbox := testEmailOutbox(t, func(_ context.Context, _, _, textBody, htmlBody string) error {
		delivered = append(delivered, textBody+"|"+htmlBody)
		return nil
	}, WithEnvelopeKeyring(loginRevokeTestKeyring(t)))
	outbox.Now = func() time.Time { return now }
	seedOutboxRow(t, outbox, "legacy-row", "pending", 0, now)

	if err := outbox.Step(t.Context()); err != nil {
		t.Fatalf("step: %v", err)
	}
	want := outboxTestBody + "|" + `<p>html</p>`
	if len(delivered) != 1 || delivered[0] != want {
		t.Fatalf("delivered=%q want=%q", delivered, want)
	}
	if row := readOutboxRow(t, outbox, "legacy-row"); row.status != "sent" {
		t.Fatalf("legacy row=%+v", row)
	}
}

func TestEmailOutboxCleanupBoundsTerminalRetention(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	outbox := testEmailOutbox(t, nil)
	outbox.Now = func() time.Time { return now }
	old := now.Add(-outboxCleanupAge - time.Hour)
	seedOutboxRow(t, outbox, "sent-old", "sent", 1, old)
	seedOutboxRow(t, outbox, "failed-old", "failed", outboxMaxAttempts, old)
	seedOutboxRow(t, outbox, "sent-recent", "sent", 1, now.Add(-time.Hour))
	seedOutboxRow(t, outbox, "pending-old", "pending", 1, old)

	removed, err := outbox.Cleanup(t.Context(), 2)
	if err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if removed != 2 {
		t.Fatalf("removed=%d want=2", removed)
	}
	removed, err = outbox.Cleanup(t.Context(), 2)
	if err != nil {
		t.Fatalf("second cleanup: %v", err)
	}
	if removed != 0 {
		t.Fatalf("second cleanup removed=%d want=0", removed)
	}
	if rows := outboxRowCount(t, outbox); rows != 2 {
		t.Fatalf("retained rows=%d want=2", rows)
	}
	if _, err := outbox.Cleanup(t.Context(), 0); err != nil {
		t.Fatalf("default batch cleanup: %v", err)
	}
}

type outboxState struct {
	status    string
	attempts  int64
	lastError string
	nextRetry int64
	lease     string
}

func testEmailOutbox(t *testing.T, sendFn func(context.Context, string, string, string, string) error, options ...EmailOutboxOption) *EmailOutbox {
	t.Helper()
	if sendFn == nil {
		sendFn = func(context.Context, string, string, string, string) error { return nil }
	}
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "email-outbox-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "email-outbox-test-schema", Statements: emailOutboxSchemaStatements()}); err != nil {
		t.Fatal(err)
	}
	outbox, err := NewEmailOutbox(db, sendFn, options...)
	if err != nil {
		t.Fatal(err)
	}
	return outbox
}

func seedOutboxRow(t *testing.T, outbox *EmailOutbox, id, status string, attempts int64, updatedAt time.Time) {
	t.Helper()
	_, err := storage.Execute(t.Context(), outbox.DB, rhiza.ExecuteRequest{
		RequestID: "outbox-test-seed/" + id,
		SQL:       `INSERT INTO email_outbox (id, recipient, mail_type, subject, body_html, body_text, status, attempts, last_error, created_at_unix_ms, updated_at_unix_ms, next_retry_at_unix_ms) VALUES (?, 'user@example.test', 'password reset', 'Reset', '<p>html</p>', ?, ?, ?, '', ?, ?, 0)`,
		Args:      []any{id, outboxTestBody, status, attempts, updatedAt.UnixMilli(), updatedAt.UnixMilli()},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func readOutboxRow(t *testing.T, outbox *EmailOutbox, id string) outboxState {
	t.Helper()
	result, err := outbox.DB.Query(t.Context(), rhiza.QueryRequest{
		SQL:         `SELECT status, attempts, last_error, next_retry_at_unix_ms, COALESCE(lease_token, '') FROM email_outbox WHERE id=?`,
		Args:        []any{id},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 5 {
		t.Fatalf("outbox row %s=%v error=%v", id, result.Rows, err)
	}
	row := result.Rows[0]
	status, _ := row[0].(string)
	attempts, _ := row[1].(int64)
	lastError, _ := row[2].(string)
	nextRetry, _ := row[3].(int64)
	lease, _ := row[4].(string)
	return outboxState{status: status, attempts: attempts, lastError: lastError, nextRetry: nextRetry, lease: lease}
}

func storedOutboxBodies(t *testing.T, outbox *EmailOutbox, id string) (string, string) {
	t.Helper()
	result, err := outbox.DB.Query(t.Context(), rhiza.QueryRequest{
		SQL:         `SELECT body_text, body_html FROM email_outbox WHERE id=?`,
		Args:        []any{id},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		t.Fatalf("stored bodies %s=%v error=%v", id, result.Rows, err)
	}
	text, _ := result.Rows[0][0].(string)
	html, _ := result.Rows[0][1].(string)
	return text, html
}

func onlyOutboxID(t *testing.T, outbox *EmailOutbox) string {
	t.Helper()
	result, err := outbox.DB.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT id FROM email_outbox`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("outbox ids=%v error=%v", result.Rows, err)
	}
	id, _ := result.Rows[0][0].(string)
	if id == "" {
		t.Fatal("empty outbox id")
	}
	return id
}

func outboxRowCount(t *testing.T, outbox *EmailOutbox) int {
	t.Helper()
	result, err := outbox.DB.Query(t.Context(), rhiza.QueryRequest{SQL: `SELECT COUNT(*) FROM email_outbox`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 1 {
		t.Fatalf("outbox count=%v error=%v", result.Rows, err)
	}
	count, _ := result.Rows[0][0].(int64)
	return int(count)
}

// startRejectingSMTPFixture answers RCPT TO with 550 so go-mail reports a real
// permanent delivery error.
func startRejectingSMTPFixture(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		_, _ = writer.WriteString("220 fixture ESMTP\r\n")
		_ = writer.Flush()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO "), strings.HasPrefix(line, "HELO "):
				_, _ = writer.WriteString("250 fixture\r\n")
			case strings.HasPrefix(line, "RCPT TO:"):
				_, _ = writer.WriteString("550 mailbox unavailable\r\n")
			case line == "QUIT\r\n":
				_, _ = writer.WriteString("221 bye\r\n")
				_ = writer.Flush()
				return
			default:
				_, _ = writer.WriteString("250 OK\r\n")
			}
			_ = writer.Flush()
		}
	}()
	return listener.Addr().String()
}
