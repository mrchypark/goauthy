package recovery

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/oidc"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// outboxRetirementBarrier is the production master-key retirement barrier
// table. The fence appends an epoch update that violates this table's epoch
// check for an old writer, which is what rolls a fenced enqueue back.
const outboxRetirementBarrier = `CREATE TABLE IF NOT EXISTS master_key_retirement_barrier (
	barrier_id INTEGER PRIMARY KEY CHECK (barrier_id = 1),
	epoch INTEGER NOT NULL UNIQUE CHECK (epoch > 0),
	old_key_id TEXT NOT NULL CHECK (length(old_key_id) BETWEEN 1 AND 64 AND old_key_id NOT GLOB '*[^A-Za-z0-9._-]*'),
	replacement_key_id TEXT NOT NULL CHECK (length(replacement_key_id) BETWEEN 1 AND 64 AND replacement_key_id NOT GLOB '*[^A-Za-z0-9._-]*' AND replacement_key_id <> old_key_id),
	membership_digest TEXT NOT NULL CHECK (length(membership_digest) = 43 AND membership_digest NOT GLOB '*[^A-Za-z0-9_-]*'),
	state TEXT NOT NULL CHECK (state IN ('prepared', 'fenced', 'ready', 'aborted')),
	prepared_at_unix_ms INTEGER NOT NULL CHECK (prepared_at_unix_ms >= 0),
	fenced_at_unix_ms INTEGER CHECK (fenced_at_unix_ms IS NULL OR fenced_at_unix_ms >= prepared_at_unix_ms),
	ready_at_unix_ms INTEGER CHECK (ready_at_unix_ms IS NULL OR (fenced_at_unix_ms IS NOT NULL AND ready_at_unix_ms >= fenced_at_unix_ms)),
	aborted_at_unix_ms INTEGER CHECK (aborted_at_unix_ms IS NULL OR aborted_at_unix_ms >= prepared_at_unix_ms),
	CHECK ((state = 'prepared' AND fenced_at_unix_ms IS NULL AND ready_at_unix_ms IS NULL AND aborted_at_unix_ms IS NULL) OR
	       (state = 'fenced' AND fenced_at_unix_ms IS NOT NULL AND ready_at_unix_ms IS NULL AND aborted_at_unix_ms IS NULL) OR
	       (state = 'ready' AND fenced_at_unix_ms IS NOT NULL AND ready_at_unix_ms IS NOT NULL AND aborted_at_unix_ms IS NULL) OR
	       (state = 'aborted' AND aborted_at_unix_ms IS NOT NULL AND ready_at_unix_ms IS NULL))
) STRICT`

const outboxTestBody = `text body https://auth.example.test/reset`

func TestEmailOutboxRetryableFailureStaysPendingUntilExhausted(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	outbox := testEmailOutbox(t, nil)
	err := outbox.Enqueue(t.Context(), "user@example.test", "password reset", "Reset", `<p>html</p>`, `https://auth.example.test/reset?token=live-secret`)
	if err == nil {
		t.Fatal("enqueue without a keyring accepted a live recovery URL")
	}
	if rows := outboxRowCount(t, outbox); rows != 0 {
		t.Fatalf("rows=%d want=0", rows)
	}
}

// TestEmailOutboxEnqueueRespectsMasterKeyRetirementFence covers the sealed
// insert path: an enqueue that seals under the retired key must not commit a
// row, while an enqueue under the replacement key inserts and delivers.
func TestEmailOutboxEnqueueRespectsMasterKeyRetirementFence(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	retired, replacement := outboxFenceKeyrings(t)
	var delivered []string
	outbox := testEmailOutbox(t, func(_ context.Context, recipient, subject, textBody, htmlBody string) error {
		delivered = append(delivered, recipient+"|"+subject+"|"+textBody+"|"+htmlBody)
		return nil
	}, WithEnvelopeKeyring(retired))
	outbox.Now = func() time.Time { return now }
	seedOutboxRetirement(t, outbox, "fenced")

	if err := outbox.Enqueue(t.Context(), "user@example.test", "password reset", "Reset", "<p>html</p>", outboxTestBody); err == nil {
		t.Fatal("enqueue sealed under the retired key committed a row")
	}
	if rows := outboxRowCount(t, outbox); rows != 0 {
		t.Fatalf("fenced enqueue rows=%d want=0", rows)
	}

	// The retry lands on a later instant, so it is a new enqueue request rather
	// than a replay of the rejected one.
	now = now.Add(time.Second)
	outbox.keyring = replacement
	if err := outbox.Enqueue(t.Context(), "user@example.test", "password reset", "Reset", "<p>html</p>", outboxTestBody); err != nil {
		t.Fatalf("enqueue under the replacement key: %v", err)
	}
	id := onlyOutboxID(t, outbox)
	if err := outbox.Step(t.Context()); err != nil {
		t.Fatalf("deliver replacement row: %v", err)
	}
	if row := readOutboxRow(t, outbox, id); row.status != "sent" {
		t.Fatalf("replacement row after delivery=%+v", row)
	}
	want := "user@example.test|Reset|" + outboxTestBody + "|<p>html</p>"
	if len(delivered) != 1 || delivered[0] != want {
		t.Fatalf("delivered=%q want=%q", delivered, want)
	}
}

// TestEmailOutboxEnqueueRejectsSealThatOutlivesItsFence pauses an enqueue
// between sealing its payload and inserting its row, advances retirement past
// that seal, then resumes it. The fenced state and the post-readiness ready
// state must both reject the insert.
func TestEmailOutboxEnqueueRejectsSealThatOutlivesItsFence(t *testing.T) {
	t.Parallel()
	for _, state := range []string{"fenced", "ready"} {
		t.Run(state, func(t *testing.T) {
			retired, _ := outboxFenceKeyrings(t)
			pausing := &pausingOutboxKeyring{inner: retired, sealed: make(chan struct{}), release: make(chan struct{})}
			outbox := testEmailOutbox(t, nil, WithEnvelopeKeyring(pausing))
			seedOutboxRetirement(t, outbox, "prepared")

			enqueued := make(chan error, 1)
			go func() {
				enqueued <- outbox.Enqueue(t.Context(), "user@example.test", "password reset", "Reset", "<p>html</p>", outboxTestBody)
			}()
			select {
			case <-pausing.sealed:
			case <-time.After(30 * time.Second):
				t.Fatal("enqueue never sealed its payload")
			}
			seedOutboxRetirement(t, outbox, state)
			close(pausing.release)

			if err := <-enqueued; err == nil {
				t.Fatalf("enqueue sealed before the %s transition committed a row", state)
			}
			if rows := outboxRowCount(t, outbox); rows != 0 {
				t.Fatalf("%s enqueue rows=%d want=0", state, rows)
			}
		})
	}
}

// pausingOutboxKeyring seals through the real keyring and holds the first seal
// until the test releases it, which is the window between sealing a payload and
// inserting its row.
type pausingOutboxKeyring struct {
	inner   OutboxKeyring
	sealed  chan struct{}
	release chan struct{}
	held    bool
}

func (k *pausingOutboxKeyring) SealEnvelope(purpose string, plaintext []byte) ([]byte, error) {
	envelope, err := k.inner.SealEnvelope(purpose, plaintext)
	if err != nil || k.held {
		return envelope, err
	}
	k.held = true
	close(k.sealed)
	<-k.release
	return envelope, nil
}

func (k *pausingOutboxKeyring) OpenEnvelope(purpose string, envelope []byte) ([]byte, error) {
	return k.inner.OpenEnvelope(purpose, envelope)
}

func (k *pausingOutboxKeyring) PurposeEnvelopeKeyID(purpose string, envelope []byte) (string, error) {
	return k.inner.PurposeEnvelopeKeyID(purpose, envelope)
}

// outboxFenceKeyrings returns keyrings over one master key directory with
// key-a and key-b active, so a test can fence A->B.
func outboxFenceKeyrings(t *testing.T) (retired, replacement *oidc.Keyring) {
	t.Helper()
	directory := t.TempDir()
	for _, id := range []string{"key-a", "key-b"} {
		value := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{id[len(id)-1]}, 32))
		if err := os.WriteFile(filepath.Join(directory, id), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	retired, err := oidc.LoadKeyring(directory, "key-a")
	if err != nil {
		t.Fatal(err)
	}
	replacement, err = oidc.LoadKeyring(directory, "key-b")
	if err != nil {
		t.Fatal(err)
	}
	return retired, replacement
}

// seedOutboxRetirement writes the A->B barrier in one state, replacing any
// earlier state so a test can advance retirement while an enqueue is paused.
func seedOutboxRetirement(t *testing.T, outbox *EmailOutbox, state string) {
	t.Helper()
	preparedAt := int64(1_800_000_000_000)
	var fencedAt, readyAt any
	switch state {
	case "prepared":
	case "fenced":
		fencedAt = preparedAt + 1
	case "ready":
		fencedAt, readyAt = preparedAt+1, preparedAt+2
	default:
		t.Fatalf("unsupported outbox retirement state %q", state)
	}
	_, err := storage.Execute(t.Context(), outbox.DB, rhiza.ExecuteRequest{
		RequestID: "outbox-test-retirement/" + state,
		SQL:       "INSERT INTO master_key_retirement_barrier (barrier_id, epoch, old_key_id, replacement_key_id, membership_digest, state, prepared_at_unix_ms, fenced_at_unix_ms, ready_at_unix_ms) VALUES (1, 1, 'key-a', 'key-b', ?, ?, ?, ?, ?) ON CONFLICT(barrier_id) DO UPDATE SET state=excluded.state, fenced_at_unix_ms=excluded.fenced_at_unix_ms, ready_at_unix_ms=excluded.ready_at_unix_ms",
		Args:      []any{strings.Repeat("a", 43), state, preparedAt, fencedAt, readyAt},
	})
	if err != nil {
		t.Fatalf("seed %s retirement: %v", state, err)
	}
}

func TestEmailOutboxDeliversLegacyPlaintextRow(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	// outboxRetirementGenerations mirrors the v105 durable generation record
	// that the envelope admission statement consults in every barrier state.
	const outboxRetirementGenerations = `CREATE TABLE IF NOT EXISTS master_key_retirement_generations (
		epoch INTEGER PRIMARY KEY CHECK (epoch > 0),
		old_key_id TEXT NOT NULL CHECK (length(old_key_id) BETWEEN 1 AND 64 AND old_key_id NOT GLOB '*[^A-Za-z0-9._-]*'),
		replacement_key_id TEXT NOT NULL CHECK (length(replacement_key_id) BETWEEN 1 AND 64 AND replacement_key_id NOT GLOB '*[^A-Za-z0-9._-]*' AND replacement_key_id <> old_key_id),
		ready_at_unix_ms INTEGER CHECK (ready_at_unix_ms IS NULL OR ready_at_unix_ms >= 0),
		removed_at_unix_ms INTEGER CHECK (removed_at_unix_ms IS NULL OR (ready_at_unix_ms IS NOT NULL AND removed_at_unix_ms >= ready_at_unix_ms))
	) STRICT`
	t.Helper()
	if sendFn == nil {
		sendFn = func(context.Context, string, string, string, string) error { return nil }
	}
	db, err := rhiza.Open(t.Context(), rhiza.Config{NodeID: "email-outbox-test", DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	statements := append(emailOutboxSchemaStatements(),
		rhiza.SQLStatement{SQL: outboxRetirementBarrier},
		rhiza.SQLStatement{SQL: outboxRetirementGenerations})
	if _, err := storage.Execute(t.Context(), db, rhiza.ExecuteRequest{RequestID: "email-outbox-test-schema", Statements: statements}); err != nil {
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
