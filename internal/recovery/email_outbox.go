package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	mail "github.com/wneessen/go-mail"
)

const (
	outboxLeaseDuration = 2 * time.Minute
	outboxMaxAttempts   = 10
	outboxRetryBase     = 1 * time.Minute
	outboxRetryMax      = 30 * time.Minute
	outboxCleanupAge    = 24 * time.Hour
	// outboxCleanupBatch bounds one retention statement so housekeeping loops
	// over a small replicated delete instead of one unbounded transaction.
	outboxCleanupBatch = 256
	// outboxSealedPrefix marks a purpose envelope in a body column. Rows written
	// before payload sealing stay readable as plaintext.
	outboxSealedPrefix = "gaoop-sealed/v1:"
)

func emailOutboxSchemaStatements() []rhiza.SQLStatement {
	return []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS email_outbox (
			id TEXT PRIMARY KEY NOT NULL,
			recipient TEXT NOT NULL CHECK (length(recipient) BETWEEN 3 AND 254),
			mail_type TEXT NOT NULL CHECK (length(mail_type) BETWEEN 1 AND 256),
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			body_html TEXT NOT NULL DEFAULT '',
			body_text TEXT NOT NULL DEFAULT '',
			status TEXT NOT NULL CHECK (status IN ('pending','sent','failed')) DEFAULT 'pending',
			attempts INTEGER NOT NULL DEFAULT 0,
			last_error TEXT NOT NULL DEFAULT '',
			created_at_unix_ms INTEGER NOT NULL,
			updated_at_unix_ms INTEGER NOT NULL,
			next_retry_at_unix_ms INTEGER NOT NULL DEFAULT 0,
			lease_token TEXT,
			lease_until_unix_ms INTEGER
		) STRICT`},
	}
}

// OutboxKeyring seals queued mail bodies. *oidc.Keyring implements it.
// PurposeEnvelopeKeyID reports the master key embedded in a sealed envelope,
// so an enqueue can fence its insert on the key that actually sealed it.
type OutboxKeyring interface {
	SealEnvelope(purpose string, plaintext []byte) ([]byte, error)
	OpenEnvelope(purpose string, envelope []byte) ([]byte, error)
	PurposeEnvelopeKeyID(purpose string, envelope []byte) (string, error)
}

// EmailOutboxOption configures an outbox without changing existing callers.
type EmailOutboxOption func(*EmailOutbox)

// WithEnvelopeKeyring protects queued bodies with purpose-bound envelopes.
// Without one the outbox refuses to enqueue, because a queued body can carry a
// live recovery bearer URL that must not reach the replicated store in clear.
func WithEnvelopeKeyring(keyring OutboxKeyring) EmailOutboxOption {
	return func(o *EmailOutbox) { o.keyring = keyring }
}

type EmailOutbox struct {
	DB      *rhiza.DB
	Now     func() time.Time
	sendFn  func(ctx context.Context, recipient, subject, textBody, htmlBody string) error
	keyring OutboxKeyring
}

func NewEmailOutbox(db *rhiza.DB, sendFn func(ctx context.Context, recipient, subject, textBody, htmlBody string) error, options ...EmailOutboxOption) (*EmailOutbox, error) {
	if db == nil {
		return nil, errors.New("email outbox requires database")
	}
	if sendFn == nil {
		return nil, errors.New("email outbox requires send function")
	}
	outbox := &EmailOutbox{DB: db, Now: time.Now, sendFn: sendFn}
	for _, option := range options {
		if option != nil {
			option(outbox)
		}
	}
	return outbox, nil
}

func (o *EmailOutbox) SchemaStatements() []rhiza.SQLStatement {
	return emailOutboxSchemaStatements()
}

// Enqueue stores one delivery for retry. Bodies are sealed before the insert, so
// a missing keyring is an error instead of a plaintext write. The insert runs
// through storage.ExecuteEnvelope for the sealing key, so a master-key
// retirement fence rejects an enqueue that sealed under the retired key.
func (o *EmailOutbox) Enqueue(ctx context.Context, recipient, mailType, subject, htmlBody, textBody string) error {
	if o == nil || o.DB == nil {
		return errors.New("email outbox is not configured")
	}
	now := o.Now()
	id := outboxRequestID(recipient, mailType, now)
	sealedHTML, htmlKeyID, err := o.sealPayload(id, "html", htmlBody)
	if err != nil {
		return err
	}
	sealedText, textKeyID, err := o.sealPayload(id, "text", textBody)
	if err != nil {
		return err
	}
	if htmlKeyID != textKeyID {
		return errors.New("email outbox sealing key changed between payloads")
	}
	_, err = storage.ExecuteEnvelope(ctx, o.DB, htmlKeyID, rhiza.ExecuteRequest{
		RequestID: "email-outbox-enqueue/" + id,
		SQL:       `INSERT OR IGNORE INTO email_outbox (id, recipient, mail_type, subject, body_html, body_text, status, attempts, last_error, created_at_unix_ms, updated_at_unix_ms, next_retry_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, '', ?, ?, ?)`,
		Args:      []any{id, recipient, mailType, subject, sealedHTML, sealedText, now.UnixMilli(), now.UnixMilli(), now.UnixMilli()},
	})
	return err
}

func (o *EmailOutbox) Step(ctx context.Context) error {
	if o == nil || o.DB == nil {
		return errors.New("email outbox is not configured")
	}
	now := o.Now()
	tok, err := outboxRandomToken()
	if err != nil {
		return err
	}
	until := now.Add(outboxLeaseDuration).UnixMilli()
	_, err = storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{
		RequestID: "email-outbox-claim/" + tok,
		Statements: []rhiza.SQLStatement{
			// A final attempt whose lease expired without a completion write
			// (for example a crash) is terminal here; otherwise it would stay
			// pending forever and never reach retention.
			{SQL: `UPDATE email_outbox SET status='failed', last_error='maximum attempts reached', lease_token=NULL, lease_until_unix_ms=NULL, updated_at_unix_ms=? WHERE status='pending' AND attempts>=? AND (lease_until_unix_ms IS NULL OR lease_until_unix_ms<?)`, Args: []any{now.UnixMilli(), int64(outboxMaxAttempts), now.UnixMilli()}},
			{SQL: `UPDATE email_outbox SET lease_token=?, lease_until_unix_ms=?, attempts=attempts+1, status='pending', updated_at_unix_ms=? WHERE rowid IN (SELECT rowid FROM email_outbox WHERE status='pending' AND next_retry_at_unix_ms<=? AND (lease_until_unix_ms IS NULL OR lease_until_unix_ms<?) AND attempts<? ORDER BY created_at_unix_ms LIMIT 1)`, Args: []any{tok, until, now.UnixMilli(), now.UnixMilli(), now.UnixMilli(), int64(outboxMaxAttempts)}},
		},
	})
	if err != nil {
		return err
	}
	result, err := o.DB.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT id, recipient, subject, body_text, body_html, attempts, lease_token FROM email_outbox WHERE lease_token=?`,
		Args:        []any{tok},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}
	if len(result.Rows) == 0 {
		return nil
	}
	row := result.Rows[0]
	id, _ := row[0].(string)
	recipient, _ := row[1].(string)
	subject, _ := row[2].(string)
	storedText, _ := row[3].(string)
	storedHTML, _ := row[4].(string)
	attempts, _ := row[5].(int64)
	lease, _ := row[6].(string)
	if id == "" || lease == "" {
		return errors.New("invalid email outbox row")
	}
	textBody, err := o.openPayload(id, "text", storedText)
	if err != nil {
		return o.fail(ctx, id, lease, now, attempts, err)
	}
	htmlBody, err := o.openPayload(id, "html", storedHTML)
	if err != nil {
		return o.fail(ctx, id, lease, now, attempts, err)
	}
	if err := o.sendFn(ctx, recipient, subject, textBody, htmlBody); err != nil {
		return o.fail(ctx, id, lease, now, attempts, err)
	}
	return o.complete(ctx, id, lease, now, attempts)
}

// complete marks one owned attempt as sent. The lease and attempt are part of
// the request ID and the row must still be owned, so a stale owner can neither
// reserve the ID nor acknowledge a re-claimed row.
func (o *EmailOutbox) complete(ctx context.Context, id, lease string, now time.Time, attempts int64) error {
	one := int64(1)
	_, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{
		RequestID:  "email-outbox-ack/" + outboxCompletionID(id, lease, attempts),
		Statements: []rhiza.SQLStatement{{SQL: `UPDATE email_outbox SET status='sent', lease_token=NULL, lease_until_unix_ms=NULL, updated_at_unix_ms=? WHERE id=? AND lease_token=?`, Args: []any{now.UnixMilli(), id, lease}, ExpectedRowsAffected: &one}},
	})
	return err
}

// fail records one delivery failure. Retryable failures stay pending with a
// future next_retry time; only an exhausted attempt budget or a classified
// permanent error is terminal.
func (o *EmailOutbox) fail(ctx context.Context, id, lease string, now time.Time, attempts int64, sendErr error) error {
	errMsg := sendErr.Error()
	if len(errMsg) > 256 {
		errMsg = errMsg[:256]
	}
	status := "pending"
	nextRetry := now.Add(outboxBackoff(attempts)).UnixMilli()
	if attempts >= outboxMaxAttempts || outboxPermanentFailure(sendErr) {
		status = "failed"
		nextRetry = now.UnixMilli()
	}
	one := int64(1)
	_, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{
		RequestID:  "email-outbox-fail/" + outboxCompletionID(id, lease, attempts),
		Statements: []rhiza.SQLStatement{{SQL: `UPDATE email_outbox SET status=?, last_error=?, next_retry_at_unix_ms=?, lease_token=NULL, lease_until_unix_ms=NULL, updated_at_unix_ms=? WHERE id=? AND lease_token=?`, Args: []any{status, errMsg, nextRetry, now.UnixMilli(), id, lease}, ExpectedRowsAffected: &one}},
	})
	return err
}

// Cleanup removes at most one bounded batch of terminal rows past retention and
// reports how many rows it removed. Callers loop until it returns zero, so
// retention never holds the whole backlog in one replicated transaction.
func (o *EmailOutbox) Cleanup(ctx context.Context, limit int) (int64, error) {
	if o == nil || o.DB == nil {
		return 0, errors.New("email outbox is not configured")
	}
	if limit <= 0 || limit > outboxCleanupBatch {
		limit = outboxCleanupBatch
	}
	tok, err := outboxRandomToken()
	if err != nil {
		return 0, err
	}
	cutoff := o.Now().Add(-outboxCleanupAge).UnixMilli()
	response, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{
		RequestID: "email-outbox-cleanup/" + tok,
		SQL:       `DELETE FROM email_outbox WHERE id IN (SELECT id FROM email_outbox WHERE status IN ('sent','failed') AND updated_at_unix_ms<? ORDER BY updated_at_unix_ms LIMIT ?)`,
		Args:      []any{cutoff, int64(limit)},
	})
	if err != nil {
		return 0, err
	}
	return response.RowsAffected, nil
}

// outboxBackoff grows the retry delay with each attempt up to a fixed cap.
func outboxBackoff(attempts int64) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	if attempts > outboxMaxAttempts {
		attempts = outboxMaxAttempts
	}
	delay := outboxRetryBase * time.Duration(1<<(attempts-1))
	if delay > outboxRetryMax {
		delay = outboxRetryMax
	}
	return delay
}

// outboxPermanentFailure accepts only errors that cannot succeed on a retry:
// SMTP 5xx replies and invalid-address rejections. Dial, TLS, timeout, and 4xx
// failures stay retryable.
func outboxPermanentFailure(err error) bool {
	var sendErr *mail.SendError
	if errors.As(err, &sendErr) && sendErr != nil {
		return sendErr.ErrorCode() >= 500 && sendErr.ErrorCode() < 600
	}
	return errors.Is(err, ErrInvalidEmail)
}

// outboxPayloadPurpose binds one body column of one row, so a sealed payload
// cannot be replayed into another row or the other column.
func outboxPayloadPurpose(id, field string) string {
	digest := sha256.Sum256([]byte(id + "\x00" + field))
	return "email/outbox/" + base64.RawURLEncoding.EncodeToString(digest[:16])
}

// sealPayload seals one body and reports the master key that sealed it, so the
// caller can fence the row insert on that exact key.
func (o *EmailOutbox) sealPayload(id, field, body string) (string, string, error) {
	if o.keyring == nil {
		return "", "", errors.New("email outbox requires an envelope keyring to protect queued payloads")
	}
	purpose := outboxPayloadPurpose(id, field)
	envelope, err := o.keyring.SealEnvelope(purpose, []byte(body))
	if err != nil {
		return "", "", fmt.Errorf("seal email outbox %s payload: %w", field, err)
	}
	keyID, err := o.keyring.PurposeEnvelopeKeyID(purpose, envelope)
	if err != nil {
		return "", "", fmt.Errorf("identify email outbox %s sealing key: %w", field, err)
	}
	return outboxSealedPrefix + base64.RawStdEncoding.EncodeToString(envelope), keyID, nil
}

func (o *EmailOutbox) openPayload(id, field, stored string) (string, error) {
	if !strings.HasPrefix(stored, outboxSealedPrefix) {
		// Rows enqueued before payload sealing stay deliverable.
		return stored, nil
	}
	if o.keyring == nil {
		return "", errors.New("email outbox cannot open a sealed payload without an envelope keyring")
	}
	envelope, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, outboxSealedPrefix))
	if err != nil {
		return "", fmt.Errorf("decode email outbox %s payload: %w", field, err)
	}
	plaintext, err := o.keyring.OpenEnvelope(outboxPayloadPurpose(id, field), envelope)
	if err != nil {
		return "", fmt.Errorf("open email outbox %s payload: %w", field, err)
	}
	return string(plaintext), nil
}

func outboxRequestID(recipient, mailType string, now time.Time) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", recipient, mailType, now.UnixNano())))
	return hex.EncodeToString(h[:16])
}

// outboxCompletionID scopes a completion request to the row, its lease, and the
// attempt. Rhiza rejects a reused request ID whose statement or arguments
// differ, so two owners of one row must never share a completion ID.
func outboxCompletionID(id, lease string, attempts int64) string {
	return outboxShortID(fmt.Sprintf("%s\x00%s\x00%d", id, lease, attempts))
}

func outboxShortID(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func outboxRandomToken() (string, error) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(token), nil
}

func SMTPSendFunc(sender *SMTPSender) func(ctx context.Context, recipient, subject, textBody, htmlBody string) error {
	return func(ctx context.Context, recipient, subject, textBody, htmlBody string) error {
		if sender == nil || sender.send == nil {
			return errors.New("SMTP sender unavailable")
		}
		to, err := canonicalEmail(recipient)
		if err != nil {
			return ErrInvalidEmail
		}
		msg := mail.NewMsg()
		if err := msg.From(sender.config.From); err != nil {
			return errors.New("invalid SMTP from address")
		}
		if err := msg.To(to); err != nil {
			return ErrInvalidEmail
		}
		msg.Subject(subject)
		msg.SetBodyString(mail.TypeTextPlain, textBody)
		msg.AddAlternativeString(mail.TypeTextHTML, htmlBody)
		return sender.send(ctx, msg)
	}
}
