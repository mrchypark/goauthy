package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	mail "github.com/wneessen/go-mail"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const (
	outboxLeaseDuration = 2 * time.Minute
	outboxMaxAttempts   = 10
	outboxRetryBase     = 1 * time.Minute
	outboxCleanupAge    = 24 * time.Hour
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

type EmailOutbox struct {
	DB     *rhiza.DB
	Now    func() time.Time
	sendFn func(ctx context.Context, recipient, subject, textBody, htmlBody string) error
}

func NewEmailOutbox(db *rhiza.DB, sendFn func(ctx context.Context, recipient, subject, textBody, htmlBody string) error) (*EmailOutbox, error) {
	if db == nil {
		return nil, errors.New("email outbox requires database")
	}
	if sendFn == nil {
		return nil, errors.New("email outbox requires send function")
	}
	return &EmailOutbox{DB: db, Now: time.Now, sendFn: sendFn}, nil
}

func (o *EmailOutbox) SchemaStatements() []rhiza.SQLStatement {
	return emailOutboxSchemaStatements()
}

func (o *EmailOutbox) Enqueue(ctx context.Context, recipient, mailType, subject, htmlBody, textBody string) error {
	now := o.Now()
	id := outboxRequestID(recipient, mailType, now)
	_, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{
		RequestID: "email-outbox-enqueue/" + id,
		SQL:       `INSERT OR IGNORE INTO email_outbox (id, recipient, mail_type, subject, body_html, body_text, status, attempts, last_error, created_at_unix_ms, updated_at_unix_ms, next_retry_at_unix_ms) VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, '', ?, ?, ?)`,
		Args:      []any{id, recipient, mailType, subject, htmlBody, textBody, now.UnixMilli(), now.UnixMilli(), now.UnixMilli()},
	})
	return err
}

func (o *EmailOutbox) Step(ctx context.Context) error {
	now := o.Now()
	tok, err := outboxRandomToken()
	if err != nil {
		return err
	}
	until := now.Add(outboxLeaseDuration).UnixMilli()
	_, err = storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{
		RequestID: "email-outbox-claim/" + tok,
		SQL:       `UPDATE email_outbox SET lease_token=?, lease_until_unix_ms=?, attempts=attempts+1, status='pending', updated_at_unix_ms=? WHERE rowid IN (SELECT rowid FROM email_outbox WHERE status='pending' AND next_retry_at_unix_ms<=? AND (lease_until_unix_ms IS NULL OR lease_until_unix_ms<?) AND attempts<? ORDER BY created_at_unix_ms LIMIT 1)`,
		Args:      []any{tok, until, now.UnixMilli(), now.UnixMilli(), now.UnixMilli(), int64(outboxMaxAttempts)},
	})
	if err != nil {
		return err
	}
	result, err := o.DB.Query(ctx, rhiza.QueryRequest{
		SQL:       `SELECT id, recipient, subject, body_text, body_html, attempts, lease_token FROM email_outbox WHERE lease_token=?`,
		Args:      []any{tok},
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
	textBody, _ := row[3].(string)
	htmlBody, _ := row[4].(string)
	attempts, _ := row[5].(int64)
	lease, _ := row[6].(string)
	if err := o.sendFn(ctx, recipient, subject, textBody, htmlBody); err != nil {
		return o.fail(ctx, id, lease, now, attempts, err)
	}
	_, err = storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{
		RequestID: "email-outbox-ack/" + outboxShortID(id),
		SQL:       `UPDATE email_outbox SET status='sent', lease_token=NULL, lease_until_unix_ms=NULL, updated_at_unix_ms=? WHERE id=? AND lease_token=?`,
		Args:      []any{now.UnixMilli(), id, lease},
	})
	return err
}

func (o *EmailOutbox) fail(ctx context.Context, id, lease string, now time.Time, attempts int64, sendErr error) error {
	errMsg := sendErr.Error()
	if len(errMsg) > 256 {
		errMsg = errMsg[:256]
	}
	delay := outboxRetryBase * time.Duration(1<<(attempts-1))
	if delay > 30*time.Minute {
		delay = 30 * time.Minute
	}
	nextRetry := now.Add(delay).UnixMilli()
	_, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{
		RequestID: "email-outbox-fail/" + outboxShortID(id),
		SQL:       `UPDATE email_outbox SET status='failed', last_error=?, next_retry_at_unix_ms=?, lease_token=NULL, lease_until_unix_ms=NULL, updated_at_unix_ms=? WHERE id=? AND lease_token=?`,
		Args:      []any{errMsg, nextRetry, now.UnixMilli(), id, lease},
	})
	return err
}

func (o *EmailOutbox) Cleanup(ctx context.Context) error {
	now := o.Now()
	cutoff := now.Add(-outboxCleanupAge).UnixMilli()
	_, err := storage.Execute(ctx, o.DB, rhiza.ExecuteRequest{
		RequestID: "email-outbox-cleanup/" + outboxShortID(fmt.Sprintf("%d", cutoff)),
		SQL:       `DELETE FROM email_outbox WHERE (status='sent' OR status='failed') AND updated_at_unix_ms<?`,
		Args:      []any{cutoff},
	})
	return err
}

func outboxRequestID(recipient, mailType string, now time.Time) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", recipient, mailType, now.UnixNano())))
	return hex.EncodeToString(h[:16])
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
