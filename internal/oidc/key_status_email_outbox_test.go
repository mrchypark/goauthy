package oidc

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

// TestInspectMasterKeyReferencesCountsEmailOutboxEnvelopes proves queued mail
// is part of the retirement evidence: rows sealed under a retained key make the
// status unsafe, a legacy plaintext row references no key, and rewrapping every
// remaining row restores safety.
func TestInspectMasterKeyReferencesCountsEmailOutboxEnvelopes(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	issuer := "https://id.example.com"
	now := time.Unix(1_900_000_000, 0).UTC()
	active := fixedKeyring("master-b")
	old := fixedKeyring("master-a")

	insertStatusOutbox(t, ctx, db, old, "old-row", "queued under the retained key")
	insertStatusOutbox(t, ctx, db, active, "active-row", "queued under the active key")
	insertStatusOutbox(t, ctx, db, nil, "legacy-row", "plain body")

	status, err := InspectMasterKeyReferences(ctx, db, active, issuer, now)
	if err != nil {
		t.Fatal(err)
	}
	if status.EmailOutbox.Total != 4 || status.EmailOutbox.ByKeyID["master-a"] != 2 || status.EmailOutbox.ByKeyID["master-b"] != 2 {
		t.Fatalf("outbox family=%+v", status.EmailOutbox)
	}
	if status.Safe {
		t.Fatal("status is safe while queued mail still references a retained key")
	}

	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "key-status-outbox-rewrap", SQL: `DELETE FROM email_outbox WHERE id='old-row'`}); err != nil {
		t.Fatal(err)
	}
	status, err = InspectMasterKeyReferences(ctx, db, active, issuer, now)
	if err != nil || !status.Safe || status.EmailOutbox.Total != 2 || status.EmailOutbox.ByKeyID["master-b"] != 2 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

// TestInspectMasterKeyReferencesFailsClosedForTamperedOutboxBody covers a
// malformed sealed body: it must never be counted as key-free.
func TestInspectMasterKeyReferencesFailsClosedForTamperedOutboxBody(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	active := fixedKeyring("master-b")
	now := time.Unix(1_900_000_000, 0).UTC()
	insertStatusOutbox(t, ctx, db, active, "tampered-row", "body")
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "key-status-outbox-tamper", SQL: `UPDATE email_outbox SET body_html=? WHERE id='tampered-row'`, Args: []any{emailOutboxSealedPrefix + "not-base64!!"}}); err != nil {
		t.Fatal(err)
	}

	status, err := InspectMasterKeyReferences(ctx, db, active, "https://id.example.com", now)
	if !errors.Is(err, ErrUnsafeMasterKeyStatus) || status.Safe {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

// TestEmailOutboxPayloadPurposeMatchesRecoveryWriter pins the binding literal,
// so a drift from the recovery outbox writer fails here instead of silently
// skipping sealed rows.
func TestEmailOutboxPayloadPurposeMatchesRecoveryWriter(t *testing.T) {
	if got, want := emailOutboxPayloadPurpose("old-row", "html"), "email/outbox/Cos_FjVpWL8XLUS-b5NHCw"; got != want {
		t.Fatalf("purpose=%q want=%q", got, want)
	}
	if emailOutboxSealedPrefix != "gaoop-sealed/v1:" {
		t.Fatalf("prefix=%q", emailOutboxSealedPrefix)
	}
}

// insertStatusOutbox writes one queued mail row. A nil keyring writes the
// legacy plaintext shape that carries no envelope.
func insertStatusOutbox(t *testing.T, ctx context.Context, db *rhiza.DB, keyring *Keyring, id, body string) {
	t.Helper()
	sealed := func(field string) string {
		if keyring == nil {
			return body
		}
		envelope, err := keyring.SealEnvelope(emailOutboxPayloadPurpose(id, field), []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		return emailOutboxSealedPrefix + base64.RawStdEncoding.EncodeToString(envelope)
	}
	at := time.Unix(1_900_000_000, 0).UnixMilli()
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "key-status-outbox-" + id, SQL: `INSERT INTO email_outbox (id, recipient, mail_type, subject, body_html, body_text, status, attempts, last_error, created_at_unix_ms, updated_at_unix_ms, next_retry_at_unix_ms) VALUES (?, 'user@example.test', 'password reset', 'Reset', ?, ?, 'pending', 0, '', ?, ?, 0)`, Args: []any{id, sealed("html"), sealed("text"), at, at}}); err != nil {
		t.Fatal(err)
	}
}

// TestRewrapEmailOutboxBatchMovesSealedBodiesToActiveKey covers the rewrap half
// of the family: sealed bodies move to the active key, a legacy plaintext body
// is left alone, and the reference gate returns to safe.
func TestRewrapEmailOutboxBatchMovesSealedBodiesToActiveKey(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	active, old := fixedKeyring("master-b"), fixedKeyring("master-a")
	insertStatusOutbox(t, ctx, db, old, "queued-row", "recovery body")
	insertStatusOutbox(t, ctx, db, nil, "legacy-row", "plain body")

	result, err := RewrapEmailOutboxBatch(ctx, db, active, "")
	if err != nil || result.Rewrapped != 2 || !result.Done {
		t.Fatalf("rewrap=%+v err=%v", result, err)
	}
	html, text := readStatusOutboxBodies(t, ctx, db, "queued-row")
	for _, column := range []struct{ field, stored string }{{"html", html}, {"text", text}} {
		envelope, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(column.stored, emailOutboxSealedPrefix))
		if err != nil {
			t.Fatalf("%s body is not sealed: %q", column.field, column.stored)
		}
		purpose := emailOutboxPayloadPurpose("queued-row", column.field)
		if keyID, err := active.PurposeEnvelopeKeyID(purpose, envelope); err != nil || keyID != "master-b" {
			t.Fatalf("%s key=%q err=%v", column.field, keyID, err)
		}
		if plain, err := active.OpenEnvelope(purpose, envelope); err != nil || string(plain) != "recovery body" {
			t.Fatalf("%s plain=%q err=%v", column.field, plain, err)
		}
	}
	if legacy, legacyText := readStatusOutboxBodies(t, ctx, db, "legacy-row"); legacy != "plain body" || legacyText != "plain body" {
		t.Fatalf("legacy bodies=%q/%q", legacy, legacyText)
	}
	if repeated, err := RewrapEmailOutboxBatch(ctx, db, active, ""); err != nil || repeated.Rewrapped != 0 || !repeated.Done {
		t.Fatalf("second rewrap=%+v err=%v", repeated, err)
	}
	status, err := InspectMasterKeyReferences(ctx, db, active, "https://id.example.com", time.Unix(1_900_000_000, 0).UTC())
	if err != nil || !status.Safe || status.EmailOutbox.Total != 2 || status.EmailOutbox.ByKeyID["master-b"] != 2 {
		t.Fatalf("status=%+v err=%v", status, err)
	}
}

// TestRewrapEmailOutboxBatchHonorsFencedOldWriter keeps the fail-closed fence:
// a fenced old writer cannot commit and the queued bodies stay untouched.
func TestRewrapEmailOutboxBatchHonorsFencedOldWriter(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	insertStatusOutbox(t, ctx, db, fixedKeyring("master-b"), "fenced-row", "recovery body")
	beforeHTML, beforeText := readStatusOutboxBodies(t, ctx, db, "fenced-row")
	fenceOIDCWriter(t, db, "master-a", "master-b", nowForTest())
	if _, err := RewrapEmailOutboxBatch(ctx, db, fixedKeyring("master-a"), ""); err == nil {
		t.Fatal("fenced old email outbox writer committed")
	}
	if html, text := readStatusOutboxBodies(t, ctx, db, "fenced-row"); html != beforeHTML || text != beforeText {
		t.Fatalf("fenced bodies changed: %q/%q -> %q/%q", beforeHTML, beforeText, html, text)
	}
}

func readStatusOutboxBodies(t *testing.T, ctx context.Context, db *rhiza.DB, id string) (string, string) {
	t.Helper()
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT body_html,body_text FROM email_outbox WHERE id=?`, Args: []any{id}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		t.Fatalf("outbox row %s=%v err=%v", id, result.Rows, err)
	}
	html, htmlOK := result.Rows[0][0].(string)
	text, textOK := result.Rows[0][1].(string)
	if !htmlOK || !textOK {
		t.Fatalf("outbox row %s types=%T/%T", id, result.Rows[0][0], result.Rows[0][1])
	}
	return html, text
}
