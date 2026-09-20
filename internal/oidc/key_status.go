package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const masterKeyStatusScanLimit = 64

var ErrUnsafeMasterKeyStatus = errors.New("master-key reference status is unsafe")

// MasterKeyReferenceFamily is a cryptographically authenticated count of the
// live envelopes in one storage family. Counts never include ciphertext or
// plaintext.
type MasterKeyReferenceFamily struct {
	ByKeyID map[string]int64
	Total   int64
}

// MasterKeyReferenceStatus is read-only evidence for deciding whether a
// non-active master key is still referenced. Safe only says every scanned
// envelope authenticates and uses ActiveMasterKeyID; it never authorizes key
// deletion.
type MasterKeyReferenceStatus struct {
	ActiveMasterKeyID        string
	CheckedAt                time.Time
	SigningKeys              MasterKeyReferenceFamily
	DCRIdempotency           MasterKeyReferenceFamily
	Upstream                 MasterKeyReferenceFamily
	ManagedClients           MasterKeyReferenceFamily
	LoginRevoke              MasterKeyReferenceFamily
	GeneratedAPIKeyBootstrap MasterKeyReferenceFamily
	EmailOutbox              MasterKeyReferenceFamily
	Safe                     bool
}

// InspectMasterKeyReferences linearly reads every durable envelope family plus
// every DCR and upstream envelope that is live at now. Each bounded page uses
// linearizable consistency and every envelope is authenticated before it is
// counted. Malformed, tampered, or unknown-key rows fail closed with
// ErrUnsafeMasterKeyStatus and no partial result marked Safe.
//
// The scan is not a cluster-wide write barrier. Before removing a key,
// operators must first ensure every pod reports the same active ID and wait
// past DCR/upstream TTLs and signing-key retirement windows.
func InspectMasterKeyReferences(ctx context.Context, db *rhiza.DB, keyring *Keyring, issuer string, now time.Time) (MasterKeyReferenceStatus, error) {
	status := MasterKeyReferenceStatus{SigningKeys: emptyReferenceFamily(), DCRIdempotency: emptyReferenceFamily(), Upstream: emptyReferenceFamily(), ManagedClients: emptyReferenceFamily(), LoginRevoke: emptyReferenceFamily(), GeneratedAPIKeyBootstrap: emptyReferenceFamily(), EmailOutbox: emptyReferenceFamily()}
	if ctx == nil || db == nil || keyring == nil || now.IsZero() {
		return status, ErrUnsafeMasterKeyStatus
	}
	activeID, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return status, ErrUnsafeMasterKeyStatus
	}
	normalizedIssuer, err := NormalizeIssuer(issuer)
	if err != nil || normalizedIssuer != issuer {
		return status, ErrUnsafeMasterKeyStatus
	}
	now = now.UTC().Truncate(time.Millisecond)
	status.ActiveMasterKeyID, status.CheckedAt = activeID, now

	if err := scanSigningKeyReferences(ctx, db, keyring, normalizedIssuer, &status.SigningKeys); err != nil {
		return unsafeMasterKeyStatus(status)
	}
	if err := scanDCRIdempotencyReferences(ctx, db, keyring, now, &status.DCRIdempotency); err != nil {
		return unsafeMasterKeyStatus(status)
	}
	if err := scanUpstreamReferences(ctx, db, keyring, now, &status.Upstream); err != nil {
		return unsafeMasterKeyStatus(status)
	}
	if err := scanManagedClientReferences(ctx, db, keyring, &status.ManagedClients); err != nil {
		return unsafeMasterKeyStatus(status)
	}
	if err := scanLoginRevokeReferences(ctx, db, keyring, &status.LoginRevoke); err != nil {
		return unsafeMasterKeyStatus(status)
	}
	if err := scanGeneratedAPIKeyBootstrapReferences(ctx, db, keyring, &status.GeneratedAPIKeyBootstrap); err != nil {
		return unsafeMasterKeyStatus(status)
	}
	if err := scanEmailOutboxReferences(ctx, db, keyring, &status.EmailOutbox); err != nil {
		return unsafeMasterKeyStatus(status)
	}
	status.Safe = familyUsesOnly(status.SigningKeys, activeID) && familyUsesOnly(status.DCRIdempotency, activeID) && familyUsesOnly(status.Upstream, activeID) && familyUsesOnly(status.ManagedClients, activeID) && familyUsesOnly(status.LoginRevoke, activeID) && familyUsesOnly(status.GeneratedAPIKeyBootstrap, activeID) && familyUsesOnly(status.EmailOutbox, activeID)
	return status, nil
}

func scanLoginRevokeReferences(ctx context.Context, db *rhiza.DB, keyring *Keyring, family *MasterKeyReferenceFamily) error {
	exists, err := loginRevokeTableExists(ctx, db)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	cursor := ""
	for {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT subject,generation,code_envelope FROM identity_login_revoke WHERE subject > ? ORDER BY subject LIMIT ?`, Args: []any{cursor, int64(masterKeyStatusScanLimit)}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return err
		}
		for _, row := range result.Rows {
			if len(row) != 3 {
				return ErrUnsafeMasterKeyStatus
			}
			subject, subjectOK := row[0].(string)
			generation, generationOK := row[1].(string)
			envelope, envelopeOK := loginRevokeEnvelopeBytes(row[2])
			if !subjectOK || !generationOK || subject == "" || generation == "" || !envelopeOK || len(envelope) == 0 {
				return ErrUnsafeMasterKeyStatus
			}
			keyID, err := keyring.PurposeEnvelopeKeyID(LoginRevokeCodePurpose(subject, generation), envelope)
			if err != nil {
				return ErrUnsafeMasterKeyStatus
			}
			addReference(family, keyID)
			cursor = subject
		}
		if len(result.Rows) < masterKeyStatusScanLimit {
			return nil
		}
	}
}

func scanGeneratedAPIKeyBootstrapReferences(ctx context.Context, db *rhiza.DB, keyring *Keyring, family *MasterKeyReferenceFamily) error {
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT payload_envelope FROM generated_api_key_bootstrap WHERE singleton=1 AND payload_envelope IS NOT NULL`, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return err
	}
	if len(result.Rows) > 1 {
		return ErrUnsafeMasterKeyStatus
	}
	if len(result.Rows) == 0 {
		return nil
	}
	if len(result.Rows[0]) != 1 {
		return ErrUnsafeMasterKeyStatus
	}
	envelope, ok := result.Rows[0][0].([]byte)
	if !ok || len(envelope) == 0 {
		return ErrUnsafeMasterKeyStatus
	}
	keyID, err := keyring.PurposeEnvelopeKeyID(GeneratedAPIKeyBootstrapEnvelopePurpose, envelope)
	if err != nil {
		return ErrUnsafeMasterKeyStatus
	}
	addReference(family, keyID)
	return nil
}

// emailOutboxSealedPrefix marks a sealed queued mail body. emailOutboxPayloadPurpose
// mirrors the recovery outbox binding of one body column of one row; the
// purpose is not stored with the row, so it is duplicated here. A drift makes
// the envelope fail authentication, which fails the whole scan closed instead
// of counting an unauthenticated reference.
const emailOutboxSealedPrefix = "gaoop-sealed/v1:"

func emailOutboxPayloadPurpose(id, field string) string {
	digest := sha256.Sum256([]byte(id + "\x00" + field))
	return "email/outbox/" + base64.RawURLEncoding.EncodeToString(digest[:16])
}

// scanEmailOutboxReferences reads every queued mail row, including terminal
// rows still waiting out retention, so a key cannot be declared unused while a
// queued body remains sealed under it. A body written before payload sealing
// carries no envelope and references no key.
func scanEmailOutboxReferences(ctx context.Context, db *rhiza.DB, keyring *Keyring, family *MasterKeyReferenceFamily) error {
	cursor := ""
	for {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,body_html,body_text FROM email_outbox WHERE id > ? ORDER BY id LIMIT ?`, Args: []any{cursor, int64(masterKeyStatusScanLimit)}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return err
		}
		for _, row := range result.Rows {
			if len(row) != 3 {
				return ErrUnsafeMasterKeyStatus
			}
			id, idOK := row[0].(string)
			html, htmlOK := row[1].(string)
			text, textOK := row[2].(string)
			if !idOK || !htmlOK || !textOK || id == "" {
				return ErrUnsafeMasterKeyStatus
			}
			for _, column := range []struct{ field, body string }{{"html", html}, {"text", text}} {
				if err := addEmailOutboxReference(keyring, family, id, column.field, column.body); err != nil {
					return err
				}
			}
			cursor = id
		}
		if len(result.Rows) < masterKeyStatusScanLimit {
			return nil
		}
	}
}

func addEmailOutboxReference(keyring *Keyring, family *MasterKeyReferenceFamily, id, field, body string) error {
	if !strings.HasPrefix(body, emailOutboxSealedPrefix) {
		return nil
	}
	envelope, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(body, emailOutboxSealedPrefix))
	if err != nil || len(envelope) == 0 {
		return ErrUnsafeMasterKeyStatus
	}
	keyID, err := keyring.PurposeEnvelopeKeyID(emailOutboxPayloadPurpose(id, field), envelope)
	if err != nil {
		return ErrUnsafeMasterKeyStatus
	}
	addReference(family, keyID)
	return nil
}

// emailOutboxRewrapBatchSize bounds one rewrap statement batch, matching the
// other purpose-envelope families.
const emailOutboxRewrapBatchSize = 32

// RewrapEmailOutboxBatch re-encrypts at most 32 queued mail bodies under the
// active master key and CASes each original ciphertext, so a concurrent
// enqueue or delivery is never clobbered. A body written before payload
// sealing holds plaintext and is left alone; a malformed sealed body fails the
// batch instead of being silently counted as rewrapped.
func RewrapEmailOutboxBatch(ctx context.Context, db *rhiza.DB, keyring *Keyring, cursor string) (SigningKeyRewrapBatchResult, error) {
	if db == nil || keyring == nil {
		return SigningKeyRewrapBatchResult{}, errors.New("email outbox rewrap is not configured")
	}
	active, err := keyring.ActiveMasterKeyID()
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,body_html,body_text FROM email_outbox WHERE id > ? ORDER BY id LIMIT ?`, Args: []any{cursor, int64(emailOutboxRewrapBatchSize)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return SigningKeyRewrapBatchResult{}, err
	}
	if len(result.Rows) == 0 {
		return SigningKeyRewrapBatchResult{Cursor: cursor, Done: true}, nil
	}
	last := cursor
	changed := int64(0)
	for _, row := range result.Rows {
		if len(row) != 3 {
			return SigningKeyRewrapBatchResult{}, errors.New("invalid email outbox envelope row")
		}
		id, idOK := row[0].(string)
		html, htmlOK := row[1].(string)
		text, textOK := row[2].(string)
		if !idOK || !htmlOK || !textOK || id == "" {
			return SigningKeyRewrapBatchResult{}, errors.New("invalid email outbox envelope row")
		}
		last = id
		for _, column := range []struct{ field, body, update string }{
			{"html", html, `UPDATE email_outbox SET body_html=? WHERE id=? AND body_html=?`},
			{"text", text, `UPDATE email_outbox SET body_text=? WHERE id=? AND body_text=?`},
		} {
			replacement, ok, err := rewrappedEmailOutboxBody(keyring, active, id, column.field, column.body)
			if err != nil {
				return SigningKeyRewrapBatchResult{}, err
			}
			if !ok {
				continue
			}
			digest := sha256.Sum256(append(append([]byte(id+"\x00"+column.field+"\x00"), column.body...), replacement...))
			response, err := storage.ExecuteEnvelope(ctx, db, active, rhiza.ExecuteRequest{
				RequestID: "email-outbox-rewrap/" + base64.RawURLEncoding.EncodeToString(digest[:16]),
				SQL:       column.update,
				Args:      []any{replacement, id, column.body},
			})
			if err != nil {
				return SigningKeyRewrapBatchResult{}, err
			}
			changed += response.RowsAffected
		}
	}
	return SigningKeyRewrapBatchResult{Cursor: last, Rewrapped: int(changed), Done: len(result.Rows) < emailOutboxRewrapBatchSize}, nil
}

// rewrappedEmailOutboxBody seals one queued body under the active key. It
// reports ok=false for a legacy plaintext body and for one already sealed under
// the active key.
func rewrappedEmailOutboxBody(keyring *Keyring, active, id, field, body string) (string, bool, error) {
	if !strings.HasPrefix(body, emailOutboxSealedPrefix) {
		return "", false, nil
	}
	envelope, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(body, emailOutboxSealedPrefix))
	if err != nil || len(envelope) == 0 {
		return "", false, ErrUnsafeMasterKeyStatus
	}
	purpose := emailOutboxPayloadPurpose(id, field)
	keyID, err := keyring.PurposeEnvelopeKeyID(purpose, envelope)
	if err != nil {
		return "", false, err
	}
	if keyID == active {
		return "", false, nil
	}
	replacement, err := keyring.RewrapEnvelope(purpose, envelope)
	if err != nil {
		return "", false, err
	}
	return emailOutboxSealedPrefix + base64.RawStdEncoding.EncodeToString(replacement), true, nil
}

func scanManagedClientReferences(ctx context.Context, db *rhiza.DB, keyring *Keyring, family *MasterKeyReferenceFamily) error {
	cursor := ""
	for {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT id,generation,secret_envelope FROM managed_oauth_clients WHERE secret_envelope IS NOT NULL AND id > ? ORDER BY id LIMIT ?`, Args: []any{cursor, int64(masterKeyStatusScanLimit)}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return err
		}
		for _, row := range result.Rows {
			if len(row) != 3 {
				return ErrUnsafeMasterKeyStatus
			}
			id, idOK := row[0].(string)
			generation, genOK := row[1].(string)
			if !idOK || !genOK || id == "" || generation == "" {
				return ErrUnsafeMasterKeyStatus
			}
			var envelope []byte
			switch value := row[2].(type) {
			case []byte:
				envelope = value
			case string:
				envelope = []byte(value)
			default:
				return ErrUnsafeMasterKeyStatus
			}
			keyID, err := keyring.PurposeEnvelopeKeyID(ManagedClientSecretPurpose(id, generation), envelope)
			if err != nil {
				return ErrUnsafeMasterKeyStatus
			}
			addReference(family, keyID)
			cursor = id
		}
		if len(result.Rows) < masterKeyStatusScanLimit {
			return nil
		}
	}
}

func emptyReferenceFamily() MasterKeyReferenceFamily {
	return MasterKeyReferenceFamily{ByKeyID: make(map[string]int64)}
}

func unsafeMasterKeyStatus(status MasterKeyReferenceStatus) (MasterKeyReferenceStatus, error) {
	status.Safe = false
	return status, ErrUnsafeMasterKeyStatus
}

func familyUsesOnly(family MasterKeyReferenceFamily, activeID string) bool {
	for keyID := range family.ByKeyID {
		if keyID != activeID {
			return false
		}
	}
	return true
}

func scanSigningKeyReferences(ctx context.Context, db *rhiza.DB, keyring *Keyring, issuer string, family *MasterKeyReferenceFamily) error {
	cursor := ""
	for {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT kid,private_envelope FROM oidc_signing_keys WHERE kid > ? ORDER BY kid LIMIT ?`, Args: []any{cursor, int64(masterKeyStatusScanLimit)}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return err
		}
		for _, row := range result.Rows {
			if len(row) != 2 {
				return ErrUnsafeMasterKeyStatus
			}
			kid, kidOK := row[0].(string)
			envelopeText, envelopeOK := row[1].(string)
			if !kidOK || !validKeyID(kid) || !envelopeOK {
				return ErrUnsafeMasterKeyStatus
			}
			envelope, ok := decodeCanonicalEnvelope(envelopeText)
			if !ok {
				return ErrUnsafeMasterKeyStatus
			}
			keyID, err := keyring.SigningKeyEnvelopeKeyID(issuer, kid, envelope)
			if err != nil {
				return ErrUnsafeMasterKeyStatus
			}
			addReference(family, keyID)
			cursor = kid
		}
		if len(result.Rows) < masterKeyStatusScanLimit {
			return nil
		}
	}
}

func scanDCRIdempotencyReferences(ctx context.Context, db *rhiza.DB, keyring *Keyring, now time.Time, family *MasterKeyReferenceFamily) error {
	principalCursor, keyCursor := "", ""
	for {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT principal_digest,key_digest,response_envelope FROM dcr_registration_idempotency WHERE expires_at_unix_ms > ? AND (principal_digest > ? OR (principal_digest = ? AND key_digest > ?)) ORDER BY principal_digest,key_digest LIMIT ?`, Args: []any{now.UnixMilli(), principalCursor, principalCursor, keyCursor, int64(masterKeyStatusScanLimit)}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return err
		}
		for _, row := range result.Rows {
			if len(row) != 3 {
				return ErrUnsafeMasterKeyStatus
			}
			principal, principalOK := row[0].(string)
			key, keyOK := row[1].(string)
			envelopeText, envelopeOK := row[2].(string)
			if !principalOK || !keyOK || !validDigest43(principal) || !validDigest43(key) || !envelopeOK {
				return ErrUnsafeMasterKeyStatus
			}
			envelope, ok := decodeCanonicalEnvelope(envelopeText)
			if !ok {
				return ErrUnsafeMasterKeyStatus
			}
			keyID, err := keyring.PurposeEnvelopeKeyID("dcr-registration-response", envelope)
			if err != nil {
				return ErrUnsafeMasterKeyStatus
			}
			addReference(family, keyID)
			principalCursor, keyCursor = principal, key
		}
		if len(result.Rows) < masterKeyStatusScanLimit {
			return nil
		}
	}
}

func scanUpstreamReferences(ctx context.Context, db *rhiza.DB, keyring *Keyring, now time.Time, family *MasterKeyReferenceFamily) error {
	cursor := ""
	for {
		result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state_digest,secret_envelope FROM upstream_provider_transactions WHERE expires_at_unix_ms > ? AND state_digest > ? ORDER BY state_digest LIMIT ?`, Args: []any{now.UnixMilli(), cursor, int64(masterKeyStatusScanLimit)}, Consistency: rhiza.ConsistencyLinearizable})
		if err != nil {
			return err
		}
		for _, row := range result.Rows {
			if len(row) != 2 {
				return ErrUnsafeMasterKeyStatus
			}
			stateDigest, stateOK := row[0].(string)
			envelopeText, envelopeOK := row[1].(string)
			if !stateOK || !validDigest43(stateDigest) || !envelopeOK {
				return ErrUnsafeMasterKeyStatus
			}
			envelope, ok := decodeCanonicalEnvelope(envelopeText)
			if !ok {
				return ErrUnsafeMasterKeyStatus
			}
			keyID, err := keyring.PurposeEnvelopeKeyID("upstream/transaction", envelope)
			if err != nil {
				return ErrUnsafeMasterKeyStatus
			}
			addReference(family, keyID)
			cursor = stateDigest
		}
		if len(result.Rows) < masterKeyStatusScanLimit {
			return nil
		}
	}
}

func decodeCanonicalEnvelope(text string) ([]byte, bool) {
	envelope, err := base64.RawURLEncoding.DecodeString(text)
	return envelope, err == nil && len(envelope) != 0 && base64.RawURLEncoding.EncodeToString(envelope) == text
}

func validDigest43(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func addReference(family *MasterKeyReferenceFamily, keyID string) {
	family.ByKeyID[keyID]++
	family.Total++
}
