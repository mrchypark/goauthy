package upstreamprovider

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

const transactionEnvelopePurpose = "upstream/transaction"

// EnvelopeKeyring is satisfied by oidc.Keyring without exposing its keys.
type EnvelopeKeyring interface {
	SealEnvelope(purpose string, plaintext []byte) ([]byte, error)
	OpenEnvelope(purpose string, envelope []byte) ([]byte, error)
	PurposeEnvelopeKeyID(purpose string, envelope []byte) (string, error)
	RewrapEnvelope(purpose string, envelope []byte) ([]byte, error)
	ActiveMasterKeyID() (string, error)
}

const (
	transactionRewrapScanLimit   = 128
	transactionRewrapUpdateLimit = 32
)

// RhizaStore persists one-use upstream authorization transactions.
type RhizaStore struct {
	db      *rhiza.DB
	keyring EnvelopeKeyring
}

// NewRhizaStore constructs a Store backed by the upstream transaction table.
func NewRhizaStore(db *rhiza.DB, keyring EnvelopeKeyring) (*RhizaStore, error) {
	if db == nil || keyring == nil {
		return nil, ErrInvalidConfig
	}
	return &RhizaStore{db: db, keyring: keyring}, nil
}

type transactionSecret struct {
	Purpose              string `json:"purpose"`
	StateDigest          string `json:"state_digest"`
	BrowserBindingDigest string `json:"browser_binding_digest"`
	SessionDigest        string `json:"session_digest"`
	InteractionDigest    string `json:"interaction_digest"`
	LinkSubject          string `json:"link_subject"`
	LinkSessionDigest    string `json:"link_session_digest"`
	ProviderID           string `json:"provider_id"`
	Nonce                string `json:"nonce"`
	PKCEVerifier         string `json:"pkce_verifier"`
	ProviderSource       string `json:"provider_source"`
	RuntimeVersion       string `json:"runtime_version"`
}

func (s *RhizaStore) Save(ctx context.Context, tx Transaction) error {
	if tx.Scopes == nil {
		tx.Scopes = []string{}
	}
	tx.Purpose = normalizeTransactionPurpose(tx.Purpose)
	if s == nil || s.db == nil || s.keyring == nil || !validTransaction(tx) {
		return ErrInvalidConfig
	}
	tx.CreatedAt, tx.ExpiresAt = transactionTime(tx.CreatedAt), transactionTime(tx.ExpiresAt)
	if !tx.ExpiresAt.After(tx.CreatedAt) {
		return ErrInvalidConfig
	}
	scopes, err := json.Marshal(tx.Scopes)
	if err != nil {
		return fmt.Errorf("encode transaction scopes: %w", err)
	}
	secret, err := json.Marshal(transactionSecret{
		Purpose:     tx.Purpose,
		StateDigest: tx.StateDigest, BrowserBindingDigest: tx.BrowserBindingDigest,
		SessionDigest: tx.SessionDigest, InteractionDigest: tx.InteractionDigest,
		LinkSubject: tx.LinkSubject, LinkSessionDigest: tx.LinkSessionDigest,
		ProviderID: tx.ProviderID, Nonce: tx.Nonce, PKCEVerifier: tx.PKCEVerifier,
			ProviderSource: tx.ProviderSource, RuntimeVersion: tx.RuntimeVersion,
	})
	if err != nil {
		return fmt.Errorf("encode transaction secret: %w", err)
	}
	envelope, err := s.keyring.SealEnvelope(transactionEnvelopePurpose, secret)
	if err != nil {
		return fmt.Errorf("seal transaction secret: %w", err)
	}
	envelopeText := base64.RawURLEncoding.EncodeToString(envelope)
	if len(envelopeText) > 4096 {
		return ErrInvalidConfig
	}
	writerKeyID, err := s.keyring.PurposeEnvelopeKeyID(transactionEnvelopePurpose, envelope)
	if err != nil {
		return fmt.Errorf("authenticate transaction envelope: %w", err)
	}
	requestID := transactionSaveRequestID(tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, envelopeText)
	_, err = storage.ExecuteEnvelope(ctx, s.db, writerKeyID, rhiza.ExecuteRequest{RequestID: requestID, Statements: append(transactionExpiredCleanup(tx.CreatedAt), rhiza.SQLStatement{SQL: `INSERT INTO upstream_provider_transactions
		(state_digest,browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,link_subject,link_session_digest,session_digest,interaction_digest,expires_at_unix_ms,created_at_unix_ms,consumed_attempt,consumed_at_unix_ms)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,NULL,NULL)`, Args: []any{
		tx.StateDigest, tx.BrowserBindingDigest, tx.ProviderID, envelopeText, tx.Issuer, tx.Audience, tx.ClientID, string(scopes), tx.CallbackURI, tx.Purpose, nullableTransactionText(tx.LinkSubject), nullableTransactionDigest(tx.LinkSessionDigest), nullableTransactionDigest(tx.SessionDigest), nullableTransactionDigest(tx.InteractionDigest), tx.ExpiresAt.UnixMilli(), tx.CreatedAt.UnixMilli(),
	}})})
	return err
}

func (s *RhizaStore) Consume(ctx context.Context, stateDigest, browserBindingDigest, providerID string, now time.Time) (Transaction, error) {
	if s == nil || s.db == nil || s.keyring == nil || !validDigest(stateDigest) {
		return Transaction{}, ErrTransactionNotFound
	}
	if !validDigest(browserBindingDigest) || providerID == "" {
		return Transaction{}, ErrBindingMismatch
	}
	now = transactionTime(now)
	stored, found, err := s.load(ctx, stateDigest, providerID)
	if err != nil {
		return Transaction{}, err
	}
	if !found {
		exists, err := s.transactionStateExists(ctx, stateDigest)
		if err != nil {
			return Transaction{}, err
		}
		if exists {
			return Transaction{}, ErrBindingMismatch
		}
		return Transaction{}, ErrTransactionNotFound
	}
	if stored.consumedAttempt != "" {
		return Transaction{}, ErrTransactionAlreadyConsumed
	}
	if !now.Before(stored.tx.ExpiresAt) {
		return Transaction{}, ErrTransactionExpired
	}
	if stored.tx.BrowserBindingDigest != browserBindingDigest || stored.tx.ProviderID != providerID {
		return Transaction{}, ErrBindingMismatch
	}
	attempt, err := transactionAttempt()
	if err != nil {
		return Transaction{}, err
	}
	requestID := transactionRequestID("consume", stateDigest, browserBindingDigest, providerID, attempt)
	_, executeErr := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, SQL: `UPDATE upstream_provider_transactions
		SET consumed_attempt=?, consumed_at_unix_ms=?
		WHERE state_digest=? AND browser_binding_digest=? AND provider_id=? AND consumed_attempt IS NULL AND expires_at_unix_ms>?`, Args: []any{attempt, now.UnixMilli(), stateDigest, browserBindingDigest, providerID, now.UnixMilli()}})
	reconciled, found, readErr := s.load(ctx, stateDigest, providerID)
	if readErr != nil {
		if executeErr != nil {
			return Transaction{}, executeErr
		}
		return Transaction{}, readErr
	}
	if found && reconciled.consumedAttempt == attempt && now.Before(reconciled.tx.ExpiresAt) {
		return reconciled.tx, nil
	}
	if executeErr != nil {
		return Transaction{}, executeErr
	}
	return Transaction{}, transactionConsumeFailure(found, reconciled, now)
}

type storedTransaction struct {
	tx              Transaction
	consumedAttempt string
}

func (s *RhizaStore) load(ctx context.Context, stateDigest, providerID string) (storedTransaction, bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT browser_binding_digest,provider_id,secret_envelope,issuer,audience,client_id,scopes_json,callback_uri,purpose,link_subject,link_session_digest,session_digest,interaction_digest,expires_at_unix_ms,created_at_unix_ms,consumed_attempt
		FROM upstream_provider_transactions WHERE state_digest=? AND provider_id=?`, Args: []any{stateDigest, providerID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return storedTransaction{}, false, err
	}
	if len(result.Rows) == 0 {
		return storedTransaction{}, false, nil
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 16 {
		return storedTransaction{}, false, ErrTransactionNotFound
	}
	row := result.Rows[0]
	browser, browserOK := row[0].(string)
	provider, providerOK := row[1].(string)
	envelopeText, envelopeOK := row[2].(string)
	issuer, issuerOK := row[3].(string)
	audience, audienceOK := row[4].(string)
	clientID, clientOK := row[5].(string)
	scopesText, scopesOK := row[6].(string)
	callbackURI, callbackOK := row[7].(string)
	purpose, purposeOK := row[8].(string)
	linkSubject, linkSubjectOK := nullableText(row[9])
	linkSessionDigest, linkSessionOK := nullableDigest(row[10])
	sessionDigest, sessionOK := nullableDigest(row[11])
	interactionDigest, interactionOK := nullableDigest(row[12])
	expires, expiresOK := row[13].(int64)
	created, createdOK := row[14].(int64)
	if !browserOK || !providerOK || !envelopeOK || !issuerOK || !audienceOK || !clientOK || !scopesOK || !callbackOK || !purposeOK || !linkSubjectOK || !linkSessionOK || !sessionOK || !interactionOK || !expiresOK || !createdOK {
		return storedTransaction{}, false, ErrTransactionNotFound
	}
	var consumed string
	if row[15] != nil {
		var consumedOK bool
		consumed, consumedOK = row[15].(string)
		if !consumedOK {
			return storedTransaction{}, false, ErrTransactionNotFound
		}
	}
	envelope, err := base64.RawURLEncoding.DecodeString(envelopeText)
	if err != nil {
		return storedTransaction{}, false, ErrTransactionNotFound
	}
	plaintext, err := s.keyring.OpenEnvelope(transactionEnvelopePurpose, envelope)
	if err != nil {
		return storedTransaction{}, false, ErrTransactionNotFound
	}
	var secret transactionSecret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return storedTransaction{}, false, ErrTransactionNotFound
	}
	var scopes []string
	if err := json.Unmarshal([]byte(scopesText), &scopes); err != nil {
		return storedTransaction{}, false, ErrTransactionNotFound
	}
	tx := Transaction{Purpose: purpose, StateDigest: stateDigest, BrowserBindingDigest: browser, SessionDigest: sessionDigest, InteractionDigest: interactionDigest, LinkSubject: linkSubject, LinkSessionDigest: linkSessionDigest, ProviderID: provider, Nonce: secret.Nonce, PKCEVerifier: secret.PKCEVerifier, Issuer: issuer, Audience: audience, ClientID: clientID, Scopes: scopes, CallbackURI: callbackURI, ProviderSource: secret.ProviderSource, RuntimeVersion: secret.RuntimeVersion, ExpiresAt: time.UnixMilli(expires).UTC(), CreatedAt: time.UnixMilli(created).UTC()}
	if !validTransaction(tx) || secret.Purpose != purpose || secret.StateDigest != stateDigest || secret.BrowserBindingDigest != browser || secret.SessionDigest != sessionDigest || secret.InteractionDigest != interactionDigest || secret.LinkSubject != linkSubject || secret.LinkSessionDigest != linkSessionDigest || secret.ProviderID != provider {
		return storedTransaction{}, false, ErrTransactionNotFound
	}
	return storedTransaction{tx: tx, consumedAttempt: consumed}, true, nil
}

type transactionRewrapRow struct {
	stateDigest     string
	envelopeText    string
	expiresAtUnix   int64
	newEnvelopeText string
}

// RewrapTransactionBatch moves at most transactionRewrapUpdateLimit eligible
// transaction envelopes to the active master key. The cursor advances through
// scanned rows, or stops at the last updated row when the update bound is
// reached, so old-key rows are never skipped. The logical clock is supplied by
// the caller to make expiry handling deterministic and to match the CAS
// predicate exactly.
func (s *RhizaStore) RewrapTransactionBatch(ctx context.Context, now time.Time, afterStateDigest string) (nextStateDigest string, done bool, updated int64, err error) {
	if s == nil || s.db == nil || s.keyring == nil {
		return "", true, 0, ErrInvalidConfig
	}
	now = transactionTime(now)
	activeKeyID, err := s.keyring.ActiveMasterKeyID()
	if err != nil {
		return "", true, 0, fmt.Errorf("active transaction envelope key: %w", err)
	}
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state_digest,secret_envelope,expires_at_unix_ms
		FROM upstream_provider_transactions
		WHERE expires_at_unix_ms > ? AND state_digest > ?
		ORDER BY state_digest LIMIT ?`, Args: []any{now.UnixMilli(), afterStateDigest, int64(transactionRewrapScanLimit)}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return "", true, 0, err
	}
	if len(result.Rows) == 0 {
		return "", true, 0, nil
	}
	rows := make([]transactionRewrapRow, 0, minInt(len(result.Rows), transactionRewrapUpdateLimit))
	writerKeyID := ""
	scannedThrough := afterStateDigest
	updatedThrough := afterStateDigest
	updateBoundReached := false
	for i, row := range result.Rows {
		if len(row) != 3 {
			return "", true, 0, fmt.Errorf("transaction rewrap row %d has %d columns", i, len(row))
		}
		stateDigest, stateOK := row[0].(string)
		envelopeText, envelopeOK := row[1].(string)
		expiresAtUnix, expiresOK := row[2].(int64)
		if !stateOK || !envelopeOK || !expiresOK || !validDigest(stateDigest) || envelopeText == "" || expiresAtUnix <= now.UnixMilli() {
			return "", true, 0, fmt.Errorf("invalid transaction rewrap row %d", i)
		}
		scannedThrough = stateDigest
		envelope, decodeErr := base64.RawURLEncoding.DecodeString(envelopeText)
		if decodeErr != nil {
			return "", true, 0, fmt.Errorf("decode transaction envelope %q: %w", stateDigest, decodeErr)
		}
		sourceKeyID, keyErr := s.keyring.PurposeEnvelopeKeyID(transactionEnvelopePurpose, envelope)
		if keyErr != nil {
			return "", true, 0, fmt.Errorf("authenticate transaction envelope %q: %w", stateDigest, keyErr)
		}
		if sourceKeyID == activeKeyID {
			continue
		}
		if len(rows) >= transactionRewrapUpdateLimit {
			updateBoundReached = true
			break
		}
		rewrapped, rewrapErr := s.keyring.RewrapEnvelope(transactionEnvelopePurpose, envelope)
		if rewrapErr != nil {
			return "", true, 0, fmt.Errorf("rewrap transaction envelope %q: %w", stateDigest, rewrapErr)
		}
		newKeyID, keyErr := s.keyring.PurposeEnvelopeKeyID(transactionEnvelopePurpose, rewrapped)
		if keyErr != nil {
			return "", true, 0, fmt.Errorf("authenticate rewrapped transaction envelope %q: %w", stateDigest, keyErr)
		}
		if writerKeyID == "" {
			writerKeyID = newKeyID
		} else if writerKeyID != newKeyID {
			return "", true, 0, errors.New("transaction rewrap batch used multiple envelope writer keys")
		}
		rows = append(rows, transactionRewrapRow{stateDigest: stateDigest, envelopeText: envelopeText, expiresAtUnix: expiresAtUnix, newEnvelopeText: base64.RawURLEncoding.EncodeToString(rewrapped)})
		updatedThrough = stateDigest
	}
	nextStateDigest = scannedThrough
	if updateBoundReached {
		nextStateDigest = updatedThrough
	}
	done = len(result.Rows) < transactionRewrapScanLimit && !updateBoundReached
	if len(rows) == 0 {
		return nextStateDigest, done, 0, nil
	}
	requestID := transactionRewrapRequestID(writerKeyID, now, rows)
	statement := transactionRewrapMutation(now, rows)
	response, err := storage.ExecuteEnvelope(ctx, s.db, writerKeyID, rhiza.ExecuteRequest{RequestID: requestID, SQL: statement.SQL, Args: statement.Args})
	if err != nil {
		return nextStateDigest, done, 0, err
	}
	if response.RowsAffected != 0 && response.RowsAffected != int64(len(rows)) {
		return afterStateDigest, false, 0, fmt.Errorf("transaction rewrap CAS changed %d rows, want %d", response.RowsAffected, len(rows))
	}
	if response.RowsAffected == 0 {
		// A concurrent worker may already have committed this exact batch. Keep
		// the cursor at the batch boundary so any non-converged row is retried.
		return afterStateDigest, false, 0, nil
	}
	return nextStateDigest, done, response.RowsAffected, nil
}

func transactionRewrapMutation(now time.Time, rows []transactionRewrapRow) rhiza.SQLStatement {
	var sql strings.Builder
	sql.WriteString("UPDATE upstream_provider_transactions SET secret_envelope = CASE state_digest ")
	args := make([]any, 0, len(rows)*7+1)
	for _, row := range rows {
		sql.WriteString("WHEN ? THEN ? ")
		args = append(args, row.stateDigest, row.newEnvelopeText)
	}
	sql.WriteString("ELSE secret_envelope END WHERE state_digest IN (")
	for index, row := range rows {
		if index > 0 {
			sql.WriteString(",")
		}
		sql.WriteString("?")
		args = append(args, row.stateDigest)
	}
	sql.WriteString(") AND (SELECT COUNT(*) FROM upstream_provider_transactions WHERE ")
	for index, row := range rows {
		if index > 0 {
			sql.WriteString(" OR ")
		}
		sql.WriteString("(state_digest=? AND secret_envelope=? AND expires_at_unix_ms=? AND expires_at_unix_ms>?)")
		args = append(args, row.stateDigest, row.envelopeText, row.expiresAtUnix, now.UnixMilli())
	}
	sql.WriteString(") = ?")
	args = append(args, int64(len(rows)))
	return rhiza.SQLStatement{SQL: sql.String(), Args: args}
}

func transactionRewrapRequestID(activeKeyID string, now time.Time, rows []transactionRewrapRow) string {
	parts := make([]string, 0, 2+len(rows)*4)
	parts = append(parts, activeKeyID, fmt.Sprintf("%d", now.UnixMilli()))
	for _, row := range rows {
		parts = append(parts, row.stateDigest, row.envelopeText, fmt.Sprintf("%d", row.expiresAtUnix), row.newEnvelopeText)
	}
	return "upstream/transaction/rewrap/" + DigestSHA256(strings.Join(parts, "\x00"))[:32]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func nullableDigest(value any) (string, bool) {
	if value == nil {
		return "", true
	}
	digest, ok := value.(string)
	return digest, ok && validDigest(digest)
}

func nullableText(value any) (string, bool) {
	if value == nil {
		return "", true
	}
	text, ok := value.(string)
	return text, ok
}

func nullableTransactionDigest(digest string) any {
	if digest == "" {
		return nil
	}
	return digest
}

func nullableTransactionText(text string) any {
	if text == "" {
		return nil
	}
	return text
}

func (s *RhizaStore) transactionStateExists(ctx context.Context, stateDigest string) (bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT 1 FROM upstream_provider_transactions WHERE state_digest=?`, Args: []any{stateDigest}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil {
		return false, err
	}
	return len(result.Rows) != 0, nil
}

func transactionConsumeFailure(found bool, stored storedTransaction, now time.Time) error {
	if !found {
		return ErrTransactionNotFound
	}
	if stored.consumedAttempt != "" {
		return ErrTransactionAlreadyConsumed
	}
	if !now.Before(stored.tx.ExpiresAt) {
		return ErrTransactionExpired
	}
	return ErrBindingMismatch
}

func transactionExpiredCleanup(now time.Time) []rhiza.SQLStatement {
	return []rhiza.SQLStatement{{SQL: `DELETE FROM upstream_provider_transactions WHERE state_digest IN (SELECT state_digest FROM upstream_provider_transactions WHERE expires_at_unix_ms<=? ORDER BY expires_at_unix_ms,state_digest LIMIT 64)`, Args: []any{now.UnixMilli()}}}
}

func transactionTime(value time.Time) time.Time { return value.UTC().Truncate(time.Millisecond) }

func transactionAttempt() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generate transaction attempt: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func transactionRequestID(operation, stateDigest, browserBindingDigest, providerID, attempt string) string {
	return "upstream/transaction/" + operation + "/" + DigestSHA256(stateDigest + ":" + browserBindingDigest + ":" + providerID + ":" + attempt)[:32]
}

func transactionSaveRequestID(stateDigest, browserBindingDigest, providerID, envelopeText string) string {
	return "upstream/transaction/save/" + DigestSHA256(stateDigest + ":" + browserBindingDigest + ":" + providerID + ":" + DigestSHA256(envelopeText))[:32]
}

func validTransaction(tx Transaction) bool {
	tx.Purpose = normalizeTransactionPurpose(tx.Purpose)
	if tx.CreatedAt.IsZero() || tx.ExpiresAt.IsZero() || !validDigest(tx.StateDigest) || !validDigest(tx.BrowserBindingDigest) || tx.ProviderID == "" || tx.PKCEVerifier == "" || tx.Issuer == "" || tx.ClientID == "" || tx.CallbackURI == "" {
		return false
	}
	if !validPurposeBinding(tx.Purpose, tx.BrowserBindingDigest, tx.SessionDigest, tx.InteractionDigest, tx.LinkSubject, tx.LinkSessionDigest) {
		return false
	}
	if err := validateRuntimeBinding(tx.ProviderSource, tx.RuntimeVersion); err != nil {
		return false
	}
	if !transactionTime(tx.ExpiresAt).After(transactionTime(tx.CreatedAt)) {
		return false
	}
	if len(tx.ProviderID) > 64 || len(tx.Nonce) > 1024 || len(tx.PKCEVerifier) > 1024 || len(tx.Issuer) > 2048 || len(tx.Audience) > 1024 || len(tx.ClientID) > 256 || len(tx.CallbackURI) > 2048 || len(tx.Scopes) > 64 {
		return false
	}
	for _, scope := range tx.Scopes {
		if scope == "" || len(scope) > 256 {
			return false
		}
	}
	encodedScopes, err := json.Marshal(tx.Scopes)
	return err == nil && len(encodedScopes) >= 2 && len(encodedScopes) <= 4096
}

func validDigest(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == value
}

func validOptionalLocalOAuthBinding(sessionDigest, interactionDigest string) bool {
	return (sessionDigest == "" && interactionDigest == "") || ValidateLocalOAuthBinding(sessionDigest, interactionDigest) == nil
}
