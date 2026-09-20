package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrOTPExpired             = errors.New("OTP expired")
	ErrOTPInvalid             = errors.New("invalid OTP")
	ErrOTPRateLimited         = errors.New("OTP rate limited")
	ErrOTPAlreadyIssued       = errors.New("OTP already issued")
	ErrOTPInteractionNotFound = errors.New("OTP interaction not found or expired")
)

const (
	otpCodeLength  = 6
	otpExpiry      = 5 * time.Minute
	otpRateWindow  = 5 * time.Minute
	otpRateLimit   = 3
	otpRatePeers   = 256
	otpActiveLimit = 256
)

func otpSchemaStatements() []rhiza.SQLStatement {
	return []rhiza.SQLStatement{
		{SQL: `CREATE TABLE IF NOT EXISTS identity_email_otp (
			code_digest TEXT PRIMARY KEY NOT NULL,
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			expires_at_unix_ms INTEGER NOT NULL,
			consumed_attempt TEXT,
			consumed_at_unix_ms INTEGER
		) STRICT`},
		{SQL: `CREATE TABLE IF NOT EXISTS identity_email_otp_rate_limits (
			subject_digest TEXT NOT NULL,
			window_start_unix_seconds INTEGER NOT NULL,
			count INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY (subject_digest, window_start_unix_seconds)
		) STRICT`},
		// The password-plus-OTP binding is keyed by the browser session that
		// proved the password, so every replica and restart reads one binding
		// instead of a process-local map.
		{SQL: `CREATE TABLE IF NOT EXISTS identity_email_otp_interactions (
			session_digest TEXT PRIMARY KEY NOT NULL CHECK (length(session_digest) = 43),
			subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 512),
			interaction_token TEXT NOT NULL CHECK (length(interaction_token) = 43),
			expires_at_unix_ms INTEGER NOT NULL CHECK (expires_at_unix_ms >= 0)
		) STRICT`},
	}
}

type OTPService struct {
	db  *rhiza.DB
	now func() time.Time
}

func NewOTPService(db *rhiza.DB) (*OTPService, error) {
	if db == nil {
		return nil, errors.New("OTP service requires database")
	}
	return &OTPService{db: db, now: time.Now}, nil
}

func (s *OTPService) GenerateOTP(ctx context.Context, subject string) (string, error) {
	if s == nil || s.db == nil {
		return "", errors.New("OTP service unavailable")
	}
	if subject == "" || len(subject) > 512 {
		return "", errors.New("invalid subject")
	}
	now := s.now().UTC().Truncate(time.Second)
	expires := now.Add(otpExpiry).UnixMilli()
	windowStart := now.Unix() / int64(otpRateWindow/time.Second) * int64(otpRateWindow/time.Second)
	subjectDigest := challengeDigest(subject)

	code, err := generateOTPCode()
	if err != nil {
		return "", err
	}
	codeHash := sha256.Sum256([]byte(code))
	codeDigest := base64.RawURLEncoding.EncodeToString(codeHash[:])

	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: recoveryMutationID("otp-issue", subjectDigest, codeDigest, strconv.FormatInt(now.Unix(), 10)),
		Statements: []rhiza.SQLStatement{
			{SQL: `DELETE FROM identity_email_otp WHERE expires_at_unix_ms <= ?`, Args: []any{now.UnixMilli()}},
			{SQL: `DELETE FROM identity_email_otp_rate_limits WHERE window_start_unix_seconds < ?`, Args: []any{windowStart}},
			{SQL: `INSERT INTO identity_email_otp (code_digest,subject,expires_at_unix_ms,consumed_attempt,consumed_at_unix_ms) SELECT ?,?,?,NULL,NULL
				WHERE (? = '' OR COALESCE((SELECT CASE WHEN window_start_unix_seconds = ? THEN count ELSE 0 END FROM identity_email_otp_rate_limits WHERE subject_digest = ?), 0) < ?)`,
				Args: []any{codeDigest, subject, expires, subjectDigest, windowStart, subjectDigest, int64(otpRateLimit)}},
			{SQL: `INSERT INTO identity_email_otp_rate_limits (subject_digest,window_start_unix_seconds,count) SELECT ?,?,1
				WHERE changes() = 1
				ON CONFLICT(subject_digest, window_start_unix_seconds) DO UPDATE SET
				count = identity_email_otp_rate_limits.count + 1`,
				Args: []any{subjectDigest, windowStart}},
		},
	})
	if err != nil {
		return "", err
	}
	if !s.otpIssued(ctx, codeDigest, subject, expires) {
		return "", ErrOTPRateLimited
	}
	return code, nil
}

func (s *OTPService) VerifyOTP(ctx context.Context, subject, code string) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("OTP service unavailable")
	}
	normalized, err := normalizeOTPCode(subject, code)
	if err != nil {
		return false, err
	}

	now := s.now().UTC().Truncate(time.Second)
	codeHash := sha256.Sum256([]byte(normalized))
	codeDigest := base64.RawURLEncoding.EncodeToString(codeHash[:])

	attemptBytes := make([]byte, 16)
	if _, err := rand.Read(attemptBytes); err != nil {
		return false, ErrOTPInvalid
	}
	attempt := base64.RawURLEncoding.EncodeToString(attemptBytes)

	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: recoveryMutationID("otp-verify", codeDigest, attempt),
		Statements: []rhiza.SQLStatement{
			{SQL: `DELETE FROM identity_email_otp WHERE expires_at_unix_ms <= ?`, Args: []any{now.UnixMilli()}},
			{SQL: `UPDATE identity_email_otp SET consumed_attempt=?, consumed_at_unix_ms=? WHERE code_digest=? AND subject=? AND expires_at_unix_ms>=? AND consumed_attempt IS NULL`,
				Args: []any{attempt, now.UnixMilli(), codeDigest, subject, now.UnixMilli()}},
		},
	})
	if err != nil {
		return false, err
	}
	if !s.otpConsumed(ctx, codeDigest, attempt, subject, now.UnixMilli()) {
		return false, ErrOTPInvalid
	}
	return true, nil
}

// VerifyOTPAndConsumeInteraction consumes the submitted code and the browser
// session's pending password-plus-OTP binding in one replicated transaction: a
// code is only accepted while the binding that authorized this session is still
// live, and the binding is only dropped by the consume it authorized. A rejected
// code leaves both the code and the binding available for one bounded retry.
func (s *OTPService) VerifyOTPAndConsumeInteraction(ctx context.Context, sessionDigest, subject, code string) (bool, error) {
	if s == nil || s.db == nil {
		return false, errors.New("OTP service unavailable")
	}
	if sessionDigest == "" {
		return false, ErrOTPInvalid
	}
	normalized, err := normalizeOTPCode(subject, code)
	if err != nil {
		return false, err
	}
	now := s.now().UTC().Truncate(time.Second)
	codeHash := sha256.Sum256([]byte(normalized))
	codeDigest := base64.RawURLEncoding.EncodeToString(codeHash[:])

	attemptBytes := make([]byte, 16)
	if _, err := rand.Read(attemptBytes); err != nil {
		return false, ErrOTPInvalid
	}
	attempt := base64.RawURLEncoding.EncodeToString(attemptBytes)

	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: recoveryMutationID("otp-verify-interaction", sessionDigest, codeDigest, attempt),
		Statements: []rhiza.SQLStatement{
			{SQL: `DELETE FROM identity_email_otp WHERE expires_at_unix_ms <= ?`, Args: []any{now.UnixMilli()}},
			{SQL: `UPDATE identity_email_otp SET consumed_attempt=?, consumed_at_unix_ms=?
				WHERE code_digest=? AND subject=? AND expires_at_unix_ms>=? AND consumed_attempt IS NULL
				AND EXISTS (SELECT 1 FROM identity_email_otp_interactions WHERE session_digest=? AND subject=? AND expires_at_unix_ms>=?)`,
				Args: []any{attempt, now.UnixMilli(), codeDigest, subject, now.UnixMilli(), sessionDigest, subject, now.UnixMilli()}},
			{SQL: `DELETE FROM identity_email_otp_interactions WHERE session_digest=?
				AND EXISTS (SELECT 1 FROM identity_email_otp WHERE code_digest=? AND consumed_attempt=?)`,
				Args: []any{sessionDigest, codeDigest, attempt}},
		},
	})
	if err != nil {
		return false, err
	}
	if !s.otpConsumed(ctx, codeDigest, attempt, subject, now.UnixMilli()) {
		return false, ErrOTPInvalid
	}
	return true, nil
}

func normalizeOTPCode(subject, code string) (string, error) {
	if subject == "" || code == "" || len(code) > 16 {
		return "", ErrOTPInvalid
	}
	normalized := strings.TrimSpace(code)
	if len(normalized) != otpCodeLength {
		return "", ErrOTPInvalid
	}
	for _, c := range normalized {
		if c < '0' || c > '9' {
			return "", ErrOTPInvalid
		}
	}
	return normalized, nil
}

func (s *OTPService) otpIssued(ctx context.Context, codeDigest, subject string, expires int64) bool {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT expires_at_unix_ms,consumed_attempt FROM identity_email_otp WHERE code_digest=? AND subject=?`,
		Args:        []any{codeDigest, subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	return err == nil && len(result.Rows) == 1 && len(result.Rows[0]) == 2 && result.Rows[0][0] == expires && result.Rows[0][1] == nil
}

func (s *OTPService) otpConsumed(ctx context.Context, codeDigest, attempt, subject string, now int64) bool {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT expires_at_unix_ms,consumed_attempt FROM identity_email_otp WHERE code_digest=? AND subject=?`,
		Args:        []any{codeDigest, subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) != 1 || len(result.Rows[0]) != 2 {
		return false
	}
	expires, ok := result.Rows[0][0].(int64)
	if !ok || expires < now {
		return false
	}
	storedAttempt, ok := result.Rows[0][1].(string)
	return ok && storedAttempt == attempt
}

func generateOTPCode() (string, error) {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", fmt.Errorf("generate OTP: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// OTPInteractionStore persists the bounded password-plus-OTP binding that
// authorizes a browser session's OTP verification. It writes to the same
// replicated database as the OTP service, so a binding created by one replica or
// process is readable by every other replica and after a restart.
type OTPInteractionStore struct {
	db  *rhiza.DB
	now func() time.Time
}

// NewOTPInteractionStore requires the Rhiza database that holds
// identity_email_otp_interactions. The optional argument preserves the original
// zero-argument call shape; a store without a database refuses every binding
// rather than falling back to process-local state.
func NewOTPInteractionStore(databases ...*rhiza.DB) *OTPInteractionStore {
	var db *rhiza.DB
	if len(databases) == 1 {
		db = databases[0]
	}
	return &OTPInteractionStore{db: db, now: time.Now}
}

// Store replaces any existing binding for the session so a repeated password
// step-up never leaves two live bindings. The legacy OTPHandler wrapper has no
// request context; one bounded replicated write is issued directly.
func (s *OTPInteractionStore) Store(sessionDigest, subject, interactionToken string, expiresAt time.Time) error {
	if sessionDigest == "" || subject == "" || interactionToken == "" {
		return errors.New("invalid OTP interaction parameters")
	}
	db, err := s.database()
	if err != nil {
		return err
	}
	expires := expiresAt.UTC().UnixMilli()
	now := s.now().UTC().UnixMilli()
	_, err = storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: recoveryMutationID("otp-interaction-store", sessionDigest, interactionToken, strconv.FormatInt(expires, 10)),
		Statements: []rhiza.SQLStatement{
			{SQL: `DELETE FROM identity_email_otp_interactions WHERE expires_at_unix_ms <= ?`, Args: []any{now}},
			{SQL: `INSERT INTO identity_email_otp_interactions (session_digest,subject,interaction_token,expires_at_unix_ms) VALUES (?,?,?,?)
				ON CONFLICT(session_digest) DO UPDATE SET subject=excluded.subject, interaction_token=excluded.interaction_token, expires_at_unix_ms=excluded.expires_at_unix_ms`,
				Args: []any{sessionDigest, subject, interactionToken, expires}},
		},
	})
	return err
}

// Load returns the live binding for a browser session without consuming it, so
// the caller can apply identity policy before the one-time consumption.
func (s *OTPInteractionStore) Load(ctx context.Context, sessionDigest string) (string, string, error) {
	if sessionDigest == "" {
		return "", "", errors.New("invalid session digest")
	}
	db, err := s.database()
	if err != nil {
		return "", "", err
	}
	result, err := db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT subject,interaction_token,expires_at_unix_ms FROM identity_email_otp_interactions WHERE session_digest=?`,
		Args:        []any{sessionDigest},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return "", "", err
	}
	if len(result.Rows) != 1 || len(result.Rows[0]) != 3 {
		return "", "", ErrOTPInteractionNotFound
	}
	subject, subjectOK := result.Rows[0][0].(string)
	interaction, interactionOK := result.Rows[0][1].(string)
	expiresAt, expiresOK := result.Rows[0][2].(int64)
	if !subjectOK || !interactionOK || !expiresOK || subject == "" || interaction == "" || expiresAt < s.now().UTC().UnixMilli() {
		return "", "", ErrOTPInteractionNotFound
	}
	return subject, interaction, nil
}

func (s *OTPInteractionStore) Consume(sessionDigest string) (string, string, error) {
	subject, interaction, err := s.Load(context.Background(), sessionDigest)
	if err != nil {
		return "", "", err
	}
	db, err := s.database()
	if err != nil {
		return "", "", err
	}
	if _, err := storage.Execute(context.Background(), db, rhiza.ExecuteRequest{
		RequestID: recoveryMutationID("otp-interaction-consume", sessionDigest, interaction),
		Statements: []rhiza.SQLStatement{{SQL: `DELETE FROM identity_email_otp_interactions WHERE session_digest=? AND subject=? AND interaction_token=?`,
			Args: []any{sessionDigest, subject, interaction}}},
	}); err != nil {
		return "", "", err
	}
	return subject, interaction, nil
}

func (s *OTPInteractionStore) database() (*rhiza.DB, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("OTP interaction store requires database")
	}
	return s.db, nil
}

// SendOTPForSubject issues the OTP for an identity subject and delivers it to
// that subject's mailbox. The code row is keyed by the subject, so verification
// stays bound to the identity while delivery uses the resolved address.
func (h *OTPHandler) SendOTPForSubject(ctx context.Context, subject, email, lang string, expiresAt time.Time) error {
	if h == nil || !h.enabled || h.otp == nil || h.sender == nil {
		return errors.New("OTP unavailable")
	}
	if email == "" {
		return errors.New("OTP recipient unavailable")
	}
	code, err := h.otp.GenerateOTP(ctx, subject)
	if err != nil {
		return err
	}
	return h.sender.SendOTP(ctx, email, code, lang, expiresAt)
}

// LoadInteraction returns the pending password-plus-OTP binding of a browser
// session without consuming it. It is declared next to the persisted store it
// reads, and the OAuth login boundary applies identity policy before the
// one-time consumption.
func (h *OTPHandler) LoadInteraction(ctx context.Context, sessionDigest string) (string, string, error) {
	if h == nil || h.interacts == nil {
		return "", "", errors.New("OTP interaction store unavailable")
	}
	return h.interacts.Load(ctx, sessionDigest)
}

// VerifyInteraction consumes the submitted code and the session binding in one
// replicated transaction and keeps the verified password-plus-OTP ceremony in
// the shared "mfa" authentication method that forced-MFA policy requires.
func (h *OTPHandler) VerifyInteraction(ctx context.Context, sessionDigest, subject, code string) (bool, error) {
	if h == nil || h.otp == nil {
		return false, errors.New("OTP service unavailable")
	}
	return h.otp.VerifyOTPAndConsumeInteraction(ctx, sessionDigest, subject, code)
}
