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
	"sync"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrOTPExpired       = errors.New("OTP expired")
	ErrOTPInvalid       = errors.New("invalid OTP")
	ErrOTPRateLimited   = errors.New("OTP rate limited")
	ErrOTPAlreadyIssued = errors.New("OTP already issued")
)

const (
	otpCodeLength   = 6
	otpExpiry       = 5 * time.Minute
	otpRateWindow   = 5 * time.Minute
	otpRateLimit    = 3
	otpRatePeers    = 256
	otpActiveLimit  = 256
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
				ON CONFLICT(subject_digest) DO UPDATE SET window_start_unix_seconds = excluded.window_start_unix_seconds,
				count = CASE WHEN identity_email_otp_rate_limits.window_start_unix_seconds = excluded.window_start_unix_seconds
					THEN identity_email_otp_rate_limits.count + 1 ELSE 1 END`,
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
	if subject == "" || code == "" || len(code) > 16 {
		return false, ErrOTPInvalid
	}
	normalized := strings.TrimSpace(code)
	if len(normalized) != otpCodeLength {
		return false, ErrOTPInvalid
	}
	for _, c := range normalized {
		if c < '0' || c > '9' {
			return false, ErrOTPInvalid
		}
	}

	now := s.now().UTC().Truncate(time.Second)
	codeHash := sha256.Sum256([]byte(normalized))
	codeDigest := base64.RawURLEncoding.EncodeToString(codeHash[:])

	attemptBytes := make([]byte, 16)
	if _, err := rand.Read(attemptBytes); err != nil {
		return false, ErrOTPInvalid
	}
	attempt := base64.RawURLEncoding.EncodeToString(attemptBytes)

	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
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

func (s *OTPService) otpIssued(ctx context.Context, codeDigest, subject string, expires int64) bool {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:   `SELECT expires_at_unix_ms,consumed_attempt FROM identity_email_otp WHERE code_digest=? AND subject=?`,
		Args:  []any{codeDigest, subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	return err == nil && len(result.Rows) == 1 && len(result.Rows[0]) == 2 && result.Rows[0][0] == expires && result.Rows[0][1] == nil
}

func (s *OTPService) otpConsumed(ctx context.Context, codeDigest, attempt, subject string, now int64) bool {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:   `SELECT expires_at_unix_ms,consumed_attempt FROM identity_email_otp WHERE code_digest=? AND subject=?`,
		Args:  []any{codeDigest, subject},
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

type otpInteraction struct {
	subject         string
	interactionToken string
	expiresAt       time.Time
}

type OTPInteractionStore struct {
	mu    sync.RWMutex
	items map[string]*otpInteraction
	now   func() time.Time
}

func NewOTPInteractionStore() *OTPInteractionStore {
	return &OTPInteractionStore{items: make(map[string]*otpInteraction), now: time.Now}
}

func (s *OTPInteractionStore) Store(sessionDigest, subject, interactionToken string, expiresAt time.Time) error {
	if sessionDigest == "" || subject == "" || interactionToken == "" {
		return errors.New("invalid OTP interaction parameters")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[sessionDigest] = &otpInteraction{subject: subject, interactionToken: interactionToken, expiresAt: expiresAt}
	return nil
}

func (s *OTPInteractionStore) Consume(sessionDigest string) (string, string, error) {
	if sessionDigest == "" {
		return "", "", errors.New("invalid session digest")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[sessionDigest]
	if !ok || s.now().After(item.expiresAt) {
		delete(s.items, sessionDigest)
		return "", "", errors.New("OTP interaction not found or expired")
	}
	subject := item.subject
	interaction := item.interactionToken
	delete(s.items, sessionDigest)
	return subject, interaction, nil
}
