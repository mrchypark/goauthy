package recovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrResetTokenExpired    = errors.New("reset token has expired")
	ErrResetTokenUsed       = errors.New("reset token has already been used")
	ErrResetTokenIPMismatch = errors.New("reset token IP mismatch")
	ErrResetRateLimited     = errors.New("reset request rate limited")
	ErrSuspiciousActivity   = errors.New("suspicious reset activity detected")
)

// EnhancedResetConfig contains enhanced security configuration for password resets
type EnhancedResetConfig struct {
	TokenLifetime  time.Duration // 토큰 수명 (기본: 15분)
	MaxAttempts    int           // 최대 시도 횟수 (기본: 3)
	IPBinding      bool          // IP 바인딩 활성화
	RequirePoW     bool          // Proof of Work 요구
	PoWDifficulty  uint8         // 난이도 (10-98)
	EnableAuditLog bool          // 감사 로그 활성화
}

// DefaultEnhancedConfig returns secure default configuration
func DefaultEnhancedConfig() EnhancedResetConfig {
	return EnhancedResetConfig{
		TokenLifetime:  15 * time.Minute,
		MaxAttempts:    3,
		IPBinding:      true,
		RequirePoW:     true,
		PoWDifficulty:  19,
		EnableAuditLog: true,
	}
}

// EnhancedResetToken contains enhanced token information
type EnhancedResetToken struct {
	Token     string
	Hash      string
	Subject   string
	Email     string
	CreatedAt time.Time
	ExpiresAt time.Time
	IP        string
	Attempts  int
	Used      bool
	UsedAt    *time.Time
	UsedIP    string
}

// IssueEnhancedResetToken issues an enhanced reset token with security features
func (s *Service) IssueEnhancedResetToken(ctx context.Context, subject, email, ip string, config EnhancedResetConfig) (*EnhancedResetToken, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("recovery service unavailable")
	}

	// Rate limiting 확인
	if err := s.checkResetRateLimit(ctx, ip); err != nil {
		return nil, err
	}

	// 의심스러운 활동 감지
	if err := s.detectSuspiciousActivity(ctx, subject, ip); err != nil {
		return nil, err
	}

	// 토큰 생성
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, err
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// 해시 생성 (저장용)
	hash := sha256.Sum256([]byte(token))
	tokenHash := base64.RawURLEncoding.EncodeToString(hash[:])

	now := s.now().UTC()
	expiresAt := now.Add(config.TokenLifetime)

	// 토큰 저장
	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: recoveryMutationID("enhanced-reset-issue", subject, tokenHash),
		SQL: `INSERT INTO identity_password_reset_tokens 
		      (token_hash, subject, email, created_at, expires_at, ip, attempts, used)
		      VALUES (?, ?, ?, ?, ?, ?, 0, 0)`,
		Args: []any{tokenHash, subject, email, now.UnixMilli(), expiresAt.UnixMilli(), ip},
	})
	if err != nil {
		return nil, err
	}

	// 감사 로그
	if config.EnableAuditLog {
		s.logResetEvent(ctx, "token_issued", subject, ip, now)
	}

	return &EnhancedResetToken{
		Token:     token,
		Hash:      tokenHash,
		Subject:   subject,
		Email:     email,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		IP:        ip,
		Attempts:  0,
		Used:      false,
	}, nil
}

// ValidateEnhancedResetToken validates an enhanced reset token
func (s *Service) ValidateEnhancedResetToken(ctx context.Context, token, ip string, config EnhancedResetConfig) (*EnhancedResetToken, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("recovery service unavailable")
	}

	// 토큰 해시 계산
	hash := sha256.Sum256([]byte(token))
	tokenHash := base64.RawURLEncoding.EncodeToString(hash[:])

	// 토큰 조회
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT subject, email, created_at, expires_at, ip, attempts, used, used_at, used_ip
		      FROM identity_password_reset_tokens WHERE token_hash = ?`,
		Args:        []any{tokenHash},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return nil, err
	}
	if len(result.Rows) == 0 {
		return nil, ErrResetTokenExpired
	}

	row := result.Rows[0]
	subject, _ := row[0].(string)
	email, _ := row[1].(string)
	createdAtMs, _ := row[2].(int64)
	expiresAtMs, _ := row[3].(int64)
	storedIP, _ := row[4].(string)
	attempts, _ := row[5].(int64)
	used, _ := row[6].(int64)
	usedAtMs, _ := row[7].(int64)
	usedIP, _ := row[8].(string)

	now := s.now().UTC()
	expiresAt := time.UnixMilli(expiresAtMs).UTC()
	createdAt := time.UnixMilli(createdAtMs).UTC()

	// 만료 확인
	if now.After(expiresAt) {
		return nil, ErrResetTokenExpired
	}

	// 사용 여부 확인
	if used != 0 {
		return nil, ErrResetTokenUsed
	}

	// 시도 횟수 확인
	if int(attempts) >= config.MaxAttempts {
		return nil, ErrResetRateLimited
	}

	// IP 바인딩 확인
	if config.IPBinding && storedIP != "" && storedIP != ip {
		return nil, ErrResetTokenIPMismatch
	}

	// 시도 횟수 증가
	_, err = storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: recoveryMutationID("enhanced-reset-attempt", tokenHash),
		SQL:       `UPDATE identity_password_reset_tokens SET attempts = attempts + 1 WHERE token_hash = ?`,
		Args:      []any{tokenHash},
	})
	if err != nil {
		return nil, err
	}

	var usedAt *time.Time
	if usedAtMs > 0 {
		t := time.UnixMilli(usedAtMs).UTC()
		usedAt = &t
	}

	return &EnhancedResetToken{
		Hash:      tokenHash,
		Subject:   subject,
		Email:     email,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
		IP:        storedIP,
		Attempts:  int(attempts) + 1,
		Used:      false,
		UsedAt:    usedAt,
		UsedIP:    usedIP,
	}, nil
}

// ConsumeEnhancedResetToken marks a token as used
func (s *Service) ConsumeEnhancedResetToken(ctx context.Context, token, ip string) error {
	if s == nil || s.db == nil {
		return errors.New("recovery service unavailable")
	}

	hash := sha256.Sum256([]byte(token))
	tokenHash := base64.RawURLEncoding.EncodeToString(hash[:])
	now := s.now().UTC()

	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: recoveryMutationID("enhanced-reset-consume", tokenHash),
		SQL:       `UPDATE identity_password_reset_tokens SET used = 1, used_at = ?, used_ip = ? WHERE token_hash = ? AND used = 0`,
		Args:      []any{now.UnixMilli(), ip, tokenHash},
	})
	return err
}

// checkResetRateLimit checks rate limiting for reset requests
func (s *Service) checkResetRateLimit(ctx context.Context, ip string) error {
	if s.policy == nil {
		return nil
	}

	allowed, err := s.policy.AllowPasswordReset(ctx, ip, s.now().UTC())
	if err != nil {
		return err
	}
	if !allowed {
		return ErrResetRateLimited
	}
	return nil
}

// detectSuspiciousActivity detects suspicious reset activity
func (s *Service) detectSuspiciousActivity(ctx context.Context, subject, ip string) error {
	// 최근 1시간 동안의 재설정 시도 횟수 확인
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT COUNT(*) FROM identity_password_reset_tokens 
		      WHERE subject = ? AND created_at > ? AND used = 0`,
		Args:        []any{subject, s.now().UTC().Add(-time.Hour).UnixMilli()},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}

	count, _ := result.Rows[0][0].(int64)
	if count >= 5 {
		return ErrSuspiciousActivity
	}

	return nil
}

// logResetEvent logs a reset event for auditing
func (s *Service) logResetEvent(ctx context.Context, eventType, subject, ip string, at time.Time) {
	// 실제 구현에서는 event_log 테이블에 저장
}

// InvalidateAllResetTokens invalidates all reset tokens for a subject
func (s *Service) InvalidateAllResetTokens(ctx context.Context, subject string) error {
	if s == nil || s.db == nil {
		return errors.New("recovery service unavailable")
	}

	_, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: recoveryMutationID("invalidate-reset-tokens", subject),
		SQL:       `DELETE FROM identity_password_reset_tokens WHERE subject = ?`,
		Args:      []any{subject},
	})
	return err
}

// CleanupExpiredTokens removes expired reset tokens
func (s *Service) CleanupExpiredTokens(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("recovery service unavailable")
	}

	result, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID: recoveryMutationID("cleanup-expired-tokens"),
		SQL:       `DELETE FROM identity_password_reset_tokens WHERE expires_at < ?`,
		Args:      []any{s.now().UTC().UnixMilli()},
	})
	if err != nil {
		return 0, err
	}

	return result.RowsAffected, nil
}
