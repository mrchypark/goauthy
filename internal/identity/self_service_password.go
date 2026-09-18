package identity

import (
	"context"
	"errors"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

var (
	ErrCurrentPasswordIncorrect = errors.New("current password is incorrect")
	ErrPasswordChangeRateLimit  = errors.New("password change rate limited")
)

// SelfServicePasswordChange represents a user-initiated password change request
type SelfServicePasswordChange struct {
	Subject         string
	CurrentPassword []byte
	NewPassword     []byte
	SourceIP        string
}

// SelfServicePasswordResult contains the result of a password change
type SelfServicePasswordResult struct {
	Subject           string
	PasswordChanged   int64
	ExpiresAt         *int64
	InvalidatedTokens bool
}

// ChangePasswordSelfService allows a user to change their own password
func (s *Store) ChangePasswordSelfService(ctx context.Context, input SelfServicePasswordChange) (*SelfServicePasswordResult, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, errors.New("identity store unavailable")
	}

	if err := validateSubject(input.Subject); err != nil {
		return nil, err
	}

	if len(input.CurrentPassword) == 0 || len(input.NewPassword) == 0 {
		return nil, ErrInvalidPasswordCredential
	}

	// Rate limiting: 최근 비밀번호 변경 시간 확인
	if err := s.checkPasswordChangeRateLimit(ctx, input.Subject); err != nil {
		return nil, err
	}

	// 현재 비밀번호 확인
	currentPHC, err := s.getUserPasswordPHC(ctx, input.Subject)
	if err != nil {
		return nil, err
	}

	valid, _, err := s.hasher.VerifyOrDummy(ctx, input.CurrentPassword, currentPHC)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, ErrCurrentPasswordIncorrect
	}

	// 새 비밀번호 정책 검증
	if err := s.rules.ValidatePassword(input.NewPassword); err != nil {
		return nil, ErrPasswordRejected
	}

	// 비밀번호 히스토리 확인
	if err := s.checkPasswordHistoryForSelf(ctx, input.Subject, input.NewPassword); err != nil {
		return nil, err
	}

	// 비밀번호 해싱
	newPHC, err := s.hasher.Hash(ctx, input.NewPassword)
	if err != nil {
		return nil, err
	}

	// 트랜잭션으로 비밀번호 변경
	now := s.now().UTC().Truncate(time.Millisecond)
	nonce, err := s.randomID(16)
	if err != nil {
		return nil, err
	}
	operation := mutationID("self-password-change", input.Subject, nonce)

	currentGen := s.getCurrentGeneration(ctx, input.Subject)

	statements := []rhiza.SQLStatement{
		// 비밀번호 업데이트
		{SQL: `UPDATE identity_users SET password_phc=?, password_changed_at_unix_ms=?, password_generation=password_generation+1 WHERE subject=?`,
			Args: []any{newPHC, now.UnixMilli(), input.Subject}},
		// 인증 모드 업데이트
		{SQL: `INSERT INTO identity_authentication_modes(subject, mode, generation, updated_at_unix_ms) VALUES(?, 'password', 1, ?) 
		       ON CONFLICT(subject) DO UPDATE SET mode='password', generation=generation+1, updated_at_unix_ms=excluded.updated_at_unix_ms`,
			Args: []any{input.Subject, now.UnixMilli()}},
		// 비밀번호 히스토리 추가
		{SQL: `INSERT INTO identity_password_history(subject, generation, password_phc, changed_at_unix_ms) VALUES(?, ?, ?, ?)`,
			Args: []any{input.Subject, currentGen, currentPHC, now.UnixMilli()}},
		// 오래된 히스토리 정리
		{SQL: `DELETE FROM identity_password_history WHERE subject=? AND generation NOT IN(SELECT generation FROM identity_password_history WHERE subject=? ORDER BY generation DESC LIMIT ?)`,
			Args: []any{input.Subject, input.Subject, int64(max(0, s.rules.History-1))}},
		// 비밀번호 재설정 토큰 무효화
		{SQL: `DELETE FROM identity_password_reset_tokens WHERE subject=?`,
			Args: []any{input.Subject}},
	}

	result, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{
		RequestID:  operation,
		Statements: statements,
	})
	if err != nil {
		return nil, err
	}
	_ = result

	// 만료 시간 계산
	expiresAt := s.PasswordExpiresAt(now.UnixMilli())

	return &SelfServicePasswordResult{
		Subject:           input.Subject,
		PasswordChanged:   now.UnixMilli(),
		ExpiresAt:         expiresAt,
		InvalidatedTokens: true,
	}, nil
}

// checkPasswordChangeRateLimit checks if the user has changed password recently
func (s *Store) checkPasswordChangeRateLimit(ctx context.Context, subject string) error {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT password_changed_at_unix_ms FROM identity_users WHERE subject=?`,
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return err
	}
	if len(result.Rows) == 0 {
		return ErrInactiveSubject
	}

	changedAt, ok := result.Rows[0][0].(int64)
	if !ok || changedAt <= 0 {
		return nil
	}

	// 24시간 이내 재변경 제한
	now := s.now().UTC().UnixMilli()
	if now-changedAt < 24*time.Hour.Milliseconds() {
		return ErrPasswordChangeRateLimit
	}

	return nil
}

// getUserPasswordPHC retrieves the current password PHC for a user
func (s *Store) getUserPasswordPHC(ctx context.Context, subject string) (string, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT password_phc FROM identity_users WHERE subject=? AND disabled=0`,
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return "", err
	}
	if len(result.Rows) == 0 {
		return "", ErrInactiveSubject
	}

	phc, ok := result.Rows[0][0].(string)
	if !ok {
		return "", errors.New("invalid password PHC")
	}

	return phc, nil
}

// checkPasswordHistoryForSelf checks if the new password was used recently
func (s *Store) checkPasswordHistoryForSelf(ctx context.Context, subject string, newPassword []byte) error {
	if s.rules.History <= 1 {
		return nil
	}

	history, err := s.passwordHistory(ctx, subject, s.rules.History-1)
	if err != nil {
		return err
	}

	for _, phc := range history {
		reused, _, err := s.hasher.VerifyOrDummy(ctx, newPassword, phc)
		if err != nil {
			return err
		}
		if reused {
			return ErrPasswordReuse
		}
	}

	return nil
}

// getCurrentGeneration returns the current password generation for a user
func (s *Store) getCurrentGeneration(ctx context.Context, subject string) int64 {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         `SELECT password_generation FROM identity_users WHERE subject=?`,
		Args:        []any{subject},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil || len(result.Rows) == 0 {
		return 1
	}

	gen, ok := result.Rows[0][0].(int64)
	if !ok || gen < 1 {
		return 1
	}

	return gen
}
