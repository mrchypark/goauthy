package recovery

import (
	"context"

	"github.com/mrchypark/goauthy/internal/identity"
)

// CreateUser creates an administrator-provisioned, password-first account.
// The identity layer owns validation and the guarded commit; recovery only
// delivers the first-password message after that commit succeeds.
func (s *Service) CreateUser(ctx context.Context, input identity.UserCreation, authoritySQL string, authorityArgs []any) (identity.OpenRegistrationResult, error) {
	result, err := s.identity.CreateUserWithGuard(ctx, input, authoritySQL, authorityArgs)
	if err != nil {
		return identity.OpenRegistrationResult{}, err
	}
	if !result.Created {
		return result, nil
	}
	if s.OnUserCreated != nil {
		s.OnUserCreated()
	}
	language, err := s.identity.UserLanguage(ctx, result.Subject)
	if err != nil {
		return result, err
	}
	message := Message{
		To:        input.Email,
		Language:  language,
		ResetURL:  s.resetURL(result.Subject, result.Token),
		ExpiresAt: result.ExpiresAt,
	}
	if err := s.sender.SendPasswordNew(ctx, message); err != nil && s.OnError != nil {
		s.OnError(err)
	}
	return result, nil
}

// CreatePasskeyOnlyUser creates an administrator-provisioned, passkey-only
// account. The identity layer owns validation and the guarded commit; no
// password reset token is created or sent.
func (s *Service) CreatePasskeyOnlyUser(ctx context.Context, input identity.UserCreation, authoritySQL string, authorityArgs []any) (string, error) {
	subject, err := s.identity.CreatePasskeyOnlyUser(ctx, input, authoritySQL, authorityArgs)
	if err != nil {
		return "", err
	}
	if s.OnUserCreated != nil {
		s.OnUserCreated()
	}
	return subject, nil
}
