package identity

import (
	"context"
	"errors"
)

// LookupPasskeyOnlySubject returns the subject and username of an active,
// non-expired, non-disabled passkey-only account identified by username.
// It reuses the existing linearizable lookupCredential query and never
// exposes the password hash. Callers receive a generic error for unknown,
// disabled, expired, or password-mode accounts to avoid user enumeration.
func (s *Store) LookupPasskeyOnlySubject(ctx context.Context, username string) (string, string, error) {
	if s == nil {
		return "", "", errors.New("identity store unavailable")
	}
	if err := ValidateUsername(username); err != nil {
		return "", "", ErrInvalidUsername
	}
	user, _, _, passwordMode, found, expired, _, err := s.lookupCredential(ctx, username)
	if err != nil {
		return "", "", err
	}
	if !found || user.Disabled || expired || passwordMode {
		return "", "", ErrInvalidCredentials
	}
	return user.Subject, user.Username, nil
}
