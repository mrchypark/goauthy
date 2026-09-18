// Package identity persists local password identities.
package identity

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

var (
	// ErrAutoLinkUnavailable is returned when an auto-link attempt cannot
	// proceed because the provider guard, account conditions, or
	// transactional insert failed.
	ErrAutoLinkUnavailable = errors.New("auto link unavailable")

	// ErrAutoLinkNoAccount is returned when no local account with a matching
	// email exists at all. The caller MAY fall through to account creation.
	// ErrAutoLinkUnavailable is returned when a local account exists but fails
	// conditions (unverified, pending, disabled, expired, or already linked).
	ErrAutoLinkNoAccount = errors.New("auto link: no eligible local account")
)

// AutoLinkConfigSnapshot captures the immutable provider configuration at
// callback time for auto-link operations. It is similar to
// FederatedConfigSnapshot but carries the auto_link flag instead of
// auto_onboarding.
type AutoLinkConfigSnapshot struct {
	Source   string // "registry"
	Version  string // runtime version
	Issuer   string
	ClientID string
	Kind     string // "oidc", "github", "oauth_userinfo"
	AutoLink bool
}

// AutoLinkInput describes an email-based auto-link attempt. The caller MUST
// NOT set EmailVerified to true based on downstream session state alone;
// only the upstream provider's verified claim authorises the verified flag.
type AutoLinkInput struct {
	Subject       upstreamprovider.SubjectResult
	Config        AutoLinkConfigSnapshot
	Email         string
	EmailVerified bool
}

// AutoLinkResult is returned after a successful atomic auto-link.
type AutoLinkResult struct {
	Subject string
}

// FindExternalLinkActive returns the local subject mapped to an active,
// non-expired upstream subject. It wraps FindExternalLink and detects the
// case where the link exists but the user is disabled or expired,
// returning ErrInactiveSubject in that case so the caller does not fall
// through to onboarding.
func (s *Store) FindExternalLinkActive(ctx context.Context, external upstreamprovider.SubjectResult) (string, error) {
	subject, found, err := s.FindExternalLink(ctx, external)
	if err != nil {
		return "", err
	}
	if found {
		// Verify the user is not expired. FindExternalLink checks disabled
		// but not expiry.
		result, err := s.db.Query(ctx, rhiza.QueryRequest{
			SQL:         "SELECT 1 FROM identity_users u WHERE u.subject = ? AND u.disabled = 0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?)",
			Args:        []any{subject, s.now().UTC().Truncate(time.Millisecond).UnixMilli()},
			Consistency: rhiza.ConsistencyLinearizable,
		})
		if err != nil {
			return "", err
		}
		if len(result.Rows) == 0 {
			return "", ErrInactiveSubject
		}
		return subject, nil
	}
	// Check whether the link exists but the user is inactive.
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL:         "SELECT l.local_subject FROM identity_external_links l WHERE l.provider_id = ? AND l.external_key = ?",
		Args:        []any{external.ProviderID, external.ExternalKey()},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return "", err
	}
	if len(result.Rows) == 0 {
		return "", nil
	}
	return "", ErrInactiveSubject
}


// localAccountExistsByEmail reports whether any local account has the given
// canonical email. It does not check verification, credentials, expiry, or
// external-link conflicts: those are enforced transactionally by the autolink
// batch. A false return means no local account matches at all and the caller
// may fall through to account creation.
func (s *Store) localAccountExistsByEmail(ctx context.Context, email string) (bool, error) {
	result, err := s.db.Query(ctx, rhiza.QueryRequest{
		SQL: `SELECT 1 FROM identity_users u JOIN identity_user_profiles p ON p.subject = u.subject WHERE p.email = ?`,
		Args:        []any{email},
		Consistency: rhiza.ConsistencyLinearizable,
	})
	if err != nil {
		return false, err
	}
	return len(result.Rows) > 0, nil
}

// AutoLinkExternal atomically binds an existing local identity to an
// upstream subject by verified email. The transaction verifies that the
// provider snapshot matches and auto_link is enabled, that a local
// account exists with a canonical verified email and is established
// (password or passkey credential), active, and non-expired, and that no
// conflicting external link exists for this provider+key or any link
// for this local_subject. On success the bound local subject is
// returned. On failure the caller receives a typed error and must not
// fall through to account creation.
func (s *Store) AutoLinkExternal(ctx context.Context, input AutoLinkInput) (AutoLinkResult, error) {
	if s == nil || s.db == nil || ctx == nil {
		return AutoLinkResult{}, ErrAutoLinkUnavailable
	}
	if err := input.Subject.Validate(); err != nil {
		return AutoLinkResult{}, ErrAutoLinkUnavailable
	}
	if input.Config.Source == "" && input.Config.Version == "" {
		return AutoLinkResult{}, ErrAutoLinkUnavailable
	}
	if input.Config.Source != "registry" || input.Config.Version == "" || input.Config.Issuer == "" || input.Config.ClientID == "" || input.Config.Kind == "" {
		return AutoLinkResult{}, ErrAutoLinkUnavailable
	}
	if !input.Config.AutoLink {
		return AutoLinkResult{}, ErrAutoLinkUnavailable
	}
	if !input.EmailVerified {
		return AutoLinkResult{}, ErrAutoLinkUnavailable
	}
	email, err := CanonicalEmail(input.Email)
	if err != nil {
		return AutoLinkResult{}, ErrAutoLinkUnavailable
	}
	// Namespace must match the deterministic issuer/clientID binding.
	if input.Subject.IdentityNamespace != upstreamprovider.ComputeNamespace(input.Config.Issuer, input.Config.ClientID) {
		return AutoLinkResult{}, ErrAutoLinkUnavailable
	}

	now := s.now().UTC().Truncate(time.Millisecond)
	externalKey := input.Subject.ExternalKey()
	// Pre-check: determine whether any local account has a matching email.
	// Only absent local account permits fallthrough to creation. Account exists
	// but ineligible (unverified, pending, disabled, expired, already linked) is
	// a hard failure - the caller must not create.
	exists, err := s.localAccountExistsByEmail(ctx, email)
	if err != nil {
		return AutoLinkResult{}, err
	}
	if !exists {
		return AutoLinkResult{}, ErrAutoLinkNoAccount
	}

	one := int64(1)
	requestID := mutationID("auto-link-email", input.Subject.ProviderID, externalKey, email, strconv.FormatInt(now.UnixMilli(), 10))

	statements := []rhiza.SQLStatement{
		// Provider guard: exactly one enabled provider with auto_link on.
		{
			SQL:  "SELECT p.id FROM auth_providers p JOIN auth_provider_runtime_versions rv ON rv.provider_id = p.id WHERE p.id = ? AND p.enabled = 1 AND rv.version = ? AND p.issuer = ? AND p.client_id = ? AND CASE p.typ WHEN 'oidc' THEN 'oidc' WHEN 'custom' THEN 'oidc' WHEN 'google' THEN 'oidc' WHEN 'github' THEN 'github' WHEN 'oauth_userinfo' THEN 'oauth_userinfo' ELSE '' END = ? AND p.auto_link = 1",
			Args: []any{input.Subject.ProviderID, input.Config.Version, input.Config.Issuer, input.Config.ClientID, input.Config.Kind},
			WantRows: true, ExpectedReturnedRows: &one,
		},
		// Atomic link: insert binding if a local account exists with
		// verified email, is established (password or passkey credential), active,
		// non-expired, and no conflicting external link of any kind.
		{
			SQL: "INSERT INTO identity_external_links (provider_id, external_key, local_subject, linked_at_unix_ms) SELECT ?, ?, u.subject, ? FROM identity_users u JOIN identity_user_profiles p ON p.subject = u.subject WHERE p.email = ? AND p.email_verified = 1 AND u.disabled = 0 AND (u.user_expires_at_unix_ms IS NULL OR u.user_expires_at_unix_ms > ?) AND (u.password_phc != '' OR EXISTS(SELECT 1 FROM identity_webauthn_credentials c WHERE c.subject = u.subject)) AND NOT EXISTS (SELECT 1 FROM identity_external_links WHERE provider_id = ? AND external_key = ?) AND NOT EXISTS (SELECT 1 FROM identity_external_links WHERE local_subject = u.subject)",
			Args: []any{input.Subject.ProviderID, externalKey, now.UnixMilli(), email, now.UnixMilli(), input.Subject.ProviderID, externalKey},
			ExpectedRowsAffected: &one,
		},
		// Verify the link exists and return the bound subject.
		{
			SQL:  "SELECT local_subject FROM identity_external_links WHERE provider_id = ? AND external_key = ?",
			Args: []any{input.Subject.ProviderID, externalKey},
			WantRows: true, ExpectedReturnedRows: &one,
		},
	}

	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err != nil {
		if response.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
			return AutoLinkResult{}, ErrAutoLinkUnavailable
		}
		return AutoLinkResult{}, err
	}
	if len(response.Statements) < 3 || len(response.Statements[2].Rows) != 1 || len(response.Statements[2].Rows[0]) != 1 {
		return AutoLinkResult{}, ErrAutoLinkUnavailable
	}
	subject, ok := response.Statements[2].Rows[0][0].(string)
	if !ok {
		return AutoLinkResult{}, ErrAutoLinkUnavailable
	}
	return AutoLinkResult{Subject: subject}, nil
}

