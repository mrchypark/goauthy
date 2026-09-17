// Package identity persists local password identities.
package identity

import (
	"context"
	"errors"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/mrchypark/goauthy/internal/eventlog"
	"github.com/mrchypark/goauthy/internal/i18n"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/goauthy/internal/upstreamprovider"
	"github.com/mrchypark/rhiza"
)

var (
	ErrFederatedMissingEmail    = errors.New("federated creation requires email")
	ErrFederatedInvalidEmail    = errors.New("federated creation invalid email")
	ErrFederatedProviderChanged = errors.New("federated provider snapshot mismatch")
	ErrFederatedConflict        = errors.New("federated identity conflict")
	ErrFederatedUnauthorized    = errors.New("federated creation authorization failed")
)

// FederatedConfigSnapshot is the immutable provider configuration captured at
// callback time. Every field is carried forward so the creation transaction
// can verify the provider has not been disabled, rotated, or reconfigured
// between the callback and the creation commit.
type FederatedConfigSnapshot struct {
	Source         string // "registry" or legacy (empty)
	Version        string // runtime version from auth_provider_runtime_versions
	Issuer         string
	ClientID       string
	Kind           string // "oidc", "github", "oauth_userinfo"
	AutoOnboarding bool
}

// FederatedCreationInput describes one new federated identity to create. The
// caller MUST NOT set EmailVerified to true based on downstream session state
// alone; only the upstream provider's verified claim (carried by
// SubjectResult at callback time) authorises the verified flag.
type FederatedCreationInput struct {
	Subject       upstreamprovider.SubjectResult
	Config        FederatedConfigSnapshot
	Email         string
	EmailVerified bool
	GivenName     string
	FamilyName    string
	SourceIP      string
	AdminMapping  *bool
}

// FederatedCreationResult is returned after a successful atomic creation.
type FederatedCreationResult struct {
	Subject string
	Created bool
}

// CreateFederatedIdentity atomically provisions a new local identity bound to
// an already-verified upstream subject. This method creates new accounts
// only; profile updates, auto-linking, and callback wiring are separate
// tasks.
//
// The transaction performs a provider-snapshot guard SELECT that must return
// exactly one row matching the verified configuration. If the provider has
// been disabled, reconfigured, or its runtime version has changed since the
// callback, the guard returns zero rows and every insert becomes a no-op.
//
// Identity uniqueness is enforced transactionally: the email must not appear
// in identity_user_profiles or identity_recovery_emails, and the external
// key must not appear in identity_external_links. The external key is bound
// to exactly one local subject; existing bindings are never reassigned.
//
// The created identity uses mode 'passkey' with an empty password_phc. This
// is the current schema's way of expressing "no password login": the UI
// selects passkey-only when !passwordMode (see IsPasskeyOnly). No actual
// WebAuthn credential is enrolled here; SetPassword requires real WebAuthn
// proof, and that contract is preserved.
//
// Recovery email mirrors the verified email with empty hash, which prevents
// password reset for federated accounts (no mailbox authority implied).
func (s *Store) CreateFederatedIdentity(ctx context.Context, input FederatedCreationInput) (FederatedCreationResult, error) {
	if s == nil || s.db == nil || ctx == nil {
		return FederatedCreationResult{}, ErrFederatedUnauthorized
	}
	if err := input.Subject.Validate(); err != nil {
		return FederatedCreationResult{}, ErrFederatedUnauthorized
	}
	if input.Config.Source == "" && input.Config.Version == "" {
		return FederatedCreationResult{}, ErrFederatedUnauthorized
	}
	if input.Config.Source != "registry" || input.Config.Version == "" || input.Config.Issuer == "" || input.Config.ClientID == "" || input.Config.Kind == "" {
		return FederatedCreationResult{}, ErrFederatedProviderChanged
	}
	if !input.Config.AutoOnboarding {
		return FederatedCreationResult{}, ErrFederatedProviderChanged
	}

	email, err := CanonicalEmail(input.Email)
	if err != nil {
		return FederatedCreationResult{}, ErrFederatedInvalidEmail
	}
	if utf8.RuneCountInString(input.GivenName) > 32 || !utf8.ValidString(input.GivenName) || utf8.RuneCountInString(input.FamilyName) > 32 || !utf8.ValidString(input.FamilyName) {
		return FederatedCreationResult{}, ErrFederatedInvalidEmail
	}
	if !i18n.ValidUserLanguage("en") {
		return FederatedCreationResult{}, ErrFederatedInvalidEmail
	}

	// Namespace must match the deterministic issuer/clientID binding.
	if input.Subject.IdentityNamespace != upstreamprovider.ComputeNamespace(input.Config.Issuer, input.Config.ClientID) {
		return FederatedCreationResult{}, ErrFederatedUnauthorized
	}

	subject, err := s.randomID(32)
	if err != nil {
		return FederatedCreationResult{}, ErrPasswordResetUnavailable
	}
	now := s.now().UTC().Truncate(time.Millisecond)
	externalKey := input.Subject.ExternalKey()
	emailVerified := int64(0)
	if input.EmailVerified {
		emailVerified = 1
	}

	one := int64(1)
	requestID := mutationID("federated-create", subject, externalKey, strconv.FormatInt(now.UnixMilli(), 10))

	statements := []rhiza.SQLStatement{
		// Provider guard: exactly one enabled provider with auto-onboarding on.
		{
			SQL: `SELECT p.id FROM auth_providers p JOIN auth_provider_runtime_versions rv ON rv.provider_id = p.id WHERE p.id = ? AND p.enabled = 1 AND rv.version = ? AND p.issuer = ? AND p.client_id = ? AND CASE p.typ WHEN 'oidc' THEN 'oidc' WHEN 'custom' THEN 'oidc' WHEN 'google' THEN 'oidc' WHEN 'github' THEN 'github' WHEN 'oauth_userinfo' THEN 'oauth_userinfo' ELSE '' END = ? AND p.auto_onboarding = 1`,
			Args: []any{input.Subject.ProviderID, input.Config.Version, input.Config.Issuer, input.Config.ClientID, input.Config.Kind},
			WantRows: true, ExpectedReturnedRows: &one,
		},
		// Identity user: exactly one insert or abort on duplicate.
		{
			SQL: `INSERT INTO identity_users(subject, username, password_phc, password_changed_at_unix_ms, password_generation, created_at_unix_ms, last_login_at_unix_ms, language, user_expires_at_unix_ms) SELECT ?, ?, '', ?, 1, ?, ?, 'en', NULL WHERE NOT EXISTS (SELECT 1 FROM identity_users WHERE username = ?) AND NOT EXISTS (SELECT 1 FROM identity_user_profiles WHERE email = ?) AND NOT EXISTS (SELECT 1 FROM identity_recovery_emails WHERE email = ?) AND NOT EXISTS (SELECT 1 FROM identity_external_links WHERE provider_id = ? AND external_key = ?)`,
			Args: []any{subject, email, now.UnixMilli(), now.UnixMilli(), now.UnixMilli(), email, email, email, input.Subject.ProviderID, externalKey},
			ExpectedRowsAffected: &one,
		},
		// Authentication mode: passkey-only, no password login.
		{
			SQL:  `INSERT INTO identity_authentication_modes(subject, mode, generation, updated_at_unix_ms) VALUES(?, 'passkey', 1, ?)`,
			Args: []any{subject, now.UnixMilli()},
		},
		// External link: bind upstream subject to local identity.
		{
			SQL:  `INSERT INTO identity_external_links(provider_id, external_key, local_subject, linked_at_unix_ms) VALUES(?, ?, ?, ?)`,
			Args: []any{input.Subject.ProviderID, externalKey, subject, now.UnixMilli()},
		},
		// Profile: exact email verification from upstream.
		{
			SQL:  `INSERT INTO identity_user_profiles(subject, email, email_verified, preferred_username, given_name, family_name, user_values_json) VALUES(?, ?, ?, NULL, ?, ?, NULL)`,
			Args: []any{subject, email, emailVerified, nullableString(input.GivenName), nullableString(input.FamilyName)},
		},
		// Recovery email: mirrors verified email, empty hash prevents reset.
		{
			SQL:  `INSERT INTO identity_recovery_emails(subject, email) VALUES(?, ?)`,
			Args: []any{subject, email},
		},
		// RBAC: revision 1 for the new principal.
		{
			SQL:  `INSERT INTO rbac_principal_versions(subject, revision, updated_at_unix_ms) VALUES(?, 1, ?)`,
			Args: []any{subject, now.UnixMilli()},
		},
	}

	if input.AdminMapping != nil && *input.AdminMapping {
		statements = append(statements, rhiza.SQLStatement{
			SQL:                 `INSERT OR IGNORE INTO rbac_user_roles(subject, role_id, granted_at_unix_ms) SELECT ?, id, ? FROM rbac_roles WHERE name = 'rauthy_admin'`,
			Args:                []any{subject, now.UnixMilli()},
			ExpectedRowsAffected: &one,
		})
	}

	// Ordinary creation event.
	condition := `EXISTS (SELECT 1 FROM identity_users WHERE subject = ? AND username = ? AND password_phc = '') AND EXISTS (SELECT 1 FROM identity_user_profiles WHERE subject = ? AND email = ? AND email_verified = ?) AND EXISTS (SELECT 1 FROM identity_external_links WHERE provider_id = ? AND external_key = ? AND local_subject = ?)`
	conditionArgs := func(extra ...any) []any {
		return append([]any{subject, email, subject, email, emailVerified, input.Subject.ProviderID, externalKey, subject}, extra...)
	}
	userEvent, err := eventlog.Creation(requestID, email, input.SourceIP, false, now).Statement(condition, conditionArgs()...)
	if err != nil {
		return FederatedCreationResult{}, err
	}
	statements = append(statements, userEvent)
	adminEvent, err := eventlog.Creation(requestID, email, input.SourceIP, true, now).Statement(condition+` AND EXISTS (SELECT 1 FROM rbac_user_roles m JOIN rbac_roles r ON r.id = m.role_id WHERE m.subject = ? AND r.name = 'rauthy_admin')`, conditionArgs(subject)...)
	if err != nil {
		return FederatedCreationResult{}, err
	}
	statements = append(statements, adminEvent)

	// Final verification: the identity must exist after all inserts.
	statements = append(statements, rhiza.SQLStatement{
		SQL:  `SELECT subject FROM identity_users WHERE subject = ? AND username = ? AND password_phc = '' AND disabled = 0`,
		Args: []any{subject, email},
		WantRows: true, ExpectedReturnedRows: &one,
	})

	response, err := storage.Execute(ctx, s.db, rhiza.ExecuteRequest{RequestID: requestID, Statements: statements})
	if err != nil {
		if response.ErrorCode == rhiza.MutationErrorCodePreconditionFailed {
			return FederatedCreationResult{}, ErrFederatedProviderChanged
		}
		return FederatedCreationResult{}, err
	}
	return FederatedCreationResult{Subject: subject, Created: true}, nil
}
