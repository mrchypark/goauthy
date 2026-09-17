package upstreamprovider

import (
	"context"
	"crypto/subtle"
	"regexp"
	"strings"
	"time"
)

const (
	PurposeLogin = "login"
	PurposeLink  = "link"
)

// Transaction represents a one-use, digest-only transient record for an
// in-flight upstream OAuth authorization exchange. It carries the
// cryptographic material (state, nonce, PKCE verifier) and the expected
// issuer/audience so the callback can verify the response without
// trusting the caller-supplied URL parameters.
type Transaction struct {
	// Purpose is login or link. Its zero value is login for compatibility.
	Purpose string

	// StateDigest is the SHA-256 digest of the state parameter.
	StateDigest string

	// BrowserBindingDigest is the SHA-256 digest of an opaque
	// browser/session identifier. It binds the transaction to a single
	// browser session so cross-browser replay is rejected before consume.
	BrowserBindingDigest string

	// SessionDigest and InteractionDigest bind a local OAuth login to the
	// session and authorization interaction that initiated it. They are either
	// both absent for legacy flows or both canonical SHA-256 digests.
	SessionDigest     string
	InteractionDigest string

	// LinkSubject and LinkSessionDigest bind an account-link transaction to an
	// authenticated local subject and session. They are used only for link.
	LinkSubject       string
	LinkSessionDigest string

	// ProviderID identifies the upstream provider (e.g., "google").
	ProviderID string

	// Nonce is the plaintext nonce for OIDC id_token verification.
	Nonce string

	// PKCEVerifier is the plaintext PKCE code_verifier.
	PKCEVerifier string

	// Issuer is the expected issuer claim for callback validation.
	Issuer string

	// Audience is the expected audience for callback validation.
	Audience string

	// ClientID is the OAuth 2.0 client identifier.
	ClientID string

	// Scopes are the requested scopes.
	Scopes []string

	// CallbackURI is the redirect URI sent in the authorization request.
	CallbackURI string

	// ProviderSource indicates the origin of the provider configuration
	// (e.g., "registry"). Empty for legacy flows.
	ProviderSource string

	// RuntimeVersion is a bounded opaque version string for managed providers.
	RuntimeVersion string


	// ExpiresAt is the transaction expiry time.
	ExpiresAt time.Time

	// CreatedAt is the transaction creation time.
	CreatedAt time.Time
}

// ValidateLocalOAuthBinding validates the session/interaction binding required
// by a local OAuth login.
func ValidateLocalOAuthBinding(sessionDigest, interactionDigest string) error {
	if !validDigest(sessionDigest) || !validDigest(interactionDigest) {
		return ErrInvalidConfig
	}
	return nil
}

// validProviderSourceValue returns true when source is one of the known sources.
func validProviderSourceValue(source string) bool {
	return source == "" || source == "registry"
}

var runtimeVersionRe = regexp.MustCompile("^[A-Za-z0-9._/-]{1,128}$")

func validateRuntimeBinding(source, version string) error {
	sourceSet := source != ""
	versionSet := version != ""
	if sourceSet != versionSet {
		return ErrInvalidConfig
	}
	if !sourceSet && !versionSet {
		return nil
	}
	if !validProviderSourceValue(source) {
		return ErrInvalidConfig
	}
	if !runtimeVersionRe.MatchString(version) {
		return ErrInvalidConfig
	}
	return nil
}

func normalizeTransactionPurpose(purpose string) string {
	if purpose == "" {
		return PurposeLogin
	}
	return purpose
}

func validPurposeBinding(purpose, browserBindingDigest, sessionDigest, interactionDigest, linkSubject, linkSessionDigest string) bool {
	switch normalizeTransactionPurpose(purpose) {
	case PurposeLogin:
		return linkSubject == "" && linkSessionDigest == "" && validOptionalLocalOAuthBinding(sessionDigest, interactionDigest)
	case PurposeLink:
		return sessionDigest == "" && interactionDigest == "" && validLinkSubject(linkSubject) && validDigest(linkSessionDigest) && digestEqual(browserBindingDigest, linkSessionDigest)
	default:
		return false
	}
}

func validLinkSubject(subject string) bool {
	return len(subject) <= 512 && subject != "" && strings.TrimSpace(subject) == subject
}

func digestEqual(left, right string) bool {
	if len(left) != len(right) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

// Store defines the interface for persisting and consuming upstream OAuth
// transactions. Implementations store only SHA-256 digests of state tokens,
// never plaintext, to limit exposure if the store is compromised.
type Store interface {
	// Save persists a new transaction. It must fail if a transaction with
	// the same StateDigest already exists.
	Save(ctx context.Context, tx Transaction) error

	// Consume atomically loads and marks a transaction as consumed.
	// It enforces:
	//   - exact state digest match
	//   - browser binding digest match
	//   - provider ID match
	//   - strict expiry (now >= ExpiresAt is expired)
	//   - exactly-once semantics under concurrency
	//
	// Returns the transaction on first access, or an error.
	Consume(ctx context.Context, stateDigest, browserBindingDigest, providerID string, now time.Time) (Transaction, error)
}
