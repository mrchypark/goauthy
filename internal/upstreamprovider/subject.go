package upstreamprovider

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"unicode"
)

const (
	maxProviderIDLen = 64
	maxSubjectLen    = 256
)

// SubjectResult represents the normalized external subject key from an
// upstream provider. It contains the provider identifier and the
// subject claim, which together form a globally unique, provider-scoped
// identity key.
type SubjectResult struct {
	// ProviderID is a stable, canonical ASCII identifier for the upstream
	// provider (e.g., "google", "github").
	ProviderID string

	// Subject is the provider's unique, case-sensitive subject claim.
	Subject string

	// IdentityNamespace is an optional domain-separation tag for managed
	// provider identities. When nonempty, ExternalKey hashes over
	// providerID, namespace, and subject instead of the legacy
	// providerID-only path. Empty for legacy flows.
	IdentityNamespace string
}

// ExternalKey returns a collision-safe, bounded external subject key.
// When IdentityNamespace is empty it hashes "providerID\x00subject" (legacy).
// When IdentityNamespace is nonempty it hashes a version-byte-prefixed,
// NUL-delimited triple for domain separation.
func (s SubjectResult) ExternalKey() string {
	h := sha256.New()
	if s.IdentityNamespace != "" {
		h.Write([]byte{0x01}) // version byte: namespaced path
		h.Write([]byte(s.ProviderID))
		h.Write([]byte{0x00})
		h.Write([]byte(s.IdentityNamespace))
		h.Write([]byte{0x00})
		h.Write([]byte(s.Subject))
	} else {
		h.Write([]byte(s.ProviderID))
		h.Write([]byte{0x00})
		h.Write([]byte(s.Subject))
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Validate checks that the SubjectResult contains valid fields.
// ProviderID must be non-empty, ASCII-only, and bounded.
// Subject must be non-empty and bounded.
// IdentityNamespace, when present, must be a 64-char lowercase hex string.
func (s SubjectResult) Validate() error {
	if s.ProviderID == "" || s.Subject == "" {
		return ErrNoSubject
	}
	if len(s.ProviderID) > maxProviderIDLen {
		return ErrInvalidConfig
	}
	if len(s.Subject) > maxSubjectLen {
		return ErrInvalidConfig
	}
	for _, r := range s.ProviderID {
		if r > unicode.MaxASCII {
			return ErrInvalidConfig
		}
	}
	if s.IdentityNamespace != "" {
		if !validNamespaceFormat(s.IdentityNamespace) {
			return ErrInvalidConfig
		}
	}
	return nil
}

// LinkDecision describes the result of evaluating whether an external
// subject should be linked to a local identity. This module never
// auto-links by email; it returns an explicit decision without side effects.
type LinkDecision int

const (
	// LinkDecisionNone indicates no link exists.
	LinkDecisionNone LinkDecision = iota

	// LinkDecisionLinked indicates the external subject is already linked.
	LinkDecisionLinked

	// LinkDecisionConflict indicates the external subject is linked to a
	// different local identity than expected.
	LinkDecisionConflict
)

// String returns a human-readable label for the link decision.
func (d LinkDecision) String() string {
	switch d {
	case LinkDecisionNone:
		return "none"
	case LinkDecisionLinked:
		return "linked"
	case LinkDecisionConflict:
		return "conflict"
	default:
		return "unknown"
	}
}

// NormalizeProviderID returns a lowercased, trimmed, ASCII-only provider
// identifier. Returns empty string for invalid input.
func NormalizeProviderID(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return ""
	}
	for _, r := range s {
		if r > unicode.MaxASCII {
			return ""
		}
	}
	if len(s) > maxProviderIDLen {
		return ""
	}
	return s
}

// isPinned24ManagedID reports whether id is exactly 24 ASCII alphanumeric
// characters (case-sensitive), matching the format created by the provider
// registry for managed providers.
func isPinned24ManagedID(id string) bool {
	if len(id) != 24 {
		return false
	}
	for i := 0; i < 24; i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// validNamespaceFormat checks that ns is a lowercase hex string of exactly
// 64 characters (SHA-256 hex output length).
func validNamespaceFormat(ns string) bool {
	if len(ns) != 64 {
		return false
	}
	for _, c := range ns {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// computeNamespace produces a collision-safe, deterministic namespace from
// the issuer and clientID pair. It uses json.Marshal to encode the pair
// without delimiter ambiguity, then SHA-256 hex output. The namespace
// deliberately excludes RuntimeVersion so secret rotation does not orphan
// stable identities.
func computeNamespace(issuer, clientID string) string {
	pair := [2]string{issuer, clientID}
	data, err := json.Marshal(pair)
	if err != nil {
		// json.Marshal of two strings cannot fail.
		panic("upstreamprovider: json.Marshal pair: " + err.Error())
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ComputeNamespace returns the deterministic domain-separation namespace
// for a managed provider binding identified by issuer and clientID.
func ComputeNamespace(issuer, clientID string) string {
	return computeNamespace(issuer, clientID)
}

// bindManagedSubject attaches a namespace to subject when the transaction
// carries a valid registry binding with nonempty issuer and clientID.
// For legacy flows (both source and version empty) it returns subject
// unchanged with empty namespace. Partial source/version or unknown
// source values are rejected.
func bindManagedSubject(subject SubjectResult, tx Transaction) (SubjectResult, error) {
	if err := validateRuntimeBinding(tx.ProviderSource, tx.RuntimeVersion); err != nil {
		return SubjectResult{}, err
	}
	// Legacy: both empty - return unchanged.
	if tx.ProviderSource == "" && tx.RuntimeVersion == "" {
		return subject, nil
	}
	// Registry path: issuer and clientID must be nonempty.
	if tx.Issuer == "" || tx.ClientID == "" {
		return SubjectResult{}, ErrInvalidConfig
	}
	subject.IdentityNamespace = computeNamespace(tx.Issuer, tx.ClientID)
	return subject, nil
}

// validConfigProviderID validates a provider ID against the config source.
// Legacy (empty source): id must be non-empty and equal to its normalized
// form, preserving existing lowercase-only semantics.
// Registry source: id must be exactly 24 ASCII alphanumeric characters
// preserving case, and the runtime binding must be valid.
// Unknown source: always fails.
func validConfigProviderID(id string, cfg Config) bool {
	if id == "" {
		return false
	}
	switch cfg.ProviderSource {
	case "":
		return id == NormalizeProviderID(id)
	case "registry":
		return isPinned24ManagedID(id) && validateRuntimeBinding(cfg.ProviderSource, cfg.RuntimeVersion) == nil
	default:
		return false
	}
}
