package upstreamprovider

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// TestLegacyExternalKeyUnchanged verifies that a SubjectResult with no
// namespace produces the same ExternalKey as the original scheme
// (SHA-256 of providerID + NUL + subject, base64url).
func TestLegacyExternalKeyUnchanged(t *testing.T) {
	s := SubjectResult{ProviderID: "google", Subject: "user123"}
	got := s.ExternalKey()
	if s.IdentityNamespace != "" {
		t.Fatal("expected empty namespace for legacy")
	}
	// The legacy key must equal the raw hash of "google\x00user123".
	// Compute it independently to guard against accidental drift.
	h := sha256Sum("google\x00user123")
	want := encodeBase64URL(h)
	if got != want {
		t.Fatalf("legacy ExternalKey = %q, want %q", got, want)
	}
}

// TestDifferentIssuerClientIDDifferentKey verifies that two registry
// providers with the same providerID and subject but different
// issuer/clientID pairs produce different ExternalKeys.
func TestDifferentIssuerClientIDDifferentKey(t *testing.T) {
	subject := SubjectResult{ProviderID: "AbCdEfGhIjKlMnOpQrStUvWx", Subject: "uid42"}

	tx1 := Transaction{
		ProviderSource: "registry",
		RuntimeVersion: "v1.0",
		Issuer:         "https://issuer1.example.com",
		ClientID:       "cid-alpha",
	}
	tx2 := Transaction{
		ProviderSource: "registry",
		RuntimeVersion: "v1.0",
		Issuer:         "https://issuer2.example.com",
		ClientID:       "cid-beta",
	}

	s1, err := bindManagedSubject(subject, tx1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := bindManagedSubject(subject, tx2)
	if err != nil {
		t.Fatal(err)
	}
	if s1.IdentityNamespace == "" || s2.IdentityNamespace == "" {
		t.Fatal("expected nonempty namespaces")
	}
	if s1.IdentityNamespace == s2.IdentityNamespace {
		t.Fatal("different issuer/clientID must produce different namespace")
	}
	if s1.ExternalKey() == s2.ExternalKey() {
		t.Fatal("different issuer/clientID must produce different ExternalKey")
	}
}

// TestVersionOnlyRotationSameKey verifies that rotating RuntimeVersion
// (e.g. secret rotation) does not change the namespace or ExternalKey,
// because the namespace is derived from issuer+clientID only.
func TestVersionOnlyRotationSameKey(t *testing.T) {
	subject := SubjectResult{ProviderID: "AbCdEfGhIjKlMnOpQrStUvWx", Subject: "uid42"}

	tx1 := Transaction{
		ProviderSource: "registry",
		RuntimeVersion: "v1.0",
		Issuer:         "https://issuer.example.com",
		ClientID:       "cid-abc",
	}
	tx2 := Transaction{
		ProviderSource: "registry",
		RuntimeVersion: "v2.0",
		Issuer:         "https://issuer.example.com",
		ClientID:       "cid-abc",
	}

	s1, err := bindManagedSubject(subject, tx1)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := bindManagedSubject(subject, tx2)
	if err != nil {
		t.Fatal(err)
	}
	if s1.IdentityNamespace != s2.IdentityNamespace {
		t.Fatalf("version rotation changed namespace: %q vs %q", s1.IdentityNamespace, s2.IdentityNamespace)
	}
	if s1.ExternalKey() != s2.ExternalKey() {
		t.Fatal("version rotation must not change ExternalKey")
	}
}

// TestInvalidBindingFails verifies that partial source/version and
// unknown source are rejected by bindManagedSubject.
func TestInvalidBindingFails(t *testing.T) {
	subject := SubjectResult{ProviderID: "google", Subject: "uid"}

	cases := []struct {
		name string
		tx   Transaction
	}{
		{"partial source only", Transaction{ProviderSource: "registry", RuntimeVersion: ""}},
		{"partial version only", Transaction{ProviderSource: "", RuntimeVersion: "v1.0"}},
		{"unknown source", Transaction{ProviderSource: "external", RuntimeVersion: "v1.0"}},
	}
	for _, tc := range cases {
		_, err := bindManagedSubject(subject, tc.tx)
		if err == nil {
			t.Errorf("%s: expected error, got nil", tc.name)
		}
	}
}

// TestBindManagedSubjectDeterministic verifies that the same inputs
// always produce the same namespace and ExternalKey.
func TestBindManagedSubjectDeterministic(t *testing.T) {
	subject := SubjectResult{ProviderID: "AbCdEfGhIjKlMnOpQrStUvWx", Subject: "uid42"}
	tx := Transaction{
		ProviderSource: "registry",
		RuntimeVersion: "v1.0",
		Issuer:         "https://issuer.example.com",
		ClientID:       "cid-abc",
	}

	s1, err := bindManagedSubject(subject, tx)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := bindManagedSubject(subject, tx)
	if err != nil {
		t.Fatal(err)
	}
	if s1.IdentityNamespace != s2.IdentityNamespace {
		t.Fatalf("non-deterministic namespace: %q vs %q", s1.IdentityNamespace, s2.IdentityNamespace)
	}
	if s1.ExternalKey() != s2.ExternalKey() {
		t.Fatal("non-deterministic ExternalKey")
	}
}

// --- test helpers (stdlib only) ---

func sha256Sum(data string) [32]byte {
	return sha256.Sum256([]byte(data))
}

func encodeBase64URL(h [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(h[:])
}
