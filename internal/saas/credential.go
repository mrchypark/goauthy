package saas

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/mrchypark/goauthy/internal/oidc"
)

var errCredential = errors.New("saas: invalid credential envelope")

// This package-private payload is never a record/API response. Expiry values
// are absolute timestamps; zero means the provider supplied no expiry.
type credential struct {
	AccountID              string   `json:"account_id,omitempty"`
	APIKey                 string   `json:"api_key,omitempty"`
	ConnectorDigest        string   `json:"connector_digest,omitempty"`
	AccessToken            string   `json:"access_token"`
	RefreshToken           string   `json:"refresh_token,omitempty"`
	ExpiresAtUnixMS        int64    `json:"expires_at_unix_ms"`
	RefreshExpiresAtUnixMS int64    `json:"refresh_expires_at_unix_ms"`
	Scopes                 []string `json:"scopes"`
}

func (credential) String() string   { return "[redacted SaaS credential]" }
func (credential) GoString() string { return "[redacted SaaS credential]" }

// Metadata edits do not change this binding. Reconnection changes Generation;
// successful refresh increments TokenVersion, independently of authorization.
type credentialBinding struct {
	Owner, CollectionID, ConnectionID, ProviderID, Generation string
	TokenVersion                                              int64
}

func credentialPurpose(binding credentialBinding) (string, error) {
	for _, value := range []string{binding.Owner, binding.CollectionID, binding.ConnectionID, binding.ProviderID, binding.Generation} {
		if !validText(value) || strings.ContainsRune(value, 0) {
			return "", errCredential
		}
	}
	if binding.TokenVersion < 1 {
		return "", errCredential
	}
	// Struct JSON makes field boundaries unambiguous before hashing to fit the
	// existing keyring's 64-byte purpose limit. No new cryptography is introduced.
	raw, err := json.Marshal(binding)
	if err != nil {
		return "", errCredential
	}
	digest := sha256.Sum256(raw)
	return "saas/cred/v1/" + base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func validCredential(value credential) bool {
	if value.AccountID != "" && (!validText(value.AccountID) || value.APIKey != "") {
		return false
	}
	if value.APIKey != "" {
		return validText(value.APIKey) && (value.ConnectorDigest == "" || validAuthorizationDigest(value.ConnectorDigest)) && value.AccessToken == "" && value.RefreshToken == "" && value.ExpiresAtUnixMS == 0 && value.RefreshExpiresAtUnixMS == 0 && len(value.Scopes) == 0
	}
	return value.ConnectorDigest == "" && validText(value.AccessToken) && (value.RefreshToken == "" || validText(value.RefreshToken)) && value.ExpiresAtUnixMS >= 0 && value.RefreshExpiresAtUnixMS >= 0 && len(value.Scopes) <= 64
}

func sealCredential(keys *oidc.Keyring, binding credentialBinding, value credential) ([]byte, error) {
	purpose, err := credentialPurpose(binding)
	if err != nil || !validCredential(value) {
		return nil, errCredential
	}
	plaintext, err := json.Marshal(value)
	if err != nil || len(plaintext) > 16<<10 {
		return nil, errCredential
	}
	defer clear(plaintext)
	envelope, err := keys.SealEnvelope(purpose, plaintext)
	if err != nil {
		return nil, errCredential
	}
	return envelope, nil
}

func openCredential(keys *oidc.Keyring, binding credentialBinding, envelope []byte) (credential, error) {
	purpose, err := credentialPurpose(binding)
	if err != nil || len(envelope) > 17<<10 {
		return credential{}, errCredential
	}
	plaintext, err := keys.OpenEnvelope(purpose, envelope)
	if err != nil {
		return credential{}, errCredential
	}
	defer clear(plaintext)
	var value credential
	if json.Unmarshal(plaintext, &value) != nil || !validCredential(value) {
		return credential{}, errCredential
	}
	return value, nil
}
