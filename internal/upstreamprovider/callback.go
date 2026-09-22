package upstreamprovider

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// CallbackParams holds the raw query parameters from the upstream callback.
type CallbackParams struct {
	State string
	Code  string
}

// CallbackResult is the validated callback outcome.
type CallbackResult struct {
	Transaction Transaction
	Code        string
	Issuer      string
	Audience    string
}

// IDTokenClaims is the minimal set of claims we verify from an OIDC id_token.
//
// Profile claim fields (Email, EmailVerified, GivenName, FamilyName) are
// preserved from the same verified signed payload. They are optional:
// nil means the provider did not include the claim. This is foundation
// for Rauthy federated onboarding/profile updates — not a full feature.
//
// rawClaims holds the full JSON payload bytes from the signature-verified
// ID token. Unexported: accessible only within this package for claim mapping.
type IDTokenClaims struct {
	Issuer             string   `json:"iss"`
	Subject            string   `json:"sub"`
	SessionID          string   `json:"sid"`
	Audience           []string `json:"aud"`
	Azp                string   `json:"azp"`
	Nonce              string   `json:"nonce"`
	ExpiresAt          int64    `json:"exp"`
	IssuedAt           int64    `json:"iat"`
	AuthenticationTime int64    `json:"auth_time"`
	NotBefore          int64    `json:"nbf"`
	// Profile claims — pointer types distinguish absent (nil) from zero value.
	Email         *string `json:"email"`
	EmailVerified *bool   `json:"email_verified"`
	GivenName     *string `json:"given_name"`
	FamilyName    *string `json:"family_name"`
	// rawClaims holds the full JSON payload bytes from the signature-verified
	// ID token. Unexported: accessible only within this package for claim mapping.
	rawClaims []byte
}

// RawClaims returns a copy of the full JSON payload from the signature-verified
// ID token. Returns nil if no raw payload was captured.
func (c *IDTokenClaims) RawClaims() json.RawMessage {
	if c.rawClaims == nil {
		return nil
	}
	out := make(json.RawMessage, len(c.rawClaims))
	copy(out, c.rawClaims)
	return out
}

// TokenVerifier abstracts OIDC token verification. Implementations must
// verify the token signature, issuer, and audience.
type TokenVerifier interface {
	VerifyIDToken(ctx context.Context, raw string, issuer, audience string) (*IDTokenClaims, error)
}

// ValidateCallback verifies the callback state, consumes the transaction
// with binding and provider checks, and enforces strict expiry.
// It derives the state digest internally from params.State via
// DigestSHA256 so callers never supply trusted input for the lookup.
func ValidateCallback(
	ctx context.Context,
	store Store,
	params CallbackParams,
	browserBindingDigest string,
	providerID string,
	now time.Time,
) (*CallbackResult, error) {
	if params.State == "" {
		return nil, errors.New("missing state")
	}
	if params.Code == "" {
		return nil, errors.New("missing code")
	}
	if browserBindingDigest == "" {
		return nil, errors.New("missing browser binding digest")
	}
	if providerID == "" {
		return nil, errors.New("missing provider ID")
	}

	// Derive state digest internally — never trust caller-supplied input.
	stateDigest := DigestSHA256(params.State)

	// Consume the transaction atomically. This enforces binding,
	// provider, strict expiry, and exactly-once semantics.
	tx, err := store.Consume(ctx, stateDigest, browserBindingDigest, providerID, now)
	if err != nil {
		// Map unknown state to ErrStateMismatch so callers don't learn
		// whether a transaction existed. Preserve all other errors.
		if errors.Is(err, ErrTransactionNotFound) {
			return nil, ErrStateMismatch
		}
		return nil, fmt.Errorf("consume transaction: %w", err)
	}

	return &CallbackResult{
		Transaction: tx,
		Code:        params.Code,
		Issuer:      tx.Issuer,
		Audience:    tx.Audience,
	}, nil
}

// ValidateIDToken verifies an id_token against the stored transaction.
// It validates: nil claims, exact issuer, constant-time nonce, audience
// membership, azp rules, nonempty subject, and token time boundaries
// via the injected now.
func ValidateIDToken(
	ctx context.Context,
	verifier TokenVerifier,
	rawToken string,
	tx Transaction,
	now time.Time,
) (*IDTokenClaims, error) {
	if verifier == nil {
		return nil, errors.New("nil token verifier")
	}
	if tx.Nonce == "" {
		return nil, errors.New("empty transaction nonce")
	}
	if tx.ClientID == "" {
		return nil, errors.New("empty transaction client ID")
	}
	if tx.Issuer == "" {
		return nil, errors.New("empty transaction issuer")
	}
	claims, err := verifier.VerifyIDToken(ctx, rawToken, tx.Issuer, tx.ClientID)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}
	if claims == nil {
		return nil, errors.New("nil claims from verifier")
	}

	// Exact issuer check.
	if claims.Issuer != tx.Issuer {
		return nil, errors.New("issuer mismatch in id_token")
	}

	// Constant-time nonce comparison.
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(tx.Nonce)) != 1 {
		return nil, ErrNonceMismatch
	}

	// Nonempty subject.
	if claims.Subject == "" {
		return nil, errors.New("empty subject in id_token")
	}

	// exp must be present and nonzero.
	if claims.ExpiresAt == 0 {
		return nil, errors.New("missing exp in id_token")
	}
	// now >= exp means expired.
	if !now.Before(time.Unix(claims.ExpiresAt, 0)) {
		return nil, errors.New("id_token expired")
	}

	// iat must be present and nonzero.
	if claims.IssuedAt == 0 {
		return nil, errors.New("missing iat in id_token")
	}
	// Future iat rejected.
	if now.Before(time.Unix(claims.IssuedAt, 0)) {
		return nil, errors.New("id_token issued in the future")
	}

	// nbf: if present, must be <= now.
	if claims.NotBefore > 0 && now.Before(time.Unix(claims.NotBefore, 0)) {
		return nil, errors.New("id_token not yet valid")
	}

	// Audience membership: tx.ClientID must be in the token's aud list.
	if !audienceContains(claims.Audience, tx.ClientID) {
		return nil, errors.New("client ID not in id_token audience")
	}

	// Multi-audience: if aud has more than one value, azp must be present
	// and must exactly equal tx.ClientID.
	if len(claims.Audience) > 1 {
		if claims.Azp == "" {
			return nil, errors.New("missing azp in multi-audience id_token")
		}
		if claims.Azp != tx.ClientID {
			return nil, errors.New("azp mismatch in multi-audience id_token")
		}
	}

	// Azp: when present, must always equal tx.ClientID exactly.
	if claims.Azp != "" && claims.Azp != tx.ClientID {
		return nil, errors.New("azp mismatch in id_token")
	}

	return claims, nil
}

// audienceContains reports whether audience contains value.
func audienceContains(audience []string, value string) bool {
	for _, a := range audience {
		if subtle.ConstantTimeCompare([]byte(a), []byte(value)) == 1 {
			return true
		}
	}
	return false
}
