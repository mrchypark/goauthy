package oidc

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	LogoutTokenMinLifetime = time.Second
	LogoutTokenMaxLifetime = 2 * time.Minute
	maxLogoutTokenText     = 512

	backchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"
)

var errInvalidLogoutToken = errors.New("invalid logout token")

// LogoutTokenClaims is the fixed claim set for an OpenID Connect Back-Channel
// Logout Token. The audience is deliberately a single client identifier.
type LogoutTokenClaims struct {
	Issuer    string
	Subject   string
	Audience  string
	JTI       string
	SessionID string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type logoutTokenPayload struct {
	jwt.Claims
	JTI       string                    `json:"jti"`
	SessionID string                    `json:"sid,omitempty"`
	Events    map[string]map[string]any `json:"events"`
}

// SignLogoutToken signs a short-lived OIDC Back-Channel Logout Token.
func SignLogoutToken(key SigningKey, claims LogoutTokenClaims) (string, error) {
	if err := validLogoutTokenClaims(claims); err != nil {
		return "", err
	}
	private := key.Private
	if len(private) != ed25519.PrivateKeySize || key.PublicJWK.KeyID == "" {
		return "", fmt.Errorf("%w: invalid signing key", errInvalidLogoutToken)
	}
	public, ok := key.PublicJWK.Key.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize || !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		return "", fmt.Errorf("%w: signing key does not match public JWK", errInvalidLogoutToken)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: private},
		(&jose.SignerOptions{}).WithType("logout+jwt").WithHeader(jose.HeaderKey("kid"), key.PublicJWK.KeyID))
	if err != nil {
		return "", fmt.Errorf("create logout token signer: %w", err)
	}
	return jwt.Signed(signer).Claims(logoutTokenPayload{
		Claims: jwt.Claims{Issuer: claims.Issuer, Audience: jwt.Audience{claims.Audience},
			Subject: claims.Subject, IssuedAt: jwt.NewNumericDate(claims.IssuedAt), Expiry: jwt.NewNumericDate(claims.ExpiresAt)},
		JTI: claims.JTI, SessionID: claims.SessionID,
		Events: map[string]map[string]any{backchannelLogoutEvent: {}},
	}).Serialize()
}

// VerifyLogoutToken verifies an OIDC Back-Channel Logout Token for one client.
func VerifyLogoutToken(compact string, keys jose.JSONWebKeySet, issuer, audience string, now time.Time) (LogoutTokenClaims, error) {
	if issuer == "" || audience == "" || now.IsZero() {
		return LogoutTokenClaims{}, fmt.Errorf("%w: missing verification input", errInvalidLogoutToken)
	}
	token, err := jwt.ParseSigned(compact, []jose.SignatureAlgorithm{jose.EdDSA})
	if strings.Count(compact, ".") != 2 || err != nil || len(token.Headers) != 1 || token.Headers[0].Algorithm != string(jose.EdDSA) || token.Headers[0].KeyID == "" {
		return LogoutTokenClaims{}, fmt.Errorf("%w: invalid signature", errInvalidLogoutToken)
	}
	typ, ok := token.Headers[0].ExtraHeaders[jose.HeaderKey("typ")].(string)
	if !ok || typ != "logout+jwt" {
		return LogoutTokenClaims{}, fmt.Errorf("%w: invalid signature", errInvalidLogoutToken)
	}
	key, ok := idTokenPublicKey(keys, token.Headers[0].KeyID)
	if !ok {
		return LogoutTokenClaims{}, fmt.Errorf("%w: unknown signing key", errInvalidLogoutToken)
	}
	var raw map[string]any
	var payload logoutTokenPayload
	if err := token.Claims(key.Key, &payload, &raw); err != nil {
		return LogoutTokenClaims{}, fmt.Errorf("%w: signature verification failed", errInvalidLogoutToken)
	}
	_, hasNonce := raw["nonce"]
	if err := validLogoutTokenRawIdentity(raw); err != nil {
		return LogoutTokenClaims{}, err
	}
	payloadType, hasType := raw["typ"]
	if hasNonce || !validLogoutEvents(raw["events"]) || !validRauthyLogoutType(payloadType, hasType) {
		return LogoutTokenClaims{}, fmt.Errorf("%w: invalid logout event claims", errInvalidLogoutToken)
	}
	claims := LogoutTokenClaims{Issuer: payload.Issuer, Subject: payload.Subject, JTI: payload.JTI, SessionID: payload.SessionID}
	if len(payload.Audience) == 1 {
		claims.Audience = payload.Audience[0]
	}
	if payload.IssuedAt != nil {
		claims.IssuedAt = payload.IssuedAt.Time()
	}
	if payload.Expiry != nil {
		claims.ExpiresAt = payload.Expiry.Time()
	}
	if err := validLogoutTokenClaims(claims); err != nil || claims.Issuer != issuer || claims.Audience != audience || now.Before(claims.IssuedAt) || !now.Before(claims.ExpiresAt) {
		return LogoutTokenClaims{}, fmt.Errorf("%w: invalid claims", errInvalidLogoutToken)
	}
	return claims, nil
}

func validLogoutTokenClaims(claims LogoutTokenClaims) error {
	if strings.TrimSpace(claims.Issuer) == "" || strings.TrimSpace(claims.Audience) == "" || strings.TrimSpace(claims.JTI) == "" || len(claims.Audience) > maxLogoutTokenText || len(claims.JTI) > maxLogoutTokenText || claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || (claims.Subject == "" && claims.SessionID == "") {
		return fmt.Errorf("%w: missing required claims", errInvalidLogoutToken)
	}
	if claims.Subject != "" && !validLogoutTokenSubject(claims.Subject) {
		return fmt.Errorf("%w: invalid subject", errInvalidLogoutToken)
	}
	lifetime := claims.ExpiresAt.Sub(claims.IssuedAt)
	if lifetime < LogoutTokenMinLifetime || lifetime > LogoutTokenMaxLifetime {
		return fmt.Errorf("%w: invalid lifetime", errInvalidLogoutToken)
	}
	if claims.SessionID != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(claims.SessionID)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != claims.SessionID {
			return fmt.Errorf("%w: invalid session ID", errInvalidLogoutToken)
		}
	}
	return nil
}

func validLogoutTokenSubject(value string) bool {
	if value == "" || len(value) > maxLogoutTokenText || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validLogoutTokenRawIdentity(raw map[string]any) error {
	for _, name := range []string{"sub", "sid"} {
		value, present := raw[name]
		if !present {
			continue
		}
		text, ok := value.(string)
		if !ok || text == "" || (name == "sub" && !validLogoutTokenSubject(text)) {
			return fmt.Errorf("%w: malformed %s", errInvalidLogoutToken, name)
		}
	}
	return nil
}

func validLogoutEvents(value any) bool {
	events, ok := value.(map[string]any)
	if !ok || len(events) != 1 {
		return false
	}
	event, ok := events[backchannelLogoutEvent].(map[string]any)
	return ok && len(event) == 0
}

// Rauthy has emitted this non-standard payload claim. It is optional, but a
// present value must retain its documented meaning.
func validRauthyLogoutType(value any, present bool) bool {
	return !present || value == "logout+jwt"
}
