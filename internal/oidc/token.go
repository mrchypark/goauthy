package oidc

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var errInvalidIDToken = errors.New("invalid ID token")

var (
	roleClaimPattern  = regexp.MustCompile(`^[a-zA-Z0-9\-_/,:*.]{2,64}$`)
	groupClaimPattern = regexp.MustCompile(`^[A-Za-z0-9\-_/,:*]{2,64}$`)
)

const (
	JWKSCacheMaxAge    = 5 * time.Minute
	MaxIDTokenLifetime = time.Hour
	// MaxAccessTokenLifetime is shared with OAuth configuration and key
	// retirement so no signed access token can outlive its verification key.
	MaxAccessTokenLifetime   = 24 * time.Hour
	IDTokenClockSkew         = 30 * time.Second
	logoutIDTokenClockLeeway = 10 * time.Minute
	// A retiring key remains available for the longest signed token plus one
	// JWKS cache interval. This dominates the shorter ID-token logout window.
	MinimumSigningKeyRetirement = MaxAccessTokenLifetime + JWKSCacheMaxAge
)

// IDTokenClaims is the fixed set of OpenID Connect claims GoAuthy issues in
// an ID token. The authorization endpoint supplies the optional
// flow-specific fields; SignIDToken rejects malformed supplied values.
type IDTokenClaims struct {
	Issuer                string
	Subject               string
	Audience              []string
	IssuedAt              time.Time
	ExpiresAt             time.Time
	NotBefore             time.Time
	Nonce                 string
	AuthTime              time.Time
	AuthorizedParty       string
	SessionID             string
	AccessTokenHash       string
	AuthenticationMethods []string
	Roles                 []string
	Groups                []string
	CustomClaims          CustomClaims
	// Standard profile claims are populated only when their corresponding
	// scope was granted. Pointers preserve the distinction between an
	// unrequested value and an explicitly empty (but valid) value.
	Profile ProfileClaims
}

// ProfileClaims is the standard OIDC user profile projection. It contains no
// credentials or authorization data and is safe to copy between token and
// UserInfo responses.
type ProfileClaims struct {
	Email               *string
	EmailVerified       *bool
	PreferredUsername   *string
	GivenName           *string
	FamilyName          *string
	Birthdate           *string
	Address             map[string]string
	PhoneNumber         *string
	PhoneNumberVerified *bool
	Zoneinfo            *string
	Locale              *string
}

type idTokenPayload struct {
	jwt.Claims
	Nonce                 string            `json:"nonce,omitempty"`
	AuthTime              *jwt.NumericDate  `json:"auth_time,omitempty"`
	AuthorizedParty       string            `json:"azp,omitempty"`
	SessionID             string            `json:"sid,omitempty"`
	AccessTokenHash       string            `json:"at_hash,omitempty"`
	AuthenticationMethods []string          `json:"amr,omitempty"`
	Roles                 []string          `json:"roles"`
	Groups                []string          `json:"groups,omitempty"`
	Custom                json.RawMessage   `json:"custom,omitempty"`
	Email                 *string           `json:"email,omitempty"`
	EmailVerified         *bool             `json:"email_verified,omitempty"`
	PreferredUsername     *string           `json:"preferred_username,omitempty"`
	GivenName             *string           `json:"given_name,omitempty"`
	FamilyName            *string           `json:"family_name,omitempty"`
	Birthdate             *string           `json:"birthdate,omitempty"`
	Address               map[string]string `json:"address,omitempty"`
	PhoneNumber           *string           `json:"phone_number,omitempty"`
	PhoneNumberVerified   *bool             `json:"phone_number_verified,omitempty"`
	Zoneinfo              *string           `json:"zoneinfo,omitempty"`
	Locale                *string           `json:"locale,omitempty"`
}

// AccessTokenHash returns the OpenID Connect at_hash value for an EdDSA ID
// token: the base64url-encoded left half of SHA-512(access token).
func AccessTokenHash(accessToken string) string {
	sum := sha512.Sum512([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:sha512.Size/2])
}

// SignIDToken signs the required OpenID Connect claims with an active Ed25519
// signing key.
func SignIDToken(key SigningKey, claims IDTokenClaims) (string, error) {
	if claims.Roles == nil {
		claims.Roles = []string{}
	}
	custom, err := normalizedCustomClaims(claims.CustomClaims)
	if err != nil {
		return "", err
	}
	claims.CustomClaims = custom
	if err := validIDTokenClaims(claims); err != nil {
		return "", err
	}
	private := key.Private
	if len(private) != ed25519.PrivateKeySize || key.PublicJWK.KeyID == "" {
		return "", fmt.Errorf("%w: invalid signing key", errInvalidIDToken)
	}
	public, ok := key.PublicJWK.Key.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize || !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		return "", fmt.Errorf("%w: signing key does not match public JWK", errInvalidIDToken)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: private},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), key.PublicJWK.KeyID))
	if err != nil {
		return "", fmt.Errorf("create ID token signer: %w", err)
	}
	payload := newIDTokenPayload(claims)
	nested, root := custom.Nested, custom.Root
	if custom.Values != nil {
		if custom.AtRoot {
			root = custom.Values
		} else {
			nested = custom.Values
		}
	}
	if len(nested) != 0 {
		customJSON, marshalErr := json.Marshal(nested)
		if marshalErr != nil {
			return "", fmt.Errorf("%w: encode custom claims", errInvalidIDToken)
		}
		payload.Custom = customJSON
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%w: encode ID token claims", errInvalidIDToken)
	}
	if len(root) != 0 {
		rootPayload := make(map[string]json.RawMessage)
		if unmarshalErr := json.Unmarshal(payloadJSON, &rootPayload); unmarshalErr != nil {
			return "", fmt.Errorf("%w: encode ID token claims", errInvalidIDToken)
		}
		for name, value := range root {
			rootPayload[name] = value
		}
		payloadJSON, err = json.Marshal(rootPayload)
		if err != nil {
			return "", fmt.Errorf("%w: encode ID token claims", errInvalidIDToken)
		}
	}
	signed, err := signer.Sign(payloadJSON)
	if err != nil {
		return "", fmt.Errorf("sign ID token: %w", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("sign ID token: %w", err)
	}
	return compact, nil
}

// VerifyIDToken verifies an EdDSA ID token against public JWKS keys and its
// issuer, audience, and expiry. It intentionally accepts no caller claims.
func VerifyIDToken(compact string, keys jose.JSONWebKeySet, issuer, audience string, now time.Time) (IDTokenClaims, error) {
	return verifyIDToken(compact, keys, issuer, audience, now, 0)
}

// VerifyLogoutIDToken verifies an ID token hint for RP-initiated logout.
// Rauthy v0.36.2 permits a 600-second clock leeway only for this use.
func VerifyLogoutIDToken(compact string, keys jose.JSONWebKeySet, issuer, audience string, now time.Time) (IDTokenClaims, error) {
	return verifyIDToken(compact, keys, issuer, audience, now, logoutIDTokenClockLeeway)
}

func verifyIDToken(compact string, keys jose.JSONWebKeySet, issuer, audience string, now time.Time, leeway time.Duration) (IDTokenClaims, error) {
	if issuer == "" || audience == "" || now.IsZero() {
		return IDTokenClaims{}, fmt.Errorf("%w: missing verification input", errInvalidIDToken)
	}
	token, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.EdDSA})
	if strings.Count(compact, ".") != 2 || err != nil || len(token.Signatures) != 1 || token.Signatures[0].Protected.Algorithm != string(jose.EdDSA) || token.Signatures[0].Protected.KeyID == "" {
		return IDTokenClaims{}, fmt.Errorf("%w: invalid signature", errInvalidIDToken)
	}
	typ, ok := token.Signatures[0].Protected.ExtraHeaders[jose.HeaderKey("typ")].(string)
	if !ok || typ != "JWT" {
		return IDTokenClaims{}, fmt.Errorf("%w: invalid signature", errInvalidIDToken)
	}
	key, ok := idTokenPublicKey(keys, token.Signatures[0].Protected.KeyID)
	if !ok {
		return IDTokenClaims{}, fmt.Errorf("%w: unknown signing key", errInvalidIDToken)
	}
	rawPayload, err := token.Verify(key.Key)
	if err != nil {
		return IDTokenClaims{}, fmt.Errorf("%w: signature verification failed", errInvalidIDToken)
	}
	if err := validateJSON(rawPayload, maxCustomJSONDepth+4, maxCustomJSONNodes+256); err != nil {
		return IDTokenClaims{}, fmt.Errorf("%w: invalid token payload", errInvalidIDToken)
	}
	var rawClaims map[string]json.RawMessage
	var payload idTokenPayload
	if err := json.Unmarshal(rawPayload, &rawClaims); err != nil || json.Unmarshal(rawPayload, &payload) != nil {
		return IDTokenClaims{}, fmt.Errorf("%w: invalid token payload", errInvalidIDToken)
	}
	if err := requiredIDTokenPayload(payload, issuer, audience, now, leeway); err != nil {
		return IDTokenClaims{}, err
	}
	custom, err := customClaimsFromPayload(rawClaims)
	if err != nil {
		return IDTokenClaims{}, err
	}
	claims := IDTokenClaims{
		Issuer: payload.Issuer, Subject: payload.Subject, Audience: append([]string(nil), payload.Audience...),
		IssuedAt: payload.IssuedAt.Time(), ExpiresAt: payload.Expiry.Time(), Nonce: payload.Nonce,
		AuthorizedParty: payload.AuthorizedParty, SessionID: payload.SessionID,
		AccessTokenHash:       payload.AccessTokenHash,
		AuthenticationMethods: append([]string(nil), payload.AuthenticationMethods...),
		Roles:                 append([]string{}, payload.Roles...),
		Groups:                append([]string(nil), payload.Groups...),
		CustomClaims:          custom,
		Profile: ProfileClaims{Email: payload.Email, EmailVerified: payload.EmailVerified,
			PreferredUsername: payload.PreferredUsername, GivenName: payload.GivenName, FamilyName: payload.FamilyName,
			Birthdate: payload.Birthdate, Address: payload.Address, PhoneNumber: payload.PhoneNumber,
			PhoneNumberVerified: payload.PhoneNumberVerified, Zoneinfo: payload.Zoneinfo, Locale: payload.Locale},
	}
	if payload.NotBefore != nil {
		claims.NotBefore = payload.NotBefore.Time()
	}
	if payload.AuthTime != nil {
		claims.AuthTime = payload.AuthTime.Time()
	}
	return claims, nil
}

func validIDTokenClaims(claims IDTokenClaims) error {
	if claims.Issuer == "" || claims.Subject == "" || len(claims.Audience) != 1 || claims.IssuedAt.IsZero() || claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(claims.IssuedAt) {
		return fmt.Errorf("%w: missing or invalid required claims", errInvalidIDToken)
	}
	for _, audience := range claims.Audience {
		if audience == "" {
			return fmt.Errorf("%w: empty audience", errInvalidIDToken)
		}
	}
	if claims.ExpiresAt.Sub(claims.IssuedAt) > MaxIDTokenLifetime {
		return fmt.Errorf("%w: ID token lifetime exceeds maximum", errInvalidIDToken)
	}
	if !claims.NotBefore.IsZero() && claims.NotBefore.After(claims.ExpiresAt) {
		return fmt.Errorf("%w: invalid not-before claim", errInvalidIDToken)
	}
	if !claims.AuthTime.IsZero() && claims.AuthTime.After(claims.IssuedAt) {
		return fmt.Errorf("%w: invalid authentication time", errInvalidIDToken)
	}
	if claims.AuthorizedParty != "" && claims.AuthorizedParty != claims.Audience[0] {
		return fmt.Errorf("%w: authorized party does not match audience", errInvalidIDToken)
	}
	if claims.AccessTokenHash != "" && !validAccessTokenHash(claims.AccessTokenHash) {
		return fmt.Errorf("%w: invalid access token hash", errInvalidIDToken)
	}
	for _, method := range claims.AuthenticationMethods {
		if method == "" {
			return fmt.Errorf("%w: invalid authentication method", errInvalidIDToken)
		}
	}
	if claims.Roles == nil || !validCanonicalClaimValues(claims.Roles, roleClaimPattern) || !validCanonicalClaimValues(claims.Groups, groupClaimPattern) {
		return fmt.Errorf("%w: invalid roles or groups claim", errInvalidIDToken)
	}
	if _, err := normalizedCustomClaims(claims.CustomClaims); err != nil {
		return err
	}
	return nil
}

func newIDTokenPayload(claims IDTokenClaims) idTokenPayload {
	payload := idTokenPayload{Claims: jwt.Claims{
		Issuer: claims.Issuer, Subject: claims.Subject, Audience: jwt.Audience(claims.Audience),
		IssuedAt: jwt.NewNumericDate(claims.IssuedAt), Expiry: jwt.NewNumericDate(claims.ExpiresAt),
		NotBefore: jwt.NewNumericDate(claims.NotBefore),
	}, Nonce: claims.Nonce, AuthorizedParty: claims.AuthorizedParty, SessionID: claims.SessionID,
		AccessTokenHash: claims.AccessTokenHash, AuthenticationMethods: claims.AuthenticationMethods,
		Roles: claims.Roles, Groups: claims.Groups, Email: claims.Profile.Email,
		EmailVerified: claims.Profile.EmailVerified, PreferredUsername: claims.Profile.PreferredUsername,
		GivenName: claims.Profile.GivenName, FamilyName: claims.Profile.FamilyName,
		Birthdate: claims.Profile.Birthdate, Address: claims.Profile.Address,
		PhoneNumber: claims.Profile.PhoneNumber, PhoneNumberVerified: claims.Profile.PhoneNumberVerified,
		Zoneinfo: claims.Profile.Zoneinfo, Locale: claims.Profile.Locale}
	if !claims.AuthTime.IsZero() {
		payload.AuthTime = jwt.NewNumericDate(claims.AuthTime)
	}
	return payload
}

func customClaimsFromPayload(raw map[string]json.RawMessage) (CustomClaims, error) {
	customRaw, nested := raw["custom"]
	root := make(map[string]json.RawMessage)
	for name, value := range raw {
		if _, standard := reservedIDTokenClaimNames[name]; !standard {
			root[name] = value
		}
	}
	if nested {
		values := make(map[string]json.RawMessage)
		if json.Unmarshal(customRaw, &values) != nil || len(values) == 0 {
			return CustomClaims{}, fmt.Errorf("%w: invalid custom claim representation", errInvalidIDToken)
		}
		if len(root) == 0 {
			return normalizedCustomClaims(CustomClaims{Values: values})
		}
		return normalizedCustomClaims(CustomClaims{Nested: values, Root: root})
	}
	return normalizedCustomClaims(CustomClaims{Values: root, AtRoot: len(root) != 0})
}

func validCanonicalClaimValues(values []string, pattern *regexp.Regexp) bool {
	if len(values) > 64 {
		return false
	}
	for i, value := range values {
		if !pattern.MatchString(value) || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}

func idTokenPublicKey(keys jose.JSONWebKeySet, kid string) (jose.JSONWebKey, bool) {
	for _, key := range keys.Keys {
		if key.KeyID == kid && key.IsPublic() && key.Algorithm == string(jose.EdDSA) && key.Use == "sig" {
			if public, ok := key.Key.(ed25519.PublicKey); ok && len(public) == ed25519.PublicKeySize {
				return key, true
			}
		}
	}
	return jose.JSONWebKey{}, false
}

func requiredIDTokenPayload(payload idTokenPayload, issuer, audience string, now time.Time, leeway time.Duration) error {
	if payload.Issuer == "" || payload.Subject == "" || len(payload.Audience) == 0 || payload.IssuedAt == nil || payload.Expiry == nil {
		return fmt.Errorf("%w: missing required claims", errInvalidIDToken)
	}
	if !payload.Expiry.Time().After(payload.IssuedAt.Time()) || (leeway == 0 && !now.Before(payload.Expiry.Time())) {
		return fmt.Errorf("%w: expired or invalid lifetime", errInvalidIDToken)
	}
	if err := payload.Claims.ValidateWithLeeway(jwt.Expected{Issuer: issuer, AnyAudience: jwt.Audience{audience}, Time: now}, leeway); err != nil {
		return fmt.Errorf("%w: claims validation failed", errInvalidIDToken)
	}
	claims := IDTokenClaims{
		Issuer: payload.Issuer, Subject: payload.Subject, Audience: append([]string(nil), payload.Audience...),
		IssuedAt: payload.IssuedAt.Time(), ExpiresAt: payload.Expiry.Time(), Nonce: payload.Nonce,
		AuthorizedParty: payload.AuthorizedParty, SessionID: payload.SessionID,
		AccessTokenHash: payload.AccessTokenHash, AuthenticationMethods: payload.AuthenticationMethods,
		Roles: payload.Roles, Groups: payload.Groups,
	}
	claims.Profile = ProfileClaims{Email: payload.Email, EmailVerified: payload.EmailVerified,
		PreferredUsername: payload.PreferredUsername, GivenName: payload.GivenName, FamilyName: payload.FamilyName,
		Birthdate: payload.Birthdate, Address: payload.Address, PhoneNumber: payload.PhoneNumber,
		PhoneNumberVerified: payload.PhoneNumberVerified, Zoneinfo: payload.Zoneinfo, Locale: payload.Locale}
	if payload.NotBefore != nil {
		claims.NotBefore = payload.NotBefore.Time()
	}
	if payload.AuthTime != nil {
		claims.AuthTime = payload.AuthTime.Time()
	}
	return validIDTokenClaims(claims)
}

func validAccessTokenHash(value string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(decoded) == sha512.Size/2
}
