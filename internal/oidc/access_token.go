package oidc

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

var errInvalidAccessToken = errors.New("invalid access token")

// AccessTokenClaims is GoAuthy's signed access-token surface. It mirrors the
// Rauthy bearer/DPoP fields while retaining stateful server-side revocation.
type AccessTokenClaims struct {
	Actor           *ActorClaims
	Issuer          string
	Subject         string
	Audience        []string
	IssuedAt        time.Time
	NotBefore       time.Time
	ExpiresAt       time.Time
	ID              string
	AuthorizedParty string
	Scope           []string
	Type            string
	ConfirmationJKT string
	Roles           []string
	Groups          []string
	CustomClaims    CustomClaims
}

type accessTokenPayload struct {
	Actor *ActorClaims `json:"act,omitempty"`
	jwt.Claims
	Type            string            `json:"typ"`
	AuthorizedParty string            `json:"azp"`
	Scope           string            `json:"scope,omitempty"`
	Confirmation    map[string]string `json:"cnf,omitempty"`
	Roles           []string          `json:"roles,omitempty"`
	Groups          []string          `json:"groups,omitempty"`
	Custom          json.RawMessage   `json:"custom,omitempty"`
}

// SignAccessToken signs a compact EdDSA JWT with the active OIDC signing key.
func SignAccessToken(key SigningKey, claims AccessTokenClaims) (string, error) {
	custom, err := normalizedCustomClaims(claims.CustomClaims)
	if err != nil {
		return "", err
	}
	if err := validAccessTokenClaims(claims); err != nil {
		return "", err
	}
	private := key.Private
	public, ok := key.PublicJWK.Key.(ed25519.PublicKey)
	if len(private) != ed25519.PrivateKeySize || key.PublicJWK.KeyID == "" || !ok || len(public) != ed25519.PublicKeySize || !bytes.Equal(private.Public().(ed25519.PublicKey), public) {
		return "", fmt.Errorf("%w: invalid signing key", errInvalidAccessToken)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: private}, (&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), key.PublicJWK.KeyID))
	if err != nil {
		return "", fmt.Errorf("create access token signer: %w", err)
	}
	payload := accessTokenPayload{Actor: claims.Actor, Claims: jwt.Claims{Issuer: claims.Issuer, Subject: claims.Subject, Audience: jwt.Audience(claims.Audience), ID: claims.ID, IssuedAt: jwt.NewNumericDate(claims.IssuedAt), NotBefore: jwt.NewNumericDate(claims.NotBefore), Expiry: jwt.NewNumericDate(claims.ExpiresAt)}, Type: claims.Type, AuthorizedParty: claims.AuthorizedParty, Scope: strings.Join(claims.Scope, " "), Roles: claims.Roles, Groups: claims.Groups}
	if claims.ConfirmationJKT != "" {
		payload.Confirmation = map[string]string{"jkt": claims.ConfirmationJKT}
	}
	nested, root := custom.Nested, custom.Root
	if custom.Values != nil {
		if custom.AtRoot {
			root = custom.Values
		} else {
			nested = custom.Values
		}
	}
	if len(nested) != 0 {
		payload.Custom, err = json.Marshal(nested)
		if err != nil {
			return "", fmt.Errorf("%w: encode custom claims", errInvalidAccessToken)
		}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%w: encode claims", errInvalidAccessToken)
	}
	if len(root) != 0 {
		var rootPayload map[string]json.RawMessage
		if json.Unmarshal(raw, &rootPayload) != nil {
			return "", fmt.Errorf("%w: encode claims", errInvalidAccessToken)
		}
		for name, value := range root {
			rootPayload[name] = value
		}
		raw, err = json.Marshal(rootPayload)
		if err != nil {
			return "", fmt.Errorf("%w: encode claims", errInvalidAccessToken)
		}
	}
	signed, err := signer.Sign(raw)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return compact, nil
}

// VerifyAccessToken verifies a compact access token using public JWKS keys.
func VerifyAccessToken(compact string, keys jose.JSONWebKeySet, issuer string, now time.Time) (AccessTokenClaims, error) {
	if issuer == "" || now.IsZero() {
		return AccessTokenClaims{}, fmt.Errorf("%w: missing verification input", errInvalidAccessToken)
	}
	token, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.EdDSA})
	if strings.Count(compact, ".") != 2 || err != nil || len(token.Signatures) != 1 || token.Signatures[0].Protected.Algorithm != string(jose.EdDSA) || token.Signatures[0].Protected.KeyID == "" {
		return AccessTokenClaims{}, fmt.Errorf("%w: invalid signature", errInvalidAccessToken)
	}
	typ, ok := token.Signatures[0].Protected.ExtraHeaders[jose.HeaderKey("typ")].(string)
	if !ok || typ != "JWT" {
		return AccessTokenClaims{}, fmt.Errorf("%w: invalid signature", errInvalidAccessToken)
	}
	key, ok := idTokenPublicKey(keys, token.Signatures[0].Protected.KeyID)
	if !ok {
		return AccessTokenClaims{}, fmt.Errorf("%w: unknown signing key", errInvalidAccessToken)
	}
	raw, err := token.Verify(key.Key)
	if err != nil || validateJSON(raw, maxCustomJSONDepth+4, maxCustomJSONNodes+256) != nil {
		return AccessTokenClaims{}, fmt.Errorf("%w: invalid token payload", errInvalidAccessToken)
	}
	var rawClaims map[string]json.RawMessage
	var payload accessTokenPayload
	if json.Unmarshal(raw, &rawClaims) != nil || json.Unmarshal(raw, &payload) != nil {
		return AccessTokenClaims{}, fmt.Errorf("%w: invalid token payload", errInvalidAccessToken)
	}
	if payload.Issuer != issuer || payload.IssuedAt == nil || payload.NotBefore == nil || payload.Expiry == nil || payload.ID == "" || payload.AuthorizedParty == "" || (payload.Type != "Bearer" && payload.Type != "DPoP") || len(payload.Audience) == 0 || !payload.Expiry.Time().After(payload.IssuedAt.Time()) || !now.Before(payload.Expiry.Time()) || payload.Claims.ValidateWithLeeway(jwt.Expected{Issuer: issuer, Time: now}, 0) != nil {
		return AccessTokenClaims{}, fmt.Errorf("%w: invalid claims", errInvalidAccessToken)
	}
	claims := AccessTokenClaims{Issuer: payload.Issuer, Subject: payload.Subject, Audience: append([]string(nil), payload.Audience...), IssuedAt: payload.IssuedAt.Time(), NotBefore: payload.NotBefore.Time(), ExpiresAt: payload.Expiry.Time(), ID: payload.ID, AuthorizedParty: payload.AuthorizedParty, Scope: strings.Fields(payload.Scope), Type: payload.Type, Roles: append([]string(nil), payload.Roles...), Groups: append([]string(nil), payload.Groups...)}
	if rawActor, exists := rawClaims["act"]; exists {
		var value any
		if json.Unmarshal(rawActor, &value) != nil {
			return AccessTokenClaims{}, fmt.Errorf("%w: invalid actor", errInvalidAccessToken)
		}
		claims.Actor, err = ParseActorClaims(value)
		if err != nil {
			return AccessTokenClaims{}, err
		}
	}
	if payload.Confirmation != nil {
		claims.ConfirmationJKT = payload.Confirmation["jkt"]
	}
	claims.CustomClaims, err = customClaimsFromPayload(rawClaims)
	if err != nil {
		return AccessTokenClaims{}, fmt.Errorf("%w: invalid custom claims", errInvalidAccessToken)
	}
	if err := validAccessTokenClaims(claims); err != nil {
		return AccessTokenClaims{}, err
	}
	return claims, nil
}

func validAccessTokenClaims(claims AccessTokenClaims) error {
	if !validActorClaims(claims.Actor) {
		return fmt.Errorf("%w: invalid actor", errInvalidAccessToken)
	}
	if claims.Issuer == "" || len(claims.Audience) == 0 || claims.IssuedAt.IsZero() || claims.NotBefore.IsZero() || claims.ExpiresAt.IsZero() || !claims.ExpiresAt.After(claims.IssuedAt) || claims.ExpiresAt.Sub(claims.IssuedAt) > MaxAccessTokenLifetime || claims.ID == "" || claims.AuthorizedParty == "" || (claims.Type != "Bearer" && claims.Type != "DPoP") || (claims.Type == "DPoP" && claims.ConfirmationJKT == "") || (claims.Type == "Bearer" && claims.ConfirmationJKT != "") {
		return fmt.Errorf("%w: missing or invalid claims", errInvalidAccessToken)
	}
	if !validCanonicalClaimValues(claims.Roles, roleClaimPattern) || !validCanonicalClaimValues(claims.Groups, groupClaimPattern) {
		return fmt.Errorf("%w: invalid roles or groups claim", errInvalidAccessToken)
	}
	seenScopes := make(map[string]struct{}, len(claims.Scope))
	for _, scope := range claims.Scope {
		if scope == "" {
			return fmt.Errorf("%w: invalid scope", errInvalidAccessToken)
		}
		if _, duplicate := seenScopes[scope]; duplicate {
			return fmt.Errorf("%w: duplicate scope", errInvalidAccessToken)
		}
		seenScopes[scope] = struct{}{}
	}
	_, err := normalizedCustomClaims(claims.CustomClaims)
	return err
}
