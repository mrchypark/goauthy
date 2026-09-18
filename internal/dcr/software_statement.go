package dcr

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/mrchypark/goauthy/internal/oidc"
)

const maxSoftwareStatementLength = 12 << 10

var (
	errInvalidSoftwareStatement    = errors.New("invalid software statement")
	errUnapprovedSoftwareStatement = errors.New("unapproved software statement")
)

// SoftwareStatementIssuer is one statically trusted software-statement issuer.
// Keys are public signing keys; no network key discovery is performed.
type SoftwareStatementIssuer struct {
	Issuer   string             `json:"issuer"`
	JWKS     jose.JSONWebKeySet `json:"jwks"`
	Audience string             `json:"audience,omitempty"`
}

// SoftwareStatementConfig is the immutable trust policy for DCR statements.
type SoftwareStatementConfig struct {
	Issuers []SoftwareStatementIssuer `json:"issuers"`
	Now     func() time.Time          `json:"-"`
}

type softwareStatementPolicy struct {
	issuers map[string]SoftwareStatementIssuer
	now     func() time.Time
}

func LoadSoftwareStatementConfig(path string) (SoftwareStatementConfig, error) {
	if path == "" {
		return SoftwareStatementConfig{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return SoftwareStatementConfig{}, errors.New("read software-statement trust file")
	}
	if len(b) > 64<<10 {
		return SoftwareStatementConfig{}, errors.New("software-statement trust file is too large")
	}
	if err := rejectDuplicateJSONMembers(b); err != nil {
		return SoftwareStatementConfig{}, errors.New("invalid software-statement trust file")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	var config SoftwareStatementConfig
	if err := decoder.Decode(&config); err != nil {
		return SoftwareStatementConfig{}, errors.New("invalid software-statement trust file")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return SoftwareStatementConfig{}, errors.New("invalid software-statement trust file")
	}
	return config, nil
}

// CanonicalDigest identifies the complete public trust policy independent of
// issuer/key ordering in the source file.
func (config SoftwareStatementConfig) CanonicalDigest() (string, error) {
	if _, err := newSoftwareStatementPolicy(config); err != nil {
		return "", err
	}
	issuers := append([]SoftwareStatementIssuer{}, config.Issuers...)
	sort.Slice(issuers, func(i, j int) bool { return issuers[i].Issuer < issuers[j].Issuer })
	type canonicalIssuer struct {
		Issuer, Audience string
		Keys             []json.RawMessage
	}
	canonical := make([]canonicalIssuer, 0, len(issuers))
	for _, issuer := range issuers {
		keys := append([]jose.JSONWebKey(nil), issuer.JWKS.Keys...)
		sort.Slice(keys, func(i, j int) bool { return keys[i].KeyID < keys[j].KeyID })
		rawKeys := make([]json.RawMessage, 0, len(keys))
		for _, key := range keys {
			raw, err := json.Marshal(key)
			if err != nil {
				return "", err
			}
			rawKeys = append(rawKeys, raw)
		}
		canonical = append(canonical, canonicalIssuer{issuer.Issuer, issuer.Audience, rawKeys})
	}
	raw, err := json.Marshal(struct {
		Issuers []canonicalIssuer `json:"issuers"`
	}{canonical})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func newSoftwareStatementPolicy(config SoftwareStatementConfig) (*softwareStatementPolicy, error) {
	if len(config.Issuers) == 0 {
		return nil, nil
	}
	policy := &softwareStatementPolicy{issuers: make(map[string]SoftwareStatementIssuer, len(config.Issuers)), now: config.Now}
	if policy.now == nil {
		policy.now = time.Now
	}
	for _, entry := range config.Issuers {
		issuer, err := oidc.NormalizeIssuer(entry.Issuer)
		if err != nil || entry.Issuer != issuer || len(entry.JWKS.Keys) == 0 {
			return nil, errors.New("invalid software-statement issuer configuration")
		}
		if _, exists := policy.issuers[issuer]; exists {
			return nil, errors.New("duplicate software-statement issuer")
		}
		seen := make(map[string]struct{}, len(entry.JWKS.Keys))
		for _, key := range entry.JWKS.Keys {
			if key.KeyID == "" || key.Use != "sig" || !key.IsPublic() {
				return nil, errors.New("invalid software-statement signing key")
			}
			if _, exists := seen[key.KeyID]; exists {
				return nil, errors.New("duplicate software-statement signing key")
			}
			seen[key.KeyID] = struct{}{}
			switch key.Key.(type) {
			case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			default:
				return nil, errors.New("software-statement signing keys must be asymmetric")
			}
			if !allowedSoftwareStatementAlgorithm(key.Algorithm) {
				return nil, errors.New("unsupported software-statement signing algorithm")
			}
		}
		policy.issuers[issuer] = entry
	}
	return policy, nil
}

func allowedSoftwareStatementAlgorithm(value string) bool {
	switch jose.SignatureAlgorithm(value) {
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512, jose.EdDSA:
		return true
	default:
		return false
	}
}

type softwareStatementClaims struct {
	jwt.Claims
	SoftwareID              string    `json:"software_id,omitempty"`
	RedirectURIs            []string  `json:"redirect_uris,omitempty"`
	GrantTypes              []string  `json:"grant_types,omitempty"`
	ResponseTypes           []string  `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method,omitempty"`
	ClientName              string    `json:"client_name,omitempty"`
	ClientURI               *string   `json:"client_uri,omitempty"`
	LogoURI                 *string   `json:"logo_uri,omitempty"`
	TOSURI                  *string   `json:"tos_uri,omitempty"`
	PolicyURI               *string   `json:"policy_uri,omitempty"`
	Contacts                *[]string `json:"contacts,omitempty"`
	Audiences               *[]string `json:"audience,omitempty"`
	DPoPBoundAccessTokens   *bool     `json:"dpop_bound_access_tokens,omitempty"`
}

func (p *softwareStatementPolicy) merge(raw string, request registrationRequest) (registrationRequest, string, error) {
	if p == nil {
		return request, "", errUnapprovedSoftwareStatement
	}
	if len(raw) == 0 || len(raw) > maxSoftwareStatementLength || strings.Count(raw, ".") != 2 {
		return request, "", errInvalidSoftwareStatement
	}
	parts := strings.Split(raw, ".")
	for _, part := range parts {
		if part == "" {
			return request, "", errInvalidSoftwareStatement
		}
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || rejectDuplicateObjectFields(headerBytes) != nil {
		return request, "", errInvalidSoftwareStatement
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || rejectDuplicateObjectFields(payloadBytes) != nil {
		return request, "", errInvalidSoftwareStatement
	}
	var unverified struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(payloadBytes, &unverified); err != nil || unverified.Issuer == "" {
		return request, "", errInvalidSoftwareStatement
	}
	entry, approved := p.issuers[unverified.Issuer]
	if !approved {
		// RFC 7591 exposes a distinct unapproved-software-statement error;
		// issuer membership is an operator-visible allow-list, so this is an
		// intentional public approval signal rather than key material leakage.
		return request, "", errUnapprovedSoftwareStatement
	}
	jws, err := jwt.ParseSigned(raw, softwareStatementAlgorithms(entry.JWKS))
	if err != nil || len(jws.Headers) != 1 {
		return request, "", errInvalidSoftwareStatement
	}
	header := jws.Headers[0]
	if header.KeyID == "" || !allowedSoftwareStatementAlgorithm(string(header.Algorithm)) {
		return request, "", errInvalidSoftwareStatement
	}
	keys := entry.JWKS.Key(header.KeyID)
	if len(keys) != 1 || keys[0].Algorithm != string(header.Algorithm) || !keys[0].IsPublic() {
		return request, "", errInvalidSoftwareStatement
	}
	var claims softwareStatementClaims
	if err := jws.Claims(keys[0].Key, &claims); err != nil || claims.Issuer != entry.Issuer {
		return request, "", errInvalidSoftwareStatement
	}
	if entry.Audience != "" {
		if !claims.Audience.Contains(entry.Audience) {
			return request, "", errInvalidSoftwareStatement
		}
	} else if len(claims.Audience) != 0 {
		// An audience claim is only meaningful when the deployment has
		// configured the recipient it is willing to accept.
		return request, "", errInvalidSoftwareStatement
	}
	if err := claims.Claims.ValidateWithLeeway(jwt.Expected{Issuer: entry.Issuer, Time: p.now().UTC()}, 30*time.Second); err != nil {
		return request, "", errInvalidSoftwareStatement
	}
	if err := validateStatementMetadata(payloadBytes); err != nil {
		return request, "", errInvalidSoftwareStatement
	}
	return mergeStatementClaims(request, claims, raw)
}

func softwareStatementAlgorithms(keys jose.JSONWebKeySet) []jose.SignatureAlgorithm {
	result := make([]jose.SignatureAlgorithm, 0, len(keys.Keys))
	for _, key := range keys.Keys {
		result = append(result, jose.SignatureAlgorithm(key.Algorithm))
	}
	return result
}

func mergeStatementClaims(request registrationRequest, claims softwareStatementClaims, raw string) (registrationRequest, string, error) {
	if claims.ClientURI != nil {
		request.ClientURI = claims.ClientURI
		request.clientURIPresent = true
	}
	if claims.LogoURI != nil {
		request.LogoURI = claims.LogoURI
		request.logoURIPresent = true
	}
	if claims.TOSURI != nil {
		request.TOSURI = claims.TOSURI
		request.tosURIPresent = true
	}
	if claims.PolicyURI != nil {
		request.PolicyURI = claims.PolicyURI
		request.policyURIPresent = true
	}
	if claims.Contacts != nil {
		request.Contacts = claims.Contacts
		request.contactsPresent = true
	}
	if claims.Audiences != nil {
		request.Audiences = claims.Audiences
		request.audiencePresent = true
	}
	if claims.DPoPBoundAccessTokens != nil {
		request.DPoPBoundAccessTokens = claims.DPoPBoundAccessTokens
		request.dpopBoundAccessTokensPresent = true
	}
	if claims.RedirectURIs != nil {
		request.RedirectURIs = claims.RedirectURIs
	}
	if claims.GrantTypes != nil {
		request.GrantTypes = claims.GrantTypes
	}
	if claims.ResponseTypes != nil {
		request.ResponseTypes = claims.ResponseTypes
	}
	if claims.TokenEndpointAuthMethod != "" {
		request.TokenEndpointAuthMethod = claims.TokenEndpointAuthMethod
	}
	if claims.ClientName != "" {
		request.ClientName = claims.ClientName
	}
	return request, raw, nil
}

func validateStatementMetadata(payload []byte) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		return err
	}
	for _, name := range []string{"redirect_uris", "grant_types", "response_types", "token_endpoint_auth_method", "client_name", "client_uri", "logo_uri", "tos_uri", "policy_uri", "contacts", "audience", "dpop_bound_access_tokens"} {
		if value, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("null software-statement metadata")
		}
	}
	if value, ok := fields["dpop_bound_access_tokens"]; ok {
		var flag bool
		if err := json.Unmarshal(value, &flag); err != nil {
			return errors.New("invalid software-statement metadata")
		}
	}
	for _, name := range []string{"token_endpoint_auth_method", "client_name"} {
		if value, ok := fields[name]; ok {
			var text string
			if err := json.Unmarshal(value, &text); err != nil || text == "" {
				return errors.New("invalid software-statement metadata")
			}
		}
	}
	return nil
}

func rejectDuplicateObjectFields(body []byte) error {
	// JWT headers and claims intentionally use RFC JSON's exact member-name
	// duplicate rule. They are signed by an already trusted key and are
	// decoded by go-jose; trust-file parsing above is stricter because the
	// standard encoding/json decoder accepts case-insensitive field aliases.
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return errors.New("JWT object required")
	}
	seen := map[string]struct{}{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errors.New("JWT member required")
		}
		if _, exists := seen[name]; exists {
			return errors.New("duplicate JWT member")
		}
		seen[name] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	if err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JWT values")
	}
	return nil
}

func rejectDuplicateJSONMembers(body []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := scanTrustJSONValue(decoder, trustJSONRoot); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("multiple JSON values")
	}
	return nil
}

type trustJSONShape uint8

const (
	trustJSONAny trustJSONShape = iota
	trustJSONRoot
	trustJSONIssuerList
	trustJSONIssuer
	trustJSONJWKS
	trustJSONKeyList
	trustJSONJWK
)

func scanTrustJSONValue(decoder *json.Decoder, shape trustJSONShape) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]string{}
		for decoder.More() {
			name, err := decoder.Token()
			if err != nil {
				return err
			}
			field, ok := name.(string)
			if !ok {
				return errors.New("invalid JSON object member")
			}
			folded := strings.ToLower(field)
			if previous, exists := seen[folded]; exists {
				return fmt.Errorf("duplicate JSON object member %q and %q", previous, field)
			}
			seen[folded] = field
			childShape, canonical := trustJSONFieldShape(shape, field)
			if !canonical {
				return errors.New("non-canonical JSON object member")
			}
			if err := scanTrustJSONValue(decoder, childShape); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		childShape := trustJSONArrayElementShape(shape)
		for decoder.More() {
			if err := scanTrustJSONValue(decoder, childShape); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	}
	return nil
}

func trustJSONFieldShape(shape trustJSONShape, field string) (trustJSONShape, bool) {
	switch shape {
	case trustJSONRoot:
		if field == "issuers" {
			return trustJSONIssuerList, true
		}
	case trustJSONIssuer:
		switch field {
		case "issuer", "audience":
			return trustJSONAny, true
		case "jwks":
			return trustJSONJWKS, true
		}
	case trustJSONJWKS:
		if field == "keys" {
			return trustJSONKeyList, true
		}
	case trustJSONJWK:
		switch field {
		case "use", "kty", "kid", "crv", "alg", "k", "x", "y", "n", "e", "d", "p", "q", "dp", "dq", "qi", "x5c", "x5u", "x5t", "x5t#S256":
			return trustJSONAny, true
		}
	case trustJSONAny:
		// The typed decoder below rejects unknown fields. Still recurse here so
		// malformed nested values cannot hide duplicate members.
		return trustJSONAny, true
	}
	return trustJSONAny, false
}

func trustJSONArrayElementShape(shape trustJSONShape) trustJSONShape {
	switch shape {
	case trustJSONIssuerList:
		return trustJSONIssuer
	case trustJSONKeyList:
		return trustJSONJWK
	default:
		return trustJSONAny
	}
}
