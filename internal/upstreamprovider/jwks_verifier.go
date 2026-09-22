package upstreamprovider

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	jwksCacheTTL = 5 * time.Minute
	jwksTimeout  = 10 * time.Second
	maxJWKSBytes = 64 << 10
)

// ErrIDTokenVerification intentionally gives callers no token, key, or
// upstream-response detail.
var ErrIDTokenVerification = errors.New("upstream provider: id token verification failed")

var allowedIDTokenAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
}

type jwksCacheEntry struct {
	keys        jose.JSONWebKeySet
	expires     time.Time
	missRefresh bool
}

type jwksFetch struct {
	done chan struct{}
	keys jose.JSONWebKeySet
	err  error
}

// defaultClient is shared by every verifier created without an explicit client
// so connection pools and TLS sessions are reused across verifiers instead of
// being rebuilt per dispatch.
var defaultClient = sync.OnceValue(func() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	return &http.Client{Transport: transport, Timeout: jwksTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
})

// JWKSVerifier verifies OIDC ID tokens using configured issuer JWKS endpoints.
type JWKSVerifier struct {
	jwksByIssuer map[string]string
	client       *http.Client
	now          func() time.Time
	mu           sync.Mutex
	entries      map[string]jwksCacheEntry
	fetching     map[string]*jwksFetch
}

// NewJWKSVerifier creates a verifier from provider configurations. Each
// configured issuer must have one unambiguous JWKS endpoint. Providers
// that do not use ID tokens (GitHub, OAuthUserInfo) are skipped.
func NewJWKSVerifier(configs map[string]Config, client *http.Client) (*JWKSVerifier, error) {
	if len(configs) == 0 {
		return nil, ErrInvalidConfig
	}
	v := &JWKSVerifier{jwksByIssuer: make(map[string]string, len(configs)), now: time.Now, entries: make(map[string]jwksCacheEntry), fetching: make(map[string]*jwksFetch)}
	for _, cfg := range configs {
		if cfg.Validate() != nil {
			return nil, ErrInvalidConfig
		}
		if cfg.NormalizedKind() == ProviderKindGitHub || cfg.NormalizedKind() == ProviderKindOAuthUserInfo {
			continue
		}
		if cfg.JWKSURI == "" {
			return nil, ErrInvalidConfig
		}
		if old, ok := v.jwksByIssuer[cfg.Issuer]; ok && old != cfg.JWKSURI {
			return nil, ErrInvalidConfig
		}
		v.jwksByIssuer[cfg.Issuer] = cfg.JWKSURI
	}
	if client == nil {
		v.client = defaultClient()
	} else {
		cloned := *client
		if cloned.Timeout == 0 || cloned.Timeout > jwksTimeout {
			cloned.Timeout = jwksTimeout
		}
		cloned.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		v.client = &cloned
	}
	return v, nil
}

// VerifyIDToken verifies a token before decoding its claims.
func (v *JWKSVerifier) VerifyIDToken(ctx context.Context, raw, issuer, audience string) (*IDTokenClaims, error) {
	if audience == "" {
		return nil, ErrIDTokenVerification
	}
	payload, err := v.verifyPayload(ctx, raw, issuer)
	if err != nil {
		return nil, err
	}
	claims, err := decodeIDTokenClaims(payload)
	if err != nil || claims.Issuer != issuer || !audienceContains(claims.Audience, audience) {
		return nil, ErrIDTokenVerification
	}
	return claims, nil
}

// verifyPayload only fetches keys from the configured issuer, never token headers.
func (v *JWKSVerifier) verifyPayload(ctx context.Context, raw, issuer string) ([]byte, error) {
	if v == nil || ctx == nil || raw == "" || issuer == "" {
		return nil, ErrIDTokenVerification
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	uri, ok := v.jwksByIssuer[issuer]
	if !ok {
		return nil, ErrIDTokenVerification
	}
	jws, err := jose.ParseSigned(raw, allowedIDTokenAlgorithms)
	if err != nil || len(jws.Signatures) != 1 {
		return nil, ErrIDTokenVerification
	}
	sig := jws.Signatures[0]
	if sig.Protected.KeyID == "" || sig.Protected.Algorithm == "" {
		return nil, ErrIDTokenVerification
	}

	keys, err := v.keys(ctx, issuer, uri, false)
	if err != nil {
		return nil, verificationError(ctx, err)
	}
	matching := compatibleKeys(keys, sig.Protected.KeyID, sig.Protected.Algorithm)
	if len(matching) == 0 { // A changed key set is the only verification failure that refreshes.
		keys, err = v.keys(ctx, issuer, uri, true)
		if err != nil {
			return nil, verificationError(ctx, err)
		}
		matching = compatibleKeys(keys, sig.Protected.KeyID, sig.Protected.Algorithm)
	}
	if len(matching) != 1 {
		return nil, ErrIDTokenVerification
	}
	payload, err := jws.Verify(matching[0].Key)
	if err != nil {
		return nil, ErrIDTokenVerification
	}
	return payload, nil
}

func verificationError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return ErrIDTokenVerification
}

func (v *JWKSVerifier) keys(ctx context.Context, issuer, uri string, force bool) (jose.JSONWebKeySet, error) {
	now := v.now()
	v.mu.Lock()
	if entry, ok := v.entries[issuer]; ok && now.Before(entry.expires) {
		if !force || entry.missRefresh {
			v.mu.Unlock()
			return entry.keys, nil
		}
		entry.missRefresh = true
		v.entries[issuer] = entry
	}
	if active := v.fetching[issuer]; active != nil {
		v.mu.Unlock()
		select {
		case <-active.done:
			return active.keys, active.err
		case <-ctx.Done():
			return jose.JSONWebKeySet{}, ctx.Err()
		}
	}
	active := &jwksFetch{done: make(chan struct{})}
	v.fetching[issuer] = active
	v.mu.Unlock()

	go func() {
		fetchCtx, cancel := context.WithTimeout(context.Background(), jwksTimeout)
		keys, err := v.fetch(fetchCtx, uri)
		cancel()
		v.mu.Lock()
		if err == nil {
			v.entries[issuer] = jwksCacheEntry{keys: keys, expires: v.now().Add(jwksCacheTTL), missRefresh: force}
		}
		active.keys, active.err = keys, err
		delete(v.fetching, issuer)
		close(active.done)
		v.mu.Unlock()
	}()
	select {
	case <-active.done:
		return active.keys, active.err
	case <-ctx.Done():
		return jose.JSONWebKeySet{}, ctx.Err()
	}
}

func (v *JWKSVerifier) fetch(ctx context.Context, uri string) (jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return jose.JSONWebKeySet{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > maxJWKSBytes {
		return jose.JSONWebKeySet{}, errors.New("invalid jwks response")
	}
	contentType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || (contentType != "application/json" && contentType != "application/jwk-set+json") {
		return jose.JSONWebKeySet{}, errors.New("invalid jwks content type")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil || len(body) > maxJWKSBytes {
		return jose.JSONWebKeySet{}, errors.New("invalid jwks body")
	}
	var keys jose.JSONWebKeySet
	if json.Unmarshal(body, &keys) != nil {
		return jose.JSONWebKeySet{}, errors.New("invalid jwks")
	}
	return keys, nil
}

func compatibleKeys(keys jose.JSONWebKeySet, kid, algorithm string) []jose.JSONWebKey {
	matched := make([]jose.JSONWebKey, 0, 1)
	for _, key := range keys.Key(kid) {
		if (key.Algorithm == "" || key.Algorithm == algorithm) && (key.Use == "" || key.Use == "sig") && publicKeyForAlgorithm(key.Key, algorithm) {
			matched = append(matched, key)
		}
	}
	return matched
}

func publicKeyForAlgorithm(key interface{}, algorithm string) bool {
	switch key := key.(type) {
	case *rsa.PublicKey:
		return key.N != nil && key.N.Sign() > 0 && key.E >= 2 && (algorithm[0:2] == "RS" || algorithm[0:2] == "PS")
	case *ecdsa.PublicKey:
		return key.Curve != nil && key.X != nil && key.Y != nil && key.Curve.IsOnCurve(key.X, key.Y) && ((algorithm == "ES256" && key.Curve.Params().Name == "P-256") || (algorithm == "ES384" && key.Curve.Params().Name == "P-384") || (algorithm == "ES512" && key.Curve.Params().Name == "P-521"))
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize && algorithm == "EdDSA"
	default:
		return false
	}
}

func decodeIDTokenClaims(payload []byte) (*IDTokenClaims, error) {
	var raw struct {
		Issuer             string          `json:"iss"`
		Subject            string          `json:"sub"`
		SessionID          string          `json:"sid"`
		Audience           json.RawMessage `json:"aud"`
		Azp                string          `json:"azp"`
		Nonce              string          `json:"nonce"`
		ExpiresAt          int64           `json:"exp"`
		IssuedAt           int64           `json:"iat"`
		AuthenticationTime json.RawMessage `json:"auth_time"`
		NotBefore          int64           `json:"nbf"`
		Email              *string         `json:"email"`
		EmailVerified      *bool           `json:"email_verified"`
		GivenName          *string         `json:"given_name"`
		FamilyName         *string         `json:"family_name"`
	}
	if err := json.Unmarshal(payload, &raw); err != nil {
		return nil, err
	}
	authenticationTime, err := authenticationTimeSeconds(raw.AuthenticationTime)
	if err != nil {
		return nil, err
	}

	var audience []string
	if json.Unmarshal(raw.Audience, &audience) != nil {
		var one string
		if err := json.Unmarshal(raw.Audience, &one); err != nil {
			return nil, err
		}
		audience = []string{one}
	}
	// Copy the verified payload bytes so the caller cannot mutate the
	// original decoder input and the raw claims survive for downstream
	// JSONPath claim mapping.
	rawClaims := make([]byte, len(payload))
	copy(rawClaims, payload)
	return &IDTokenClaims{
		Issuer: raw.Issuer, Subject: raw.Subject, SessionID: raw.SessionID,
		Audience: audience, Azp: raw.Azp, Nonce: raw.Nonce,
		ExpiresAt: raw.ExpiresAt, IssuedAt: raw.IssuedAt, NotBefore: raw.NotBefore, AuthenticationTime: authenticationTime,
		Email: raw.Email, EmailVerified: raw.EmailVerified,
		GivenName: raw.GivenName, FamilyName: raw.FamilyName,
		rawClaims: rawClaims,
	}, nil
}

// authenticationTimeSeconds normalizes the already JSON-validated NumericDate
// exactly. Bounds prevent compact extreme exponents from allocating large powers.
func authenticationTimeSeconds(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, nil
	}
	if len(raw) > 1024 {
		return 0, ErrIDTokenVerification
	}
	number := string(raw)
	if i := strings.IndexAny(number, "eE"); i >= 0 {
		exponent, err := strconv.ParseInt(number[i+1:], 10, 32)
		if err != nil || exponent < -1024 || exponent > 1024 {
			return 0, ErrIDTokenVerification
		}
	}
	value, ok := new(big.Rat).SetString(number)
	if !ok {
		return 0, ErrIDTokenVerification
	}
	seconds := new(big.Int).Div(value.Num(), value.Denom())
	if !seconds.IsInt64() {
		return 0, ErrIDTokenVerification
	}
	return seconds.Int64(), nil
}
