// Package dpop validates RFC 9449 DPoP proofs at an HTTP boundary.
package dpop

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-jose/go-jose/v4"
)

const MaxProofSize = 8 << 10

var (
	ErrInvalidProof = errors.New("invalid DPoP proof")
	ErrUseNonce     = errors.New("DPoP nonce required or invalid")
)

// Options supplies server-controlled request context. Issuer, not request Host
// or forwarding headers, is used to construct the expected htu.
type Options struct {
	Issuer      string
	Now         time.Time
	MaxAge      time.Duration
	FutureSkew  time.Duration
	Nonce       string // non-empty requires an exactly matching nonce claim
	AccessToken string // non-empty requires a matching ath claim
}

type Proof struct {
	JKT      string
	JTI      string
	Nonce    string
	IssuedAt time.Time
	Key      jose.JSONWebKey
}

type header struct {
	Typ string          `json:"typ"`
	Alg string          `json:"alg"`
	JWK json.RawMessage `json:"jwk"`
}
type claims struct {
	JTI   string `json:"jti"`
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	Nonce string `json:"nonce,omitempty"`
	ATH   string `json:"ath,omitempty"`
}

// Validate validates one already-selected DPoP header value. Callers must
// reject duplicate HTTP DPoP fields before calling it.
func Validate(raw string, r *http.Request, options Options) (Proof, error) {
	if r == nil || len(raw) == 0 || len(raw) > MaxProofSize || strings.Count(raw, ".") != 2 {
		return Proof{}, ErrInvalidProof
	}
	issuer, err := issuerURL(options.Issuer)
	if err != nil {
		return Proof{}, fmt.Errorf("%w: issuer", ErrInvalidProof)
	}
	parts := strings.Split(raw, ".")
	headerJSON, err := decodeSegment(parts[0])
	if err != nil || hasDuplicateJSONKeys(headerJSON) {
		return Proof{}, ErrInvalidProof
	}
	var h header
	if json.Unmarshal(headerJSON, &h) != nil || h.Typ != "dpop+jwt" || !allowedAlgorithm(h.Alg) || len(h.JWK) == 0 || hasDuplicateJSONKeys(h.JWK) || privateJWK(h.JWK) {
		return Proof{}, ErrInvalidProof
	}
	var key jose.JSONWebKey
	if json.Unmarshal(h.JWK, &key) != nil || !key.Valid() || !key.IsPublic() || !asymmetricKey(key.Key) {
		return Proof{}, ErrInvalidProof
	}
	payload, err := decodeSegment(parts[1])
	if err != nil || hasDuplicateJSONKeys(payload) {
		return Proof{}, ErrInvalidProof
	}
	var c claims
	if json.Unmarshal(payload, &c) != nil || !validJTI(c.JTI) || c.HTM != r.Method {
		return Proof{}, ErrInvalidProof
	}
	expected, err := expectedHTU(issuer, r.URL.Path)
	if err != nil || canonicalHTU(c.HTU) != expected {
		return Proof{}, ErrInvalidProof
	}
	now := options.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	maxAge := options.MaxAge
	if maxAge == 0 {
		maxAge = time.Minute
	}
	future := options.FutureSkew
	issued := time.Unix(c.IAT, 0).UTC()
	if maxAge <= 0 || future < 0 || issued.Before(now.Add(-maxAge)) || issued.After(now.Add(future)) {
		return Proof{}, ErrInvalidProof
	}
	if options.Nonce != "" && subtle.ConstantTimeCompare([]byte(c.Nonce), []byte(options.Nonce)) != 1 {
		return Proof{}, ErrUseNonce
	}
	if options.AccessToken != "" && !validATH(c.ATH, options.AccessToken) {
		return Proof{}, ErrInvalidProof
	}
	jws, err := jose.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.ES512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.EdDSA})
	if err != nil || len(jws.Signatures) != 1 {
		return Proof{}, ErrInvalidProof
	}
	verified, err := jws.Verify(key)
	if err != nil || !bytes.Equal(verified, payload) {
		return Proof{}, ErrInvalidProof
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return Proof{}, ErrInvalidProof
	}
	return Proof{JKT: base64.RawURLEncoding.EncodeToString(thumbprint), JTI: c.JTI, Nonce: c.Nonce, IssuedAt: issued, Key: key.Public()}, nil
}

func decodeSegment(value string) ([]byte, error) {
	if value == "" || strings.ContainsAny(value, "= \t\r\n") {
		return nil, errors.New("bad segment")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("bad segment")
	}
	return decoded, nil
}
func allowedAlgorithm(a string) bool {
	switch jose.SignatureAlgorithm(a) {
	case jose.ES256, jose.ES384, jose.ES512, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.EdDSA:
		return true
	}
	return false
}
func asymmetricKey(key any) bool {
	switch key.(type) {
	case []byte:
		return false
	}
	return true
}
func privateJWK(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return true
	}
	for _, name := range []string{"d", "k", "p", "q", "dp", "dq", "qi", "oth"} {
		if _, ok := fields[name]; ok {
			return true
		}
	}
	return false
}
func validJTI(value string) bool {
	if !utf8.ValidString(value) || len(value) < 16 || len(value) > 256 {
		return false
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
func validATH(ath, accessToken string) bool {
	sum := sha256.Sum256([]byte(accessToken))
	expected := base64.RawURLEncoding.EncodeToString(sum[:])
	return ath != "" && subtle.ConstantTimeCompare([]byte(ath), []byte(expected)) == 1
}
func issuerURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, errors.New("issuer")
	}
	return u, nil
}
func expectedHTU(issuer *url.URL, path string) (string, error) {
	if path == "" || !strings.HasPrefix(path, "/") {
		return "", errors.New("path")
	}
	u := *issuer
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return canonicalHTU(u.String()), nil
}
func canonicalHTU(value string) string {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.RawPath = ""
	return u.String()
}

// hasDuplicateJSONKeys rejects duplicate keys at every JSON object depth.
func hasDuplicateJSONKeys(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	if duplicateJSONValue(d) != nil {
		return true
	}
	return d.Decode(new(any)) != io.EOF
}
func duplicateJSONValue(d *json.Decoder) error {
	token, err := d.Token()
	if err != nil {
		return err
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			seen := map[string]struct{}{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := k.(string)
				if !ok {
					return errors.New("key")
				}
				if _, ok = seen[key]; ok {
					return errors.New("duplicate")
				}
				seen[key] = struct{}{}
				if e = duplicateJSONValue(d); e != nil {
					return e
				}
			}
			_, err = d.Token()
			return err
		case '[':
			for d.More() {
				if err = duplicateJSONValue(d); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
	}
	return nil
}
