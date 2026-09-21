package oidc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	maxCustomClaimCount = 32
	maxCustomClaimKey   = 64
	maxCustomClaimBytes = 8 << 10
	maxCustomJSONDepth  = 8
	maxCustomJSONNodes  = 256
)

// CustomClaims holds JSON-valued, application-defined ID token claims. Values
// and AtRoot are retained for single-form callers. New callers can set Nested
// and Root independently; both are emitted when non-empty.
type CustomClaims struct {
	Values map[string]json.RawMessage
	AtRoot bool
	Nested map[string]json.RawMessage
	Root   map[string]json.RawMessage
}

var reservedIDTokenClaimNames = map[string]struct{}{
	"iss": {}, "sub": {}, "aud": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {},
	"nonce": {}, "auth_time": {}, "azp": {}, "sid": {}, "at_hash": {}, "amr": {},
	"acr": {}, "roles": {}, "groups": {}, "custom": {}, "cnf": {}, "typ": {}, "scope": {},
	"did": {}, "act": {}, "allowed_origins": {}, "webid": {}, "email": {}, "email_verified": {},
	"preferred_username": {}, "given_name": {}, "family_name": {}, "birthdate": {}, "address": {},
	"phone_number": {}, "phone_number_verified": {}, "zoneinfo": {}, "locale": {},
}

// NormalizeCustomClaims validates, copies, and canonicalizes custom JSON
// claims. Callers can use it before placing the same claims in UserInfo.
func NormalizeCustomClaims(in CustomClaims) (CustomClaims, error) {
	return normalizedCustomClaims(in)
}

func normalizedCustomClaims(in CustomClaims) (CustomClaims, error) {
	if in.Values != nil && (in.Nested != nil || in.Root != nil) {
		return CustomClaims{}, fmt.Errorf("%w: ambiguous custom claim representation", errInvalidIDToken)
	}
	if in.Values != nil || in.AtRoot {
		if len(in.Values) == 0 {
			if in.AtRoot {
				return CustomClaims{}, fmt.Errorf("%w: empty root custom claims", errInvalidIDToken)
			}
			return CustomClaims{}, nil
		}
		values, err := normalizeCustomClaimSet(in.Values, in.AtRoot, nil, new(int), new(int))
		if err != nil {
			return CustomClaims{}, err
		}
		return CustomClaims{Values: values, AtRoot: in.AtRoot}, nil
	}
	if len(in.Nested)+len(in.Root) == 0 {
		return CustomClaims{}, nil
	}
	count, total := new(int), new(int)
	nested, err := normalizeCustomClaimSet(in.Nested, false, nil, count, total)
	if err != nil {
		return CustomClaims{}, err
	}
	root, err := normalizeCustomClaimSet(in.Root, true, nil, count, total)
	if err != nil {
		return CustomClaims{}, err
	}
	return CustomClaims{Nested: nested, Root: root}, nil
}

func normalizeCustomClaimSet(values map[string]json.RawMessage, atRoot bool, seen map[string]struct{}, count, total *int) (map[string]json.RawMessage, error) {
	if len(values) == 0 {
		return nil, nil
	}
	if seen == nil {
		seen = make(map[string]struct{}, len(values))
	}
	out := make(map[string]json.RawMessage, len(values))
	for name, raw := range values {
		if !validCustomClaimName(name) {
			return nil, fmt.Errorf("%w: invalid custom claim name", errInvalidIDToken)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, fmt.Errorf("%w: duplicate custom claim name", errInvalidIDToken)
		}
		seen[name] = struct{}{}
		if atRoot {
			if _, reserved := reservedIDTokenClaimNames[name]; reserved {
				return nil, fmt.Errorf("%w: custom claim collides with reserved claim", errInvalidIDToken)
			}
		}
		canonical, err := canonicalJSON(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid custom claim %q", errInvalidIDToken, name)
		}
		*count++
		*total += len(name) + len(canonical)
		if *count > maxCustomClaimCount || *total > maxCustomClaimBytes {
			return nil, fmt.Errorf("%w: custom claims exceed limit", errInvalidIDToken)
		}
		out[name] = canonical
	}
	return out, nil
}

func validCustomClaimName(name string) bool {
	if len(name) == 0 || len(name) > maxCustomClaimKey || !utf8.ValidString(name) {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func canonicalJSON(raw []byte) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxCustomClaimBytes {
		return nil, fmt.Errorf("invalid JSON size")
	}
	if err := validateJSON(raw, maxCustomJSONDepth, maxCustomJSONNodes); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, err
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(canonical), nil
}

func validateJSON(raw []byte, maxDepth, maxNodes int) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	if err := validateJSONValue(decoder, 0, maxDepth, maxNodes, &nodes); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

func validateJSONValue(decoder *json.Decoder, depth, maxDepth, maxNodes int, nodes *int) error {
	if depth > maxDepth {
		return fmt.Errorf("JSON exceeds depth limit")
	}
	*nodes++
	if *nodes > maxNodes {
		return fmt.Errorf("JSON exceeds node limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return fmt.Errorf("invalid object key")
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("duplicate object key")
			}
			seen[name] = struct{}{}
			if err := validateJSONValue(decoder, depth+1, maxDepth, maxNodes, nodes); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder, depth+1, maxDepth, maxNodes, nodes); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("invalid JSON delimiter")
	}
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}
