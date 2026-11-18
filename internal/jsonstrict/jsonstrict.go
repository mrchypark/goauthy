// Package jsonstrict provides strict JSON structural validation helpers.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// ErrDuplicateKey indicates a JSON object contained a repeated key.
var ErrDuplicateKey = errors.New("duplicate JSON object key")

// DecodeStrict validates that data contains a single JSON value without duplicate
// object keys or trailing tokens, then decodes it into target with
// DisallowUnknownFields enabled.
func DecodeStrict(data []byte, target any) error {
	if err := RejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// RejectDuplicateKeys verifies that data contains a single valid JSON value
// with no repeated object keys at any nesting depth and no trailing tokens.
func RejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
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
				return io.ErrUnexpectedEOF
			}
			if _, exists := seen[name]; exists {
				return ErrDuplicateKey
			}
			seen[name] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return io.ErrUnexpectedEOF
	}
}
