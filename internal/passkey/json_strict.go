package passkey

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

// decodeStrictJSON rejects duplicate keys, unknown struct fields, and any
// trailing JSON value. The duplicate-key pass is needed because the standard
// decoder otherwise keeps the last duplicate silently.
func decodeStrictJSON(data []byte, target any) error {
	if err := rejectDuplicateJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}

func rejectDuplicateJSON(data []byte) error {
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
				return io.ErrUnexpectedEOF
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

// credentialJSON is an alias so strict decoding does not invoke
// webauthn.Credential.UnmarshalJSON, whose compatibility decoder is
// intentionally permissive. The one historical attestation migration it
// performs is retained below.
type credentialJSON wa.Credential

func decodeCredentialJSON(data []byte, credential *wa.Credential) error {
	var value credentialJSON
	if err := decodeStrictJSON(data, &value); err != nil {
		return err
	}
	*credential = wa.Credential(value)
	if credential.AttestationFormat == "" && protocol.IsAttestationFormatString(credential.AttestationType) {
		credential.AttestationFormat = credential.AttestationType
		credential.AttestationType = ""
	}
	if len(credential.ID) == 0 || len(credential.PublicKey) == 0 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func decodeSealedStateJSON(data []byte, state *sealedState) error {
	if err := decodeStrictJSON(data, state); err != nil {
		return err
	}
	if !validSessionData(state.Session) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func decodeModificationSealedStateJSON(data []byte, state *modificationSealedState) error {
	if err := decodeStrictJSON(data, state); err != nil {
		return err
	}
	if !validSessionData(state.Session) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func validSessionData(state wa.SessionData) bool {
	challenge, err := base64.RawURLEncoding.DecodeString(state.Challenge)
	return err == nil && len(challenge) == 32 && base64.RawURLEncoding.EncodeToString(challenge) == state.Challenge
}
