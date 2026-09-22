package passkey

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	wa "github.com/go-webauthn/webauthn/webauthn"
)

func TestStrictPasskeyJSONRejectsDuplicateUnknownAndTrailingValues(t *testing.T) {
	t.Parallel()
	good, err := json.Marshal(wa.Credential{ID: []byte("credential"), PublicKey: []byte("public-key")})
	if err != nil {
		t.Fatal(err)
	}
	var credential wa.Credential
	if err := decodeCredentialJSON(good, &credential); err != nil {
		t.Fatalf("compatible credential rejected: %v", err)
	}
	if err := decodeCredentialJSON([]byte(`{"id":"YQ","id":"Yg","publicKey":"cGs"}`), &credential); err == nil {
		t.Fatal("duplicate credential field accepted")
	}
	if err := decodeCredentialJSON([]byte(`{"id":"YQ","publicKey":"cGs","unknown":true}`), &credential); err == nil {
		t.Fatal("unknown credential field accepted")
	}
	if err := decodeCredentialJSON(append(good, []byte(`{"trailing":true}`)...), &credential); err == nil {
		t.Fatal("trailing credential value accepted")
	}

	challenge := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'c'}, 32))
	var state sealedState
	if err := decodeSealedStateJSON([]byte(`{"session":{"challenge":"`+challenge+`"}}`), &state); err != nil {
		t.Fatalf("compatible ceremony rejected: %v", err)
	}
	if err := decodeSealedStateJSON([]byte(`{"session":{"challenge":"`+challenge+`","challenge":"other"}}`), &state); err == nil {
		t.Fatal("duplicate session field accepted")
	}
	if err := decodeSealedStateJSON([]byte(`{"session":{"challenge":"`+challenge+`"},"unknown":true}`), &state); err == nil {
		t.Fatal("unknown ceremony field accepted")
	}
}
