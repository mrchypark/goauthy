package saas

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/mrchypark/goauthy/internal/oidc"
)

func credentialKeys(t *testing.T, active string, ids ...string) *oidc.Keyring {
	t.Helper()
	dir := t.TempDir()
	for _, id := range ids {
		key := bytes.Repeat([]byte{id[len(id)-1]}, 32)
		if err := os.WriteFile(filepath.Join(dir, id), []byte(base64.RawURLEncoding.EncodeToString(key)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	keys, err := oidc.LoadKeyring(dir, active)
	if err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestCredentialEnvelopeBindsIdentityAndTokenVersion(t *testing.T) {
	keys := credentialKeys(t, "key-a", "key-a")
	binding := credentialBinding{"owner", "collection", "connection", "provider", "generation", 1}
	value := credential{AccessToken: "private-access", RefreshToken: "private-refresh", ExpiresAtUnixMS: 1700000000000, Scopes: []string{"read"}}
	envelope, err := sealCredential(keys, binding, value)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(envelope, []byte(value.AccessToken)) || bytes.Contains(envelope, []byte(value.RefreshToken)) {
		t.Fatal("plaintext token in envelope")
	}
	opened, err := openCredential(keys, binding, envelope)
	if err != nil || !reflect.DeepEqual(opened, value) {
		t.Fatalf("round trip error=%v", err)
	}
	for _, change := range []func(*credentialBinding){
		func(b *credentialBinding) { b.Owner = "other" }, func(b *credentialBinding) { b.CollectionID = "other" },
		func(b *credentialBinding) { b.ConnectionID = "other" }, func(b *credentialBinding) { b.ProviderID = "other" },
		func(b *credentialBinding) { b.Generation = "other" }, func(b *credentialBinding) { b.TokenVersion++ },
	} {
		other := binding
		change(&other)
		if _, err := openCredential(keys, other, envelope); err == nil {
			t.Fatal("wrong binding accepted")
		}
	}
	if strings.Contains(fmt.Sprintf("%v %#v", value, value), "private-") {
		t.Fatal("credential debug output leaked")
	}
	envelope[len(envelope)-1] ^= 1
	if _, err := openCredential(keys, binding, envelope); err == nil {
		t.Fatal("modified envelope accepted")
	}
}

func TestCredentialEnvelopeReusesMasterKeyRotation(t *testing.T) {
	binding := credentialBinding{"owner", "collection", "connection", "provider", "generation", 1}
	value := credential{AccessToken: "access"}
	old := credentialKeys(t, "key-a", "key-a")
	envelope, err := sealCredential(old, binding, value)
	if err != nil {
		t.Fatal(err)
	}
	rotated := credentialKeys(t, "key-b", "key-a", "key-b")
	purpose, err := credentialPurpose(binding)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := rotated.PurposeEnvelopeKeyID(purpose, envelope)
	if err != nil || keyID != "key-a" {
		t.Fatalf("old key reference=%s error=%v", keyID, err)
	}
	updated, err := rotated.RewrapEnvelope(purpose, envelope)
	if err != nil {
		t.Fatal(err)
	}
	newOnly := credentialKeys(t, "key-b", "key-b")
	if _, err := openCredential(newOnly, binding, envelope); err == nil {
		t.Fatal("removed key still usable")
	}
	opened, err := openCredential(newOnly, binding, updated)
	if err != nil || !reflect.DeepEqual(opened, value) {
		t.Fatalf("rewrapped credential error=%v", err)
	}
	if _, err := sealCredential(nil, binding, value); err == nil {
		t.Fatal("nil keyring accepted")
	}
}
