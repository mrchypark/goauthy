package saas

import "testing"

func TestProviderSecretPurposeBindsIDAndGeneration(t *testing.T) {
	a := providerSecretPurpose("github", "generation-a")
	if a == providerSecretPurpose("github", "generation-b") || a == providerSecretPurpose("other", "generation-a") {
		t.Fatal("provider secret purpose is not bound")
	}
	if len(a) == 0 {
		t.Fatal("empty provider secret purpose")
	}
}

func TestProviderEnvelopeInspectionAndRewrap(t *testing.T) {
	ctx, credentials, db, _ := credentialStoreFixture(t)
	store, err := NewProviderStore(db, credentials.keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, providerInputForTest("0123456789012345"), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	family, err := InspectProviderEnvelopeReferences(ctx, db, credentials.keys)
	if err != nil || family.Total != 1 {
		t.Fatalf("family=%+v err=%v", family, err)
	}
	result, err := RewrapProviderEnvelopeBatch(ctx, db, credentials.keys, "")
	if err != nil || result.Rewrapped != 0 || !result.Done {
		t.Fatalf("rewrap=%+v err=%v", result, err)
	}
	if _, err := store.LoadOAuth2(ctx, "github", credentialAuthority()); err != nil {
		t.Fatal(err)
	}
}

func TestProviderEnvelopeTwoRotationsAndAPIKeyHasNoSecret(t *testing.T) {
	ctx, _, db, _ := credentialStoreFixture(t)
	keys := credentialKeys(t, "key-a", "key-a", "key-b", "key-c")
	store, err := NewProviderStore(db, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(ctx, providerInputForTest("rotation-test-secret"), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	api := ProviderInput{ID: "billing", Name: "Billing", Kind: "api_key", Enabled: true, Connector: &APIKeyConnectorConfig{ID: "billing", Header: "X-API-Key", Operations: []APIKeyOperationConfig{{ID: "account", URL: "https://api.example/account", ResponseFields: map[string]string{"id": "string"}}}}}
	if _, err := store.Create(ctx, api, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	for _, active := range []string{"key-b", "key-c"} {
		rotated := credentialKeys(t, active, "key-a", "key-b", "key-c")
		result, err := RewrapProviderEnvelopeBatch(ctx, db, rotated, "")
		if err != nil || result.Rewrapped != 1 {
			t.Fatalf("%s result=%+v err=%v", active, result, err)
		}
		family, err := InspectProviderEnvelopeReferences(ctx, db, rotated)
		if err != nil || family.Total != 1 || family.ByKeyID[active] != 1 {
			t.Fatalf("%s family=%+v err=%v", active, family, err)
		}
		reader, err := NewProviderStore(db, rotated)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := reader.LoadOAuth2(ctx, "github", credentialAuthority()); err != nil {
			t.Fatal(err)
		}
	}
}
