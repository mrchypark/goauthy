package saas

import "testing"

func TestOAuth2ProviderRechecksAuthorityAtUse(t *testing.T) {
	t.Parallel()
	ctx, credentials, db, _ := credentialStoreFixture(t)
	providers, err := NewProviderStore(db, credentials.keys)
	if err != nil {
		t.Fatal(err)
	}
	in := providerInputForTest("test-secret")
	in.IdentityEndpoint, in.SubjectField = "https://provider.example/me", "id"
	if _, err := providers.Create(ctx, in, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	witness := int64(1)
	p, guard, err := oauth2Provider(ctx, providers, in.ID, in.CallbackURI, func() (string, []any) { return "?=1", []any{witness} })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := providers.Get(ctx, p.ID, guard); err != nil {
		t.Fatal(err)
	}
	witness = 0
	if _, err := providers.Get(ctx, p.ID, guard); err == nil {
		t.Fatal("cached authority survived its revocation")
	}
}
