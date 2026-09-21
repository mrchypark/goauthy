package saas

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestProviderValidationSeparatesKinds(t *testing.T) {
	t.Parallel()
	oauth := ProviderInput{ID: "github", Name: "GitHub", Kind: "oauth2", ClientID: "client", ClientSecret: "0123456789012345", CallbackURI: "https://auth.example/callback", AuthorizationURL: "https://github.example/authorize", TokenURL: "https://github.example/token", Scopes: []string{"read:user"}, AuthStyle: "header"}
	if _, err := validateProviderInput(oauth, true); err != nil {
		t.Fatal(err)
	}
	bad := oauth
	bad.Connector = &APIKeyConnectorConfig{ID: "github"}
	if _, err := validateProviderInput(bad, true); err == nil {
		t.Fatal("oauth connector accepted")
	}
	connector := APIKeyConnectorConfig{ID: "billing", Header: "Authorization", Prefix: "Bearer ", Operations: []APIKeyOperationConfig{{ID: "account", URL: "https://api.example/account", ResponseFields: map[string]string{"id": "string"}}}}
	api := ProviderInput{ID: "billing", Name: "Billing", Kind: "api_key", Connector: &connector}
	if _, err := validateProviderInput(api, true); err != nil {
		t.Fatal(err)
	}
	bad = api
	bad.ClientID = "unexpected"
	if _, err := validateProviderInput(bad, true); err == nil {
		t.Fatal("api-key oauth fields accepted")
	}
}

func providerInputForTest(secret string) ProviderInput {
	return ProviderInput{ID: "github", Name: "GitHub", Kind: "oauth2", Enabled: true, ClientID: "client", ClientSecret: secret, CallbackURI: "https://auth.example/callback", AuthorizationURL: "https://github.example/authorize", TokenURL: "https://github.example/token", Scopes: []string{"read:user"}, AuthStyle: "header"}
}

func TestProviderStoreCRUDRetentionCASAndReferenceGuard(t *testing.T) {
	t.Parallel()
	ctx, credentials, db, _ := credentialStoreFixture(t)
	store, err := NewProviderStore(db, credentials.keys)
	if err != nil {
		t.Fatal(err)
	}
	denied := func() (string, []any) { return "0", nil }
	if _, err := store.List(ctx, denied); !errors.Is(err, ErrProviderUnauthorized) {
		t.Fatalf("empty catalog denied authority=%v", err)
	}
	p, err := store.Create(ctx, providerInputForTest("0123456789012345"), credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if p.Revision != 1 || p.ID != "github" {
		t.Fatalf("created=%+v", p)
	}
	if _, err := store.List(ctx, denied); !errors.Is(err, ErrProviderUnauthorized) {
		t.Fatalf("nonempty catalog denied authority=%v", err)
	}
	inIdentity := providerInputForTest("")
	inIdentity.IdentityEndpoint, inIdentity.SubjectField = "https://github.example/user", "sub"
	inIdentity.ClientSecret = "0123456789012345"
	if _, err := store.Update(ctx, "github", p.Revision, inIdentity, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	p, err = store.Get(ctx, "github", credentialAuthority())
	if err != nil || p.IdentityEndpoint != inIdentity.IdentityEndpoint || p.SubjectField != inIdentity.SubjectField {
		t.Fatalf("identity persistence=%+v err=%v", p, err)
	}
	loaded, err := store.LoadOAuth2(ctx, "github", credentialAuthority())
	if err != nil || loaded.identityEndpoint != inIdentity.IdentityEndpoint || loaded.subjectField != inIdentity.SubjectField {
		t.Fatalf("loaded identity configuration mismatch: %v", err)
	}
	in := providerInputForTest("")
	in.IdentityEndpoint, in.SubjectField = inIdentity.IdentityEndpoint, inIdentity.SubjectField
	in.Name = "GitHub 2"
	p, err = store.Update(ctx, "github", 2, in, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if p.Revision != 3 {
		t.Fatalf("updated=%+v", p)
	}
	if _, err := store.LoadOAuth2(ctx, "github", credentialAuthority()); err != nil {
		t.Fatal("retained secret:", err)
	}
	in.Name = "GitHub 3"
	in.ClientSecret = "abcdefghijklmnop"
	p, err = store.Update(ctx, "github", 3, in, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if p.Revision != 4 {
		t.Fatalf("rotated=%+v", p)
	}
	if _, err := store.Update(ctx, "github", 3, in, credentialAuthority()); !errors.Is(err, ErrProviderConflict) {
		t.Fatalf("stale=%v", err)
	}
	if _, err := store.Update(ctx, "github", 4, in, nil); !errors.Is(err, ErrProviderUnauthorized) {
		t.Fatalf("nil authority=%v", err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "provider-ref", SQL: `INSERT INTO auth_collection_definitions(id,name,auth_method,enabled,revision,generation,fields_json,providers_json) VALUES(?,?,?,?,?,?,?,?)`, Args: []any{"collection-ref", "Ref", "oauth2", int64(1), int64(1), "ref-generation", "[]", `["github"]`}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "github", 4, credentialAuthority()); !errors.Is(err, ErrProviderConflict) {
		t.Fatalf("referenced delete=%v", err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "provider-unref", SQL: `UPDATE auth_collection_definitions SET deleted=1,providers_json='[]' WHERE id=?`, Args: []any{"collection-ref"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, "github", 4, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "github", credentialAuthority()); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("tombstone get=%v", err)
	}
	if _, err := store.Create(ctx, providerInputForTest("0123456789012345"), credentialAuthority()); !errors.Is(err, ErrProviderConflict) {
		t.Fatalf("id reuse=%v", err)
	}
}
