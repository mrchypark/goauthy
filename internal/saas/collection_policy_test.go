package saas

import (
	"context"
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestCredentialCollectionProviderRemovalCannotResurrect(t *testing.T) {
	t.Parallel()
	ctx, store, db, binding := credentialStoreFixture(t)
	wrong := binding
	wrong.ProviderID = "unapproved"
	if err := store.Install(ctx, wrong, testCredential(), credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("unapproved provider install=%v", err)
	}
	if err := store.Install(ctx, binding, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	_, err := store.refreshCredential(ctx, binding, credentialAuthority(), func(context.Context, credential) (credential, error) {
		if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "remove-provider", SQL: `UPDATE auth_collection_definitions SET providers_json='[]' WHERE id=?`, Args: []any{binding.CollectionID}}); err != nil {
			t.Fatal(err)
		}
		return credential{AccessToken: "must-not-commit"}, nil
	})
	if !errors.Is(err, errRefreshUncertain) {
		t.Fatalf("removed provider refresh=%v", err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "readd-provider", SQL: `UPDATE auth_collection_definitions SET providers_json='["provider"]' WHERE id=?`, Args: []any{binding.CollectionID}}); err != nil {
		t.Fatal(err)
	}
	for _, version := range []int64{1, 2} {
		binding.TokenVersion = version
		if _, err := store.Load(ctx, binding, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
			t.Fatalf("version %d resurrected: %v", version, err)
		}
	}
}
