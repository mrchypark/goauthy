package saas

import (
	"errors"
	"testing"

	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
)

func TestAuthorizationCompletionRequiresConsumedCurrentConsent(t *testing.T) {
	for _, invalidated := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "removed-and-readded"}[invalidated], func(t *testing.T) {
			ctx, store, db, binding := credentialStoreFixture(t)
			request := authorizationTestRequest(store, binding)
			if err := store.CreateAuthorization(ctx, request, credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			complete := func() error {
				return store.CompleteAuthorization(ctx, binding, request.StateDigest, request.SessionDigest, request.ProviderDigest, testCredential(), credentialAuthority())
			}
			if err := complete(); !errors.Is(err, ErrCredentialConflict) {
				t.Fatalf("unconsumed completion=%v", err)
			}
			if _, err := store.ConsumeAuthorization(ctx, request.StateDigest, request.VerifierDigest, request.SessionDigest, request.ProviderDigest, credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			if err := store.CompleteAuthorization(ctx, binding, request.StateDigest, authorizationDigest("other-session"), request.ProviderDigest, testCredential(), credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
				t.Fatalf("wrong-session completion=%v", err)
			}
			if err := store.CompleteAuthorization(ctx, binding, request.StateDigest, request.SessionDigest, authorizationDigest("changed-provider-policy"), testCredential(), credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
				t.Fatalf("changed-policy completion=%v", err)
			}
			if invalidated {
				for i, providers := range []string{`[]`, `["provider"]`} {
					id := []string{"remove-after-consume", "readd-after-consume"}[i]
					if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: id, SQL: `UPDATE auth_collection_definitions SET providers_json=? WHERE id=?`, Args: []any{providers, binding.CollectionID}}); err != nil {
						t.Fatal(err)
					}
				}
				if err := complete(); !errors.Is(err, ErrCredentialConflict) {
					t.Fatalf("invalidated completion=%v", err)
				}
				if _, err := store.Load(ctx, binding, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
					t.Fatalf("invalidated credential persisted=%v", err)
				}
				return
			}
			if err := complete(); err != nil {
				t.Fatal(err)
			}
			if got, err := store.Load(ctx, binding, credentialAuthority()); err != nil || got.AccessToken != "access" {
				t.Fatalf("completed credential unavailable: %v", err)
			}
		})
	}
}
