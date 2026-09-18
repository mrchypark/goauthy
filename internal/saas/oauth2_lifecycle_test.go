package saas

import (
	"errors"
	"github.com/mrchypark/goauthy/internal/storage"
	"github.com/mrchypark/rhiza"
	"testing"
)

func TestOAuth2StatusAndRevoke(t *testing.T) {
	ctx, store, _, b := credentialStoreFixture(t)
	status, err := store.OAuth2Status(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || status.Connected || status.State != "draft" || status.Version != 0 || status.Scopes == nil {
		t.Fatalf("draft=%#v err=%v", status, err)
	}
	if err := store.Install(ctx, b, credential{AccountID: "acct", AccessToken: "access", Scopes: []string{"a"}}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	status, err = store.OAuth2Status(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || !status.Connected || status.AccountID != "acct" || len(status.Scopes) != 1 {
		t.Fatalf("ready=%#v err=%v", status, err)
	}
	if err := store.RevokeOAuth2(ctx, b.Owner, b.CollectionID, b.ConnectionID, status.Version, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	status, err = store.OAuth2Status(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
	if err != nil || status.Connected || status.State != "revoked" {
		t.Fatalf("revoked=%#v err=%v", status, err)
	}
	if err := store.RevokeOAuth2(ctx, b.Owner, b.CollectionID, b.ConnectionID, status.Version, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("replay=%v", err)
	}
}

func TestOAuth2RevokeBlocksOlderPendingAuthorization(t *testing.T) {
	ctx, store, _, b := credentialStoreFixture(t)
	req, state, session, provider, _ := verifierRequestWithSeed(b, "pending-before-install")
	if err := store.CreateAuthorization(ctx, req, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if err := store.Install(ctx, b, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthorization(ctx, state, req.VerifierDigest, session, provider, credentialAuthority()); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("pending after install=%v", err)
	}
	if err := store.RevokeOAuth2(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeAuthorization(ctx, state, req.VerifierDigest, session, provider, credentialAuthority()); !errors.Is(err, ErrAuthorizationNotFound) {
		t.Fatalf("pending after revoke=%v", err)
	}
}

func TestOAuth2RevokePreventsRefreshResurrection(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "refreshing", true: "uncertain"}[uncertain], func(t *testing.T) {
			ctx, store, db, b := credentialStoreFixture(t)
			if err := store.Install(ctx, b, testCredential(), credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			claim, err := store.ClaimRefresh(ctx, b, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			if uncertain {
				if err := store.MarkRefreshUncertain(ctx, b, claim); err != nil {
					t.Fatal(err)
				}
			}
			// Disabling the collection must not prevent owner cleanup.
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "disable-collection", SQL: `UPDATE auth_collection_definitions SET enabled=0 WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
				t.Fatal(err)
			}
			if err := store.RevokeOAuth2(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			status, err := store.OAuth2Status(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority())
			if err != nil || status.State != "revoked" || status.Connected {
				t.Fatalf("status=%+v err=%v", status, err)
			}
			if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "enable-collection", SQL: `UPDATE auth_collection_definitions SET enabled=1 WHERE id=?`, Args: []any{b.CollectionID}}); err != nil {
				t.Fatal(err)
			}
			if err := store.CompleteRefresh(ctx, b, claim, testCredential(), credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
				t.Fatalf("refresh after revoke=%v", err)
			}
			if _, err := store.Load(ctx, b, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
				t.Fatalf("load after revoke=%v", err)
			}
		})
	}
}

func TestOAuth2RevokeRejectsChangedGenerationAndAuthority(t *testing.T) {
	ctx, store, db, b := credentialStoreFixture(t)
	if err := store.Install(ctx, b, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeOAuth2(ctx, "other", b.CollectionID, b.ConnectionID, 1, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("wrong owner=%v", err)
	}
	if err := store.RevokeOAuth2(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, nil); !errors.Is(err, ErrCredentialUnauthorized) {
		t.Fatalf("nil authority=%v", err)
	}
	if err := store.RevokeOAuth2(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, func() (string, []any) { return "0", nil }); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("denied=%v", err)
	}
	if _, err := storage.Execute(ctx, db, rhiza.ExecuteRequest{RequestID: "change-generation", SQL: `UPDATE auth_collection_connections SET generation=? WHERE id=?`, Args: []any{"replacement", b.ConnectionID}}); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeOAuth2(ctx, b.Owner, b.CollectionID, b.ConnectionID, 1, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("old generation=%v", err)
	}
	if _, err := store.OAuth2Status(ctx, b.Owner, b.CollectionID, b.ConnectionID, credentialAuthority()); err == nil {
		t.Fatal("mismatched envelope generation exposed metadata")
	}
}

func TestOAuth2LifecycleGuards(t *testing.T) {
	ctx, store, _, b := credentialStoreFixture(t)
	if _, err := store.OAuth2Status(ctx, "wrong", b.CollectionID, b.ConnectionID, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("wrong owner=%v", err)
	}
	if _, err := store.OAuth2Status(ctx, b.Owner, b.CollectionID, b.ConnectionID, nil); !errors.Is(err, ErrCredentialUnauthorized) {
		t.Fatalf("nil authority=%v", err)
	}
	if err := store.Install(ctx, b, credential{AccessToken: "access"}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeOAuth2(ctx, b.Owner, b.CollectionID, b.ConnectionID, 99, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("stale=%v", err)
	}
}
