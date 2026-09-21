package saas

import (
	"context"
	"errors"
	"testing"

	"github.com/mrchypark/rhiza"
)

func TestRefreshCredentialCommitsBeforeReturningBinding(t *testing.T) {
	t.Parallel()
	ctx, store, _, binding := credentialStoreFixture(t)
	if err := store.Install(ctx, binding, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	next, err := store.refreshCredential(ctx, binding, credentialAuthority(), func(ctx context.Context, old credential) (credential, error) {
		calls++
		if old.RefreshToken != "refresh" {
			t.Fatal("wrong refresh token")
		}
		if _, err := store.ClaimRefresh(ctx, binding, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
			t.Fatalf("competing claim=%v", err)
		}
		return credential{AccessToken: "new-access", RefreshToken: "rotated-refresh"}, nil
	})
	if err != nil || next.TokenVersion != 2 || calls != 1 {
		t.Fatalf("next=%+v calls=%d err=%v", next, calls, err)
	}
	got, err := store.Load(ctx, next, credentialAuthority())
	if err != nil || got.AccessToken != "new-access" || got.RefreshToken != "rotated-refresh" {
		t.Fatalf("stored credential mismatch: %v", err)
	}
}

func TestRefreshCredentialUncertainNeverRetries(t *testing.T) {
	t.Parallel()
	for _, canceled := range []bool{false, true} {
		t.Run(map[bool]string{false: "provider-error", true: "canceled-after-send"}[canceled], func(t *testing.T) {
			ctx, store, db, binding := credentialStoreFixture(t)
			if err := store.Install(ctx, binding, testCredential(), credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			request, cancel := context.WithCancel(ctx)
			defer cancel()
			calls := 0
			exchange := func(context.Context, credential) (credential, error) {
				calls++
				if canceled {
					cancel()
				}
				return credential{}, errors.New("provider body contains secret")
			}
			if _, err := store.refreshCredential(request, binding, credentialAuthority(), exchange); !errors.Is(err, errRefreshUncertain) {
				t.Fatalf("refresh error=%v", err)
			}
			result, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT state,refresh_claim FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{binding.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
			if err != nil || len(result.Rows) != 1 || result.Rows[0][0] != "uncertain" || result.Rows[0][1] != nil {
				t.Fatalf("state=%#v err=%v", result.Rows, err)
			}
			if _, err := store.refreshCredential(ctx, binding, credentialAuthority(), exchange); err == nil || calls != 1 {
				t.Fatalf("retried uncertain refresh calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestRefreshCredentialRevocationDuringExchangePreventsCommit(t *testing.T) {
	t.Parallel()
	ctx, store, _, binding := credentialStoreFixture(t)
	if err := store.Install(ctx, binding, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	_, err := store.refreshCredential(ctx, binding, credentialAuthority(), func(context.Context, credential) (credential, error) {
		if err := store.Revoke(ctx, binding, credentialAuthority()); err != nil {
			t.Fatal(err)
		}
		return credential{AccessToken: "must-not-be-used"}, nil
	})
	if !errors.Is(err, errRefreshUncertain) {
		t.Fatalf("refresh=%v", err)
	}
	for _, version := range []int64{1, 2} {
		binding.TokenVersion = version
		if _, err := store.Load(ctx, binding, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
			t.Fatalf("version=%d load=%v", version, err)
		}
	}
}

func TestRefreshCredentialChecksExpiryAndCurrentAuthority(t *testing.T) {
	t.Parallel()
	ctx, store, _, binding := credentialStoreFixture(t)
	store.now = func() int64 { return 1000 }
	value := testCredential()
	value.RefreshExpiresAtUnixMS = 1001
	if err := store.Install(ctx, binding, value, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	exchange := func(context.Context, credential) (credential, error) {
		calls++
		return testCredential(), nil
	}
	denied := func() (string, []any) { return "0", nil }
	if _, err := store.refreshCredential(ctx, binding, denied, exchange); err == nil || calls != 0 {
		t.Fatalf("denied exchange calls=%d err=%v", calls, err)
	}
	store.now = func() int64 { return 1001 }
	if _, err := store.refreshCredential(ctx, binding, credentialAuthority(), exchange); err == nil || calls != 0 {
		t.Fatalf("expired exchange calls=%d err=%v", calls, err)
	}
	store.now = func() int64 { return 1000 }
	allowed := true
	authority := func() (string, []any) { return "?", []any{allowed} }
	_, err := store.refreshCredential(ctx, binding, authority, func(context.Context, credential) (credential, error) {
		calls++
		allowed = false
		return credential{AccessToken: "must-not-commit"}, nil
	})
	if !errors.Is(err, errRefreshUncertain) || calls != 1 {
		t.Fatalf("authority revoked during exchange calls=%d err=%v", calls, err)
	}
	binding.TokenVersion = 2
	if _, err := store.Load(ctx, binding, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("unauthorized result stored: %v", err)
	}
}
