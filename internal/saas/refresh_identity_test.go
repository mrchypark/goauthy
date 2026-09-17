package saas

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/mrchypark/rhiza"
)

func credentialSnapshot(t *testing.T, ctx context.Context, s *CredentialStore, b credentialBinding) (int64, string, []byte) {
	t.Helper()
	q, err := s.db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT token_version,state,credential FROM saas_connection_credentials WHERE connection_id=?`, Args: []any{b.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(q.Rows) != 1 {
		t.Fatalf("credential snapshot failed err=%v", err)
	}
	version, _ := q.Rows[0][0].(int64)
	state, _ := q.Rows[0][1].(string)
	ciphertext, _ := q.Rows[0][2].([]byte)
	return version, state, append([]byte(nil), ciphertext...)
}

func TestCompleteRefreshRejectsIdentityChangesWithoutReplacingCredential(t *testing.T) {
	for _, tc := range []struct{ name, oldAccount, newAccount string }{
		{"nonempty-to-different", "account-1", "account-2"},
		{"nonempty-to-empty", "account-1", ""},
		{"empty-to-nonempty", "", "account-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, s, _, b := credentialStoreFixture(t)
			if err := s.Install(ctx, b, credential{AccountID: tc.oldAccount, AccessToken: "old", RefreshToken: "refresh", ExpiresAtUnixMS: s.now() + 60000}, credentialAuthority()); err != nil {
				t.Fatal(err)
			}
			version, _, before := credentialSnapshot(t, ctx, s, b)
			claim, err := s.ClaimRefresh(ctx, b, credentialAuthority())
			if err != nil {
				t.Fatal(err)
			}
			if err := s.CompleteRefresh(ctx, b, claim, credential{AccountID: tc.newAccount, AccessToken: "replacement", ExpiresAtUnixMS: s.now() + 60000}, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
				t.Fatalf("completion err=%v", err)
			}
			gotVersion, gotState, gotCipher := credentialSnapshot(t, ctx, s, b)
			if gotVersion != version || gotState != "refreshing" || !bytes.Equal(gotCipher, before) {
				t.Fatalf("changed version=%d state=%s ciphertext=%t", gotVersion, gotState, !bytes.Equal(gotCipher, before))
			}
		})
	}
}

func TestCompleteRefreshAcceptsMatchingIdentity(t *testing.T) {
	ctx, s, _, b := credentialStoreFixture(t)
	if err := s.Install(ctx, b, credential{AccountID: "account-1", AccessToken: "old", RefreshToken: "refresh", ExpiresAtUnixMS: s.now() + 60000}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	claim, err := s.ClaimRefresh(ctx, b, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteRefresh(ctx, b, claim, credential{AccountID: "account-1", AccessToken: "replacement", ExpiresAtUnixMS: s.now() + 60000}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	version, state, _ := credentialSnapshot(t, ctx, s, b)
	if version != 2 || state != "ready" {
		t.Fatalf("version=%d state=%s", version, state)
	}
}

func TestRefreshCredentialIdentityMismatchMarksUncertainWithoutRetry(t *testing.T) {
	ctx, s, _, b := credentialStoreFixture(t)
	if err := s.Install(ctx, b, credential{AccountID: "account-1", AccessToken: "old", RefreshToken: "refresh", ExpiresAtUnixMS: s.now() + 60000}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err := s.refreshCredential(ctx, b, credentialAuthority(), func(context.Context, credential) (credential, error) {
		calls++
		return credential{AccountID: "account-2", AccessToken: "replacement", ExpiresAtUnixMS: s.now() + 60000}, nil
	})
	if !errors.Is(err, errRefreshUncertain) || calls != 1 {
		t.Fatalf("err=%v exchange calls=%d", err, calls)
	}
	if _, err := s.refreshCredential(ctx, b, credentialAuthority(), func(context.Context, credential) (credential, error) {
		calls++
		return credential{AccountID: "account-2", AccessToken: "retry", ExpiresAtUnixMS: s.now() + 60000}, nil
	}); !errors.Is(err, ErrCredentialNotFound) || calls != 1 {
		t.Fatalf("retry err=%v exchange calls=%d", err, calls)
	}
	version, state, _ := credentialSnapshot(t, ctx, s, b)
	if version != 1 || state != "uncertain" {
		t.Fatalf("version=%d state=%s", version, state)
	}
}
