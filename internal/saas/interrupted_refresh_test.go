package saas

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/mrchypark/rhiza"
)

func TestAbandonedRefreshClaimRequiresOwnerRecovery(t *testing.T) {
	ctx, original, db, old := credentialStoreFixture(t)
	if err := original.Install(ctx, old, testCredential(), credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	claim, err := original.ClaimRefresh(ctx, old, credentialAuthority())
	if err != nil {
		t.Fatal(err)
	}
	// Simulate losing the worker immediately after the durable claim, without
	// a completion or uncertainty marker. A new worker sees only persisted state.
	next, err := NewCredentialStore(db, original.keys)
	if err != nil {
		t.Fatal(err)
	}
	next.now = func() int64 { return original.now() + int64((24*time.Hour)/time.Millisecond) }
	calls := 0
	if _, err := next.refreshCredential(ctx, old, credentialAuthority(), func(context.Context, credential) (credential, error) { calls++; return testCredential(), nil }); err == nil || calls != 0 {
		t.Fatalf("abandoned claim retried: calls=%d err=%v", calls, err)
	}
	status, err := next.OAuth2Status(ctx, old.Owner, old.CollectionID, old.ConnectionID, credentialAuthority())
	if err != nil || status.State != "refreshing" || status.Connected || status.Version != old.TokenVersion {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if err := next.RevokeOAuth2(ctx, old.Owner, old.CollectionID, old.ConnectionID, old.TokenVersion, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if _, err := next.PrepareOAuth2Reconnect(ctx, old.Owner, old.CollectionID, old.ConnectionID, old.TokenVersion, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	row, err := db.Query(ctx, rhiza.QueryRequest{SQL: `SELECT generation FROM auth_collection_connections WHERE id=?`, Args: []any{old.ConnectionID}, Consistency: rhiza.ConsistencyLinearizable})
	if err != nil || len(row.Rows) != 1 {
		t.Fatal("reconnect generation unavailable")
	}
	fresh := old
	fresh.Generation = row.Rows[0][0].(string)
	fresh.TokenVersion++
	if fresh.Generation == old.Generation {
		t.Fatal("generation not fenced")
	}
	if err := next.Install(ctx, fresh, credential{AccessToken: "replacement", RefreshToken: "replacement-refresh"}, credentialAuthority()); err != nil {
		t.Fatal(err)
	}
	if err := original.CompleteRefresh(ctx, old, claim, credential{AccessToken: "late-worker"}, credentialAuthority()); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("late completion=%v", err)
	}
	if err := original.MarkRefreshUncertain(ctx, old, claim); !errors.Is(err, ErrCredentialConflict) {
		t.Fatalf("late uncertainty=%v", err)
	}
	got, err := next.Load(ctx, fresh, credentialAuthority())
	if err != nil || got.AccessToken != "replacement" {
		t.Fatal("old worker changed recovered credential")
	}
	if _, err := next.Load(ctx, old, credentialAuthority()); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("old generation load=%v", err)
	}
}
