package saas

import (
	"errors"
	"testing"
)

func TestProviderStoreGetMany(t *testing.T) {
	ctx, credentials, db, _ := credentialStoreFixture(t)
	store, err := NewProviderStore(db, credentials.keys)
	if err != nil {
		t.Fatal(err)
	}
	in := providerInputForTest("0123456789012345")
	for _, id := range []string{"alpha", "beta"} {
		in.ID = id
		if _, err := store.Create(ctx, in, credentialAuthority()); err != nil {
			t.Fatal(err)
		}
	}
	allowed := func() (string, []any) { return "?=?", []any{int64(1), int64(1)} }
	rows, err := store.GetMany(ctx, []string{"beta", "alpha"}, allowed)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	for i, id := range []string{"alpha", "beta"} {
		single, err := store.Get(ctx, id, allowed)
		if err != nil || rows[i].ID != single.ID || rows[i].Kind != single.Kind || rows[i].Enabled != single.Enabled || rows[i].Revision != single.Revision {
			t.Fatalf("batch mismatch for %s: %v", id, err)
		}
	}
	for _, tc := range []struct {
		name      string
		ids       []string
		authority func() (string, []any)
		want      error
	}{
		{"empty", nil, allowed, ErrProviderInvalid},
		{"duplicate", []string{"alpha", "alpha"}, allowed, ErrProviderInvalid},
		{"over limit", make([]string, 33), allowed, ErrProviderInvalid},
		{"invalid ID", []string{"alpha", "bad'id"}, allowed, ErrProviderInvalid},
		{"missing", []string{"alpha", "missing"}, allowed, ErrProviderNotFound},
		{"denied", []string{"alpha"}, func() (string, []any) { return "?=?", []any{int64(1), int64(0)} }, ErrProviderNotFound},
		{"nil authority", []string{"alpha"}, nil, ErrProviderUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.GetMany(ctx, tc.ids, tc.authority)
			if !errors.Is(err, tc.want) || got != nil {
				t.Fatalf("rows=%v err=%v want %v", got, err, tc.want)
			}
		})
	}
	if err := store.Delete(ctx, "beta", 1, allowed); err != nil {
		t.Fatal(err)
	}
	if got, err := store.GetMany(ctx, []string{"alpha", "beta"}, allowed); !errors.Is(err, ErrProviderNotFound) || got != nil {
		t.Fatalf("deleted rows=%v err=%v", got, err)
	}
}
