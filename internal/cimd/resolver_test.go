package cimd

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestResolverUsesSharedCacheWithoutRefetch(t *testing.T) {
	ctx, store, _ := testStore(t)
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	id := "https://client.example.test/metadata.json"
	want := testMetadata(id, "client")
	calls := 0
	resolver := &Resolver{store: store, now: func() time.Time { return now }, fetch: func(context.Context, string) (Metadata, time.Time, error) {
		calls++
		return want, now.Add(time.Hour), nil
	}}
	if _, err := resolver.Lookup(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cold lookup err=%v", err)
	}
	if got, err := resolver.Resolve(ctx, id); err != nil || !sameMetadata(got, want) {
		t.Fatalf("resolve=%#v err=%v", got, err)
	}
	if got, err := resolver.Resolve(ctx, id); err != nil || !sameMetadata(got, want) || calls != 1 {
		t.Fatalf("cached resolve=%#v calls=%d err=%v", got, calls, err)
	}
	if got, err := resolver.Lookup(ctx, id); err != nil || !sameMetadata(got, want) || calls != 1 {
		t.Fatalf("lookup=%#v calls=%d err=%v", got, calls, err)
	}
}

func TestResolverExactExpiryAndFetchFailureAreDeterministic(t *testing.T) {
	ctx, store, _ := testStore(t)
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	id := "https://client.example.test/metadata.json"
	want := testMetadata(id, "client")
	calls := 0
	resolver := &Resolver{store: store, now: func() time.Time { return now }, fetch: func(context.Context, string) (Metadata, time.Time, error) {
		calls++
		if calls == 1 {
			return want, now.Add(time.Minute), nil
		}
		return Metadata{}, time.Time{}, errFetch
	}}
	if _, err := resolver.Resolve(ctx, id); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, err := resolver.Lookup(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("exact-expiry lookup err=%v", err)
	}
	if _, err := resolver.Resolve(ctx, id); !errors.Is(err, errFetch) || calls != 2 {
		t.Fatalf("expired resolve calls=%d err=%v", calls, err)
	}
}

func TestResolverRejectsAlreadyExpiredFetch(t *testing.T) {
	ctx, store, _ := testStore(t)
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	id := "https://client.example.test/metadata.json"
	resolver := &Resolver{store: store, now: func() time.Time { return now }, fetch: func(context.Context, string) (Metadata, time.Time, error) {
		return testMetadata(id, "client"), now, nil
	}}
	if _, err := resolver.Resolve(ctx, id); !errors.Is(err, errFetch) {
		t.Fatalf("expired fetch err=%v", err)
	}
	if _, err := resolver.Lookup(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired fetch was cached: %v", err)
	}
}

func TestResolverPoliciesDoNotShareCIMDCacheEntries(t *testing.T) {
	ctx, store, _ := testStore(t)
	now := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	id := "https://client.example.test/metadata.json"
	metadata := testMetadata(id, "lenient")
	lenient := &Resolver{
		store: store, now: func() time.Time { return now }, policyDigest: policyDigestFor(Policy{IgnoreUnknownAuthFlows: true}),
		fetch: func(context.Context, string) (Metadata, time.Time, error) { return metadata, now.Add(time.Hour), nil },
	}
	if _, err := lenient.Resolve(ctx, id); err != nil {
		t.Fatal(err)
	}
	strict := &Resolver{store: store, now: func() time.Time { return now }, fetch: func(context.Context, string) (Metadata, time.Time, error) {
		return Metadata{}, time.Time{}, errFetch
	}}
	if _, err := strict.Lookup(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("strict resolver reused lenient cache: %v", err)
	}
}

func TestResolverPolicyDigestSeparatesDangerMode(t *testing.T) {
	strict := policyDigestFor(Policy{})
	lenient := policyDigestFor(Policy{IgnoreUnknownAuthFlows: true})
	danger := policyDigestFor(Policy{DangerAllowUnvalidatedResource: true})
	combined := policyDigestFor(Policy{IgnoreUnknownAuthFlows: true, DangerAllowUnvalidatedResource: true})
	if strict != policyDigest || strict == lenient || strict == danger || strict == combined || lenient == danger || lenient == combined || danger == combined {
		t.Fatalf("policy digests are not distinct: strict=%q lenient=%q danger=%q combined=%q", strict, lenient, danger, combined)
	}
}
