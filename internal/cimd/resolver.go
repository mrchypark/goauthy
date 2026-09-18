package cimd

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/mrchypark/rhiza"
)

var (
	ErrNotFound  = errors.New("CIMD metadata not found")
	policyDigest = func() string {
		sum := sha256.Sum256([]byte("goauthy-cimd-v1|public|authorization_code|code|pkce-s256|same-origin-https|openid-goauthy.read|no-resource"))
		return base64.RawURLEncoding.EncodeToString(sum[:])
	}()
)

func policyDigestFor(policy Policy) string {
	if !policy.IgnoreUnknownAuthFlows && !policy.DangerAllowUnvalidatedResource {
		return policyDigest
	}
	policyValue := "goauthy-cimd-v1|public|authorization_code|code|pkce-s256|same-origin-https|openid-goauthy.read|no-resource"
	if policy.IgnoreUnknownAuthFlows {
		policyValue += "|ignore-unknown-auth-flows"
	}
	if policy.DangerAllowUnvalidatedResource {
		policyValue += "|danger-allow-unvalidated-resource"
	}
	sum := sha256.Sum256([]byte(policyValue))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type fetchFunc func(context.Context, string) (Metadata, time.Time, error)

// Resolver combines the shared Rhiza cache with the network trust boundary.
// Lookup never performs network I/O; Resolve is reserved for authorization.
type Resolver struct {
	store        *Store
	fetch        fetchFunc
	now          func() time.Time
	policyDigest string
}

func NewResolver(db *rhiza.DB, fetcher *Fetcher) (*Resolver, error) {
	store, err := NewStore(db)
	if err != nil {
		return nil, err
	}
	if fetcher == nil {
		return nil, errFetch
	}
	return &Resolver{store: store, fetch: fetcher.Fetch, now: time.Now, policyDigest: policyDigestFor(fetcher.policy)}, nil
}

func (r *Resolver) cachePolicyDigest() string {
	if r.policyDigest != "" {
		return r.policyDigest
	}
	return policyDigest
}

func (r *Resolver) Lookup(ctx context.Context, clientID string) (Metadata, error) {
	if r == nil || r.store == nil || r.now == nil {
		return Metadata{}, ErrInvalidCache
	}
	metadata, found, err := r.store.Lookup(ctx, clientID, r.cachePolicyDigest(), r.now().UTC())
	if err != nil {
		return Metadata{}, err
	}
	if !found {
		return Metadata{}, ErrNotFound
	}
	return metadata, nil
}

func (r *Resolver) Resolve(ctx context.Context, clientID string) (Metadata, error) {
	metadata, err := r.Lookup(ctx, clientID)
	if err == nil || !errors.Is(err, ErrNotFound) {
		return metadata, err
	}
	if r.fetch == nil {
		return Metadata{}, errFetch
	}
	metadata, expiresAt, err := r.fetch(ctx, clientID)
	if err != nil {
		return Metadata{}, err
	}
	fetchedAt := r.now().UTC()
	if !expiresAt.After(fetchedAt) {
		return Metadata{}, errFetch
	}
	return r.store.PutFirstWinner(ctx, clientID, r.cachePolicyDigest(), metadata, fetchedAt, expiresAt.Sub(fetchedAt))
}
