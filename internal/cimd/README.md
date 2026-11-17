# cimd

## Overview
`internal/cimd` validates, fetches, and caches OAuth Client ID Metadata Documents (CIMD) in `*rhiza.DB` with strict SSRF, policy-digest, and fail-closed cache invariants.

## Interface
- `[metadata.go:Metadata]`: Narrow public-client metadata subset (`ID`, `Name`, `RedirectURIs`, `Scopes`, `GrantTypes`, `AllowedResources`, `AllowedResourcesPresent`).
- `[fetch.go:Fetcher]`, `[fetch.go:Policy]`, `[fetch.go:NewFetcher]`, `[fetch.go:NewFetcherWithPolicy]`, `[fetch.go:Fetcher.Fetch]`: Direct HTTPS metadata fetcher bypassing proxy environment variables and pinning resolved IPs.
- `[store.go:ErrInvalidCache]`, `[store.go:ErrCacheFull]`, `[store.go:Store]`, `[store.go:NewStore]`, `[store.go:Store.Lookup]`, `[store.go:Store.PutFirstWinner]`: Shared, fail-closed Rhiza metadata cache.
- `[resolver.go:ErrNotFound]`, `[resolver.go:Resolver]`, `[resolver.go:NewResolver]`, `[resolver.go:Resolver.Lookup]`, `[resolver.go:Resolver.Resolve]`: Combines cache `Lookup` (no network I/O) with `Resolve` (fetches and caches on miss).

## Invariants
- Network trust boundary: `[resolver.go:Resolver.Lookup]` never performs network I/O; only `[resolver.go:Resolver.Resolve]` (reserved for authorization) triggers `Fetcher.Fetch`.
- Fail-closed shared cache: `[store.go:Store]` has no process-local fallback; malformed persisted rows or digest mismatches fail closed with `ErrInvalidCache`, and active cache entries are capped at `storeActiveCacheCap = 1024`.
- Policy-bound cache keys: Cache lookups and inserts are keyed by `(client_id, policy_digest)` so policy changes cannot reuse stale admission decisions.
- Bounded documents & lists: `maxDocumentBytes = 5 << 10`, `maxListEntries = 32`, `maxValueLength = 2048`, cache TTL clamped to `[10m, 1h]`.

## Side Effects
- Reads and writes `cimd_client_documents` in `*rhiza.DB`.
- Makes outbound HTTPS GET requests to client metadata URLs during `Resolve`/`Fetch` (bypassing proxy env vars).

## Verification
- Run: `go test ./internal/cimd`
