# cache

## Overview
`internal/cache` provides a generic, concurrent-safe, power-of-2 sharded, TTL-aware in-memory LRU cache (`Cache[K, V]`) designed for authentication server hot paths.

## Interface
- `[cache.go:Metrics]`, `[cache.go:Metrics.HitRate]`: Atomic counters (`Hits`, `Misses`, `Evictions`, `Stores`, `Deletes`) and hit-rate percentage calculation.
- `[cache.go:Config]`: Cache configuration (`MaxEntries`, `DefaultTTL`, `ShardCount`, `OnEvict`).
- `[cache.go:Cache]`, `[cache.go:New]`, `[cache.go:Cache.Get]`: Sharded LRU cache constructor and operations (`Get`, `Set`, `Delete`, etc.).

## Invariants
- Power-of-2 shard count: `[cache.go:New]` rounds `ShardCount` up to the next power of 2 (default 16, or 1 when `MaxEntries < 16`) so shard indexing uses a bitmask (`shardMask`).
- Per-shard locking & LRU/TTL eviction: Each shard is guarded by its own `sync.Mutex`, and expired or least-recently-used entries are evicted within the shard.
- Defaults for non-positive config: `MaxEntries <= 0` defaults to `1024`; `DefaultTTL <= 0` defaults to `5 * time.Minute`.

## Side Effects
- Maintains in-memory shard maps/lists and atomic metrics counters.
- Invokes optional `onEvict` callback upon LRU or TTL eviction.

## Verification
- Run: `go test ./internal/cache`
