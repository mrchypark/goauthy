# audit

## Overview
`internal/audit` provides the durable, append-only security-event store and deterministic pseudonymization helpers backed by `*rhiza.DB`.

## Interface
- `[audit.go:ErrInvalid]`: Sentinel error returned for invalid store, event, cursor, or pagination parameters.
- `[audit.go:Event]`: Security-event record (`Sequence`, `ID`, `OccurredAtUnixMilli`, `Type`, `Action`, `Outcome`, `ActorKind`, `ActorHash`, `TargetHash`).
- `[audit.go:Cursor]`: Keyset pagination cursor (`Sequence`).
- `[audit.go:Store]`, `[audit.go:NewStore]`: Audit store constructor and handle.
- `[audit.go:EventID]`: Derives a domain-separated SHA-256 base64url event ID from a request ID.
- `[audit.go:Pseudonym]`: Computes a domain-separated HMAC-SHA256 pseudonym keyed by a persisted secret digest.
- `[audit.go:NewEvent]`: Constructs a validated `Event` with `Outcome: "success"`.
- `[audit.go:Event.Statement]`: Builds a conditional `rhiza.SQLStatement` that appends the event with `MAX(sequence)+1` only when `condition` holds.
- `[audit.go:Store.List]`, `[audit.go:Store.ListWhen]`, `[audit.go:Store.ListGuarded]`: Linearizable keyset-paginated queries (`maxPageSize = 32`), including atomic authorization-checked listing (`ListGuarded`).

## Invariants
- Linearizable reads & bounded pages: `[audit.go:Store.ListWhen]` and `[audit.go:Store.ListGuarded]` require `1 <= limit <= 32` (`maxPageSize`), a non-empty `condition`, and execute with `rhiza.ConsistencyLinearizable`.
- Atomic authorization & page read: `[audit.go:Store.ListGuarded]` evaluates the authorization predicate and fetches the page in a single SQL `WITH` query, eliminating TOCTOU windows between auth check and read.
- Co-transactional append: `[audit.go:Event.Statement]` emits a guarded `INSERT ... SELECT ... WHERE <condition>` statement intended to run in the same replicated mutation as the security state change.

## Side Effects
- Inserts into and queries the `audit_events` table in `*rhiza.DB`.

## Verification
- Run: `go test ./internal/audit`
