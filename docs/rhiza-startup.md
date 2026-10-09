# Rhiza startup close guard

The current greenfield build pins Rhiza to
`github.com/mrchypark/rhiza v0.19.1-0.20261008214459-3895b723e194` in `go.mod`,
resolving to upstream commit [`3895b723e194`](https://github.com/mrchypark/rhiza/commit/3895b723e194).
Earlier documentation cited the official Rhiza `v0.19.0` release (commit
[`abb87a0336cba8fee3fd1d9e5a0bf797de5b25b8`](https://github.com/mrchypark/rhiza/commit/abb87a0336cba8fee3fd1d9e5a0bf797de5b25b8),
[release tag](https://github.com/mrchypark/rhiza/releases/tag/v0.19.0)). PR #146 inherits
the same pseudo-version unchanged from its base and corrects this stale release citation;
it does not change the Rhiza dependency.
This build uses `github.com/mrchypark/latticedb-go v0.11.3` with a fresh `DataDir`,
unused cluster ID, and unused object-store namespace. Existing-data migration is
out of scope and unsupported.
Rhiza's SQL execution policy changes from 4 to 7; earlier materializers,
checkpoints and history are rejected. Mixed-version peers and downgrade are
unsupported. The earlier citation links to the
[official v0.19.0 release](https://github.com/mrchypark/rhiza/releases/tag/v0.19.0).
After Rhiza opens, `cmd/goauthy` starts the existing HTTP listener and answers
canonical `GET /livez` while waiting up to 30 seconds for `DB.Ready()` and then
initializing the schema and application. `/readyz` and all application routes
return 503 until initialization finishes; the complete existing handler is then
published atomically. TLS and request draining apply from the first accepted
connection. Rhiza opening itself retains the existing startup-probe bound;
probe budgets and storage durability are unchanged.

The startup defer intentionally does not call `DB.Close()` until all startup
initialization has succeeded and the server lifecycle is about to begin. This
is an application-side workaround for a confirmed Rhiza v0.10.0
checkpoint-corruption hazard when a database is closed during startup, even if
`DB.Ready()` became true transiently before a later migration, quorum, or
configuration failure. Once startup is complete, the normal close path remains
active for graceful shutdown, so this guard does not alter ordinary lifecycle
cleanup.

The GoAuthy startup-close regression test verifies this guard. One fresh local
v0.18.0 diagnostic with three logical GoAuthy members on one Kind node and a Versity
fixture completed its scheduled IAM/API and drain checks on first startup
without GoAuthy restarts. See the [Run 25 evidence](measurements/saas-isolation-113-local/README.md).
That historical run does not qualify the current pinned Rhiza revision, data
integrity after an early close and cold reopen, physical host failure tolerance,
production qualification, or existing-data migration.
See [the no-PVC recovery and upgrade contract](no-pvc-dr.md).
