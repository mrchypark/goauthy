# Rauthy cron reference checks

## Overview

Development-only executable evidence for the `cron = 0.17.0` dependency in
[Rauthy v0.36.2 Cargo.lock](https://github.com/sebadob/rauthy/blob/v0.36.2/Cargo.lock).
This does not introduce Rust into the GoAuthy runtime or prove that its automatic
backup scheduler is implemented. Chrono and the test timezone database are pinned
by the local Cargo manifest/lock; they are fixture dependencies, not a claim to
reproduce every upstream dependency or host timezone database.

## Interface

- `Cargo.toml` & `Cargo.lock` — Pins `cron = "=0.17.0"`, `chrono = "=0.4.44"`, and `chrono-tz = "=0.10.4"` (`publish = false`).
- `src/`: [./src/README.md](./src/README.md) — Rust reference tests (`lib.rs`) and hex-line parser oracle (`main.rs`).

## Invariants

- The checks preserve six/seven-field and shorthand acceptance, rejection of extra fields, Sunday numbering, day-of-month AND day-of-week, year 2100 and exhaustion, and New York spring/fall DST behavior.
- GoAuthy intentionally orders dispatches strictly forward rather than reproducing Rust's backward UTC iteration during a repeated hour; see [the scheduling contract](../../../docs/backup-scheduling.md).

## Side Effects

- Building and running Cargo tests/oracle writes build artifacts to `CARGO_TARGET_DIR` (recommended `/tmp/goauthy-cron-reference-target`).

## Verification

- Run: `CARGO_TARGET_DIR=/tmp/goauthy-cron-reference-target cargo test --locked --manifest-path test/compat/rauthy-cron/Cargo.toml`
- Run differential gate: `CARGO_TARGET_DIR=/tmp/goauthy-cron-reference-target go test -tags cronoracle ./internal/backupschedule`

## Developer Notes

Run from the repository root (Rust/Cargo required):

```sh
CARGO_TARGET_DIR=/tmp/goauthy-cron-reference-target cargo test --locked --manifest-path test/compat/rauthy-cron/Cargo.toml
```

The checks preserve six/seven-field and shorthand acceptance, rejection of extra
fields, Sunday numbering, day-of-month AND day-of-week, year 2100 and exhaustion,
and New York spring/fall DST behavior. They are a small reference corpus, not an
exhaustive grammar conformance suite. Future Go parser/evaluator tests must match
these semantics and extend the corpus for ranges, lists, steps, names, whitespace
and scheduler cancellation/ownership behavior. Do not substitute a default-only
schedule for Rauthy's configurable schedule.

The reference now also reproduces Rust's backward UTC iteration during a repeated
hour. GoAuthy intentionally orders dispatches strictly forward; see
[the scheduling contract](../../../docs/backup-scheduling.md).
The `main` binary accepts hex-encoded UTF-8 expressions, one per line, and emits
`err` or the seven allowed-value sets for the opt-in Go differential gate:

```sh
CARGO_TARGET_DIR=/tmp/goauthy-cron-reference-target go test -tags cronoracle ./internal/backupschedule
```
