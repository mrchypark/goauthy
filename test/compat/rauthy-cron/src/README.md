# rauthy-cron/src

## Overview
Rust source for the development-only `cron = "=0.17.0"` compatibility oracle used to cross-check Rauthy v0.36.2 cron parsing and calendar/DST semantics against GoAuthy's Go implementation.

## Interface
- `main.rs` — Stdin/stdout CLI oracle for the opt-in Go differential gate (`go test -tags cronoracle ./internal/backupschedule`). Reads hex-encoded UTF-8 cron expressions (one per line from `stdin`), parses each with `cron::Schedule`, and prints `err` or seven `|`-separated comma-delimited integer lists (`seconds|minutes|hours|days_of_month|months|days_of_week|years`) to `stdout`.
- `lib.rs` — `#[cfg(test)]` reference tests (`grammar_and_calendar_contract`, `local_dst_gap_and_duplicate`, `upstream_fold_iterator_can_go_backwards`) exercising `cron 0.17.0`, `chrono 0.4.44`, and `chrono-tz 0.10.4`.

## Invariants
- Input lines to `main.rs` must be even-length valid hexadecimal encoding UTF-8; invalid hex, invalid UTF-8, or parse errors emit `err` without panicking.
- `upstream_fold_iterator_can_go_backwards` documents upstream `cron 0.17.0` backward UTC iteration during DST fold; GoAuthy intentionally orders dispatches strictly forward.

## Side Effects
- Reads from `stdin` and writes one line per input expression to `stdout`.

## Verification
- Run: `CARGO_TARGET_DIR=/tmp/goauthy-cron-reference-target cargo test --locked --manifest-path test/compat/rauthy-cron/Cargo.toml`
