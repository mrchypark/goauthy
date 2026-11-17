# test/compat

## Overview
Development-only compatibility and differential reference harnesses comparing external scheduler/cron libraries (`rauthy-cron` and `go-quartz`) against GoAuthy's backup-scheduling contracts.

## Subdirectories & Boundaries
- `rauthy-cron`: [./rauthy-cron/README.md](./rauthy-cron/README.md) - Pinned Rust `cron = 0.17.0` reference tests and stdin hex-line parser oracle for Rauthy v0.36.2 compatibility.
- `go-quartz`: Go module (`goquartzvet`, `github.com/reugn/go-quartz v0.15.2`) compatibility test (`compat_test.go`).
