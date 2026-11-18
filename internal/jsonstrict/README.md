# Strict JSON Validation (`internal/jsonstrict`)

## Overview
Provides strict JSON structural validation helpers used at HTTP and configuration boundaries to reject duplicate object keys, unknown fields, and trailing JSON tokens.

## Interface
- `[jsonstrict.go:RejectDuplicateKeys]` — Verifies that `data` contains a single valid JSON value with no repeated object keys at any depth and no trailing tokens.
- `[jsonstrict.go:DecodeStrict]` — Runs `RejectDuplicateKeys`, decodes into `target` with `DisallowUnknownFields()`, and rejects trailing tokens.
- `[jsonstrict.go:ErrDuplicateKey]` — Sentinel error returned when a JSON object contains a repeated key.

## Verification
- Run: `go test ./internal/jsonstrict`
