# Security Header Text Validation (`internal/security`)

## Overview
Provides HTTP header text validation for upstream login metadata.

## Interface
- `[header_text.go:ValidHeaderText]` — Reports whether `value` is non-empty and contains only visible ASCII (`32..126`) or horizontal tab (`\t`).

## Verification
- Run: `go test ./internal/security`
