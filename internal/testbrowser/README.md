# Test Browser (`internal/testbrowser`)

## Overview
Provides a bounded headless Chrome lifecycle helper for UI and end-to-end browser regression tests using `chromedp`.

## Interface
- `[browser.go:Start]` — Locates Chrome/Chromium (via `GOAUTHY_E2E_CHROME_BIN`, `PATH`, or macOS default), allocates a headless browser with bounded startup (`60s` max) and action (`30s`) contexts, registers `t.Cleanup` handlers, and returns the action `context.Context`.

## Invariants
- The startup context also owns the Chrome process lifetime (`exec.CommandContext`), so it is never cancelled after readiness until test cleanup.
- `startupBudget` reserves `30s` for actions plus `5s` for cleanup when `t.Deadline()` is set, failing the test immediately if insufficient budget remains.
- Adds `chromedp.NoSandbox` only when `CI=true`.

## Side Effects
- Spawns and terminates an external headless Chrome/Chromium OS process and allocates temporary browser state via `chromedp.NewExecAllocator`.
- Reads `GOAUTHY_E2E_CHROME_BIN` and `CI` environment variables.

## Verification
- Run: `go test ./internal/testbrowser`
