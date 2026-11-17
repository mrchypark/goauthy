# goauthy-smtp-sink

## Overview
Local-kind-only SMTP mailbox and HTTP inspection sink for end-to-end email delivery tests (`[main.go:main]`). It intentionally has neither TLS nor authentication and must never be deployed outside an isolated test namespace.

## Interface
- CLI flags (`[main.go:main]`):
  - `-smtp-addr`: SMTP listen address (default `:1025`)
  - `-http-addr`: HTTP inspection listen address (default `:8082`)
- HTTP routes (`[main.go:mailbox.handler]`):
  - `GET /livez`: Returns `204 No Content`.
  - `GET /messages`: Returns JSON `{"messages": [...]}` with stored `{id, from, to, data}`.
  - `DELETE /messages`: Clears all stored messages.
- SMTP commands (`[main.go:handleSMTP]`): `EHLO`, `HELO`, `MAIL FROM:`, `RCPT TO:`, `DATA`, `RSET`, `NOOP`, `QUIT`.

## Invariants
- In-memory mailbox is capped at `maxMessages` (`128`), evicting oldest messages `[main.go:mailbox.store]`.
- Per-message limits: `maxRecipients` (`32`), `maxMessage` (`64 KiB`), `maxSMTPLine` (`4 KiB`), and `30s` connection deadline `[main.go:handleSMTP]`, `[main.go:readSMTPLine]`, `[main.go:readSMTPData]`.
- HTTP endpoints reject query parameters (`400`) and set `Cache-Control: no-store` `[main.go:mailbox.livez]`, `[main.go:mailbox.messagesHandler]`.

## Side Effects
- Binds TCP listeners on `-smtp-addr` and `-http-addr` and handles `SIGINT`/`SIGTERM` for graceful shutdown `[main.go:main]`.
- Stores received email envelopes and bodies in a mutex-protected in-memory slice `[main.go:mailbox]`.

## Verification
- Run: `go test ./...`
