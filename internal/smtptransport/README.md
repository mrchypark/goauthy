# SMTP Transport (`internal/smtptransport`)

## Overview
Provides a context-bound SMTP dialer and custom authentication selector for `github.com/wneessen/go-mail`, ensuring implicit TLS handshakes and channel-bound SCRAM authentication work properly with custom dialer hooks.

## Interface
- `[dialer.go:Dialer]` — Returns a `mail.DialContextFunc` tied to `ctx` and an auth option builder `func(username, password string) mail.Option` using `[dialer.go:autoAuth]`.

## Invariants
- Connection lifetime is bound to `ctx` via `context.AfterFunc`, closing the underlying `net.Conn` upon cancellation.
- When `implicitTLS` is true, `[dialer.go:Dialer]` performs the `tls.Client` handshake directly inside the dial function using a cloned `*tls.Config`.
- `[dialer.go:autoAuth.Start]` enforces mechanism preference order: `SCRAM-SHA-256-PLUS`, `SCRAM-SHA-256`, `SCRAM-SHA-1-PLUS`, `SCRAM-SHA-1`, `CRAM-MD5`, `PLAIN`, `LOGIN` over TLS; `SCRAM-SHA-256`, `SCRAM-SHA-1`, `CRAM-MD5` without TLS (disallowing plaintext `PLAIN`/`LOGIN` and `-PLUS` channel-binding without TLS).

## Side Effects
- Opens outbound TCP and TLS network connections to SMTP servers and closes them on context cancellation or connection close.

## Verification
- Run: `go test ./internal/smtptransport`
