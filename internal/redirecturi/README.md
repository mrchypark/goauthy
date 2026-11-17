# Redirect URI Policy (`internal/redirecturi`)

## Overview
Provides the shared, narrow RFC 8252 loopback redirect URI matching policy and Dynamic Client Registration (DCR) loopback template validation.

## Interface
- `[policy.go:Policy]` — Struct with `AllowLoopback bool` configuring whether loopback port wildcarding is enabled.
- `[policy.go:Policy.Matches]` — Matches a requested redirect URI against registered URIs; permits different loopback ports only when `AllowLoopback` and `publicDynamic` are true.
- `[policy.go:IsLoopbackTemplate]` — Validates the DCR registration subset: canonical HTTP literal loopback URI (`localhost`, `127.0.0.1`, or `::1`), optional valid port (`1..65535`), and no query or fragment.
- `[policy.go:IsPortlessLoopbackTemplate]` — Reports whether `raw` is a valid numeric loopback template (`127.0.0.1` or `::1`) without an explicit port, query, or fragment.

## Invariants
- Any URI containing `#` (even an empty fragment) is rejected by `[policy.go:Policy.Matches]` and `[policy.go:parseLoopbackRedirect]`.
- Loopback port wildcard matching requires `publicDynamic == true`, `AllowLoopback == true`, non-`localhost` numeric loopback host (`127.0.0.1` or `::1`), an explicit port on the requested URI, and exact equality of host, escaped path, and query.
- Only `http` scheme absolute URIs without userinfo or opaque parts are accepted as loopback templates.

## Side Effects
- None (pure in-memory URI parsing and string comparison).

## Verification
- Run: `go test ./internal/redirecturi`
