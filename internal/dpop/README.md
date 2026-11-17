# dpop

## Overview
`internal/dpop` validates RFC 9449 Demonstrating Proof-of-Possession (DPoP) JWT proofs at the HTTP boundary and manages server-issued DPoP nonces and JTI replay detection in `*rhiza.DB`.

## Interface
- `[proof.go:MaxProofSize]`: Maximum accepted DPoP header size (`8 << 10` bytes).
- `[proof.go:ErrInvalidProof]`, `[proof.go:ErrUseNonce]`: Validation and nonce-challenge error sentinels.
- `[proof.go:Options]`: Server-controlled validation context (`Issuer`, `Now`, `MaxAge`, `FutureSkew`, `Nonce`, `AccessToken`).
- `[proof.go:Proof]`: Validated proof result (`JKT`, `JTI`, `Nonce`, `IssuedAt`, `Key`).
- `[proof.go:Validate]`: Validates a single `DPoP` JWT header against HTTP method (`htm`), issuer-derived target URI (`htu`), `iat` window, optional `nonce`, optional `ath` (SHA-256 of `AccessToken`), and public asymmetric JWK signature.
- `[store.go:DefaultNonceTTL]`: Default nonce lifetime (`5 * time.Minute`).
- `[store.go:Store]`, `[store.go:NewStore]`, `[store.go:Store.IssueNonce]`, `[store.go:Store.ConsumeNonce]`, `[store.go:Store.MarkReplay]`: Rhiza-backed single-use nonce issuance/consumption and `(jkt, jti)` replay tracking.

## Invariants
- Issuer-derived `htu`: `[proof.go:Validate]` constructs the expected `htu` from `Options.Issuer` + request path, never from `Host` or forwarding headers.
- Strict JWT & JWK checks: Rejects duplicate JSON keys, `typ != "dpop+jwt"`, disallowed algorithms, private JWK material, or non-asymmetric keys; callers must reject duplicate `DPoP` HTTP headers before calling `Validate`.
- Single-use nonces & replay protection: `[store.go:Store.ConsumeNonce]` atomically consumes nonces bound to `(clientID, jkt)` and `[store.go:Store.MarkReplay]` records `(jkt, jti)` until `expiresAt`.

## Side Effects
- Reads and writes DPoP nonce and replay-tracking tables in `*rhiza.DB`.

## Verification
- Run: `go test ./internal/dpop`
