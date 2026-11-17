# WebID Profile Handler (`internal/webid`)

## Overview
Serves bounded public Solid/FOAF WebID profile documents in `text/turtle` format for active accounts, deliberately omitting credentials, email, roles, groups, and custom attributes.

## Interface
- `[http.go:Handler]` — `http.Handler` serving `GET` WebID Turtle documents from an `*identity.Store`.
- `[http.go:NewHandler]` — Constructs a `Handler` after validating the non-nil `identity.Store` and normalizing `issuer` via `oidc.NormalizeIssuer`.
- `[http.go:CanonicalProfilePath]` — Returns `<issuer>/auth/<subject>/profile` if `subject` is a valid single URL-safe path segment (`[A-Za-z0-9._~-]`, not `.` or `..`, max 512 bytes).

## Invariants
- Only `GET` requests without raw query strings or `RawPath` overrides are accepted; `Accept` headers are strictly parsed (bounded to 8 KiB / 32 ranges) and must allow `text/turtle`, `text/*`, or `*/*` with `q > 0` (contradictory equal-specificity ranges fail closed to the lowest `q`).
- Generated Turtle documents are strictly bounded to `8 KiB` (`maxDocumentBytes`) and escape string literals safely via `turtleLiteral`.
- Inactive or invalid subjects return `404 Not Found`.

## Side Effects
- Queries `identity.Store.AccountProfileBySubject` and writes HTTP security headers (`Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'`, `X-Frame-Options: DENY`) and Turtle body to `http.ResponseWriter`.

## Verification
- Run: `go test ./internal/webid`
