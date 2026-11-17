# goauthy-upstream-fixture

## Overview
Deterministic, test-only HTTPS upstream identity provider fixture supporting both OIDC Authorization Code + PKCE (with EdDSA ID tokens) and GitHub-style OAuth endpoints (`[main.go:main]`).

## Interface
- Environment variables (`[main.go:configFromEnv]`):
  - `LISTEN_ADDR`: HTTPS listen address (default `:8443`)
  - `ISSUER`, `CALLBACK_URI`: Required exact HTTPS URLs
  - `GITHUB_CALLBACK_URI`: Optional exact HTTPS URL (derived from `CALLBACK_URI` if unset)
  - `CLIENT_ID`, `CLIENT_SECRET`: Required client credentials (`CLIENT_SECRET` >= 16 bytes)
  - `TLS_CERT_FILE` / `UPSTREAM_FIXTURE_TLS_CERT_FILE`, `TLS_KEY_FILE` / `UPSTREAM_FIXTURE_TLS_KEY_FILE`: Required TLS cert and key
  - `SUBJECT`: Subject claim value (default `"fixture-subject"`)
  - `ALLOW_MANAGED_CALLBACKS`: Set `"1"` to allow `/upstream/<24-alnum>/callback` redirect URIs
  - `ALLOW_TEST_CLAIMS`: Set `"1"` to allow `fixture_*` query parameters to inject test claims
- HTTP routes (`[main.go:handler.serveHTTP]`):
  - `GET /readyz`, `GET /jwks`
  - OIDC: `GET /authorize`, `POST /token`
  - GitHub-style: `GET /login/oauth/authorize`, `POST /login/oauth/access_token`, `GET /user`

## Invariants
- Generates an ephemeral Ed25519 signing keypair at startup (`kid: "fixture"`, `alg: EdDSA`) `[main.go:newHandler]`.
- Authorization codes are single-use (deleted before verification), expire after `codeLifetime` (`5m`), capped at `maxCodes` (`1024`), and require S256 PKCE `[main.go:handler.authorize]`, `[main.go:handler.token]`.
- `CLIENT_SECRET` must be at least 16 bytes `[main.go:configFromEnv]`.

## Side Effects
- Reads TLS cert/key files and binds an HTTPS server on `LISTEN_ADDR` `[main.go:main]`.
- Mutates mutex-protected in-memory `codes` and `githubTokens` maps `[main.go:handler]`.

## Verification
- Run: `go test ./...`
