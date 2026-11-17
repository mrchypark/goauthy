# goauthy-saas-oauth-fixture

## Overview
Deterministic, test-only HTTPS OAuth 2.0 / OIDC-like SaaS provider and model endpoint fixture (`[main.go:main]`). Used to test GoAuthy's outbound SaaS OAuth token acquisition, refresh, and consumer model proxy flows.

## Interface
- Environment variables (`[main.go:configFromEnv]`):
  - `SAAS_OAUTH_FIXTURE_ADDR`: HTTPS listen address (default `:8443`)
  - `SAAS_OAUTH_FIXTURE_TLS_CERT_FILE`, `SAAS_OAUTH_FIXTURE_TLS_KEY_FILE`: Required TLS cert and key paths
  - `SAAS_OAUTH_FIXTURE_REDIRECT_URI`: Required exact HTTPS redirect URI
- HTTP routes (`[main.go:handler.serveHTTP]`):
  - `GET /authorize`: Issues single-use authorization codes with S256 PKCE for `fixtureClientID` (`"goauthy-saas-oauth-fixture"`).
  - `POST /token`: HTTP Basic authenticated (`fixtureClientID` / `fixtureSecret`) token endpoint supporting `authorization_code` and rotating `refresh_token` grants.
  - `GET /userinfo`: Bearer-authenticated endpoint returning `{"sub":"fixture-subject"}`.
  - `POST /v1/chat/completions`: Bearer-authenticated non-streaming synthetic chat completion target.
  - `GET /healthz`, `GET /stats`: Liveness and per-endpoint counter/failure statistics.

## Invariants
- `SAAS_OAUTH_FIXTURE_REDIRECT_URI` must be an exact HTTPS URL without userinfo, query, or fragment `[main.go:exactHTTPS]`.
- Authorization codes expire after `codeTTL` (`5m`), are single-use, and require S256 PKCE verification `[main.go:handler.authorize]`, `[main.go:handler.authorizationToken]`.
- Refresh tokens are single-use and rotated on each refresh `[main.go:handler.refreshToken]`.
- Client credentials are compared in constant time `[main.go:handler.basicAuth]`.

## Side Effects
- Reads TLS cert/key files and binds an HTTPS server on `SAAS_OAUTH_FIXTURE_ADDR` `[main.go:main]`.
- Mutates mutex-protected in-memory maps (`codes`, `access`, `refresh`, `stats`) `[main.go:handler]`.

## Verification
- Run: `go test ./...`
