# apidocs

## Overview
`internal/apidocs` generates and validates the deployment's OpenAPI 3.0.3 specification from checked-in Go contracts and serves a read-only Swagger UI at `/auth/v1/docs/`.

## Interface
- `[http.go:Admin]`: Authorization callback `func(http.ResponseWriter, *http.Request, bool) bool` used when docs are configured as private.
- `[http.go:Handler]`, `[http.go:NewHandler]`, `[http.go:ServeHTTP]`: HTTP handler serving `/auth/v1/docs/`, `/auth/v1/docs/openapi.json`, and embedded Swagger UI assets from `github.com/swaggo/files/v2`.
- `[spec.go:Features]`: Feature-flag struct (`DCR`, `Passkeys`, `Recovery`, `OpenRegistration`, `Blacklist`, `WebID`, `FedCM`, `Upstream`, `DCRAnonymous`, `FedCMLanding`) controlling which optional routes appear in the spec.
- `[spec.go:Document]`: Builds, resolves internal `$ref`s, validates via `openapi3.Loader`, and marshals the OpenAPI 3.0.3 JSON document for the given `issuer` and `Features`.

## Invariants
- Issuer validation: `[http.go:NewHandler]` requires an absolute `http` or `https` URL with no userinfo, query, or fragment; `[spec.go:Document]` normalizes the issuer via `oidc.NormalizeIssuer`.
- Private-mode guard: When `public` is `false`, `[http.go:NewHandler]` requires a non-nil `admin` callback, and `[http.go:Handler.ServeHTTP]` gates every request through `admin(w, r, false)`.
- Read-only & query-free: `[http.go:Handler.ServeHTTP]` allows only `GET` and `HEAD`, rejects any query string (`400 Bad Request`), and configures Swagger UI with `supportedSubmitMethods: []` and `validatorUrl: null`.
- No remote schema fetching: `[spec.go:Document]` builds all paths and schemas from local Go catalog definitions without external `$ref` resolution.

## Side Effects
- Writes HTTP responses with strict security headers (`Cache-Control: no-store`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and restrictive `Content-Security-Policy`).

## Verification
- Run: `go test ./internal/apidocs`
