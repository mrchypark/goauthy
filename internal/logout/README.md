# logout

## Overview
`logout` implements OpenID Connect RP-initiated logout validation (`Engine.Plan`) and the browser/backend HTTP handler (`Handler`) for revoking OIDC sessions, clearing browser/FedCM cookies, and rendering localized logout confirmation pages.

## Interface
- Errors and decision types: `ErrInvalidRequest`, `ErrInvalidHint`, `Action` (`ActionLogout`, `ActionConfirm`, `ActionRootRedirect`), `Client`, `Config`, `Request`, `Decision`, `Engine`, `New`, and `Engine.Plan` in [logout.go](file:///Users/cypark/Documents/project/goauthy/internal/logout/logout.go#L18-L148).
- HTTP handler: `Handler`, `ClientResolver`, `NewHandler`, `Handler.EnableFedCM`, and `Handler.ServeHTTP` in [http.go](file:///Users/cypark/Documents/project/goauthy/internal/logout/http.go#L40-L158).

## Invariants
- `Engine.Plan` validates `id_token_hint` signatures, issuer, audience, `azp`, and 32-byte base64url `sid` before authorizing logout or redirect; `post_logout_redirect_uri` must exactly match a registered client URI (HTTPS or loopback HTTP) ([logout.go:Plan](file:///Users/cypark/Documents/project/goauthy/internal/logout/logout.go#L117-L214)).
- `Handler` reloads JWKS public keys from Rhiza and resolves dynamic clients on every request so key rotation and client deletion take effect immediately ([http.go:Handler](file:///Users/cypark/Documents/project/goauthy/internal/logout/http.go#L37-L53), [http.go:plan](file:///Users/cypark/Documents/project/goauthy/internal/logout/http.go#L204-L241)).
- Confirmation `POST`s require an active browser session, `Sec-Fetch-Site: same-origin`, and a single-use `browser.Store` interaction token bound to `logout-` and the current subject ([http.go:confirm](file:///Users/cypark/Documents/project/goauthy/internal/logout/http.go#L331-L372)).
- `EnableFedCM(true)` requires an `https` issuer ([http.go:EnableFedCM](file:///Users/cypark/Documents/project/goauthy/internal/logout/http.go#L82-L91)).

## Side Effects
- Revokes OIDC sessions via `oauth.Server.RevokeOIDCSession`, creates/consumes `browser.Store` interactions, and sets expired session/FedCM cookies on the HTTP response.
- Sets strict security headers (`Cache-Control: no-store`, `X-Frame-Options: DENY`, CSP) on all responses.

## Verification
- Run: `go test ./internal/logout`
