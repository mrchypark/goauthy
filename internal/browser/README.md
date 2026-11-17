# browser

## Overview
`internal/browser` manages peer-bound browser sessions, initialization/reauthentication flows, authorization interactions, issuer-scoped session/FedCM/browser-ID cookies, and session-derived CSRF tokens backed by `*rhiza.DB`.

## Interface
- `[store.go:ContextWithPeerIP]`, `[store.go:PeerIPFromContext]`: Context helpers carrying the client peer IP for session binding.
- `[store.go:SchemaStatements]`, `[store.go:LoginRecordSQL]`: SQL schema statements and login timestamp update query.
- `[store.go:Store]`, `[store.go:NewStore]`, `[store.go:Session]`, `[store.go:IssuedSession]`, `[store.go:UpstreamSessionBinding]`, `[store.go:AuthorizationInteraction]`, `[store.go:IssuedAuthorizationInteraction]`: Session and interaction store and domain types.
- `[store.go:Store.SessionAuthorizationGuard]`, `[store.go:Session.Authenticated]`, `[store.go:CheckPeerIP]`, `[store.go:CanonicalTokenDigest]`: SQL guard, authentication-state, peer-IP, and token-digest helpers.
- `[store.go:Store.CreateSession]`, `[store.go:Store.CreateUpstreamSession]`, `[store.go:Store.CreateInitSession]`, `[store.go:Store.CreateInitSessionWithAuthorizationInteraction]`, `[store.go:Store.CreatePasswordSession]`, `[store.go:Store.CreatePasswordMFASession]`: Session creation methods for init, password, MFA, and upstream-linked flows.
- `[store.go:Store.LoadSession]`, `[store.go:Store.LoadSessionReadOnly]`, `[store.go:Store.LoadSessionForPeer]`, `[store.go:Store.RefreshSessionForPeerIfTouchDue]`, `[store.go:Store.LoadSessionReadOnlyForPeer]`, `[store.go:Store.RevokeSession]`, `[store.go:Store.RevokeSessionID]`: Session loading, idle-touch refresh, and revocation.
- `[store.go:Store.CreateAuthorizationInteraction]`, `[store.go:Store.CreateAuthorizationInteractionForInit]`: Creates short-lived authorization interaction records.
- `[reauthentication.go:Store.LoadReauthenticationParent]`, `[reauthentication.go:Store.ConsumeReauthenticationInteractionByDigest]`, `[reauthentication.go:Store.CreateReauthenticatedSession]`, `[reauthentication.go:Store.CreateReauthenticatedPasswordMFASession]`: Reauthentication parent-session and interaction-consumption helpers.
- `[cookie.go:SessionCookie]`, `[cookie.go:CookieName]`, `[cookie.go:DeleteSessionCookie]`, `[cookie.go:FedCMSessionCookie]`, `[cookie.go:DeleteFedCMSessionCookie]`: Issuer-derived HTTP cookie builders and deleters.
- `[browser_id.go:ErrInvalidBrowserIDMode]`, `[browser_id.go:BrowserIDPolicy]`, `[browser_id.go:NewBrowserIDPolicy]`, `[browser_id.go:BrowserIDCookie]`, `[browser_id.go:BrowserID]`: Browser-ID cookie policy and extraction.
- `[csrf.go:ErrInvalidCSRFToken]`, `[csrf.go:DeriveCSRFToken]`, `[csrf.go:ValidateCSRFToken]`: Session-token-bound CSRF token derivation and validation.

## Invariants
- Peer-IP & issuer binding: Sessions are bound to `peerIP` (`LoadSessionForPeer`, `SessionAuthorizationGuard`) and cookies are scoped to `CookieName(issuer)`.
- Init vs. authenticated sessions: Init sessions (`Authenticated() == false`) cannot satisfy authenticated/admin guards.
- Session-bound CSRF: `[csrf.go:DeriveCSRFToken]` and `[csrf.go:ValidateCSRFToken]` bind CSRF tokens cryptographically to the active browser session token.

## Side Effects
- Reads and mutates browser session and authorization-interaction tables in `*rhiza.DB`.
- Constructs `http.Cookie` values for HTTP responses.

## Verification
- Run: `go test ./internal/browser`
