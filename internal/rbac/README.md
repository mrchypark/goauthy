# RBAC & Admin HTTP Boundary (`internal/rbac`)

## Overview
Persists roles, groups, subject memberships, and static bootstrap client login restrictions in Rhiza, and exposes the browser-admin and account-management HTTP endpoints (users, sessions, forced logouts, managed OAuth clients, auth collections, SaaS providers/connections/use-grants, device sessions, and SSE event streams).

## Interface
- `[store.go:Store]`, `[store.go:NewStore]`, `[store.go:Entity]`, `[store.go:Principal]`, `[store.go:BootstrapClientLoginRestriction]` — Core RBAC persistence and membership resolution (`ResolvePrincipal`, `IsAdmin`, `EnsureBootstrapPrincipal`, `CreateRole`/`UpdateRole`/`DeleteRole`, `CreateGroup`/`UpdateGroup`/`DeleteGroup`, `PatchPrincipal`, `UpdateBootstrapClientLoginRestriction`, plus `*APIKey` and `*ForAdmin` variants).
- `[store.go:AdminRole]` (`"goauthy_admin"`), `[preferred_username.go]` / validation helpers: `ValidateRoleName`, `ValidateGroupName`, `ValidateGroupPrefix`.
- `[http.go:Handler]`, `[http.go:NewHandler]` — Browser-session-authorized HTTP handler with optional bindings (`BindClients`, `BindDeviceSessions`, `BindAuthCollections`, `BindUserCreation`, `BindSaaSProviders`, `BindSaaSProviderStore`, `BindSaaSCredentials`, `BindConnectionUseResource`, `BindConnectionUseAuthorizer`, `BindConnectionHandoffAuthorizer`, `BindConnectionResourceAuthorizer`, `BindProviderResourceAuthorizer`, `SetPasskeyService`, `SetUserListThreshold`, `SetUserValuesPolicy`).
- HTTP endpoints on `[http.go:Handler]`: `Roles`/`Role`, `Groups`/`Group`, `PatchUserMembership`, `LoginRestriction`, `Users`/`User`/`CreateUser`/`UpdateUser`/`UpdatePreferredUsername`, `AdminConvertPassword`, `AdminRegisterPasskey`, `Sessions`/`DeleteSessionByID`/`ForceLogoutUser`/`LogoutAllSessions`, `Clients`/`Client`/`ClientSecret`/`RotateClientSecret`, `AuthCollections`/`AuthCollection`/`AccountAuthCollections`/`UserResourceAuthCollections`, `SaaSProviders`/`SaaSProvider`, `AccountConnections`/`AccountConnection`/`AccountConnectionAPIKey`/`AccountConnectionOAuth2*`/`AccountConnectionUseGrants*`/`ConnectionCredentialStatus`/`DeliverConnectionCredential`/`RefreshConnectionCredential`/`InvokeConnectionGrant`/`CreateConnectionHandoff`/`ConnectionHandoffPage`/`OwnerConnectionHandoff`/`UserResourceConnection*`, `AccountDevices`, `EventsQuery`/`EventsStream`/`EventsTest`, `UserValuesConfigHandler`.
- Request/response & listing options: `[user_list_http.go:DefaultUserListThreshold]`, `[user_list.go:UserListOptions]`, `[user_list.go:UserResponseSimple]`, `[user_create_http.go:UserCreateRequest]`, `[user_update_request.go:UserUpdateRequest]`, `[user_update_request.go:UserValuesRequest]`, `[user_detail.go:UserResponse]`, `[user_detail.go:UserValuesResponse]`, `[session_list.go:SessionListOptions]`, `[saas_providers_http.go:SaaSProviderInfo]`.
- Sentinels: `[store.go:ErrInvalid]`, `[store.go:ErrNotFound]`, `[store.go:ErrConflict]`, `[store.go:ErrReserved]`, `[store.go:ErrUnauthorized]`, `[store.go:ErrInactiveSubject]`, `[store.go:ErrTooManyMemberships]`.

## Invariants
- `[http.go:Handler]` authorizes every request from the current browser session and rejects cross-site requests and raw queries where disallowed; request bodies never supply an actor or privilege-bearing subject.
- `[store.go:Store]` enforces optimistic concurrency via `revision`, caps subject memberships at `64` (`maxMemberships`), and protects `AdminRole` (`"goauthy_admin"`) from deletion/rename (`ErrReserved`).
- `[store.go:Store.BindAPIKeys]` is a startup-only seam for API-key-authorized admin mutations; browser requests continue to use the session/CSRF boundary.

## Side Effects
- Reads and mutates RBAC, identity, browser session, device, OAuth client, auth collection, and SaaS connection/grant tables in `*rhiza.DB`.
- Emits audit/event-log records and streams SSE events via `EventsStream`.

## Verification
- Run: `go test ./internal/rbac`
