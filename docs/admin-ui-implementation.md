# Browser admin UI implementation

The browser UI is served by `internal/admin.UI` under these page routes:

- `/auth/v1/admin/users` — live user list, detail/edit, create and subject-confirmed delete form.
- `/auth/v1/admin/roles` and `/auth/v1/admin/groups` — live listing, create, edit, and confirmed delete forms. Entity edit data is selected from the list because production exposes no entity `GET` route.
- `/auth/v1/admin/api-keys` — list/create, rights/expiry edit, rotate and confirmed delete. Plaintext secrets appear only after successful creation/rotation; an explicit Done action leaves the create view, with no forced timer or persistent browser storage.
- `/auth/v1/admin/scopes` and `/auth/v1/admin/attributes` — catalog CRUD, scope claim bindings/root flag, typed JSON attribute defaults, email type and self-editable flag.
- `/auth/v1/admin/sessions` — state filters, continuation pagination, single-session revoke, subject force logout and explicitly acknowledged global logout.
- `/auth/v1/admin/collections` — administrator-defined metadata schemas; `/new` creates and `/{id}/edit` edits (including ID `new`). User-owned draft CRUD lives in `/account`, not this administrator page.
- `/auth/v1/admin/app.js`, `/auth/v1/admin/admin.css` — same-origin embedded assets.
- `/auth/v1/admin/csrf` — startup-wired issuer-bound CSRF token handoff.

The screens call the production JSON APIs (`GET/POST/PUT /auth/v1/users`, user detail/update, and role/group CRUD). Those APIs remain the authorization and validation authority. Mutations wait for a real response before showing success. Empty, loading, and error states are represented in the UI, and all account/entity values are HTML-escaped before display.

## Startup wiring

`cmd/goauthy/main.go` mounts `UI.ServeHTTP` for `/auth/v1/admin/` alongside the
existing index and navigation. `adminCSRFTokenProvider` derives the
CSRF token from the issuer-specific cookie after the UI's live admin guard.
It never returns the raw session credential. The underlying composition is:

```go
ui, err := admin.NewUI(browserAdministrator)
if err != nil { return err }
ui.SetCSRFTokenProvider(func(w http.ResponseWriter, r *http.Request) bool {
    name, err := browser.CookieName(issuer); if err != nil { http.Error(w, "unavailable", 503); return false }
    cookie, err := r.Cookie(name); if err != nil { http.Error(w, "unauthorized", 401); return false }
    token, err := browser.DeriveCSRFToken(cookie.Value); if err != nil { http.Error(w, "unauthorized", 401); return false }
    w.Header().Set("Content-Type", "application/json")
    _ = json.NewEncoder(w).Encode(map[string]string{"token": token}); return true
})
```

Run the focused checks with `go test ./internal/admin`, `node --check internal/admin/admin.js`, and `node internal/admin/ui_regression_test.js`.

`TestAdminUIHTTPAcrossPods` passed on standalone and exact-three Kind; it covers
authenticated pages/assets/CSRF and real role/group create, visibility and deletion.
The dependency-free JS tests execute routing, DELETE CSRF, ordinary-user create,
update field preservation and exactly-once path decoding without wall-clock waits.

The user form also supports deletion, optional password changes, account-expiry
editing and city/phone fields. The backend still owns validation and authorization.
`TestAdminUIBrowserAcrossPods` passed against the standalone server in actual
Chromium (6.61s), including exact-created-user/role/group create/edit/delete,
persisted user-name verification, server-side deletion verification and cookie
access. It waits for populated lists and completed natural navigation, not
fixed sleeps or still-empty containers. See [status](status.md) for HA results.

User listing now consumes `X-User-Count`, `X-Page-Count`, `X-Page-Size` and
`X-Continuation-Token` for continuation links. User edit includes all seven
accepted `user_values` fields and validates expiry as a nonnegative safe integer.
Native controls and the existing response reader/CSRF helper are reused.

`TestAdminAPIKeyUIAcrossPods` exercises actual Chromium create/edit/rotate/delete,
Events-to-Clients rights changes and old/new/deleted credential effects on every
node. Its explicit fixture includes `ApiKeys:read` for the self-test endpoint;
a valid key without that right correctly returns 403. Node regressions verify
exact copyable secret text, explicit Done, expiry inputs and continuation links.
The API-key browser lifecycle passed in standalone and exact-three Kind;
see [status](status.md) for the final candidate logs and remaining chaos scope.

Remaining full-admin gaps include full profile policy discovery,
dedicated membership assignment screens, full client policy/provider/settings
screens and their feature-specific E2E. Password and expiry editor semantics need
their own browser value/boundary assertions; CRUD coverage is not that proof.

The managed-client core screen is now wired at `/auth/v1/admin/clients` with
Web/Device presets, all currently supported grant flows, CAS edits, explicit
secret read/hide/rotation, disable and delete. Its real Chromium standalone and
same-DB restart lifecycle passed; see [managed clients](managed-clients-implementation.md)
for the candidate HA gate and remaining full policy fields. The screen reuses
the existing API/CSRF helper and native forms without additional dependencies.

Catalog and sessions use small separate native scripts, embedded into the same
authorized `app.js` response before the existing dispatcher. They reuse its
single `api()`/CSRF/escaping helpers. Their deterministic Node checks execute
request mapping and cancellation/error handling. The global-logout success view
does not fetch again with the now-revoked admin session. This UI does not change
the server's revocation or authorization scope.

`TestAdminCatalogSessionsUIAcrossPods` exercises catalog CRUD with typed defaults
and claim bindings, then revokes a specific ordinary session. The same ordinary
cookie must access `/account/data` before revocation and receive 401 afterward
on every configured node. An ordinary user's denial on an admin route would not
prove session revocation. Global/subject logout UI live tests, pagination boundary
UI tests and interruption of each mutation remain distinct gaps; existing API
coverage does not automatically establish browser coverage.

Known follow-up: the catalog's `/new` page sentinel conflicts with an existing
scope/attribute literally named `new`; that reserved-name editing path needs a
distinct create URL and browser regression. General admin issuer-prefix routing
and full small-screen/device coverage also remain unfinished. The broad admin
feature must not be checked off on the strength of the successful fixture names.

Authentication collections reuse the existing admin/account asset and CSRF
boundaries. Native controls, JSON arrays for enum options, and JSON reviver
source context/BigInt preserve whitespace and int64 metadata without another UI
or parsing package. The browser rejects unsafe-number reads if the native source
context is unavailable. These are draft metadata screens, not credential editors.
`TestAuthCollectionsUIAcrossPods` exercises real create/edit/delete, disabled
definitions, stale-record input preservation, and typed metadata round trips.
The standalone/restart, exact-three/pod-replacement, and 1280/375 viewport gates
passed on the final candidate; [authentication collections](auth-collections.md) tracks evidence,
explicit UI limitations, package rationale and the remaining SaaS/agent work.
