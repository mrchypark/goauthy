# Common ID branding

Administrators can open **Common brand** at `/auth/v1/admin/branding` (under
the configured issuer path) to set the common name, logo, light/dark colors,
and English/Korean login text. For a shared identity across two applications,
save `GoAuthy ID` as the common name and leave each application's theme and logo
unset. Both applications still authenticate through the same central account.

The common name is independent of the login title. Account sign-in uses the
common login text; device and connection approval pages keep their security
instructions. Central account and administration pages use the common name,
logo, and colors. App login uses its saved theme or inherits the entire common
theme when absent; its own logo wins independently over the common logo.
Removing an app override restores inheritance.

The common theme and logo have separate storage and HTTP endpoints. The theme
document still uses `goauthy` as its `client_id` for compatibility; that value
does not select an OAuth client on the common endpoints. Anonymous DCR reserves it alongside
the configured bootstrap client ID so dynamic registration cannot claim it.
Other client lookup and authority rules remain unchanged. Existing
administrator/CSRF guards and Clients-scoped API-key rights also protect common
settings, including atomic checks for revoked keys. SVG upload sanitization and
page CSP remain in effect.

Schema 114 adds the separate common-brand tables after bootstrap policy schema
113. It preserves the bootstrap policy and existing client records without
copying legacy branding or deciding its ownership.

**Upgrade:** Existing `goauthy` and `rauthy` client records are retained, but
are not automatically treated as common branding. Until an operator restores
the common theme and logo, pages use the built-in defaults. Back up the database
and inspect the records and matching OAuth clients before deciding ownership;
neither client existence nor an ID proves who owns a record. Do not run mixed
versions or roll back to binaries that still share the client namespace.
Until resolution, normal `goauthy` client reads do not claim legacy theme or
logo rows and instead use the common fallback; the inspection endpoints below
remain available to an administrator. Favicons are client-only and remain
readable and editable without resolution. If there is no legacy theme or
nonfavicon logo, the first authorized client-branding mutation records that
the namespace was empty, so subsequent edits do not need manual resolution.

For legacy `goauthy` records, a browser administrator with CSRF protection or a
Clients.Update API key can call `POST /auth/v1/branding/legacy/resolve` once with
`{"confirm_client_ownership":true,"copy_theme":true,"copy_logo":true}`.
Set each copy flag to `true` only after verifying that the corresponding legacy
data should also become the common brand. The operation copies without deleting
the legacy rows and marks those rows as client-owned, permitting subsequent
client branding edits and client deletion. If a destination already contains
data, the copy fails atomically; inspect and explicitly clear it before retrying.
If a request fails or times out, inspect both the common settings and the
resolution state before retrying because a committed response may be lost.
The common logo copy excludes favicons. A request with both flags false resolves
the rows as client-owned without restoring any common settings. This decision is
one-time; preserve the backup before invoking it. For `rauthy` or other IDs,
manually recreate the intended common settings in the common brand editor after
inspection; those client records are not changed.

Use authenticated `GET /auth/v1/branding/legacy` to inspect whether legacy and
common data exist and whether resolution completed. The protected
`GET /auth/v1/branding/legacy/theme` and `/auth/v1/branding/legacy/logo` expose
the legacy theme and small-or-SVG logo for inspection; the theme endpoint
returns built-in defaults when no legacy theme exists, so check status first.
Status and theme inspection require Clients.Read; logo inspection requires
Clients.Update. Independently inspect client existence and ownership.

Common API routes are `/auth/v1/branding/theme` (POST to read, PUT, DELETE),
`/auth/v1/branding/theme/{version}` (GET/HEAD CSS), and
`/auth/v1/branding/logo` (GET, PUT, DELETE). The existing client routes remain
client-scoped, including when a client ID is `goauthy`.

**Reset common theme to defaults** deletes the common theme document, restoring
the built-in `GoAuthy` name, colors, and login text. Logo changes save separately;
**Remove common logo** removes only the common logo. Fresh installations retain
the `GoAuthy` fallback until an administrator saves a name.

The admin JavaScript and page templates are embedded in the Go executable.
Rebuild and restart `cmd/goauthy` to expose the editor; saved settings themselves
take effect on subsequent page loads without a restart and survive a restart.
