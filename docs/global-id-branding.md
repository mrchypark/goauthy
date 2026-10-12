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

The theme and logo stores persist common settings under the canonical `goauthy`
branding ID. It is not an OAuth client, but anonymous DCR reserves it alongside
the configured bootstrap client ID so dynamic registration cannot claim it.
Other client lookup and authority rules remain unchanged. Existing
administrator/CSRF guards and Clients-scoped API-key rights also protect common
settings, including atomic checks for revoked keys. SVG upload sanitization and
page CSP remain in effect.

**Reset common theme to defaults** deletes the common theme document, restoring
the built-in `GoAuthy` name, colors, and login text. Logo changes save separately;
**Remove common logo** removes only the common logo. Fresh installations retain
the `GoAuthy` fallback until an administrator saves a name.

The admin JavaScript and page templates are embedded in the Go executable.
Rebuild and restart `cmd/goauthy` to expose the editor; saved settings themselves
take effect on subsequent page loads without a restart and survive a restart.
