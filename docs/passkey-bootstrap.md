# Bootstrap passkey policy

Passkeys are an opt-in feature. GoAuthy creates the passkey service only when
the complete `GOAUTHY_PASSKEY_RP_ID`, `GOAUTHY_PASSKEY_ORIGINS`, and
`GOAUTHY_PASSKEY_KEY_FILE` configuration is present. With that configuration
absent, the initial/bootstrap administrator continues to use the existing
password login and no WebAuthn routes are mounted.

`GOAUTHY_BOOTSTRAP_FORCE_MFA=true` is the explicit exception: startup requires
valid passkey configuration so the existing user-verification flow can be
completed. A forced-MFA deployment never starts in a configuration that would
silently fall back to password-only login. With the flag unset (the default),
passkeys may be configured for optional enrollment without forcing the
bootstrap administrator to enroll or use one.

`GOAUTHY_FORWARD_AUTH_HEADERS=true` is independent of passkey configuration.
It enables the existing identity headers, and emits
`X-Forwarded-User-MFA: false` when passkeys are disabled. When passkeys are
enabled, that header reflects whether the subject has an enrolled credential;
the option does not create another MFA mechanism or weaken the existing
forward-auth checks.

## Listing and browser verification

`GET /auth/v1/users/{subject}/webauthn` uses the Rauthy list wire shape:
`name`, integer Unix-second `registered` and `last_used`, and optional
`user_verified`. Empty lists are `[]`, not `null`. This is an HTTP DTO; the
internal credential still uses `time.Time`. Fixed-time handler tests and the
OpenAPI response use the same exported `account.PasskeyResponse` type.

Run the real Chrome virtual-authenticator management flow with:

```sh
make e2e-standalone-admin-passkey
make e2e-kind-admin-passkey KIND_CLUSTER=goauthy-passkey-wire E2E_PORT=20910 GOAUTHY_IMAGE=goauthy:passkey-wire GOAUTHY_BACKCHANNEL_SINK_IMAGE=goauthy-backchannel-sink:passkey-wire
```

The shared flow registers a credential, checks API-key reads, rejects API-key
deletion, consumes a self-service MFA proof, deletes the credential and checks
the empty list on every supplied peer. Standalone supplies one URL; the HA
gate supplies three distinct pod forwards. This gate does not assert pod
replacement or network-partition recovery.

An explicitly enabled E2E fails if Chrome or its required CDP WebAuthn
capabilities are unavailable. It logs the actual browser version instead of
silently skipping after a Chrome major-version update. The regular Go suite
still skips live tests unless their opt-in environment flag is set.
The management profiles use a long session idle lifetime; exact expiry belongs
in injected-clock tests, not in a race against a ten-second browser deadline.

The Kind profiles apply `deploy/k8s/passkey-cookie-key-patch.yaml` after adding
the selected `passkey-key` Secret item. Kubernetes `fsGroup` makes projected
secrets group-readable, which the cookie-key loader deliberately rejects.
The non-root init container reads only the selected item and copies it to a
memory-backed volume as UID 65532 with mode `0400`; the application mounts it
read-only at `/run/passkey/passkey-key`. The loader's regular-file, owner-only,
32-byte and same-file checks remain intact. Secret changes require pod
replacement to refresh this copy; automatic CookieKey rotation is not implied.

Whole passkey/admin parity remains incomplete; see
[the user-management checklist](user-management.md).
