# Two local apps sharing one GoAuthy ID

`goauthy-demo` is a small local relying party. Run it twice with separate confidential managed clients and cookie names to demonstrate signing in to both apps with one GoAuthy account.

The bundle enables `-force-login` only for Demo A. Each A sign-in sends OIDC `prompt=login` so GoAuthy displays its login page, including after app logout. Demo B keeps the default mode and reuses the GoAuthy session for SSO. This changes only the authorization request; app logout still leaves the provider and the other app signed in. The flag defaults to false and does not depend on the client ID.

| App | URL | Managed client | Registered redirect |
| --- | --- | --- | --- |
| GoAuthy Demo A | http://localhost:18081/ | `goauthy-demo-a` | `http://localhost:18081/callback` |
| GoAuthy Demo B | http://localhost:18082/ | `goauthy-demo-b` | `http://localhost:18082/callback` |

Both use issuer `http://localhost:18080`, scopes `openid email profile`, and authorization code with S256 PKCE. The issuer's existing `internal/oidc.VerifyIDToken` verifies EdDSA signatures through public JWKS, exact issuer, receiving-client audience and expiration. The RP additionally checks nonce and any access-token hash. It displays only verified subject/email and login status, and does not call UserInfo or keep raw tokens in sessions.

Each pending login has random state, verifier, nonce and a separate browser binding, a five-minute expiry and a single-use callback. Session and transaction cookie names include the client ID because localhost cookies ignore port numbers. Cookies are HttpOnly and SameSite=Lax, with separate opaque in-memory app sessions. Signing out of one app leaves the other app and the GoAuthy session signed in. App sessions expire with the verified ID token and are lost on app restart. These HTTP/localhost fixtures are not production relying parties.

Pages use `Referrer-Policy: strict-origin`: native form POSTs retain the app's Origin for the exact-origin logout check while referrers disclose no path or query. `no-referrer` would make the form send `Origin: null`, which logout rejects. Missing, null and other-app Origins remain rejected.

## Run from the repository

With GoAuthy running and the two confidential managed clients registered with the
redirects above, save each client secret in an owner-only regular file. Set
`DEMO_A_SECRET_FILE` and `DEMO_B_SECRET_FILE` to those file paths, then run each
command from the repository in a separate terminal:

```sh
go run ./cmd/goauthy-demo -name 'GoAuthy Demo A' -listen 127.0.0.1:18081 \
  -client-id goauthy-demo-a -client-secret-file "$DEMO_A_SECRET_FILE" -force-login
# In another terminal:
go run ./cmd/goauthy-demo -name 'GoAuthy Demo B' -listen 127.0.0.1:18082 \
  -client-id goauthy-demo-b -client-secret-file "$DEMO_B_SECRET_FILE"
```

## Existing local acceptance bundle

For a separately prepared native bundle at
`$HOME/.local/share/goauthy/local-v0.3.3`, the examples below reuse its local
acceptance tools. `goauthy-local`, `register-demo-clients`, `configure-demo-users`,
`verify-local` and `verify-demo-users` are not provided by this repository; these
commands assume that bundle and its dependencies already exist. Registration
uses authenticated browser-admin endpoints and CSRF; it creates only the two
named clients, checks any existing configuration and preserves existing secret
files. It never uses raw SQL, rotates credentials, resets accounts or replaces
keys.

The configured ordinary account signs in with **`demo-user@goauthy.local`**, using the private `secrets/demo-user-password` file in that bundle. `demo-user` is its preferred display username, not its password login identifier. Both demo clients require the group prefix `demo-service-users`; the ordinary account belongs to that group, has no roles, and the bootstrap administrator has no matching group. The existing prefix policy controls admission rather than excluding admin roles globally.

```sh
b="$HOME/.local/share/goauthy/local-v0.3.3"
"$b/register-demo-clients"

# Run serially in the repository, after coordinating the local Go build slot.
GOWORK=off GOCACHE="$b/build-cache" GOTMPDIR="$b/tmp" GOMAXPROCS=2 \
  go test -mod=readonly -p=2 ./cmd/goauthy-demo
GOWORK=off GOCACHE="$b/build-cache" GOTMPDIR="$b/tmp" GOMAXPROCS=2 \
  GOOS=darwin GOARCH=arm64 go build -mod=readonly -buildvcs=false -p=2 \
  -trimpath -o "$b/bin/goauthy-demo" ./cmd/goauthy-demo

# Initial setup only; preserve pre-existing aliases.
test -e "$b/bin/goauthy-demo-a" || ln -s goauthy-demo "$b/bin/goauthy-demo-a"
test -e "$b/bin/goauthy-demo-b" || ln -s goauthy-demo "$b/bin/goauthy-demo-b"
"$b/goauthy-local" apps-start
"$b/goauthy-local" apps-status
```

Managed-client secrets are protected files at `secrets/goauthy-demo-a-client-secret` and `secrets/goauthy-demo-b-client-secret`; registration does not print their values. It uses the existing initial admin password file, so after a manual admin password change, authenticate registration with the current credential rather than resetting the account.

The executable can also run directly from a terminal:

```sh
"$b/bin/goauthy-demo" -name 'GoAuthy Demo A' -listen 127.0.0.1:18081 \
  -client-id goauthy-demo-a -client-secret-file "$b/secrets/goauthy-demo-a-client-secret" -force-login
# In another terminal:
"$b/bin/goauthy-demo" -name 'GoAuthy Demo B' -listen 127.0.0.1:18082 \
  -client-id goauthy-demo-b -client-secret-file "$b/secrets/goauthy-demo-b-client-secret"
```

## Browser proof

Open Demo A, click **Sign in with GoAuthy ID**, and authenticate on GoAuthy's branded login page. Confirm the app's **Signed in · Identity verified** status and subject/email. Then open Demo B in the same browser profile and click its sign-in button. GoAuthy's existing authenticated browser session should complete the second authorization without entering credentials again. Confirm equal verified subjects in A and B, distinct client IDs and separate app cookies. Sign out of A and click its sign-in button again: GoAuthy's login page should be shown while B remains signed in. This actual browser sequence is the acceptance check; mocked token tests alone do not establish live SSO or interactive login.

Focused tests reject wrong state/binding, replay, expired transactions, wrong issuer/audience/nonce, expired tokens, untrusted signatures and disallowed algorithms. A synthetic provider test exercises PKCE/client authentication, verified account rendering, opaque cookies, no credential rendering and local-only logout.
