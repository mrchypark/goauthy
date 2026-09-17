# Registered OAuth standalone E2E

This is a test-only image with synthetic provider credentials. It reuses the
standalone application/SMTP/TLS harness and runs the real public owner APIs:
provider registration → collection/connection → PKCE authorization and callback
→ identity lookup → confidential consumer consent and access-token receipt →
explicit refresh → new-token receipt → stale-version rejection → consent revoke
and receipt denial → local connection revoke.
By default it repeats independent workflows after restarting GoAuthy; select the
active-restart profile below to verify preservation of the same connection.
Neither profile tests a downstream Beesuh/Conductor adapter. Consumer authentication uses a real GoAuthy user
authorization-code/PKCE token with the exact connections resource and use scope.
The image enables `GOAUTHY_E2E_OAUTH2_GRANT_UI=1`: Chromium creates the owner
consent after displaying provider/account/scopes and token-export warnings. The
test verifies no grant before approval and that editing the purpose resets review.
Set `GOAUTHY_E2E_OAUTH2_GRANT_SCREENSHOT` to a container-local path to capture the
review screen. Chromium trusts only the test issuer's pinned certificate SPKI.

`GOAUTHY_E2E_OAUTH2_ACTIVE_RESTART=1` selects a single continuous workflow:
the shell restarts only GoAuthy after the first version-1 receipt and again after
the version-2 receipt. The provider and test process remain alive, retaining
credentials in memory rather than serializing them. Empty request/ready markers
coordinate each restart; readiness and deadlines bound waiting, not assertions.
The same owner session, consumer token, connection and grant must still work;
each version must retain its exact access token across restart. Refresh must
still rotate the token, and provider counters must total one authorization, two
token exchanges and six identity lookups. This profile passed together with the
connection UI profile below in isolated Dory (5.79 seconds, 2026-09-07).

`GOAUTHY_E2E_OAUTH2_CONNECTION_UI=1` additionally starts authorization and performs
explicit refresh/local revoke using the account's OAuth controls. The caller still
drives the synthetic provider authorization/callback over HTTP, so this does not
claim to test a real external SaaS login page. Rebuild the image with current
sources before enabling it. Example flags for the `docker run` below:
`-e GOAUTHY_E2E_OAUTH2_ACTIVE_RESTART=1 -e GOAUTHY_E2E_OAUTH2_CONNECTION_UI=1`.

`GOAUTHY_E2E_OAUTH2_CALLBACK_UI=1` replaces the HTTP-client authorization/callback
step with real Chromium top-level navigation through the synthetic provider.
It checks the saved-connection HTML, no-store/no-referrer/frame headers, absence
of secret material, and the fixed return link back to the account page.
Set `GOAUTHY_E2E_OAUTH2_CALLBACK_SCREENSHOT` to a container-local screenshot path.
The provider still has no external SaaS login/consent UI.
Combined callback/connection/grant UI and active-restart profiles passed in
isolated Dory on 2026-09-07 (5.36 seconds); the completion screenshot was reviewed.

`GOAUTHY_E2E_OAUTH2_RECONNECT_UI=1` requires all three UI profiles and extends the
workflow with local revoke → prepare reconnect → new authorization → callback →
fresh explicit consent → version-3 receipt → revoke. The original grant is left
unrevoked until after reconnect, proving that the old generation cannot authorize
the new credential. It verifies a distinct generation in the new grant and rejects
a stale version-2 revoke. With active restarts the exact provider totals are two
authorizations, three token exchanges and eight identity lookups.
`GOAUTHY_E2E_OAUTH2_CONNECTION_SCREENSHOT` captures the revoked connection panel
before the reconnect action. This profile is not an additional HA/restart claim.
The combined reconnect profile passed on 2026-09-07 (5.99 seconds), with its
panel screenshot reviewed. Stale version-2 DELETE is a metadata-only 409;
the first run's incorrect 404 expectation was corrected against the existing
handler and boundary test before this final-source image was built.

```sh
sh scripts/e2e-preflight.sh host-capacity
docker buildx build --builder dory --load -f deploy/e2e-saas-oauth/Dockerfile -t goauthy-saas-oauth-e2e:local .
docker run --rm --network none --cap-drop ALL --cap-add NET_ADMIN --security-opt no-new-privileges --add-host oauth-provider.e2e.test:8.8.8.8 goauthy-saas-oauth-e2e:local
```

No host directories, Docker socket, host ports, or host network are mounted.
The runner first requires that only loopback is up and no IPv4/IPv6 default
route exists. The only other permitted interface is the kernel's DOWN `sit0`
tunnel; Ethernet and other interfaces are rejected. It assigns `8.8.8.8/32` **only to this container's loopback** and
binds the fixture there. There is no route to the actual external address.
GoAuthy's production resolver/IP restriction, TLS certificate verification and
redirect rejection remain unchanged. `NET_ADMIN` is needed only for the isolated
loopback alias; it is not a production application capability.

Dependencies are fetched while building; runtime uses `GOPROXY=off` and cannot
reach an external network. The temporary CA signs localhost and the fixture DNS
name. No real SaaS credentials are accepted by the fixture. `/stats` exposes only
counters and the test verifies exactly two token exchanges and four identity
lookups (two by GoAuthy and two using the delivered tokens). Each credential
receipt must cause no provider request. Missing authorization and another
confidential consumer's valid token are denied; consent revocation prevents
further receipt. Assertions use observed responses and counts, not sleeps; readiness
polling and test timeouts only bound startup/deadlock failures.

The fixture is not a general OAuth authorization server. Protocol behavior here
is synthetic test scaffolding built from the standard library; production code
continues to use `golang.org/x/oauth2` and the existing credential claim/commit
primitives. Full external-provider browser login, OAuth handoff, downstream consumer
adapters, HA and chaos remain separate gates.
