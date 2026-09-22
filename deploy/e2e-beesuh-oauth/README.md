# Real Beesuh OAuth consumer bridge

This opt-in test overlays a GoAuthy-owned harness into a selected Beesuh checkout.
The actual Beesuh Runtime and OAuth delivery adapter perform two model calls for
each receipt check. GoAuthy's existing registered-provider lifecycle supplies the
owner, confidential consumer, consent and authorized refresh. Revoked or obsolete
grants must result in zero provider model calls. The synthetic provider accepts
only access tokens it actually issued; refresh tokens are rejected at the model
endpoint. No real SaaS credentials belong in this test.

The consumer checkout is external to GoAuthy. Pin its source manifest, resolved
module files, and any Rhiza replacement before qualification; a local unpublished
checkout is not a reproducible public consumer release. Copy only reviewed source
files to the build contexts. Do not copy `.git`, credentials, local databases or
configuration. Do not edit the user's original consumer module files.

Prepare two source snapshots, `$BEESUH_SNAPSHOT` and `$RHIZA_SNAPSHOT`. The consumer
snapshot's resolved `go.mod`/`go.sum` must be read-only-buildable and its Rhiza
replacement, if used, must point at `/rhiza`. Record source and module SHA256
manifests outside the image. Both images below must contain the same GoAuthy SHA.

```sh
sh scripts/e2e-preflight.sh host-capacity
docker buildx build --builder dory --load \
  -f deploy/e2e-saas-oauth/Dockerfile -t goauthy-saas-oauth-e2e:base .
docker buildx build --builder dory --load \
  -f deploy/e2e-beesuh-oauth/Dockerfile \
  --build-arg GOAUTHY_E2E_IMAGE=goauthy-saas-oauth-e2e:base \
  --build-context beesuh="$BEESUH_SNAPSHOT" \
  --build-context rhiza="$RHIZA_SNAPSHOT" \
  -t goauthy-beesuh-oauth-e2e:candidate .
sh scripts/e2e-preflight.sh host-capacity
docker run --rm --network none --cap-drop ALL --cap-add NET_ADMIN \
  --security-opt no-new-privileges \
  --add-host oauth-provider.e2e.test:8.8.8.8 \
  -e GOAUTHY_E2E_OAUTH2_GRANT_UI=0 \
  goauthy-beesuh-oauth-e2e:candidate
```

The inherited entrypoint verifies isolated networking before assigning the public
unicast fixture address to this container's loopback. Never add that address or a
route on the host. Runtime dependencies are already downloaded; `GOPROXY=off`
and `GOSUMDB=off` remain inherited. No host ports, directories or Docker socket
are mounted. The runtime harness uses private temporary files for the human token
and fixture CA, suppresses child output, and checks model dispatch counters.

The example uses owner HTTP APIs for consent. For the existing graphical
reconnect profile, enable `GOAUTHY_E2E_OAUTH2_GRANT_UI=1`,
`GOAUTHY_E2E_OAUTH2_CONNECTION_UI=1`, `GOAUTHY_E2E_OAUTH2_CALLBACK_UI=1` and
`GOAUTHY_E2E_OAUTH2_RECONNECT_UI=1`. These flags select additional evidence, not
an assertion that it has passed. Keep ordinary and graphical results distinct.

Current status: fixture unit tests and both sides of harness compilation passed.
Live bridge execution, final source/dependency pinning, reconnect and complete
negative-case qualification remain open in issue #96. The earlier prototype
image does not contain the corrected native provider base URL and must not be
used as final evidence. Host capacity must meet the 12GiB preflight for a new run.
