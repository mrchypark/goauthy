# Ternal local GoAuthy candidate — 2026-09-07

Local build complete; no registry publication or IED deployment was performed.
This is a candidate, not full Rauthy parity or production qualification.

## Artifact identity

- Local image: `goauthy:ternal-csp-candidate-20260907`
- OCI index: `sha256:54ddb4239b0236ea0adf8e7f0700a6ea9c300724aeb0b2b282f93c7c8606fbe6`
- Runtime manifest: `sha256:0c4cf4d32497dc87327f431a5f53a69e19b2dc1d84d64bf6517ab23ad8931f44`
- Config: `sha256:6cdbfcb3622677ef0e23b2c2a5986db53b2837f4dab094a21373ba96e66ca507`
- Platform: linux/amd64; scratch runtime; UID/GID 65532:65532.
- Extracted binary SHA-256: `2455ad138d341fd3107816ae0c3b90529bd108210b93e4e0ea844474545a13d8`.
  `file` confirms statically linked x86-64 ELF. `go version -m` confirms Go1.27.1,
  GOOS=linux, GOARCH=amd64, CGO_ENABLED=0, Rhiza v0.12.0.

The local index digest is not evidence of availability in any registry. The
Ternal task owns any subsequent authorized publication to its repository and
must verify the resulting registry digest before deployment.

## Complete selected source identity

Snapshot: `/tmp/goauthy-candidate-20260907.IgxSUc/source`.
It contains Dockerfile, .dockerignore, go.mod, go.sum and complete cmd/internal
directories, including untracked source. No Git metadata, host settings or
runtime data are part of this selected build context. No symlinks were found.
The 684-entry `../source.sha256` manifest covers every regular file; checksum
verification against the copied context passed. Source manifest SHA-256:
`5351941df0f9af0fb13f012d69754a1284d22cc01c8fed405239dec20864661b`.

- go.mod: `15d4bfcf24c3b15c6706ae721dc01486f3cfd445d811a6b119d762943875bb96`
- go.sum: `8aa4da74b1e400a8a9a4afd69d994ed97836fa0aa444b8f2ba618f1b7e95d09d`
- Snapshot Dockerfile: `538f67b8e96652ba2cb14fab0e3d63200ff09b3346576152347a0edb098ca17c`

The only snapshot recipe change is pinning the existing Go builder image to
`golang:1.27-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125`.
The workspace Dockerfile is unchanged. Its recipe cross-compiles on the arm64
builder using TARGETOS/TARGETARCH; arm64 in provenance describes the builder,
not the verified amd64 runtime artifact. The initial Git commit omits current
untracked sources and is not used as provenance.

```sh
docker buildx build --builder dory --platform linux/amd64 --load \
  --metadata-file /tmp/goauthy-candidate-20260907.IgxSUc/build-metadata.json \
  -t goauthy:ternal-csp-candidate-20260907 \
  /tmp/goauthy-candidate-20260907.IgxSUc/source
```

Build exited 0. Log: `/tmp/goauthy-candidate-20260907.IgxSUc/build.log`.
BuildKit reference: `dory/dory/cvxem7xxfg9ds3o4w0vxbocyk`.
Metadata records the pinned base, index and provenance. Snapshot/manifest/log
remain local and should be retained with any handoff; this is not a claim of
bit-identical rebuilds or independently signed provenance.

## Compatibility and qualification boundaries

The CSP change uses only the validated callback origin on the authorization
login page; it introduces no configuration or schema migration. The complete
candidate nevertheless includes schema 79 and all selected current source.
Startup migrates the database before serving. v79 rebuilds use-handoff rows to
admit credential delivery; this is not a guarantee of arbitrary older deployed
schema upgrade or downgrade compatibility.

Existing no-PVC standalone profiles remain source-compatible: one Rhiza member,
emptyDir local data, required external object storage and before-ack durability.
S3 uses dedicated endpoint/bucket/prefix/region and paired credentials. Native
GCS uses bucket/prefix with ADC/Workload Identity and rejects S3/static GCP
credential configuration. The selected profile needs its existing dedicated
issuer/client/master-key/HMAC settings and operator-supplied ingress/egress.
Do not change these secrets or share object prefixes as part of image adoption.
The no-PVC render checker passed in the read-only compatibility review.

Source-equivalent native Chromium login, PKCE exchange, JWKS ID-token/nonce
verification, UserInfo and post-revocation 401 passed before/after standalone
restart (3.70/1.27s). Full login package passed 80.554s. These runs used the
earlier arm64 source-overlay harness, **not this amd64 runtime image**.

An exact-image execution probe on local Dory (`--platform linux/amd64`,
`--network none`, `--read-only`, no mounts) failed before application startup:
`exec /goauthy: exec format error`, exit 255. The container exited and was
removed. This arm64 host cannot execute the amd64 candidate in its present
configuration; no emulation/host setting was installed or changed. This is not
an application startup or functional test. An authorized amd64 runner is needed
to qualify this exact image; the artifact must not be marked runtime-qualified.

Remaining: amd64 candidate runtime qualification, actual Ternal web-session
completion, deployed-schema upgrade/rollback, GCS empty-disk recovery and IED
network/identity checks. Existing local S3 recovery evidence is not native GCS
or IED evidence. No HA rolling-upgrade or new chaos qualification is claimed.
