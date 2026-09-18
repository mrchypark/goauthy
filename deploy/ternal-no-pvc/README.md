# Ternal-dedicated GoAuthy, no-PVC profiles

These isolated GoAuthy profiles are for Ternal only. They do not alter
`deploy/k8s` or `deploy/standalone`, deploy MinIO, create a PVC, or share the
default GoAuthy namespace, Secret, Rhiza cluster ID, or object-store prefix.

`deploy/ternal-no-pvc` is the three-voter HA profile. Its `standalone`
subdirectory is a one-member overlay: it removes every peer/member/admin-token
setting and peer port, while retaining the external S3 before-ack path and the
required object-store guard. Both use `emptyDir` for `/var/lib/goauthy`; the
external S3 checkpoint prefix is durable state. Neither profile claims that
empty-disk recovery or backup/restore has been qualified.

## Activation contract

Create these objects out of band in `ternal-auth`; the profiles never embed
secret values or a placeholder S3 target.

`ternal-goauthy-config` must contain non-empty production values for:

- `issuer` — exact public GoAuthy issuer, such as `https://auth.example.com`,
  with no trailing slash and not a copied Rauthy `/auth/v1/` path.
- `s3-endpoint`, `s3-bucket`, `s3-prefix`, `s3-region` — a dedicated external
  S3-compatible location. The prefix must be exclusive to this GoAuthy
  cluster; do not reuse an existing GoAuthy, Ternal, or test prefix.
- `bootstrap-client-id`, `bootstrap-redirect-uri`, `bootstrap-username` — the
  exact fixed Ternal client contract, not GoAuthy's local defaults.

`ternal-goauthy-secrets` must be type `Opaque` and contain dedicated
`master-key-ternal-1`, `oauth-hmac`, `bootstrap-client`,
`bootstrap-user-password-phc`, `rhiza-members`, `rhiza-admin-token`,
`s3-access-key`, and `s3-secret-key` values. HA `rhiza-members` must describe
exactly `ternal-goauthy-0` through `ternal-goauthy-2` at
`ternal-goauthy.ternal-auth.svc.cluster.local:8444`, with distinct voter
tokens. The standalone overlay does not read the member or admin-token keys.
The bootstrap user is intentionally a `ternal-admins` member with the
`rauthy_admin` administrator role.

The image `goauthy:ternal-no-pvc-candidate` is deliberately unbuilt and
unpublished. Replace it only with a reviewed, qualified immutable digest. Add
bounded egress to the resolved S3 endpoint (normally TLS TCP 443) and bounded
HTTP ingress from the actual gateway and Ternal namespaces. The included
policies otherwise allow only same-namespace HTTP, peer traffic for HA, and
DNS; they fail closed until those activation rules are supplied. NetworkPolicy
is a boundary only where the CNI enforces it.

Render and inspect either profile before any apply:

```sh
./deploy/ternal-no-pvc/test.sh
kustomize build deploy/ternal-no-pvc
kustomize build deploy/ternal-no-pvc/standalone
kustomize build deploy/ternal-no-pvc/gcs-standalone
kustomize build deploy/ternal-no-pvc/gcs-ha
```

Before accepting user traffic, verify rendered ConfigMap/Secret names and keys
without printing values, S3 write/read under the exclusive prefix, readiness,
authorization-code and device flows, and an empty-disk recovery rehearsal from
the S3 checkpoint.

## GCS standalone profile

`deploy/ternal-no-pvc/gcs-standalone` is the no-PVC standalone profile for
native GCS. It uses `GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER=gcs` and the generic
`object-store-bucket` / `object-store-prefix` ConfigMap keys. It deliberately
removes all S3 endpoint, region, access-key, and secret-key environment values;
native GCS is not an S3 compatibility mode.

The existing `ternal-goauthy` Kubernetes ServiceAccount is expected to receive
only its dedicated Workload Identity principal through the metadata service.
It remains `automountServiceAccountToken: false`; do not add a service-account
JSON key, `GOOGLE_APPLICATION_CREDENTIALS`, or a static cloud credential. The
bucket's `goauthy/` prefix must remain exclusive to this provider instance.
Actual metadata-service and GCS egress reachability still require IED runtime
validation before activation.

## GCS HA profile

`deploy/ternal-no-pvc/gcs-ha` is the three-voter HA profile for native GCS.
It reuses the base HA overlay (3 replicas, peer port 8444, PDB minAvailable
2) and replaces S3 object-store config with
`GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER=gcs`,
`object-store-bucket`, and `object-store-prefix` from the ConfigMap.

`ternal-goauthy-config` must contain `issuer`, `object-store-bucket`,
`object-store-prefix`, `bootstrap-client-id`, `bootstrap-redirect-uri`,
and `bootstrap-username`. `ternal-goauthy-secrets` must contain
`master-key-ternal-1`, `oauth-hmac`, `bootstrap-client`,
`bootstrap-user-password-phc`, `rhiza-members`, and `rhiza-admin-token`.
The S3 keys (`s3-endpoint`, `s3-region`, `s3-access-key`,
`s3-secret-key`) are not used.

The ServiceAccount needs Workload Identity access to the GCS bucket and
metadata-service egress. Do not apply this overlay over an existing
standalone deployment without an explicit migration plan. Rendering passes
all automated checks; this is not live qualification.

## S3 recovery regression check

`sh scripts/e2e-no-pvc-s3.sh` runs a disposable MinIO instance through the
local `dory` Docker context (override with `GOAUTHY_TEST_DOCKER_CONTEXT`).
It passed on 2026-09-07: the GoAuthy writer exits without closing Rhiza, then
a new process with an empty data directory recovers the account and signing
key through real S3 HTTP requests. Correct password acceptance, wrong password
rejection, and missing/wrong master-key rejection are checked. Credentials
are generated per run, passed without values in argv, and the fixture is
removed. This is standalone S3 protocol evidence, not an IED, production TLS,
HA, or end-to-end Ternal OAuth qualification. No real user account is created.
