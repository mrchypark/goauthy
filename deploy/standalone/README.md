# GoAuthy standalone Kubernetes profile

## Overview

This existing profile runs one GoAuthy StatefulSet pod with
`GOAUTHY_RHIZA_PROFILE=standalone` and Rhiza `Local: false`. GoAuthy's `data`
volume is an `emptyDir` bounded to 1Gi: it is a disposable recovery cache, not
durable application storage. `GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE=true` keeps
startup fail-closed unless the shared object store is configured. The separate
opt-in `standalone-local` (`Local: true`) archive contract is documented in
[`docs/no-pvc-dr.md`](../../docs/no-pvc-dr.md).

The overlay removes only the three-voter peer address, member list, and admin
token. It deliberately retains the object-store configuration, bucket-wait
init container, VersityGW service/statefulset/init job, and their policies. VersityGW's
PVC is an external-object-store test fixture for this manifest; it is not
GoAuthy's product data PVC.

This is only a storage/topology overlay. It retains every non-cluster
application setting from the HA manifest; `test.sh` compares the rendered
environment lists so a feature cannot silently disappear in standalone mode.

## Interface

- `kustomization.yaml` — Kustomize overlay referencing `../k8s`, `networkpolicy.yaml`, and patches (`statefulset-patch.yaml`, `service-patch.yaml`, `pdb-patch.yaml`, `delete-resources.yaml`).
- `test.sh` — Offline validation script comparing `deploy/standalone` and `deploy/k8s` renders with `kustomize`, `yq`, and `awk`.

## Invariants

- `StatefulSet/goauthy` has `replicas: 1`, zero `volumeClaimTemplates`, `emptyDir.sizeLimit: 1Gi` for `data`, `GOAUTHY_RHIZA_PROFILE=standalone`, `GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE=true`, and `PodDisruptionBudget` `minAvailable: 1`.
- Pod template retains `app.kubernetes.io/component: object-store-client` so `versity-ingress` admits TCP/9000.
- Rendered manifest must not contain `GOAUTHY_RHIZA_PEER_ADDR`, `GOAUTHY_RHIZA_MEMBERS`, `GOAUTHY_RHIZA_ADMIN_TOKEN`, or `peer` ports.
- Application environment variable names must match `deploy/k8s` (excluding `GOAUTHY_RHIZA_(PEER_ADDR|MEMBERS|ADMIN_TOKEN)`).

## Side Effects

- `test.sh` writes temporary rendered manifests via `mktemp` and removes them on `EXIT`.
- Applying via `kubectl apply -k deploy/standalone` creates/updates Kubernetes resources including the VersityGW test fixture PVC.

## Verification

- Run: `./deploy/standalone/test.sh`

## Usage & Operational Notes

Build or apply it with Kustomize:

```sh
kustomize build deploy/standalone
kubectl apply -k deploy/standalone
```

The overlay inherits the base Secret contract (`goauthy-secrets`) and the
base image name (`goauthy:e2e`); set the image in the rendered manifest or
through your normal image promotion workflow before applying to a cluster.
Run `./deploy/standalone/test.sh` to check the rendered topology and profile
constraints without contacting a Kubernetes cluster.

For the standalone cold filesystem-copy proof, run
`make e2e-standalone-backup-restore`. It gracefully stops the source process,
copies its local data directory, and starts a second process from that copy;
master keys and application secrets are provisioned separately. This script
does not configure or restore from an object-store prefix and does not prove
abrupt-loss or Kubernetes Pod-replacement recovery.

The inherited default-deny policy and this overlay's standalone policy permit
DNS-only egress. SMTP, upstream, SCIM, and other external integrations need
operator-added destination-specific NetworkPolicies; this profile does not
open general external egress by default.
