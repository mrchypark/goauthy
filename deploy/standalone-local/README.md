# GoAuthy standalone-local Kubernetes profile

## Overview
Kustomize overlay on [`../standalone`](../standalone/README.md) that configures GoAuthy with `GOAUTHY_RHIZA_PROFILE=standalone-local` (`Local: true` local-archive contract). It replaces the init container with `restore-local-archive` (`/goauthy-rhiza-init`), sharing `/var/lib/goauthy` (`emptyDir` 1Gi) and `/tmp` with the main `goauthy` container against the S3-compatible VersityGW fixture.

## Interface
- `kustomization.yaml` — Kustomize overlay referencing `../standalone` and applying `statefulset-patch.yaml`.
- `statefulset-patch.yaml` — Patches `StatefulSet/goauthy` (namespace `goauthy`, 1 replica) with `restore-local-archive` init container (`/goauthy-rhiza-init`) and sets `GOAUTHY_RHIZA_PROFILE=standalone-local`, `GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER=s3`, `GOAUTHY_RHIZA_OBJECT_STORE_PREFIX=goauthy-local`, `GOAUTHY_RHIZA_OBJECT_STORE_ENDPOINT=versity.goauthy.svc.cluster.local:9000`, `GOAUTHY_RHIZA_OBJECT_STORE_BUCKET=rhiza`, `GOAUTHY_RHIZA_OBJECT_STORE_REGION=us-east-1`, and `goauthy-secrets` S3 credentials.
- `test.sh` — Offline manifest validation script using `kustomize` and `yq`.

## Invariants
- `StatefulSet/goauthy` has `replicas: 1`, zero `volumeClaimTemplates`, `emptyDir.sizeLimit: 1Gi` for `data`, and a single init container `restore-local-archive` running `/goauthy-rhiza-init` with no args, `runAsUser: 65532`, and `readOnlyRootFilesystem: true`.
- `restore-local-archive` and `goauthy` must share the exact same container `image`, `data` and `sqlite-tmp` volume mounts, and identity/storage env vars (`SQLITE_TMPDIR`, `GOAUTHY_RHIZA_PROFILE`, `GOAUTHY_CLUSTER_ID`, `GOAUTHY_NODE_ID`, `GOAUTHY_DATA_DIR`, `GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE`, and `GOAUTHY_RHIZA_OBJECT_STORE_*`).
- Must not retain peer/cluster env vars (`GOAUTHY_RHIZA_MEMBERS`, `GOAUTHY_RHIZA_PEER_ADDR`, `GOAUTHY_RHIZA_ADMIN_TOKEN`), `peer` ports, operator/CRD resources (`RhizaCluster`, `CustomResourceDefinition`), or obsolete `--staging-dir`/`--mode=` flags.

## Side Effects
- `test.sh` creates a temporary file via `mktemp` and removes it on `EXIT`/`HUP`/`INT`/`TERM`.
- Applying the overlay via `kubectl apply -k deploy/standalone-local` mutates Kubernetes resources in namespace `goauthy`.

## Verification
- Run: `./deploy/standalone-local/test.sh`
