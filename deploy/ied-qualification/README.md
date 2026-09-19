# IED GCS qualification harness

Bounded, live qualification for the latest candidate image against GCS with
HA3 (3-member cluster) and standalone1 (single-member). This harness owns
scripts/e2e-ied-gcs-candidate.sh and deploy/ied-qualification/ only.
It does not modify deploy/ternal-no-pvc, production secrets, or any existing
workload.

## Candidate image

Current frozen candidate:

    ghcr.io/mrchypark/ternal@sha256:cf6b1d862e7a6cd6dfa6bc3543aed498d9c0701e6593f8191052d7d4c3bfb6bf

Source: commit a9b712c3, linux/amd64, scratch base, UID 65532.
Built via local dory cross-compilation. Parent pushes the immutable digest;
the harness applies it verbatim.

## What it creates (all owned, all cleaned up)

All resources live in existing namespace ternal-auth and reference
existing SA ternal-goauthy (Workload Identity).

- HA3: StatefulSet goauthy-qual-0917, Service goauthy-qual-0917,
  Secret goauthy-qual-secrets, PDB min 2, NP goauthy-qual-ha3-ingress-peer
- Standalone1: StatefulSet goauthy-qual-s1-0917, Service goauthy-qual-s1-0917,
  Secret goauthy-qual-s1-secrets, PDB min 1, NP goauthy-qual-s1-ingress
- Shared: ConfigMap goauthy-qual-config

Labels: app.kubernetes.io/part-of=goauthy-qual-0917 (HA3) or
goauthy-qual-s1-0917 (standalone1). Never part-of: ternal.

## GCS object store

Provider: native GCS (GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER=gcs).
No S3 endpoint, region, access-key, or secret-key.
ADC through Workload Identity via existing ternal-goauthy SA.

- HA3 prefix: goauthy/qualification/0917-unique
- Standalone1 prefix: goauthy/qualification/s1-0917-unique

Both prefixes must be exclusive to this qualification run.

## Limitations

- No physical node cordon/stop. Anti-affinity is requiredDuringScheduling
  but only if the cluster has enough nodes.
- No PVC. Data is emptyDir. Durability depends on GCS checkpoint recovery.
- No production secrets. All fixtures generated locally per run.
- No external OIDC. Bootstrap user only.
- NetworkPolicy requires a CNI that enforces it.
- GCS metadata egress (TCP 443 to googleapis.com) depends on node access.

## Manifest validation

    ./deploy/ied-qualification/test.sh

## Running (after parent review)

    GOAUTHY_QUAL_GCS_BUCKET=bucket-name ./scripts/e2e-ied-gcs-candidate.sh
