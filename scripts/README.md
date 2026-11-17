# scripts

## Overview
Operational, E2E orchestration, chaos, backup/restore, SaaS isolation, and qualification shell/Python scripts for GoAuthy. These scripts drive local `go` binaries, Docker/Podman (`dory`), Kind clusters, `kustomize`/`kubectl`, and CI summary pipelines.

## Interface
- **Standalone & Kind E2E Runners**: `e2e-*-standalone.sh`, `e2e-*-kind.sh`, `e2e-standalone.sh`, `e2e-tls.sh`, `e2e-v038-readiness.sh`, `e2e-preflight.sh`, `e2e-port-lock.sh`, `e2e-journal-entrypoint.sh`, `e2e-stage-supervisor.sh`, `verify-isolated.sh` (plus `test-e2e-*.sh`, `test-verify-isolated.sh`).
- **Backup, Restore & Storage Verification**: `e2e-kind-backup-restore.sh`, `e2e-standalone-backup-restore.sh`, `e2e-no-pvc-s3.sh`, `test-backup-age.sh`, `test-backup-pause.sh`, `test-backup-pause-copy.sh`, `test-backup-rotation.sh`, `test-backup-schedule-clock.sh`, `test-object-store-contract.sh`, `test-rhiza-local-upgrade.sh`, `test-k8s-ha-manifest.sh`.
- **Chaos & Network Fault Injection**: `e2e-network-chaos.sh`, `e2e-network-chaos-calico.sh`, `e2e-pod-restart-chaos.sh`, `e2e-scim-delete-chaos-kind.sh`, `test-e2e-tc-capability.sh`, `test-e2e-tc-oracles.sh`.
- **SaaS Isolation & Capacity 113 Harnesses**: `e2e-kind-saas-isolation-113.sh`, `e2e-kind-saas-isolation-113-node-pins.sh`, `e2e-kind-saas-isolation-sample.sh`, `run-capacity-113-ci.sh`, `collect-saas-isolation-113-auth-stage.sh`, `summarize-*.sh`/`.jq`, `capacity-113-oci-archive-identity.sh`, `test-saas-isolation-113-*.sh`, `test-e2e-kind-saas-isolation-*.sh`, `test-capacity-113-oci-archive-identity.sh`, `test-confirmation-proof.sh`, `test-run-capacity-113-ci-summarize.sh`.
- **IED Qualification & Consumer Probes**: `e2e-ied-gcs-candidate.sh`, `e2e-ied-gcs-candidate.py`, `e2e-ied-cni-probe.sh`, `test_ied_gcs_candidate.py`, `ternal_consumer_probe.py`, `test_ternal_consumer_probe.py`, `e2e-s3-client.sh`, `e2e-saas-oauth-isolated.sh`.
- **Stage Supervisor Source**: [`./e2e-stage-supervisor-src/README.md`](./e2e-stage-supervisor-src/README.md) — Go source for the process-group supervisor cached at `~/.cache/goauthy-stage-supervisor/` by `e2e-stage-supervisor.sh --prepare`.

## Invariants
- `e2e-stage-supervisor.sh` builds with `GOENV=off GOWORK=off CGO_ENABLED=0` and requires `--prepare` before non-prepare invocations can `exec` the content-addressed binary.
- Test/validation scripts (`test-*.sh`, `test_*.py`) verify harness logic and contracts offline without mutating production clusters.

## Side Effects
- E2E and Kind runners build binaries, create/delete Kind clusters or Docker containers, acquire port locks, and write logs/artifacts to temporary or `testdata/` directories.
- `e2e-stage-supervisor.sh --prepare` writes a content-addressed binary under `${HOME}/.cache/goauthy-stage-supervisor/`.

## Verification
- Run: `sh scripts/test-e2e-port-lock.sh` (or individual `scripts/test-*.sh` / `python3 -m unittest` scripts; `cd scripts/e2e-stage-supervisor-src && go test ./...` for supervisor tests)
