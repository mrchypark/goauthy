# deploy

## Overview
Kubernetes/Kustomize deployment profiles, Kind cluster configurations, E2E test overlays, and fixture Dockerfiles for GoAuthy HA, standalone, and qualification environments.

## Subdirectories & Boundaries
- `k8s`: [./k8s/README.md](./k8s/README.md) - Base three-voter HA Kubernetes StatefulSet profile with VersityGW S3 fixture and NetworkPolicies.
- `standalone`: [./standalone/README.md](./standalone/README.md) - One-replica standalone overlay (`GOAUTHY_RHIZA_PROFILE=standalone`) with `emptyDir` cache and required object store.
- `standalone-local`: [./standalone-local/README.md](./standalone-local/README.md) - Opt-in `standalone-local` (`Local: true`) overlay using `restore-local-archive` init container against S3.
- `ternal-no-pvc`: [./ternal-no-pvc/README.md](./ternal-no-pvc/README.md) - Isolated Ternal no-PVC profiles (S3 HA, S3 standalone, GCS standalone, GCS HA).
- `ied-qualification`: [./ied-qualification/README.md](./ied-qualification/README.md) - Bounded live GCS qualification manifests (HA3 and standalone1) for candidate images.
- `e2e-beesuh-oauth`: [./e2e-beesuh-oauth/README.md](./e2e-beesuh-oauth/README.md) - E2E Beesuh OAuth consumer fixture Dockerfile and notes.
- `e2e-saas-oauth`: [./e2e-saas-oauth/README.md](./e2e-saas-oauth/README.md) - E2E SaaS OAuth consumer fixture Dockerfile and notes.
- `kind-admission`: [./kind-admission/README.md](./kind-admission/README.md) - Kind admission-check overlay and notes.
- `defaultaud`, `e2e-*`, `kind-*`: Feature-specific Kustomize overlays, Kind cluster/CNI configs (`kind-calico`, `kind-cilium`, `kind-dcr-anonymous`, `kind-issuer-path`, `kind-saas-isolation-113`, `kind-upstream`), and E2E fixture Dockerfiles (`e2e-s3-client`, `e2e-saas-isolation-113`, `e2e-ternal-device`, `e2e-tls`, etc.).
