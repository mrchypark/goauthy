# Container Publishing

This project publishes a production container image to GHCR via the `Publish container` workflow.

## When it runs

- **Automatically**: after a successful `CI` push run on `main`.
- **Release tag**: pushing a `vMAJOR.MINOR.PATCH` tag at current `main`, after that exact commit passes CI.
- **Manually**: via `gh workflow run publish.yml --ref main` (must be run against `main`).

## What it produces

- Tags: `latest` and `sha-<full-sha>` for `linux/amd64`, plus the release tag (for example `v0.1.0`) on release runs.
- To retry publication of an existing release tag: `gh workflow run publish.yml --ref main -f version=v0.1.0`. The tag must resolve to the current main commit; the same CI and vulnerability-scan gates apply.
- A tag pushed before CI succeeds fails closed; retry after CI completes.
- OCI labels for source repository and revision.

## Security gates

- Grype scans the built image; high/critical vulnerabilities fail the build.
- Before pushing, the workflow re-verifies `main` HEAD still points at the source SHA.

## Usage

Pull by tag:

```
docker pull ghcr.io/mrchypark/goauthy:latest
docker pull ghcr.io/mrchypark/goauthy:sha-<full-commit-sha>
```

Pin by digest for reproducibility:

```
docker pull ghcr.io/mrchypark/goauthy@sha256:<digest>
```

The digest is printed in the workflow run summary.

## Scope

This workflow publishes the default production image only. It does not deploy to Kubernetes, trigger Cloud Build, or affect the existing `ternal` package.
