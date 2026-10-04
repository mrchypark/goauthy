# Issue #113 manual CI calibration

This document describes the manual CI entry for the issue #113 local SaaS
isolation diagnostic. It is a calibration and reporting surface only. It does
not define a production SLO, does not establish a memory ceiling, and does not
close issue #113 automatically.

## Entry point

`.github/workflows/capacity-113.yml` is `workflow_dispatch` only. It has no
`push`, `schedule`, `pull_request`, or `pull_request_target` trigger, so it
never runs on its own. It requests `contents: read` and `packages: read` and
performs no release, deploy, package write, or foreign write. Dispatch it from
the branch that contains this workflow and the CI wrapper.

Inputs (both default to the reviewed pinned values):

| Input | Meaning | Default |
| --- | --- | --- |
| `candidate_image` | Immutable GoAuthy candidate image reference | `ghcr.io/mrchypark/goauthy@sha256:21c941913d6ae6333d59fa5da4dfc4d61ab2ecafa0eb9299ade01815d486c499` (v0.2.0, linux/amd64) |
| `candidate_source` | Reviewed GoAuthy source SHA | `944895a2b10b50275d6691e6b07d692414454f01` |

Inputs are passed to the shell through environment variables, never
interpolated directly into a `run:` script.

## What the run does

`scripts/run-capacity-113-ci.sh` is a CI-only POSIX `sh` setup wrapper. It:

1. Checks host capacity with `scripts/e2e-preflight.sh host-capacity`.
2. Creates one disposable Kind cluster from the pinned node image
   `kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5`,
   raises the node inotify limit, and verifies it with
   `scripts/e2e-preflight.sh kind-inotify`.
3. Pulls the pinned immutable candidate image and asserts its
   `org.opencontainers.image.revision` label equals `candidate_source`
   (fail-closed provenance). Both the workflow and the wrapper restrict
   `candidate_image` to `ghcr.io/mrchypark/goauthy@sha256:<64 lowercase hex>`.
   The sixth run confirmed the app container `ErrImageNeverPull`. The importer
   mechanism is inferred, not directly observed: Kind's `docker save` importer
   may not attach the original digest reference, so the canonical deployment
   reference may not resolve. The wrapper therefore loads a task-owned alias
   derived from the unique `KIND_CLUSTER` name, refusing to touch a pre-existing
   host tag, and first checks whether the canonical `name@sha256:...` reference
   already resolves at the CRI; only when absent does it attach that reference
   to the loaded image with `ctr --namespace k8s.io images tag`. It then
   requires the node config image ID (strict `sha256:<64 hex>`) to equal the
   host original config ID, failing fast on mismatch without overwriting an
   existing node identity, and removes only the tag this run created. The
   deployment keeps the exact canonical reference; the config blob (config ID)
   is preserved while the packaging/manifest digest may differ from the
   original registry manifest and is not claimed equal. The archive `RepoTags`
   were not captured, so the importer mechanism is inferred, not directly
   observed.
4. Generates ephemeral synthetic local credentials (bootstrap password, client
   secret, master key, OAuth HMAC, DCR token, Rhiza admin/voter tokens, Versity
   root credentials) with `openssl`. No credential is hardcoded or committed.
   The bootstrap password hash is derived with `cmd/goauthy-password`.
5. Applies the namespace and the synthetic `goauthy-secrets`, renders
   `deploy/k8s` to JSON, and sets only the GoAuthy StatefulSet to zero
   replicas and the immutable candidate image before the first apply, so the
   baseline never starts before the final overlay. It validates exactly one
   selected GoAuthy StatefulSet at zero replicas, then waits for Versity and
   `versity-init`.
6. Runs the existing `scripts/e2e-kind-saas-isolation-113.sh` diagnostic
   unchanged. Its security, durability, status, metrics, and resource oracles
   are not modified.
7. Derives every calibration output from the mandatory shared analyzer
   `scripts/summarize-e2e-kind-saas-isolation-113.sh` (see below).
8. Deletes only its own Kind cluster and restores the node inotify limit in a
   cleanup trap, including on failure.

The diagnostic itself builds the fixture and driver helper images from the
clean committed checkout and records their build/runtime pins.

## Mandatory shared analyzer

`scripts/summarize-e2e-kind-saas-isolation-113.sh` (with its companion
`.jq`) is a read-only shared calculator dependency. The wrapper
makes it mandatory: it stages the diagnostic directory (bridging the runner's
per-driver log naming to the analyzer's expected pattern), runs the analyzer,
and derives `criterion.json` and `resource-summary.json` from its schema. The
wrapper performs no latency or resource calculation of its own; all such
values come from the shared calculator.

The analyzer emits `schema_version: 1` with `overall.correctness`,
`overall.performance`, `protected.errors`, `denominators`, `fixture`,
`resources`, and `small_sample`. The wrapper maps:

- `criterion_pass = (overall.correctness == "pass" and overall.performance == "pass")`.
- `criterion_status = overall.performance` (`pass` / `fail` / `inconclusive`).

## Approved relative local initial criterion

The diagnostic phases (`baseline`, `mixed`, `recovery`) run in the same CI
execution, so the comparison is always within a single run. For IAM
`completion_latency_ms`, using the nearest-rank percentile method already used
by `docs/measurements/saas-isolation-113/summarize.jq`:

- `P95(mixed) <= max(1.25 * P95(baseline), P95(baseline) + 25ms)`
- `P99(mixed) <= max(1.5 * P99(baseline), P99(baseline) + 50ms)`
- Protected errors (IAM and API-key account) across all phases: `0`

The same comparison is reported for the `recovery` phase. This is a relative
local calibration criterion only; it is not a production SLO.

Because the per-run IAM sample is small (per driver: baseline 6, mixed 6,
recovery 4; aggregate 18/18/12 across the three driver pods), the report
always carries the counts and the nearest-rank percentiles so the small-n
effect is visible.

## Failure handling

- **Correctness fail-closed.** If `overall.correctness` is `fail` (protected
  errors, incomplete/excess denominators, or unexpected groups), the run exits
  nonzero after writing every safe aggregate. Correctness is never reported as
  passing.
- **Performance fail is reported, not hidden.** A latency breach sets
  `criterion_pass=false` and `criterion_status=fail`; the run stays green in
  calibration mode and the job summary states the criterion was not met. No
  qualification, capacity, or SLO claim is made.
- **Missing/malformed/all-failed baseline.** If the analyzer cannot produce a
  valid summary (missing fixture metrics, malformed observations, no driver
  records), the wrapper still writes a safe error `criterion.json`
  (`criterion_pass=false`, `overall.correctness=fail`), `pins.json`,
  `runner-environment.json`, `report.md`, and a `resource-summary.json` with an
  `available: false` unavailable-resource marker. No raw logs, stack traces, or
  container IDs are included.

## Safe aggregate outputs

The workflow uploads only the contents of `capacity-113-results`:

- `criterion.json` - analyzer-derived criterion, protected errors, denominators,
  performance comparisons, fixture aggregate, small-sample note, and overall
  status.
- `resource-summary.json` - analyzer-derived resource series, evidence, and
  ceiling (or an `available: false` marker when the analyzer is unavailable).
  It carries an additive `startup` object derived from the already-captured
  private `failure-capture/pods.json`: a `reason` field (`null` when available;
  otherwise one of `capture-missing`, `capture-invalid`, `projection-error`),
  a `pods_json_exit` field (the runner's `pods.json_exit` capture exit code as
  `null` or an integer `0..255`; malformed/duplicate/out-of-range -> `null`),
  plus `available`/`complete`/`observed` flags and a sparse `pods` array (only
  captured members, no synthetic absent records; `complete` requires sorted
  unique indexes `[0,1,2]` and exactly three entries). `available` requires a
  real `List`/`PodList` object with an array `items`; valid JSON that is not
  that shape is `capture-invalid`, and `projection-error` is reserved for actual
  transform failures. Each container view is bounded to a fixed role
  (`init`/`app`/`fixture`/`other`), a fixed phase (`Running`/`Waiting`/
  `Terminated`/`Unknown`), a bounded restart bucket (`0`/`1-2`/`3-5`/`6+`/
  `unknown`), and fixed waiting/terminated reasons (Kubernetes states such as
  `ErrImageNeverPull`, `CrashLoopBackOff`, `OOMKilled`, `Error`, `Completed`,
  `ContainerCreating`, `PodInitializing`, `ErrImagePull`, `ImagePullBackOff`,
  `CreateContainerConfigError`, `CreateContainerError`, `RunContainerError`,
  `InvalidImageName`, else `other`). Missing/absent status or restart counts
  yield `Unknown`/`unknown` without dropping other records; private fields
  (messages, image/container IDs, IPs, env, URLs, logs) are never emitted.
- `pins.json` - candidate image/source, helper source head, fixed helper build
  digests (`image_ref`/`manifest_digest`/`config_digest`/`loaded_image_id`),
  and fixture/driver runtime `image` and normalized `imageID` digests only.
  Arbitrary fields such as pod names are dropped.
- `runner-environment.json` - OS, kernel, arch, CPU count, memory total, and
  tool versions (including `awk` and `jq`).
- `report.md` - the human-readable summary also written to the job summary.

The upload step uses an explicit file allowlist (the five files above), not
the whole results directory, so no extra file can be uploaded. Never uploaded:
kubeconfig, private keys, TLS material, raw container samples, raw driver or
pod logs, captured failure state, rendered manifests, analyzer stderr, or any
secret. The raw evidence directory stays in the runner temporary space and is
deleted with the job.

## Pinned runner environment

The workflow reuses the action pins already present in the repository's other
workflows: `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`,
`actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e`, and
`docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f`.
`actions/upload-artifact` is pinned to `v4.4.3`
(`b4b15b8c7c6ac21ea08fcf65892d2ee8f75cf882`) because no existing workflow uses
an artifact action.

Client tooling is pinned and hash-verified before install (SHA256 checked with
`sha256sum`, not runner-image implicit tools):

- `kind` v0.32.0 linux/amd64, SHA256
  `50030de23cf40a18505f20426f6a8506bedf13c6e509244bd1fa9463721b0f54`.
- `kubectl` v1.35.3 linux/amd64, SHA256
  `fd31c7d7129260e608f6faf92d5984c3267ad0b5ead3bced2fe125686e286ad6`.
- `kustomize` v5.4.3 archive, SHA256
  `3669470b454d865c8184d6bce78df05e977c9aea31c30df3c669317d43bcc7a7`, verified
  before extraction.

The wrapper additionally fails closed if the installed `kind` is not `v0.32.0`
or `kubectl` is not `v1.35.3`, and it requires `awk` and `sha256sum` as
prerequisites. The Kind node image stays at `v1.36.1`; the client minor skew
(1.35.x client, 1.36.x node) is supported and introduces no new topology. The
job has a bounded `timeout-minutes: 150`.

Compatibility requirement: the pinned node image `v1.36.1` uses containerd
config version 4, which the older pinned client could not load. The first live
capacity run (`37163776231`, head `9a`) failed at `kind load` with
`ERROR: unknown containerd config version: 4`, before any workload or aggregate
result. `kind` v0.32.0 adds containerd config v4 support and defaults to the
same `v1.36.1` node image already pinned here, so the client is bumped to
v0.32.0 while the node image pin is unchanged (see the
[kind v0.32.0 release notes](https://github.com/kubernetes-sigs/kind/releases/tag/v0.32.0)).
This is a client compatibility fix only; it is not an IAM causal fix, SLO, GC
claim, or measured pass.

## Offline tests

- `scripts/test-e2e-kind-saas-isolation-113-summarize.sh` (owned separately)
  covers the analyzer's positive, missing-baseline, admitted-error, and
  fail-closed cases.
- `scripts/test-run-capacity-113-ci-summarize.sh` covers the wrapper's
  `--summarize` report-aggregation path, missing-baseline controls, the
  multi-document baseline transform, and startup observability (real separate
  `initContainerStatuses`/`containerStatuses`, fixed role/reason allowlist
  including `ImagePullBackOff`/`CreateContainerConfigError`, unknown strings as
  `other`, adversarial private fields absent, missing-status/null-restart
  retention, non-list-shape `capture-invalid`, and the `pods_json_exit`
  null-or-0..255 signal with malformed/duplicate/out-of-range -> `null`) offline.

Both run as a cheap step in the existing `Manifest checks` job of
`.github/workflows/ci.yml`, after a `jq` presence check. No required check is
removed, bypassed, or path-filtered. The capacity workflow additionally runs
`scripts/test-run-capacity-113-ci-summarize.sh` as an offline preflight on the
actual runner `jq` before any cluster setup, so a jq-grammar/version
incompatibility in the wrapper fails fast without provisioning Kind.

## Limitations

- Three logical GoAuthy members on one Kind node; no physical-host or
  production failure-tolerance claim.
- Versity is a local fixture; the profile is a lab-only routing technique.
- Default Kind kindnet does not enforce NetworkPolicy, so fixture egress
  enforcement is unverified.
- The candidate is a trace-instrumented local image; results do not qualify all
  OAuth routes, conditional refresh, production provider behavior, capacity, or
  an SLO.
- Calibration and reporting only; the workflow does not close issue #113.
- The live capacity run is not completed. The first dispatch `37163776231`
  (head `9a`) reached Kind cluster setup and candidate pull, then failed at
  `kind load` (`ERROR: unknown containerd config version: 4`) before any
  workload or aggregate result. After the client bump, the second dispatch
  `37164764400` passed `kind load` but failed in the wrapper baseline transform
  (`jq: Cannot iterate over null` on the multi-document `baseline.json`, exit 5),
  again before any workload or aggregate result. The third dispatch
  `37165483144`
  reached a readiness timeout with cause unknown because the private
  `failure-capture/pods.json` was not exported; the wrapper now derives a fixed
  allowlisted `.startup` view from that already-captured file (never exported)
  so a future readiness failure has a bounded, privacy-safe diagnosis. The
  fourth dispatch `37167408020` again failed at the 3-GoAuthy readiness stage
  and its safe `.startup` aggregate was still
  `available:false`/`complete:false`/`observed:false`, but the private capture
  is not exported so the actual root (missing/invalid capture versus projection
  failure) remains unknown; the `.startup` aggregate now distinguishes these via
  the `reason` and `pods_json_exit` fields. The fifth dispatch `37169046902`
  (head `c997`) failed at the 3-GoAuthy readiness stage with
  `.startup` `reason:projection-error`, `pods_json_exit:0`, `available:false`,
  which proved the capture command succeeded and the `List`/`items` array
  precheck passed while the transform jq itself failed. A compatibility defect
  was reproduced with jq 1.7.1: a bare comparison as an object value,
  `observed: (... | length) > 0`, fails to compile. The fifth run did not
  record its jq version or transform stderr, so its exact error is unverified.
  The projection now wraps that comparison in parentheses and the same program
  compiles on jq 1.7.1 and 1.8.1. The workflow runs the offline controls as a
  preflight on the actual runner jq before any cluster setup and records the jq
  version in `runner-environment.json`. The sixth dispatch `37170059233`
  (head `9b`) then reached readiness with the safe `.startup` aggregate
  `available/complete/observed:true`, `pods_json_exit:0`, all three indexes
  present, both init containers `Terminated`/`Completed` ready, the fixture
  sidecar `Running` ready, and the GoAuthy app container `Waiting`/
   `ErrImageNeverPull`. This isolates a local candidate image-reference
   resolution failure in the Kind CRI, not an app/Rhiza/runtime/latency defect.
   The observed `ErrImageNeverPull` is consistent with Kind's `docker save`
   importer not attaching the original digest reference, so
   `kind load docker-image name@sha256:...` may leave the canonical deployment
   reference unresolvable; the archive `RepoTags` were not captured, so this
   mechanism is inferred, not directly observed. The wrapper now loads a
   task-owned alias derived from the unique `KIND_CLUSTER` name (refusing to
   touch a pre-existing host tag), first checks whether the canonical reference
   already resolves at the CRI, and only attaches it with
   `ctr --namespace k8s.io images tag` when absent. It then requires the node
   config image ID (strict `sha256:<64 hex>`) to equal the host original config
   ID, failing fast on mismatch without overwriting an existing node identity,
   and removes only the tag this run created on all exits. The image config blob
   (config ID) is preserved; the packaging/manifest digest may differ from the
   original registry manifest and is not claimed equal. No workload or aggregate
   result was produced.
