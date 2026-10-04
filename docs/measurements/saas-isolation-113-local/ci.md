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
   reference may not resolve. The wrapper therefore loads a cluster-scoped,
   task-owned alias (a fixed default on the fresh, disposable CI host; it
   refuses a pre-existing cluster or host tag), and first checks whether the
   canonical `name@sha256:...` reference
   already resolves at the CRI; only when absent does it attach that reference
   to the loaded image with `ctr --namespace k8s.io images tag`. It then
   requires the node config image ID (strict `sha256:<64 hex>`) to equal the
   host original config ID, failing fast on mismatch without overwriting an
   existing node identity. The retained host tag keeps the original digest
   lookup alive until EXIT; the alias is not passed to the host inspect. The
   alias is removed only once, with its own Kind node, by the EXIT cleanup trap
   on normal and error exit (removing it midrun can drop the image content the
   host still needs). A SIGKILL may leave the owned alias behind; the next local
   run fails closed and requires manual cleanup, and no unrelated tag is
   auto-deleted. The
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
6. Runs `scripts/e2e-kind-saas-isolation-113.sh`, which builds the fixture and
   driver helper images from the clean committed checkout and records their
   build pins. After `kind load` it takes early config-bound node pin snapshots
   of both helper images: an exact fixed-reference lookup inside the owned Kind node
   CRI where the same object's `status.id` must equal the saved archive config
   digest, with strict associated `repoDigest` hashes stripped to unique
   sha256 digests (an absent `repoDigests` field is treated as empty; a
   provided non-array value is rejected). After the overlay and readiness it
   snapshots the candidate the same way and asserts the app pods: expected
   ref, `Running`, ready, exactly three unique pods `0`/`1`/`2` and exactly
   three nonblank rows, each normalized `imageID` digest equal to the known
   config/manifest digest or a verified node digest. After the driver job
   completes it refreshes the driver node pin snapshot before runtime
   verification. Helper runtime pins preserve exact refs, count, and unique
   pod names.
7. Derives every calibration output from the mandatory shared analyzer
   `scripts/summarize-e2e-kind-saas-isolation-113.sh` (see below).
8. Deletes only its own Kind cluster and restores the node inotify limit in a
   cleanup trap, including on failure.

The diagnostic's resource sampler
(`scripts/e2e-kind-saas-isolation-sample.sh`, shipped in
`7ab96a95e47ea907447c443c2a7149bbe10edac6`) writes pod JSON to a private
`0600` owned TMPDIR file, validates an exact single object with an `items`
array, and uses `jq --slurpfile` so no giant argv is built. Its EXIT
cleanup trap preserves streamed output and the original failure status; normal
TERM shutdown exits 0.
malformed or multi-document JSON is fatal nonzero, while an actual kubectl
command failure keeps the unavailable rows. Focused offline controls (13
cases, sh syntax PASS) cover pod JSON larger than 2 MiB, six series, current IDs, RSS,
private `0600`, TERM, and error cleanup.

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

The CI wrapper derives `iam_failure_diagnostics` (shipped in
`c2c439d8dbaf9594139e2844d0b08d5f192bb9c7`): a diagnostic-only allowlist on
the existing private driver fatal prefix `connection_use_grant_test.go:digits`
mapping to a fixed reason enum, numeric HTTP `100..599`, or `null`. Safe
`criterion.json`/`report.md` carry these plus actual shared
outcomes/statuses/fault_routes. Per-driver aggregation runs once;
`phase_error_counts` is a separate observation count (no raw-fatal-to-phase
association). Diagnostics are complete only for exact recognized errors with
no unknown/excess; missing/unrecognized/extra is `incomplete`, and an
analyzer-unavailable result is `unavailable` — not an additional acceptance
criterion. The sampler uses a private JSON slurpfile (not argv); normal
waiting logf is skipped; private body/URL is not exported or classified (URL
stripped before the timeout test). No Go, app, shared-calculator, oracle,
timeout, retry, or security change. Focused offline controls (34 cases, sh
syntax PASS) cover the allowlist. Static shared labels such as `deferred_to_ci`
in actual artifacts are legacy descriptive metadata; they are not a claim that
no CI execution occurred.

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
  performance comparisons, fixture aggregate, small-sample note,
  `iam_failure_diagnostics`, and overall status.
- `resource-summary.json` - analyzer-derived resource series, evidence, and
  ceiling (or an `available: false` marker when the analyzer is unavailable).
  It carries an additive `startup` object derived from the already-captured
  private `failure-capture/pods.json`: a `reason` field (`null` when available;
  otherwise one of `capture-missing`, `capture-invalid`, `projection-error`),
  a `pods_json_exit` field (the runner's `pods.json_exit` capture exit code as
  `null` or an integer `0..255`; malformed/duplicate/out-of-range -> `null`),
  plus `available`/`complete`/`observed` flags and a sparse `pods` array (only
  captured members, no synthetic absent records; `complete` requires sorted
  unique indexes `[0,1,2]` and exactly three entries). `available` requires an
  object with an array `items` (the precheck does not require a literal
  `List`/`PodList`); valid JSON that is not
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
  fixture/driver runtime `image` and normalized `imageID` digests, and
  `candidate`/`fixture`/`driver` `node_pins` carrying only the whitelisted
  `config_digest` and `runtime_digests` hashes. Arbitrary fields such as pod
  names are dropped; raw CRI objects and private fields are never emitted.
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
   cluster-scoped, task-owned alias (a fixed default; the fresh disposable CI
   host refuses a pre-existing cluster or host tag), first checks whether the
   canonical reference already resolves at the CRI, and only attaches it with
   `ctr --namespace k8s.io images tag` when absent. It then requires the node
   config image ID (strict `sha256:<64 hex>`) to equal the host original config
   ID, failing fast on mismatch without overwriting an existing node identity.
   The owned alias is retained through every later host candidate use and
   removed only once by the EXIT cleanup, because removing it midrun can drop
   the image content the host still needs. The image config blob
   (config ID) is preserved; the packaging/manifest digest may differ from the
   original registry manifest and is not claimed equal. The seventh dispatch
   `37171888645` (head `cfa`) reached the new canonical loader and logged
   `candidate image loaded: config_id=sha256:aff79de4... reference=ghcr.io/
   mrchypark/goauthy@sha256:21c9419...` before failing a later host candidate
   lookup (`No such image` on the exact canonical reference) with no workload
   result; that failure came from the midrun alias removal now fixed,
   and no app/Rhiza/runtime/latency defect is inferred. The eighth dispatch
   `37172298984` (head `d2f`) passed the canonical config, host lookup, and
   helper stages: both init containers `Terminated`/`Completed`, the fixture
   sidecar `Running` with a `0` restart bucket, and all three GoAuthy app
   containers `Waiting`/`CrashLoopBackOff` in the `3-5` restart bucket, then a
   `Ready` timeout at 240s (`FAIL`). No workload metrics were
   produced, IAM latency and protected-error counts were not measured, and no
   qualification claim is made. Source inspection identified a guaranteed
   credential-encoding blocker that prevents startup: the actual
   `internal/oidc/keys.go:190` decodes the master key with `RawURLEncoding`
   requiring exactly 32 bytes, so a standard padded Base64 value is always
   rejected; the adjacent OAuth HMAC consumer `internal/oauth/server.go:309`
   has the same `RawURLEncoding`/32-nonzero requirement. Both are now generated
   as 32 crypto-random bytes encoded as unpadded URL-safe Base64 (43 chars). The
   actual source generator pipeline was executed and checked to emit 43
   URL-safe characters decoding to 32 bytes for both values without printing
   either secret; shell syntax and diff checks passed and the source consumer
   validators are unchanged. No raw fatal log is available for this analysis,
   so this document does not claim the exact stderr was observed, that all app
   causes are resolved, or that the measurement passed. All eight failures
   (1-8) remain documented. The ninth dispatch `37174512852`
   (head `528ea6f`, same candidate) passed the canonical config guard
   (`config_id=sha256:aff79de4...`) and reached all three GoAuthy pods `Ready` at
   `03:43:07Z`, with the app container `Running`/ready/`restarts:0`, then failed a
   fixture pin jq mismatch before any workload ran. The fallback report is
   `criterion_pass=false` with `overall.correctness=fail` (fail-closed) and
   `overall.performance=inconclusive` (resources likewise inconclusive); protected
   errors were not measured and no request counts or IAM latency were produced, so no
   performance PASS is claimed. Focused source reviews approved the encoding fix;
   the historical fatal message remains unproved. The helper/fixture
   pin mismatch's actual digest is unknown and is being investigated without
   weakening the strict pin; the next diagnostic adds an expected-vs-allowlisted
   observed digest comparison and does not predict a PASS. The eight prior
   failures (1-8) remain documented.
10. [Run 37176080305](https://github.com/mrchypark/goauthy/actions/runs/37176080305),
    helper `af798a03a20d285ee23f54d4c8e4dbb51bad4bb2`, again reached app readiness
    and failed before workload. The new safe diagnostic observed three pins with
    all helper references matching, but the common runtime digest was
    `sha256:a7bb98dd7c05a8b86fb6be4c81c5d993ebc9ebcd56bddcd7bbdab93f86a6c36b`,
    different from the recorded fixture build manifest
    `sha256:bd226f0a454616d50a38346b87ffa5e89f95d8e6c9d6743c60d9bdd8729c78c1`
    and archive/host config
    `sha256:d6cd0a9804b06340e062ae35b82d750419fac8ff4e51c9099bf7ac4c67ff2be9`.
    This proves a mismatch in the current two-digest predicate, not the node's
    image content or an import serialization mechanism. The correction must
    independently bind the node image config to the saved helper config before
    trusting associated runtime digests.
    No workload counts, protected-zero-error result or latency qualification
    was obtained; all ten outcomes are retained.
11. [Run 37178290180](https://github.com/mrchypark/goauthy/actions/runs/37178290180),
    head `f5f908a` (exact shipping commit
    `f5f908a674fd170c03c540c3c6aad65d4c6335bd`), reached all three GoAuthy app
    containers `Running`/ready/`restarts:0`, then failed before any workload at
    `04:58:55Z` (diagnostic exit 1). The fixture config
    `444fd1ff17356c1157f188f1a924e3522c62a1a2b4e3f2409affe1dbd00ee963` matched
    the archive config, and the verified node runtime digest
    `18648b0fca3266cf1510fc5252ff0c9a6fd13089347edd0890833dc464ebac76` matched
    all three fixture pods. The driver's early config-bound snapshot had
    `runtime_digests` empty. The app's old manifest-or-config-only predicate
    rejected the observed node runtime digest
    `b6759e473094338fddba0bb70c88a65ee0945147fc259459c49d02829a2d42d2` before
    the workload. No app runtime digest content was verified in this failed run,
    and no causal import mechanism is claimed. No IAM traffic, latency, request
    denominators, or protected errors were measured; these are explicitly NOT
    MEASURED and must not be read as zero errors. The follow-up commit
    `013784cab964244a48891575a48358bcf36c5edc` is source-only and is not a
    measured result. All ten prior failures (1-10) remain
    documented; issue #113 stays OPEN with resource ceilings and the production
    SLO unapproved, GC disabled, and three logical members on one physical CI
    node.
12. [Run 37179836342](https://github.com/mrchypark/goauthy/actions/runs/37179836342),
    shipping commit `013784cab964244a48891575a48358bcf36c5edc`, created
    `05:25:22Z`, failed `05:33:59Z` (diagnostic exit 1, analyzer exit 5). All
    three GoAuthy app pods reached `Ready` with `restarts:0`. The candidate
    node config
    `aff79de4d18cf163652837ba1f17331c4d71ed266ded63a8eb94ddc55ee8a224` equaled
    the archive config, and the strict node digest set
    `21c941913d6ae6333d59fa5da4dfc4d61ab2ecafa0eb9299ade01815d486c499` and
    `b6759e473094338fddba0bb70c88a65ee0945147fc259459c49d02829a2d42d2` passed.
    All three fixture node digests were
    `04040bc91c3cd1e0b592fbd30548e379abc824a58f730dc4681759e2ee4938da` with
    node config `96053ef20fbb0027fddb5bc4ab1b1c17de718c10c1bd8b4cb9a7312cb232c0f1`
    equal to the archive config. All three driver pods matched the known config
    `5177363448efc4b8c6952eb8500b9394d4d851d763f5933980fa5bbe1197c5a4` and
    passed the post-job refreshed proof. The app/helper pin verification passed.
    The workload driver job completed at `05:33:54Z`; the subsequent sampler
    exited 126 with output missing or empty, so the analyzer was unavailable
    (exit 5) and the run fail-closed with correctness `fail` and performance
    `inconclusive`. No analyzer-derived request denominators, latency, or
    protected errors are available: NOT MEASURED, not zero errors. The raw
    sampler stderr is private and not exported; the exact historical 126 cause
    is unconfirmed. The source git mode is 100755; no permissions failure is
    claimed. The source fix has landed in
    `7ab96a95e47ea907447c443c2a7149bbe10edac6`; the old `013` sampler was
    independently shown to fail on valid pod JSON larger than 2 MiB
    (Darwin argv-limit error, exit 1); this does not establish the
    historical CI 126 direct cause (raw stderr missing). All twelve outcomes
    (1-12) are retained; issue #113 stays OPEN with resource ceilings and the production
    SLO unapproved, GC disabled, and three logical members on one physical CI
    node.
13. [Run 37183331751](https://github.com/mrchypark/goauthy/actions/runs/37183331751),
    helper `7ab`, head `7ab96a95e47ea907447c443c2a7149bbe10edac6`, created
    `06:37:11Z`, finished `06:47:49Z` (job `111380114402`). The safe analyzer
    exited 0 and the diagnostic exited 1: overall correctness `FAIL` with 2
    protected errors and `criterion_pass=false`. All three app pods were
    `Running`/ready/`restarts:0` and the node C+D proof passed. The driver job
    `Complete` wait (220s) timed out at `06:47:34Z`; the job condition is not
    exported so no failed-job assertion is made. 78 observations were
    complete: 48 IAM (46 success, 2 errors — recovery driver 1 and 2 each 1)
    and 30 API-key (15 account success, 15 fault-request errors; the exact
    fault HTTP status is not exported, so no `15x502` claim is made). Fixture
    started/completed 30, active 0. Resources: 6 series, 192 timestamps, 1152
    valid rows, 0 unavailable_non_rss. The relative IAM six comparisons passed
    (small n 6/6/4); quantiles use successful observations only (failed
    latencies excluded, not a stable SLO) while counts include errors.
    Nearest-rank IAM P95=P99 (ms):

    | Driver | Baseline (n) | Mixed (n) | Recovery (n) |
    | --- | --- | --- | --- |
    | 0 | 12052.431 (6) | 10846.452 (6) | 10652.646 (4 success) |
    | 1 | 10749.838 (6) | 9275.725 (6) | 9954.741 (3 success, 1 error) |
    | 2 | 10749.428 (6) | 9276.009 (6) | 10955.105 (3 success, 1 error) |

    Thresholds (P95/P99 ms): driver 0 `15065.53875`/`18078.6465`; driver 1
    `13437.2975`/`16124.757`; driver 2 `13436.785`/`16124.142`. App peak
    working-set bytes: 0=`206213120`, 1=`118620160`, 2=`200822784`
    (observations only, not a ceiling). The current source collector is fixed
    and the actual sampler succeeded; no historical CI 126 cause is proved. No
    qualification, #113 closure, or #105 GC claim is made. The raw failure
    stage/status is not exported. The shipped source observability fix
    (`c2c439d8dbaf9594139e2844d0b08d5f192bb9c7`) adds a diagnostic-only
    allowlist on the existing private driver fatal prefix. All
    twelve prior failures (1-12) remain documented; issue #113 stays OPEN
    with resource ceilings and the production SLO unapproved, GC disabled, and
    three logical members on one physical CI node.
14. [Run 37185182575](https://github.com/mrchypark/goauthy/actions/runs/37185182575),
    helper `c2c439d8dbaf9594139e2844d0b08d5f192bb9c7`, created
    `2026-10-04T07:14:34Z`, job `111385524648` completed `07:27:33Z` (run
    updated `07:27:34Z`). The diagnostic exited 1 and the analyzer was
    available: overall correctness `FAIL`, performance `FAIL`,
    `criterion_pass=false`, resource ceiling `inconclusive`, no admission. 78
    records were complete across all request denominators; 1176 valid sampler
    rows over 196 timestamps and 6 series, resource evidence complete with 0
    non-RSS unavailable. All three app pods were `Running`/ready/`restarts:0`
    and the candidate/helper content identity checks were accepted. IAM had 48
    total / 43 success / 5 protected errors (d0 mixed 1 recovery 1; d1 mixed 1
    recovery 1; d2 mixed 1). The new diagnostics were exactly 5 anchored fixed
    `transport_timeout` reasons with `null` HTTP status across drivers 2/2/1,
    with 0 unrecognized/excess/missing and `complete:true`/diagnosed; the
    per-phase counts are separate observations with no raw-fatal-to-phase
    association. No root cause is proved and no actual quota `429` is
    asserted. API: 30 records — account 15 all HTTP 200 / protected 0; fault
    15 all actual HTTP 502 / `wrong_outcome:0` / `wrong_status:0`. Fixture 30
    started/completed, active 0, drain true. The job `Complete` wait (220s)
    timed out at `07:27:13Z` and the runner rejected all three driver evidence
    at `07:27:14Z`; the actual job `Failed` condition is not exported, so no
    failed-job assertion is made. Successful-observation nearest-rank IAM
    P95=P99 (ms): phase totals are 6/6/4, while percentiles exclude failed
    observations and use the success counts shown below:

    | Driver | Baseline (n) | Mixed (n) | Recovery (n) |
    | --- | --- | --- | --- |
    | 0 | 4330.606 (6) | 6635.865 (5 success, 1 error) | 13400.517 (3 success, 1 error) |
    | 1 | 4096.740 (6) | 8489.009 (5 success, 1 error) | 13198.003 (3 success, 1 error) |
    | 2 | 3988.956 (6) | 8490.179 (5 success, 1 error) | 1892.955 (4 success) |

    Thresholds (P95/P99 ms): driver 0 `5413.2575`/`6495.909` (both FAIL);
    driver 1 `5120.925`/`6145.11` (both FAIL); driver 2 `4986.195`/`5983.434`
    (mixed FAIL, recovery PASS). 5 of 6 relative comparisons fail; the tails
    are success-only and not a stable SLO. Observed app peak working-set bytes:
    d0=`232333312`, d1=`191574016`, d2=`194969600` (no ceiling claim);
    `peak_cpu_nano` is cumulative ns, not peak utilization. The
    follow-up `a3605cb` aligns only the fallback IAM diagnostics
    excess/missing `null`/no unknown/same criterion string plus the existing
    no-analyzer exact-key regression (34 controls, sh syntax PASS; an
    independent Longcat review is CLEAN with P2 closed); the actual 14 was
    measured at `c2`, not `a360`, and the fallback metadata delta needs no
    further unchanged campaign. This actual measurement `FAIL` is retained
    without a blind rerun or criterion loosening; merging tool changes through
    the normal exact 4 CI/reviews is not workload qualification or #113
    closure, and the unresolved client timeout/latency SLO keeps issue #113
    OPEN with #105 GC disabled, unapproved resource/SLO, and three logical
    members on one physical CI node. All thirteen prior failures (1-13) remain
    documented with their metrics and unconfirmed causes.

## Forthcoming source-build measurement mode

A forthcoming run mode builds the candidate inside the workflow from a clean
`candidate_source` commit on the branch workflow ref (`local_build=true`)
instead of pulling a prebuilt immutable image. The image is ephemeral: it is
built for one run and is neither a release artifact nor published to a
registry. The measurement criteria are unchanged: three logical GoAuthy
members on one Kind host with local Versity, the same shared analyzer, the
same relative IAM P95/P99 criterion, and the same failure handling. The exact
source commit, helper/fixture manifest digests, config, and runtime image
pins are recorded as separate evidence and are not conflated.

Dependency state: Lattice 0.11.1 is now the current candidate; run 14 measured
release v0.2.0 with Lattice 0.10. The current candidate also carries a
structural read-amplification reduction on the connection-use invoke path: the
API provider metadata and the ready credential are read in one linearizable
snapshot, reducing the per-invoke linearizable read count from 9 to 7. This is
a structural estimate only; no causal fix claim is made until an actual
measurement under the approved criteria.

All fourteen prior failure histories and their uncertainty are preserved. This
mode changes no timing, scheduler, security, or oracle behavior and adds no new
test, build, or implementation files and no raw logs or caches. Issue #113
stays OPEN until an actual approved-criteria proof is recorded and the
resource/SLO scope is made explicit; no resource ceiling is invented here.
