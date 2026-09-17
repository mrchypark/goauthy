# Ternal dependency-security candidate — 2026-09-07

Status: linux/amd64 build, focused auth/mail regressions and exact-image scan
passed. Consumer operational validation is reported below; this is not full
release qualification. No registry publication, IED mutation or session change
by this task.

## Scope and provenance

Original frozen source is preserved at
`/tmp/goauthy-candidate-20260907.IgxSUc/source` (manifest
`5351941df0f9af0fb13f012d69754a1284d22cc01c8fed405239dec20864661b`).
Security-only copy: `/tmp/goauthy-security-candidate-20260907.44wMr8/source`.
Recursive comparison confirms **only go.mod and go.sum differ**. Schema remains
79; current Device DPoP and DCR/schema80 work is excluded.

New complete source manifest: `../source.sha256`, SHA-256
`a32cd84ceb4fda64394d47e2cbfe436013fd8f71e18167c4c4a7b3ac6666ccc5`.
`go mod verify` passed. Application source, pinned builder and Dockerfile remain
identical to the original candidate.

## Package mapping and rationale

| Package | Before → after | Maintainer/Go advisory |
| --- | --- | --- |
| go-jose/v3 | 3.0.3 → 3.0.5 | [JWE panic fix](https://github.com/go-jose/go-jose/security/advisories/GHSA-78h2-9frx-2jm8) |
| go-mail | 0.7.0 → 0.7.1 | [SMTP address encoding fix](https://github.com/wneessen/go-mail/security/advisories/GHSA-wpwj-69cm-q9c5) |
| x/crypto | 0.55.0 → 0.56.0 | [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354), [GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355) |
| otlptracehttp | 1.21.0 → 1.43.0 | [Bounded collector response fix](https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-w8rr-5gcm-pp58) |

Go module selection also updates otlptrace to 1.43.0, proto/otlp to 1.10.0,
grpc-gateway/v2 to 2.28.0 and adds backoff/v5 5.0.3. Existing OTel core/sdk remain
1.44.0; Go requirement remains 1.27.0; Rhiza remains 0.12.0.
Use upstream fixes, not custom crypto/mail workarounds. Module presence alone
does not prove a vulnerable function is reachable in this application.

## Built artifact

- Local tag: `goauthy:ternal-security-candidate-20260907`.
- OCI index: `sha256:4d125ac2b1167a7f814e7322a39b3751033d39908f14ecb29dc2eb4b9f063dba`.
- Runtime manifest: `sha256:0710f23b0918e04c91c2cb7da145328ff87fba0973afa568e1bb4fc6010eef5e`.
- Config: `sha256:80a5061789ac7ade5dc0c515d0753a1f1d37cc98ea10b11f78e7f945ce7d0591`.
- Build metadata: `/tmp/goauthy-security-candidate-20260907.44wMr8/build-metadata.json`.
- BuildKit reference: `dory/dory/01jw2lnk5kz4tm3qbkisai0o2`.
- Extracted binary SHA-256: `e9ddc2e0b3ccadf13672fefa0f085d16effe8d1be7515155563bd27a0af49399`.

`file` and `go version -m` confirm static x86-64 ELF, Go1.27.1, CGO=0,
linux/amd64 and all four updated dependencies in the built binary. Runtime user
is 65532:65532. The extraction container was never started and was removed after
copying the binary; extraction is not runtime qualification.

## Required gates

- [x] Preserve original; dependency-only source diff and module checksums verified.
- [x] Existing credential, recovery/SMTP, notification, OAuth and login package tests.
- [x] Build exact linux/amd64 image and record OCI identity/provenance.
- [x] Fresh exact-image security scan with scanner and database identity; review
  remaining findings, including previously reported GO-2026-5932.
- [x] Consumer task reports replacement-candidate runtime and real RP flow
  qualification; root has not independently repeated the IED checks.

The Ternal task reported the original candidate's High vulnerability gate failed.
Its original scan JSON was not retained; a fresh exact-digest scan is being
prepared there. The original candidate must not be treated as cleared by these
dependency edits or by the previously successful isolated readiness probe.

Final five-package results: credential 0.683s, recovery 110.745s, notification
17.565s, OAuth 366.063s, login 179.197s PASS (outer exit 0).
`go vet` of credential/recovery/notify/oauth/login passed. These are complete
tests of the five selected packages, not a whole-repository or runtime-image E2E.

Focused `-race` checks passed: credential HashVerifyAndNeedsRehash 2.254s,
recovery SMTP tests 2.682s, notification email 1.874s. The same go.mod/go.sum
updates are applied to the main worktree (byte-identical to this candidate's
module files); candidate source still excludes all later feature changes.

## Remaining advisory applicability

Ternal's exact replacement image scan passed pinned Grype 0.104.1
`--platform linux/amd64 --fail-on high` (exit 0 reported by that task).
Root independently inspected `/tmp/ternal-goauthy-scan.3yuY6V/security-grype.json`
(SHA-256 `be2a337ad21112074447e49e1d7833d103cba7ea204ed2b233131eee48e725fc`):
source index, runtime manifest and config match the identities above;
architecture is amd64. High/Medium findings are absent. DB schema v6.1.9,
built `2026-09-06T06:27:35Z`, valid=true, matches the original scan's DB.
The sole remaining finding is GO-2026-5932 with severity Unknown.

The remaining Unknown [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)
affects the unmaintained `golang.org/x/crypto/openpgp` package and its subpackages,
not every package in x/crypto. Upstream lists all versions and no fixed version.
The module-level match is not a claim that OpenPGP is linked into GoAuthy.

For this exact candidate, `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go list -deps
./cmd/goauthy` succeeded and the complete package closure contains no OpenPGP
package. Output: `../linux-amd64-packages.txt`, SHA-256
`3998466a78d33c4e97f624c08735e66429fce06173440db1c7500ebdbf0ace9d`.
Assessment: affected packages are absent from this candidate's runtime build;
not an upstream fix or a universal false-positive claim. Reassess after import,
dependency or build-tag changes. No global scanner suppression was added.

## Consumer-task operational report

Ternal task `019facaf-6a23-7680-b498-b389c8d8a456` subsequently reported publication
of this exact index as `ghcr.io/mrchypark/ternal:goauthy-ied-security-a32cd84ceb4f`.
Its isolated GCS-prefix old-image → candidate → emptyDir cold replay preserved
token introspection and JWKS kid continuity. No old-schema version was asserted.
The task reported fixture cleanup, an image-only replacement of its existing
provider with config/Secret/storage unchanged, Ready 2/2 and zero restarts,
then real Chrome RP administrator-session/login/logout success. These are
consumer-task reports, not root-run IED checks or a new independently committed
GoAuthy release. Root did not publish, deploy or alter user sessions. The local
source remains frozen schema79; schema80 development remains separate.
