# Local HA and Versity qualification receipt

Status: selected local HA global-logout and default backup/restore profiles passed for the pinned candidate.

## Candidate and environment

- GoAuthy source: `bab7fe2e95c71efa2183021a8c63713a47d2e78a` (tree `b15d640f2ef4abbed04ff26e4d86ee5b4df360e5`).
- GoAuthy candidate image: `sha256:e0c888bd45f7a96f121d5063d9bf110502172a4eec2d7f243fc0e96768e7ddeb`; the three GoAuthy pods reported image ID `sha256:abedc1d99cfc66962d7e7d9dacc89519fc40ae99425dacf4f20ebba461d412c2` before and after replacement.
- Rhiza dependency: v0.12.3. Kind runtime node image: `sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f`.
- Local Versity fixture: `versity/versitygw:v1.8.0`, resolved to `sha256:30292fc2eeacc67a36993b01f7a7a5e3361a19cced0e80c1d71cfa2a4b0a2499`.
- The Kind cluster had one node hosting three ready GoAuthy process pods and the Versity fixture. This is a local single-node test, not a three-node Kubernetes deployment.
- GoAuthy local data used `emptyDir`; Versity fixture storage was local PVC-backed. Rhiza GC remained disabled for this run.

## HA result

Command: `make e2e-kind KIND_CLUSTER=goauthy-issue93-20261002 K8S_NAMESPACE=goauthy E2E_PORT=18193 E2E_PROFILE=global-logout GOAUTHY_IMAGE=goauthy:issue93-bab7fe2-20261002`.

The command exited 0. `TestGlobalLogoutBackchannel` passed in both phases: session preparation (1.98s), then the post-replacement flow (12.70s). The harness deleted `goauthy-0`, observed a different pod UID, waited for all three pods to become ready, and reran the after-restart phase. The pinned GoAuthy image ID remained the same across replacement.

After replacement, the test checked the saved sessions through UserInfo on all three pods, deleted the sessions, and verified the sink received a signed subject-only logout token (expected issuer and `goauthy-dev` audience, no `sid` or `nonce`). It then checked a fresh login, rejected the revoked browser session/access/refresh tokens across the pods, and confirmed a separate logout used a distinct token/JTI while two sessions for one user/client produced one delivery. This does not qualify every GoAuthy feature or a multi-node Kubernetes failure domain.

The recorded clock probes were aligned: before, host/VM/host samples were `1790914808/1790914808/1790914809`; after, they were `1790914844/1790914844/1790914844` (Unix seconds). An earlier run failed after replacement while the VM clock was observed 8 seconds ahead. The failed token was not retained, so the exact rejected claim is unknown. The passing rerun used the unchanged source and candidate image after clock synchronization; no token-validation leeway or source change was made.

An earlier preflight found the Kind-node inotify limit at 128, below the harness requirement of 256; it was temporarily raised and restored to 128 after the run. Disk was also brought back above the harness's 12 GiB preflight threshold before execution. Only owned temporary test images were cleaned up.
No persistent Docker configuration, NTP configuration, source, or token-validation policy was changed.

## Backup and restore result

Command: `make e2e-kind-backup-restore BACKUP_RESTORE_KIND_CLUSTER=goauthy-backup-restore-e2e-93-20261002 E2E_PORT=18293 GOAUTHY_IMAGE=goauthy:issue93-bab7fe2-20261002`.

The command exited 0 with `Kind exact-three Rhiza backup/restore E2E passed`. The default profile backed up the source cluster, verified the catalog digest, destroyed that source cluster, and restored into a fresh cluster with the same fixture master key and member/secret identity supplied separately from the encrypted data backup, using a new storage prefix. This was not an operator key-recovery exercise. Both clusters had one Kind node, three ready GoAuthy process pods, and the same GoAuthy image ID and Versity digest listed above. Source and restore pod pins were captured.

The existing harness checks passed: restored checkpoint/catalog markers were present; the restore deployment had no GoAuthy PVC; the pre-backup OAuth token introspected active on all three restored pods; generated bootstrap material matched across all three, and the recovered `generated-reader` API key authenticated on each with no token leakage in their logs; the restored JWKS key ID matched the source; and a newly issued restore-cluster OAuth token introspected active on all three pods. This was the standard/default profile; expiry, all-voter crash, and outage profiles were not run. The restore cluster was not rolled out after recovery; the all-pod restart check belongs to the separate expiry profile.

## Scope limits

This completes the selected local scope for issue #93 and exact candidate above: three GoAuthy process pods on one Kind node. Versity is a local test fixture; this is not production object-storage, multi-node HA, or generalized disaster-recovery evidence. The local test does not establish GC behavior, a capacity target, or an SLO. Issue #105 remains deferred; issue #113 has no selected SLO/capacity evidence.

Sources: [global logout test](../test/e2e/browser/global_logout_backchannel_test.go), [Kind profile](../Makefile), [backup/restore harness](../scripts/e2e-kind-backup-restore.sh), and [GoAuthy StatefulSet storage](../deploy/k8s/statefulset.yaml).
