# IED storage qualification — 2026-09-07

Storage-only checkpoint, not application activation or real-user qualification.

- Created dedicated GCS bucket `ternal-ied-602454948273` in `ASIA-NORTHEAST3`.
- Uniform bucket-level access enabled; public access prevention enforced.
- Separate managed folders `goauthy/` and `ternal/` grant Object User only to
  their respective Kubernetes workload identities (`ternal-auth/ternal-goauthy`
  and `ternal/ternal`). No service-account JSON or static cloud credential was
  created. Existing buckets and providers were not reused.
- On IED, the GoAuthy identity created, read, listed and deleted its own fixture;
  reading a known fixture in the Ternal folder returned an explicit 403.
  Folder-scoped `gcloud storage ls` requires a trailing `/**`; an initial
  directory-style request attempted bucket-level listing and was denied.
  Bucket-wide permissions were not added to work around that denial.
- A Linux/amd64 GoAuthy storage test binary ran in an IED Pod using `emptyDir`
  and Workload Identity against native GCS. The writer exited without Rhiza
  Close, then a fresh process/data directory recovered the account and the
  original signing key. Correct-password acceptance, wrong-password rejection,
  and absent/wrong-master-key refusal passed in 54.09 seconds.
- Test binary SHA-256:
  `dae0cb0e25809e206569865d2e87f7a698320123eade13fe053d28801ebb53c0`.
- Local standalone MinIO/S3 transport recovery also passed. The current full
  storage suite passed after updating the schema-v69 test's expected full
  schema to include the v73 `verifier_envelope` column.
- Removed the two IED probe Pods, uploaded test binary, both probe objects and
  the exact recovery-test object prefix. No Pod or PVC remains in `ternal-auth`.
  The bucket, managed-folder IAM, namespace and service account remain for the
  requested deployment. Cloud soft-delete retention may retain deleted object
  versions; this is not a claim of immediate physical erasure.

The test used disposable fixture identities, not the requested real email
account. This does not establish HA GCS recovery, production image qualification,
Ternal browser/device OAuth integration, or real account creation.
