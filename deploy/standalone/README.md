# GoAuthy standalone Kubernetes profile

This existing profile runs one GoAuthy StatefulSet pod with
`GOAUTHY_RHIZA_PROFILE=standalone` and Rhiza `Local: false`. GoAuthy's `data`
volume is an `emptyDir` bounded to 1Gi: it is a disposable recovery cache, not
durable application storage. `GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE=true` keeps
startup fail-closed unless the shared object store is configured. The separate
opt-in `standalone-local` (`Local: true`) archive contract is documented in
[`docs/no-pvc-dr.md`](../../docs/no-pvc-dr.md).

The overlay removes only the three-voter peer address, member list, and admin
token. It deliberately retains the object-store configuration, bucket-wait
init container, VersityGW service/statefulset/init job, and their policies. VersityGW's
PVC is an external-object-store test fixture for this manifest; it is not
GoAuthy's product data PVC.

This is only a storage/topology overlay. It retains every non-cluster
application setting from the HA manifest; `test.sh` compares the rendered
environment lists so a feature cannot silently disappear in standalone mode.

Build or apply it with Kustomize:

```sh
kustomize build deploy/standalone
kubectl apply -k deploy/standalone
```

The overlay inherits the base Secret contract (`goauthy-secrets`) and the
base image name (`goauthy:e2e`); set the image in the rendered manifest or
through your normal image promotion workflow before applying to a cluster.
Run `./deploy/standalone/test.sh` to check the rendered topology and profile
constraints without contacting a Kubernetes cluster.

For the standalone cold filesystem-copy proof, run
`make e2e-standalone-backup-restore`. It gracefully stops the source process,
copies its local data directory, and starts a second process from that copy;
master keys and application secrets are provisioned separately. This script
does not configure or restore from an object-store prefix and does not prove
abrupt-loss or Kubernetes Pod-replacement recovery.

The inherited default-deny policy and this overlay's standalone policy permit
DNS-only egress. SMTP, upstream, SCIM, and other external integrations need
operator-added destination-specific NetworkPolicies; this profile does not
open general external egress by default.
