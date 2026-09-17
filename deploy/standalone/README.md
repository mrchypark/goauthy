# GoAuthy standalone Kubernetes profile

This profile runs one GoAuthy StatefulSet pod with
`GOAUTHY_RHIZA_PROFILE=standalone`. GoAuthy's `data` volume is an `emptyDir`
bounded to 1Gi: it is a disposable recovery cache, not durable application
storage. `GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE=true` keeps startup fail-closed
unless the shared object store is configured.

The overlay removes only the three-voter peer address, member list, and admin
token. It deliberately retains the object-store configuration, bucket-wait
init container, MinIO service/statefulset/init job, and their policies. MinIO's
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

For the standalone cold backup/restore proof, run
`make e2e-standalone-backup-restore`. It verifies recovery against the shared
object-store prefix with master keys and application secrets provisioned
separately.

The inherited default-deny policy and this overlay's standalone policy permit
DNS-only egress. SMTP, upstream, SCIM, and other external integrations need
operator-added destination-specific NetworkPolicies; this profile does not
open general external egress by default.
