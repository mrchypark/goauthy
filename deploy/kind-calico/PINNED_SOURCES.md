# Calico fallback pins

This profile installs the official `projectcalico/calico` release manifest at
`v3.32.1`, as prescribed by Calico's kind installation guide. The download is
verified before it is applied:

```
https://raw.githubusercontent.com/projectcalico/calico/v3.32.1/manifests/calico.yaml
sha256:a1df919d9721cf667accdc3e72848911b0cb25cfab7d2478ad0c996302c95744
```

The script rewrites only the three image references in that manifest to the
following Linux/ARM64 digest-pinned images. These digests were resolved from
the release's `quay.io` multi-architecture manifests on 2026-08-31.

| Image | Linux/ARM64 digest |
| --- | --- |
| `quay.io/calico/cni:v3.32.1` | `sha256:f83ba4048763b8dbfa95f65b5094e8fb08b7326ce8d465111bb9da416ecb6bdb` |
| `quay.io/calico/node:v3.32.1` | `sha256:9da8e32d2d6f9405be1985f258842bfc808bbf5aca51091bdef8110fca722a1b` |
| `quay.io/calico/kube-controllers:v3.32.1` | `sha256:afa3429708de65af587ede22064a7abddf57082edd368066c24781e3b2d30cb5` |

References: [Calico kind installation](https://docs.tigera.io/calico/latest/getting-started/kubernetes/kind), [v3.32.1 release](https://github.com/projectcalico/calico/releases/tag/v3.32.1), and [ordered Calico deny policies](https://docs.tigera.io/calico/latest/network-policy/get-started/calico-policy/calico-network-policy).
