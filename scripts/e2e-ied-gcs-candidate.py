#!/usr/bin/env python3
"""IED GCS qualification runner with --replicas {1,3} support.

Creates per-run K8s resources (Secret, ConfigMap, Service, StatefulSet) in
namespace ternal-auth, runs client_credentials + introspect + JWKS flow,
faults the pod, proves token/key continuity across restart, then cleans up.

Replicas=1 (default): existing standalone behavior unchanged.
Replicas=3 (HA3): cluster profile, headless service with UDP peer port,
rhiza members JSON, per-voter tokens + admin token, required podAntiAffinity,
3-pod readiness on distinct nodes, multi-pod token verification, single-pod
fault with surviving-pod continuity check.

No live kubectl/gcloud/docker is executed at import time.  Run with --help
for usage.  The caller (parent harness) executes this with the real cluster
context already set.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

from ternal_consumer_probe import TernalProbe

# ── constants ────────────────────────────────────────────────────────────────
NAMESPACE = "ternal-auth"
SERVICE_ACCOUNT = "ternal-goauthy"
BUCKET = "ternal-ied-602454948273"
ISSUER_PORT = 18092
ISSUER = f"http://127.0.0.1:{ISSUER_PORT}"
ALLOWED_RESOURCE = "https://api.example.test/v1"
GRANT_SCOPE = "goauthy.read"
BOOTSTRAP_REDIRECT_URI_CONSUMER = "http://127.0.0.1:18093/auth/callback"
READINESS_TIMEOUT_S = 180
POD_DELETE_READY_TIMEOUT_S = 120
PORT_FORWARD_START_TIMEOUT_S = 10
HTTP_TIMEOUT_S = 15

_KUBECTL_CTX = ["--context", "gke_ied-cluster"]
_IMAGE_RE = re.compile(r"^ghcr\.io/mrchypark/ternal@sha256:[0-9a-f]{64}$")


def ensure_port_free(port: int) -> None:
    """Verify port is free by attempting to bind. Raise if occupied."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            s.bind(("127.0.0.1", port))
        except OSError as exc:
            raise RuntimeError(f"port {port} already in use: {exc}") from exc

# ── helpers ──────────────────────────────────────────────────────────────────

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def kubectl_json(args: list[str], stdin: str | None = None) -> dict:
    """Run kubectl with -o json and return parsed output."""
    cmd = ["kubectl"] + _KUBECTL_CTX + ["-n", NAMESPACE] + args + ["-o", "json"]
    proc = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"kubectl failed: {' '.join(cmd)}\n{proc.stderr}")
    return json.loads(proc.stdout)


def kubectl_create_stdin(kind: str, manifest: dict) -> dict:
    """kubectl create -f - and return the created object (with UID)."""
    body = json.dumps(manifest)
    cmd = ["kubectl"] + _KUBECTL_CTX + ["-n", NAMESPACE, "create", "-f", "-", "-o", "json"]
    proc = subprocess.run(cmd, input=body, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"kubectl create {kind} failed (rc={proc.returncode})")
    return json.loads(proc.stdout)


def kubectl_delete(kind: str, name: str, uid: str) -> None:
    if not uid:
        raise ValueError(f"uid required for kubectl_delete({kind}, {name})")
    if kind == "StatefulSet":
        path = f"/apis/apps/v1/namespaces/{NAMESPACE}/statefulsets/{name}"
    else:
        plural = kind.lower() + "s"
        path = f"/api/v1/namespaces/{NAMESPACE}/{plural}/{name}"
    body = json.dumps({
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "preconditions": {"uid": uid},
    })
    cmd = ["kubectl"] + _KUBECTL_CTX + ["-n", NAMESPACE, "delete", "--raw", path, "-f", "-"]
    proc = subprocess.run(cmd, input=body, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        if "not found" in proc.stderr.lower() or "notfound" in proc.stderr.lower():
            return
        raise RuntimeError(f"kubectl delete {kind}/{name} failed (rc={proc.returncode})")


def wait_pod_ready(selector: str, timeout_s: int, expected_controller_uid: str, exclude_pod_uid: str | None = None, fault_pod_name: str | None = None) -> dict:
    """Poll for a pod matching label selector that is Ready.

    Only returns a pod whose controller ownerReference UID matches
    *expected_controller_uid*.  Skips pods with deletionTimestamp or whose
    own UID equals *exclude_pod_uid*.

    When *fault_pod_name* is provided the selector is narrowed to the exact
    StatefulSet pod via statefulset.kubernetes.io/pod-name so that the
    replacement for the faulted ordinal is returned instead of any surviving
    pod that happens to be Ready.
    """
    effective_selector = selector
    if fault_pod_name:
        effective_selector = f"{selector},statefulset.kubernetes.io/pod-name={fault_pod_name}"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pods = kubectl_json(["get", "pods", "-l", effective_selector])
        for pod in pods.get("items", []):
            meta = pod.get("metadata", {})
            if meta.get("deletionTimestamp"):
                continue
            if exclude_pod_uid and meta.get("uid") == exclude_pod_uid:
                continue
            if fault_pod_name and meta.get("name") != fault_pod_name:
                continue
            matched_controller = False
            for ref in meta.get("ownerReferences", []):
                if ref.get("controller") and ref.get("uid") == expected_controller_uid:
                    matched_controller = True
                    break
            if not matched_controller:
                continue
            for cond in pod.get("status", {}).get("conditions", []):
                if cond.get("type") == "Ready" and cond.get("status") == "True":
                    return pod
        time.sleep(3)
    raise TimeoutError(f"No ready pod for selector={effective_selector} within {timeout_s}s")


def wait_n_pods_ready(selector: str, n: int, timeout_s: int, expected_controller_uid: str) -> list[dict]:
    """Poll for exactly *n* Ready pods owned by *expected_controller_uid*.

    Returns the list of pod dicts.  Each pod must have a distinct
    spec.nodeName (enforced after collection).
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pods = kubectl_json(["get", "pods", "-l", selector])
        ready: list[dict] = []
        for pod in pods.get("items", []):
            meta = pod.get("metadata", {})
            if meta.get("deletionTimestamp"):
                continue
            matched_controller = False
            for ref in meta.get("ownerReferences", []):
                if ref.get("controller") and ref.get("uid") == expected_controller_uid:
                    matched_controller = True
                    break
            if not matched_controller:
                continue
            for cond in pod.get("status", {}).get("conditions", []):
                if cond.get("type") == "Ready" and cond.get("status") == "True":
                    ready.append(pod)
                    break
        if len(ready) >= n:
            return ready[:n]
        time.sleep(3)
    raise TimeoutError(f"Expected {n} ready pods for selector={selector} within {timeout_s}s")


def assert_distinct_nodes(pods: list[dict]) -> list[str]:
    """Assert each pod is scheduled on a distinct node. Return node names."""
    nodes: list[str] = []
    for pod in pods:
        node = pod.get("spec", {}).get("nodeName", "")
        assert node, f"pod {pod['metadata']['name']} has no spec.nodeName"
        assert node not in nodes, f"duplicate node {node} for pod {pod['metadata']['name']}"
        nodes.append(node)
    return nodes


def _reap_proc(proc: subprocess.Popen) -> None:
    """Terminate (SIGTERM), then kill (SIGKILL) a process. Never raises."""
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass


def wait_port_forward(local_port: int, target_port: int, pod_name: str) -> subprocess.Popen:
    """Start kubectl port-forward with --address 127.0.0.1, verify stdout.

    Returns the Popen object only after the exact forwarding line is seen
    on stdout.  Uses non-blocking os.read on the subprocess stdout fd so
    a partial line + process exit cannot hang forever.
    """
    expected_line = f"Forwarding from 127.0.0.1:{local_port} -> {target_port}\n"
    cmd = (
        ["kubectl"] + _KUBECTL_CTX + ["-n", NAMESPACE, "port-forward",
         "--address", "127.0.0.1", f"pod/{pod_name}", f"{local_port}:{target_port}"]
    )
    pf = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    assert pf.stdout is not None
    fd = pf.stdout.fileno()
    os.set_blocking(fd, False)
    buf = b""
    deadline = time.monotonic() + PORT_FORWARD_START_TIMEOUT_S
    found_line = False
    try:
        while time.monotonic() < deadline:
            if pf.poll() is not None:
                # drain any remaining bytes after exit
                try:
                    buf += os.read(fd, 65536)
                except OSError:
                    pass
                raise RuntimeError(
                    f"port-forward exited early (rc={pf.returncode}): "
                    f"{buf.decode('utf-8', errors='replace')}"
                )
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                chunk = b""
            if chunk:
                buf += chunk
            while b"\n" in buf:
                line_bytes, buf = buf.split(b"\n", 1)
                line = line_bytes.decode("utf-8", errors="replace").replace("\r", "") + "\n"
                if line == expected_line:
                    found_line = True
                    break
            if found_line:
                break
            time.sleep(0.05)
        else:
            _reap_proc(pf)
            raise TimeoutError("port-forward did not emit expected forwarding line")

        # health probe AFTER forwarding line confirmed
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{local_port}/livez", timeout=2):
                pass
        except Exception:
            pass
    except BaseException:
        _reap_proc(pf)
        raise

    return pf


def http_post(url: str, data: dict, auth: tuple[str, str] | None = None) -> dict:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    if auth:
        raw = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {raw}")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
        return json.loads(resp.read())


def http_get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT_S) as resp:
        return json.loads(resp.read())


def canonical_jwks(data: dict) -> str:
    """Return deterministic JSON of JWKS keys sorted by kid."""
    keys = data.get("keys", [])
    assert keys, "JWKS keyset is empty"
    return json.dumps(sorted(keys, key=lambda k: k["kid"]), sort_keys=True, separators=(",", ":"))


def _run_password_hasher(hasher_bin: str, password: str) -> str:
    """Run the password-hasher binary with the password on stdin, return PHC string."""
    proc = subprocess.run(
        [hasher_bin],
        input=password + "\n",
        capture_output=True,
        text=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError("password-hasher failed")
    phc = proc.stdout.strip()
    if "\n" in phc or len(phc) > 4096 or not phc.startswith("$argon2id$"):
        raise RuntimeError("password-hasher produced invalid output")
    return phc


def validate_discovery(well_known: dict) -> str:
    """Validate .well-known/openid-configuration and return jwks_uri."""
    assert well_known.get("issuer") == ISSUER, (
        f"issuer mismatch: expected={ISSUER!r} got={well_known.get('issuer')!r}"
    )
    jwks_uri = well_known["jwks_uri"]
    parsed = urllib.parse.urlparse(jwks_uri)
    assert parsed.scheme == "http" and parsed.hostname == "127.0.0.1" and parsed.port == ISSUER_PORT, (
        f"jwks_uri must be from origin http://127.0.0.1:{ISSUER_PORT}: {jwks_uri}"
    )
    assert not parsed.username and not parsed.password, (
        f"jwks_uri must have no userinfo: {jwks_uri}"
    )
    return jwks_uri


# ── manifest builders ────────────────────────────────────────────────────────

def _build_secret_manifest(secret_name: str, resource_label: str, string_data: dict) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": secret_name,
            "namespace": NAMESPACE,
            "labels": {
                "app.kubernetes.io/name": "goauthy",
                "app.kubernetes.io/part-of": resource_label,
            },
        },
        "type": "Opaque",
        "stringData": string_data,
    }


def _build_configmap_manifest(configmap_name: str, resource_label: str, flavor: str, prefix: str, client_id: str) -> dict:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": configmap_name,
            "namespace": NAMESPACE,
            "labels": {
                "app.kubernetes.io/name": "goauthy",
                "app.kubernetes.io/part-of": resource_label,
            },
        },
        "data": {
            f"issuer-{flavor}": ISSUER,
            "gcs-bucket": BUCKET,
            f"gcs-prefix-{flavor}": prefix,
            f"bootstrap-client-id-{flavor}": client_id,
            f"bootstrap-redirect-uri-{flavor}": f"http://127.0.0.1:{ISSUER_PORT}/oidc/callback",
        },
    }


def _build_service_manifest(service_name: str, resource_label: str, ha3: bool) -> dict:
    ports = [{"name": "http", "port": 8080, "targetPort": "http"}]
    if ha3:
        ports.append({"name": "peer", "port": 8444, "targetPort": "peer", "protocol": "UDP"})
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": service_name,
            "namespace": NAMESPACE,
            "labels": {
                "app.kubernetes.io/name": "goauthy",
                "app.kubernetes.io/part-of": resource_label,
            },
        },
        "spec": {
            "clusterIP": "None",
            "publishNotReadyAddresses": True,
            "selector": {
                "app.kubernetes.io/name": "goauthy",
                "app.kubernetes.io/part-of": resource_label,
            },
            "ports": ports,
        },
    }


def _build_statefulset_manifest(
    statefulset_name: str,
    service_name: str,
    resource_label: str,
    configmap_name: str,
    secret_name: str,
    master_key_id: str,
    flavor: str,
    replicas: int,
    ha3: bool,
    image: str,
    consumer: bool = False,
) -> dict:
    ports = [{"name": "http", "containerPort": 8080}]
    if ha3:
        ports.append({"name": "peer", "containerPort": 8444, "protocol": "UDP"})

    env = [
        {"name": "GOAUTHY_LISTEN_ADDR", "value": ":8080"},
        {"name": "GOAUTHY_ISSUER", "valueFrom": {"configMapKeyRef": {"name": configmap_name, "key": f"issuer-{flavor}"}}},
        {"name": "GOAUTHY_SIGNING_KEY_ROTATION_PERIOD", "value": "720h"},
        {"name": "GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT", "value": "90m"},
        {"name": "GOAUTHY_CLUSTER_ID", "value": resource_label},
        {"name": "GOAUTHY_NODE_ID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
        {"name": "GOAUTHY_DATA_DIR", "value": "/var/lib/goauthy"},
        {"name": "SQLITE_TMPDIR", "value": "/tmp"},
        {"name": "GOAUTHY_RHIZA_PROFILE", "value": "cluster" if ha3 else "standalone"},
        {"name": "GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE", "value": "true"},
        {"name": "GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER", "value": "gcs"},
        {"name": "GOAUTHY_RHIZA_OBJECT_STORE_BUCKET", "valueFrom": {"configMapKeyRef": {"name": configmap_name, "key": "gcs-bucket"}}},
        {"name": "GOAUTHY_RHIZA_OBJECT_STORE_PREFIX", "valueFrom": {"configMapKeyRef": {"name": configmap_name, "key": f"gcs-prefix-{flavor}"}}},
        {"name": "GOAUTHY_MASTER_KEY_DIR", "value": "/run/secrets/master-keys"},
        {"name": "GOAUTHY_ACTIVE_MASTER_KEY_ID", "value": master_key_id},
        {"name": "GOAUTHY_OAUTH_HMAC_SECRET_FILE", "value": "/run/secrets/oauth-hmac"},
        {"name": "GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE", "value": "/run/secrets/bootstrap-client"},
        {"name": "GOAUTHY_BOOTSTRAP_CLIENT_ID", "valueFrom": {"configMapKeyRef": {"name": configmap_name, "key": f"bootstrap-client-id-{flavor}"}}},
        {"name": "GOAUTHY_BOOTSTRAP_REDIRECT_URI", "valueFrom": {"configMapKeyRef": {"name": configmap_name, "key": f"bootstrap-redirect-uri-{flavor}"}}},
        {"name": "GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES", "value": f'["{ALLOWED_RESOURCE}"]'},
        {"name": "GOAUTHY_RFC8252_LOOPBACK_REDIRECTS", "value": "false"},
    ]
    if ha3:
        env.append({"name": "GOAUTHY_RHIZA_PEER_ADDR", "value": ":8444"})
        env.append({"name": "GOAUTHY_RHIZA_MEMBERS", "valueFrom": {"secretKeyRef": {"name": secret_name, "key": "rhiza-members"}}})
        env.append({"name": "GOAUTHY_RHIZA_ADMIN_TOKEN", "valueFrom": {"secretKeyRef": {"name": secret_name, "key": "rhiza-admin-token"}}})
    if consumer:
        env.append({"name": "GOAUTHY_BOOTSTRAP_USER", "value": "qual@example.test"})
        env.append({"name": "GOAUTHY_BOOTSTRAP_USER_SUBJECT", "value": "qual-browser"})
        env.append({"name": "GOAUTHY_BOOTSTRAP_USER_PASSWORD_PHC_FILE", "value": "/run/secrets/password-phc"})
        env.append({"name": "GOAUTHY_BOOTSTRAP_FORCE_MFA", "value": "false"})
        env.append({"name": "GOAUTHY_BOOTSTRAP_USER_GROUPS", "value": '["ternal-admins"]'})
        env.append({"name": "GOAUTHY_BOOTSTRAP_USER_EMAIL", "value": "qual@example.test"})

    affinity = None
    if ha3:
        affinity = {
            "podAntiAffinity": {
                "requiredDuringSchedulingIgnoredDuringExecution": [
                    {
                        "labelSelector": {
                            "matchLabels": {
                                "app.kubernetes.io/name": "goauthy",
                                "app.kubernetes.io/part-of": resource_label,
                            },
                        },
                        "topologyKey": "kubernetes.io/hostname",
                    }
                ],
            },
        }

    spec: dict = {
        "serviceName": service_name,
        "podManagementPolicy": "Parallel",
        "replicas": replicas,
        "selector": {
            "matchLabels": {
                "app.kubernetes.io/name": "goauthy",
                "app.kubernetes.io/part-of": resource_label,
            },
        },
        "template": {
            "metadata": {
                "labels": {
                    "app.kubernetes.io/name": "goauthy",
                    "app.kubernetes.io/part-of": resource_label,
                    "app.kubernetes.io/component": "object-store-client",
                },
            },
            "spec": {
                "serviceAccountName": SERVICE_ACCOUNT,
                "automountServiceAccountToken": False,
                "securityContext": {
                    "fsGroup": 65532,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [
                    {
                        "name": "goauthy",
                        "image": image,
                        "imagePullPolicy": "IfNotPresent",
                        "ports": ports,
                        "env": env,
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "capabilities": {"drop": ["ALL"]},
                            "readOnlyRootFilesystem": True,
                            "runAsNonRoot": True,
                            "runAsUser": 65532,
                            "runAsGroup": 65532,
                        },
                        "resources": {
                            "requests": {"cpu": "100m", "memory": "128Mi"},
                            "limits": {"cpu": "500m", "memory": "512Mi"},
                        },
                        "startupProbe": {
                            "httpGet": {"path": "/livez", "port": "http"},
                            "periodSeconds": 2,
                            "failureThreshold": 30,
                        },
                        "livenessProbe": {
                            "httpGet": {"path": "/livez", "port": "http"},
                            "periodSeconds": 10,
                        },
                        "readinessProbe": {
                            "httpGet": {"path": "/readyz", "port": "http"},
                            "periodSeconds": 2,
                            "failureThreshold": 3,
                        },
                        "volumeMounts": [
                            {"name": "sqlite-tmp", "mountPath": "/tmp"},
                            {"name": "data", "mountPath": "/var/lib/goauthy"},
                            {"name": "secrets", "mountPath": "/run/secrets/master-keys", "subPath": "master-keys", "readOnly": True},
                            {"name": "secrets", "mountPath": "/run/secrets/oauth-hmac", "subPath": "oauth-hmac", "readOnly": True},
                            {"name": "secrets", "mountPath": "/run/secrets/bootstrap-client", "subPath": "bootstrap-client", "readOnly": True},
                            *([{"name": "secrets", "mountPath": "/run/secrets/password-phc", "subPath": "password-phc", "readOnly": True}] if consumer else []),
                        ],
                    }
                ],
                "volumes": [
                    {
                        "name": "secrets",
                        "secret": {
                            "secretName": secret_name,
                            "defaultMode": 0o440,
                            "items": [
                                {"key": "master-key", "path": f"master-keys/{master_key_id}"},
                                {"key": "oauth-hmac", "path": "oauth-hmac"},
                                {"key": "bootstrap-client", "path": "bootstrap-client"},
                                *([{"key": "password-phc", "path": "password-phc"}] if consumer else []),
                            ],
                        },
                    },
                    {"name": "sqlite-tmp", "emptyDir": {"sizeLimit": "64Mi"}},
                    {"name": "data", "emptyDir": {"sizeLimit": "1Gi"}},
                ],
            },
        },
    }

    if affinity:
        spec["template"]["spec"]["affinity"] = affinity

    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": statefulset_name,
            "namespace": NAMESPACE,
            "labels": {
                "app.kubernetes.io/name": "goauthy",
                "app.kubernetes.io/part-of": resource_label,
            },
        },
        "spec": spec,
    }


# ── verification helpers ─────────────────────────────────────────────────────

def _introspect_and_jwks(
    base: str,
    token: str,
    client_id: str,
    client_secret: str,
    pf_procs: list[subprocess.Popen],
    pod_name: str | None = None,
    baseline_jwks: str | None = None,
) -> str:
    """Introspect token + fetch JWKS, optionally switching port-forward.

    If *pod_name* is given, tears down last pf and starts a new one to that pod.
    If *baseline_jwks* is given, asserts the fetched JWKS matches it.
    Returns the canonical JWKS string.
    """
    if pod_name:
        if pf_procs and pf_procs[-1].poll() is None:
            pf_procs[-1].kill()
            pf_procs[-1].wait(timeout=5)
        pf = wait_port_forward(ISSUER_PORT, 8080, pod_name)
        pf_procs.append(pf)
        print(f"  port-forward → {pod_name} pid={pf.pid}")

    intro = http_post(
        f"{base}/oidc/introspect",
        {"token": token},
        auth=(client_id, client_secret),
    )
    assert intro.get("active") is True, f"token not active on {pod_name or 'pod'}: {intro}"
    assert intro.get("client_id") == client_id
    assert intro.get("scope") == GRANT_SCOPE, f"scope mismatch on {pod_name or 'pod'}: {intro}"

    well_known = http_get(f"{base}/.well-known/openid-configuration")
    jwks_uri = validate_discovery(well_known)
    jwks = http_get(jwks_uri)
    canonical = canonical_jwks(jwks)

    if baseline_jwks is not None:
        assert canonical == baseline_jwks, f"JWKS mismatch on {pod_name or 'pod'}"

    label = pod_name or "pod"
    print(f"  {label}: introspect OK, JWKS canonical match")
    return canonical


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="IED GCS qualification runner")
    ap.add_argument("--image", required=True, help="Immutable container image digest")
    ap.add_argument("--replicas", type=int, choices=[1, 3], default=1, help="Number of replicas (1=standalone, 3=HA)")
    ap.add_argument("--ternal-bin", default=None, help="Absolute path to ternal-api binary (requires --password-hasher)")
    ap.add_argument("--password-hasher", default=None, help="Absolute path to password-hasher binary (requires --ternal-bin)")
    args = ap.parse_args()

    if not _IMAGE_RE.fullmatch(args.image):
        print(f"ERROR: --image does not match required pattern", file=sys.stderr)
        return 1

    if (args.ternal_bin is None) != (args.password_hasher is None):
        print("ERROR: --ternal-bin and --password-hasher must both be provided or both omitted", file=sys.stderr)
        return 1

    consumer = args.ternal_bin is not None
    if consumer:
        for label, path in [("ternal-bin", args.ternal_bin), ("password-hasher", args.password_hasher)]:
            if not os.path.isabs(path):
                print(f"ERROR: --{label} must be an absolute path, got: {path}", file=sys.stderr)
                return 1
            if not os.path.isfile(path):
                print(f"ERROR: --{label} file does not exist: {path}", file=sys.stderr)
                return 1
            if not os.access(path, os.X_OK):
                print(f"ERROR: --{label} is not executable: {path}", file=sys.stderr)
                return 1

    run_id = str(uuid.uuid4())
    if args.replicas == 3:
        return _main_ha3(run_id, args.image, consumer=consumer, ternal_bin=args.ternal_bin, password_hasher=args.password_hasher)
    return _main_standalone(run_id, args.image, consumer=consumer, ternal_bin=args.ternal_bin, password_hasher=args.password_hasher)


def _main_standalone(run_id: str, image: str, *, consumer: bool = False, ternal_bin: str | None = None, password_hasher: str | None = None) -> int:
    """Thin wrapper for routing tests that patch this name."""
    return _main(run_id, image, 1, consumer=consumer, ternal_bin=ternal_bin, password_hasher=password_hasher)


def _main_ha3(run_id: str, image: str, *, consumer: bool = False, ternal_bin: str | None = None, password_hasher: str | None = None) -> int:
    """Thin wrapper for routing tests that patch this name."""
    return _main(run_id, image, 3, consumer=consumer, ternal_bin=ternal_bin, password_hasher=password_hasher)


def _main(run_id: str, image: str, replicas: int, *, consumer: bool = False, ternal_bin: str | None = None, password_hasher: str | None = None) -> int:
    """Unified qualification flow for replicas=1 (standalone) and replicas=3 (HA3)."""
    ha3 = replicas == 3
    flavor = "ha3" if ha3 else "s1"
    prefix = f"goauthy/qualification/{run_id}/{flavor}"
    resource_label = f"goauthy-qual-{flavor}-{run_id}"
    secret_name = f"goauthy-qual-{flavor}-secrets-{run_id}"
    configmap_name = f"goauthy-qual-config-{run_id}"
    service_name = f"goauthy-qual-{flavor}-{run_id}"
    statefulset_name = f"gq-{flavor}-{run_id}"
    master_key_id = f"qual-{flavor}-{run_id}"
    client_id = f"qual-{flavor}-goauthy"

    # ── generate secrets ─────────────────────────────────────────────────
    master_key = secrets.token_bytes(32)
    hmac_secret = secrets.token_bytes(32)
    client_secret_bytes = secrets.token_bytes(32)
    client_secret = b64url(client_secret_bytes)

    string_data: dict[str, str] = {
        "master-key": b64url(master_key),
        "oauth-hmac": b64url(hmac_secret),
        "bootstrap-client": client_secret,
    }

    browser_password: str | None = None
    if consumer:
        assert password_hasher is not None
        browser_password = secrets.token_urlsafe(24)
        phc = _run_password_hasher(password_hasher, browser_password)
        string_data["password-phc"] = phc

    if ha3:
        voter_tokens = [b64url(secrets.token_bytes(32)) for _ in range(3)]
        admin_token = b64url(secrets.token_bytes(32))
        members = []
        for i in range(3):
            members.append({
                "node_id": f"{statefulset_name}-{i}",
                "peer_url": f"quic://{statefulset_name}-{i}.{service_name}.{NAMESPACE}.svc.cluster.local:8444",
                "token": voter_tokens[i],
            })
        string_data["rhiza-members"] = json.dumps(members)
        string_data["rhiza-admin-token"] = admin_token

    secret_manifest = _build_secret_manifest(secret_name, resource_label, string_data)
    configmap_manifest = _build_configmap_manifest(configmap_name, resource_label, flavor, prefix, client_id)
    if consumer:
        configmap_manifest["data"][f"bootstrap-redirect-uri-{flavor}"] = BOOTSTRAP_REDIRECT_URI_CONSUMER
    service_manifest = _build_service_manifest(service_name, resource_label, ha3)
    statefulset_manifest = _build_statefulset_manifest(
        statefulset_name, service_name, resource_label,
        configmap_name, secret_name, master_key_id,
        flavor, replicas, ha3, image, consumer,
    )

    created: dict[str, tuple[str, str]] = {}  # kind -> (name, uid)
    pf_procs: list[subprocess.Popen] = []
    probe: TernalProbe | None = None
    token = ""
    result = 1
    cleanup_failed = False

    def cleanup():
        print(f"\n{'='*60}")
        print("CLEANUP")
        print(f"{'='*60}")
        nonlocal cleanup_failed
        cleanup_failed = False
        if probe is not None:
            try:
                probe.__exit__(None, None, None)
                print("  stopped ternal-api probe")
            except Exception as exc:
                print(f"  probe stop FAILED: {exc}")
                cleanup_failed = True
        for pf in pf_procs:
            if pf.poll() is None:
                try:
                    pf.terminate()
                    pf.wait(timeout=5)
                    print(f"  killed port-forward pid={pf.pid}")
                except Exception:
                    try:
                        pf.kill()
                        pf.wait(timeout=5)
                        print(f"  killed port-forward pid={pf.pid}")
                    except Exception as exc:
                        print(f"  port-forward pid={pf.pid} stop FAILED: {exc}")
                        cleanup_failed = True
        for kind in ["StatefulSet", "Service", "ConfigMap", "Secret"]:
            if kind in created:
                name, uid = created[kind]
                try:
                    kubectl_delete(kind, name, uid)
                    print(f"  deleted {kind}/{name} uid={uid[:12]}… ok")
                except Exception as exc:
                    print(f"  deleted {kind}/{name} uid={uid[:12]}… FAIL({exc})")
                    cleanup_failed = True
        print(f"\nGCS prefix (parent cleanup): {prefix}")
        print(f"Network isolation: UNQUALIFIED (IED policy enforcement disabled)")

    try:
        ensure_port_free(ISSUER_PORT)

        print(f"run_id    = {run_id}")
        print(f"prefix    = {prefix}")
        print(f"label     = {resource_label}")
        print(f"image     = {image}")
        print(f"replicas  = {replicas} ({'HA' if ha3 else 'standalone'})")
        print(f"consumer  = {consumer}")
        print()

        for kind, manifest in [
            ("Secret", secret_manifest),
            ("ConfigMap", configmap_manifest),
            ("Service", service_manifest),
            ("StatefulSet", statefulset_manifest),
        ]:
            obj = kubectl_create_stdin(kind, manifest)
            name = obj["metadata"]["name"]
            uid = obj["metadata"]["uid"]
            created[kind] = (name, uid)
            print(f"created {kind}/{name} uid={uid}")

        sts_uid = created["StatefulSet"][1]
        selector = f"app.kubernetes.io/name=goauthy,app.kubernetes.io/part-of={resource_label}"
        base = f"http://127.0.0.1:{ISSUER_PORT}"

        if ha3:
            # ── HA3: wait for 3 ready pods on distinct nodes ────────────
            print(f"\nwaiting for {replicas} ready pods (timeout {READINESS_TIMEOUT_S}s)…")
            ready_pods = wait_n_pods_ready(selector, replicas, READINESS_TIMEOUT_S, sts_uid)
            node_names = assert_distinct_nodes(ready_pods)
            for i, (p, n) in enumerate(zip(ready_pods, node_names)):
                print(f"  pod-{i}: {p['metadata']['name']} node={n}")
            print(f"all {replicas} pods on distinct nodes: {', '.join(node_names)}")

            issuer_pod = ready_pods[0]["metadata"]["name"]
            print(f"\nport-forward localhost:{ISSUER_PORT} → {issuer_pod}:8080…")
            pf = wait_port_forward(ISSUER_PORT, 8080, issuer_pod)
            pf_procs.append(pf)
            print(f"port-forward pid={pf.pid}")

            if consumer:
                assert ternal_bin is not None
                probe = TernalProbe(ternal_bin, ISSUER, client_id, client_secret)
                probe.__enter__()
                print(f"  ternal-api probe started, login as qual@example.test…")
                probe.login("qual@example.test", browser_password, "qual-browser")
                print("  probe login OK")

            # ── issue token via first pod ────────────────────────────────
            print("\nissuing client_credentials token…")
            token_resp = http_post(
                f"{base}/oidc/token",
                {
                    "grant_type": "client_credentials",
                    "scope": GRANT_SCOPE,
                    "resource": ALLOWED_RESOURCE,
                },
                auth=(client_id, client_secret),
            )
            token = token_resp["access_token"]
            print(f"token issued, len={len(token) if token else 0}")

            # ── verify token + full JWKS via each of the 3 pre-fault pods ─
            baseline_jwks = None
            print(f"\nverifying token + full JWKS + scope via each pod sequentially…")
            for i, pod in enumerate(ready_pods):
                pname = pod["metadata"]["name"]
                if i > 0:
                    canonical = _introspect_and_jwks(base, token, client_id, client_secret, pf_procs, pod_name=pname, baseline_jwks=baseline_jwks)
                else:
                    canonical = _introspect_and_jwks(base, token, client_id, client_secret, pf_procs)
                    baseline_jwks = canonical
                if probe is not None:
                    probe.verify()
                    print(f"  ternal probe verify OK (pod-{i} pre-fault)")

            # ── fault: delete ONE pod with UID precondition ──────────────
            fault_pod = ready_pods[2]
            fault_pod_name = fault_pod["metadata"]["name"]
            fault_pod_uid = fault_pod["metadata"]["uid"]
            surviving_pod = ready_pods[1]
            surviving_pod_name = surviving_pod["metadata"]["name"]

            print(f"\n--- FAULT: deleting pod {fault_pod_name} (uid={fault_pod_uid}) with precondition ---")
            kubectl_delete("Pod", fault_pod_name, fault_pod_uid)
            print("pod deleted")

            # ── verify SAME token + full JWKS via surviving pod ─────────
            print(f"\nverifying SAME token + full JWKS via surviving pod {surviving_pod_name}…")
            _introspect_and_jwks(base, token, client_id, client_secret, pf_procs, pod_name=surviving_pod_name, baseline_jwks=baseline_jwks)
            if probe is not None:
                probe.verify()
                print("  ternal probe verify OK (survivor)")

            # ── wait for replacement pod (same ordinal, new UID) ─────────
            print(f"\nwaiting for replacement pod (timeout {POD_DELETE_READY_TIMEOUT_S}s)…")
            replacement = wait_pod_ready(selector, POD_DELETE_READY_TIMEOUT_S, sts_uid, exclude_pod_uid=fault_pod_uid, fault_pod_name=fault_pod_name)
            replacement_name = replacement["metadata"]["name"]
            replacement_uid = replacement["metadata"]["uid"]
            assert replacement_name == fault_pod_name, f"replacement pod name {replacement_name!r} != fault pod name {fault_pod_name!r}"
            assert replacement_uid != fault_pod_uid, "replacement pod has same UID — restart not proven"
            print(f"replacement pod ready: {replacement_name} uid={replacement_uid}")

            # ── verify SAME token + full JWKS on replacement ─────────────
            print(f"\nverifying SAME token + full JWKS on replacement pod {replacement_name}…")
            _introspect_and_jwks(base, token, client_id, client_secret, pf_procs, pod_name=replacement_name, baseline_jwks=baseline_jwks)
            if probe is not None:
                probe.verify()
                print("  ternal probe verify OK (replacement)")

            print(f"\n{'='*60}")
            print("QUALIFICATION PASSED (HA3)")
            print(f"{'='*60}")
            print(f"  token continuity    : PROVEN (issued via pod-0, verified via all 3)")
            print(f"  token survivability : PROVEN (surviving pod after single-pod fault)")
            print(f"  key continuity      : PROVEN (full JWKS unchanged after replacement)")
            print(f"  emptyDir loss       : PROVEN (pod uid changed)")
            print(f"  distinct nodes      : PROVEN ({', '.join(node_names)})")
            print(f"  network isolation   : UNQUALIFIED (IED policy enforcement disabled)")
            if probe is not None:
                print(f"  Retained Ternal consumer: PROVEN")
            print(f"  GCS prefix          : {prefix}")
            result = 0

        else:
            # ── Standalone: wait for 1 pod ready ────────────────────────
            print(f"\nwaiting for pod ready (timeout {READINESS_TIMEOUT_S}s)…")
            pod = wait_pod_ready(selector, READINESS_TIMEOUT_S, sts_uid)
            pod_name = pod["metadata"]["name"]
            pod_uid = pod["metadata"]["uid"]
            print(f"pod ready: {pod_name} uid={pod_uid}")

            print(f"\nport-forward localhost:{ISSUER_PORT} → pod:8080…")
            pf = wait_port_forward(ISSUER_PORT, 8080, pod_name)
            pf_procs.append(pf)
            print(f"port-forward pid={pf.pid}")

            if consumer:
                assert ternal_bin is not None
                assert browser_password is not None
                probe = TernalProbe(ternal_bin, ISSUER, client_id, client_secret)
                probe.__enter__()
                print(f"  ternal-api probe started, login as qual@example.test…")
                probe.login("qual@example.test", browser_password, "qual-browser")
                print("  probe login OK")

            # ── client_credentials token ─────────────────────────────────
            print("\nissuing client_credentials token…")
            token_resp = http_post(
                f"{base}/oidc/token",
                {
                    "grant_type": "client_credentials",
                    "scope": GRANT_SCOPE,
                    "resource": ALLOWED_RESOURCE,
                },
                auth=(client_id, client_secret),
            )
            token = token_resp["access_token"]
            print(f"token issued, len={len(token) if token else 0}")

            # ── introspect + JWKS baseline ──────────────────────────────
            canonical = _introspect_and_jwks(base, token, client_id, client_secret, pf_procs)
            baseline_jwks = canonical
            if probe is not None:
                probe.verify()
                print("  ternal probe verify OK (baseline)")

            # ── fault: delete pod with UID precondition ──────────────────
            print(f"\n--- FAULT: deleting pod {pod_name} (uid={pod_uid}) with precondition ---")
            kubectl_delete("Pod", pod_name, pod_uid)
            print("pod deleted")

            # ── wait for NEW pod ready (different UID) ───────────────────
            print(f"\nwaiting for replacement pod ready (timeout {POD_DELETE_READY_TIMEOUT_S}s)…")
            new_pod = wait_pod_ready(selector, POD_DELETE_READY_TIMEOUT_S, sts_uid, exclude_pod_uid=pod_uid)
            new_pod_name = new_pod["metadata"]["name"]
            new_pod_uid = new_pod["metadata"]["uid"]
            assert new_pod_uid != pod_uid, "replacement pod has same UID — restart not proven"
            print(f"new pod ready: {new_pod_name} uid={new_pod_uid}")

            # ── restart port-forward to new pod ──────────────────────────
            if pf_procs[-1].poll() is None:
                pf_procs[-1].kill()
                pf_procs[-1].wait(timeout=5)
            print(f"\nrestarting port-forward → {new_pod_name}…")
            pf = wait_port_forward(ISSUER_PORT, 8080, new_pod_name)
            pf_procs.append(pf)
            print(f"port-forward pid={pf.pid}")

            # ── verify SAME token + full JWKS on replacement ─────────────
            _introspect_and_jwks(base, token, client_id, client_secret, pf_procs, baseline_jwks=baseline_jwks)
            if probe is not None:
                probe.verify()
                print("  ternal probe verify OK (after replacement)")

            print(f"\n{'='*60}")
            print("QUALIFICATION PASSED")
            print(f"{'='*60}")
            print(f"  token continuity : PROVEN")
            print(f"  key continuity   : PROVEN")
            print(f"  emptyDir loss    : PROVEN (pod uid changed)")
            print(f"  network isolation: UNQUALIFIED (IED policy enforcement disabled)")
            if probe is not None:
                print(f"  Retained Ternal consumer: PROVEN")
            print(f"  GCS prefix       : {prefix}")
            result = 0

    except KeyboardInterrupt as exc:
        print(f"\nQUALIFICATION INTERRUPTED: {exc}", file=sys.stderr)
        result = 1
    except Exception as exc:
        print(f"\nQUALIFICATION FAILED: {exc}", file=sys.stderr)
        result = 1
    finally:
        cleanup()

    if cleanup_failed:
        return 1
    return result


if __name__ == "__main__":
    sys.exit(main())
