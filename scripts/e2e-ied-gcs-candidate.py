#!/usr/bin/env python3
"""Standalone IED GCS qualification runner.

Creates per-run K8s resources (Secret, ConfigMap, Service, StatefulSet) in
namespace ternal-auth, runs client_credentials + introspect + JWKS flow,
faults the pod, proves token/key continuity across restart, then cleans up.

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

# ── constants ────────────────────────────────────────────────────────────────
NAMESPACE = "ternal-auth"
SERVICE_ACCOUNT = "ternal-goauthy"
BUCKET = "ternal-ied-602454948273"
CLIENT_ID = "qual-s1-goauthy"
ISSUER_PORT = 18092
ISSUER = f"http://127.0.0.1:{ISSUER_PORT}"
REDIRECT_URI = f"http://127.0.0.1:{ISSUER_PORT}/oidc/callback"
ALLOWED_RESOURCE = "https://api.example.test/v1"
GRANT_SCOPE = "goauthy.read"
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


def wait_pod_ready(selector: str, timeout_s: int, expected_controller_uid: str, exclude_pod_uid: str | None = None) -> dict:
    """Poll for a pod matching label selector that is Ready.

    Only returns a pod whose controller ownerReference UID matches
    *expected_controller_uid*.  Skips pods with deletionTimestamp or whose
    own UID equals *exclude_pod_uid*.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pods = kubectl_json(["get", "pods", "-l", selector])
        for pod in pods.get("items", []):
            meta = pod.get("metadata", {})
            if meta.get("deletionTimestamp"):
                continue
            if exclude_pod_uid and meta.get("uid") == exclude_pod_uid:
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
    raise TimeoutError(f"No ready pod for selector={selector} within {timeout_s}s")


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


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(description="IED GCS qualification runner")
    ap.add_argument("--image", required=True, help="Immutable container image digest")
    args = ap.parse_args()

    if not _IMAGE_RE.fullmatch(args.image):
        print(f"ERROR: --image does not match required pattern", file=sys.stderr)
        return 1

    run_id = str(uuid.uuid4())
    prefix = f"goauthy/qualification/{run_id}/s1"
    resource_label = f"goauthy-qual-s1-{run_id}"
    secret_name = f"goauthy-qual-s1-secrets-{run_id}"
    configmap_name = f"goauthy-qual-config-{run_id}"
    service_name = f"goauthy-qual-s1-{run_id}"
    statefulset_name = f"goauthy-qual-s1-{run_id}"
    master_key_id = f"qual-s1-{run_id}"

    created: dict[str, tuple[str, str]] = {}  # kind -> (name, uid)
    pf_proc: subprocess.Popen | None = None
    token: str | None = None
    jwks_kid_before: str | None = None
    result = 1
    cleanup_failed = False

    def cleanup():
        print(f"\n{'='*60}")
        print("CLEANUP")
        print(f"{'='*60}")
        nonlocal cleanup_failed
        cleanup_failed = False
        if pf_proc and pf_proc.poll() is None:
            try:
                pf_proc.terminate()
                pf_proc.wait(timeout=5)
                print(f"  killed port-forward pid={pf_proc.pid}")
            except Exception:
                try:
                    pf_proc.kill()
                    pf_proc.wait(timeout=5)
                    print(f"  killed port-forward pid={pf_proc.pid}")
                except Exception as exc:
                    print(f"  port-forward pid={pf_proc.pid} stop FAILED: {exc}")
                    cleanup_failed = True
        # Delete in reverse dependency order
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

    # ── generate secrets ─────────────────────────────────────────────────
    master_key = secrets.token_bytes(32)
    hmac_secret = secrets.token_bytes(32)
    client_secret_bytes = secrets.token_bytes(32)
    client_secret = b64url(client_secret_bytes)

    secret_manifest = {
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
        "stringData": {
            "master-key": b64url(master_key),
            "oauth-hmac": b64url(hmac_secret),
            "bootstrap-client": client_secret,
        },
    }

    configmap_manifest = {
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
            "issuer-s1": ISSUER,
            "gcs-bucket": BUCKET,
            "gcs-prefix-s1": prefix,
            "bootstrap-client-id-s1": CLIENT_ID,
            "bootstrap-redirect-uri-s1": REDIRECT_URI,
        },
    }

    service_manifest = {
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
            "ports": [{"name": "http", "port": 8080, "targetPort": "http"}],
        },
    }

    statefulset_manifest = {
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
        "spec": {
            "serviceName": service_name,
            "podManagementPolicy": "Parallel",
            "replicas": 1,
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
                            "image": args.image,
                            "imagePullPolicy": "IfNotPresent",
                            "ports": [{"name": "http", "containerPort": 8080}],
                            "env": [
                                {"name": "GOAUTHY_LISTEN_ADDR", "value": ":8080"},
                                {"name": "GOAUTHY_ISSUER", "valueFrom": {"configMapKeyRef": {"name": configmap_name, "key": "issuer-s1"}}},
                                {"name": "GOAUTHY_SIGNING_KEY_ROTATION_PERIOD", "value": "720h"},
                                {"name": "GOAUTHY_BROWSER_SESSION_IDLE_TIMEOUT", "value": "90m"},
                                {"name": "GOAUTHY_CLUSTER_ID", "value": resource_label},
                                {"name": "GOAUTHY_NODE_ID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.name"}}},
                                {"name": "GOAUTHY_DATA_DIR", "value": "/var/lib/goauthy"},
                                {"name": "SQLITE_TMPDIR", "value": "/tmp"},
                                {"name": "GOAUTHY_RHIZA_PROFILE", "value": "standalone"},
                                {"name": "GOAUTHY_RHIZA_REQUIRE_OBJECT_STORE", "value": "true"},
                                {"name": "GOAUTHY_RHIZA_OBJECT_STORE_PROVIDER", "value": "gcs"},
                                {"name": "GOAUTHY_RHIZA_OBJECT_STORE_BUCKET", "valueFrom": {"configMapKeyRef": {"name": configmap_name, "key": "gcs-bucket"}}},
                                {"name": "GOAUTHY_RHIZA_OBJECT_STORE_PREFIX", "valueFrom": {"configMapKeyRef": {"name": configmap_name, "key": "gcs-prefix-s1"}}},
                                {"name": "GOAUTHY_MASTER_KEY_DIR", "value": "/run/secrets/master-keys"},
                                {"name": "GOAUTHY_ACTIVE_MASTER_KEY_ID", "value": master_key_id},
                                {"name": "GOAUTHY_OAUTH_HMAC_SECRET_FILE", "value": "/run/secrets/oauth-hmac"},
                                {"name": "GOAUTHY_BOOTSTRAP_CLIENT_SECRET_FILE", "value": "/run/secrets/bootstrap-client"},
                                {"name": "GOAUTHY_BOOTSTRAP_CLIENT_ID", "valueFrom": {"configMapKeyRef": {"name": configmap_name, "key": "bootstrap-client-id-s1"}}},
                                {"name": "GOAUTHY_BOOTSTRAP_REDIRECT_URI", "valueFrom": {"configMapKeyRef": {"name": configmap_name, "key": "bootstrap-redirect-uri-s1"}}},
                                {"name": "GOAUTHY_BOOTSTRAP_ALLOWED_RESOURCES", "value": f'["{ALLOWED_RESOURCE}"]'},
                                {"name": "GOAUTHY_RFC8252_LOOPBACK_REDIRECTS", "value": "false"},
                            ],
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
                                ],
                            },
                        },
                        {"name": "sqlite-tmp", "emptyDir": {"sizeLimit": "64Mi"}},
                        {"name": "data", "emptyDir": {"sizeLimit": "1Gi"}},
                    ],
                },
            },
        },
    }

    try:
        # ── verify port free before creating resources ────────────────────
        ensure_port_free(ISSUER_PORT)

        # ── create resources ─────────────────────────────────────────────
        print(f"run_id    = {run_id}")
        print(f"prefix    = {prefix}")
        print(f"label     = {resource_label}")
        print(f"image     = {args.image}")
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

        # ── wait for pod ready ───────────────────────────────────────────
        selector = f"app.kubernetes.io/name=goauthy,app.kubernetes.io/part-of={resource_label}"
        print(f"\nwaiting for pod ready (timeout {READINESS_TIMEOUT_S}s)…")
        pod = wait_pod_ready(selector, READINESS_TIMEOUT_S, sts_uid)
        pod_name = pod["metadata"]["name"]
        pod_uid = pod["metadata"]["uid"]
        print(f"pod ready: {pod_name} uid={pod_uid}")

        # ── port-forward ─────────────────────────────────────────────────
        print(f"\nport-forward localhost:{ISSUER_PORT} → pod:8080…")
        pf_proc = wait_port_forward(ISSUER_PORT, 8080, pod_name)
        print(f"port-forward pid={pf_proc.pid}")

        base = f"http://127.0.0.1:{ISSUER_PORT}"

        # ── client_credentials token ─────────────────────────────────────
        print("\nissuing client_credentials token…")
        token_resp = http_post(
            f"{base}/oidc/token",
            {
                "grant_type": "client_credentials",
                "scope": GRANT_SCOPE,
                "resource": ALLOWED_RESOURCE,
            },
            auth=(CLIENT_ID, client_secret),
        )
        token = token_resp["access_token"]
        print(f"token issued, len={len(token) if token else 0}")

        # ── introspect ───────────────────────────────────────────────────
        print("introspecting token…")
        intro = http_post(
            f"{base}/oidc/introspect",
            {"token": token},
            auth=(CLIENT_ID, client_secret),
        )
        assert intro.get("active") is True, f"token not active: {intro}"
        assert intro.get("client_id") == CLIENT_ID, f"wrong client_id: {intro}"
        assert intro.get("scope") == GRANT_SCOPE, f"wrong scope: {intro}"
        print(f"introspect OK: active={intro['active']} client_id={intro['client_id']}")

        # ── JWKS discovery ───────────────────────────────────────────────
        print("fetching JWKS via discovery…")
        well_known = http_get(f"{base}/.well-known/openid-configuration")
        jwks_uri = validate_discovery(well_known)
        jwks = http_get(jwks_uri)
        jwks_kid_before = jwks["keys"][0]["kid"]
        print(f"JWKS kid={jwks_kid_before}  keys={len(jwks['keys'])}")

        # ── fault: delete pod with UID precondition ──────────────────────
        print(f"\n--- FAULT: deleting pod {pod_name} (uid={pod_uid}) with precondition ---")
        kubectl_delete("Pod", pod_name, pod_uid)
        print("pod deleted")

        # ── wait for NEW pod ready (different UID) ───────────────────────
        print(f"\nwaiting for replacement pod ready (timeout {POD_DELETE_READY_TIMEOUT_S}s)…")
        new_pod = wait_pod_ready(selector, POD_DELETE_READY_TIMEOUT_S, sts_uid, exclude_pod_uid=pod_uid)
        new_pod_name = new_pod["metadata"]["name"]
        new_pod_uid = new_pod["metadata"]["uid"]
        assert new_pod_uid != pod_uid, "replacement pod has same UID — restart not proven"
        print(f"new pod ready: {new_pod_name} uid={new_pod_uid}")

        # ── restart port-forward to new pod ──────────────────────────────
        if pf_proc.poll() is None:
            pf_proc.kill()
            pf_proc.wait(timeout=5)
        print(f"\nrestarting port-forward → {new_pod_name}…")
        pf_proc = wait_port_forward(ISSUER_PORT, 8080, new_pod_name)
        print(f"port-forward pid={pf_proc.pid}")

        # ── introspect SAME pre-fault token ──────────────────────────────
        print("\nre-introspecting SAME pre-fault token…")
        intro2 = http_post(
            f"{base}/oidc/introspect",
            {"token": token},
            auth=(CLIENT_ID, client_secret),
        )
        assert intro2.get("active") is True, f"token not active after restart: {intro2}"
        assert intro2.get("client_id") == CLIENT_ID
        assert intro2.get("scope") == GRANT_SCOPE
        print(f"introspect OK after restart: active={intro2['active']}")

        # ── verify signing keys unchanged (canonical full JWKS comparison) ─
        print("verifying JWKS keys unchanged…")
        jwks2 = http_get(jwks_uri)
        canonical_before = canonical_jwks(jwks)
        canonical_after = canonical_jwks(jwks2)
        assert canonical_before == canonical_after, (
            f"JWKS keyset changed after restart"
        )
        print(f"JWKS keys unchanged: {len(jwks['keys'])} keys")

        # ── success ──────────────────────────────────────────────────────
        print(f"\n{'='*60}")
        print("QUALIFICATION PASSED")
        print(f"{'='*60}")
        print(f"  token continuity : PROVEN")
        print(f"  key continuity   : PROVEN")
        print(f"  emptyDir loss    : PROVEN (pod uid changed)")
        print(f"  network isolation: UNQUALIFIED (IED policy enforcement disabled)")
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
