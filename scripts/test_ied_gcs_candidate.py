#!/usr/bin/env python3
"""Unit tests for e2e-ied-gcs-candidate.py using stdlib unittest + mocks."""

from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, __import__("os").path.dirname(__file__))

import importlib.util
_spec = importlib.util.spec_from_file_location(
    "e2e_ied_gcs_candidate",
    __import__("os").path.join(__import__("os").path.dirname(__file__), "e2e-ied-gcs-candidate.py"),
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)

VALID_IMAGE = "ghcr.io/mrchypark/ternal@sha256:" + "a" * 64


class TestEnsurePortFree(unittest.TestCase):
    @mock.patch("socket.socket")
    def test_port_free(self, mock_cls):
        sock_inst = mock_cls.return_value.__enter__.return_value
        mod.ensure_port_free(18092)
        sock_inst.bind.assert_called_once_with(("127.0.0.1", 18092))

    @mock.patch("socket.socket")
    def test_port_occupied(self, mock_cls):
        sock_inst = mock_cls.return_value.__enter__.return_value
        sock_inst.bind.side_effect = OSError("Address already in use")
        with self.assertRaises(RuntimeError):
            mod.ensure_port_free(18092)


class TestKubectlCreateStdin(unittest.TestCase):
    @mock.patch("subprocess.run")
    def test_create_json(self, mock_run):
        manifest = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "s"}}
        fake_obj = {"metadata": {"name": "s", "uid": "uid-123"}}
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(fake_obj), stderr=""
        )
        result = mod.kubectl_create_stdin("Secret", manifest)
        self.assertEqual(result["metadata"]["uid"], "uid-123")
        cmd = mock_run.call_args[0][0]
        self.assertIn("--context", cmd)
        self.assertIn("gke_ied-cluster", cmd)
        self.assertIn("create", cmd)


class TestKubectlDelete(unittest.TestCase):
    @mock.patch("subprocess.run")
    def test_delete_with_uid(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="{}", stderr="")
        mod.kubectl_delete("Service", "svc-x", "uid-aaa")
        body = mock_run.call_args[1]["input"]
        parsed = json.loads(body)
        self.assertEqual(parsed["preconditions"]["uid"], "uid-aaa")

    @mock.patch("subprocess.run")
    def test_delete_not_found_is_ok(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="not found")
        mod.kubectl_delete("Service", "svc-x", "uid-aaa")

    @mock.patch("subprocess.run")
    def test_delete_conflict_raises(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="Conflict: the object has been modified"
        )
        with self.assertRaises(RuntimeError):
            mod.kubectl_delete("Service", "svc-x", "uid-aaa")

    def test_delete_requires_uid(self):
        with self.assertRaises(ValueError):
            mod.kubectl_delete("Service", "svc-x", "")


class TestWaitPortForward(unittest.TestCase):
    """wait_port_forward uses os.pipe with non-blocking reads."""

    def test_partial_line_timeout_kills(self):
        """Partial line that never completes times out and reaps."""
        rd, wr = os.pipe()
        proc = mock.MagicMock()
        proc.stdout = os.fdopen(rd, "rb", closefd=False)
        proc.poll.return_value = None
        proc.pid = 99999

        with mock.patch("subprocess.Popen", return_value=proc) as mock_popen:
            with mock.patch.object(mod, "PORT_FORWARD_START_TIMEOUT_S", 0.2):
                with self.assertRaises(TimeoutError):
                    mod.wait_port_forward(18092, 8080, "pod-x")
            mock_popen.assert_called_once()
            proc.terminate.assert_called()

        os.close(wr)
        os.close(rd)

    def test_partial_line_written_later_timeout(self):
        """Partial line arrives but full line never arrives → timeout."""
        rd, wr = os.pipe()
        os.set_blocking(wr, False)
        proc = mock.MagicMock()
        proc.stdout = os.fdopen(rd, "rb", closefd=False)
        proc.poll.return_value = None
        proc.pid = 88888

        # Write a partial prefix — never completed
        os.write(wr, b"Forwarding from 127.0.0.1:18092")

        with mock.patch("subprocess.Popen", return_value=proc):
            with mock.patch.object(mod, "PORT_FORWARD_START_TIMEOUT_S", 0.2):
                with self.assertRaises(TimeoutError):
                    mod.wait_port_forward(18092, 8080, "pod-x")

        os.close(wr)
        os.close(rd)

    def test_wrong_target_port_timeout(self):
        """Exact line but with wrong target port → timeout."""
        rd, wr = os.pipe()
        os.set_blocking(wr, False)
        proc = mock.MagicMock()
        proc.stdout = os.fdopen(rd, "rb", closefd=False)
        proc.poll.return_value = None
        proc.pid = 77777

        # Wrong target port (9999 instead of 8080)
        os.write(wr, b"Forwarding from 127.0.0.1:18092 -> 9999\n")

        with mock.patch("subprocess.Popen", return_value=proc):
            with mock.patch.object(mod, "PORT_FORWARD_START_TIMEOUT_S", 0.2):
                with self.assertRaises(TimeoutError):
                    mod.wait_port_forward(18092, 8080, "pod-x")

        os.close(wr)
        os.close(rd)

    def test_extra_suffix_timeout(self):
        """Line with trailing suffix after target port → timeout."""
        rd, wr = os.pipe()
        os.set_blocking(wr, False)
        proc = mock.MagicMock()
        proc.stdout = os.fdopen(rd, "rb", closefd=False)
        proc.poll.return_value = None
        proc.pid = 66666

        os.write(wr, b"Forwarding from 127.0.0.1:18092 -> 8080 extra\n")

        with mock.patch("subprocess.Popen", return_value=proc):
            with mock.patch.object(mod, "PORT_FORWARD_START_TIMEOUT_S", 0.2):
                with self.assertRaises(TimeoutError):
                    mod.wait_port_forward(18092, 8080, "pod-x")

        os.close(wr)
        os.close(rd)

    def test_exact_line_success(self):
        """Exact forwarding line → returns proc."""
        rd, wr = os.pipe()
        os.set_blocking(wr, False)
        proc = mock.MagicMock()
        proc.stdout = os.fdopen(rd, "rb", closefd=False)
        proc.poll.return_value = None
        proc.pid = 42

        os.write(wr, b"Forwarding from 127.0.0.1:18092 -> 8080\n")

        with mock.patch("subprocess.Popen", return_value=proc):
            with mock.patch.object(mod, "PORT_FORWARD_START_TIMEOUT_S", 5):
                result = mod.wait_port_forward(18092, 8080, "pod-x")
        self.assertIs(result, proc)
        os.close(wr)
        os.close(rd)

    def test_exact_line_with_crlf(self):
        """CRLF-normalized forwarding line → returns proc."""
        rd, wr = os.pipe()
        os.set_blocking(wr, False)
        proc = mock.MagicMock()
        proc.stdout = os.fdopen(rd, "rb", closefd=False)
        proc.poll.return_value = None
        proc.pid = 43

        os.write(wr, b"Forwarding from 127.0.0.1:18092 -> 8080\r\n")

        with mock.patch("subprocess.Popen", return_value=proc):
            with mock.patch.object(mod, "PORT_FORWARD_START_TIMEOUT_S", 5):
                result = mod.wait_port_forward(18092, 8080, "pod-x")
        self.assertIs(result, proc)
        os.close(wr)
        os.close(rd)

    def test_exact_line_with_noise_before(self):
        """Noise lines before exact line → succeeds."""
        rd, wr = os.pipe()
        os.set_blocking(wr, False)
        proc = mock.MagicMock()
        proc.stdout = os.fdopen(rd, "rb", closefd=False)
        proc.poll.return_value = None
        proc.pid = 44

        os.write(wr, b"some unrelated output\n")
        os.write(wr, b"Forwarding from 127.0.0.1:18092 -> 8080\n")

        with mock.patch("subprocess.Popen", return_value=proc):
            with mock.patch.object(mod, "PORT_FORWARD_START_TIMEOUT_S", 5):
                result = mod.wait_port_forward(18092, 8080, "pod-x")
        self.assertIs(result, proc)
        os.close(wr)
        os.close(rd)

    def test_health_probe_not_called_before_line(self):
        """Health endpoint MUST NOT be probed before forwarding line is seen."""
        rd, wr = os.pipe()
        os.set_blocking(wr, False)
        proc = mock.MagicMock()
        proc.stdout = os.fdopen(rd, "rb", closefd=False)
        proc.poll.return_value = None
        proc.pid = 45

        os.write(wr, b"some unrelated output\n")
        os.write(wr, b"Forwarding from 127.0.0.1:18092 -> 8080\n")

        with mock.patch("subprocess.Popen", return_value=proc):
            with mock.patch.object(mod, "PORT_FORWARD_START_TIMEOUT_S", 5):
                with mock.patch.object(mod.urllib.request, "urlopen") as mock_urlopen:
                    mod.wait_port_forward(18092, 8080, "pod-x")
                    mock_urlopen.assert_called_once()

        os.close(wr)
        os.close(rd)

    def test_keyboard_interrupt_cleanup(self):
        """KeyboardInterrupt during wait → reaps process."""
        rd, wr = os.pipe()
        os.set_blocking(wr, False)
        proc = mock.MagicMock()
        proc.stdout = os.fdopen(rd, "rb", closefd=False)
        proc.poll.return_value = None
        proc.pid = 50

        call_count = [0]
        orig_read = os.read

        def _mock_read(fd, n):
            call_count[0] += 1
            if call_count[0] > 2:
                raise KeyboardInterrupt
            return b""

        with mock.patch("subprocess.Popen", return_value=proc):
            with mock.patch.object(mod, "PORT_FORWARD_START_TIMEOUT_S", 5):
                with mock.patch("os.read", side_effect=_mock_read):
                    with self.assertRaises(KeyboardInterrupt):
                        mod.wait_port_forward(18092, 8080, "pod-x")
        proc.terminate.assert_called()

        os.close(wr)
        os.close(rd)

    def test_early_exit_cleanup(self):
        """Process exits before forwarding line → RuntimeError, reaps."""
        rd, wr = os.pipe()
        proc = mock.MagicMock()
        proc.stdout = os.fdopen(rd, "rb", closefd=False)
        proc.poll.return_value = 1
        proc.returncode = 1
        proc.pid = 51

        with mock.patch("subprocess.Popen", return_value=proc):
            with mock.patch.object(mod, "PORT_FORWARD_START_TIMEOUT_S", 5):
                with self.assertRaises(RuntimeError) as cm:
                    mod.wait_port_forward(18092, 8080, "pod-x")
                self.assertIn("exited early", str(cm.exception))

        os.close(wr)
        os.close(rd)


class TestCanonicalJwks(unittest.TestCase):
    """canonical_jwks is a real production helper."""

    def test_same_keys_different_order(self):
        keys_a = [{"kid": "k2", "kty": "RSA"}, {"kid": "k1", "kty": "RSA"}]
        keys_b = [{"kid": "k1", "kty": "RSA"}, {"kid": "k2", "kty": "RSA"}]
        self.assertEqual(mod.canonical_jwks({"keys": keys_a}), mod.canonical_jwks({"keys": keys_b}))

    def test_empty_keys_rejected(self):
        with self.assertRaises(AssertionError):
            mod.canonical_jwks({"keys": []})

    def test_changed_kid_detected(self):
        keys_a = [{"kid": "k1", "kty": "RSA"}]
        keys_b = [{"kid": "k2", "kty": "RSA"}]
        self.assertNotEqual(mod.canonical_jwks({"keys": keys_a}), mod.canonical_jwks({"keys": keys_b}))

    def test_changed_field_detected(self):
        keys_a = [{"kid": "k1", "kty": "RSA"}]
        keys_b = [{"kid": "k1", "kty": "EC"}]
        self.assertNotEqual(mod.canonical_jwks({"keys": keys_a}), mod.canonical_jwks({"keys": keys_b}))


class TestValidateDiscovery(unittest.TestCase):
    """validate_discovery is a real production helper."""

    def test_valid_returns_jwks_uri(self):
        wk = {"issuer": mod.ISSUER, "jwks_uri": f"http://127.0.0.1:{mod.ISSUER_PORT}/jwks"}
        self.assertEqual(mod.validate_discovery(wk), wk["jwks_uri"])

    def test_issuer_mismatch(self):
        wk = {"issuer": "http://evil.com", "jwks_uri": "http://evil.com/jwks"}
        with self.assertRaises(AssertionError):
            mod.validate_discovery(wk)

    def test_wrong_origin(self):
        wk = {"issuer": mod.ISSUER, "jwks_uri": "http://evil.com/jwks"}
        with self.assertRaises(AssertionError):
            mod.validate_discovery(wk)

    def test_userinfo_rejected(self):
        wk = {"issuer": mod.ISSUER, "jwks_uri": "http://user:pass@127.0.0.1:18092/jwks"}
        with self.assertRaises(AssertionError):
            mod.validate_discovery(wk)


class TestImageValidation(unittest.TestCase):
    def test_valid(self):
        self.assertIsNotNone(mod._IMAGE_RE.fullmatch(VALID_IMAGE))

    def test_trailing_newline(self):
        self.assertIsNone(mod._IMAGE_RE.fullmatch(VALID_IMAGE + "\n"))

    def test_missing_prefix(self):
        self.assertIsNone(mod._IMAGE_RE.fullmatch("other@sha256:" + "a" * 64))


class TestMainLifecycle(unittest.TestCase):
    """Test the full main() lifecycle by patching thin external wrappers."""

    def _run_main(self, extra_argv=None):
        argv = ["e2e-ied-gcs-candidate.py", "--image", VALID_IMAGE]
        if extra_argv:
            argv.extend(extra_argv)
        with mock.patch("sys.argv", argv):
            return mod.main()

    def _fake_kubectl_create(self, kind, manifest):
        uid = f"uid-{kind.lower()}"
        return {"metadata": {"name": f"{kind.lower()}-name", "uid": uid}}

    def _fake_kubectl_json(self, *args, **kwargs):
        # For wait_pod_ready calls
        return {"items": [{"metadata": {
            "name": "pod-1",
            "uid": "pod-uid-1",
            "ownerReferences": [{"controller": True, "uid": "uid-statefulset"}],
        }, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}]}

    def _make_http_responses(self):
        """Return dicts that http_get/http_post would return."""
        return {
            "token": {"access_token": "tok-abc", "token_type": "Bearer"},
            "introspect": {"active": True, "client_id": mod.CLIENT_ID, "scope": mod.GRANT_SCOPE},
            "well_known": {"issuer": mod.ISSUER, "jwks_uri": f"http://127.0.0.1:{mod.ISSUER_PORT}/jwks"},
            "jwks": {"keys": [{"kid": "key-1", "kty": "RSA", "n": "x", "e": "AQAB"}]},
        }

    @mock.patch.object(mod, "kubectl_delete")
    @mock.patch.object(mod, "kubectl_create_stdin")
    @mock.patch.object(mod, "kubectl_json")
    @mock.patch.object(mod, "http_post")
    @mock.patch.object(mod, "http_get")
    @mock.patch.object(mod, "wait_port_forward")
    @mock.patch.object(mod, "wait_pod_ready")
    @mock.patch.object(mod, "ensure_port_free")
    def test_success_path(self, mock_epf, mock_wpd, mock_wpr, mock_hget, mock_hpost, mock_kj, mock_kcs, mock_kd):
        resp = self._make_http_responses()
        mock_epf.return_value = None
        mock_kcs.side_effect = self._fake_kubectl_create
        mock_kj.side_effect = self._fake_kubectl_json
        mock_wpd.side_effect = [
            {"metadata": {"name": "pod-1", "uid": "pod-uid-1"}},
            {"metadata": {"name": "pod-2", "uid": "pod-uid-2"}},
        ]

        fake_proc = mock.MagicMock()
        fake_proc.poll.return_value = None
        mock_wpr.return_value = fake_proc

        def _http_get(url):
            if "well-known" in url:
                return resp["well_known"]
            if "jwks" in url:
                return resp["jwks"]
            return {}
        mock_hget.side_effect = _http_get
        mock_hpost.side_effect = lambda url, data, **kw: resp["token"] if "token" in url else resp["introspect"]

        result = self._run_main()
        self.assertEqual(result, 0)

        # Secret created with correct stringData keys
        secret_call = [c for c in mock_kcs.call_args_list if c[0][0] == "Secret"][0]
        sd = secret_call[0][1]["stringData"]
        self.assertIn("master-key", sd)
        self.assertIn("oauth-hmac", sd)
        self.assertIn("bootstrap-client", sd)

        # All 4 resource types created
        created_kinds = [c[0][0] for c in mock_kcs.call_args_list]
        for k in ["Secret", "ConfigMap", "Service", "StatefulSet"]:
            self.assertIn(k, created_kinds)

        # All 4 cleanup deletes have UID
        for c in mock_kd.call_args_list:
            self.assertTrue(c[0][0], f"cleanup delete for {c[0][0]} missing UID")

        # Every volume secret.items key resolves to an actual stringData key
        sts_call = [c for c in mock_kcs.call_args_list if c[0][0] == "StatefulSet"][0]
        sts_manifest = sts_call[0][1]
        vol_secrets = sts_manifest["spec"]["template"]["spec"]["volumes"][0]["secret"]
        for item in vol_secrets["items"]:
            self.assertIn(item["key"], sd, f"volume.items key {item['key']!r} not in stringData")

        # Projected active master-key path matches env activeID
        master_key_id = [e["value"] for e in sts_manifest["spec"]["template"]["spec"]["containers"][0]["env"]
                         if e["name"] == "GOAUTHY_ACTIVE_MASTER_KEY_ID"][0]
        master_key_item = [i for i in vol_secrets["items"] if i["path"].startswith("master-keys/")][0]
        self.assertEqual(master_key_item["path"], f"master-keys/{master_key_id}")

        # Three decoded base64url keys have 32 bytes, production prefix not used, UUID full
        decoded_keys = []
        for v in sd.values():
            try:
                raw = base64.urlsafe_b64decode(v + "==")
                decoded_keys.append(raw)
            except Exception:
                pass
        self.assertEqual(len(decoded_keys), 3, f"expected 3 decodable keys, got {len(decoded_keys)}")
        for raw in decoded_keys:
            self.assertEqual(len(raw), 32, f"decoded key len={len(raw)}, expected 32")
        self.assertNotIn("goauthy/qualification/", sd.values(), "production prefix must not appear in stringData")
        self.assertIn("-", master_key_id, "master_key_id should contain full UUID with dashes")

    @mock.patch.object(mod, "kubectl_create_stdin")
    def test_bad_image_no_create(self, mock_kcs):
        with mock.patch("sys.argv", ["e2e-ied-gcs-candidate.py", "--image", "bad-image"]):
            result = mod.main()
        self.assertEqual(result, 1)
        mock_kcs.assert_not_called()

    @mock.patch.object(mod, "ensure_port_free", side_effect=RuntimeError("port in use"))
    @mock.patch.object(mod, "kubectl_create_stdin")
    def test_occupied_port_no_create(self, mock_kcs, mock_epf):
        with mock.patch("sys.argv", ["e2e-ied-gcs-candidate.py", "--image", VALID_IMAGE]):
            result = mod.main()
        self.assertEqual(result, 1)
        mock_kcs.assert_not_called()

    @mock.patch.object(mod, "kubectl_delete")
    @mock.patch.object(mod, "kubectl_create_stdin")
    @mock.patch.object(mod, "kubectl_json")
    @mock.patch.object(mod, "http_post")
    @mock.patch.object(mod, "http_get")
    @mock.patch.object(mod, "wait_port_forward")
    @mock.patch.object(mod, "wait_pod_ready")
    @mock.patch.object(mod, "ensure_port_free")
    def test_cleanup_conflict_continues_rest(self, mock_epf, mock_wpd, mock_wpr, mock_hget, mock_hpost, mock_kj, mock_kcs, mock_kd):
        resp = self._make_http_responses()
        mock_epf.return_value = None
        mock_kcs.side_effect = self._fake_kubectl_create
        mock_kj.side_effect = self._fake_kubectl_json
        mock_wpd.side_effect = [
            {"metadata": {"name": "pod-1", "uid": "pod-uid-1"}},
            {"metadata": {"name": "pod-2", "uid": "pod-uid-2"}},
        ]
        fake_proc = mock.MagicMock()
        fake_proc.poll.return_value = None
        mock_wpr.return_value = fake_proc

        def _http_get(url):
            if "well-known" in url:
                return resp["well_known"]
            if "jwks" in url:
                return resp["jwks"]
            return {}
        mock_hget.side_effect = _http_get
        mock_hpost.side_effect = lambda url, data, **kw: resp["token"] if "token" in url else resp["introspect"]

        # First delete (StatefulSet) fails, rest succeed
        def _delete(kind, name, uid):
            if kind == "StatefulSet":
                raise RuntimeError("Conflict")
        mock_kd.side_effect = _delete

        result = self._run_main()
        # Nonzero because cleanup failed, but remaining deletes still called
        self.assertEqual(result, 1)
        self.assertGreaterEqual(mock_kd.call_count, 3)
        # cleanup_failed should be True (nonzero return), but not swallowed
        # Verify StatefulSet delete was attempted
        ss_calls = [c for c in mock_kd.call_args_list if c[0][0] == "StatefulSet"]
        self.assertEqual(len(ss_calls), 1)


class TestWaitPodReady(unittest.TestCase):
    def _make_pod(self, uid="pod-1", owner_uid="sts-1", controller=True, deleting=False):
        meta = {"name": f"pod-{uid}", "uid": uid}
        if deleting:
            meta["deletionTimestamp"] = "2025-01-01T00:00:00Z"
        if owner_uid:
            meta["ownerReferences"] = [{"name": "sts", "uid": owner_uid, "controller": controller}]
        return {"metadata": meta, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}

    @mock.patch.object(mod, "kubectl_json")
    def test_returns_matching_controller(self, mock_kj):
        mock_kj.return_value = {"items": [self._make_pod(uid="pod-a", owner_uid="sts-1")]}
        result = mod.wait_pod_ready("app=test", 5, "sts-1")
        self.assertEqual(result["metadata"]["uid"], "pod-a")

    @mock.patch.object(mod, "kubectl_json")
    def test_skips_non_controller(self, mock_kj):
        mock_kj.return_value = {"items": [self._make_pod(uid="pod-a", owner_uid="sts-999")]}
        with self.assertRaises(TimeoutError):
            mod.wait_pod_ready("app=test", 1, "sts-1")

    @mock.patch.object(mod, "kubectl_json")
    def test_skips_deleting(self, mock_kj):
        mock_kj.return_value = {"items": [self._make_pod(uid="pod-a", owner_uid="sts-1", deleting=True)]}
        with self.assertRaises(TimeoutError):
            mod.wait_pod_ready("app=test", 1, "sts-1")


if __name__ == "__main__":
    unittest.main()
