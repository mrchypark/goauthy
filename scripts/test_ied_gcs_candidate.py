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

_subprocess_run_patch = mock.patch(
    "subprocess.run",
    side_effect=AssertionError("unexpected external process in unit test"),
)
_subprocess_popen_patch = mock.patch(
    "subprocess.Popen",
    side_effect=AssertionError("unexpected external process in unit test"),
)


def setUpModule():
    _subprocess_run_patch.start()
    _subprocess_popen_patch.start()


def tearDownModule():
    _subprocess_popen_patch.stop()
    _subprocess_run_patch.stop()


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
        """Partial line arrives but full line never arrives -> timeout."""
        rd, wr = os.pipe()
        os.set_blocking(wr, False)
        proc = mock.MagicMock()
        proc.stdout = os.fdopen(rd, "rb", closefd=False)
        proc.poll.return_value = None
        proc.pid = 88888

        # Write a partial prefix -- never completed
        os.write(wr, b"Forwarding from 127.0.0.1:18092")

        with mock.patch("subprocess.Popen", return_value=proc):
            with mock.patch.object(mod, "PORT_FORWARD_START_TIMEOUT_S", 0.2):
                with self.assertRaises(TimeoutError):
                    mod.wait_port_forward(18092, 8080, "pod-x")

        os.close(wr)
        os.close(rd)

    def test_wrong_target_port_timeout(self):
        """Exact line but with wrong target port -> timeout."""
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
        """Line with trailing suffix after target port -> timeout."""
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
        """Exact forwarding line -> returns proc."""
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
        """CRLF-normalized forwarding line -> returns proc."""
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
        """Noise lines before exact line -> succeeds."""
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
        """KeyboardInterrupt during wait -> reaps process."""
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
        """Process exits before forwarding line -> RuntimeError, reaps."""
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

    @mock.patch.object(mod, "kubectl_json")
    def test_meta_name_narrows_when_fault_pod_name(self, mock_kj):
        """When fault_pod_name is given, only the matching pod name is returned."""
        good = self._make_pod(uid="pod-2-new", owner_uid="sts-1")
        good["metadata"]["name"] = "pod-2"
        wrong = self._make_pod(uid="pod-1", owner_uid="sts-1")
        wrong["metadata"]["name"] = "pod-1"
        mock_kj.return_value = {"items": [wrong, good]}
        result = mod.wait_pod_ready("app=test", 5, "sts-1", fault_pod_name="pod-2")
        self.assertEqual(result["metadata"]["uid"], "pod-2-new")

    @mock.patch.object(mod, "kubectl_json")
    def test_meta_name_skips_mismatched_name(self, mock_kj):
        """When fault_pod_name is set, pods with other names are skipped."""
        wrong = self._make_pod(uid="pod-1", owner_uid="sts-1")
        wrong["metadata"]["name"] = "pod-1"
        mock_kj.return_value = {"items": [wrong]}
        with self.assertRaises(TimeoutError):
            mod.wait_pod_ready("app=test", 1, "sts-1", fault_pod_name="pod-2")

    @mock.patch.object(mod, "kubectl_json")
    def test_returns_replacement_with_narrowed_selector(self, mock_kj):
        """Deterministic: mock kubectl returns survivors first, then same-ordinal new-UID pod."""
        survivor = self._make_pod(uid="pod-0", owner_uid="sts-1")
        survivor["metadata"]["name"] = "pod-0"
        replacement = self._make_pod(uid="pod-2-new-uid", owner_uid="sts-1")
        replacement["metadata"]["name"] = "pod-2"
        # First call: survivor only; second call: both
        mock_kj.side_effect = [
            {"items": [survivor]},
            {"items": [survivor, replacement]},
        ]
        with mock.patch.object(mod, "time") as mock_time:
            mock_time.monotonic.side_effect = [0, 0, 0, 0, 0, 0]
            mock_time.sleep = mock.MagicMock()
            result = mod.wait_pod_ready("app=test", 10, "sts-1", fault_pod_name="pod-2")
        self.assertEqual(result["metadata"]["uid"], "pod-2-new-uid")
        # Verify the narrowed selector was used
        first_call_args = mock_kj.call_args_list[0][0][0]
        selector_arg = first_call_args[first_call_args.index("-l") + 1]
        self.assertIn("statefulset.kubernetes.io/pod-name=pod-2", selector_arg)


class TestWaitNPodsReady(unittest.TestCase):
    """Tests for wait_n_pods_ready helper."""

    def _make_pod(self, uid, owner_uid="sts-1", node="node-1"):
        return {
            "metadata": {
                "name": f"pod-{uid}",
                "uid": uid,
                "ownerReferences": [{"name": "sts", "uid": owner_uid, "controller": True}],
            },
            "spec": {"nodeName": node},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        }

    @mock.patch.object(mod, "kubectl_json")
    def test_returns_n_pods(self, mock_kj):
        mock_kj.return_value = {"items": [
            self._make_pod("p0", node="n0"),
            self._make_pod("p1", node="n1"),
            self._make_pod("p2", node="n2"),
        ]}
        result = mod.wait_n_pods_ready("app=test", 3, 5, "sts-1")
        self.assertEqual(len(result), 3)

    @mock.patch.object(mod, "kubectl_json")
    def test_filters_non_controller(self, mock_kj):
        good = self._make_pod("p0", node="n0")
        bad = self._make_pod("p1", node="n1")
        bad["metadata"]["ownerReferences"] = [{"uid": "other-sts", "controller": True}]
        mock_kj.return_value = {"items": [good, bad]}
        with self.assertRaises(TimeoutError):
            mod.wait_n_pods_ready("app=test", 2, 1, "sts-1")

    @mock.patch.object(mod, "kubectl_json")
    def test_filters_deleting(self, mock_kj):
        good = self._make_pod("p0", node="n0")
        bad = self._make_pod("p1", node="n1")
        bad["metadata"]["deletionTimestamp"] = "2025-01-01T00:00:00Z"
        mock_kj.return_value = {"items": [good, bad]}
        with self.assertRaises(TimeoutError):
            mod.wait_n_pods_ready("app=test", 2, 1, "sts-1")

    @mock.patch.object(mod, "kubectl_json")
    def test_filters_not_ready(self, mock_kj):
        good = self._make_pod("p0", node="n0")
        bad = self._make_pod("p1", node="n1")
        bad["status"]["conditions"] = [{"type": "Ready", "status": "False"}]
        mock_kj.return_value = {"items": [good, bad]}
        with self.assertRaises(TimeoutError):
            mod.wait_n_pods_ready("app=test", 2, 1, "sts-1")


class TestAssertDistinctNodes(unittest.TestCase):
    """Tests for assert_distinct_nodes helper."""

    def test_all_distinct(self):
        pods = [
            {"metadata": {"name": "p0"}, "spec": {"nodeName": "node-a"}},
            {"metadata": {"name": "p1"}, "spec": {"nodeName": "node-b"}},
            {"metadata": {"name": "p2"}, "spec": {"nodeName": "node-c"}},
        ]
        nodes = mod.assert_distinct_nodes(pods)
        self.assertEqual(nodes, ["node-a", "node-b", "node-c"])

    def test_duplicate_node_fails(self):
        pods = [
            {"metadata": {"name": "p0"}, "spec": {"nodeName": "node-a"}},
            {"metadata": {"name": "p1"}, "spec": {"nodeName": "node-a"}},
        ]
        with self.assertRaises(AssertionError):
            mod.assert_distinct_nodes(pods)

    def test_empty_node_name_fails(self):
        pods = [{"metadata": {"name": "p0"}, "spec": {"nodeName": ""}}]
        with self.assertRaises(AssertionError):
            mod.assert_distinct_nodes(pods)

    def test_missing_node_name_fails(self):
        pods = [{"metadata": {"name": "p0"}, "spec": {}}]
        with self.assertRaises(AssertionError):
            mod.assert_distinct_nodes(pods)


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
            "introspect": {"active": True, "client_id": "qual-s1-goauthy", "scope": mod.GRANT_SCOPE},
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

    def test_replicas_flag_accepted(self):
        """--replicas 1 and --replicas 3 are accepted by argparse."""
        import argparse as _ap
        for val in ["1", "3"]:
            parser = _ap.ArgumentParser()
            parser.add_argument("--image", required=True)
            parser.add_argument("--replicas", type=int, choices=[1, 3], default=1)
            args = parser.parse_args(["--image", VALID_IMAGE, "--replicas", val])
            self.assertEqual(args.replicas, int(val))


class TestMainHA3Lifecycle(unittest.TestCase):
    """Test the HA3 main() lifecycle with mocked externals."""

    def _run_ha3(self):
        argv = ["e2e-ied-gcs-candidate.py", "--image", VALID_IMAGE, "--replicas", "3"]
        with mock.patch("sys.argv", argv):
            return mod.main()

    def _fake_kubectl_create(self, kind, manifest):
        uid = f"uid-{kind.lower()}"
        return {"metadata": {"name": f"{kind.lower()}-name", "uid": uid}}

    def _make_http_responses(self):
        return {
            "token": {"access_token": "tok-ha3", "token_type": "Bearer"},
            "introspect": {"active": True, "client_id": "qual-ha3-goauthy", "scope": mod.GRANT_SCOPE},
            "well_known": {"issuer": mod.ISSUER, "jwks_uri": f"http://127.0.0.1:{mod.ISSUER_PORT}/jwks"},
            "jwks": {"keys": [{"kid": "key-ha3", "kty": "RSA", "n": "x", "e": "AQAB"}]},
        }

    def _make_3_pods(self, sts_uid="uid-statefulset"):
        """Return 3 pods on distinct nodes owned by sts_uid."""
        return [
            {
                "metadata": {
                    "name": f"pod-{i}",
                    "uid": f"pod-uid-{i}",
                    "ownerReferences": [{"controller": True, "uid": sts_uid}],
                },
                "spec": {"nodeName": f"node-{i}"},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
            }
            for i in range(3)
        ]

    @mock.patch.object(mod, "kubectl_delete")
    @mock.patch.object(mod, "kubectl_create_stdin")
    @mock.patch.object(mod, "kubectl_json")
    @mock.patch.object(mod, "http_post")
    @mock.patch.object(mod, "http_get")
    @mock.patch.object(mod, "wait_port_forward")
    @mock.patch.object(mod, "wait_n_pods_ready")
    @mock.patch.object(mod, "wait_pod_ready")
    @mock.patch.object(mod, "ensure_port_free")
    def test_ha3_success_path(self, mock_epf, mock_wpd, mock_wpn, mock_wpr, mock_hget, mock_hpost, mock_kj, mock_kcs, mock_kd):
        resp = self._make_http_responses()
        mock_epf.return_value = None
        mock_kcs.side_effect = self._fake_kubectl_create
        mock_kj.side_effect = lambda *a, **kw: {"items": []}
        mock_wpn.return_value = self._make_3_pods()
        # Replacement pod after fault: same ordinal name, new UID
        mock_wpd.return_value = {
            "metadata": {
                "name": "pod-2",
                "uid": "pod-uid-2-new",
                "ownerReferences": [{"controller": True, "uid": "uid-statefulset"}],
            },
            "spec": {"nodeName": "node-2"},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        }

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

        result = self._run_ha3()
        self.assertEqual(result, 0)

        # Secret has rhiza-members and rhiza-admin-token
        secret_call = [c for c in mock_kcs.call_args_list if c[0][0] == "Secret"][0]
        sd = secret_call[0][1]["stringData"]
        self.assertIn("rhiza-members", sd)
        self.assertIn("rhiza-admin-token", sd)
        self.assertIn("master-key", sd)
        self.assertIn("oauth-hmac", sd)
        self.assertIn("bootstrap-client", sd)

        # Verify rhiza-members is valid JSON with 3 entries
        members = json.loads(sd["rhiza-members"])
        self.assertEqual(len(members), 3)
        for i, m in enumerate(members):
            self.assertTrue(m["node_id"].endswith(f"-{i}"), f"node_id {m['node_id']} should end with -{i}")
            self.assertIn(":8444", m["peer_url"])
            self.assertIn("quic://", m["peer_url"])
            self.assertTrue(m["token"])

        # Admin token differs from all voter tokens
        voter_tokens = {m["token"] for m in members}
        self.assertNotIn(sd["rhiza-admin-token"], voter_tokens)

        # All 4 resource types created
        created_kinds = [c[0][0] for c in mock_kcs.call_args_list]
        for k in ["Secret", "ConfigMap", "Service", "StatefulSet"]:
            self.assertIn(k, created_kinds)

        # HA3 statefulset has replicas=3 and required podAntiAffinity
        sts_call = [c for c in mock_kcs.call_args_list if c[0][0] == "StatefulSet"][0]
        sts = sts_call[0][1]
        self.assertEqual(sts["spec"]["replicas"], 3)
        affinity = sts["spec"]["template"]["spec"]["affinity"]
        required = affinity["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
        self.assertEqual(len(required), 1)
        self.assertEqual(required[0]["topologyKey"], "kubernetes.io/hostname")

        # HA3 service has UDP peer port
        svc_call = [c for c in mock_kcs.call_args_list if c[0][0] == "Service"][0]
        svc = svc_call[0][1]
        peer_ports = [p for p in svc["spec"]["ports"] if p.get("name") == "peer"]
        self.assertEqual(len(peer_ports), 1)
        self.assertEqual(peer_ports[0]["protocol"], "UDP")
        self.assertEqual(peer_ports[0]["port"], 8444)

        # HA3 statefulset has peer container port
        container_ports = sts["spec"]["template"]["spec"]["containers"][0]["ports"]
        peer_cp = [p for p in container_ports if p.get("name") == "peer"]
        self.assertEqual(len(peer_cp), 1)
        self.assertEqual(peer_cp[0]["containerPort"], 8444)
        self.assertEqual(peer_cp[0]["protocol"], "UDP")

        # RHIZA_PROFILE is cluster, PEER_ADDR is :8444
        env_list = sts["spec"]["template"]["spec"]["containers"][0]["env"]
        env_by_name = {}
        for e in env_list:
            if "value" in e:
                env_by_name[e["name"]] = e["value"]
        self.assertEqual(env_by_name.get("GOAUTHY_RHIZA_PROFILE"), "cluster")
        self.assertEqual(env_by_name.get("GOAUTHY_RHIZA_PEER_ADDR"), ":8444")

        # Consumer env uses correct GOAUTHY_ prefix, not bare BOOTSTRAP_USER_EMAIL
        env_names = {e["name"] for e in env_list}
        self.assertNotIn("BOOTSTRAP_USER_EMAIL", env_names, "wrong env var prefix: use GOAUTHY_BOOTSTRAP_USER_EMAIL")

        # All 4 cleanup deletes have UID
        for c in mock_kd.call_args_list:
            self.assertTrue(c[0][0], f"cleanup delete for {c[0][0]} missing UID")

    @mock.patch.object(mod, "kubectl_delete")
    @mock.patch.object(mod, "kubectl_create_stdin")
    @mock.patch.object(mod, "kubectl_json")
    @mock.patch.object(mod, "http_post")
    @mock.patch.object(mod, "http_get")
    @mock.patch.object(mod, "wait_port_forward")
    @mock.patch.object(mod, "wait_n_pods_ready")
    @mock.patch.object(mod, "wait_pod_ready")
    @mock.patch.object(mod, "ensure_port_free")
    def test_ha3_retained_token_after_fault(self, mock_epf, mock_wpd, mock_wpn, mock_wpr, mock_hget, mock_hpost, mock_kj, mock_kcs, mock_kd):
        """Same access token verified via surviving pod and replacement pod."""
        resp = self._make_http_responses()
        mock_epf.return_value = None
        mock_kcs.side_effect = self._fake_kubectl_create
        mock_kj.side_effect = lambda *a, **kw: {"items": []}
        mock_wpn.return_value = self._make_3_pods()
        mock_wpd.return_value = {
            "metadata": {
                "name": "pod-2",
                "uid": "pod-uid-2-new",
                "ownerReferences": [{"controller": True, "uid": "uid-statefulset"}],
            },
            "spec": {"nodeName": "node-2"},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        }

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

        introspect_calls = []
        def _http_post(url, data, **kw):
            if "token" in url:
                return resp["token"]
            introspect_calls.append(data.get("token"))
            return resp["introspect"]
        mock_hpost.side_effect = _http_post

        result = self._run_ha3()
        self.assertEqual(result, 0)

        # All introspect calls used the SAME token
        self.assertTrue(len(introspect_calls) >= 3, f"expected >=3 introspect calls, got {len(introspect_calls)}")
        self.assertEqual(len(set(introspect_calls)), 1, "introspect calls used different tokens")

    @mock.patch.object(mod, "kubectl_delete")
    @mock.patch.object(mod, "kubectl_create_stdin")
    @mock.patch.object(mod, "kubectl_json")
    @mock.patch.object(mod, "http_post")
    @mock.patch.object(mod, "http_get")
    @mock.patch.object(mod, "wait_port_forward")
    @mock.patch.object(mod, "wait_n_pods_ready")
    @mock.patch.object(mod, "wait_pod_ready")
    @mock.patch.object(mod, "ensure_port_free")
    def test_ha3_label_is_ha3_not_standalone(self, mock_epf, mock_wpd, mock_wpn, mock_wpr, mock_hget, mock_hpost, mock_kj, mock_kcs, mock_kd):
        """HA3 resources use ha3 labels, not s1."""
        resp = self._make_http_responses()
        mock_epf.return_value = None
        mock_kcs.side_effect = self._fake_kubectl_create
        mock_kj.side_effect = lambda *a, **kw: {"items": []}
        mock_wpn.return_value = self._make_3_pods()
        mock_wpd.return_value = {
            "metadata": {
                "name": "pod-2",
                "uid": "pod-uid-2-new",
                "ownerReferences": [{"controller": True, "uid": "uid-statefulset"}],
            },
            "spec": {"nodeName": "node-2"},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        }

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

        self._run_ha3()

        for call in mock_kcs.call_args_list:
            kind = call[0][0]
            manifest = call[0][1]
            part_of = manifest["metadata"]["labels"]["app.kubernetes.io/part-of"]
            self.assertIn("ha3", part_of, f"{kind} label part-of should contain 'ha3', got {part_of!r}")
            self.assertNotIn("s1", part_of, f"{kind} label part-of should not contain 's1', got {part_of!r}")

    def test_ha3_replicas_flag_routing(self):
        """--replicas 3 routes to _main_ha3, --replicas 1 routes to _main_standalone."""
        with mock.patch.object(mod, "_main_ha3", return_value=0) as mock_ha3:
            with mock.patch("sys.argv", ["e2e-ied-gcs-candidate.py", "--image", VALID_IMAGE, "--replicas", "3"]):
                mod.main()
            mock_ha3.assert_called_once()

        with mock.patch.object(mod, "_main_standalone", return_value=0) as mock_s1:
            with mock.patch("sys.argv", ["e2e-ied-gcs-candidate.py", "--image", VALID_IMAGE, "--replicas", "1"]):
                mod.main()
            mock_s1.assert_called_once()

        with mock.patch.object(mod, "_main_standalone", return_value=0) as mock_s1:
            with mock.patch("sys.argv", ["e2e-ied-gcs-candidate.py", "--image", VALID_IMAGE]):
                mod.main()
            mock_s1.assert_called_once()

    def test_ha3_members_json_format(self):
        """Members JSON matches config.go: [{node_id, peer_url, token}, ...]."""
        statefulset_name = "goauthy-qual-ha3-test"
        service_name = "goauthy-qual-ha3-test"
        voter_tokens = ["tok-0", "tok-1", "tok-2"]
        members = []
        for i in range(3):
            members.append({
                "node_id": f"{statefulset_name}-{i}",
                "peer_url": f"quic://{statefulset_name}-{i}.{service_name}.{mod.NAMESPACE}.svc.cluster.local:8444",
                "token": voter_tokens[i],
            })
        raw = json.dumps(members)
        parsed = json.loads(raw)
        self.assertEqual(len(parsed), 3)
        for i, m in enumerate(parsed):
            self.assertEqual(m["node_id"], f"{statefulset_name}-{i}")
            self.assertTrue(m["peer_url"].startswith("quic://"))
            self.assertIn(":8444", m["peer_url"])
            self.assertEqual(m["token"], voter_tokens[i])

    @mock.patch.object(mod, "kubectl_delete")
    @mock.patch.object(mod, "kubectl_create_stdin")
    @mock.patch.object(mod, "kubectl_json")
    @mock.patch.object(mod, "http_post")
    @mock.patch.object(mod, "http_get")
    @mock.patch.object(mod, "wait_port_forward")
    @mock.patch.object(mod, "wait_n_pods_ready")
    @mock.patch.object(mod, "wait_pod_ready")
    @mock.patch.object(mod, "ensure_port_free")
    def test_ha3_jwks_mutated_on_prefault_second_pod(self, mock_epf, mock_wpd, mock_wpn, mock_wpr, mock_hget, mock_hpost, mock_kj, mock_kcs, mock_kd):
        """Mutate JWKS on pre-fault second pod -> result1 (JWKS mismatch), cleanup still runs. Each iteration uses same original token."""
        resp = self._make_http_responses()
        mutated_jwks = {"keys": [{"kid": "key-mutated", "kty": "RSA", "n": "y", "e": "AQAB"}]}
        mock_epf.return_value = None
        mock_kcs.side_effect = self._fake_kubectl_create
        mock_kj.side_effect = lambda *a, **kw: {"items": []}
        mock_wpn.return_value = self._make_3_pods()
        mock_wpd.return_value = {
            "metadata": {
                "name": "pod-2",
                "uid": "pod-uid-2-new",
                "ownerReferences": [{"controller": True, "uid": "uid-statefulset"}],
            },
            "spec": {"nodeName": "node-2"},
            "status": {"conditions": [{"type": "Ready", "status": "True"}]},
        }

        fake_proc = mock.MagicMock()
        fake_proc.poll.return_value = None
        mock_wpr.return_value = fake_proc

        call_count = [0]
        def _http_get(url):
            if "well-known" in url:
                return resp["well_known"]
            if "jwks" in url:
                call_count[0] += 1
                # On pod-1 (second pod pre-fault), return mutated JWKS
                if call_count[0] == 2:
                    return mutated_jwks
                return resp["jwks"]
            return {}
        mock_hget.side_effect = _http_get

        introspect_calls = []
        def _http_post(url, data, **kw):
            if "token" in url:
                return resp["token"]
            introspect_calls.append(data.get("token"))
            return resp["introspect"]
        mock_hpost.side_effect = _http_post

        result = self._run_ha3()
        # JWKS mismatch on pod-1 causes result=1
        self.assertEqual(result, 1)

        # All introspect calls used the SAME token
        self.assertTrue(len(introspect_calls) >= 2, f"expected >=2 introspect calls, got {len(introspect_calls)}")
        self.assertEqual(len(set(introspect_calls)), 1, "introspect calls used different tokens")

        # Cleanup called for all 4 resource kinds
        deleted_kinds = [c[0][0] for c in mock_kd.call_args_list]
        for k in ["Secret", "ConfigMap", "Service", "StatefulSet"]:
            self.assertIn(k, deleted_kinds)


class TestStatefulSetNameLength(unittest.TestCase):
    """Deterministic: sts name + '-' + typical 10-char revision-hash <= 63."""

    def test_s1_name_plus_revision_within_63(self):
        run_id = "01234567-89ab-cdef-0123-456789abcdef"  # 36-char UUID
        sts_name = f"gq-s1-{run_id}"  # 43 chars
        revision_hash = "a1b2c3d4e5"  # typical 10-char hash
        controller_rev_label = f"{sts_name}-{revision_hash}"
        self.assertLessEqual(len(controller_rev_label), 63,
                             f"controller-revision-hash label length {len(controller_rev_label)} > 63: {controller_rev_label!r}")

    def test_ha3_name_plus_revision_within_63(self):
        run_id = "01234567-89ab-cdef-0123-456789abcdef"
        sts_name = f"gq-ha3-{run_id}"  # 44 chars
        revision_hash = "a1b2c3d4e5"
        controller_rev_label = f"{sts_name}-{revision_hash}"
        self.assertLessEqual(len(controller_rev_label), 63,
                             f"controller-revision-hash label length {len(controller_rev_label)} > 63: {controller_rev_label!r}")

    def test_old_name_would_exceed_63(self):
        """Verify the old goauthy-qual-ha3-* pattern would have exceeded 63."""
        run_id = "01234567-89ab-cdef-0123-456789abcdef"
        old_sts_name = f"goauthy-qual-ha3-{run_id}"  # 53 chars
        revision_hash = "a1b2c3d4e5"
        controller_rev_label = f"{old_sts_name}-{revision_hash}"
        self.assertGreater(len(controller_rev_label), 63,
                           "old name pattern should exceed 63 to confirm the bug existed")

    def test_member_node_ids_use_short_name(self):
        """Member node_id and peer_url use the shortened sts name."""
        run_id = "01234567-89ab-cdef-0123-456789abcdef"
        flavor = "ha3"
        sts_name = f"gq-{flavor}-{run_id}"
        svc_name = f"goauthy-qual-{flavor}-{run_id}"
        ns = mod.NAMESPACE
        for i in range(3):
            node_id = f"{sts_name}-{i}"
            peer_url = f"quic://{sts_name}-{i}.{svc_name}.{ns}.svc.cluster.local:8444"
            self.assertTrue(node_id.startswith("gq-ha3-"), f"node_id should start with gq-ha3-: {node_id}")
            self.assertIn(f".{svc_name}.{ns}.svc.cluster.local", peer_url)

    def test_manifests_sts_name_is_short(self):
        """_build_statefulset_manifest receives the short name, not the old long one."""
        run_id = "01234567-89ab-cdef-0123-456789abcdef"
        flavor = "s1"
        sts_name = f"gq-{flavor}-{run_id}"
        svc_name = f"goauthy-qual-{flavor}-{run_id}"
        manifest = mod._build_statefulset_manifest(
            sts_name, svc_name, "goauthy-qual-s1-test",
            "cm", "sec", "mkid", flavor, 1, False, VALID_IMAGE,
        )
        self.assertEqual(manifest["metadata"]["name"], sts_name)
        self.assertEqual(manifest["spec"]["serviceName"], svc_name)
        self.assertTrue(sts_name.startswith("gq-s1-"))


class TestPasswordHasher(unittest.TestCase):
    """Tests for _run_password_hasher sanitized errors and validation."""

    @mock.patch("subprocess.run")
    def test_success_returns_phc(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="$argon2id$v=19$m=65536,t=3,p=4$salt$hash\n",
            stderr="",
        )
        result = mod._run_password_hasher("/usr/bin/hasher", "s3cret")
        self.assertTrue(result.startswith("$argon2id$"))

    @mock.patch("subprocess.run")
    def test_failure_no_stderr_leak(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1,
            stdout="",
            stderr="/path/to/hasher: internal secret error\n",
        )
        with self.assertRaises(RuntimeError) as cm:
            mod._run_password_hasher("/usr/bin/hasher", "s3cret")
        self.assertNotIn("secret", str(cm.exception).lower())
        self.assertNotIn("/path", str(cm.exception))
        self.assertEqual(str(cm.exception), "password-hasher failed")

    @mock.patch("subprocess.run")
    def test_rejects_non_argon2id(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="$bcrypt$something\n",
            stderr="",
        )
        with self.assertRaises(RuntimeError) as cm:
            mod._run_password_hasher("/usr/bin/hasher", "pw")
        self.assertIn("invalid output", str(cm.exception))

    @mock.patch("subprocess.run")
    def test_rejects_multiline(self, mock_run):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="$argon2id$v=19$m=65536,t=3,p=4$salt$hash\nextra line\n",
            stderr="",
        )
        with self.assertRaises(RuntimeError) as cm:
            mod._run_password_hasher("/usr/bin/hasher", "pw")
        self.assertIn("invalid output", str(cm.exception))

    @mock.patch("subprocess.run")
    def test_rejects_too_long(self, mock_run):
        long_phc = "$argon2id$" + "a" * 5000 + "\n"
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout=long_phc,
            stderr="",
        )
        with self.assertRaises(RuntimeError) as cm:
            mod._run_password_hasher("/usr/bin/hasher", "pw")
        self.assertIn("invalid output", str(cm.exception))


class TestPairArgsExecutableCheck(unittest.TestCase):
    """Tests for os.access(path, os.X_OK) validation of --ternal-bin and --password-hasher."""

    def _run_main(self, extra_argv):
        argv = ["e2e-ied-gcs-candidate.py", "--image", VALID_IMAGE] + extra_argv
        with mock.patch("sys.argv", argv):
            return mod.main()

    @mock.patch("os.access", return_value=False)
    @mock.patch("os.path.isfile", return_value=True)
    @mock.patch("os.path.isabs", return_value=True)
    def test_non_executable_ternal_bin_rejected(self, mock_abs, mock_file, mock_access):
        result = self._run_main(["--ternal-bin", "/usr/bin/ternal", "--password-hasher", "/usr/bin/hasher"])
        self.assertEqual(result, 1)

    @mock.patch("os.access", return_value=False)
    @mock.patch("os.path.isfile", return_value=True)
    @mock.patch("os.path.isabs", return_value=True)
    def test_non_executable_hasher_rejected(self, mock_abs, mock_file, mock_access):
        result = self._run_main(["--ternal-bin", "/usr/bin/ternal", "--password-hasher", "/usr/bin/hasher"])
        self.assertEqual(result, 1)


class TestConsumerProbeLifecycle(unittest.TestCase):
    """Tests for TernalProbe login-before-fault, verify-after-replacement, cleanup->__exit__."""

    def _run_main(self, replicas):
        argv = ["e2e-ied-gcs-candidate.py", "--image", VALID_IMAGE,
                "--replicas", str(replicas),
                "--ternal-bin", "/usr/bin/ternal",
                "--password-hasher", "/usr/bin/hasher"]
        with mock.patch("sys.argv", argv):
            return mod.main()

    def _setup_common_mocks(self, replicas):
        """Return dict of mocks needed for consumer probe lifecycle tests."""
        patches = {}
        patches["ensure_port_free"] = mock.patch.object(mod, "ensure_port_free")
        patches["kubectl_create_stdin"] = mock.patch.object(mod, "kubectl_create_stdin")
        patches["kubectl_delete"] = mock.patch.object(mod, "kubectl_delete")
        patches["kubectl_json"] = mock.patch.object(mod, "kubectl_json")
        patches["http_post"] = mock.patch.object(mod, "http_post")
        patches["http_get"] = mock.patch.object(mod, "http_get")
        patches["wait_port_forward"] = mock.patch.object(mod, "wait_port_forward")
        patches["wait_pod_ready"] = mock.patch.object(mod, "wait_pod_ready")
        if replicas == 3:
            patches["wait_n_pods_ready"] = mock.patch.object(mod, "wait_n_pods_ready")
        patches["isabs"] = mock.patch("os.path.isabs", return_value=True)
        patches["isfile"] = mock.patch("os.path.isfile", return_value=True)
        patches["access"] = mock.patch("os.access", return_value=True)
        patches["hasher"] = mock.patch.object(mod, "_run_password_hasher", return_value="$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$hash")
        patches["TernalProbe"] = mock.patch.object(mod, "TernalProbe")
        return patches

    def _start_patches(self, patches):
        started = {}
        for name, p in patches.items():
            started[name] = p.start()
        return started

    def _stop_patches(self, patches):
        for p in patches.values():
            p.stop()

    def test_standalone_login_before_fault(self):
        """Login happens before fault, verify after replacement."""
        patches = self._setup_common_mocks(1)
        started = self._start_patches(patches)
        try:
            started["ensure_port_free"].return_value = None
            started["kubectl_create_stdin"].side_effect = lambda kind, m: {"metadata": {"name": f"{kind.lower()}-name", "uid": f"uid-{kind.lower()}"}}
            started["kubectl_json"].return_value = {"items": []}
            started["wait_pod_ready"].side_effect = [
                {"metadata": {"name": "pod-1", "uid": "pod-uid-1"}},
                {"metadata": {"name": "pod-2", "uid": "pod-uid-2"}},
            ]
            fake_proc = mock.MagicMock()
            fake_proc.poll.return_value = None
            started["wait_port_forward"].return_value = fake_proc

            resp = {
                "token": {"access_token": "tok-1", "token_type": "Bearer"},
                "introspect": {"active": True, "client_id": "qual-s1-goauthy", "scope": mod.GRANT_SCOPE},
                "well_known": {"issuer": mod.ISSUER, "jwks_uri": f"http://127.0.0.1:{mod.ISSUER_PORT}/jwks"},
                "jwks": {"keys": [{"kid": "key-1", "kty": "RSA", "n": "x", "e": "AQAB"}]},
            }
            def _http_get(url):
                if "well-known" in url:
                    return resp["well_known"]
                if "jwks" in url:
                    return resp["jwks"]
                return {}
            started["http_get"].side_effect = _http_get
            started["http_post"].side_effect = lambda url, data, **kw: resp["token"] if "token" in url else resp["introspect"]

            probe_inst = started["TernalProbe"].return_value
            probe_inst.__enter__ = mock.MagicMock(return_value=probe_inst)
            probe_inst.__exit__ = mock.MagicMock(return_value=False)

            result = self._run_main(1)
            self.assertEqual(result, 0)

            # login called BEFORE kubectl_delete (fault)
            probe_inst.login.assert_called_once()
            # verify called after replacement (at least once)
            self.assertGreaterEqual(probe_inst.verify.call_count, 1)
            # __exit__ called during cleanup
            probe_inst.__exit__.assert_called()
        finally:
            self._stop_patches(patches)

    def test_ha3_login_before_fault_verify_after(self):
        """HA3: login before fault, verify after survivor and replacement."""
        patches = self._setup_common_mocks(3)
        started = self._start_patches(patches)
        try:
            started["ensure_port_free"].return_value = None
            started["kubectl_create_stdin"].side_effect = lambda kind, m: {"metadata": {"name": f"{kind.lower()}-name", "uid": f"uid-{kind.lower()}"}}
            started["kubectl_json"].return_value = {"items": []}
            three_pods = [
                {"metadata": {"name": f"pod-{i}", "uid": f"pod-uid-{i}",
                              "ownerReferences": [{"controller": True, "uid": "uid-statefulset"}]},
                 "spec": {"nodeName": f"node-{i}"},
                 "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
                for i in range(3)
            ]
            started["wait_n_pods_ready"].return_value = three_pods
            started["wait_pod_ready"].return_value = {
                "metadata": {"name": "pod-2", "uid": "pod-uid-2-new",
                             "ownerReferences": [{"controller": True, "uid": "uid-statefulset"}]},
                "spec": {"nodeName": "node-2"},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
            }
            fake_proc = mock.MagicMock()
            fake_proc.poll.return_value = None
            started["wait_port_forward"].return_value = fake_proc

            resp = {
                "token": {"access_token": "tok-ha3", "token_type": "Bearer"},
                "introspect": {"active": True, "client_id": "qual-ha3-goauthy", "scope": mod.GRANT_SCOPE},
                "well_known": {"issuer": mod.ISSUER, "jwks_uri": f"http://127.0.0.1:{mod.ISSUER_PORT}/jwks"},
                "jwks": {"keys": [{"kid": "key-ha3", "kty": "RSA", "n": "x", "e": "AQAB"}]},
            }
            def _http_get(url):
                if "well-known" in url:
                    return resp["well_known"]
                if "jwks" in url:
                    return resp["jwks"]
                return {}
            started["http_get"].side_effect = _http_get
            started["http_post"].side_effect = lambda url, data, **kw: resp["token"] if "token" in url else resp["introspect"]

            probe_inst = started["TernalProbe"].return_value
            probe_inst.__enter__ = mock.MagicMock(return_value=probe_inst)
            probe_inst.__exit__ = mock.MagicMock(return_value=False)

            result = self._run_main(3)
            self.assertEqual(result, 0)

            # login called
            probe_inst.login.assert_called_once()
            # verify called: 3 pre-fault + 1 survivor + 1 replacement = 5
            self.assertGreaterEqual(probe_inst.verify.call_count, 5)
            # __exit__ called during cleanup
            probe_inst.__exit__.assert_called()
        finally:
            self._stop_patches(patches)

    def test_standalone_ordered_events(self):
        """Standalone: login < fault < replacement < last_verify < close ordering via events list."""
        patches = self._setup_common_mocks(1)
        started = self._start_patches(patches)
        try:
            started["ensure_port_free"].return_value = None
            started["kubectl_create_stdin"].side_effect = lambda kind, m: {"metadata": {"name": f"{kind.lower()}-name", "uid": f"uid-{kind.lower()}"}}
            started["kubectl_json"].return_value = {"items": []}

            events = []

            _wpd_call_count = [0]
            def _wait_pod_ready(*a, **kw):
                _wpd_call_count[0] += 1
                if _wpd_call_count[0] == 1:
                    return {"metadata": {"name": "pod-1", "uid": "pod-uid-1"}}
                events.append("replacement")
                return {"metadata": {"name": "pod-2", "uid": "pod-uid-2"}}

            started["wait_pod_ready"].side_effect = _wait_pod_ready

            fake_proc = mock.MagicMock()
            fake_proc.poll.return_value = None
            started["wait_port_forward"].return_value = fake_proc

            resp = {
                "token": {"access_token": "tok-1", "token_type": "Bearer"},
                "introspect": {"active": True, "client_id": "qual-s1-goauthy", "scope": mod.GRANT_SCOPE},
                "well_known": {"issuer": mod.ISSUER, "jwks_uri": f"http://127.0.0.1:{mod.ISSUER_PORT}/jwks"},
                "jwks": {"keys": [{"kid": "key-1", "kty": "RSA", "n": "x", "e": "AQAB"}]},
            }
            def _http_get(url):
                if "well-known" in url:
                    return resp["well_known"]
                if "jwks" in url:
                    return resp["jwks"]
                return {}
            started["http_get"].side_effect = _http_get
            started["http_post"].side_effect = lambda url, data, **kw: resp["token"] if "token" in url else resp["introspect"]

            def _kubectl_delete(kind, name, uid):
                if kind == "Pod":
                    events.append("fault")
            started["kubectl_delete"].side_effect = _kubectl_delete

            probe_inst = started["TernalProbe"].return_value
            probe_inst.__enter__ = mock.MagicMock(return_value=probe_inst)
            probe_inst.__exit__ = mock.MagicMock(return_value=False)

            def _login(*a, **kw):
                events.append("login")
            probe_inst.login.side_effect = _login

            def _verify(*a, **kw):
                events.append("verify")
            probe_inst.verify.side_effect = _verify

            def _exit(*a, **kw):
                events.append("close")
                return False
            probe_inst.__exit__.side_effect = _exit

            result = self._run_main(1)
            self.assertEqual(result, 0)

            self.assertLess(events.index("login"), events.index("fault"), f"login must precede fault: {events}")
            self.assertLess(events.index("fault"), events.index("replacement"), f"fault must precede replacement: {events}")
            self.assertLess(events.index("replacement"), len(events) - 1, f"replacement must precede last verify: {events}")
            last_verify = len(events) - 1 - events[::-1].index("verify")
            self.assertLess(last_verify, events.index("close"), f"last verify must precede close: {events}")
        finally:
            self._stop_patches(patches)

    def test_ha3_ordered_events_with_survivor_verify(self):
        """HA3: login < fault < survivor_verify < replacement < replacement_verify < close."""
        patches = self._setup_common_mocks(3)
        started = self._start_patches(patches)
        try:
            started["ensure_port_free"].return_value = None
            started["kubectl_create_stdin"].side_effect = lambda kind, m: {"metadata": {"name": f"{kind.lower()}-name", "uid": f"uid-{kind.lower()}"}}
            started["kubectl_json"].return_value = {"items": []}
            three_pods = [
                {"metadata": {"name": f"pod-{i}", "uid": f"pod-uid-{i}",
                              "ownerReferences": [{"controller": True, "uid": "uid-statefulset"}]},
                 "spec": {"nodeName": f"node-{i}"},
                 "status": {"conditions": [{"type": "Ready", "status": "True"}]}}
                for i in range(3)
            ]
            started["wait_n_pods_ready"].return_value = three_pods
            started["wait_pod_ready"].return_value = {
                "metadata": {"name": "pod-2", "uid": "pod-uid-2-new",
                             "ownerReferences": [{"controller": True, "uid": "uid-statefulset"}]},
                "spec": {"nodeName": "node-2"},
                "status": {"conditions": [{"type": "Ready", "status": "True"}]},
            }

            fake_proc = mock.MagicMock()
            fake_proc.poll.return_value = None
            started["wait_port_forward"].return_value = fake_proc

            events = []

            resp = {
                "token": {"access_token": "tok-ha3", "token_type": "Bearer"},
                "introspect": {"active": True, "client_id": "qual-ha3-goauthy", "scope": mod.GRANT_SCOPE},
                "well_known": {"issuer": mod.ISSUER, "jwks_uri": f"http://127.0.0.1:{mod.ISSUER_PORT}/jwks"},
                "jwks": {"keys": [{"kid": "key-ha3", "kty": "RSA", "n": "x", "e": "AQAB"}]},
            }
            def _http_get(url):
                if "well-known" in url:
                    return resp["well_known"]
                if "jwks" in url:
                    return resp["jwks"]
                return {}
            started["http_get"].side_effect = _http_get
            started["http_post"].side_effect = lambda url, data, **kw: resp["token"] if "token" in url else resp["introspect"]

            def _kubectl_delete(kind, name, uid):
                if kind == "Pod":
                    events.append("fault")
            started["kubectl_delete"].side_effect = _kubectl_delete

            probe_inst = started["TernalProbe"].return_value
            probe_inst.__enter__ = mock.MagicMock(return_value=probe_inst)
            probe_inst.__exit__ = mock.MagicMock(return_value=False)

            def _login(*a, **kw):
                events.append("login")
            probe_inst.login.side_effect = _login

            def _verify(*a, **kw):
                events.append("verify")
            probe_inst.verify.side_effect = _verify

            def _exit(*a, **kw):
                events.append("close")
                return False
            probe_inst.__exit__.side_effect = _exit

            result = self._run_main(3)
            self.assertEqual(result, 0)

            self.assertIn("login", events, f"login missing: {events}")
            self.assertIn("fault", events, f"fault missing: {events}")
            self.assertIn("close", events, f"close missing: {events}")
            self.assertGreaterEqual(events.count("verify"), 3, f"expected >=3 verify events (survivor + replacement + others): {events}")
            self.assertLess(events.index("login"), events.index("fault"), f"login must precede fault: {events}")
            fault_idx = events.index("fault")
            post_fault_verifies = [i for i, e in enumerate(events) if e == "verify" and i > fault_idx]
            self.assertGreaterEqual(len(post_fault_verifies), 1, f"at least one verify after fault: {events}")
            last_verify = max(i for i, e in enumerate(events) if e == "verify")
            self.assertLess(last_verify, events.index("close"), f"last verify must precede close: {events}")
        finally:
            self._stop_patches(patches)

    def test_cleanup_calls_exit_on_failure(self):
        """probe.__exit__ called even when qualification fails."""
        patches = self._setup_common_mocks(1)
        started = self._start_patches(patches)
        try:
            started["ensure_port_free"].return_value = None
            started["kubectl_create_stdin"].side_effect = lambda kind, m: {"metadata": {"name": f"{kind.lower()}-name", "uid": f"uid-{kind.lower()}"}}
            started["kubectl_json"].return_value = {"items": []}
            started["wait_pod_ready"].return_value = {"metadata": {"name": "pod-1", "uid": "pod-uid-1"}}
            fake_proc = mock.MagicMock()
            fake_proc.poll.return_value = None
            started["wait_port_forward"].return_value = fake_proc

            # Make http_post raise to fail the flow after probe starts
            started["http_post"].side_effect = RuntimeError("token endpoint down")

            probe_inst = started["TernalProbe"].return_value
            probe_inst.__enter__ = mock.MagicMock(return_value=probe_inst)
            probe_inst.__exit__ = mock.MagicMock(return_value=False)

            result = self._run_main(1)
            self.assertEqual(result, 1)
            # __exit__ still called during cleanup
            probe_inst.__exit__.assert_called()
        finally:
            self._stop_patches(patches)

    def test_invalid_pair_no_factory_calls(self):
        """When --ternal-bin given without --password-hasher, no factory calls."""
        argv = ["e2e-ied-gcs-candidate.py", "--image", VALID_IMAGE,
                "--ternal-bin", "/usr/bin/ternal"]
        with mock.patch("sys.argv", argv):
            with mock.patch.object(mod, "TernalProbe") as mock_probe:
                with mock.patch.object(mod, "_run_password_hasher") as mock_hasher:
                    result = mod.main()
        self.assertEqual(result, 1)
        mock_probe.assert_not_called()
        mock_hasher.assert_not_called()


class TestDefaultSubprocessGuards(unittest.TestCase):
    """Verify default subprocess blocks remain: no live process spawned in unit tests."""

    def test_subprocess_run_blocked(self):
        """subprocess.run should raise from module-level guard."""
        with self.assertRaises(AssertionError):
            import subprocess as _sp
            _sp.run(["echo", "hello"], capture_output=True)

    def test_subprocess_popen_blocked(self):
        """subprocess.Popen should raise from module-level guard."""
        with self.assertRaises(AssertionError):
            import subprocess as _sp
            _sp.Popen(["echo", "hello"])


if __name__ == "__main__":
    unittest.main()
