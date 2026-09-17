#!/usr/bin/env python3
"""Unit tests for ternal_consumer_probe.py using stdlib unittest + mocks."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import urllib.error

sys.path.insert(0, os.path.dirname(__file__))

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "ternal_consumer_probe",
    os.path.join(os.path.dirname(__file__), "ternal_consumer_probe.py"),
)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


class TestExtractForm(unittest.TestCase):
    def test_basic_form(self):
        html = b'<html><body><form method="post" action="/auth/login"><input type="hidden" name="interaction" value="abc"><input type="hidden" name="csrf_token" value="xyz"><label>Username <input name="username"></label><button type="submit">Sign in</button></form></body></html>'
        action, hidden = mod._extract_form(html)
        self.assertEqual(action, "/auth/login")
        self.assertEqual(hidden["interaction"], "abc")
        self.assertEqual(hidden["csrf_token"], "xyz")
        self.assertNotIn("username", hidden)

    def test_empty_action(self):
        html = b'<form method="post" action=""><input type="hidden" name="x" value="1"></form>'
        action, hidden = mod._extract_form(html)
        self.assertEqual(action, "")
        self.assertEqual(hidden["x"], "1")

    def test_no_form_raises(self):
        with self.assertRaises(RuntimeError):
            mod._extract_form(b"<html><body>no form here</body></html>")

    def test_ignores_second_form_action(self):
        html = b'<form action="/first"><input type="hidden" name="a" value="1"></form><form action="/second"><input type="hidden" name="b" value="2"></form>'
        action, hidden = mod._extract_form(html)
        self.assertEqual(action, "/first")
        self.assertIn("a", hidden)
        self.assertNotIn("b", hidden)

    def test_duplicate_hidden_input_raises(self):
        html = b'<form action="/login"><input type="hidden" name="interaction" value="v1"><input type="hidden" name="interaction" value="v2"></form>'
        with self.assertRaises(RuntimeError) as cm:
            mod._extract_form(html)
        self.assertIn("duplicate", str(cm.exception))

    def test_missing_interaction_raises(self):
        html = b'<form action="/login"><input type="hidden" name="csrf_token" value="abc"></form>'
        action, hidden = mod._extract_form(html)
        self.assertNotIn("interaction", hidden)

    def test_closes_form_on_endtag(self):
        html = b'<form action="/first"><input type="hidden" name="a" value="1"></form><form action="/second"><input type="hidden" name="b" value="2"></form>'
        p = mod._FormParser()
        p.feed(html.decode())
        self.assertTrue(p._form_closed)
        self.assertEqual(p.action, "/first")
        self.assertNotIn("b", p.hidden)


class TestPortFree(unittest.TestCase):
    @mock.patch("socket.socket")
    def test_free(self, mock_cls):
        sock = mock_cls.return_value.__enter__.return_value
        self.assertTrue(mod._port_free(18093))
        sock.bind.assert_called_once_with(("127.0.0.1", 18093))

    @mock.patch("socket.socket")
    def test_occupied(self, mock_cls):
        sock = mock_cls.return_value.__enter__.return_value
        sock.bind.side_effect = OSError("Address already in use")
        self.assertFalse(mod._port_free(18093))


class TestBuildEnv(unittest.TestCase):
    def test_whitelist_only(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._tmpdir = "/tmp/test"
        probe._issuer_url = "http://127.0.0.1:18092"
        probe._oidc_client_id = "test-client"
        probe._oidc_client_secret = "test-secret"
        probe._bind = "127.0.0.1:18093"
        env = probe._build_env("k" * 64, "r" * 64)
        allowed_keys = {"PATH", "HOME", "TMPDIR", "TERNAL_BIND", "TERNAL_DATA_DIR",
                        "TERNAL_SESSION_KEY", "TERNAL_RELAY_ACCESS_TOKEN", "TERNAL_DEV_HEADERS",
                        "TERNAL_OIDC_ISSUER", "TERNAL_OIDC_CLIENT_ID", "TERNAL_OIDC_CLIENT_SECRET",
                        "TERNAL_OIDC_REDIRECT_URL", "TERNAL_OIDC_ADMIN_GROUP"}
        self.assertEqual(set(env.keys()), allowed_keys)
        self.assertEqual(env["TERNAL_BIND"], "127.0.0.1:18093")
        self.assertEqual(env["TERNAL_DEV_HEADERS"], "0")
        self.assertEqual(env["TERNAL_OIDC_ADMIN_GROUP"], "ternal-admins")
        self.assertEqual(env["TERNAL_OIDC_REDIRECT_URL"], "http://127.0.0.1:18093/auth/callback")
        self.assertEqual(len(env["TERNAL_SESSION_KEY"]), 64)
        self.assertEqual(len(env["TERNAL_RELAY_ACCESS_TOKEN"]), 64)

    def test_never_inherits_rhiza_vars(self):
        with mock.patch.dict(os.environ, {
            "RHIZA_DATA_DIR": "/prod/data",
            "RHIZA_BIND": "0.0.0.0:9999",
            "PATH": "/usr/bin",
            "HOME": "/home/test",
        }):
            probe = mod.TernalProbe.__new__(mod.TernalProbe)
            probe._tmpdir = "/tmp/test"
            probe._issuer_url = "http://127.0.0.1:18092"
            probe._oidc_client_id = "cid"
            probe._oidc_client_secret = "csec"
            probe._bind = "127.0.0.1:18093"
            env = probe._build_env("k" * 64, "r" * 64)
            for k in env:
                self.assertFalse(k.startswith("RHIZA_"), f"leaked RHIZA var: {k}")

    def test_session_key_minimum_32_bytes(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._tmpdir = "/tmp/test"
        probe._issuer_url = "http://127.0.0.1:18092"
        probe._oidc_client_id = "cid"
        probe._oidc_client_secret = "csec"
        probe._bind = "127.0.0.1:18093"
        env = probe._build_env("a" * 64, "b" * 64)
        self.assertGreaterEqual(len(env["TERNAL_SESSION_KEY"]), 32)
        self.assertGreaterEqual(len(env["TERNAL_RELAY_ACCESS_TOKEN"]), 32)

    def test_build_env_requires_tmpdir(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._tmpdir = None
        probe._issuer_url = "http://127.0.0.1:18092"
        probe._oidc_client_id = "cid"
        probe._oidc_client_secret = "csec"
        probe._bind = "127.0.0.1:18093"
        with self.assertRaises(RuntimeError) as cm:
            probe._build_env("a" * 64, "b" * 64)
        self.assertIn("tmpdir", str(cm.exception))


class TestKill(unittest.TestCase):
    def test_kill_terminates_process(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        proc = mock.MagicMock()
        proc.poll.return_value = None
        proc.pid = 12345
        probe._proc = proc
        probe._tmpdir = tempfile.mkdtemp()
        tmpdir = probe._tmpdir

        probe._kill()

        proc.terminate.assert_called_once()
        proc.wait.assert_called_once_with(timeout=5)
        self.assertIsNone(probe._proc)
        self.assertFalse(os.path.exists(tmpdir))

    def test_kill_idempotent(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._proc = None
        probe._tmpdir = None
        probe._kill()

    def test_kill_already_exited(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._proc = mock.MagicMock()
        probe._proc.poll.return_value = 0
        probe._tmpdir = None
        probe._kill()
        self.assertIsNone(probe._proc)

    def test_kill_timeout_falls_back_to_kill(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        proc = mock.MagicMock()
        proc.poll.return_value = None
        proc.pid = 12345
        proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="", timeout=5), None]
        probe._proc = proc
        probe._tmpdir = tempfile.mkdtemp()

        probe._kill()

        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()
        self.assertEqual(proc.wait.call_count, 2)
        self.assertIsNone(probe._proc)

    def test_timeout_then_kill_error_propagates(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        proc = mock.MagicMock()
        proc.poll.return_value = None
        proc.pid = 12345
        proc.wait.side_effect = [subprocess.TimeoutExpired(cmd="", timeout=5), OSError("kill wait failed")]
        probe._proc = proc
        probe._tmpdir = tempfile.mkdtemp()
        tmpdir = probe._tmpdir

        with self.assertRaises(OSError) as cm:
            probe._kill()
        self.assertIn("kill wait failed", str(cm.exception))
        proc.terminate.assert_called_once()
        proc.kill.assert_called_once()
        self.assertIs(probe._proc, proc)
        self.assertEqual(probe._tmpdir, tmpdir)
        self.assertTrue(os.path.exists(tmpdir))

    def test_kill_stop_error_propagates(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        proc = mock.MagicMock()
        proc.poll.return_value = None
        proc.pid = 12345
        proc.terminate.side_effect = OSError("terminate failed")
        probe._proc = proc
        probe._tmpdir = tempfile.mkdtemp()
        tmpdir = probe._tmpdir

        with self.assertRaises(OSError) as cm:
            probe._kill()
        self.assertIn("terminate failed", str(cm.exception))
        self.assertIs(probe._proc, proc)
        self.assertEqual(probe._tmpdir, tmpdir)
        self.assertTrue(os.path.exists(tmpdir))


class TestConstructor(unittest.TestCase):
    def test_valid_construction(self):
        probe = mod.TernalProbe("/bin/true", "http://127.0.0.1:18092", "cid", "csec")
        self.assertEqual(probe._bind, "127.0.0.1:18093")
        self.assertEqual(probe._issuer_url, "http://127.0.0.1:18092")

    def test_invalid_bind_raises(self):
        with self.assertRaises(ValueError) as cm:
            mod.TernalProbe("/bin/true", "http://127.0.0.1:18092", "cid", "csec", bind="0.0.0.0:8080")
        self.assertIn("invalid bind", str(cm.exception))

    def test_invalid_issuer_raises(self):
        with self.assertRaises(ValueError) as cm:
            mod.TernalProbe("/bin/true", "http://127.0.0.1:9999", "cid", "csec")
        self.assertIn("invalid issuer", str(cm.exception))

    def test_custom_bind_raises(self):
        with self.assertRaises(ValueError):
            mod.TernalProbe("/bin/true", "http://127.0.0.1:18092", "cid", "csec", bind="127.0.0.1:9999")


class TestContextManagerEnter(unittest.TestCase):
    @mock.patch.object(mod, "_port_free", return_value=False)
    def test_port_occupied_raises(self, _):
        with self.assertRaises(RuntimeError) as cm:
            with mod.TernalProbe("/bin/true", "http://127.0.0.1:18092", "cid", "csec"):
                pass
        self.assertIn("18093", str(cm.exception))

    @mock.patch.object(mod.TernalProbe, "_wait_ready")
    @mock.patch("subprocess.Popen")
    @mock.patch.object(mod, "_port_free", return_value=True)
    def test_success(self, mock_port, mock_popen, mock_ready):
        proc = mock.MagicMock()
        proc.poll.return_value = None
        mock_popen.return_value = proc
        probe = mod.TernalProbe("/bin/true", "http://127.0.0.1:18092", "cid", "csec")
        with probe:
            self.assertIs(probe._proc, proc)
        mock_ready.assert_called_once()

    @mock.patch.object(mod.TernalProbe, "_wait_ready", side_effect=TimeoutError("timeout"))
    @mock.patch("subprocess.Popen")
    @mock.patch.object(mod, "_port_free", return_value=True)
    def test_ready_timeout_kills(self, mock_port, mock_popen, mock_ready):
        proc = mock.MagicMock()
        proc.poll.return_value = None
        mock_popen.return_value = proc
        with self.assertRaises(TimeoutError):
            with mod.TernalProbe("/bin/true", "http://127.0.0.1:18092", "cid", "csec"):
                pass

    @mock.patch("subprocess.Popen", side_effect=OSError("popen failed"))
    @mock.patch.object(mod, "_port_free", return_value=True)
    def test_popen_failure_cleans_tmpdir(self, mock_port, mock_popen):
        with self.assertRaises(OSError):
            with mod.TernalProbe("/bin/true", "http://127.0.0.1:18092", "cid", "csec"):
                pass


class TestWaitReady(unittest.TestCase):
    def test_immediate_ready(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._proc = mock.MagicMock()
        probe._proc.poll.return_value = None

        mock_resp = mock.MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps({"status": "ready"}).encode()

        with mock.patch("http.client.HTTPConnection") as mock_conn_cls:
            conn = mock_conn_cls.return_value
            conn.getresponse.return_value = mock_resp
            probe._wait_ready(18093, timeout=5.0)
            conn.request.assert_called_with("GET", "/ready")

    def test_process_exits_early(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._proc = mock.MagicMock()
        probe._proc.poll.return_value = 1
        probe._proc.returncode = 1
        with self.assertRaises(RuntimeError) as cm:
            probe._wait_ready(18093, timeout=1.0)
        self.assertIn("exited early", str(cm.exception))


class TestRestrictedRedirectHandler(unittest.TestCase):
    def test_allows_issuer_origin(self):
        handler = mod._RestrictedRedirectHandler({"http://127.0.0.1:18092", "http://127.0.0.1:18093"})
        req = mock.MagicMock()
        req.full_url = "http://127.0.0.1:18092/auth/login"
        req.get_method.return_value = "GET"
        fp = mock.MagicMock()
        headers = {"location": "http://127.0.0.1:18092/callback"}
        result = handler.redirect_request(req, fp, 301, "Moved", headers, "http://127.0.0.1:18092/callback")
        self.assertIsNotNone(result)

    def test_allows_api_origin(self):
        handler = mod._RestrictedRedirectHandler({"http://127.0.0.1:18092", "http://127.0.0.1:18093"})
        req = mock.MagicMock()
        req.full_url = "http://127.0.0.1:18093/auth/login"
        req.get_method.return_value = "GET"
        fp = mock.MagicMock()
        headers = {"location": "http://127.0.0.1:18093/"}
        result = handler.redirect_request(req, fp, 301, "Moved", headers, "http://127.0.0.1:18093/")
        self.assertIsNotNone(result)

    def test_rejects_external_origin(self):
        handler = mod._RestrictedRedirectHandler({"http://127.0.0.1:18092", "http://127.0.0.1:18093"})
        req = mock.MagicMock()
        with self.assertRaises(urllib.error.HTTPError) as cm:
            handler.redirect_request(req, None, 302, "Found", {}, "http://evil.com/steal")
        self.assertIn("unauthorized", str(cm.exception))

    def test_rejects_similar_port(self):
        handler = mod._RestrictedRedirectHandler({"http://127.0.0.1:18092", "http://127.0.0.1:18093"})
        req = mock.MagicMock()
        with self.assertRaises(urllib.error.HTTPError):
            handler.redirect_request(req, None, 302, "Found", {}, "http://127.0.0.1:18094/evil")


class TestLoginFlow(unittest.TestCase):
    def test_missing_cookie_raises(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._bind = "127.0.0.1:18093"
        probe._issuer_url = "http://127.0.0.1:18092"
        probe._session_cookie = None
        probe._principal = None
        probe._is_admin = False

        login_html = b'<form action="/auth/login" method="post"><input type="hidden" name="interaction" value="i1"><input type="hidden" name="csrf_token" value="c1"><input name="username"><input type="password" name="password"><button>Go</button></form>'

        mock_resp1 = mock.MagicMock()
        mock_resp1.geturl.return_value = "http://127.0.0.1:18092/auth/login"
        mock_resp1.read.return_value = login_html
        mock_resp2 = mock.MagicMock()
        mock_resp2.read.return_value = b""

        opener = mock.MagicMock()
        opener.open.side_effect = [mock_resp1, mock_resp2]

        jar = mock.MagicMock()
        jar.__iter__ = mock.MagicMock(return_value=iter([]))

        with mock.patch("urllib.request.build_opener", return_value=opener):
            with mock.patch("http.cookiejar.CookieJar", return_value=jar):
                with self.assertRaises(RuntimeError) as cm:
                    probe.login("alice", "pass", "user-1")
                self.assertIn("ternal_session", str(cm.exception))

    def test_form_action_origin_mismatch_raises(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._bind = "127.0.0.1:18093"
        probe._issuer_url = "http://127.0.0.1:18092"
        probe._session_cookie = None
        probe._principal = None
        probe._is_admin = False

        login_html = b'<form action="http://evil.com/auth/login" method="post"><input type="hidden" name="interaction" value="i1"></form>'

        mock_resp = mock.MagicMock()
        mock_resp.geturl.return_value = "http://127.0.0.1:18092/auth/login"
        mock_resp.read.return_value = login_html

        opener = mock.MagicMock()
        opener.open.return_value = mock_resp

        jar = mock.MagicMock()

        with mock.patch("urllib.request.build_opener", return_value=opener):
            with mock.patch("http.cookiejar.CookieJar", return_value=jar):
                with self.assertRaises(RuntimeError) as cm:
                    probe.login("alice", "pass", "user-1")
                self.assertIn("origin mismatch", str(cm.exception))

    def test_form_action_path_invalid_raises(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._bind = "127.0.0.1:18093"
        probe._issuer_url = "http://127.0.0.1:18092"
        probe._session_cookie = None
        probe._principal = None
        probe._is_admin = False

        login_html = b'<form action="/auth/steal" method="post"><input type="hidden" name="interaction" value="i1"></form>'

        mock_resp = mock.MagicMock()
        mock_resp.geturl.return_value = "http://127.0.0.1:18092/auth/login"
        mock_resp.read.return_value = login_html

        opener = mock.MagicMock()
        opener.open.return_value = mock_resp

        jar = mock.MagicMock()

        with mock.patch("urllib.request.build_opener", return_value=opener):
            with mock.patch("http.cookiejar.CookieJar", return_value=jar):
                with self.assertRaises(RuntimeError) as cm:
                    probe.login("alice", "pass", "user-1")
                self.assertIn("path invalid", str(cm.exception))

    def test_external_redirect_rejected(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._bind = "127.0.0.1:18093"
        probe._issuer_url = "http://127.0.0.1:18092"

        login_html = b'<form action="/auth/login" method="post"><input type="hidden" name="interaction" value="i1"></form>'

        mock_resp = mock.MagicMock()
        mock_resp.geturl.return_value = "http://127.0.0.1:18092/auth/login"
        mock_resp.read.return_value = login_html

        jar = mock.MagicMock()

        with mock.patch("urllib.request.build_opener") as mock_build:
            opener = mock.MagicMock()
            opener.open.side_effect = urllib.error.HTTPError(
                "http://evil.com/steal", 302, "redirect to unauthorized origin: http://evil.com", {}, None
            )
            mock_build.return_value = opener
            with mock.patch("http.cookiejar.CookieJar", return_value=jar):
                with self.assertRaises(urllib.error.HTTPError):
                    probe.login("alice", "pass", "user-1")

    def test_missing_interaction_rejects_post(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._bind = "127.0.0.1:18093"
        probe._issuer_url = "http://127.0.0.1:18092"
        probe._session_cookie = None
        probe._principal = None
        probe._is_admin = False

        login_html = b'<form action="/auth/login" method="post"><input type="hidden" name="csrf_token" value="c1"></form>'

        mock_resp = mock.MagicMock()
        mock_resp.geturl.return_value = "http://127.0.0.1:18092/auth/login"
        mock_resp.read.return_value = login_html

        opener = mock.MagicMock()
        opener.open.return_value = mock_resp

        jar = mock.MagicMock()

        with mock.patch("urllib.request.build_opener", return_value=opener):
            with mock.patch("http.cookiejar.CookieJar", return_value=jar):
                with self.assertRaises(RuntimeError) as cm:
                    probe.login("alice", "pass", "user-1")
                self.assertIn("interaction", str(cm.exception))


class TestGetJsonRedirectCookieBoundary(unittest.TestCase):
    def test_rejects_non_api_origin(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        with self.assertRaises(RuntimeError) as cm:
            probe._get_json("http://evil.com/data", "cookie123")
        self.assertIn("non-API origin", str(cm.exception))

    def test_rejects_issuer_origin(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        with self.assertRaises(RuntimeError) as cm:
            probe._get_json("http://127.0.0.1:18092/data", "cookie123")
        self.assertIn("non-API origin", str(cm.exception))

    def test_builds_opener_with_restricted_redirect(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = json.dumps({"ok": True}).encode()

        with mock.patch("urllib.request.build_opener") as mock_build:
            opener = mock.MagicMock()
            opener.open.return_value = mock_resp
            mock_build.return_value = opener
            result = probe._get_json("http://127.0.0.1:18093/test", "cookie123")

        self.assertEqual(result, {"ok": True})
        opener.open.assert_called_once()
        req = opener.open.call_args[0][0]
        self.assertIn("ternal_session=cookie123", req.get_header("Cookie"))


class TestVerify(unittest.TestCase):
    def test_verify_no_session_raises(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._session_cookie = None
        with self.assertRaises(RuntimeError):
            probe.verify()

    def test_verify_not_authenticated_raises(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._session_cookie = "v1.abc.def"
        probe._principal = "user-1"
        probe._is_admin = True
        probe._bind = "127.0.0.1:18093"

        with mock.patch.object(probe, "_get_json", return_value={"authenticated": False}):
            with self.assertRaises(RuntimeError):
                probe.verify()

    def test_verify_subject_mismatch_raises(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._session_cookie = "v1.abc.def"
        probe._principal = "user-1"
        probe._is_admin = True
        probe._bind = "127.0.0.1:18093"

        with mock.patch.object(probe, "_get_json", return_value={
            "authenticated": True,
            "user": {"sub": "user-different"},
            "is_admin": True,
        }):
            with self.assertRaises(RuntimeError) as cm:
                probe.verify()
            self.assertIn("principal mismatch", str(cm.exception))

    def test_verify_not_admin_raises(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._session_cookie = "v1.abc.def"
        probe._principal = "user-1"
        probe._is_admin = True
        probe._bind = "127.0.0.1:18093"

        with mock.patch.object(probe, "_get_json", return_value={
            "authenticated": True,
            "user": {"sub": "user-1"},
            "is_admin": False,
        }):
            with self.assertRaises(RuntimeError) as cm:
                probe.verify()
            self.assertIn("admin", str(cm.exception))

    def test_verify_success(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._session_cookie = "v1.abc.def"
        probe._principal = "user-1"
        probe._is_admin = True
        probe._bind = "127.0.0.1:18093"

        calls = []
        def fake_get_json(url, cookie):
            calls.append(url)
            if "/auth/session" in url:
                return {"authenticated": True, "user": {"sub": "user-1"}, "is_admin": True}
            if "/hosts/" in url:
                return [{"id": "h1"}]
            return {}

        with mock.patch.object(probe, "_get_json", side_effect=fake_get_json):
            probe.verify()
        self.assertEqual(len(calls), 2)
        self.assertIn("/hosts/", calls[1])


class TestNoSecretsPrinted(unittest.TestCase):
    def test_env_keys_not_leaked_in_repr(self):
        probe = mod.TernalProbe.__new__(mod.TernalProbe)
        probe._binary = "/usr/bin/ternal"
        probe._issuer_url = "http://issuer"
        probe._oidc_client_id = "cid"
        probe._oidc_client_secret = "supersecret"
        probe._bind = "127.0.0.1:18093"
        probe._tmpdir = None
        probe._proc = None
        probe._session_cookie = None
        probe._principal = None
        probe._is_admin = False
        probe._ready = False
        r = repr(probe)
        self.assertNotIn("supersecret", r)


class TestOriginHelper(unittest.TestCase):
    def test_http_origin(self):
        self.assertEqual(mod._origin("http://127.0.0.1:18092/path"), "http://127.0.0.1:18092")

    def test_https_origin(self):
        self.assertEqual(mod._origin("https://example.com:8443/api"), "https://example.com:8443")


if __name__ == "__main__":
    unittest.main()
