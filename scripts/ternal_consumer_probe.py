#!/usr/bin/env python3
"""Stdlib-only Ternal API consumer probe module.

Provides a reusable context manager that starts a verified local ternal-api
binary, performs an OIDC-mediated login through a real GoAuthy issuer, and
retains the authenticated session cookie for subsequent verification.
"""

from __future__ import annotations

import html.parser
import http.client
import http.cookiejar
import json
import os
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

_API_ORIGIN = "http://127.0.0.1:18093"
_ISSUER_ORIGIN = "http://127.0.0.1:18092"


def _port_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


class _FormParser(html.parser.HTMLParser):
    """Extract the first <form> action URL and all hidden input name/value."""

    def __init__(self) -> None:
        super().__init__()
        self._in_form = False
        self._form_closed = False
        self.action: str | None = None
        self.hidden: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if self._form_closed:
            return
        attr: dict[str, str] = {k: (v or "") for k, v in attrs}
        if tag == "form" and self.action is None:
            self._in_form = True
            self.action = attr.get("action", "")
        elif tag == "input" and self._in_form:
            if attr.get("type", "").lower() == "hidden":
                name = attr.get("name", "")
                if name:
                    if name in self.hidden:
                        raise RuntimeError(f"duplicate hidden input: {name}")
                    self.hidden[name] = attr.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._in_form:
            self._in_form = False
            self._form_closed = True


def _extract_form(html_bytes: bytes) -> tuple[str, dict[str, str]]:
    p = _FormParser()
    p.feed(html_bytes.decode("utf-8", errors="replace"))
    if p.action is None:
        raise RuntimeError("no <form> found in login page")
    return p.action, p.hidden


def _origin(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class _RestrictedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Only follow redirects to allowed origins."""

    def __init__(self, allowed_origins: set[str]) -> None:
        super().__init__()
        self._allowed_origins = allowed_origins

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new_origin = _origin(newurl)
        if new_origin not in self._allowed_origins:
            raise urllib.error.HTTPError(
                newurl, code, f"redirect to unauthorized origin: {new_origin}", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class TernalProbe:
    """Context manager that owns a ternal-api child process and authenticated session."""

    def __init__(
        self,
        binary: str,
        issuer_url: str,
        oidc_client_id: str,
        oidc_client_secret: str,
        bind: str = "127.0.0.1:18093",
    ) -> None:
        if bind != "127.0.0.1:18093":
            raise ValueError(f"invalid bind address: {bind}")
        if issuer_url != "http://127.0.0.1:18092":
            raise ValueError(f"invalid issuer URL: {issuer_url}")
        self._binary = binary
        self._issuer_url = issuer_url
        self._oidc_client_id = oidc_client_id
        self._oidc_client_secret = oidc_client_secret
        self._bind = bind
        self._tmpdir: str | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self._session_cookie: str | None = None
        self._principal: str | None = None
        self._is_admin: bool = False
        self._ready = False

    # -- context manager --------------------------------------------------

    def __enter__(self) -> "TernalProbe":
        host, port_str = self._bind.rsplit(":", 1)
        port = int(port_str)
        if not _port_free(port):
            raise RuntimeError(f"port {port} already in use")

        self._tmpdir = tempfile.mkdtemp(prefix="ternal-probe-")
        try:
            session_key = secrets.token_hex(32)
            relay_token = secrets.token_hex(32)
            env = self._build_env(session_key, relay_token)
            self._proc = subprocess.Popen(
                [self._binary],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            try:
                self._wait_ready(port)
                self._ready = True
            except BaseException:
                self._kill()
                raise
        except BaseException:
            if self._tmpdir and self._proc is None:
                import shutil
                shutil.rmtree(self._tmpdir, ignore_errors=True)
                self._tmpdir = None
            raise
        return self

    def __exit__(self, *exc_info: object) -> None:
        self._kill()

    # -- public API -------------------------------------------------------

    def login(self, username: str, password: str, expected_subject: str) -> None:
        """Authenticate via real GoAuthy OIDC form flow, verify session, retain cookie."""
        base = f"http://{self._bind}"
        issuer = self._issuer_url.rstrip("/")
        issuer_origin = _origin(self._issuer_url)
        api_origin = base

        jar = http.cookiejar.CookieJar()
        redirect_handler = _RestrictedRedirectHandler({issuer_origin, api_origin})
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            redirect_handler,
        )

        # GET ternal /auth/login → follow redirect to GoAuthy authorize → form page
        login_url = f"{base}/auth/login"
        resp = opener.open(login_url, timeout=15)
        final_url = resp.geturl()
        page = resp.read()

        # Parse form action and hidden fields (interaction, csrf_token, etc.)
        form_action, hidden = _extract_form(page)
        if not form_action:
            raise RuntimeError("login form has no action")

        # Require hidden interaction nonempty before password POST
        if not hidden.get("interaction"):
            raise RuntimeError("login form missing required interaction field")

        # Resolve relative action against final URL
        form_url = urllib.parse.urljoin(final_url, form_action)

        # Validate form action: must be issuer origin + /auth/login
        expected_form_origin = issuer_origin
        actual_form_origin = _origin(form_url)
        if actual_form_origin != expected_form_origin:
            raise RuntimeError(f"form action origin mismatch: got {actual_form_origin}, want {expected_form_origin}")

        parsed_form = urllib.parse.urlparse(form_url)
        if parsed_form.path != "/auth/login":
            raise RuntimeError(f"form action path invalid: {parsed_form.path}")

        # POST credentials to GoAuthy login endpoint
        post_data = dict(hidden)
        post_data["username"] = username
        post_data["password"] = password
        encoded = urllib.parse.urlencode(post_data).encode()
        req = urllib.request.Request(form_url, data=encoded, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        # Follow redirects back to ternal /auth/callback then /
        resp2 = opener.open(req, timeout=15)
        _ = resp2.read()

        # Extract ternal_session cookie
        session_cookie = None
        for cookie in jar:
            if cookie.name == "ternal_session":
                session_cookie = cookie.value
                break
        if session_cookie is None:
            raise RuntimeError("ternal_session cookie not found after login")
        self._session_cookie = session_cookie

        # Verify /auth/session
        session_info = self._get_json(f"{base}/auth/session", cookie=session_cookie)
        if not session_info.get("authenticated"):
            raise RuntimeError("session not authenticated")
        user = session_info.get("user", {})
        actual_sub = user.get("sub", "")
        if actual_sub != expected_subject:
            raise RuntimeError(
                f"subject mismatch: got {actual_sub!r}, want {expected_subject!r}"
            )
        if not session_info.get("is_admin"):
            raise RuntimeError("session is not admin")
        self._principal = actual_sub
        self._is_admin = True

        # Verify GET /hosts/ returns 200
        hosts = self._get_json(f"{base}/hosts/", cookie=session_cookie)
        if not isinstance(hosts, list):
            raise RuntimeError("GET /hosts/ did not return a list")

    def verify(self) -> None:
        """Re-verify the retained session cookie against the same process."""
        if self._session_cookie is None:
            raise RuntimeError("no session to verify; call login() first")
        base = f"http://{self._bind}"
        session_info = self._get_json(
            f"{base}/auth/session", cookie=self._session_cookie
        )
        if not session_info.get("authenticated"):
            raise RuntimeError("session no longer authenticated after restart")
        user = session_info.get("user", {})
        if user.get("sub") != self._principal:
            raise RuntimeError("principal mismatch after restart")
        if not session_info.get("is_admin"):
            raise RuntimeError("admin flag lost after restart")
        hosts = self._get_json(f"{base}/hosts/", cookie=self._session_cookie)
        if not isinstance(hosts, list):
            raise RuntimeError("GET /hosts/ failed after restart")

    # -- internals --------------------------------------------------------

    def _build_env(self, session_key: str, relay_token: str) -> dict[str, str]:
        allowed = {"PATH", "HOME", "TMPDIR"}
        env: dict[str, str] = {}
        for k in allowed:
            v = os.environ.get(k)
            if v is not None:
                env[k] = v
        env["TERNAL_BIND"] = self._bind
        if self._tmpdir is None:
            raise RuntimeError("tmpdir not set")
        env["TERNAL_DATA_DIR"] = self._tmpdir
        env["TERNAL_SESSION_KEY"] = session_key
        env["TERNAL_RELAY_ACCESS_TOKEN"] = relay_token
        env["TERNAL_DEV_HEADERS"] = "0"
        env["TERNAL_OIDC_ISSUER"] = self._issuer_url
        env["TERNAL_OIDC_CLIENT_ID"] = self._oidc_client_id
        env["TERNAL_OIDC_CLIENT_SECRET"] = self._oidc_client_secret
        env["TERNAL_OIDC_REDIRECT_URL"] = f"http://{self._bind}/auth/callback"
        env["TERNAL_OIDC_ADMIN_GROUP"] = "ternal-admins"
        return env

    def _wait_ready(self, port: int, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._proc is not None and self._proc.poll() is not None:
                raise RuntimeError(
                    f"ternal-api exited early with code {self._proc.returncode}"
                )
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                conn.request("GET", "/ready")
                resp = conn.getresponse()
                body = resp.read()
                conn.close()
                if resp.status == 200:
                    data = json.loads(body)
                    if data.get("status") == "ready":
                        return
            except (OSError, http.client.HTTPException, json.JSONDecodeError):
                pass
            time.sleep(0.3)
        raise TimeoutError(f"ternal-api /ready not ready within {timeout}s")

    def _kill(self) -> None:
        proc = self._proc
        if proc is None:
            return
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        self._proc = None
        if self._tmpdir:
            import shutil
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None

    @staticmethod
    def _get_json(url: str, cookie: str) -> dict:
        parsed = urllib.parse.urlparse(url)
        url_origin = f"{parsed.scheme}://{parsed.netloc}"
        if url_origin != _API_ORIGIN:
            raise RuntimeError(f"refusing to request non-API origin: {url_origin}")

        redirect_handler = _RestrictedRedirectHandler({_API_ORIGIN})
        opener = urllib.request.build_opener(redirect_handler)

        req = urllib.request.Request(url)
        req.add_header("Cookie", f"ternal_session={cookie}")
        try:
            resp = opener.open(req, timeout=10)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"GET {url} returned {exc.code}") from exc
        raw = resp.read()
        return json.loads(raw)
