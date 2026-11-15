#!/usr/bin/env python3
"""Serve the isolated BP007 Web Account login fixture.

The fixture deliberately has one purpose: validate a browser-based Web Account
launch against a target that checks the same owner-only username/password pair
that is supplied to the protected Secret-create path.  It neither contacts
FortiPAM nor emits credentials in responses or access logs.  Deploy it only
behind the laboratory TLS proxy. A Docker-only bind may use ``0.0.0.0`` when
the container is published solely to the host loopback interface.
"""

from __future__ import annotations

import argparse
import hmac
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import secrets
import stat
from typing import Final
from urllib.parse import parse_qs


_MAX_FORM_BYTES: Final = 4096
_LOGIN_PAGE: Final = b"""<!doctype html><html><body><main>
<h1>Laboratory Web Account</h1>
<form method="post" action="login">
<label>Username <input name="username" autocomplete="username"></label>
<label>Password <input type="password" name="password" autocomplete="current-password"></label>
<button type="submit">Sign in</button></form></main></body></html>"""
_FIXTURE_PAGE: Final = b"<!doctype html><html><body>BP007 fixture authenticated.</body></html>"
_GENERIC_FAILURE: Final = b"<!doctype html><html><body>Authentication failed.</body></html>"


class FixtureConfigurationError(RuntimeError):
    """Raised when fixture material cannot be safely loaded."""


def _owner_only_text(path: Path) -> str:
    try:
        details = path.stat()
        if (
            not path.is_absolute()
            or not path.is_file()
            or stat.S_IMODE(details.st_mode) & 0o077
            or details.st_size > 1024
        ):
            raise ValueError
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError, ValueError) as exc:
        raise FixtureConfigurationError("BP007 fixture material is unavailable.") from exc
    if not value or len(value) > 255 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise FixtureConfigurationError("BP007 fixture material is unavailable.")
    return value


def create_handler(username_file: Path, password_file: Path) -> type[BaseHTTPRequestHandler]:
    """Create an in-memory authenticated handler without returning material."""

    username = _owner_only_text(username_file)
    password = _owner_only_text(password_file)
    sessions: set[str] = set()

    class BP007FixtureHandler(BaseHTTPRequestHandler):
        server_version = "BP007Fixture"
        sys_version = ""

        def log_message(self, _format: str, *_args: object) -> None:
            """Never log request paths, form values, addresses, or cookies."""

        def do_GET(self) -> None:  # noqa: N802
            if self.path in {"/", "/login"}:
                self._send(HTTPStatus.OK, _LOGIN_PAGE)
                return
            if self.path == "/protected" and self._authenticated():
                self._send(HTTPStatus.OK, _FIXTURE_PAGE)
                return
            self._send(HTTPStatus.NOT_FOUND, b"")

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/login":
                self._send(HTTPStatus.NOT_FOUND, b"")
                return
            length = self._content_length()
            if length is None:
                self._send(HTTPStatus.BAD_REQUEST, _GENERIC_FAILURE)
                return
            fields = parse_qs(
                self.rfile.read(length).decode("utf-8", errors="replace"),
                keep_blank_values=True,
                strict_parsing=False,
            )
            supplied_username = fields.get("username", [""])
            supplied_password = fields.get("password", [""])
            if (
                len(supplied_username) != 1
                or len(supplied_password) != 1
                or not hmac.compare_digest(supplied_username[0], username)
                or not hmac.compare_digest(supplied_password[0], password)
            ):
                self._send(HTTPStatus.UNAUTHORIZED, _GENERIC_FAILURE)
                return
            token = secrets.token_urlsafe(32)
            sessions.add(token)
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "protected")
            self.send_header("Set-Cookie", f"bp007_session={token}; HttpOnly; SameSite=Strict")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def _authenticated(self) -> bool:
            try:
                cookie = SimpleCookie(self.headers.get("Cookie"))
                token = cookie.get("bp007_session")
                return token is not None and token.value in sessions
            except (CookieError, KeyError):
                return False

        def _content_length(self) -> int | None:
            try:
                value = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return None
            return value if 0 <= value <= _MAX_FORM_BYTES else None

        def _send(self, status: HTTPStatus, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

    return BP007FixtureHandler


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username-file", required=True, type=Path)
    parser.add_argument("--password-file", required=True, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=18047, type=int)
    return parser.parse_args()


def main() -> None:
    args = _arguments()
    if not 1 <= args.port <= 65535 or args.host not in {"127.0.0.1", "0.0.0.0"}:
        raise SystemExit("BP007 fixture configuration is invalid.")
    try:
        handler = create_handler(args.username_file, args.password_file)
    except FixtureConfigurationError:
        raise SystemExit("BP007 fixture material is unavailable.") from None
    ThreadingHTTPServer((args.host, args.port), handler).serve_forever()


if __name__ == "__main__":
    main()
