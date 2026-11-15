from __future__ import annotations

import http.client
from pathlib import Path
import threading
from urllib.parse import urlencode, urljoin

from scripts.bp007_web_fixture import create_handler
from http.server import ThreadingHTTPServer


def _owner_file(path: Path, value: str) -> Path:
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)
    return path


def test_fixture_authenticates_only_the_owner_only_pair_without_echoing_it(
    tmp_path: Path,
) -> None:
    username = _owner_file(tmp_path / "username", "fixture-user")
    password = _owner_file(tmp_path / "password", "fixture-password")
    server = ThreadingHTTPServer(("127.0.0.1", 0), create_handler(username, password))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port)
        connection.request("GET", "/login")
        page = connection.getresponse().read().decode("utf-8")
        assert "name=\"username\"" in page
        assert "fixture-user" not in page
        assert "fixture-password" not in page

        body = urlencode({"username": "fixture-user", "password": "fixture-password"})
        connection.request(
            "POST",
            "/login",
            body,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        response = connection.getresponse()
        assert response.status == 303
        location = response.getheader("Location")
        assert location == "protected"
        for prefix in ("", "/bp007-web-fixture"):
            assert urljoin(f"https://fixture.example{prefix}/login", location) == (
                f"https://fixture.example{prefix}/protected"
            )
        cookie = response.getheader("Set-Cookie")
        assert cookie is not None
        assert "fixture-user" not in cookie
        assert "fixture-password" not in cookie
        response.read()

        connection.request("GET", "/protected", headers={"Cookie": cookie})
        protected = connection.getresponse()
        assert protected.status == 200
        assert b"authenticated" in protected.read()

        connection.request(
            "POST",
            "/login",
            urlencode({"username": "fixture-user", "password": "wrong"}),
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        failed = connection.getresponse()
        assert failed.status == 401
        assert b"fixture-user" not in failed.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
