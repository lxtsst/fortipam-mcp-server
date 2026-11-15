"""Fixed transport and cleanup checks for the private BP002 event reader."""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest

from fortipam_mcp.local_user_reset_creation_audit_reader import (
    FortiPamLocalUserResetCreationAuditReader, LocalUserResetCreationAuditReadError,
    _ACTOR, _EVENTS, _STATE,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig

from test_local_user_reset_creation_audit_projection import ACTOR, CREATED, NAME, _response


def _actor() -> bytes:
    return json.dumps({
        "http_method": "GET", "http_status": 200, "status": "success",
        "version": "v7.0.0", "build": 29, "path": "web-ui", "name": "state",
        "results": {"admin": {"name": ACTOR, "login_name": ACTOR,
                              "sponsored_group_name": "", "guest_admin": False}},
    }).encode()


def _state(*, enabled: bool = True, excluded: list[str] | None = None) -> bytes:
    disk = {"is_enabled": enabled, "is_loggable": True}
    if excluded is not None:
        disk["excluded_categories"] = excluded
    return json.dumps({
        "http_method": "GET", "status": "success", "version": "v7.0.0",
        "build": 29, "serial": "synthetic-serial",
        "results": {"disk": disk},
    }).encode()


class Response:
    status = 200

    def __init__(self, body: bytes) -> None:
        self.body = body
        self.offset = 0
        self.closed = False

    def getheader(self, name: str, default: str = "") -> str:
        return "application/json" if name.lower() == "content-type" else default

    def readinto(self, target: memoryview) -> int:
        chunk = self.body[self.offset:self.offset + len(target)]
        target[:len(chunk)] = chunk
        self.offset += len(chunk)
        return len(chunk)

    def close(self) -> None:
        self.closed = True


class Connection:
    def __init__(self, harness: Harness) -> None:
        self.harness = harness
        self.response: Response | None = None
        self.closed = False

    def request(self, method: str, target: str, *, headers: dict[str, str]) -> None:
        self.harness.calls.append((method, target))
        assert headers["Authorization"] == "Bearer synthetic-token"
        path = urlsplit(target).path
        if method == "POST" and path.startswith("/api/v2/log/search/abort/"):
            if self.harness.abort_fails:
                raise OSError("synthetic abort failure")
            body = b"{}"
        elif path == _ACTOR:
            body = self.harness.actor
        elif path == _STATE:
            body = self.harness.state
        elif path == _EVENTS:
            body = self.harness.events.pop(0)
        else:
            raise AssertionError("unexpected route")
        self.response = Response(body)
        self.harness.responses.append(self.response)

    def getresponse(self) -> Response:
        assert self.response is not None
        return self.response

    def close(self) -> None:
        self.closed = True


class Harness:
    def __init__(self, directory: Path) -> None:
        self.calls: list[tuple[str, str]] = []
        self.responses: list[Response] = []
        self.actor = _actor()
        self.state = _state()
        self.events = [bytes(_response())]
        self.abort_fails = False
        config = SecretMetadataHttpTransportConfig(
            base_url="https://synthetic.example", bearer_token="synthetic-token",
            timeout_seconds=3, ca_file=None,
        )
        self.reader = FortiPamLocalUserResetCreationAuditReader(
            config, fixture_directory=directory, api_principal=ACTOR,
            connection_factory=self.connect, clock=lambda: CREATED + 601,
            pause=lambda _: None,
        )

    def connect(self, *args, **kwargs) -> Connection:
        return Connection(self)


@pytest.fixture
def fixture_directory(tmp_path: Path) -> Path:
    path = tmp_path / "retained-fixture"
    path.mkdir(mode=0o700)
    binding = path / "binding.json"
    binding.write_text(json.dumps({"username": NAME, "purpose": "new_disabled_reset_fixture"}))
    binding.chmod(0o600)
    os.utime(binding, (CREATED, CREATED))
    return path


def test_fixed_query_qualifies_and_aborts_own_session(fixture_directory: Path) -> None:
    h = Harness(fixture_directory)
    observed = h.reader.read_creation_event()
    assert len(observed.creation_event_digest) == 64
    assert observed.lifecycle_observed_through_ms == (CREATED + 601) * 1000
    assert [method for method, _ in h.calls] == ["GET", "GET", "GET", "POST"]
    query = parse_qs(urlsplit(h.calls[2][1]).query)
    assert query["rows"] == ["25"] and query["start"] == ["0"]
    assert len(query["filter"]) == 4
    assert 'subtype=="system"' in query["filter"]
    assert h.calls[3][1].endswith("/7")
    assert all(response.closed for response in h.responses)


def test_incomplete_search_polls_same_session_and_cleans_up(fixture_directory: Path) -> None:
    h = Harness(fixture_directory)
    h.events = [bytes(_response(root_changes={"completed": 60})), bytes(_response())]
    assert h.reader.read_creation_event().creation_timestamp_ms == CREATED * 1000
    assert len(h.calls) == 5
    assert parse_qs(urlsplit(h.calls[3][1]).query)["session_id"] == ["7"]
    assert h.calls[-1][0] == "POST"


@pytest.mark.parametrize("subtype", ["user", None])
def test_wrong_or_missing_category_rejects_and_cleans_up(
    fixture_directory: Path, subtype: str | None,
) -> None:
    h = Harness(fixture_directory)
    payload = json.loads(_response())
    if subtype is None:
        del payload["results"][0]["subtype"]
    else:
        payload["results"][0]["subtype"] = subtype
    h.events = [json.dumps(payload).encode()]
    with pytest.raises(LocalUserResetCreationAuditReadError):
        h.reader.read_creation_event()
    assert h.calls[-1] == ("POST", "/api/v2/log/search/abort/7")
    assert all(response.closed for response in h.responses)


def test_regressed_search_progress_rejects_and_cleans_up(fixture_directory: Path) -> None:
    h = Harness(fixture_directory)
    h.events = [bytes(_response(root_changes={"completed": 60})),
                bytes(_response(root_changes={"completed": 40}))]
    with pytest.raises(LocalUserResetCreationAuditReadError):
        h.reader.read_creation_event()
    assert [method for method, _ in h.calls][-1] == "POST"


@pytest.mark.parametrize("change", ["actor", "disk", "excluded", "event", "abort"])
def test_failure_stays_closed_and_cleans_known_session(fixture_directory: Path, change: str) -> None:
    h = Harness(fixture_directory)
    if change == "actor":
        h.actor = h.actor.replace(ACTOR.encode(), b"another-actor")
    elif change == "disk":
        h.state = _state(enabled=False)
    elif change == "excluded":
        h.state = _state(excluded=["event"])
    elif change == "event":
        h.events = [bytes(_response(row_changes={"action": "Delete"}))]
    else:
        h.abort_fails = True
    with pytest.raises(LocalUserResetCreationAuditReadError):
        h.reader.read_creation_event()
    assert len([method for method, _ in h.calls if method == "POST"]) == (0 if change in {"actor", "disk", "excluded"} else 1)


def test_binding_mode_or_identity_drift_rejected(fixture_directory: Path) -> None:
    h = Harness(fixture_directory)
    (fixture_directory / "binding.json").chmod(0o644)
    with pytest.raises(LocalUserResetCreationAuditReadError):
        h.reader.read_creation_event()
    assert h.calls == []
