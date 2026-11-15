"""Synthetic Owner and file-query resources; no network or device fixtures."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from fortipam_mcp import secret_file_audit_owner_reader as module
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig

SERIAL = "SYNTHETIC01"
OWNER = "synthetic-admin"
EVENT_ACTOR = "synthetic-requester"
START = 1_790_000_000_000
END = START + 60_000


def envelope(path: str, name: str, results: object) -> dict[str, Any]:
    return {"version": "v7.0.0", "build": 29, "serial": SERIAL, "http_method": "GET",
            "http_status": 200, "status": "success", "path": path, "name": name, "results": results}


def event() -> dict[str, Any]:
    return {"#": 1, "secretid": 42, "user": EVENT_ACTOR, "subtype": "secret-file",
            "apptype": "web-sftp", "action": "upload", "operation": "upload-file",
            "sessionid": 17, "uuid": "synthetic-uuid", "_metadata": {"timestamp": START},
            "msg": "opaque_material_marker", "filename": "opaque_filename_marker"}


def query(*, handle: int | str = 7, completed: int | float = 100,
          results: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rows = [] if results is None else results
    return {"completed": completed, "session_id": handle, "rows": 25,
            "total_lines": len(rows), "results": rows}


class Harness:
    def __init__(self, directory: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        directory.chmod(0o700)
        self.manifest = directory / "private" / "search.jsonl"
        self.config = SecretMetadataHttpTransportConfig("https://pam.example.test", "synthetic-token", 5, None)
        self.calls: list[tuple[str, str, dict[str, Any]]] = []
        self.actor = envelope("web-ui", "state", {"admin": {"name": OWNER, "login_name": OWNER,
            "sponsored_group_name": "", "guest_admin": False}})
        self.role = envelope("system", "admin", {"name": OWNER, "accprofile": "super_admin",
            "status": "enable", "remote-auth": "disable", "wildcard": "disable"})
        self.state = envelope("log", "state", {"disk": {"is_enabled": True, "is_loggable": True,
            "excluded_categories": []}})
        self.queries = [query()]
        self.cookie = 'ccsrftoken="synthetic-csrf"'
        self.abort_status = 200
        self.abort_body = b""
        self.fail_query = False
        self.lose_csrf_after_query = False
        self.logout_fail = False
        self.stream_closed = 0
        self.buffers: list[bytearray] = []
        self.owner = object.__new__(OwnerSessionMetadataTransport)
        self.owner._config = self.config
        self.owner._owner_name = OWNER
        self.owner._client = self
        self.owner._clock = lambda: 0.0
        self.owner._expires_at = 300.0
        monkeypatch.setattr(OwnerSessionMetadataTransport, "authenticated", lambda owner: self.session())
        original = module._zeroize_mutable

        def wipe(content: bytearray) -> None:
            self.buffers.append(content)
            original(content)

        monkeypatch.setattr(module, "_zeroize_mutable", wipe)

    @contextmanager
    def session(self) -> Iterator[OwnerSessionMetadataTransport]:
        yield self.owner
        if self.logout_fail:
            raise OSError("synthetic private logout detail")

    def reader(self, **changes: Any) -> module.FortiPamSecretFileAuditOwnerReader:
        args: dict[str, Any] = {"expected_serial": SERIAL, "owner_name": OWNER,
            "expected_secret_id": 42, "expected_actor": EVENT_ACTOR, "start_ms": START, "end_ms": END,
            "requester": "synthetic-root-request", "manifest_path": self.manifest, "pause": lambda _: None}
        args.update(changes)
        return module.FortiPamSecretFileAuditOwnerReader(self.config, self.owner, **args)

    def records(self) -> list[dict[str, Any]]:
        return [json.loads(line) for line in self.manifest.read_bytes().splitlines()]

    def build_request(self, method: str, url: str) -> Any:
        assert method == "GET" and url == self.config.base_url + module._EVENTS
        return SimpleNamespace(headers={"cookie": self.cookie})

    @contextmanager
    def stream(self, method: str, path: str, **kwargs: Any) -> Iterator[Any]:
        self.calls.append((method, path, kwargs))
        status = 200
        content_type = "application/json"
        if method == "POST":
            assert path.startswith(module._ABORT)
            assert kwargs.get("content") is None
            assert "Content-Type" not in kwargs["headers"]
            assert kwargs["headers"]["X-Requested-With"] == "XMLHttpRequest"
            assert kwargs["headers"]["X-CSRFTOKEN"] == "synthetic-csrf"
            records = self.records()
            assert records[-1] == {"kind": "abort_attempted", "handle": int(path.split("/")[-1])}
            assert any(record["kind"] == "handle" for record in records)
            raw = self.abort_body
            status = self.abort_status
            content_type = "text/plain"
        elif path == module._ACTOR_PATH: raw = json.dumps(self.actor).encode()
        elif path.startswith("/api/v2/cmdb/system/admin/"): raw = json.dumps(self.role).encode()
        elif path == module._STATE: raw = json.dumps(self.state).encode()
        else:
            assert path.startswith(module._EVENTS + "?")
            assert self.records()[0]["kind"] == "binding"
            filters = parse_qs(urlsplit(path).query)
            assert filters["rows"] == ["25"] and filters["serial_no"] == [SERIAL]
            assert f'user=="{EVENT_ACTOR}"' in filters["filter"]
            if self.fail_query: raise OSError("synthetic private peer detail")
            response = self.queries.pop(0)
            raw = json.dumps(response).encode()
            if self.lose_csrf_after_query:
                self.cookie = ""
        try:
            yield SimpleNamespace(status_code=status, headers={"content-type": content_type},
                                  iter_bytes=lambda **_: iter([raw]))
        finally:
            self.stream_closed += 1


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Harness:
    return Harness(tmp_path, monkeypatch)


def test_complete_empty_ack_and_empty_page_persist_handle_and_cleanup(harness: Harness) -> None:
    result = harness.reader().read_file_audit()
    assert result.observation.returned_event_count == 0
    assert result.cleanup == module.SecretFileAuditCleanupObservation(1, 1, 1, True, "confirmed")
    assert [record["kind"] for record in harness.records()] == ["binding", "query_attempted", "handle", "abort_attempted", "cleanup_confirmed"]
    assert harness.manifest.stat().st_mode & 0o777 == 0o600
    assert harness.manifest.parent.stat().st_mode & 0o777 == 0o700
    assert all(not content for content in harness.buffers)
    assert b"synthetic-token" not in harness.manifest.read_bytes()


def test_admin_reads_distinct_event_actor_and_projection_sees_durable_handle(
    harness: Harness, monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness.queries = [query(results=[event()])]
    original = module.project_secret_file_audit

    def project(content: bytearray, **kwargs: Any) -> Any:
        assert harness.records()[-1] == {"kind": "handle", "handle": 7}
        assert kwargs["expected_actor"] == EVENT_ACTOR and EVENT_ACTOR != OWNER
        return original(content, **kwargs)

    monkeypatch.setattr(module, "project_secret_file_audit", project)
    result = harness.reader().read_file_audit()
    assert result.observation.upload_event_count == 1
    assert b"opaque_" not in harness.manifest.read_bytes()
    assert all(not content for content in harness.buffers)


def test_monotonic_same_handle_polling_is_bounded_and_recorded_once(harness: Harness) -> None:
    harness.queries = [query(handle="7", completed=20), query(completed=100)]
    result = harness.reader().read_file_audit()
    assert result.cleanup.qualified_handle_count == 1
    searches = [path for method, path, _ in harness.calls if path.startswith(module._EVENTS)]
    assert len(searches) == 2 and "session_id=7" not in searches[0] and "session_id=7" in searches[1]


@pytest.mark.parametrize("fault", ["actor", "role", "serial", "build", "disk", "excluded", "csrf"])
def test_owner_disk_and_csrf_preflight_reject_before_query(harness: Harness, fault: str) -> None:
    if fault == "actor": harness.actor["results"]["admin"]["name"] = EVENT_ACTOR
    elif fault == "role": harness.role["results"]["accprofile"] = "other"
    elif fault == "serial": harness.state["serial"] = "OTHER_SERIAL"
    elif fault == "build": harness.state["build"] = 30
    elif fault == "disk": harness.state["results"]["disk"]["is_loggable"] = False
    elif fault == "excluded": harness.state["results"]["disk"]["excluded_categories"] = ["secret"]
    else: harness.cookie = ""
    with pytest.raises(module.SecretFileAuditOwnerReadError) as error:
        harness.reader().read_file_audit()
    assert error.value.cleanup.category == "not_started"
    assert not any(path.startswith((module._EVENTS, module._ABORT)) for _, path, _ in harness.calls)
    assert harness.records()[0]["kind"] == "binding"
    assert all(not content for content in harness.buffers)


@pytest.mark.parametrize("fault", ["event_actor", "secret", "window", "total", "rows", "enum"])
def test_projection_and_query_binding_failure_preserves_handle_and_cleans(harness: Harness, fault: str) -> None:
    row = event()
    payload = query(results=[row])
    if fault == "event_actor": row["user"] = OWNER
    elif fault == "secret": row["secretid"] = 43
    elif fault == "window": row["_metadata"]["timestamp"] = END + 1
    elif fault == "total": payload["total_lines"] = 26
    elif fault == "rows": payload["rows"] = 26
    elif fault == "enum": row["operation"] = "unknown"
    harness.queries = [payload]
    with pytest.raises(module.SecretFileAuditOwnerReadError) as error:
        harness.reader().read_file_audit()
    assert error.value.cleanup.cleanup_complete
    assert [record["kind"] for record in harness.records()] == ["binding", "query_attempted", "handle", "abort_attempted", "cleanup_confirmed"]
    assert all(not content for content in harness.buffers)


def test_new_handle_drift_is_persisted_before_stop_and_each_abort_is_once(harness: Harness) -> None:
    harness.queries = [query(completed=10), query(handle=8, completed=100)]
    with pytest.raises(module.SecretFileAuditOwnerReadError) as error:
        harness.reader().read_file_audit()
    assert error.value.cleanup == module.SecretFileAuditCleanupObservation(2, 2, 2, True, "confirmed")
    assert [record["handle"] for record in harness.records() if record["kind"] == "handle"] == [7, 8]
    assert len([path for method, path, _ in harness.calls if method == "POST"]) == 2


def test_over_limit_incomplete_query_stops_before_another_poll(harness: Harness) -> None:
    first = query(completed=10)
    first["total_lines"] = 26
    harness.queries = [first, query()]
    with pytest.raises(module.SecretFileAuditOwnerReadError) as error:
        harness.reader().read_file_audit()
    assert error.value.cleanup.cleanup_complete
    assert len(harness.queries) == 1


@pytest.mark.parametrize("fault", ["regression", "fractional_regression", "poll_limit", "abort_status", "abort_oversize", "logout"])
def test_uncertain_or_unfinished_reads_do_not_retry_and_preserve_records(harness: Harness, fault: str) -> None:
    if fault == "regression": harness.queries = [query(completed=50), query(completed=49)]
    elif fault == "fractional_regression": harness.queries = [query(completed=50.9), query(completed=50.1)]
    elif fault == "poll_limit": harness.queries = [query(completed=0)] * 8
    elif fault == "abort_status": harness.abort_status = 403
    elif fault == "abort_oversize": harness.abort_body = b"x" * (1_048_576 + 1)
    else: harness.logout_fail = True
    observer = harness.reader()
    with pytest.raises(module.SecretFileAuditOwnerReadError) as error:
        observer.read_file_audit()
    assert error.value.cleanup.abort_attempted_count == 1
    if fault.startswith("abort_"):
        assert error.value.cleanup.category == "cleanup_unconfirmed"
        assert harness.records()[-1]["kind"] == "cleanup_unconfirmed"
    previous_calls = len(harness.calls)
    with pytest.raises(module.SecretFileAuditOwnerReadError):
        observer.read_file_audit()
    assert len(harness.calls) == previous_calls
    assert all(not content for content in harness.buffers)


@pytest.mark.parametrize("fault", ["existing", "symlink", "parent_mode"])
def test_manifest_preflight_blocks_any_new_query(harness: Harness, fault: str) -> None:
    harness.manifest.parent.mkdir(mode=0o700)
    if fault == "existing": harness.manifest.write_text("unknown prior record")
    elif fault == "symlink": harness.manifest.symlink_to(harness.manifest.parent / "missing")
    else: harness.manifest.parent.chmod(0o755)
    with pytest.raises(module.SecretFileAuditOwnerReadError):
        harness.reader().read_file_audit()
    assert harness.calls == []


@pytest.mark.parametrize("fault", ["transport", "missing_handle"])
def test_first_query_uncertainty_remains_recorded_and_cannot_reopen(harness: Harness, fault: str) -> None:
    harness.fail_query = fault == "transport"
    if fault == "missing_handle":
        del harness.queries[0]["session_id"]
    observer = harness.reader()
    with pytest.raises(module.SecretFileAuditOwnerReadError) as error:
        observer.read_file_audit()
    assert error.value.cleanup == module.SecretFileAuditCleanupObservation(0, 0, 0, False, "cleanup_unconfirmed")
    assert [record["kind"] for record in harness.records()] == ["binding", "query_attempted"]
    previous = len(harness.calls)
    with pytest.raises(module.SecretFileAuditOwnerReadError) as repeated:
        observer.read_file_audit()
    assert repeated.value.cleanup == error.value.cleanup
    with pytest.raises(module.SecretFileAuditOwnerReadError):
        harness.reader().read_file_audit()
    assert len(harness.calls) == previous


@pytest.mark.parametrize("contradiction", [{"serial": "OTHER_SERIAL"}, {"version": "v7.0.1"}, {"build": 30}])
@pytest.mark.parametrize("prior_qualified", [False, True])
def test_contradictory_context_never_qualifies_or_aborts_its_handle(
    harness: Harness, contradiction: dict[str, Any], prior_qualified: bool,
) -> None:
    wrong = query(handle=8)
    wrong.update(contradiction)
    harness.queries = ([query(completed=10)] if prior_qualified else []) + [wrong]
    with pytest.raises(module.SecretFileAuditOwnerReadError) as error:
        harness.reader().read_file_audit()
    qualified = int(prior_qualified)
    assert error.value.cleanup.qualified_handle_count == qualified
    assert error.value.cleanup.abort_attempted_count == qualified
    assert [record["handle"] for record in harness.records() if record["kind"] == "handle"] == ([7] if prior_qualified else [])
    assert [path for method, path, _ in harness.calls if method == "POST"] == ([module._ABORT + "7"] if prior_qualified else [])
    assert not error.value.cleanup.cleanup_complete
    assert error.value.cleanup.category == "cleanup_unconfirmed"
    assert all(not content for content in harness.buffers)


def test_csrf_loss_before_abort_leaves_handle_and_cleanup_unconfirmed_without_post(harness: Harness) -> None:
    harness.lose_csrf_after_query = True
    with pytest.raises(module.SecretFileAuditOwnerReadError) as error:
        harness.reader().read_file_audit()
    assert error.value.cleanup == module.SecretFileAuditCleanupObservation(1, 0, 0, False, "cleanup_unconfirmed")
    assert harness.records()[-1] == {"kind": "cleanup_unconfirmed", "handle": 7}
    assert not any(method == "POST" for method, _, _ in harness.calls)
    assert all(not content for content in harness.buffers)


@pytest.mark.parametrize("changes", [
    {"expected_secret_id": True}, {"expected_actor": "bad\nactor"}, {"owner_name": EVENT_ACTOR},
    {"end_ms": START + 86_400_001}, {"start_ms": True}, {"expected_serial": "bad serial"},
])
def test_invalid_private_binding_has_no_manifest_or_network(harness: Harness, changes: dict[str, Any]) -> None:
    with pytest.raises(module.SecretFileAuditOwnerReadError):
        harness.reader(**changes)
    assert harness.calls == [] and not harness.manifest.exists()


def test_handles_are_fsynced_before_projection_and_abort(harness: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
    synced: list[int] = []
    original = os.fsync

    def fsync(fd: int) -> None:
        synced.append(fd)
        original(fd)

    monkeypatch.setattr(module.os, "fsync", fsync)
    result = harness.reader().read_file_audit()
    assert result.cleanup.cleanup_complete and len(synced) == 6
