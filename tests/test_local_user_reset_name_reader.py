"""Source-equivalent name checks never promote visibility into create authority."""

from __future__ import annotations

import json
import pickle
import ssl
from typing import Any

import pytest

from fortipam_mcp.local_user_reset_name_reader import FortiPamLocalUserResetNameReader, _QUERIES
from fortipam_mcp.local_user_reset_metadata_reader import (
    LocalUserResetMetadataReadError, LocalUserResetReadFailure as Failure,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning.material_provider import MaterialAccessDenied

NAME = "mcp-v4-user-reset-name-test"
PRINCIPAL = "synthetic-api-principal"


def _payload(table: str, names: list[str] | None = None, **updates: Any) -> bytearray:
    data = {
        "http_method": "POST", "http_status": 200, "status": "success", "version": "v7.0.0",
        "build": 29, "path": "system", "name": table, "action": "", "serial": "synthetic-device",
        "results": [{"name": name} for name in (names if names is not None else [
            PRINCIPAL if table == "api-user" else "synthetic-local-control",
        ])],
    }
    data.update(updates)
    return bytearray(json.dumps(data, separators=(",", ":")).encode("utf-8"))


class Harness:
    def __init__(self) -> None:
        self.bodies = {table: _payload(table) for table, _ in _QUERIES}
        self.calls: list[str] = []
        self.buffers: list[bytearray] = []
        self.resources: list[Any] = []
        self.status = 200
        self.fail = ""
        self.reader = FortiPamLocalUserResetNameReader(
            SecretMetadataHttpTransportConfig("https://pam.example.test:9443", "synthetic-token", 5, None),
            username=NAME, api_principal=PRINCIPAL, connection_factory=self.connect,
        )

    def connect(self, host: str, port: int, **kwargs: Any) -> Any:
        assert (host, port) == ("pam.example.test", 9443)
        assert kwargs["context"].verify_mode == ssl.CERT_REQUIRED and kwargs["context"].check_hostname
        h = self

        class Response:
            status = h.status
            offset = 0
            closed = False
            body = bytearray()

            def getheader(self, key: str, default: str = "") -> str:
                return {"content-type": "text/html" if h.fail == "media" else "application/json",
                        "content-encoding": "gzip" if h.fail == "encoding" else "identity"}.get(key, default)

            def readinto(self, view: memoryview) -> int:
                h.buffers.append(view.obj)
                if h.fail == "timeout": raise TimeoutError("synthetic-private-error")
                if h.fail == "count": return True  # type: ignore[return-value]
                count = min(len(view), len(self.body) - self.offset)
                view[:count] = self.body[self.offset:self.offset + count]
                self.offset += count
                return count

            def close(self) -> None:
                self.closed = True

        class Connection:
            closed = False
            response = Response()

            def request(self, method: str, path: str, *, body: bytes, headers: dict[str, str]) -> None:
                assert method == "POST" and headers["X-HTTP-Method-Override"] == "GET"
                assert headers["Accept-Encoding"] == "identity" and headers["User-Agent"]
                table = "api-user" if "/api-user?" in path else "admin"
                assert path == f"/api/v2/cmdb/system/{table}?format=name&with_meta=true"
                assert body == dict(_QUERIES)[table]
                h.calls.append(table)
                if h.fail == "network": raise ConnectionError("synthetic-private-error")
                if h.fail == "api_denied" and table == "api-user": self.response.status = 403
                self.response.body = h.bodies[table]

            def getresponse(self) -> Response:
                h.resources.append(self.response)
                return self.response

            def close(self) -> None:
                self.closed = True

        result = Connection()
        h.resources.append(result)
        return result

    def disposed(self) -> None:
        assert all(not any(buffer) for buffer in self.buffers)
        assert all(resource.closed for resource in self.resources)


def test_both_namespaces_and_positive_control_produce_only_private_visibility() -> None:
    h = Harness()
    value = h.reader.read_observation()
    assert h.calls == ["admin", "api-user"]
    assert value.source_name_check_clear and not value.local_user_collision and not value.api_user_collision
    assert len(value.state_digest) == 64
    assert not hasattr(value, "user_absent") and not hasattr(value, "fixture_creation_digest")
    assert NAME not in repr(value) and PRINCIPAL not in repr(value)
    with pytest.raises(MaterialAccessDenied): pickle.dumps(value)
    h.disposed()


@pytest.mark.parametrize("table", ["admin", "api-user"])
@pytest.mark.parametrize("candidate", [NAME, NAME.upper()])
def test_case_insensitive_collision_in_either_namespace_is_not_clear(table: str, candidate: str) -> None:
    h = Harness()
    names = [PRINCIPAL, candidate] if table == "api-user" else [candidate]
    h.bodies[table] = _payload(table, names)
    value = h.reader.read_observation()
    assert not value.source_name_check_clear and h.calls == ["admin", "api-user"]
    assert value.local_user_collision is (table == "admin")
    assert value.api_user_collision is (table == "api-user")
    h.disposed()


@pytest.mark.parametrize("table,names", [
    ("admin", []), ("api-user", []), ("api-user", ["unrelated-api-user"]),
    ("api-user", [PRINCIPAL, PRINCIPAL.upper()]), ("api-user", [PRINCIPAL, PRINCIPAL]),
])
def test_missing_or_ambiguous_visibility_control_never_clears_name(table: str, names: list[str]) -> None:
    h = Harness(); h.bodies[table] = _payload(table, names)
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_observation()
    h.disposed()


@pytest.mark.parametrize("updates", [
    {"matched_count": 1}, {"matched_count": 1, "next_idx": 3, "size": 2},
    {"matched_count": 2, "next_idx": 0, "size": 2},
    {"matched_count": True, "next_idx": 0, "size": 1},
    {"matched_count": 1, "next_idx": 0, "size": "synthetic-secret"},
    {"limit_reached": True}, {"limit_reached": 0},
    {"version": "v7.0.1"}, {"build": True}, {"http_method": "GET"}, {"action": "default"},
    {"status": "error"}, {"path": "user"}, {"name": "group"}, {"unknown": "synthetic-secret"},
])
def test_incomplete_paging_metadata_or_envelope_drift_is_unknown(updates: dict[str, Any]) -> None:
    h = Harness(); h.bodies["admin"] = _payload("admin", **updates)
    with pytest.raises(LocalUserResetMetadataReadError) as error: h.reader.read_observation()
    assert error.value.reason is Failure.UNQUALIFIED_RESPONSE and h.calls == ["admin"]
    h.disposed()


@pytest.mark.parametrize("next_idx", [0, 1, 2])
def test_reported_match_count_is_checked_without_inventing_cursor_exhaustion(next_idx: int) -> None:
    h = Harness()
    h.bodies["admin"] = _payload("admin", matched_count=1, next_idx=next_idx, size=2, limit_reached=False)
    value = h.reader.read_observation()
    assert value.source_name_check_clear and not hasattr(value, "global_absence_proven")
    h.disposed()


@pytest.mark.parametrize("row", [
    {"name": "synthetic", "password": "synthetic-secret"},
    {"name": "synthetic", "api-key": "synthetic-secret"},
    {"name": "synthetic", "q_ref": {"password": "synthetic-secret"}},
    {"name": "synthetic", "q_static": {"password": "synthetic-secret"}},
    {"name": "synthetic", "q_origin_key": {"password": "synthetic-secret"}},
    {"name": {"password": "synthetic-secret"}},
])
def test_unexpected_material_or_container_never_reaches_value_decoder(row: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness(); h.bodies["admin"] = _payload("admin", results=[row])
    original = json.loads
    sensitive_decode_attempts: list[bool] = []

    def decode(data: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(data, (bytes, bytearray)) and b"synthetic-secret" in data:
            sensitive_decode_attempts.append(True)
        return original(data, *args, **kwargs)

    monkeypatch.setattr(json, "loads", decode)
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_observation()
    assert not sensitive_decode_attempts
    h.disposed()


def test_observed_name_metadata_is_syntax_checked_without_value_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    h = Harness()
    row = {"name": "synthetic-local-control", **{key: "synthetic-metadata-must-not-decode" for key in (
        "q_mkey_type", "q_name", "q_no_edit", "q_no_rename", "q_path", "q_type",
    )}}
    h.bodies["admin"] = _payload("admin", results=[row])
    original = json.loads

    def decode(data: Any, *args: Any, **kwargs: Any) -> Any:
        if isinstance(data, (bytes, bytearray)):
            assert b"synthetic-metadata-must-not-decode" not in data
        return original(data, *args, **kwargs)

    monkeypatch.setattr(json, "loads", decode)
    assert h.reader.read_observation().source_name_check_clear
    h.disposed()


def test_invalid_json_in_ignored_name_metadata_is_rejected() -> None:
    h = Harness()
    h.bodies["admin"] = _payload("admin", results=[{"name": "synthetic", "q_no_edit": True}]).replace(
        b'"q_no_edit":true', b'"q_no_edit":tru',
    )
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_observation()
    h.disposed()


@pytest.mark.parametrize("status,expected", [(401, Failure.AUTHORIZATION_DENIED), (403, Failure.AUTHORIZATION_DENIED),
    (404, Failure.NOT_FOUND), (302, Failure.UNQUALIFIED_RESPONSE)])
def test_http_failure_does_not_mean_absent(status: int, expected: Failure) -> None:
    h = Harness(); h.status = status
    with pytest.raises(LocalUserResetMetadataReadError) as error: h.reader.read_observation()
    assert error.value.reason is expected and h.calls == ["admin"]
    h.disposed()


@pytest.mark.parametrize("fail,expected", [("network", Failure.TRANSPORT_UNAVAILABLE), ("timeout", Failure.TIMED_OUT),
    ("media", Failure.UNQUALIFIED_RESPONSE), ("encoding", Failure.UNQUALIFIED_RESPONSE), ("count", Failure.UNQUALIFIED_RESPONSE)])
def test_transport_failure_is_categorical_and_clears_buffers(fail: str, expected: Failure) -> None:
    h = Harness(); h.fail = fail
    with pytest.raises(LocalUserResetMetadataReadError) as error: h.reader.read_observation()
    assert error.value.reason is expected and "synthetic-private" not in str(error.value)
    h.disposed()


def test_every_read_is_fresh_and_new_api_user_collision_changes_digest() -> None:
    h = Harness(); initial = h.reader.read_observation()
    h.bodies["api-user"] = _payload("api-user", [PRINCIPAL, NAME.upper()])
    changed = h.reader.read_observation()
    assert not changed.source_name_check_clear and changed.state_digest != initial.state_digest
    assert h.calls == ["admin", "api-user", "admin", "api-user"]
    h.disposed()


def test_api_user_denial_after_successful_local_read_never_returns_clear() -> None:
    h = Harness(); h.fail = "api_denied"
    with pytest.raises(LocalUserResetMetadataReadError) as error: h.reader.read_observation()
    assert error.value.reason is Failure.AUTHORIZATION_DENIED and h.calls == ["admin", "api-user"]
    h.disposed()


@pytest.mark.parametrize("kind", ["duplicate_key", "trailing_data", "response_limit", "row_limit"])
def test_malformed_or_oversized_collection_is_rejected(kind: str) -> None:
    h = Harness()
    if kind == "duplicate_key":
        h.bodies["admin"] = _payload("admin").replace(b'"status":"success"', b'"status":"success","status":"success"')
    elif kind == "trailing_data":
        h.bodies["admin"].extend(b" false")
    elif kind == "response_limit":
        h.bodies["admin"] = bytearray(b" " * 1_048_577)
    else:
        h.bodies["admin"] = _payload("admin", [f"synthetic-{index}" for index in range(4097)])
    with pytest.raises(LocalUserResetMetadataReadError): h.reader.read_observation()
    assert h.calls == ["admin"]
    h.disposed()


@pytest.mark.parametrize("username,principal", [("existing-user", PRINCIPAL), (NAME, NAME.upper()), (NAME, ""), (NAME, "x\ny")])
def test_invalid_private_binding_is_rejected(username: str, principal: str) -> None:
    with pytest.raises(LocalUserResetMetadataReadError):
        FortiPamLocalUserResetNameReader(
            SecretMetadataHttpTransportConfig("https://pam.example.test", "synthetic-token", 5, None),
            username=username, api_principal=principal,
        )
