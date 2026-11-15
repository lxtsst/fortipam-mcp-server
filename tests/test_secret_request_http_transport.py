from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timedelta, timezone

import pytest

from fortipam_mcp import secret_request_http_transport as request_module
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
)
from fortipam_mcp.secret_request_http_transport import (
    FortiPamSecretRequestHttpTransport,
    OwnerOnlySecretRequestObservationBindingResolver,
    ProtectedSecretRequestObserver,
    SecretRequestHttpTransportError,
    SecretRequestObservationBinding,
)
from fortipam_mcp.secret_request_mcp_observation import (
    ProtectedSecretRequestMcpObservation,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal


@pytest.mark.parametrize("case,expected", [
    ("past", "elapsed"), ("future", "not_elapsed"),
    ("missing", "unknown"), ("timezone", "unknown"),
    ("stale_clock", "unknown"), ("malformed", "unknown"),
])
def test_job_deadline_does_not_invent_product_expiration(monkeypatch, case, expected):
    now = datetime.now(timezone.utc)
    deadline = (now + timedelta(minutes=1 if case == "future" else -1)).astimezone(
        timezone(timedelta(hours=8))
    ).strftime("%Y-%m-%d %H:%M:%S")
    fields = {"secret-id": 83, "request-type": "job", "final-status": "pending",
              "tier1-status": "pending", "start-time": "",
              "expiration-time": deadline, "timezone": "Asia/Shanghai"}
    if case == "missing": fields.pop("expiration-time")
    if case == "timezone": fields["timezone"] = "UTC"
    if case == "malformed": fields["expiration-time"] = "2026-9-30 12:00:00"
    clock = now - timedelta(minutes=10) if case == "stale_clock" else now
    transport = FortiPamSecretRequestHttpTransport(
        SecretMetadataHttpTransportConfig("https://fpa.example", "synthetic-token", 5, None),
    )
    monkeypatch.setattr(transport, "_request", lambda *_args, **_kwargs: (200, fields, clock))
    result = transport.observe(71, expected_secret_id=83, expected_request_type="job")
    assert result.deadline_state == expected
    assert result.lifecycle_state == "pending" and result.approval_progress == "tier1"
    assert result.action_status == "unknown" and result.raw_values_returned is False
from v4_planning.models import AuthenticatedRequester


@pytest.mark.parametrize("case,expected", [
    ("active", "approved_available"),
    ("future", "approved_not_yet_available"),
    ("expired", "expired"),
    ("stale_clock", "approved_availability_unknown"),
    ("wrong_timezone", "approved_availability_unknown"),
])
def test_launcher_window_observation_preserves_approval_without_inventing_access(
    monkeypatch: pytest.MonkeyPatch, case: str, expected: str,
) -> None:
    now = datetime.now(timezone.utc)
    start = now + timedelta(minutes=1 if case == "future" else -30)
    end = now + timedelta(minutes=-1 if case == "expired" else 30)
    shanghai = timezone(timedelta(hours=8))
    fields: dict[str, object] = {
        "secret-id": 83, "request-type": "launcher",
        "final-status": "approved", "tier1-status": "approved",
        "start-time": start.astimezone(shanghai).strftime("%Y-%m-%d %H:%M:%S"),
        "expiration-time": end.astimezone(shanghai).strftime("%Y-%m-%d %H:%M:%S"),
        "timezone": "UTC" if case == "wrong_timezone" else "Asia/Shanghai",
    }
    clock = now - timedelta(minutes=10) if case == "stale_clock" else now
    transport = FortiPamSecretRequestHttpTransport(
        SecretMetadataHttpTransportConfig("https://fpa.example", "synthetic-token", 5, None),
    )
    monkeypatch.setattr(transport, "_request", lambda *_args, **_kwargs: (200, fields, clock))

    result = transport.observe(71, expected_secret_id=83)

    assert result.lifecycle_state == expected
    assert result.approval_progress == "complete"
    assert result.action_status == ("none" if case == "expired" else "unknown")
    assert result.raw_values_returned is False


class _Response:
    def __init__(self, payload: bytes, *, status: int = 200) -> None:
        self.payload = payload
        self.status = status
        self.offset = 0

    def getheader(self, name: str, default: str = "") -> str:
        return "application/json" if name == "content-type" else default

    def readinto(self, view: memoryview) -> int:
        chunk = self.payload[self.offset : self.offset + len(view)]
        view[: len(chunk)] = chunk
        self.offset += len(chunk)
        return len(chunk)

    def close(self) -> None:
        return None


class _Connection:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.requests: list[tuple[str, str, dict[str, str]]] = []

    def request(self, method: str, path: str, *, headers: dict[str, str]) -> None:
        self.requests.append((method, path, headers))

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        return None


def _transport(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> tuple[FortiPamSecretRequestHttpTransport, _Connection]:
    connection = _Connection(_Response(payload))
    monkeypatch.setattr(request_module, "_ssl_context", lambda _config: object())
    transport = FortiPamSecretRequestHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example",
            "synthetic-token",
            5,
            None,
        ),
        connection_factory=lambda *_args, **_kwargs: connection,
    )
    return transport, connection


def test_observer_decodes_only_fixed_categorical_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.dumps(
        {
            "results": {
                "id": 71,
                "secret-id": 83,
                "request-type": "launcher",
                "final-status": "approved",
                "availability-status": "available",
                "action-status": "complete",
                "current-tier": "complete",
                "user": "must-not-enter-decoder",
                "comments": "must-not-enter-decoder",
                "field": [{"value": "must-not-enter-decoder"}],
            }
        }
    ).encode()
    decoded: list[bytes] = []
    original_loads = request_module.json.loads

    def recording_loads(value: bytes | bytearray | str) -> object:
        data = bytes(value) if not isinstance(value, str) else value.encode()
        decoded.append(data)
        return original_loads(value)

    monkeypatch.setattr(request_module.json, "loads", recording_loads)
    transport, connection = _transport(monkeypatch, payload)

    result = transport.observe(71, expected_secret_id=83)

    assert result.request_exists is True
    assert result.request_type == "launcher"
    assert result.lifecycle_state == "approved_available"
    assert result.approval_progress == "complete"
    assert result.action_status == "complete"
    assert result.raw_values_returned is False
    assert all(b"must-not-enter-decoder" not in value for value in decoded)
    assert all(value != b"83" for value in decoded)
    assert connection.requests[0][0] == "GET"
    assert connection.requests[0][1].startswith(
        "/api/v2/cmdb/secret/request/71?format="
    )


def test_observer_rejects_unknown_status_without_returning_raw_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.dumps(
        {
            "results": {
                "secret-id": 83,
                "request-type": "launcher",
                "final-status": "unexpected",
                "availability-status": "pending",
                "action-status": "needed",
                "current-tier": "first tier",
            }
        }
    ).encode()
    transport, _connection = _transport(monkeypatch, payload)

    with pytest.raises(SecretRequestHttpTransportError):
        transport.observe(71, expected_secret_id=83)


def test_observer_reads_v70_raw_approval_without_inventing_availability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    format_response = _Response(json.dumps({"results": {
        "secret-id": 83,
        "request-type": "launcher",
        "final-status": "approved",
    }}).encode())
    metadata_response = _Response(json.dumps({"results": {
        "secret-id": 83,
        "request-type": "launcher",
        "final-status": "approved",
        "tier1-status": "approved",
        "user": "must-not-enter-decoder",
        "field": [{"value": "must-not-enter-decoder"}],
    }}).encode())

    class _SequenceConnection(_Connection):
        def __init__(self) -> None:
            super().__init__(format_response)
            self.responses = [format_response, metadata_response]

        def getresponse(self) -> _Response:
            return self.responses.pop(0)

    connection = _SequenceConnection()
    monkeypatch.setattr(request_module, "_ssl_context", lambda _config: object())
    decoded: list[bytes] = []
    original_loads = request_module.json.loads

    def recording_loads(value: bytes | bytearray | str) -> object:
        decoded.append(bytes(value) if not isinstance(value, str) else value.encode())
        return original_loads(value)

    monkeypatch.setattr(request_module.json, "loads", recording_loads)
    transport = FortiPamSecretRequestHttpTransport(
        SecretMetadataHttpTransportConfig("https://fpa.example", "synthetic-token", 5, None),
        connection_factory=lambda *_args, **_kwargs: connection,
    )

    result = transport.observe(71, expected_secret_id=83)

    assert result.lifecycle_state == "approved_availability_unknown"
    assert result.approval_progress == "complete"
    assert result.action_status == "unknown"
    assert result.raw_values_returned is False
    assert connection.requests[1][1].endswith("?with_meta=true&vdom=root")
    assert all(b"must-not-enter-decoder" not in value for value in decoded)


def test_protected_observer_never_accepts_a_numeric_id_from_the_caller(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.dumps(
        {
            "results": {
                "secret-id": 83,
                "request-type": "launcher",
                "final-status": "pending",
                "availability-status": "pending",
                "action-status": "needed",
                "current-tier": "first tier",
            }
        }
    ).encode()
    transport, connection = _transport(monkeypatch, payload)
    binding = SecretRequestObservationBinding(
        "opaque-request-reference01",
        71,
        83,
        "a" * 64,
        "approval-environment-ref01",
        "approval-scope-reference01",
    )
    observer = ProtectedSecretRequestObserver(
        transport,
        binding,
        authorized_environment_ref="approval-environment-ref01",
        authorized_scope_ref="approval-scope-reference01",
    )

    result = observer.observe(
        "opaque-request-reference01",
        requester_digest="a" * 64,
    )

    assert result.lifecycle_state == "pending"
    assert result.approval_progress == "tier1"
    assert "/71?" in connection.requests[0][1]
    with pytest.raises(SecretRequestHttpTransportError):
        observer.observe("different-request-reference01", requester_digest="a" * 64)
    assert len(connection.requests) == 1


def test_protected_observer_rejects_request_for_a_different_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = json.dumps(
        {
            "results": {
                "secret-id": 84,
                "request-type": "launcher",
                "final-status": "pending",
                "availability-status": "pending",
                "action-status": "needed",
                "current-tier": "first tier",
            }
        }
    ).encode()
    transport, _connection = _transport(monkeypatch, payload)
    binding = SecretRequestObservationBinding(
        "opaque-request-reference01",
        71,
        83,
        "a" * 64,
        "approval-environment-ref01",
        "approval-scope-reference01",
    )
    observer = ProtectedSecretRequestObserver(
        transport,
        binding,
        authorized_environment_ref="approval-environment-ref01",
        authorized_scope_ref="approval-scope-reference01",
    )

    with pytest.raises(SecretRequestHttpTransportError):
        observer.observe(
            "opaque-request-reference01",
            requester_digest="a" * 64,
        )


@pytest.mark.parametrize("request_type", ["launcher", "job"])
def test_mcp_observation_uses_owner_binding_and_returns_no_identifiers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    request_type: str,
) -> None:
    payload = json.dumps(
        {
            "results": {
                "secret-id": 83,
                "request-type": request_type,
                "final-status": "approved",
                "availability-status": "available",
                "action-status": "complete",
                "current-tier": "complete",
            }
        }
    ).encode()
    transport, connection = _transport(monkeypatch, payload)
    requester = AuthenticatedRequester("approval-requester-ref01", "operator")
    principal = V4PlanningPrincipal(requester, "b" * 64)
    binding_path = tmp_path / "request-observation.json"
    binding_path.write_text(
        json.dumps(
            {
                "contract": "fortipam-secret-request-observation-binding-v1",
                "version": "1.0.0",
                "request_ref": "opaque-request-reference01",
                "request_id": 71,
                "secret_id": 83,
                "requester_digest": requester.digest,
                "environment_ref": "approval-environment-ref01",
                "scope_ref": "approval-scope-reference01",
                "request_type": request_type,
            }
        ),
        encoding="utf-8",
    )
    binding_path.chmod(0o600)
    observation = ProtectedSecretRequestMcpObservation(
        transport,
        OwnerOnlySecretRequestObservationBindingResolver(binding_path),
    )

    result = observation.observe("opaque-request-reference01", principal)

    expected = {
        "contract": "fortipam-v4-secret-request-observation-v1",
        "request_exists": True,
        "request_type": request_type,
        "lifecycle_state": "approved_available",
        "approval_progress": "complete",
        "action_status": "complete",
        "raw_values_returned": False,
    }
    if request_type == "job": expected["deadline_state"] = "unknown"
    assert result == expected
    assert "71" not in json.dumps(result)
    assert "83" not in json.dumps(result)
    assert "opaque-request-reference01" not in json.dumps(result)
    assert len(connection.requests) == 1


def test_mcp_observation_rejects_a_different_requester_before_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, connection = _transport(monkeypatch, b"{}")
    owner = AuthenticatedRequester("approval-requester-ref01", "operator")
    binding_path = tmp_path / "request-observation.json"
    binding_path.write_text(
        json.dumps(
            {
                "contract": "fortipam-secret-request-observation-binding-v1",
                "version": "1.0.0",
                "request_ref": "opaque-request-reference01",
                "request_id": 71,
                "secret_id": 83,
                "requester_digest": owner.digest,
                "environment_ref": "approval-environment-ref01",
                "scope_ref": "approval-scope-reference01",
                "request_type": "launcher",
            }
        ),
        encoding="utf-8",
    )
    binding_path.chmod(0o600)
    observation = ProtectedSecretRequestMcpObservation(
        transport,
        OwnerOnlySecretRequestObservationBindingResolver(binding_path),
    )
    other = V4PlanningPrincipal(
        AuthenticatedRequester("different-requester-ref01", "operator"),
        "b" * 64,
    )

    with pytest.raises(RuntimeError, match="observation is unavailable"):
        observation.observe("opaque-request-reference01", other)

    assert connection.requests == []
