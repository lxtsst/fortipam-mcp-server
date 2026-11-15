from __future__ import annotations

import json

import pytest

from fortipam_mcp import secret_request_default_http_transport as default_module
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
)
from fortipam_mcp.secret_request_create_contract import (
    SecretRequestCreateContractError,
    SecretRequestCreateInput,
    SecretRequestCustomField,
    validate_secret_request_default_response,
)
from fortipam_mcp.secret_request_default_http_transport import (
    FortiPamSecretRequestDefaultHttpTransport,
)


class _Response:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.status = 200
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


def _target_version_default(
    version: str = "v1.9.1",
    build: int = 1758,
) -> dict[str, object]:
    return {
        "http_method": "GET",
        "revision": "0" * 32,
        "results": {
            "id": 0,
            "user": "",
            "secret-id": 0,
            "display-name": "",
            "approval-profile": "",
            "request-type": "launcher",
            "request-ownership-type": "self",
            "request-invitation-user": "",
            "creation-time": "0000-00-00 00:00:00",
            "start-after-approve": "disable",
            "expiration-time": "0000-00-00 00:00:00",
            "start-time": "0000-00-00 00:00:00",
            "duration": 30,
            "final-status": "pending",
            "tier1-status": "pending",
            "tier2-status": "pending",
            "tier3-status": "pending",
            "comments": "",
            "job-name": "",
            "timezone": "",
            "tier-last-sent": 0,
            "emails-sent": [],
            "tier1": [],
            "tier2": [],
            "tier3": [],
            "field": [],
        },
        "vdom": "root",
        "path": "secret",
        "name": "request",
        "action": "default",
        "status": "success",
        "http_status": 200,
        "serial": "synthetic-target",
        "version": version,
        "build": build,
    }


def test_exact_default_fixture_compiles_frontend_equivalent_request_body() -> None:
    evidence = validate_secret_request_default_response(_target_version_default())
    request = SecretRequestCreateInput(
        requester="synthetic-requester",
        secret_id=83,
        request_type="launcher",
        start_after_approve="enable",
        start_time="",
        expiration_time="",
        duration=30,
        comments="bounded reason",
        timezone="Asia/Shanghai",
        custom_fields=(
            SecretRequestCustomField("Ticket", "synthetic-ticket", True),
        ),
    )

    assert request.body(evidence) == {
        "id": 0,
        "user": "synthetic-requester",
        "secret-id": 83,
        "request-type": "launcher",
        "start-after-approve": "enable",
        "start-time": "",
        "expiration-time": "",
        "duration": 30,
        "comments": "bounded reason",
        "timezone": "Asia/Shanghai",
        "field": [
            {
                "id": 1,
                "q_origin_key": 1,
                "name": "Ticket",
                "value": "synthetic-ticket",
            }
        ],
    }

    changed = _target_version_default()
    changed["results"] = {**changed["results"], "duration": 31}  # type: ignore[arg-type]
    with pytest.raises(SecretRequestCreateContractError):
        validate_secret_request_default_response(changed)

    bool_drift = _target_version_default()
    bool_drift["results"] = {  # type: ignore[arg-type]
        **bool_drift["results"],  # type: ignore[misc]
        "id": False,
    }
    with pytest.raises(SecretRequestCreateContractError):
        validate_secret_request_default_response(bool_drift)

    with pytest.raises(SecretRequestCreateContractError):
        SecretRequestCustomField("Required", "", True)


def test_700_build29_default_uses_the_same_exact_request_shape() -> None:
    evidence = validate_secret_request_default_response(
        _target_version_default("v7.0.0", 29)
    )
    request = SecretRequestCreateInput(
        requester="synthetic-requester",
        secret_id=83,
        request_type="launcher",
        start_after_approve="enable",
        start_time="",
        expiration_time="",
        duration=30,
        comments="bounded reason",
        timezone="Asia/Shanghai",
    )

    assert evidence.fortipam_version == "7.0.0"
    assert evidence.fortipam_build == 29
    assert evidence.request_schema_ref == (
        "fortipam-7.0.0-build29-secret-request-create-v1"
    )
    assert request.body(evidence)["request-type"] == "launcher"

    with pytest.raises(SecretRequestCreateContractError):
        validate_secret_request_default_response(
            _target_version_default("v7.0.0", 1758)
        )


def test_700_job_request_binds_one_job_without_launcher_shape_drift() -> None:
    evidence = validate_secret_request_default_response(
        _target_version_default("v7.0.0", 29)
    )
    request = SecretRequestCreateInput(
        requester="synthetic-requester",
        secret_id=83,
        request_type="job",
        job_name="mcp-v4-bp008-job-20260930-r9",
        start_after_approve="disable",
        start_time="",
        expiration_time="2026-09-30 12:30:00",
        duration=0,
        comments="fixed harmless job acceptance",
        timezone="Asia/Shanghai",
    )
    body = request.body(evidence)
    assert body["request-type"] == "job"
    assert body["job-name"] == "mcp-v4-bp008-job-20260930-r9"
    assert body["start-after-approve"] == "disable"
    assert body["start-time"] == ""
    assert body["expiration-time"] == "2026-09-30 12:30:00"
    assert body["duration"] == 0
    assert set(body) == {
        "id", "user", "secret-id", "request-type", "job-name",
        "start-after-approve", "start-time", "expiration-time",
        "duration", "comments", "timezone", "field",
    }

    with pytest.raises(SecretRequestCreateContractError):
        SecretRequestCreateInput(
            requester="synthetic-requester",
            secret_id=83,
            request_type="job",
            job_name="mcp-v4-bp008-job-20260930-r9",
            start_after_approve="enable",
            start_time="",
            expiration_time="",
            duration=30,
            comments="fixed harmless job acceptance",
            timezone="Asia/Shanghai",
        )


def test_default_transport_performs_only_the_fixed_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _Response(json.dumps(_target_version_default()).encode())
    connection = _Connection(response)
    monkeypatch.setattr(default_module, "_ssl_context", lambda _config: object())
    transport = FortiPamSecretRequestDefaultHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example",
            "synthetic-token",
            5,
            None,
        ),
        connection_factory=lambda *_args, **_kwargs: connection,
    )

    evidence = transport.inspect()

    assert evidence.complete_default_projection is True
    assert evidence.raw_values_returned is False
    assert len(connection.requests) == 1
    assert connection.requests[0][0] == "GET"
    assert connection.requests[0][1] == (
        "/api/v2/cmdb/secret/request?"
        "action=default&with_meta=true&vdom=root"
    )


def test_scheduled_request_rejects_an_impossible_timestamp() -> None:
    with pytest.raises(SecretRequestCreateContractError):
        SecretRequestCreateInput(
            requester="synthetic-requester",
            secret_id=83,
            request_type="launcher",
            start_after_approve="disable",
            start_time="2026-02-30 08:00:00",
            expiration_time="2026-03-01 08:00:00",
            duration=0,
            comments="bounded reason",
            timezone="Asia/Shanghai",
        )
