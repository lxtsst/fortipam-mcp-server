from __future__ import annotations

import hashlib
import json

import pytest

import fortipam_mcp.approval_email_template_delete_http_transport as transport_module
from fortipam_mcp.address_http_transport import AddressHttpTransportConfig
from fortipam_mcp.approval_email_template_delete_http_transport import (
    ApprovalEmailTemplateDeleteHttpTransportError,
    FortiPamApprovalEmailTemplateDeleteHttpTransport,
    TEMPLATE_DELETE_NAME,
)
from fortipam_mcp.approval_email_template_ssh_transport import (
    APPROVAL_EMAIL_TEMPLATE_UPDATED_CONTENT,
    APPROVAL_EMAIL_TEMPLATE_UPDATED_SUBJECT,
    ApprovalEmailTemplateInspection,
    ApprovalEmailTemplateUpdateReadback,
)


class _Response:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self.content = json.dumps(payload).encode("utf-8")
        self.headers = {"content-type": "application/json"}


class _Client:
    def __init__(self, responses: list[_Response], calls: list[dict[str, object]]) -> None:
        self._responses = responses
        self._calls = calls

    def __enter__(self) -> "_Client":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: object) -> _Response:
        self._calls.append({"method": method, "url": url, **kwargs})
        return self._responses.pop(0)


class _Ssh:
    def __init__(self) -> None:
        self.exists = True
        self.updated = True
        self.references = 0
        self.calls: list[tuple[str, str]] = []

    def inspect(self, name: str) -> ApprovalEmailTemplateInspection:
        self.calls.append(("inspect", name))
        return ApprovalEmailTemplateInspection(self.exists)

    def readback_updated(self, name: str) -> ApprovalEmailTemplateUpdateReadback:
        self.calls.append(("readback_updated", name))
        return ApprovalEmailTemplateUpdateReadback(
            self.exists,
            self.updated,
            self.updated,
        )

    def reference_count(self, name: str) -> int:
        self.calls.append(("references", name))
        return self.references


def _config() -> AddressHttpTransportConfig:
    return AddressHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _record() -> dict[str, object]:
    return {
        "content": APPROVAL_EMAIL_TEMPLATE_UPDATED_CONTENT,
        "name": TEMPLATE_DELETE_NAME,
        "q_origin_key": TEMPLATE_DELETE_NAME,
        "subject": APPROVAL_EMAIL_TEMPLATE_UPDATED_SUBJECT,
    }


def _digest(record: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            record,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _transport(
    responses: list[_Response],
    ssh: _Ssh,
    calls: list[dict[str, object]] | None = None,
) -> FortiPamApprovalEmailTemplateDeleteHttpTransport:
    request_calls = calls if calls is not None else []
    return FortiPamApprovalEmailTemplateDeleteHttpTransport(
        _config(),
        ssh,  # type: ignore[arg-type]
        client_factory=lambda **_: _Client(responses, request_calls),
        accepted_digest=_digest(_record()),
    )


def test_inspect_requires_complete_updated_projection_and_zero_refs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    ssh = _Ssh()

    result = _transport(
        [_Response(200, {"results": [_record()]})],
        ssh,
    ).inspect_delete_target()

    assert result.exists is True
    assert result.eligible_fixed_template is True
    assert result.template_reference_count == 0
    assert result.target_digest == _digest(_record())
    assert ssh.calls == [
        ("readback_updated", TEMPLATE_DELETE_NAME),
        ("references", TEMPLATE_DELETE_NAME),
    ]


def test_inspect_fails_closed_on_digest_projection_or_ssh_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    drifted = _record()
    drifted["subject"] = "changed"
    with pytest.raises(ApprovalEmailTemplateDeleteHttpTransportError):
        _transport(
            [_Response(200, {"results": [drifted]})],
            _Ssh(),
        ).inspect_delete_target()

    unknown = _record()
    unknown["extra"] = "unknown"
    with pytest.raises(ApprovalEmailTemplateDeleteHttpTransportError):
        FortiPamApprovalEmailTemplateDeleteHttpTransport(
            _config(),
            _Ssh(),  # type: ignore[arg-type]
            client_factory=lambda **_: _Client(
                [_Response(200, {"results": [unknown]})],
                [],
            ),
            accepted_digest=_digest(unknown),
        ).inspect_delete_target()

    ssh = _Ssh()
    ssh.updated = False
    with pytest.raises(ApprovalEmailTemplateDeleteHttpTransportError):
        _transport(
            [_Response(200, {"results": [_record()]})],
            ssh,
        ).inspect_delete_target()


def test_nonzero_reference_is_ineligible(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    ssh = _Ssh()
    ssh.references = 1

    result = _transport(
        [_Response(200, {"results": [_record()]})],
        ssh,
    ).inspect_delete_target()

    assert result.eligible_fixed_template is False
    assert result.template_reference_count == 1


def test_delete_is_one_exact_bodyless_request_with_dual_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    ssh = _Ssh()
    calls: list[dict[str, object]] = []
    transport = _transport(
        [
            _Response(200, {"results": [_record()]}),
            _Response(200, {"http_status": 200}),
            _Response(404, {"http_status": 404}),
        ],
        ssh,
        calls,
    )
    inspect_count = 0

    def inspect(name: str) -> ApprovalEmailTemplateInspection:
        nonlocal inspect_count
        inspect_count += 1
        ssh.calls.append(("inspect", name))
        return ApprovalEmailTemplateInspection(inspect_count == 0)

    monkeypatch.setattr(ssh, "inspect", inspect)

    result = transport.delete_and_readback(_digest(_record()))

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "DELETE", "GET"]
    assert calls[1]["url"] == (
        "https://fpa.example.test/api/v2/cmdb/secret/approval-email-template/"
        "mcp-v4-approval-email-template-b37"
    )
    assert "json" not in calls[1]
    assert "content" not in calls[1]


def test_absent_is_categorical(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())

    result = _transport(
        [_Response(404, {"http_status": 404})],
        _Ssh(),
    ).inspect_delete_target()

    assert result.exists is False
    assert result.eligible_fixed_template is False
