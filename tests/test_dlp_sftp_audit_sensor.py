from __future__ import annotations

from copy import deepcopy
from collections.abc import Callable, Iterator
import json
from typing import Any

import pytest

from fortipam_mcp.dlp_sensor_delete_http_transport import DlpSensorDeleteHttpTransportConfig
from fortipam_mcp.dlp_sensor_mcp_action import (
    DLP_PROFILE_SFTP_AUDIT, ProtectedDlpSensorMcpAction, V4DlpSensorActionRuntimeError,
)
from fortipam_mcp.dlp_sensor_ssh_transport import (
    DlpRegexpSensorInspection, DlpSensorSshTransportError, _sftp_audit_sensor_name,
)
from fortipam_mcp.dlp_sftp_audit_sensor_http_transport import (
    DlpSftpAuditSensorHttpTransportError, DlpSftpAuditSensorInspection,
    DlpSftpAuditSensorReadback, FortiPamDlpSftpAuditSensorHttpTransport, _readback,
    MAX_RESPONSE_BYTES,
)
from fortipam_mcp.dlp_sftp_audit_sensor_live_workflow import (
    DlpSftpAuditSensorLiveWorkflow, DlpSftpAuditSensorLiveWorkflowError,
)
from fortipam_mcp.secret_dlp_association_contract import fixed_log_only_sensor_profile
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from test_v4_m3 import _requester
from test_dlp_api_actor_guard import Harness as _ActorHarness, SERIAL as _ACTOR_SERIAL


NAME = "mcp-v4-dlp-sftp-audit-test1"
REQUESTER = "a" * 64
SERIAL = _ACTOR_SERIAL


def _envelope(method: str, status: int, record: object = None) -> dict[str, object]:
    return {
        "status": "success" if status == 200 else "error", "http_method": method,
        "http_status": status, "path": "dlp", "name": "sensor",
        "version": "v7.0.0", "build": 29, "serial": SERIAL, "results": record,
    }


def _ack() -> dict[str, object]:
    ack = _envelope("POST", 200)
    ack.pop("results")
    ack.update({"mkey": NAME, "revision": "native-revision", "old_revision": "native-old",
                "revision_changed": True, "vdom": "root"})
    return ack


def _native_profile() -> dict[str, Any]:
    profile: dict[str, Any] = deepcopy(dict(fixed_log_only_sensor_profile(sensor_name=NAME)))
    profile["q_origin_key"] = NAME
    entry = profile["filter"][0]
    entry["q_origin_key"] = 1
    entry.pop("file-size")
    entry.pop("match-percentage")
    return profile


class _Response:
    def __init__(self, status: int, payload: object) -> None:
        self.status_code = status
        self.headers = {"content-type": "application/json"}
        self.content = json.dumps(payload).encode()

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def iter_bytes(self, *, chunk_size: int) -> Iterator[bytes]:
        for offset in range(0, len(self.content), chunk_size):
            yield self.content[offset:offset + chunk_size]


class _Client:
    def __init__(self) -> None:
        self.responses: list[_Response | Exception] = []
        self.calls: list[tuple[str, str, object]] = []
        self.options: list[dict[str, object]] = []

    def __call__(self, **kwargs: Any) -> _Client:
        self.options.append(kwargs)
        return self

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def stream(self, method: str, url: str, **kwargs: Any) -> _Response:
        self.calls.append((method, url, kwargs.get("json")))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class _Ssh:
    exists = False

    def inspect_sftp_audit_sensor(self, sensor_name: str) -> DlpRegexpSensorInspection:
        assert sensor_name == NAME
        return DlpRegexpSensorInspection(self.exists)


def _transport(
    client: _Client, ssh: _Ssh | None = None, *, actor_harness: _ActorHarness | None = None,
) -> FortiPamDlpSftpAuditSensorHttpTransport:
    actor = actor_harness or _ActorHarness()
    return FortiPamDlpSftpAuditSensorHttpTransport(
        actor.config,
        ssh or _Ssh(), sensor_name=NAME, expected_serial=SERIAL, client_factory=client,
        actor_guard=actor.guard,
    )


def _absent() -> _Response:
    return _Response(404, _envelope("GET", 404))


def test_transport_final_prewrite_one_post_and_full_canonical_readback() -> None:
    client = _Client()
    client.responses = [
        _absent(), _absent(), _Response(200, _ack()),
        _Response(200, _envelope("GET", 200, _native_profile())),
    ]
    transport = _transport(client)
    inspection = transport.inspect_sftp_sensor(NAME)
    assert not inspection.sensor_name_exists
    assert len(inspection.source_digest) == 64
    readback = transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100)
    assert readback.verified
    assert [call[0] for call in client.calls] == ["GET", "GET", "POST", "GET"]
    assert client.calls[2][1] == "https://pam.example.test:9443/api/v2/cmdb/dlp/sensor"
    assert client.calls[2][2] == fixed_log_only_sensor_profile(sensor_name=NAME)
    assert all(options["trust_env"] is False and options["follow_redirects"] is False
               and options["verify"] is not False for options in client.options)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100)
    assert len(client.calls) == 4


def _change_actor_role(actor: _ActorHarness) -> None:
    path = actor.guard._role_path
    payload = json.loads(actor.bodies[path])
    payload["results"][0]["sysgrp-permission"]["cfg"] = "read"
    actor.bodies[path] = bytearray(json.dumps(payload).encode())


@pytest.mark.parametrize("kind", ["missing", "attestation", "other_config"])
def test_concrete_actor_guard_and_exact_config_are_required(kind: str) -> None:
    actor = _ActorHarness()
    guard: Any = actor.guard
    config = actor.config
    if kind == "missing":
        guard = None
    elif kind == "attestation":
        class Attestation:
            qualified = True
        guard = Attestation()
    else:
        config = _ActorHarness().config
    client = _Client()
    transport = FortiPamDlpSftpAuditSensorHttpTransport(
        config, _Ssh(), sensor_name=NAME, expected_serial=SERIAL,
        client_factory=client, actor_guard=guard,
    )
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.inspect_sftp_sensor(NAME)
    assert not client.calls and not actor.calls


def test_actor_is_fresh_in_each_native_inspection_and_before_post() -> None:
    actor = _ActorHarness()
    client = _Client()
    client.responses = [_absent(), _absent(), _Response(200, _ack()),
                        _Response(200, _envelope("GET", 200, _native_profile()))]
    transport = _transport(client, actor_harness=actor)
    transport.inspect_sftp_sensor(NAME)
    assert len(actor.calls) == 3
    transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100)
    assert len(actor.calls) == 9
    actor.disposed()


def test_guard_role_drift_after_preview_blocks_confirmation_before_native_read() -> None:
    actor = _ActorHarness()
    client = _Client()
    client.responses = [_absent()]
    transport = _transport(client, actor_harness=actor)
    workflow = DlpSftpAuditSensorLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(sensor_name=NAME, requester_digest=REQUESTER)
    _change_actor_role(actor)
    with pytest.raises(DlpSftpAuditSensorLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    assert [call[0] for call in client.calls] == ["GET"]
    actor.disposed()


def test_role_drift_after_final_native_read_means_zero_post() -> None:
    actor = _ActorHarness()

    class _DriftingClient(_Client):
        def __call__(self, **kwargs: Any) -> _Client:
            if len(self.calls) == 2:
                _change_actor_role(actor)
            return super().__call__(**kwargs)

    client = _DriftingClient()
    client.responses = [_absent(), _absent()]
    transport = _transport(client, actor_harness=actor)
    transport.inspect_sftp_sensor(NAME)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100)
    assert [call[0] for call in client.calls] == ["GET", "GET"]
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100)
    actor.disposed()


def test_expiry_during_final_guard_observation_means_zero_post() -> None:
    actor = _ActorHarness()
    epoch = [100]
    original_factory = actor.guard._factory

    def expiring_factory(*args: Any, **kwargs: Any) -> Any:
        if len(actor.calls) == 6:
            epoch[0] = 700
        return original_factory(*args, **kwargs)

    actor.guard._factory = expiring_factory
    client = _Client()
    client.responses = [_absent(), _absent()]
    transport = _transport(client, actor_harness=actor)
    transport.inspect_sftp_sensor(NAME)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: epoch[0])
    assert len(actor.calls) == 9
    assert [call[0] for call in client.calls] == ["GET", "GET"]
    actor.disposed()


def test_transport_requires_preflight_and_consumes_uncertain_post() -> None:
    client = _Client()
    transport = _transport(client)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100)
    assert not client.calls
    client.responses = [_absent(), _absent(), TimeoutError("private response")]
    transport.inspect_sftp_sensor(NAME)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError, match="unavailable"):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100)
    assert [call[0] for call in client.calls] == ["GET", "GET", "POST"]


@pytest.mark.parametrize("field,value", [("serial", "OTHER"), ("build", 30), ("build", True),
                                         ("version", "v7.1.0"), ("http_method", "POST")])
def test_transport_rejects_identity_or_envelope_drift(field: str, value: object) -> None:
    payload = _envelope("GET", 404)
    payload[field] = value
    client = _Client()
    client.responses = [_Response(404, payload)]
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _transport(client).inspect_sftp_sensor(NAME)
    assert [call[0] for call in client.calls] == ["GET"]


def test_final_absence_drift_or_ssh_disagreement_blocks_post() -> None:
    client = _Client()
    client.responses = [_absent(), _Response(
        200, _envelope("GET", 200, fixed_log_only_sensor_profile(sensor_name=NAME)),
    )]
    ssh = _Ssh()
    transport = _transport(client, ssh)
    transport.inspect_sftp_sensor(NAME)
    ssh.exists = True
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100)
    assert [call[0] for call in client.calls] == ["GET", "GET"]
    client = _Client()
    client.responses = [_absent()]
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _transport(client, ssh).inspect_sftp_sensor(NAME)


@pytest.mark.parametrize("status,extra", [
    (200, {"error": -3}), (200, {"error": False}),
    (200, {"status": "error"}), (404, {"results": {"name": NAME}}),
    (404, {"result": [{"name": NAME}]}), (404, {"error": 0}),
    (404, {"mkey": "other"}), (404, {"status": "success"}),
])
def test_envelope_contradictions_are_rejected(status: int, extra: dict[str, object]) -> None:
    payload = _envelope("GET", status,
                        fixed_log_only_sensor_profile(sensor_name=NAME) if status == 200 else None)
    payload.update(extra)
    client = _Client()
    client.responses = [_Response(status, payload)]
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _transport(client).inspect_sftp_sensor(NAME)


def test_stream_rejects_oversize_before_reading_the_remaining_body() -> None:
    class _OversizeResponse(_Response):
        chunks_read = 0

        def iter_bytes(self, *, chunk_size: int) -> Iterator[bytes]:
            for _ in range(MAX_RESPONSE_BYTES // chunk_size + 20):
                self.chunks_read += 1
                yield b"x" * chunk_size

    response = _OversizeResponse(404, {})
    client = _Client()
    client.responses = [response]
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _transport(client).inspect_sftp_sensor(NAME)
    assert response.chunks_read == MAX_RESPONSE_BYTES // 4096 + 1


@pytest.mark.parametrize("change", ["missing_mkey", "wrong_mkey", "unknown", "results",
                                    "error", "revision_type", "revision_control",
                                    "revision_oversize", "old_revision_control",
                                    "unchanged", "changed_integer", "wrong_action", "wrong_vdom"])
def test_post_ack_denial_consumes_attempt_and_never_replays(change: str) -> None:
    ack = _ack()
    if change == "missing_mkey":
        ack.pop("mkey")
    else:
        key, value = {
            "wrong_mkey": ("mkey", "other"), "unknown": ("future-ack-option", "value"),
            "results": ("results", None), "error": ("error", -3),
            "revision_type": ("revision", 123), "revision_control": ("revision", "unsafe\n"),
            "revision_oversize": ("revision", "x" * 256),
            "old_revision_control": ("old_revision", "unsafe\x7f"),
            "unchanged": ("revision_changed", False), "changed_integer": ("revision_changed", 1),
            "wrong_action": ("action", "clone"), "wrong_vdom": ("vdom", "other"),
        }[change]
        ack[key] = value
    client = _Client()
    client.responses = [_absent(), _absent(), _Response(200, ack)]
    transport = _transport(client)
    transport.inspect_sftp_sensor(NAME)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100)
    assert [call[0] for call in client.calls] == ["GET", "GET", "POST"]


def test_response_duplicate_members_are_rejected() -> None:
    response = _absent()
    response.content = response.content.replace(b'"status": "error"',
                                                b'"status": "success", "status": "error"')
    client = _Client()
    client.responses = [response]
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _transport(client).inspect_sftp_sensor(NAME)


def test_expiry_during_final_native_read_rejects_before_post() -> None:
    epoch = [100]

    class _ExpiringSsh(_Ssh):
        inspections = 0

        def inspect_sftp_audit_sensor(self, sensor_name: str) -> DlpRegexpSensorInspection:
            self.inspections += 1
            if self.inspections == 2:
                epoch[0] = 700
            return super().inspect_sftp_audit_sensor(sensor_name)

    client = _Client()
    client.responses = [_absent(), _absent()]
    transport = _transport(client, _ExpiringSsh())
    transport.inspect_sftp_sensor(NAME)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: epoch[0])
    assert [call[0] for call in client.calls] == ["GET", "GET"]


def test_expiry_during_post_client_preparation_rejects_before_dispatch() -> None:
    epoch = [100]

    class _ExpiringClient(_Client):
        def __call__(self, **kwargs: Any) -> _Client:
            if len(self.calls) == 2:
                epoch[0] = 700
            return super().__call__(**kwargs)

    client = _ExpiringClient()
    client.responses = [_absent(), _absent()]
    transport = _transport(client)
    transport.inspect_sftp_sensor(NAME)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: epoch[0])
    assert [call[0] for call in client.calls] == ["GET", "GET"]


@pytest.mark.parametrize("change", ["extra_filter", "extra_protocol", "block", "archive",
                                    "full_archive", "summary", "extra_native", "origin",
                                    "extra_filter_native", "bool_id", "truncated",
                                    "nac_quarantine", "unsafe_inactive"])
def test_readback_rejects_dangerous_extra_and_incomplete_native_shape(change: str) -> None:
    profile = _native_profile()
    entry = profile["filter"][0]
    if change == "extra_filter":
        profile["filter"].append(deepcopy(entry))
    elif change == "extra_protocol":
        entry["proto"] += " ssh"
    elif change == "block":
        entry["action"] = "block"
    elif change == "archive":
        entry["archive"] = "enable"
    elif change == "full_archive":
        profile["full-archive-proto"] = "http-get"
    elif change == "summary":
        profile["summary-proto"] = "http-post"
    elif change == "extra_native":
        profile["future-dangerous-option"] = "enable"
    elif change == "origin":
        profile["q_origin_key"] = "other"
    elif change == "extra_filter_native":
        entry["future-dangerous-option"] = "enable"
    elif change == "bool_id":
        entry["id"] = True
    elif change == "nac_quarantine":
        profile["nac-quar-log"] = "enable"
    elif change == "unsafe_inactive":
        entry["file-size"] = 1
    else:
        entry.pop("expiry")
    assert not _readback(_envelope("GET", 200, profile), NAME).verified


def test_name_limit_and_cross_profile_inputs_are_denied() -> None:
    assert len(_sftp_audit_sensor_name("mcp-v4-dlp-sftp-audit-" + "x" * 13)) == 35
    for name in ["mcp-v4-dlp-sftp-audit-" + "x" * 14, "mcp-v4-dlp-sensor-b34",
                 "mcp-v4-dlp-regexp-sensor-test", NAME + '"\nset action block']:
        with pytest.raises(DlpSensorSshTransportError):
            _sftp_audit_sensor_name(name)
    client = _Client()
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _transport(client).inspect_sftp_sensor("mcp-v4-dlp-sftp-audit-other")
    assert not client.calls


class _WorkflowTransport:
    exists = False
    source_digest = "b" * 64
    calls = 0
    fail = False

    def inspect_sftp_sensor(self, sensor_name: str) -> DlpSftpAuditSensorInspection:
        assert sensor_name == NAME
        return DlpSftpAuditSensorInspection(self.exists, self.source_digest)

    def create_sftp_and_readback(
        self, sensor_name: str, *, expires_at: int, clock: Callable[[], int],
    ) -> DlpSftpAuditSensorReadback:
        assert sensor_name == NAME
        assert clock() < expires_at
        self.calls += 1
        if self.fail:
            raise TimeoutError("private data")
        return DlpSftpAuditSensorReadback(True, True, True, True, True, True, True, True, True)


def test_injected_mcp_profile_reuses_workflow_one_confirmation_one_create() -> None:
    transport = _WorkflowTransport()
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    action = ProtectedDlpSensorMcpAction(object(), sftp_workflow=DlpSftpAuditSensorLiveWorkflow(
        transport, clock=lambda: 100,
    ))
    preview = action.preview(NAME, None, None, principal, DLP_PROFILE_SFTP_AUDIT)
    assert str(preview["preview_ref"]).startswith("dlp-sftp-audit-sensor-preview-")
    proposed = preview["Proposed Changes"]
    assert isinstance(proposed, dict) and proposed["action"] == "log-only"
    assert proposed["protocols"] == ["http-get", "http-post"]
    assert "MCP_V4_DLP_REGEX_SENTINEL" not in repr(preview)
    confirmation = action.confirm(str(preview["preview_ref"]), principal)
    result = action.execute(str(confirmation["authorization_ref"]), principal)
    assert result["outcome"] == "succeeded" and result["raw_api_returned"] is False
    assert result["contract"] == "fortipam_v4_dlp_sftp_audit_sensor_create_execution_v1"
    assert action.execute(str(confirmation["authorization_ref"]), principal)["idempotent_replay"] is True
    assert transport.calls == 1


def test_new_profile_default_denial_binding_and_execution_gate() -> None:
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    denied = ProtectedDlpSensorMcpAction(object())
    for args in [(None, None), (1001, "mcp-v4-dlp-pattern-test")]:
        with pytest.raises(V4DlpSensorActionRuntimeError):
            denied.preview(NAME, *args, principal, DLP_PROFILE_SFTP_AUDIT)
    with pytest.raises(V4DlpSensorActionRuntimeError):
        denied.confirm("dlp-sftp-audit-sensor-preview-test", principal)
    workflow = DlpSftpAuditSensorLiveWorkflow(_WorkflowTransport(), clock=lambda: 100)
    gated = ProtectedDlpSensorMcpAction(object(), sftp_workflow=workflow, execution_enabled=False)
    preview = gated.preview(NAME, None, None, principal, DLP_PROFILE_SFTP_AUDIT)
    confirmation = gated.confirm(str(preview["preview_ref"]), principal)
    with pytest.raises(V4DlpSensorActionRuntimeError):
        gated.execute(str(confirmation["authorization_ref"]), principal)


@pytest.mark.parametrize("phase", ["confirm", "execute"])
def test_workflow_source_drift_is_rejected_before_dispatch(phase: str) -> None:
    transport = _WorkflowTransport()
    workflow = DlpSftpAuditSensorLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(sensor_name=NAME, requester_digest=REQUESTER)
    if phase == "confirm":
        transport.source_digest = "c" * 64
        with pytest.raises(DlpSftpAuditSensorLiveWorkflowError):
            workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    else:
        confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
        transport.source_digest = "c" * 64
        with pytest.raises(DlpSftpAuditSensorLiveWorkflowError):
            workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
    assert transport.calls == 0


def test_workflow_requester_expiry_cross_refs_and_uncertain_consumption() -> None:
    transport = _WorkflowTransport()
    epoch = [100]
    workflow = DlpSftpAuditSensorLiveWorkflow(transport, clock=lambda: epoch[0])
    preview = workflow.preview(sensor_name=NAME, requester_digest=REQUESTER)
    with pytest.raises(DlpSftpAuditSensorLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest="d" * 64)
    with pytest.raises(DlpSftpAuditSensorLiveWorkflowError):
        workflow.confirm("dlp-regexp-sensor-preview-test", requester_digest=REQUESTER)
    epoch[0] = 700
    with pytest.raises(DlpSftpAuditSensorLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    epoch[0] = 800
    preview = workflow.preview(sensor_name=NAME, requester_digest=REQUESTER)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    transport.fail = True
    assert workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)["outcome"] == "reconciliation_required"
    with pytest.raises(DlpSftpAuditSensorLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
    assert transport.calls == 1


@pytest.mark.parametrize("phase", ["confirm", "execute"])
def test_workflow_revalidates_expiry_after_slow_inspection(phase: str) -> None:
    epoch = [100]

    class _ExpiringWorkflowTransport(_WorkflowTransport):
        expire_on_inspect = False

        def inspect_sftp_sensor(self, sensor_name: str) -> DlpSftpAuditSensorInspection:
            if self.expire_on_inspect:
                epoch[0] = 700
            return super().inspect_sftp_sensor(sensor_name)

    transport = _ExpiringWorkflowTransport()
    workflow = DlpSftpAuditSensorLiveWorkflow(transport, clock=lambda: epoch[0])
    preview = workflow.preview(sensor_name=NAME, requester_digest=REQUESTER)
    if phase == "confirm":
        transport.expire_on_inspect = True
        with pytest.raises(DlpSftpAuditSensorLiveWorkflowError):
            workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    else:
        confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
        transport.expire_on_inspect = True
        with pytest.raises(DlpSftpAuditSensorLiveWorkflowError):
            workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)
    assert transport.calls == 0
