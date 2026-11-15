"""Synthetic dependency models test gating; they do not qualify native sources."""

from __future__ import annotations

from collections.abc import Callable
import asyncio
from dataclasses import replace
from typing import Any

import pytest
from mcp import Client

from fortipam_mcp.dlp_sensor_delete_http_transport import DlpSensorDeleteHttpTransportConfig
from fortipam_mcp.dlp_sensor_mcp_action import (
    DLP_PROFILE_SFTP_AUDIT, ProtectedDlpSensorMcpAction, V4DlpSensorActionRuntimeError,
)
from fortipam_mcp.dlp_sftp_audit_sensor_delete_live_workflow import (
    DlpSftpAuditSensorDeleteLiveWorkflow, DlpSftpAuditSensorDeleteLiveWorkflowError,
)
from fortipam_mcp.dlp_sftp_audit_sensor_http_transport import (
    DlpSftpAuditSensorDeleteReadback, DlpSftpAuditSensorHttpTransportError,
    FortiPamDlpSftpAuditSensorHttpTransport,
    _recovery_inspection_digest,
)
from fortipam_mcp.secret_dlp_dependency_ssh_reader import DlpDependencyInspection
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.server import FortiPamMcpServer
from test_dlp_sftp_audit_sensor import (
    NAME, REQUESTER, SERIAL, _Client, _Response, _Ssh, _absent, _ack, _envelope, _native_profile,
    _change_actor_role,
)
from test_v4_m3 import _requester
from test_dlp_api_actor_guard import Harness as _ActorHarness


class _Dependencies:
    """A synthetic trusted-reader output, never a production source qualifier."""

    def __init__(self) -> None:
        self.observation = DlpDependencyInspection(NAME, SERIAL, "v7.0.0", 29, 64, 5, 0, 0, "d" * 64)
        self.error: Exception | None = None
        self.on_inspect: Callable[[], None] | None = None

    def inspect(self, sensor_name: str) -> DlpDependencyInspection:
        assert sensor_name == NAME
        if self.error is not None:
            raise self.error
        if self.on_inspect is not None:
            self.on_inspect()
        return self.observation


class _DeleteAwareClient(_Client):
    def __init__(self, ssh: _Ssh) -> None:
        super().__init__()
        self.ssh = ssh

    def stream(self, method: str, url: str, **kwargs: Any) -> _Response:
        response = super().stream(method, url, **kwargs)
        if method == "DELETE":
            self.ssh.exists = False
        return response


def _bound(
    client: _Client, ssh: _Ssh, observer: _Dependencies | None,
    *, actor_harness: _ActorHarness | None = None,
) -> FortiPamDlpSftpAuditSensorHttpTransport:
    actor = actor_harness or _ActorHarness()
    return FortiPamDlpSftpAuditSensorHttpTransport(
        actor.config,
        ssh, sensor_name=NAME, expected_serial=SERIAL, client_factory=client,
        dependency_observer=observer, actor_guard=actor.guard,
    )


def _created(
    observer: _Dependencies | None,
    *, actor_harness: _ActorHarness | None = None,
) -> tuple[FortiPamDlpSftpAuditSensorHttpTransport, _DeleteAwareClient, _Ssh]:
    ssh = _Ssh()
    client = _DeleteAwareClient(ssh)
    client.responses = [_absent(), _absent(), _Response(200, _ack()), _profile_response()]
    transport = _bound(client, ssh, observer, actor_harness=actor_harness)
    transport.inspect_sftp_sensor(NAME)
    assert transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100).verified
    ssh.exists = True
    return transport, client, ssh


def _profile_response() -> _Response:
    return _Response(200, _envelope("GET", 200, _native_profile()))


def _delete_ack() -> _Response:
    ack = _ack()
    ack["http_method"] = "DELETE"
    return _Response(200, ack)


def _delete(
    transport: FortiPamDlpSftpAuditSensorHttpTransport, *, state_digest: str, target_digest: str,
    clock: Callable[[], int] = lambda: 100,
) -> DlpSftpAuditSensorDeleteReadback:
    return transport.delete_owned_sftp_and_readback(
        expected_target_digest=target_digest, expected_state_digest=state_digest,
        expires_at=700, clock=clock,
    )


def test_unknown_uncertain_or_new_creator_never_acquires_delete_ownership() -> None:
    client = _Client()
    ssh = _Ssh()
    transport = _bound(client, ssh, _Dependencies())
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.inspect_owned_sftp_delete_target()
    assert not client.calls
    client.responses = [_absent(), _absent(), TimeoutError("private response")]
    transport.inspect_sftp_sensor(NAME)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.inspect_owned_sftp_delete_target()
    assert [call[0] for call in client.calls] == ["GET", "GET", "POST"]
    owned, _, _ = _created(_Dependencies())
    assert owned._ownership is not None
    fresh_client = _Client()
    fresh = _bound(fresh_client, _Ssh(), _Dependencies())
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        fresh.inspect_owned_sftp_delete_target()
    assert not fresh_client.calls


def test_failed_full_native_readback_never_acquires_ownership() -> None:
    client = _Client()
    ssh = _Ssh()
    transport = _bound(client, ssh, _Dependencies())
    profile = _native_profile()
    profile["filter"][0]["action"] = "block"
    client.responses = [_absent(), _absent(), _Response(200, _ack()),
                        _Response(200, _envelope("GET", 200, profile))]
    transport.inspect_sftp_sensor(NAME)
    assert not transport.create_sftp_and_readback(NAME, expires_at=700, clock=lambda: 100).verified
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.inspect_owned_sftp_delete_target()
    assert len(client.calls) == 4


def test_missing_or_unqualified_dependency_observer_blocks_recovery() -> None:
    transport, client, _ = _created(None)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.inspect_owned_sftp_delete_target()
    assert len(client.calls) == 4
    observer = _Dependencies()
    observer.error = ValueError("unqualified 64 native / 59 REST source")
    transport, client, _ = _created(observer)
    client.responses = [_profile_response()]
    with pytest.raises(DlpSftpAuditSensorHttpTransportError, match="unavailable") as failure:
        transport.inspect_owned_sftp_delete_target()
    assert "64 native" not in str(failure.value)
    assert not any(call[0] == "DELETE" for call in client.calls)


@pytest.mark.parametrize("field,value", [
    ("device_serial", "OTHER"), ("sensor_name", "other"), ("build", 30),
    ("secret_reference_count", True), ("policy_reference_count", -1),
    ("secret_object_count", -1), ("evidence_digest", "unknown"),
])
def test_dependency_binding_and_typed_evidence_are_mandatory(field: str, value: Any) -> None:
    observer = _Dependencies()
    observer.observation = replace(observer.observation, **{field: value})
    transport, client, _ = _created(observer)
    client.responses = [_profile_response()]
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.inspect_owned_sftp_delete_target()
    assert not any(call[0] == "DELETE" for call in client.calls)


def test_native_digest_drift_and_new_reference_block_delete() -> None:
    observer = _Dependencies()
    transport, client, _ = _created(observer)
    profile = _native_profile()
    profile["filter"][0]["file-size"] = 10
    client.responses = [_Response(200, _envelope("GET", 200, profile))]
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.inspect_owned_sftp_delete_target()
    client.responses = [_profile_response(), _profile_response()]
    before = transport.inspect_owned_sftp_delete_target()
    observer.observation = replace(observer.observation, secret_reference_count=1)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _delete(transport, state_digest=_recovery_inspection_digest(before), target_digest=before.target_digest)
    assert not any(call[0] == "DELETE" for call in client.calls)


def test_one_delete_and_independent_absence_clear_ownership() -> None:
    transport, client, _ = _created(_Dependencies())
    client.responses = [_profile_response(), _profile_response(), _delete_ack(), _absent()]
    current = transport.inspect_owned_sftp_delete_target()
    result = _delete(transport, state_digest=_recovery_inspection_digest(current), target_digest=current.target_digest)
    assert result.verified
    assert transport._ownership is None
    assert [call[0] for call in client.calls].count("DELETE") == 1
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _delete(transport, state_digest=_recovery_inspection_digest(current), target_digest=current.target_digest)
    assert [call[0] for call in client.calls].count("DELETE") == 1


def test_uncertain_delete_is_consumed_without_repreview_or_retry() -> None:
    transport, client, _ = _created(_Dependencies())
    client.responses = [_profile_response(), _profile_response(), TimeoutError("private response")]
    current = transport.inspect_owned_sftp_delete_target()
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _delete(transport, state_digest=_recovery_inspection_digest(current), target_digest=current.target_digest)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.inspect_owned_sftp_delete_target()
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _delete(transport, state_digest=_recovery_inspection_digest(current), target_digest=current.target_digest)
    assert [call[0] for call in client.calls].count("DELETE") == 1


def test_expiry_after_final_dependency_read_means_zero_delete() -> None:
    observer = _Dependencies()
    transport, client, _ = _created(observer)
    client.responses = [_profile_response(), _profile_response()]
    current = transport.inspect_owned_sftp_delete_target()
    epoch = [100]
    observer.on_inspect = lambda: epoch.__setitem__(0, 700)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _delete(transport, state_digest=_recovery_inspection_digest(current),
                target_digest=current.target_digest, clock=lambda: epoch[0])
    assert not any(call[0] == "DELETE" for call in client.calls)


def test_recovery_fresh_actor_drift_refuses_before_target_read() -> None:
    actor = _ActorHarness()
    transport, client, _ = _created(_Dependencies(), actor_harness=actor)
    _change_actor_role(actor)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.inspect_owned_sftp_delete_target()
    assert len(client.calls) == 4
    actor.disposed()


def test_recovery_final_actor_drift_means_zero_delete() -> None:
    actor = _ActorHarness()
    transport, client, _ = _created(_Dependencies(), actor_harness=actor)
    client.responses = [_profile_response(), _profile_response()]
    current = transport.inspect_owned_sftp_delete_target()
    observer = transport._dependency_observer
    assert isinstance(observer, _Dependencies)
    observer.on_inspect = lambda: _change_actor_role(actor)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _delete(transport, state_digest=_recovery_inspection_digest(current), target_digest=current.target_digest)
    assert not any(call[0] == "DELETE" for call in client.calls)
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        transport.inspect_owned_sftp_delete_target()
    actor.disposed()


def test_recovery_guard_crossing_ttl_means_zero_delete() -> None:
    actor = _ActorHarness()
    transport, client, _ = _created(_Dependencies(), actor_harness=actor)
    client.responses = [_profile_response(), _profile_response()]
    current = transport.inspect_owned_sftp_delete_target()
    epoch = [100]
    calls_before_final = len(actor.calls)
    original_factory = actor.guard._factory

    def expiring_factory(*args: Any, **kwargs: Any) -> Any:
        if len(actor.calls) == calls_before_final + 3:
            epoch[0] = 700
        return original_factory(*args, **kwargs)

    actor.guard._factory = expiring_factory
    with pytest.raises(DlpSftpAuditSensorHttpTransportError):
        _delete(transport, state_digest=_recovery_inspection_digest(current),
                target_digest=current.target_digest, clock=lambda: epoch[0])
    assert not any(call[0] == "DELETE" for call in client.calls)
    actor.disposed()


def test_injected_mcp_delete_profile_keeps_distinct_refs_and_one_dispatch() -> None:
    transport, client, _ = _created(_Dependencies())
    client.responses = [_profile_response() for _ in range(4)]
    client.responses.extend([_delete_ack(), _absent()])
    workflow = DlpSftpAuditSensorDeleteLiveWorkflow(transport, clock=lambda: 100)
    action = ProtectedDlpSensorMcpAction(object(), sftp_delete_workflow=workflow,
                                        delete_execution_enabled=True)
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    preview = action.preview_delete(principal, DLP_PROFILE_SFTP_AUDIT)
    assert str(preview["preview_ref"]).startswith("dlp-sftp-audit-sensor-delete-preview-")
    assert "mcp-v4-dlp-sftp-audit" not in repr(preview)
    confirmation = action.confirm_delete(str(preview["preview_ref"]), principal)
    result = action.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert result["outcome"] == "succeeded"
    assert result["contract"] == "fortipam_v4_dlp_sftp_audit_sensor_delete_execution_v1"
    assert action.execute_delete(str(confirmation["authorization_ref"]), principal)["idempotent_replay"] is True
    assert [call[0] for call in client.calls].count("DELETE") == 1


def test_missing_mcp_binding_closed_delete_gate_and_wrong_requester_deny() -> None:
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    action = ProtectedDlpSensorMcpAction(object())
    with pytest.raises(V4DlpSensorActionRuntimeError):
        action.preview_delete(principal, DLP_PROFILE_SFTP_AUDIT)
    transport, client, _ = _created(_Dependencies())
    client.responses = [_profile_response(), _profile_response()]
    workflow = DlpSftpAuditSensorDeleteLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(requester_digest=REQUESTER)
    with pytest.raises(DlpSftpAuditSensorDeleteLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest="e" * 64)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    action = ProtectedDlpSensorMcpAction(object(), sftp_delete_workflow=workflow)
    with pytest.raises(V4DlpSensorActionRuntimeError):
        action.execute_delete(str(confirmation["authorization_ref"]), principal)
    assert not any(call[0] == "DELETE" for call in client.calls)


def test_existing_mcp_delete_family_forwards_only_explicit_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, http_client, _ = _created(_Dependencies())
    http_client.responses = [_profile_response() for _ in range(4)]
    http_client.responses.extend([_delete_ack(), _absent()])
    action = ProtectedDlpSensorMcpAction(
        object(), sftp_delete_workflow=DlpSftpAuditSensorDeleteLiveWorkflow(transport, clock=lambda: 100),
        delete_execution_enabled=True,
    )
    principal = V4PlanningPrincipal(_requester(), "a" * 64)
    server = FortiPamMcpServer(
        runtime_profile=RuntimeProfile.V4_CONTROLLED, v4_folder_action=object(),
        v4_folder_action_enabled=True, v4_dlp_sensor_action=action,
        v4_dlp_sensor_action_enabled=True, v4_http_oauth=True,
    )
    monkeypatch.setattr(server, "_v4_planning_principal", lambda: principal)
    monkeypatch.setattr(server, "_v4_dlp_sensor_action_principal", lambda: principal)

    async def exercise() -> dict[str, Any]:
        async with Client(server.mcp) as client:
            tools = await client.list_tools()
            assert not any("sftp_audit_sensor" in tool.name for tool in tools.tools)
            preview = await client.call_tool(
                "preview_v4_dlp_sensor_delete", {"configuration_profile": DLP_PROFILE_SFTP_AUDIT},
            )
            assert preview.structured_content is not None
            confirmation = await client.call_tool(
                "confirm_v4_dlp_sensor_delete", {"preview_ref": preview.structured_content["preview_ref"]},
            )
            assert confirmation.structured_content is not None
            result = await client.call_tool(
                "execute_confirmed_v4_dlp_sensor_delete",
                {"authorization_ref": confirmation.structured_content["authorization_ref"]},
            )
            assert result.structured_content is not None
            return dict(result.structured_content)

    assert asyncio.run(exercise())["outcome"] == "succeeded"
    assert [call[0] for call in http_client.calls].count("DELETE") == 1
