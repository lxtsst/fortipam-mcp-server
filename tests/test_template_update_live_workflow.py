from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import stat
import pytest

from fortipam_mcp.template_ssh_transport import (
    TEMPLATE_DEFAULT_PORT,
    TEMPLATE_UPDATED_PORT,
    TemplateUpdateBaselineReadback,
    TemplateUpdateReadback,
)
from fortipam_mcp.template_update_live_workflow import (
    TemplateUpdateLiveWorkflowError,
    TemplateWebVncPortUpdateLiveWorkflow,
)


REQUESTER = "a" * 64
TEMPLATE_NAME = "mcp-v4-template-01"


class FakeTemplateUpdateTransport:
    def __init__(self) -> None:
        self.baseline = TemplateUpdateBaselineReadback(
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            configuration_digest="a" * 64,
        )
        self.updated = TemplateUpdateReadback(
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            True,
            configuration_digest="a" * 64,
        )
        self.update_calls: list[str] = []

    def update_baseline_readback(
        self,
        template_name: str,
    ) -> TemplateUpdateBaselineReadback:
        assert template_name == TEMPLATE_NAME
        return self.baseline

    def update_web_vnc_port_and_readback(
        self,
        template_name: str,
    ) -> TemplateUpdateReadback:
        assert template_name == TEMPLATE_NAME
        self.update_calls.append(template_name)
        return self.updated


def _preview(workflow: TemplateWebVncPortUpdateLiveWorkflow) -> dict[str, object]:
    return workflow.preview(template_name=TEMPLATE_NAME, requester_digest=REQUESTER)


def test_preview_is_live_cpe_and_limits_the_change_to_web_vnc_port() -> None:
    workflow = TemplateWebVncPortUpdateLiveWorkflow(
        FakeTemplateUpdateTransport(),
        clock=lambda: 100,
    )

    preview = _preview(workflow)

    assert preview["Current State"] == {
        "requested_template_name": TEMPLATE_NAME,
        "template_name_exists": True,
        "known_web_vnc_create_baseline_verified": True,
        "web_vnc_launcher_port": TEMPLATE_DEFAULT_PORT,
        "write_transport": "ssh_cli_fallback",
    }
    assert preview["Proposed Changes"]["template_name"] == TEMPLATE_NAME
    assert preview["Proposed Changes"]["web_vnc_launcher_port"] == {
        "from": TEMPLATE_DEFAULT_PORT,
        "to": TEMPLATE_UPDATED_PORT,
    }
    assert preview["Proposed Changes"]["template_field_or_access_changes"] is False
    assert preview["Expected State"]["template_name_matches"] is True
    assert preview["Expected State"]["web_vnc_launcher_port"] == TEMPLATE_UPDATED_PORT
    assert preview["device_write_executed"] is False


def _claim(tmp_path: Path) -> Path:
    tmp_path.chmod(0o700)
    return tmp_path / "update.claim.json"


def test_execute_requires_one_confirmation_and_performs_one_update(tmp_path: Path) -> None:
    transport = FakeTemplateUpdateTransport()
    claim = _claim(tmp_path)
    workflow = TemplateWebVncPortUpdateLiveWorkflow(transport, clock=lambda: 100, claim_path=claim)
    preview = _preview(workflow)

    with pytest.raises(TemplateUpdateLiveWorkflowError):
        workflow.execute("template-update-authorized-missing", requester_digest=REQUESTER)

    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert transport.update_calls == [TEMPLATE_NAME]
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["template_field_or_access_changes"] is False

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert len(transport.update_calls) == 1
    assert stat.S_IMODE(claim.stat().st_mode) == 0o600
    value = json.loads(claim.read_text())
    assert value["state"] == "execution_reserved"
    assert TEMPLATE_NAME not in claim.read_text()
    assert value["requester_digest"] == REQUESTER


def test_confirm_invalidates_when_known_baseline_drifts() -> None:
    transport = FakeTemplateUpdateTransport()
    workflow = TemplateWebVncPortUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    transport.baseline = TemplateUpdateBaselineReadback(
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
    )

    with pytest.raises(TemplateUpdateLiveWorkflowError):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.update_calls == []


@pytest.mark.parametrize("phase", ("confirm", "execute"))
def test_complete_configuration_drift_invalidates_before_write(phase: str, tmp_path: Path) -> None:
    transport = FakeTemplateUpdateTransport()
    workflow = TemplateWebVncPortUpdateLiveWorkflow(transport, clock=lambda: 100, claim_path=_claim(tmp_path))
    preview = _preview(workflow)
    ref = str(preview["preview_ref"])
    if phase == "execute":
        ref = str(workflow.confirm(ref, requester_digest=REQUESTER)["authorization_ref"])
    transport.baseline = replace(transport.baseline, configuration_digest="b" * 64)

    with pytest.raises(TemplateUpdateLiveWorkflowError):
        getattr(workflow, phase)(ref, requester_digest=REQUESTER)

    assert transport.update_calls == []


def test_post_write_non_port_drift_requires_reconciliation(tmp_path: Path) -> None:
    transport = FakeTemplateUpdateTransport()
    workflow = TemplateWebVncPortUpdateLiveWorkflow(transport, clock=lambda: 100, claim_path=_claim(tmp_path))
    preview = _preview(workflow)
    ref = str(workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)["authorization_ref"])
    transport.updated = replace(transport.updated, configuration_digest="b" * 64)

    result = workflow.execute(ref, requester_digest=REQUESTER)

    assert result["outcome"] == "reconciliation_required"
    assert transport.update_calls == [TEMPLATE_NAME]


def test_invalid_post_write_readback_requires_reconciliation(tmp_path: Path) -> None:
    transport = FakeTemplateUpdateTransport()
    transport.updated = TemplateUpdateReadback(
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
    )
    workflow = TemplateWebVncPortUpdateLiveWorkflow(transport, clock=lambda: 100, claim_path=_claim(tmp_path))
    preview = _preview(workflow)
    confirmation = workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["outcome"] == "reconciliation_required"
    assert result["verification"] == "unknown"
    with pytest.raises(TemplateUpdateLiveWorkflowError):
        workflow.execute(str(confirmation["authorization_ref"]), requester_digest=REQUESTER)


def test_consumed_claim_blocks_fresh_process_before_baseline_read(tmp_path: Path) -> None:
    claim = _claim(tmp_path)
    transport = FakeTemplateUpdateTransport()
    workflow = TemplateWebVncPortUpdateLiveWorkflow(transport, clock=lambda: 100, claim_path=claim)
    preview = _preview(workflow)
    ref = str(workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)["authorization_ref"])
    workflow.execute(ref, requester_digest=REQUESTER)

    class UnreachableTransport(FakeTemplateUpdateTransport):
        def update_baseline_readback(self, template_name: str) -> TemplateUpdateBaselineReadback:
            pytest.fail("consumed claim must reject before device reads")

    fresh = TemplateWebVncPortUpdateLiveWorkflow(UnreachableTransport(), claim_path=claim)
    with pytest.raises(TemplateUpdateLiveWorkflowError):
        _preview(fresh)
    assert transport.update_calls == [TEMPLATE_NAME]


def test_missing_claim_prevents_dispatch() -> None:
    transport = FakeTemplateUpdateTransport()
    workflow = TemplateWebVncPortUpdateLiveWorkflow(transport, clock=lambda: 100)
    preview = _preview(workflow)
    ref = str(workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)["authorization_ref"])

    with pytest.raises(TemplateUpdateLiveWorkflowError):
        workflow.execute(ref, requester_digest=REQUESTER)
    assert transport.update_calls == []


def test_claim_is_synced_before_adapter_and_preserved_after_uncertain_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fortipam_mcp.template_update_live_workflow as module
    claim = _claim(tmp_path)
    fsync_calls: list[int] = []
    actual_fsync = module.os.fsync

    def fsync(fd: int) -> None:
        fsync_calls.append(fd)
        actual_fsync(fd)

    monkeypatch.setattr(module.os, "fsync", fsync)

    class FailingTransport(FakeTemplateUpdateTransport):
        def update_web_vnc_port_and_readback(self, template_name: str) -> TemplateUpdateReadback:
            assert claim.is_file() and len(fsync_calls) == 2
            self.update_calls.append(template_name)
            raise RuntimeError("unqualified acknowledgement")

    transport = FailingTransport()
    workflow = TemplateWebVncPortUpdateLiveWorkflow(transport, clock=lambda: 100, claim_path=claim)
    preview = _preview(workflow)
    ref = str(workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)["authorization_ref"])
    result = workflow.execute(ref, requester_digest=REQUESTER)

    assert result["outcome"] == "reconciliation_required"
    consumed = claim.read_bytes()
    with pytest.raises(TemplateUpdateLiveWorkflowError):
        workflow.execute(ref, requester_digest=REQUESTER)
    assert claim.read_bytes() == consumed
    assert transport.update_calls == [TEMPLATE_NAME]


def test_claim_parent_must_be_private_and_cannot_be_a_symlink(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(private, target_is_directory=True)
    tmp_path.chmod(0o755)
    for parent in (tmp_path, alias):
        with pytest.raises(TemplateUpdateLiveWorkflowError):
            TemplateWebVncPortUpdateLiveWorkflow(FakeTemplateUpdateTransport(), claim_path=parent / "claim")


def test_preview_rejects_out_of_scope_input_and_non_string_requester() -> None:
    workflow = TemplateWebVncPortUpdateLiveWorkflow(FakeTemplateUpdateTransport())

    with pytest.raises(TemplateUpdateLiveWorkflowError):
        workflow.preview(template_name="Web VNC Template", requester_digest=REQUESTER)
    with pytest.raises(TemplateUpdateLiveWorkflowError):
        workflow.preview(template_name=TEMPLATE_NAME, requester_digest=object())  # type: ignore[arg-type]
