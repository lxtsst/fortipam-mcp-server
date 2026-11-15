from pathlib import Path

import pytest

from fortipam_mcp.target_contract import WebTargetCreateInput, WebTargetReadback
from fortipam_mcp.web_target_live_workflow import WebTargetLiveWorkflow, WebTargetWorkflowError


class Transport:
    def __init__(self):
        self.digest = "a" * 64
        self.reads = 0
        self.writes = 0
        self.result = WebTargetReadback(True, True, True, True)
        self.error = False
        self.consumed = False

    def inspect_web_target_create(self, request, *, claim_path):
        self.reads += 1
        if self.consumed:
            raise RuntimeError("private transport failure")
        return self.digest

    def create_web_target_and_readback(self, request, *, claim_path, expected_state_digest, expires_at):
        assert expected_state_digest == self.digest and expires_at == 1600
        self.writes += 1
        self.consumed = True
        if self.error:
            raise RuntimeError("private selector and native response")
        return self.result


def build(tmp_path, *, enabled=False):
    transport = Transport()
    now = [1000]
    binding = WebTargetCreateInput("mcp-v4-target-web-20261003-r1", "https://app.example.test")
    workflow = WebTargetLiveWorkflow(transport, binding, tmp_path / "claim.json",
        execution_enabled=enabled, clock=lambda: now[0])
    return workflow, transport, now, binding


def authorize(workflow):
    preview = workflow.preview(requester_digest="1" * 64)
    auth = workflow.confirm(preview["preview_ref"], requester_digest="1" * 64)
    return preview, auth["authorization_ref"]


def test_private_bound_cpe_and_default_gate(tmp_path: Path) -> None:
    workflow, transport, _, binding = build(tmp_path)
    preview, auth = authorize(workflow)
    assert preview["execution_gate_enabled"] is False
    assert binding.target_name not in str(preview) and binding.web_url not in str(preview)
    assert transport.digest not in str(preview)
    with pytest.raises(WebTargetWorkflowError):
        workflow.execute(auth, requester_digest="1" * 64)
    assert transport.writes == 0


@pytest.mark.parametrize("failure", [None, "readback", "exception"])
def test_one_transport_invocation_and_cached_categorical_result(tmp_path: Path, failure) -> None:
    workflow, transport, now, _ = build(tmp_path, enabled=True)
    _, auth = authorize(workflow)
    if failure == "readback":
        transport.result = WebTargetReadback(True, True, False, True)
    transport.error = failure == "exception"
    result = workflow.execute(auth, requester_digest="1" * 64)
    assert result["verified"] is (failure is None)
    assert result["cached_result"] is False
    assert "private" not in str(result)
    now[0] = 2000
    cached = workflow.execute(auth, requester_digest="1" * 64)
    assert cached["cached_result"] is True and cached["state"] == result["state"]
    assert transport.writes == 1
    with pytest.raises(WebTargetWorkflowError):
        workflow.execute(auth, requester_digest="2" * 64)
    restarted = WebTargetLiveWorkflow(transport, workflow._request, workflow._claim_path, execution_enabled=True)
    with pytest.raises(WebTargetWorkflowError):
        restarted.execute(auth, requester_digest="1" * 64)
    with pytest.raises(WebTargetWorkflowError):
        restarted.preview(requester_digest="1" * 64)
    assert transport.writes == 1


@pytest.mark.parametrize("stage", ["confirm", "execute"])
@pytest.mark.parametrize("reason", ["drift", "expiry", "other_requester"])
def test_changed_or_expired_or_cross_requester_intent_cannot_dispatch(tmp_path, stage, reason) -> None:
    workflow, transport, now, _ = build(tmp_path, enabled=True)
    preview = workflow.preview(requester_digest="1" * 64)
    ref = preview["preview_ref"]
    if stage == "execute":
        ref = workflow.confirm(ref, requester_digest="1" * 64)["authorization_ref"]
    if reason == "drift":
        transport.digest = "b" * 64
    if reason == "expiry":
        now[0] = 1600
    with pytest.raises(WebTargetWorkflowError):
        getattr(workflow, stage)(ref, requester_digest=("2" if reason == "other_requester" else "1") * 64)
    assert transport.writes == 0


def test_repeated_confirm_does_not_extend_or_replace_intent(tmp_path) -> None:
    workflow, transport, now, _ = build(tmp_path, enabled=True)
    preview, auth = authorize(workflow)
    now[0] = 1500
    with pytest.raises(WebTargetWorkflowError):
        workflow.confirm(preview["preview_ref"], requester_digest="1" * 64)
    assert workflow.execute(auth, requester_digest="1" * 64)["verified"]
    assert transport.writes == 1


@pytest.mark.parametrize("defect", [None, "public_file", "symlink", "extra_key", "public_claim_parent", "relative", "same_file", "wrong_contract"])
def test_web_binding_factory_protects_fixed_selector_file(tmp_path, defect) -> None:
    import json
    from fortipam_mcp.web_target_live_workflow import build_web_target_workflow
    tmp_path.chmod(0o700)
    path = tmp_path / "binding.json"
    data = {"contract": "fortipam_700_web_target_binding_v1", "target_name": "mcp-v4-target-web-20261003-r1",
            "web_url": "https://app.example.test"}
    if defect == "extra_key": data["password"] = "synthetic-forbidden"
    if defect == "wrong_contract": data["contract"] = "unknown"
    path.write_text(json.dumps(data)); path.chmod(0o600)
    if defect == "public_file": path.chmod(0o644)
    if defect == "symlink":
        link = tmp_path / "link"; link.symlink_to(path); path = link
    if defect == "public_claim_parent": tmp_path.chmod(0o755)
    env = {"FORTIPAM_MCP_V4_WEB_TARGET_ENABLED": "true",
           "FORTIPAM_MCP_V4_WEB_TARGET_BINDING_FILE": "relative.json" if defect == "relative" else str(path),
           "FORTIPAM_MCP_V4_WEB_TARGET_CLAIM_FILE": str(path if defect == "same_file" else tmp_path / "claim.json")}
    transport = Transport()
    if defect:
        with pytest.raises(WebTargetWorkflowError): build_web_target_workflow(env, transport)
    else:
        workflow = build_web_target_workflow(env, transport)
        assert workflow is not None
        assert workflow.preview(requester_digest="a" * 64)["execution_gate_enabled"] is False
    assert transport.writes == 0


def test_web_factory_requires_exact_independent_flags() -> None:
    from fortipam_mcp.web_target_live_workflow import build_web_target_workflow
    assert build_web_target_workflow({}, Transport()) is None
    for env in ({"FORTIPAM_MCP_V4_WEB_TARGET_ENABLED": "TRUE"},
                {"FORTIPAM_MCP_V4_WEB_TARGET_EXECUTION_ENABLED": "true"},
                {"FORTIPAM_MCP_V4_WEB_TARGET_EXECUTION_ENABLED": "yes"}):
        with pytest.raises(WebTargetWorkflowError): build_web_target_workflow(env, Transport())
