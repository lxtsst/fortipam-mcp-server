from __future__ import annotations

import pytest

from fortipam_mcp.classification_tag_assign_contract import (
    ClassificationTagAssignInspection,
    ClassificationTagAssignReadback,
)
from fortipam_mcp.classification_tag_assign_live_workflow import (
    ClassificationTagAssignLiveWorkflow,
    ClassificationTagAssignLiveWorkflowError,
    ClassificationTagAssignRollbackLiveWorkflow,
    EXECUTION_CONTRACT,
    ROLLBACK_EXECUTION_CONTRACT,
    ROLLBACK_WORKFLOW_CONTRACT,
    WORKFLOW_CONTRACT,
    WORKFLOW_UNAVAILABLE,
)


TARGET_NAME = "mcp-v4-target-update-01"
TAG_NAME = "mcp-v4-classification-tag-01"
REQUESTER = "a" * 64


def _inspection(
    state: str = "1",
    *,
    target_exists: bool = True,
    tag_exists: bool = True,
    current_is_other: bool = True,
    current_matches_tag: bool = False,
) -> ClassificationTagAssignInspection:
    return ClassificationTagAssignInspection(
        target_exists=target_exists,
        classification_tag_exists=tag_exists,
        current_class_is_other=current_is_other,
        target_non_class_state_digest="2" * 64,
        classification_tag_state_digest="3" * 64,
        state_digest=state * 64,
        current_class_matches_tag=current_matches_tag,
    )


class _Transport:
    def __init__(
        self,
        inspections: list[ClassificationTagAssignInspection],
        readback: ClassificationTagAssignReadback | Exception,
    ) -> None:
        self.inspections = inspections
        self.readback = readback
        self.inspect_calls = 0
        self.write_calls = 0
        self.restore_calls = 0

    def inspect_classification_tag_assignment(
        self,
        target_name: str,
        classification_tag_name: str,
    ) -> ClassificationTagAssignInspection:
        assert target_name == TARGET_NAME
        assert classification_tag_name == TAG_NAME
        self.inspect_calls += 1
        return self.inspections.pop(0)

    def assign_classification_tag_and_readback(
        self,
        target_name: str,
        classification_tag_name: str,
        *,
        target_non_class_state_digest: str,
        classification_tag_state_digest: str,
    ) -> ClassificationTagAssignReadback:
        assert target_name == TARGET_NAME
        assert classification_tag_name == TAG_NAME
        assert target_non_class_state_digest == "2" * 64
        assert classification_tag_state_digest == "3" * 64
        self.write_calls += 1
        if isinstance(self.readback, Exception):
            raise self.readback
        return self.readback

    def restore_default_classification_and_readback(
        self,
        target_name: str,
        classification_tag_name: str,
        *,
        target_non_class_state_digest: str,
        classification_tag_state_digest: str,
    ) -> ClassificationTagAssignReadback:
        assert target_name == TARGET_NAME
        assert classification_tag_name == TAG_NAME
        assert target_non_class_state_digest == "2" * 64
        assert classification_tag_state_digest == "3" * 64
        self.restore_calls += 1
        if isinstance(self.readback, Exception):
            raise self.readback
        return self.readback


@pytest.mark.parametrize("phase", ["confirm", "execute"])
@pytest.mark.parametrize("rollback", [False, True])
def test_expiry_during_current_state_read_refuses_authorization_and_write(
    phase: str, rollback: bool, monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [100]
    current = _inspection(current_is_other=not rollback, current_matches_tag=rollback)
    transport = _Transport(
        [current, current, current],
        ClassificationTagAssignReadback(True, True, True, True, True),
    )
    if rollback:
        workflow = ClassificationTagAssignRollbackLiveWorkflow(
            transport, target_name=TARGET_NAME, classification_tag_name=TAG_NAME,
            clock=lambda: now[0],
        )
        preview = workflow.preview(requester_digest=REQUESTER)
    else:
        workflow = ClassificationTagAssignLiveWorkflow(transport, clock=lambda: now[0])
        preview = workflow.preview(
            target_name=TARGET_NAME, classification_tag_name=TAG_NAME,
            requester_digest=REQUESTER,
        )
    reference = str(preview["preview_ref"])
    if phase == "execute":
        confirmation = workflow.confirm(reference, requester_digest=REQUESTER)
        reference = str(confirmation["authorization_ref"])
    expires_at = int(str(preview["expires_at"]))
    now[0] = expires_at - 1
    inspect = transport.inspect_classification_tag_assignment

    def expire_during_query(
        target_name: str, classification_tag_name: str,
    ) -> ClassificationTagAssignInspection:
        result = inspect(target_name, classification_tag_name)
        now[0] = expires_at
        return result

    monkeypatch.setattr(transport, "inspect_classification_tag_assignment", expire_during_query)
    with pytest.raises(ClassificationTagAssignLiveWorkflowError):
        if phase == "confirm":
            workflow.confirm(reference, requester_digest=REQUESTER)
        else:
            workflow.execute(reference, requester_digest=REQUESTER)

    assert now[0] == expires_at
    assert transport.write_calls == 0
    assert transport.restore_calls == 0


def test_assignment_workflow_renders_exact_cpe_and_executes_once() -> None:
    transport = _Transport(
        [_inspection(), _inspection(), _inspection()],
        ClassificationTagAssignReadback(True, True, True, True, True),
    )
    workflow = ClassificationTagAssignLiveWorkflow(transport, clock=lambda: 100)

    preview = workflow.preview(
        target_name=TARGET_NAME,
        classification_tag_name=TAG_NAME,
        requester_digest=REQUESTER,
    )

    assert preview["contract"] == WORKFLOW_CONTRACT
    assert preview["Current State"] == {
        "requested_target_name": TARGET_NAME,
        "target_exists": True,
        "current_classification_tag_is_default": True,
        "requested_classification_tag_name": TAG_NAME,
        "classification_tag_exists": True,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "assign_classification_tag_to_target_via_api",
        "target_name": TARGET_NAME,
        "classification_tag_name": TAG_NAME,
        "request_body": "fixed_class_only",
    }
    assert preview["Expected State"] == {
        "target_exists": True,
        "classification_tag_exists": True,
        "target_class_matches": True,
        "target_non_class_state_preserved": True,
        "classification_tag_state_preserved": True,
        "readback_transport": "rest_api",
    }
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["contract"] == EXECUTION_CONTRACT
    assert result["outcome"] == "succeeded"
    assert result["verification"] == "verified"
    assert result["idempotent_replay"] is False
    assert transport.write_calls == 1

    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert transport.write_calls == 1


@pytest.mark.parametrize(
    "target_name,tag_name",
    [
        ("other-target", TAG_NAME),
        (TARGET_NAME, "other-tag"),
        (TARGET_NAME + "!", TAG_NAME),
    ],
)
def test_assignment_workflow_rejects_nonlaboratory_names(
    target_name: str,
    tag_name: str,
) -> None:
    workflow = ClassificationTagAssignLiveWorkflow(
        _Transport([], ClassificationTagAssignReadback(True, True, True, True, True))
    )

    with pytest.raises(ClassificationTagAssignLiveWorkflowError, match=WORKFLOW_UNAVAILABLE):
        workflow.preview(
            target_name=target_name,
            classification_tag_name=tag_name,
            requester_digest=REQUESTER,
        )


@pytest.mark.parametrize(
    "inspection",
    [
        _inspection(target_exists=False),
        _inspection(tag_exists=False),
        _inspection(current_is_other=False),
    ],
)
def test_assignment_workflow_requires_exact_other_and_existing_pair(
    inspection: ClassificationTagAssignInspection,
) -> None:
    workflow = ClassificationTagAssignLiveWorkflow(
        _Transport(
            [inspection],
            ClassificationTagAssignReadback(True, True, True, True, True),
        )
    )

    with pytest.raises(ClassificationTagAssignLiveWorkflowError, match=WORKFLOW_UNAVAILABLE):
        workflow.preview(
            target_name=TARGET_NAME,
            classification_tag_name=TAG_NAME,
            requester_digest=REQUESTER,
        )


def test_assignment_workflow_rejects_drift_before_confirmation() -> None:
    transport = _Transport(
        [_inspection("1"), _inspection("4")],
        ClassificationTagAssignReadback(True, True, True, True, True),
    )
    workflow = ClassificationTagAssignLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(
        target_name=TARGET_NAME,
        classification_tag_name=TAG_NAME,
        requester_digest=REQUESTER,
    )

    with pytest.raises(ClassificationTagAssignLiveWorkflowError, match=WORKFLOW_UNAVAILABLE):
        workflow.confirm(str(preview["preview_ref"]), requester_digest=REQUESTER)

    assert transport.write_calls == 0


def test_assignment_workflow_marks_uncertain_write_nonretry() -> None:
    transport = _Transport(
        [_inspection(), _inspection(), _inspection()],
        RuntimeError("uncertain"),
    )
    workflow = ClassificationTagAssignLiveWorkflow(transport, clock=lambda: 100)
    preview = workflow.preview(
        target_name=TARGET_NAME,
        classification_tag_name=TAG_NAME,
        requester_digest=REQUESTER,
    )
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    authorization_ref = str(confirmation["authorization_ref"])

    result = workflow.execute(authorization_ref, requester_digest=REQUESTER)

    assert result["outcome"] == "reconciliation_required"
    assert transport.write_calls == 1
    with pytest.raises(ClassificationTagAssignLiveWorkflowError, match=WORKFLOW_UNAVAILABLE):
        workflow.execute(authorization_ref, requester_digest=REQUESTER)
    assert transport.write_calls == 1


def test_assignment_rollback_is_fixed_value_minimized_and_executes_once() -> None:
    transport = _Transport(
        [
            _inspection(current_is_other=False, current_matches_tag=True),
            _inspection(current_is_other=False, current_matches_tag=True),
            _inspection(current_is_other=False, current_matches_tag=True),
        ],
        ClassificationTagAssignReadback(True, True, True, True, True),
    )
    workflow = ClassificationTagAssignRollbackLiveWorkflow(
        transport,
        target_name=TARGET_NAME,
        classification_tag_name=TAG_NAME,
        clock=lambda: 100,
    )

    preview = workflow.preview(requester_digest=REQUESTER)

    assert preview["contract"] == ROLLBACK_WORKFLOW_CONTRACT
    assert preview["Current State"] == {
        "target_exists": True,
        "classification_tag_exists": True,
        "target_class_matches_protected_tag": True,
        "target_or_tag_reference_returned": False,
        "write_transport": "rest_api",
    }
    assert preview["Proposed Changes"] == {
        "operation": "restore_target_default_classification_via_api",
        "request_body": "fixed_class_only",
        "target_classification": "Other",
        "target_non_class_fields_changed": False,
        "classification_tag_changed": False,
        "secret_folder_ztna_or_session_changed": False,
    }
    assert preview["Expected State"] == {
        "pre_action_state_restored": True,
        "target_classification_is_default": True,
        "target_non_class_state_preserved": True,
        "classification_tag_state_preserved": True,
        "target_or_tag_reference_returned": False,
        "readback_transport": "rest_api",
    }
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    result = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )

    assert result["contract"] == ROLLBACK_EXECUTION_CONTRACT
    assert result["outcome"] == "succeeded"
    assert result["pre_action_state_restored"] is True
    assert result["target_classification_is_default"] is True
    assert transport.restore_calls == 1
    replay = workflow.execute(
        str(confirmation["authorization_ref"]),
        requester_digest=REQUESTER,
    )
    assert replay["idempotent_replay"] is True
    assert transport.restore_calls == 1


@pytest.mark.parametrize(
    "inspection",
    [
        _inspection(target_exists=False, current_matches_tag=True),
        _inspection(tag_exists=False, current_matches_tag=True),
        _inspection(current_is_other=True, current_matches_tag=False),
    ],
)
def test_assignment_rollback_requires_exact_assigned_pair(
    inspection: ClassificationTagAssignInspection,
) -> None:
    workflow = ClassificationTagAssignRollbackLiveWorkflow(
        _Transport(
            [inspection],
            ClassificationTagAssignReadback(True, True, True, True, True),
        ),
        target_name=TARGET_NAME,
        classification_tag_name=TAG_NAME,
    )

    with pytest.raises(ClassificationTagAssignLiveWorkflowError, match=WORKFLOW_UNAVAILABLE):
        workflow.preview(requester_digest=REQUESTER)


def test_assignment_rollback_rejects_drift_before_execution() -> None:
    transport = _Transport(
        [
            _inspection("1", current_is_other=False, current_matches_tag=True),
            _inspection("1", current_is_other=False, current_matches_tag=True),
            _inspection("4", current_is_other=False, current_matches_tag=True),
        ],
        ClassificationTagAssignReadback(True, True, True, True, True),
    )
    workflow = ClassificationTagAssignRollbackLiveWorkflow(
        transport,
        target_name=TARGET_NAME,
        classification_tag_name=TAG_NAME,
        clock=lambda: 100,
    )
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )

    with pytest.raises(ClassificationTagAssignLiveWorkflowError, match=WORKFLOW_UNAVAILABLE):
        workflow.execute(
            str(confirmation["authorization_ref"]),
            requester_digest=REQUESTER,
        )
    assert transport.restore_calls == 0


def test_assignment_rollback_marks_uncertain_write_nonretry() -> None:
    transport = _Transport(
        [
            _inspection(current_is_other=False, current_matches_tag=True),
            _inspection(current_is_other=False, current_matches_tag=True),
            _inspection(current_is_other=False, current_matches_tag=True),
        ],
        RuntimeError("uncertain"),
    )
    workflow = ClassificationTagAssignRollbackLiveWorkflow(
        transport,
        target_name=TARGET_NAME,
        classification_tag_name=TAG_NAME,
        clock=lambda: 100,
    )
    preview = workflow.preview(requester_digest=REQUESTER)
    confirmation = workflow.confirm(
        str(preview["preview_ref"]),
        requester_digest=REQUESTER,
    )
    authorization_ref = str(confirmation["authorization_ref"])

    result = workflow.execute(authorization_ref, requester_digest=REQUESTER)

    assert result["outcome"] == "reconciliation_required"
    assert transport.restore_calls == 1
    with pytest.raises(ClassificationTagAssignLiveWorkflowError, match=WORKFLOW_UNAVAILABLE):
        workflow.execute(authorization_ref, requester_digest=REQUESTER)
    assert transport.restore_calls == 1
