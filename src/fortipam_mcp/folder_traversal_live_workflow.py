"""Private-bound traversal ACL candidate using existing signed workflow storage."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
import logging
import secrets
from typing import Any, cast

from v4_planning import M4ExecutionPlan, canonical_digest
from .folder_live_workflow import (
    ChildFolderLiveWorkflow, ChildFolderWorkflowTransport, ChildFolderWorkflowError,
    _WorkflowRecord, _require_requester,
)
from .folder_traversal_m4_adapter import (
    ACTION_ID, ACTION_VERSION, ADAPTER_REF, FolderTraversalBinding,
    FolderTraversalM4Adapter, FolderTraversalTransport,
)

CONTRACT = "fortipam_v4_folder_traversal_candidate_v1"
_UNAVAILABLE = "The Folder traversal workflow is unavailable."


class FolderTraversalLiveWorkflow(ChildFolderLiveWorkflow):
    """Reuse durable confirmation/reservation; never promote an ordinary receipt."""
    def __init__(self, database: Path, hmac_key_path: Path, transport: FolderTraversalTransport,
                 *, binding: FolderTraversalBinding, clock: Callable[[], int] | None = None) -> None:
        self._traversal_transport = transport
        self._binding = binding
        super().__init__(database, hmac_key_path, cast(ChildFolderWorkflowTransport, transport), clock=clock)

    def _check_record_binding(self, record: _WorkflowRecord) -> None:
        b = self._binding
        if (record.name != "folder-traversal" or record.parent_folder_id != b.folder_id
            or record.current_digest != b.current_digest
            or record.expected_digest != b.expected_digest):
            raise ChildFolderWorkflowError(_UNAVAILABLE)

    def _plan(self, record: _WorkflowRecord) -> M4ExecutionPlan:
        self._check_record_binding(record)
        binding = self._binding
        digest = canonical_digest({"contract": CONTRACT, "preview": record.preview_ref,
            "requester": record.requester_digest, "parameters": binding.parameters_digest,
            "authorization": record.authorization_ref})
        values: dict[str, Any] = dict(
            plan_ref=record.preview_ref, revision=1, action_id=ACTION_ID, action_version=ACTION_VERSION,
            adapter_ref=ADAPTER_REF, target_ref="folder-traversal",
            requester_digest=record.requester_digest, summary_digest=digest,
            confirmation_digest=digest, approval_digest=digest, parameters_digest=binding.parameters_digest,
            expected_current_digest=record.current_digest, expected_state_digest=record.expected_digest,
            idempotency_digest=digest, expires_at=record.expires_at, compensation_ref=None)
        return M4ExecutionPlan(**values, plan_digest=canonical_digest(values))

    def _adapter(self, record: _WorkflowRecord) -> tuple[M4ExecutionPlan, FolderTraversalM4Adapter]:
        plan = self._plan(record)
        return plan, FolderTraversalM4Adapter(plan, self._binding, self._traversal_transport)

    def preview(self, *, folder_name: str, parent_folder_id: int, requester_digest: str) -> dict[str, object]:
        _require_requester(requester_digest)
        b = self._binding
        if folder_name != "folder-traversal" or type(parent_folder_id) is not int or parent_folder_id != b.folder_id:
            raise ChildFolderWorkflowError(_UNAVAILABLE)
        record = _WorkflowRecord("folder-preview-" + secrets.token_urlsafe(24), None,
            requester_digest, "folder-traversal", b.folder_id, b.current_digest,
            b.expected_digest, "previewed", self._clock() + 600)
        plan, adapter = self._adapter(record)
        adapter.read_current(plan)
        self._insert(record)
        return self._preview_projection(record)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        record = self._get_by_preview(preview_ref)
        self._validate_record(record, requester_digest, expected_state="previewed")
        plan, adapter = self._adapter(record)
        try:
            adapter.read_current(plan)
        except Exception:
            self._set_state(record.preview_ref, "invalidated")
            raise ChildFolderWorkflowError(_UNAVAILABLE) from None
        authorization_ref = "folder-authorized-" + secrets.token_urlsafe(24)
        self._authorize(record.preview_ref, authorization_ref)
        return {"contract": CONTRACT, "preview_ref": record.preview_ref,
            "authorization_ref": authorization_ref, "confirmation": "recorded",
            "execution": "authorized_once", "expires_at": record.expires_at,
            "device_write_executed": False}

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        record = self._get_by_authorization(authorization_ref)
        self._validate_requester(record, requester_digest)
        self._check_record_binding(record)
        if record.state == "completed":
            return self._result(record, idempotent_replay=True)
        self._validate_record(record, requester_digest, expected_state="authorized")
        if not self._reserve(record.preview_ref):
            raise ChildFolderWorkflowError(_UNAVAILABLE)
        stage = "preflight"
        try:
            plan, adapter = self._adapter(record)
            adapter.read_current(plan)
            stage = "dispatch"
            adapter.dispatch(plan)
            stage = "readback"
            if adapter.read_postcondition(plan) != record.expected_digest:
                raise ValueError
        except Exception:
            # Fixed categories only: never log exceptions, bindings or responses.
            logging.getLogger(__name__).warning(
                "Folder traversal execution requires reconciliation: stage=%s", stage
            )
            self._set_state(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        self._set_state(record.preview_ref, "completed")
        return self._result(record, idempotent_replay=False)

    def _preview_projection(self, record: _WorkflowRecord) -> dict[str, object]:
        return {"contract": CONTRACT, "preview_ref": record.preview_ref, "expires_at": record.expires_at,
            "Current State": {"bound_folder_matches": True, "owner_available": True,
                              "requested_relation_exists": False},
            "Proposed Changes": {"operation": "add_folder_traversal_permission",
                "private_binding_digest": self._binding.parameters_digest,
                "folder_permission": "view", "secret_permission": "none"},
            "Expected State": {"requested_relation_exists": True,
                "existing_relations_preserved": True, "inheritance_unchanged": True},
            "device_write_executed": False}

    def _result(self, record: _WorkflowRecord, *, idempotent_replay: bool) -> dict[str, object]:
        result = super()._result(record, idempotent_replay=idempotent_replay)
        result["contract"] = CONTRACT
        return result
