"""Private-bound isolated Folder candidate using existing signed workflow storage.

The ordinary inherited-child MCP builder never constructs this class. A host
must separately bind the owner decision and enforce its operation scope/Gate.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace
import hashlib
import hmac
import json
from pathlib import Path
import logging
import os
import re
import secrets
import sqlite3
import stat
from typing import Any, cast

from v4_planning import M4ExecutionPlan, canonical_digest
from .folder_live_workflow import (
    ChildFolderLiveWorkflow, ChildFolderWorkflowTransport, ChildFolderWorkflowError,
    _WorkflowRecord, _record_from_row, _require_requester, _valid_ref,
)
from .isolated_folder_m4_adapter import (
    ACTION_ID, ACTION_VERSION, ADAPTER_REF, IsolatedFolderBinding,
    IsolatedFolderM4Adapter, IsolatedFolderTransport,
)
from .isolated_folder_creation_ownership import IsolatedFolderCreationOwnership

CONTRACT = "fortipam_v4_isolated_child_folder_candidate_v1"
RDP_POLICY_CONTRACT = "fortipam_v4_initial_rdp_policy_folder_candidate_v1"
_UNAVAILABLE = "The isolated Folder workflow is unavailable."


class IsolatedFolderLiveWorkflow(ChildFolderLiveWorkflow):
    """Reuse durable confirmation/reservation; never promote an ordinary receipt."""
    def __init__(self, database: Path, hmac_key_path: Path, transport: IsolatedFolderTransport,
                 *, binding: IsolatedFolderBinding, clock: Callable[[], int] | None = None,
                 ownership_expected_serial: str | None = None) -> None:
        if binding.initial_rdp_policy is not None and ownership_expected_serial is None:
            raise ChildFolderWorkflowError(_UNAVAILABLE)
        if ownership_expected_serial is not None and (
            type(ownership_expected_serial) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", ownership_expected_serial) is None
            or not callable(getattr(transport, "read_created_folder_snapshot", None))
            or not callable(getattr(transport, "read_creation_device_serial", None))
        ):
            raise ChildFolderWorkflowError(_UNAVAILABLE)
        self._ownership_serial = ownership_expected_serial
        if ownership_expected_serial is not None:
            self._prepare_private_database(database)
        self._isolated_transport = transport
        self._binding = binding
        super().__init__(database, hmac_key_path, cast(ChildFolderWorkflowTransport, transport), clock=clock)
        if ownership_expected_serial is not None:
            with self._connect() as connection:
                connection.execute("CREATE TABLE IF NOT EXISTS v4_isolated_folder_creation_ownership "
                                   "(preview_ref TEXT PRIMARY KEY, payload TEXT NOT NULL, receipt_mac TEXT NOT NULL)")

    def _check_record_binding(self, record: _WorkflowRecord) -> None:
        b = self._binding
        if (record.name != b.name or record.parent_folder_id != b.parent_folder_id
            or record.current_digest != b.state_digest(exists=False)
            or record.expected_digest != b.state_digest(exists=True)):
            raise ChildFolderWorkflowError(_UNAVAILABLE)

    def _plan(self, record: _WorkflowRecord) -> M4ExecutionPlan:
        self._check_record_binding(record)
        binding = self._binding
        digest = canonical_digest({"contract": self._contract, "preview": record.preview_ref,
            "requester": record.requester_digest, "parameters": binding.parameters_digest,
            "authorization": record.authorization_ref})
        values: dict[str, Any] = dict(
            plan_ref=record.preview_ref, revision=1, action_id=ACTION_ID, action_version=binding.action_version,
            adapter_ref=binding.adapter_ref, target_ref="isolated-child-folder",
            requester_digest=record.requester_digest, summary_digest=digest,
            confirmation_digest=digest, approval_digest=digest, parameters_digest=binding.parameters_digest,
            expected_current_digest=record.current_digest, expected_state_digest=record.expected_digest,
            idempotency_digest=digest, expires_at=record.expires_at, compensation_ref=None)
        return M4ExecutionPlan(**values, plan_digest=canonical_digest(values))

    def _adapter(self, record: _WorkflowRecord) -> tuple[M4ExecutionPlan, IsolatedFolderM4Adapter]:
        plan = self._plan(record)
        return plan, IsolatedFolderM4Adapter(
            plan, self._binding, self._isolated_transport, clock=self._clock,
            expected_serial=self._ownership_serial,
        )

    def preview(self, *, folder_name: str, parent_folder_id: int, requester_digest: str) -> dict[str, object]:
        _require_requester(requester_digest)
        b = self._binding
        if folder_name != b.name or type(parent_folder_id) is not int or parent_folder_id != b.parent_folder_id:
            raise ChildFolderWorkflowError(_UNAVAILABLE)
        record = _WorkflowRecord("folder-preview-" + secrets.token_urlsafe(24), None,
            requester_digest, b.name, b.parent_folder_id, b.state_digest(exists=False),
            b.state_digest(exists=True), "previewed", self._clock() + 600)
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
            self._validate_record(record, requester_digest, expected_state="previewed")
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
            if self._ownership_serial is not None:
                stage = "ownership_snapshot"
                from .isolated_folder_creation_ownership import (
                    CONTRACT as OWNERSHIP_CONTRACT, RDP_POLICY_CONTRACT as RDP_OWNERSHIP_CONTRACT,
                    IsolatedFolderCreationOwnership,
                    _digest, validate_creation_snapshot,
                )
                folder_id = adapter.verified_created_id
                snapshot_reader = getattr(self._isolated_transport, "read_created_folder_snapshot")
                snapshot = snapshot_reader(
                    folder_id, name=self._binding.name, parent_folder_id=self._binding.parent_folder_id,
                    owner_name=self._binding.owner_name,
                )
                baseline = validate_creation_snapshot(snapshot, expected_serial=self._ownership_serial,
                                                       folder_id=folder_id, binding=self._binding)
                completed = replace(record, state="completed")
                ownership = IsolatedFolderCreationOwnership(
                    OWNERSHIP_CONTRACT if self._binding.initial_rdp_policy is None else RDP_OWNERSHIP_CONTRACT,
                    record.preview_ref, str(record.authorization_ref), record.requester_digest,
                    self._binding.parameters_digest, self._mac(completed), folder_id, self._ownership_serial,
                    baseline, _digest(json.loads(baseline)),
                )
                stage = "ownership_commit"
                self._complete_with_ownership(record, ownership)
            else:
                self._set_state(record.preview_ref, "completed")
        except Exception:
            # Fixed categories only: never log exceptions, bindings or responses.
            logging.getLogger(__name__).warning(
                "Isolated Folder execution requires reconciliation: stage=%s", stage
            )
            self._set_state(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        return self._result(record, idempotent_replay=False)

    @staticmethod
    def _prepare_private_database(database: Path) -> None:
        try:
            if not database.is_absolute():
                raise ValueError
            database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            parent = database.parent.lstat()
            if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or stat.S_IMODE(parent.st_mode) != 0o700):
                raise ValueError
            descriptor = os.open(database, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                    raise ValueError
                os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        except Exception:
            raise ChildFolderWorkflowError(_UNAVAILABLE) from None

    def _connect(self) -> sqlite3.Connection:
        if self._ownership_serial is not None:
            info = self._database.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
                raise ChildFolderWorkflowError(_UNAVAILABLE)
        return super()._connect()

    def _ownership_mac(self, payload: str) -> str:
        return hmac.new(self._key, b"isolated-folder-creation-ownership/v1\0" + payload.encode("ascii"),
                        hashlib.sha256).hexdigest()

    def _complete_with_ownership(self, record: _WorkflowRecord, ownership: IsolatedFolderCreationOwnership) -> None:
        from .isolated_folder_creation_ownership import ownership_payload, validate_creation_ownership
        validate_creation_ownership(ownership, binding=self._binding, expected_serial=str(self._ownership_serial))
        payload = ownership_payload(ownership)
        executing, completed = replace(record, state="executing"), replace(record, state="completed")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            # Both writes commit or roll back together. Never overwrite a preseeded receipt.
            connection.execute("INSERT INTO v4_isolated_folder_creation_ownership VALUES (?, ?, ?)",
                               (record.preview_ref, payload, self._ownership_mac(payload)))
            changed = connection.execute(
                "UPDATE v4_child_folder_workflows SET state = ?, record_mac = ? "
                "WHERE preview_ref = ? AND state = ? AND record_mac = ?",
                ("completed", self._mac(completed), record.preview_ref, "executing", self._mac(executing)),
            )
            if changed.rowcount != 1:
                raise ChildFolderWorkflowError(_UNAVAILABLE)

    def read_creation_ownership(self, preview_ref: str, requester_digest: str) -> IsolatedFolderCreationOwnership:
        """Read only an existing signed receipt; never observe or import a device object."""
        from .isolated_folder_creation_ownership import (
            IsolatedFolderCreationOwnership, ownership_payload, validate_creation_ownership,
        )
        try:
            if self._ownership_serial is None or not _valid_ref(preview_ref, "folder-preview-"):
                raise ValueError
            with self._connect() as connection:
                connection.execute("BEGIN")
                signed = connection.execute("SELECT * FROM v4_child_folder_workflows WHERE preview_ref = ?",
                                            (preview_ref,)).fetchone()
                if signed is None:
                    raise ValueError
                record = _record_from_row(signed)
                if record.state != "completed" or not hmac.compare_digest(str(signed["record_mac"]), self._mac(record)):
                    raise ValueError
                self._validate_requester(record, requester_digest)
                self._check_record_binding(record)
                row = connection.execute("SELECT payload, receipt_mac FROM v4_isolated_folder_creation_ownership "
                                         "WHERE preview_ref = ?", (preview_ref,)).fetchone()
            if (row is None or type(row["payload"]) is not str or len(row["payload"]) > 16384
                or not hmac.compare_digest(str(row["receipt_mac"]), self._ownership_mac(row["payload"]))):
                raise ValueError
            ownership = IsolatedFolderCreationOwnership(**json.loads(row["payload"]))
            if (ownership_payload(ownership) != row["payload"] or ownership.preview_ref != record.preview_ref
                or ownership.authorization_ref != record.authorization_ref
                or ownership.requester_digest != record.requester_digest
                or ownership.workflow_record_mac != self._mac(record)):
                raise ValueError
            validate_creation_ownership(ownership, binding=self._binding, expected_serial=self._ownership_serial)
            return ownership
        except Exception:
            raise ChildFolderWorkflowError(_UNAVAILABLE) from None

    def _preview_projection(self, record: _WorkflowRecord) -> dict[str, object]:
        result: dict[str, object] = {"contract": self._contract, "preview_ref": record.preview_ref, "expires_at": record.expires_at,
            "Current State": {"parent_matches": True, "owner_available": True, "matching_child_exists": False},
            "Proposed Changes": {"operation": "create_isolated_public_child_folder",
                "private_binding_digest": self._binding.parameters_digest,
                "disable_permission_inheritance": True, "owner_relation_count": 1, "group_relation_count": 0},
            "Expected State": {"matching_child_exists": True, "owner_only": True,
                "inherit_policy": "enable" if self._binding.initial_rdp_policy is None else "disable",
                "inherit_permission": "disable", "inherit_folder_ztna": "enable"},
            "device_write_executed": False}
        if self._binding.initial_rdp_policy is not None:
            current = result["Current State"]
            expected = result["Expected State"]
            assert isinstance(current, dict) and isinstance(expected, dict)
            current.update(complete_policy_matches=True, recording_enabled=True, clipboard_blocking_enabled=True)
            expected.update(fixed_policy_bound=True, complete_policy_preserved=True)
        return result

    @property
    def _contract(self) -> str:
        return CONTRACT if self._binding.initial_rdp_policy is None else RDP_POLICY_CONTRACT

    def _result(self, record: _WorkflowRecord, *, idempotent_replay: bool) -> dict[str, object]:
        result = super()._result(record, idempotent_replay=idempotent_replay)
        result["contract"] = self._contract
        return result
