from __future__ import annotations

import json
from pathlib import Path
from typing import TypedDict

import pytest

from fortipam_mcp.administrative_operations import (
    AdministrativeOperationError,
    AdministrativeOperationService,
    ConfirmationInvalidated,
    OperationPreview,
)
from fortipam_mcp.lab_admin_adapter import LabAdminAdapter


class _ExecuteArgs(TypedDict):
    confirmation_token: str
    confirmation_digest: str
    requester_ref: str
    environment_ref: str
    scope_ref: str
    idempotency_key: str
    now_epoch: int


def _service(tmp_path: Path) -> AdministrativeOperationService:
    return AdministrativeOperationService(LabAdminAdapter(tmp_path / "fixture.json"))


def _parameters(action_id: str) -> dict[str, object]:
    values: dict[str, dict[str, object]] = {
        "create_public_folder": {
            "parent_folder_ref": "root-folder-0001",
            "folder_type": "public",
            "vault_policy_ref": "default-secret-policy",
            "user_permission": "use",
            "group_permission": "use",
            "folder_permission": "manage",
            "vault_permission": "use",
            "allowed_launcher_type": "any",
        },
        "create_target": {
            "target_class": "ssh",
            "template_ref": "linux-template-01",
            "address_ref": "ubuntu-address-01",
            "gateway_ref": "direct-gateway-01",
        },
        "create_secret": {
            "name_ref": "linux-secret-01",
            "folder_ref": "public-folder-01",
            "template_ref": "linux-secret-template",
            "target_ref": "ubuntu-target-01",
            "value_ref": "write-only-value-01",
            "field_name": "password",
            "field_type": "password",
            "field_desc_ref": "password-description-01",
        },
        "create_local_user": {
            "name_ref": "lab-user-01",
            "status": "enable",
            "access_profile_ref": "resource-admin-profile",
            "display_name_ref": "lab-user-display-01",
            "comments_ref": "fixture-comments-01",
            "schedule_ref": "always-schedule-01",
            "two_factor": False,
        },
        "assign_folder_access": {
            "folder_ref": "public-folder-01",
            "subject_ref": "lab-user-01",
            "folder_permission": "manage",
            "vault_permission": "use",
            "allowed_launcher_type": "ssh",
        },
    }
    return values[action_id]


def _preview(
    service: AdministrativeOperationService,
    action_id: str,
    *,
    now: int = 100,
) -> OperationPreview:
    return service.preview(
        action_id,
        f"{action_id}-object-01",
        _parameters(action_id),
        requester_ref="operator-0001",
        environment_ref="lab-fixture",
        scope_ref="admin-scope",
        now_epoch=now,
    )


@pytest.mark.parametrize(
    "action_id",
    [
        "create_public_folder",
        "create_target",
        "create_secret",
        "create_local_user",
        "assign_folder_access",
    ],
)
def test_fixed_actions_support_preview_confirmation_execution_and_readback(
    tmp_path: Path, action_id: str
) -> None:
    service = _service(tmp_path)
    plan = _preview(service, action_id)

    assert plan.current["exists"] is False
    assert plan.expected["exists"] is True
    result = service.execute(
        plan,
        confirmation_token=plan.confirmation_token,
        confirmation_digest=plan.confirmation_digest,
        requester_ref="operator-0001",
        environment_ref="lab-fixture",
        scope_ref="admin-scope",
        idempotency_key=f"idempotency-{action_id}-0001",
        secret_value="do-not-return-this-value" if action_id == "create_secret" else None,
        now_epoch=110,
    )

    assert result.outcome == "succeeded"
    assert result.readback_verified is True
    assert result.idempotent_replay is False


def test_unconfirmed_or_tampered_confirmation_is_denied(tmp_path: Path) -> None:
    service = _service(tmp_path)
    plan = _preview(service, "create_target")

    with pytest.raises(ConfirmationInvalidated):
        service.execute(
            plan,
            confirmation_token=plan.confirmation_token,
            confirmation_digest="0" * 64,
            requester_ref="operator-0001",
            environment_ref="lab-fixture",
            scope_ref="admin-scope",
            idempotency_key="idempotency-target-0001",
            now_epoch=110,
        )

    with pytest.raises(ConfirmationInvalidated):
        service.execute(
            plan,
            confirmation_token="confirmation-tampered-token-01",
            confirmation_digest=plan.confirmation_digest,
            requester_ref="operator-0001",
            environment_ref="lab-fixture",
            scope_ref="admin-scope",
            idempotency_key="idempotency-target-0002",
            now_epoch=110,
        )


def test_current_state_drift_invalidates_preview(tmp_path: Path) -> None:
    service = _service(tmp_path)
    plan = _preview(service, "create_public_folder")
    service.adapter._state["public_folders"][plan.target_ref] = {"unexpected": True}  # type: ignore[attr-defined]

    with pytest.raises(ConfirmationInvalidated, match="drifted"):
        service.execute(
            plan,
            confirmation_token=plan.confirmation_token,
            confirmation_digest=plan.confirmation_digest,
            requester_ref="operator-0001",
            environment_ref="lab-fixture",
            scope_ref="admin-scope",
            idempotency_key="idempotency-folder-0001",
            now_epoch=110,
        )


def test_idempotent_replay_does_not_execute_fixture_twice(tmp_path: Path) -> None:
    service = _service(tmp_path)
    plan = _preview(service, "create_target")
    kwargs: _ExecuteArgs = {
        "confirmation_token": plan.confirmation_token,
        "confirmation_digest": plan.confirmation_digest,
        "requester_ref": "operator-0001",
        "environment_ref": "lab-fixture",
        "scope_ref": "admin-scope",
        "idempotency_key": "idempotency-replay-0001",
        "now_epoch": 110,
    }
    first = service.execute(plan, **kwargs)
    replay = service.execute(plan, **kwargs)

    assert first.outcome == "succeeded"
    assert replay.outcome == "succeeded"
    assert replay.idempotent_replay is True
    assert replay.readback_verified is True


def test_secret_material_is_write_only_and_not_persisted_or_returned(tmp_path: Path) -> None:
    service = _service(tmp_path)
    plan = _preview(service, "create_secret")
    secret = "transient-noncredential-lab-marker"
    preview_text = json.dumps(plan.as_dict(), sort_keys=True)
    assert secret not in preview_text

    result = service.execute(
        plan,
        confirmation_token=plan.confirmation_token,
        confirmation_digest=plan.confirmation_digest,
        requester_ref="operator-0001",
        environment_ref="lab-fixture",
        scope_ref="admin-scope",
        idempotency_key="idempotency-secret-0001",
        secret_value=secret,
        now_epoch=110,
    )
    serialized_result = json.dumps(result.as_dict(), sort_keys=True)
    persisted = (tmp_path / "fixture.json").read_text(encoding="utf-8")
    persisted_secret = next(iter(json.loads(persisted)["secrets"].values()))
    assert secret not in serialized_result
    assert secret not in persisted
    assert "has_secret_value" not in serialized_result
    assert "has_secret_value" not in persisted
    assert "value_ref_digest" not in serialized_result
    assert "value_ref_digest" not in persisted
    assert persisted_secret["material_status"] == "excluded"
    assert persisted_secret["dynamic-field"][0]["material_status"] == "not_provided"


def test_json_fixture_state_survives_adapter_reload(tmp_path: Path) -> None:
    path = tmp_path / "fixture.json"
    service = AdministrativeOperationService(LabAdminAdapter(path))
    plan = _preview(service, "create_target")
    service.execute(
        plan,
        confirmation_token=plan.confirmation_token,
        confirmation_digest=plan.confirmation_digest,
        requester_ref="operator-0001",
        environment_ref="lab-fixture",
        scope_ref="admin-scope",
        idempotency_key="idempotency-persist-0001",
        now_epoch=110,
    )

    reloaded = LabAdminAdapter(path)
    current = reloaded.query_current(
        "create_target", plan.target_ref, plan.parameters
    )
    assert current["exists"] is True


def test_unknown_action_and_arbitrary_request_shape_are_denied(tmp_path: Path) -> None:
    service = _service(tmp_path)
    with pytest.raises(AdministrativeOperationError):
        service.preview(
            "delete_everything",
            "unsafe-target-01",
            {},
            requester_ref="operator-0001",
            environment_ref="lab-fixture",
            scope_ref="admin-scope",
            now_epoch=100,
        )
    with pytest.raises(AdministrativeOperationError):
        service.preview(
            "create_target",
            "target-object-01",
            {**_parameters("create_target"), "method": "DELETE"},
            requester_ref="operator-0001",
            environment_ref="lab-fixture",
            scope_ref="admin-scope",
            now_epoch=100,
        )
