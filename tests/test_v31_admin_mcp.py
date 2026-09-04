from __future__ import annotations

import inspect
import json
from pathlib import Path
from typing import Callable

import pytest

from fortipam_mcp.administrative_operations import AdministrativeOperationService
from fortipam_mcp.lab_admin_adapter import LabAdminAdapter
from fortipam_mcp.v31_admin_mcp import (
    V31AdministrativeMcp,
    V31AdministrativeMcpError,
)


PreviewCall = Callable[[V31AdministrativeMcp], dict[str, object]]


def _public_folder(api: V31AdministrativeMcp) -> dict[str, object]:
    return api.preview_public_folder(
        folder_ref="folder-ref-lab-01",
        parent_folder_ref="folder-ref-root-01",
        folder_type="public",
        folder_permission="manage",
        vault_permission="use",
        allowed_launcher_type="ssh",
    )


def _target(api: V31AdministrativeMcp) -> dict[str, object]:
    return api.preview_target(
        target_ref="target-ref-lab-01",
        target_class="ssh",
        template_ref="template-ref-lab-01",
        address_ref="address-ref-lab-01",
        gateway_ref="gateway-ref-lab-01",
    )


def _secret(api: V31AdministrativeMcp) -> dict[str, object]:
    return api.preview_secret_metadata(
        secret_ref="secret-ref-lab-01",
        name_ref="secret-name-ref-lab-01",
        folder_ref="folder-ref-lab-01",
        template_ref="secret-template-ref-01",
        target_ref="target-ref-lab-01",
        field_desc_ref="field-description-ref-01",
    )


def _local_user(api: V31AdministrativeMcp) -> dict[str, object]:
    return api.preview_local_user(
        user_ref="user-ref-lab-01",
        name_ref="user-name-ref-lab-01",
        status="enable",
        access_profile_ref="access-profile-ref-01",
        display_name_ref="display-name-ref-01",
        comments_ref="comments-ref-lab-01",
        schedule_ref="schedule-ref-lab-01",
        two_factor=True,
    )


def _assignment(api: V31AdministrativeMcp) -> dict[str, object]:
    return api.preview_folder_access_assignment(
        assignment_ref="folder-grant-ref-lab-01",
        folder_ref="folder-ref-lab-01",
        subject_ref="user-ref-lab-01",
        folder_permission="use",
        vault_permission="use",
        allowed_launcher_type="ssh",
    )


PREVIEWS: tuple[PreviewCall, ...] = (
    _public_folder,
    _target,
    _secret,
    _local_user,
    _assignment,
)


@pytest.mark.parametrize("preview_call", PREVIEWS)
def test_five_typed_previews_expose_only_lab_boundaries_and_comparison(
    preview_call: PreviewCall,
) -> None:
    preview = preview_call(V31AdministrativeMcp())
    assert preview["lab_adapter"] is True
    assert preview["adapter_kind"] == "lab_simulated"
    assert preview["device_contacted"] is False
    assert preview["fortipam_contacted"] is False
    assert preview["device_write"] is False
    assert preview["current"]
    assert preview["proposed"]
    assert preview["expected"]
    assert preview["confirmation_token"]
    assert preview["confirmation_digest"]


@pytest.mark.parametrize("preview_call", PREVIEWS)
def test_five_confirmed_actions_return_verified_lab_readback(
    preview_call: PreviewCall,
) -> None:
    api = V31AdministrativeMcp()
    preview = preview_call(api)
    result = api.execute_confirmed(
        str(preview["confirmation_token"]),
        str(preview["confirmation_digest"]),
        "idempotency-key-lab-0001",
    )
    assert result["lab_adapter"] is True
    assert result["adapter_kind"] == "lab_simulated"
    assert result["device_contacted"] is False
    assert result["fortipam_contacted"] is False
    assert result["device_write"] is False
    readback = result["readback"]
    assert isinstance(readback, dict)
    assert readback["readback_verified"] is True
    assert readback["outcome"] == "succeeded"


def test_secret_method_accepts_no_external_plaintext_and_never_exposes_internal_marker() -> None:
    signature = inspect.signature(V31AdministrativeMcp.preview_secret_metadata)
    assert "secret_value" not in signature.parameters
    assert "password" not in signature.parameters

    api = V31AdministrativeMcp()
    preview = _secret(api)
    result = api.execute_confirmed(
        str(preview["confirmation_token"]),
        str(preview["confirmation_digest"]),
        "idempotency-key-secret-0001",
    )
    output = json.dumps(
        {"preview": preview, "result": result}, sort_keys=True
    ).lower()
    assert "v31-internal-lab-material-present" not in output
    assert "v31-internal-lab-material-ref" not in output
    assert "password" not in output


def test_secret_internal_marker_is_not_persisted_or_returned(tmp_path: Path) -> None:
    fixture_path = tmp_path / "lab-state.json"
    api = V31AdministrativeMcp(
        AdministrativeOperationService(LabAdminAdapter(fixture_path))
    )
    preview = _secret(api)
    result = api.execute_confirmed(
        str(preview["confirmation_token"]),
        str(preview["confirmation_digest"]),
        "idempotency-key-secret-persist-01",
    )
    combined = (
        json.dumps({"preview": preview, "result": result}, sort_keys=True)
        + fixture_path.read_text(encoding="utf-8")
    ).lower()
    assert "v31-internal-lab-material-present" not in combined
    assert "v31-internal-lab-material-ref" not in combined
    assert "password" not in combined
    assert "has_secret_value" not in combined
    assert "value_ref_digest" not in combined
    assert '"material_status": "excluded"' in combined
    assert '"material_status": "not_provided"' in combined


@pytest.mark.parametrize(
    "unsafe_ref",
    ("203.0.113.10", "https://lab.invalid", "/private/lab/path", "user@example.invalid"),
)
def test_resolvable_locator_shapes_are_rejected_before_preview(unsafe_ref: str) -> None:
    api = V31AdministrativeMcp()
    with pytest.raises(V31AdministrativeMcpError, match="non-resolvable opaque"):
        api.preview_target(
            target_ref="target-ref-lab-unsafe",
            target_class="ssh",
            template_ref="template-ref-lab-01",
            address_ref=unsafe_ref,
            gateway_ref="gateway-ref-lab-01",
        )


def test_unknown_token_and_wrong_digest_fail_closed() -> None:
    api = V31AdministrativeMcp()
    preview = _target(api)
    with pytest.raises(V31AdministrativeMcpError, match="token or digest"):
        api.execute_confirmed(
            "confirmation-unknown-token",
            str(preview["confirmation_digest"]),
            "idempotency-key-lab-0001",
        )
    with pytest.raises(V31AdministrativeMcpError, match="token or digest"):
        api.execute_confirmed(
            str(preview["confirmation_token"]),
            "0" * 64,
            "idempotency-key-lab-0001",
        )


def test_current_state_drift_invalidates_token_and_stays_failed_closed() -> None:
    adapter = LabAdminAdapter()
    service = AdministrativeOperationService(adapter)
    api = V31AdministrativeMcp(service)
    preview = _public_folder(api)
    adapter._state["public_folders"]["folder-ref-lab-01"] = {  # noqa: SLF001
        "folder-type": "private"
    }
    token = str(preview["confirmation_token"])
    digest = str(preview["confirmation_digest"])
    with pytest.raises(V31AdministrativeMcpError, match="invalidated"):
        api.execute_confirmed(token, digest, "idempotency-key-lab-0001")
    with pytest.raises(V31AdministrativeMcpError, match="token or digest"):
        api.execute_confirmed(token, digest, "idempotency-key-lab-0002")


def test_same_token_digest_and_idempotency_key_returns_safe_replay() -> None:
    api = V31AdministrativeMcp()
    preview = _assignment(api)
    token = str(preview["confirmation_token"])
    digest = str(preview["confirmation_digest"])
    first = api.execute_confirmed(token, digest, "idempotency-key-replay-0001")
    second = api.execute_confirmed(token, digest, "idempotency-key-replay-0001")
    assert first["readback"] != second["readback"]
    assert isinstance(second["readback"], dict)
    assert second["readback"]["idempotent_replay"] is True


def test_requester_environment_and_scope_are_not_caller_parameters() -> None:
    for method_name in (
        "preview_public_folder",
        "preview_target",
        "preview_secret_metadata",
        "preview_local_user",
        "preview_folder_access_assignment",
        "execute_confirmed",
    ):
        parameters = inspect.signature(getattr(V31AdministrativeMcp, method_name)).parameters
        assert "requester_ref" not in parameters
        assert "environment_ref" not in parameters
        assert "scope_ref" not in parameters
