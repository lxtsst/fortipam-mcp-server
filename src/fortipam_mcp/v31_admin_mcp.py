"""Strongly typed V3.1 administrative business facade for the LAB ADAPTER.

This lab-only MCP business facade wraps the fixed
:class:`AdministrativeOperationService` with five explicit preview methods and
one confirmation-bound execution method.  Registration does not expand its
authority: all operations remain local fixture operations, and no FortiPAM
device is contacted or written.
"""

from __future__ import annotations

import re
from typing import Literal, Mapping

from .administrative_operations import (
    AdministrativeOperationError,
    AdministrativeOperationService,
    ConfirmationInvalidated,
    OperationPreview,
)
from .controlled_operations import ControlledOperationError


FolderType = Literal["public", "private", "shared"]
Permission = Literal["use", "manage"]
LauncherType = Literal["any", "ssh", "sftp", "rdp"]
TargetClass = Literal["ssh", "sftp", "rdp", "https"]
UserStatus = Literal["enable", "disable"]

_REQUESTER_REF = "v31-lab-mcp-requester"
_ENVIRONMENT_REF = "v31-lab-environment"
_SCOPE_REF = "v31-lab-administrative-scope"
_INTERNAL_SECRET_VALUE_REF = "v31-internal-lab-material-ref"
_INTERNAL_SECRET_MARKER = "v31-internal-lab-material-present"
_OPAQUE_LAB_REF = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{7,127}$")


class V31AdministrativeMcpError(ValueError):
    """Safe public failure for the registered lab-only V3.1 business facade."""


class V31AdministrativeMcp:
    """Bounded business wrapper around one local administrative service."""

    def __init__(self, service: AdministrativeOperationService | None = None) -> None:
        self._service = service or AdministrativeOperationService()
        self._previews: dict[str, OperationPreview] = {}

    def preview_public_folder(
        self,
        *,
        folder_ref: str,
        parent_folder_ref: str,
        folder_type: FolderType,
        folder_permission: Permission,
        vault_permission: Permission,
        allowed_launcher_type: LauncherType,
        # These aliases map to the GUI's secret-policy/user-permission/
        # group-permission fields.  The V3 parameter contract reserves names
        # containing "secret" or "credential", so the service uses the
        # bounded vault_* aliases while the adapter emits GUI field names.
        vault_policy_ref: str = "default-vault-policy-01",
        user_permission: Permission = "use",
        group_permission: Permission = "use",
    ) -> dict[str, object]:
        """Preview creation or reconciliation of one Public Folder."""

        return self._preview(
            "create_public_folder",
            folder_ref,
            {
                "parent_folder_ref": parent_folder_ref,
                "folder_type": folder_type,
                "vault_policy_ref": vault_policy_ref,
                "user_permission": user_permission,
                "group_permission": group_permission,
                "folder_permission": folder_permission,
                "vault_permission": vault_permission,
                "allowed_launcher_type": allowed_launcher_type,
            },
        )

    def preview_target(
        self,
        *,
        target_ref: str,
        target_class: TargetClass,
        template_ref: str,
        address_ref: str,
        gateway_ref: str,
    ) -> dict[str, object]:
        """Preview creation or reconciliation of one Target metadata object."""

        return self._preview(
            "create_target",
            target_ref,
            {
                "target_class": target_class,
                "template_ref": template_ref,
                "address_ref": address_ref,
                "gateway_ref": gateway_ref,
            },
        )

    def preview_secret_metadata(
        self,
        *,
        secret_ref: str,
        name_ref: str,
        folder_ref: str,
        template_ref: str,
        target_ref: str,
        field_desc_ref: str,
    ) -> dict[str, object]:
        """Preview Secret metadata without accepting external secret material."""

        return self._preview(
            "create_secret",
            secret_ref,
            {
                "name_ref": name_ref,
                "folder_ref": folder_ref,
                "template_ref": template_ref,
                "target_ref": target_ref,
                "value_ref": _INTERNAL_SECRET_VALUE_REF,
                "field_name": "credential_field",
                "field_type": "string",
                "field_desc_ref": field_desc_ref,
            },
        )

    def preview_local_user(
        self,
        *,
        user_ref: str,
        name_ref: str,
        status: UserStatus,
        access_profile_ref: str,
        display_name_ref: str,
        comments_ref: str,
        schedule_ref: str,
        two_factor: bool,
    ) -> dict[str, object]:
        """Preview creation or reconciliation of one local user metadata object."""

        return self._preview(
            "create_local_user",
            user_ref,
            {
                "name_ref": name_ref,
                "status": status,
                "access_profile_ref": access_profile_ref,
                "display_name_ref": display_name_ref,
                "comments_ref": comments_ref,
                "schedule_ref": schedule_ref,
                "two_factor": two_factor,
            },
        )

    def preview_folder_access_assignment(
        self,
        *,
        assignment_ref: str,
        folder_ref: str,
        subject_ref: str,
        folder_permission: Permission,
        vault_permission: Permission,
        allowed_launcher_type: LauncherType,
    ) -> dict[str, object]:
        """Preview one bounded folder access assignment."""

        return self._preview(
            "assign_folder_access",
            assignment_ref,
            {
                "folder_ref": folder_ref,
                "subject_ref": subject_ref,
                "folder_permission": folder_permission,
                "vault_permission": vault_permission,
                "allowed_launcher_type": allowed_launcher_type,
            },
        )

    def execute_confirmed(
        self,
        confirmation_token: str,
        confirmation_digest: str,
        idempotency_key: str,
    ) -> dict[str, object]:
        """Execute one exact stored preview through the local fixture only."""

        if (
            not isinstance(confirmation_token, str)
            or not isinstance(confirmation_digest, str)
            or not isinstance(idempotency_key, str)
        ):
            raise V31AdministrativeMcpError(
                "The confirmation token or digest was rejected."
            )
        preview = self._previews.get(confirmation_token)
        if preview is None or confirmation_digest != preview.confirmation_digest:
            raise V31AdministrativeMcpError(
                "The confirmation token or digest was rejected."
            )
        secret_marker = (
            _INTERNAL_SECRET_MARKER if preview.action_id == "create_secret" else None
        )
        try:
            result = self._service.execute(
                preview,
                confirmation_token=confirmation_token,
                confirmation_digest=confirmation_digest,
                requester_ref=_REQUESTER_REF,
                environment_ref=_ENVIRONMENT_REF,
                scope_ref=_SCOPE_REF,
                idempotency_key=idempotency_key,
                secret_value=secret_marker,
            )
        except ConfirmationInvalidated as exc:
            self._previews.pop(confirmation_token, None)
            raise V31AdministrativeMcpError(
                "The confirmed preview was invalidated by expiry, scope change, or drift."
            ) from exc
        except (AdministrativeOperationError, ControlledOperationError) as exc:
            raise V31AdministrativeMcpError(
                "The confirmed LAB operation was rejected."
            ) from exc
        return {
            "lab_adapter": True,
            "adapter_kind": "lab_simulated",
            "device_contacted": False,
            "fortipam_contacted": False,
            "device_write": False,
            "readback": result.as_dict(),
        }

    def _preview(
        self,
        action_id: str,
        target_ref: str,
        parameters: Mapping[str, object],
    ) -> dict[str, object]:
        _require_opaque_lab_ref(target_ref)
        for name, value in parameters.items():
            if name.endswith("_ref"):
                _require_opaque_lab_ref(value)
        try:
            preview = self._service.preview(
                action_id,
                target_ref,
                parameters,
                requester_ref=_REQUESTER_REF,
                environment_ref=_ENVIRONMENT_REF,
                scope_ref=_SCOPE_REF,
            )
        except (AdministrativeOperationError, ControlledOperationError) as exc:
            raise V31AdministrativeMcpError(
                "The LAB preview request was rejected."
            ) from exc
        self._previews[preview.confirmation_token] = preview
        return {
            "lab_adapter": True,
            "adapter_kind": "lab_simulated",
            "device_contacted": False,
            "fortipam_contacted": False,
            "device_write": False,
            "current": dict(preview.current),
            "proposed": dict(preview.proposed),
            "expected": dict(preview.expected),
            "confirmation_token": preview.confirmation_token,
            "confirmation_digest": preview.confirmation_digest,
            "expires_at": preview.expires_at,
        }


def _require_opaque_lab_ref(value: object) -> None:
    if not isinstance(value, str) or _OPAQUE_LAB_REF.fullmatch(value) is None:
        raise V31AdministrativeMcpError(
            "Only non-resolvable opaque LAB references are accepted."
        )


__all__ = ["V31AdministrativeMcp", "V31AdministrativeMcpError"]
