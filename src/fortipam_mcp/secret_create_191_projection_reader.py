"""Metadata-only M4 projection reader for one FortiPAM 1.9.1 Secret create.

The fixed product read excludes Secret fields and proves only absence before
dispatch or the exact Folder, Template, Target, and inheritance relations after
an action-specific transport has received a successful create acknowledgement.
"""

from __future__ import annotations

from v4_planning import (
    AuthoritativeProjection,
    M4AdapterFailure,
    M4ExecutionPlan,
    ObjectClass,
)
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
)

from .secret_create_191_private_adapter import (
    SecretCreate191Binding,
    SecretCreate191TargetBinding,
    SecretCreate191WebBinding,
)
from .secret_metadata_http_transport import SecretMetadataProjectionInspection
from .secret_onboarding_projection_source import (
    SecretMetadataReadTransport,
    SecretOnboardingBinding,
    SecretOnboardingProductBinding,
    WebSecretOnboardingBinding,
    secret_onboarding_binding_digest,
    secret_onboarding_projection_contract,
)


SECRET_CREATE_191_PROJECTION_UNAVAILABLE = (
    "FortiPAM 1.9.1 Secret-create projection is unavailable."
)


class SecretCreate191ProjectionReaderError(M4AdapterFailure):
    """Stable, non-disclosing fixed projection failure."""


class SecretCreate191ProjectionReader:
    """Return only an authoritative absent-state digest without reading C3."""

    __slots__ = ("_binding", "_target_binding", "_transport")

    def __init__(
        self,
        binding: SecretOnboardingProductBinding,
        target_binding: SecretCreate191Binding,
        transport: SecretMetadataReadTransport,
    ) -> None:
        try:
            linux_profile = isinstance(binding, SecretOnboardingBinding) and (
                binding.target_protocol in {"ssh", "sftp"}
                and binding.launcher_object_ref is None
                and binding.policy_object_ref is None
            )
            windows_rdp_profile = isinstance(binding, SecretOnboardingBinding) and (
                binding.target_protocol == "rdp"
                and binding.launcher_object_ref is not None
                and binding.policy_object_ref is not None
            )
            web_profile = (
                isinstance(binding, WebSecretOnboardingBinding)
                and isinstance(target_binding, SecretCreate191WebBinding)
                and binding.template_name == "Web Account"
                and binding.session_recording is True
                and target_binding.web_url == binding.web_url
                and target_binding.session_recording is True
            )
            if (
                not isinstance(
                    target_binding,
                    (SecretCreate191TargetBinding, SecretCreate191WebBinding),
                )
                or not (linux_profile or windows_rdp_profile or web_profile)
                or target_binding.folder_path != binding.folder_path
                or target_binding.secret_name != binding.secret_name
                or target_binding.template_name != binding.template_name
            ):
                raise ValueError("binding mismatch")
            if isinstance(binding, SecretOnboardingBinding):
                if (
                    not isinstance(target_binding, SecretCreate191TargetBinding)
                    or not callable(getattr(transport, "inspect_projection", None))
                    or target_binding.target_name != binding.target_name
                    or target_binding.target_ipv4_address
                    != binding.target_ipv4_address
                    or target_binding.rdp_event_filter_profile_name
                    != binding.rdp_event_filter_profile_name
                    or target_binding.rdp_service_enabled
                    != (binding.target_protocol == "rdp")
                ):
                    raise ValueError("binding mismatch")
            elif not callable(getattr(transport, "inspect_web_projection", None)):
                raise ValueError("binding mismatch")
        except Exception as exc:
            raise SecretCreate191ProjectionReaderError(
                SECRET_CREATE_191_PROJECTION_UNAVAILABLE
            ) from exc
        self._binding = binding
        self._target_binding = target_binding
        self._transport = transport

    def inspect_onboarding_binding_digest(self) -> str:
        """Return only the complete private-selector integrity digest."""

        return secret_onboarding_binding_digest(self._binding)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        """Digest only an unambiguous absent Secret with present dependencies."""

        try:
            self._validate_plan(plan)
            inspection = self._inspect()
            if not inspection.folder_exists or not inspection.template_exists:
                raise ValueError("dependency relation unavailable")
            if inspection.secret_exists:
                raise ValueError("existing Secret is not authoritatively readable")
            if (
                inspection.folder_matches
                or inspection.template_matches
                or inspection.inherit_permission_matches
                or inspection.field_values_attached
            ):
                raise ValueError("absent relation is contradictory")
            return self._state_digest(exists=False)
        except SecretCreate191ProjectionReaderError:
            raise
        except Exception as exc:
            raise SecretCreate191ProjectionReaderError(
                SECRET_CREATE_191_PROJECTION_UNAVAILABLE
            ) from exc

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        """Verify only the non-secret product relations after fixed dispatch."""

        try:
            self._validate_plan(plan)
            inspection = self._inspect()
            if not inspection.metadata_relation_verified:
                raise ValueError("metadata relation unavailable")
            if (
                isinstance(self._binding, SecretOnboardingBinding)
                and self._binding.target_protocol == "rdp"
                and not inspection.rdp_service_enabled
            ):
                raise ValueError("RDP service is not enabled")
            if (
                isinstance(self._target_binding, SecretCreate191TargetBinding)
                and self._target_binding.target_product_build == 29
                and not self._target_binding.rdp_service_enabled
                and not inspection.ssh_service_enabled
            ):
                raise ValueError("SSH service is not enabled")
            if (
                isinstance(self._target_binding, SecretCreate191TargetBinding)
                and self._target_binding.contract_ref
                == "fortipam-700-build29-linux-ssh-sftp-recording-create-candidate-v2"
                and (not inspection.sftp_service_enabled or not inspection.recording_matches)
            ):
                raise ValueError("SFTP or recording is not enabled")
            if (
                isinstance(self._target_binding, SecretCreate191TargetBinding)
                and self._target_binding.contract_ref
                == "fortipam-700-build29-windows-rdp-create-candidate-v1"
                and (
                    not inspection.recording_matches
                    or not inspection.clipboard_blocking_matches
                    or not inspection.rdp_clipboard_control_compatible
                )
            ):
                raise ValueError("RDP recording or clipboard controls are unavailable")
            if isinstance(self._binding, WebSecretOnboardingBinding):
                if not inspection.recording_matches or not inspection.http_service_enabled:
                    raise ValueError("Web recording or service relation unavailable")
            elif (
                self._binding.rdp_event_filter_profile_name is not None
                and not inspection.rdp_event_filter_matches
            ):
                raise ValueError("RDP event-filter relation unavailable")
            return self._state_digest(exists=True)
        except SecretCreate191ProjectionReaderError:
            raise
        except Exception as exc:
            raise SecretCreate191ProjectionReaderError(
                SECRET_CREATE_191_PROJECTION_UNAVAILABLE
            ) from exc

    def _validate_plan(self, plan: M4ExecutionPlan) -> None:
        if (
            not isinstance(plan, M4ExecutionPlan)
            or plan.action_id != SECRET_CREATE_ACTION_ID
            or plan.action_version != SECRET_CREATE_ACTION_VERSION
            or plan.target_ref != self._binding.secret_object_ref
            or plan.plan_digest != self._target_binding.plan_digest
        ):
            raise SecretCreate191ProjectionReaderError(
                SECRET_CREATE_191_PROJECTION_UNAVAILABLE
            )

    def _inspect(self) -> SecretMetadataProjectionInspection:
        if isinstance(self._binding, WebSecretOnboardingBinding):
            inspection = self._transport.inspect_web_projection(
                self._binding.folder_path,
                self._binding.secret_name,
                self._binding.template_name,
            )
            if not isinstance(inspection, SecretMetadataProjectionInspection):
                raise SecretCreate191ProjectionReaderError(
                    SECRET_CREATE_191_PROJECTION_UNAVAILABLE
                )
            return inspection
        profile_name = self._binding.rdp_event_filter_profile_name
        inspection = (
            self._transport.inspect_projection(
                self._binding.folder_path,
                self._binding.secret_name,
                self._binding.template_name,
                self._binding.target_name,
                expected_rdp_event_filter_profile=profile_name,
            )
            if profile_name is not None
            else self._transport.inspect_projection(
                self._binding.folder_path,
                self._binding.secret_name,
                self._binding.template_name,
                self._binding.target_name,
            )
        )
        if not isinstance(inspection, SecretMetadataProjectionInspection):
            raise SecretCreate191ProjectionReaderError(
                SECRET_CREATE_191_PROJECTION_UNAVAILABLE
            )
        return inspection

    def _state_digest(self, *, exists: bool) -> str:
        projection = AuthoritativeProjection.from_mapping(
            contract=secret_onboarding_projection_contract(
                ObjectClass.WEB_SECRET_METADATA
                if isinstance(self._binding, WebSecretOnboardingBinding)
                else ObjectClass.SECRET_METADATA
            ),
            object_ref=self._binding.secret_object_ref,
            observed_at=0,
            fresh_until=1,
            fields=(
                (
                    {
                        "exists": True,
                        "inherit_permission": True,
                        "session_recording": True,
                    }
                    if isinstance(self._binding, WebSecretOnboardingBinding)
                    else {"exists": True, "inherit_permission": True}
                )
                if exists
                else {"exists": False}
            ),
        )
        return projection.state_digest


__all__ = [
    "SECRET_CREATE_191_PROJECTION_UNAVAILABLE",
    "SecretCreate191ProjectionReader",
    "SecretCreate191ProjectionReaderError",
]
