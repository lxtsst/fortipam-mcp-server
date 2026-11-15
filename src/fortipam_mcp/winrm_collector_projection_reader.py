"""Fixed 7.0 collector projections for the existing M4 Secret-create runtime."""

from __future__ import annotations

from dataclasses import asdict
from typing import Protocol

from v4_planning import (
    AuthoritativeProjection, FieldKind, FieldRule, M4AdapterFailure,
    M4ExecutionPlan, ObjectClass, ProjectionContract, canonical_digest,
    SchemeDraft, SchemeId, AuthenticatedRequester,
)
from v4_planning.material_provider import MaterialProviderClass, MaterialPurpose
from v4_planning.models import require_ref
from v4_planning.secret_create_adapter import SECRET_CREATE_ACTION_ID, SECRET_CREATE_ACTION_VERSION

from .secret_create_191_private_adapter import SecretCreate700WinrmBinding
from .secret_metadata_http_transport import SecretMetadataInspection
from .secret_onboarding_projection_source import (
    SecretOnboardingBinding, SecretOnboardingBindingResolver, secret_onboarding_projection_contract,
)


ADAPTER_REF = "fortipam-700-winrm-collector-create-adapter"
_UNAVAILABLE = "The WinRM collector projection is unavailable."
_FIELDS = (
    "inherit_permission", "privileged_account", "owner_only_folder",
    "rdp_service_enabled", "recording_enabled", "rdp_event_filter_enabled",
    "rdp_event_filter_profile_matches", "non_rdp_services_disabled",
    "target_association_matches",
)


def winrm_collector_projection_contract(
    object_class: ObjectClass = ObjectClass.WINRM_COLLECTOR_METADATA,
) -> ProjectionContract:
    if object_class not in {
        ObjectClass.WINRM_COLLECTOR_METADATA, ObjectClass.FOLDER_BINDING,
        ObjectClass.TARGET, ObjectClass.TEMPLATE_BINDING,
    }:
        raise M4AdapterFailure(_UNAVAILABLE)
    rules = (tuple(FieldRule(name, FieldKind.BOOLEAN) for name in ("exists", *_FIELDS))
             if object_class is ObjectClass.WINRM_COLLECTOR_METADATA
             else secret_onboarding_projection_contract(object_class).field_rules)
    return ProjectionContract(
        contract_id="fortipam-winrm-collector-observation-v1", version="1.0.0",
        source_ref="fortipam-700-build29-winrm-collector-projection",
        object_class=object_class,
        field_rules=rules,
        max_age_seconds=300,
    )


def winrm_collector_binding_digest(binding: SecretCreate700WinrmBinding, object_ref: str) -> str:
    require_ref(object_ref, "collector object_ref")
    values = asdict(binding)
    # Plan digest includes parameters_digest, so including it here would be circular.
    values.pop("plan_digest")
    return canonical_digest({"profile": binding.contract_ref, "object_ref": object_ref, "binding": values})


def winrm_collector_state_digest(object_ref: str, *, exists: bool) -> str:
    return AuthoritativeProjection.from_mapping(
        contract=winrm_collector_projection_contract(), object_ref=object_ref,
        observed_at=0, fresh_until=1,
        fields={"exists": True, **dict.fromkeys(_FIELDS, True)} if exists else {"exists": False},
    ).state_digest


class WinrmCollectorReadTransport(Protocol):
    def inspect(self, folder_path: str, secret_name: str, template: str) -> SecretMetadataInspection: ...

    def verify_winrm_collector_preflight(
        self, folder_path: str, secret_name: str, owner_name: str,
        witness_folder_path: str, witness_secret_name: str, target_name: str,
        expected_target_address: str,
    ) -> bool: ...

    def resolve_existing_secret_id(self, folder_path: str, secret_name: str) -> int: ...

    def verify_winrm_collector(
        self, folder_path: str, secret_name: str, target_name: str,
        *, expected_secret_id: int, owner_name: str, expected_target_address: str,
        expected_rdp_event_filter_profile: str,
    ) -> bool: ...


class WinrmCollectorProjectionReader:
    """Bind source-backed reads to one plan, target reference and private intent.

    Existing M4 calls read_current before dispatch enters the material runtime.
    A positive HTTP acknowledgement cannot satisfy read_postcondition.
    """

    def __init__(
        self, binding: SecretCreate700WinrmBinding, object_ref: str,
        transport: WinrmCollectorReadTransport,
    ) -> None:
        if not isinstance(binding, SecretCreate700WinrmBinding):
            raise M4AdapterFailure(_UNAVAILABLE)
        require_ref(object_ref, "collector object_ref")
        self._binding = binding
        self._object_ref = object_ref
        self._transport = transport

    def inspect_onboarding_binding_digest(self) -> str:
        return winrm_collector_binding_digest(self._binding, self._object_ref)

    def state_digest(self, *, exists: bool) -> str:
        return winrm_collector_state_digest(self._object_ref, exists=exists)

    def _validate_plan(self, plan: M4ExecutionPlan) -> None:
        if (
            not isinstance(plan, M4ExecutionPlan)
            or plan.action_id != SECRET_CREATE_ACTION_ID
            or plan.action_version != SECRET_CREATE_ACTION_VERSION
            or plan.adapter_ref != ADAPTER_REF
            or plan.target_ref != self._object_ref
            or plan.plan_digest != self._binding.plan_digest
            or plan.parameters_digest != self.inspect_onboarding_binding_digest()
            or plan.expected_current_digest != self.state_digest(exists=False)
            or plan.expected_state_digest != self.state_digest(exists=True)
        ):
            raise M4AdapterFailure(_UNAVAILABLE)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            self._validate_plan(plan)
            b = self._binding
            inspection = self._transport.inspect(b.folder_path, b.secret_name, b.template_name)
            if (not isinstance(inspection, SecretMetadataInspection)
                or inspection.secret_exists or not inspection.folder_exists or not inspection.template_exists
                or self._transport.verify_winrm_collector_preflight(
                    b.folder_path, b.secret_name, b.folder_owner_name,
                    b.witness_folder_path, b.witness_secret_name, b.target_name, b.target_ipv4_address,
                ) is not True):
                raise ValueError
            return self.state_digest(exists=False)
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            self._validate_plan(plan)
            b = self._binding
            secret_id = self._transport.resolve_existing_secret_id(b.folder_path, b.secret_name)
            if self._transport.verify_winrm_collector(
                b.folder_path, b.secret_name, b.target_name,
                expected_secret_id=secret_id, owner_name=b.folder_owner_name,
                expected_target_address=b.target_ipv4_address,
                expected_rdp_event_filter_profile=b.rdp_event_filter_profile_name,
            ) is not True:
                raise ValueError
            return self.state_digest(exists=True)
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None


class WinrmCollectorPlanningSource:
    """Read-only planning source; selectors remain behind the existing resolver."""

    mode = "source_backed"
    contract_registered = True

    def __init__(self, binding: SecretCreate700WinrmBinding,
                 resolver: "SecretOnboardingBindingResolver",
                 transport: WinrmCollectorReadTransport) -> None:
        self._binding = binding
        self._resolver = resolver
        self._transport = transport

    def inspect_collector_binding_digest(self, draft: SchemeDraft, requester: AuthenticatedRequester) -> str:
        refs = self.resolve_private_binding(draft, requester)
        return winrm_collector_binding_digest(self._binding, refs.secret_object_ref)

    def resolve_private_binding(self, draft: SchemeDraft, requester: AuthenticatedRequester) -> SecretOnboardingBinding:
        refs = self._resolver.resolve(draft, requester)
        if (not isinstance(refs, SecretOnboardingBinding)
            or any(getattr(refs, key) != getattr(self._binding, key) for key in (
                "folder_path", "secret_name", "target_name", "template_name", "target_ipv4_address",
            ))):
            raise M4AdapterFailure(_UNAVAILABLE)
        return refs

    def project(self, draft: "SchemeDraft", requester: "AuthenticatedRequester", *,
                now_epoch: int) -> tuple[AuthoritativeProjection, ...]:
        from .owner_session_metadata import OwnerSessionMetadataTransport
        if isinstance(self._transport, OwnerSessionMetadataTransport):
            with self._transport.authenticated():
                return self._project(draft, requester, now_epoch=now_epoch)
        return self._project(draft, requester, now_epoch=now_epoch)

    def _project(self, draft: SchemeDraft, requester: AuthenticatedRequester, *,
                 now_epoch: int) -> tuple[AuthoritativeProjection, ...]:
        try:
            b = self._binding
            refs = self.resolve_private_binding(draft, requester)
            if (not isinstance(refs, SecretOnboardingBinding)
                or draft.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.blueprint_ref != "FPA-BP-006"
                or draft.outcome_code != "onboard_windows_rdp_resource"
                or type(now_epoch) is not int or now_epoch < 0
                or draft.material_reference_metadata is None
                or draft.material_reference_metadata.provider_class != MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE.value
                or draft.material_reference_metadata.purpose != MaterialPurpose.INITIAL_ONBOARDING.value
                or draft.material_reference_metadata.lifecycle != "available"
                or refs.target_protocol != "rdp"
                or any(getattr(refs, key) is not None for key in (
                    "launcher_object_ref", "policy_object_ref", "rdp_event_filter_object_ref",
                    "secret_session_controls_object_ref", "existing_secret_id",
                ))
                or any(getattr(refs, key) != getattr(b, key) for key in (
                    "folder_path", "secret_name", "target_name", "template_name", "target_ipv4_address",
                ))):
                raise ValueError
            expected: dict[str, tuple[ObjectClass, dict[str, bool | str]]] = {
                refs.folder_object_ref: (ObjectClass.FOLDER_BINDING, {"folder_ref": refs.folder_ref}),
                refs.target_object_ref: (ObjectClass.TARGET, {"protocol": "rdp", "connectivity_profile_ref": refs.connectivity_profile_ref}),
                refs.template_object_ref: (ObjectClass.TEMPLATE_BINDING, {"compatibility": "compatible", "template_ref": refs.template_ref}),
                refs.secret_object_ref: (ObjectClass.WINRM_COLLECTOR_METADATA, dict.fromkeys(_FIELDS, True)),
            }
            if (len(expected) != 4 or len(draft.desired_objects) != 4
                or {o.object_ref for o in draft.desired_objects} != set(expected)
                or any(not o.desired_exists or (o.object_class, dict(o.desired_fields)) != expected[o.object_ref]
                       for o in draft.desired_objects)):
                raise ValueError
            inspection = self._transport.inspect(b.folder_path, b.secret_name, b.template_name)
            if (not isinstance(inspection, SecretMetadataInspection)
                or not inspection.folder_exists or not inspection.template_exists):
                raise ValueError
            if inspection.secret_exists:
                secret_id = self._transport.resolve_existing_secret_id(b.folder_path, b.secret_name)
                valid = self._transport.verify_winrm_collector(
                    b.folder_path, b.secret_name, b.target_name,
                    expected_secret_id=secret_id, owner_name=b.folder_owner_name,
                    expected_target_address=b.target_ipv4_address,
                    expected_rdp_event_filter_profile=b.rdp_event_filter_profile_name,
                )
            else:
                valid = self._transport.verify_winrm_collector_preflight(
                    b.folder_path, b.secret_name, b.folder_owner_name,
                    b.witness_folder_path, b.witness_secret_name, b.target_name, b.target_ipv4_address,
                )
            if valid is not True:
                raise ValueError
            return tuple(AuthoritativeProjection.from_mapping(
                contract=winrm_collector_projection_contract(cls),
                object_ref=ref, observed_at=now_epoch, fresh_until=now_epoch + 300,
                fields=({"exists": False} if cls is ObjectClass.WINRM_COLLECTOR_METADATA
                        and not inspection.secret_exists else {"exists": True, **fields}),
            ) for ref, (cls, fields) in expected.items())
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None
