"""Fixed build-29 Target-bound Web readback for the protected M4 runtime."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import stat
from typing import Protocol

from v4_planning import (
    AuthoritativeProjection, M4AdapterFailure, M4ExecutionPlan, ObjectClass,
    canonical_digest, AuthenticatedRequester, SchemeDraft, SchemeId,
)
from v4_planning.models import require_ref, require_digest
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID, SECRET_CREATE_ACTION_VERSION,
)

from .secret_create_191_private_adapter import SecretCreate700WebTargetBinding
from .secret_metadata_http_transport import SecretMetadataProjectionInspection
from .secret_onboarding_projection_source import secret_onboarding_projection_contract
from .target_contract import WebTargetCreateInput


ADAPTER_REF = "fortipam-700-target-bound-web-create-adapter"
_UNAVAILABLE = "The Target-bound Web Secret projection is unavailable."
_FIELDS = (
    "inherit_permission", "session_recording", "http_service_enabled",
    "proxy_mode_enabled", "target_association_matches",
)
_RELATION_FIELDS = (
    "folder_matches", "template_matches", "target_matches",
    "inherit_permission_matches", "recording_matches", "http_service_enabled",
    "proxy_mode_enabled",
)


def target_bound_web_binding_digest(
    binding: SecretCreate700WebTargetBinding, object_ref: str,
) -> str:
    """Bind all selectors without a circular dependency on the plan digest."""
    if type(binding) is not SecretCreate700WebTargetBinding:
        raise M4AdapterFailure(_UNAVAILABLE)
    try:
        require_ref(object_ref, "Target-bound Web object reference")
    except (TypeError, ValueError):
        raise M4AdapterFailure(_UNAVAILABLE) from None
    values = asdict(binding)
    values.pop("plan_digest")
    return canonical_digest({
        "profile": binding.contract_ref, "object_ref": object_ref, "binding": values,
    })


def target_bound_web_state_digest(object_ref: str, *, exists: bool) -> str:
    return AuthoritativeProjection.from_mapping(
        contract=secret_onboarding_projection_contract(
            ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA,
        ),
        object_ref=object_ref, observed_at=0, fresh_until=1,
        fields={"exists": True, **dict.fromkeys(_FIELDS, True)}
        if exists else {"exists": False},
    ).state_digest


class TargetBoundWebReadTransport(Protocol):
    def inspect_target_bound_web_projection(
        self, folder_path: str, secret_name: str, *, target: WebTargetCreateInput,
        expected_secret_id: int | None = None,
    ) -> SecretMetadataProjectionInspection: ...


class TargetBoundWebProjectionReader:
    """Require exact private intent and independent pre/post device evidence."""

    def __init__(
        self, binding: SecretCreate700WebTargetBinding, object_ref: str,
        transport: TargetBoundWebReadTransport,
    ) -> None:
        target_bound_web_binding_digest(binding, object_ref)
        if not callable(getattr(transport, "inspect_target_bound_web_projection", None)):
            raise M4AdapterFailure(_UNAVAILABLE)
        self._binding = binding
        self._object_ref = object_ref
        self._transport = transport

    def inspect_onboarding_binding_digest(self) -> str:
        return target_bound_web_binding_digest(self._binding, self._object_ref)

    def state_digest(self, *, exists: bool) -> str:
        return target_bound_web_state_digest(self._object_ref, exists=exists)

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

    def _inspect(self, plan: M4ExecutionPlan) -> SecretMetadataProjectionInspection:
        self._validate_plan(plan)
        return _inspect_binding(self._binding, self._transport)

    def read_current(self, plan: M4ExecutionPlan) -> str:
        try:
            result = self._inspect(plan)
            _require_absent(result)
            return self.state_digest(exists=False)
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        try:
            result = self._inspect(plan)
            _require_present(result)
            # field_values_attached records stripping at the transport boundary;
            # no material field or payload is carried by this categorical result.
            return self.state_digest(exists=True)
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None


def _inspect_binding(
    binding: SecretCreate700WebTargetBinding, transport: TargetBoundWebReadTransport,
) -> SecretMetadataProjectionInspection:
    result = transport.inspect_target_bound_web_projection(
        binding.folder_path, binding.secret_name, target=binding.target,
    )
    if (
        type(result) is not SecretMetadataProjectionInspection
        or any(type(value) is not bool for value in asdict(result).values())
        or not result.folder_exists or not result.template_exists
    ):
        raise M4AdapterFailure(_UNAVAILABLE)
    return result


def _require_absent(result: SecretMetadataProjectionInspection) -> None:
    if (result.secret_exists or result.field_values_attached
            or any(getattr(result, name) for name in _RELATION_FIELDS)):
        raise M4AdapterFailure(_UNAVAILABLE)


def _require_present(result: SecretMetadataProjectionInspection) -> None:
    if (not result.secret_exists
            or not all(getattr(result, name) for name in _RELATION_FIELDS)):
        raise M4AdapterFailure(_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class TargetBoundWebPlanningBinding:
    """Trusted host binding; never accepted as a caller-controlled Scheme field."""

    create_binding: SecretCreate700WebTargetBinding
    requester_digest: str
    environment_ref: str
    scope_ref: str
    folder_object_ref: str
    folder_ref: str
    target_object_ref: str
    target_profile_ref: str
    template_object_ref: str
    template_ref: str
    secret_object_ref: str

    def __post_init__(self) -> None:
        try:
            target_bound_web_binding_digest(self.create_binding, self.secret_object_ref)
            require_digest(self.requester_digest, "Web requester digest")
            for name, value in asdict(self).items():
                if name not in {"create_binding", "requester_digest"}:
                    require_ref(value, "Web planning reference")
            if len({self.folder_object_ref, self.target_object_ref,
                    self.template_object_ref, self.secret_object_ref}) != 4:
                raise ValueError
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None

    def expected_objects(self) -> dict[str, tuple[ObjectClass, dict[str, bool | str]]]:
        b = self
        return {
            b.folder_object_ref: (ObjectClass.FOLDER_BINDING, {"folder_ref": b.folder_ref}),
            b.target_object_ref: (ObjectClass.WEB_TARGET_BINDING, {
                "profile_ref": b.target_profile_ref, "target_relation_matches": True,
            }),
            b.template_object_ref: (ObjectClass.TEMPLATE_BINDING, {
                "template_ref": b.template_ref, "compatibility": "compatible",
            }),
            b.secret_object_ref: (ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA,
                                  dict.fromkeys(_FIELDS, True)),
        }

    def validate_intent(
        self, draft: SchemeDraft, requester: AuthenticatedRequester,
    ) -> TargetBoundWebPlanningBinding:
        try:
            b = self
            if (
                draft.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.scheme_version != "1.0.0"
                or draft.blueprint_ref != "FPA-BP-007"
                or draft.outcome_code != "onboard_web_account"
                or requester.digest != b.requester_digest
                or draft.environment_ref != b.environment_ref
                or draft.scope_ref != b.scope_ref
                or draft.material_reference_metadata is None
                or draft.material_reference_metadata.provider_class != "central_lab_inventory_reference"
                or draft.material_reference_metadata.purpose != "initial_onboarding"
                or draft.material_reference_metadata.lifecycle != "available"
            ):
                raise ValueError
            expected = self.expected_objects()
            if (
                len(draft.desired_objects) != 4
                or {item.object_ref for item in draft.desired_objects} != set(expected)
                or any(not item.desired_exists
                       or (item.object_class, dict(item.desired_fields)) != expected[item.object_ref]
                       for item in draft.desired_objects)
            ):
                raise ValueError
            return b
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None



class TargetBoundWebPlanningSource:
    """Observe one private binding without accepting selectors from a draft."""

    mode = "source_backed"
    contract_registered = True

    def __init__(
        self, binding: TargetBoundWebPlanningBinding, transport: TargetBoundWebReadTransport,
    ) -> None:
        if type(binding) is not TargetBoundWebPlanningBinding or not callable(
            getattr(transport, "inspect_target_bound_web_projection", None),
        ):
            raise M4AdapterFailure(_UNAVAILABLE)
        self._binding = binding
        self._transport = transport

    def _expected(self) -> dict[str, tuple[ObjectClass, dict[str, bool | str]]]:
        return self._binding.expected_objects()

    def resolve_private_binding(
        self, draft: SchemeDraft, requester: AuthenticatedRequester,
    ) -> TargetBoundWebPlanningBinding:
        return self._binding.validate_intent(draft, requester)

    def inspect_target_bound_web_binding_digest(
        self, draft: SchemeDraft, requester: AuthenticatedRequester,
    ) -> str:
        b = self.resolve_private_binding(draft, requester)
        return target_bound_web_binding_digest(b.create_binding, b.secret_object_ref)

    def project(
        self, draft: SchemeDraft, requester: AuthenticatedRequester, *, now_epoch: int,
    ) -> tuple[AuthoritativeProjection, ...]:
        try:
            b = self.resolve_private_binding(draft, requester)
            if type(now_epoch) is not int or now_epoch < 0:
                raise ValueError
            result = _inspect_binding(b.create_binding, self._transport)
            if result.secret_exists:
                _require_present(result)
            else:
                _require_absent(result)
            return tuple(
                AuthoritativeProjection.from_mapping(
                    contract=secret_onboarding_projection_contract(cls),
                    object_ref=ref, observed_at=now_epoch, fresh_until=now_epoch + 300,
                    fields=({"exists": False}
                            if cls is ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA
                            and not result.secret_exists else {"exists": True, **fields}),
                )
                for ref, (cls, fields) in self._expected().items()
            )
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None


PLANNING_BINDING_CONTRACT = "fortipam-700-target-bound-web-planning-binding-v1"
_PLANNING_REFERENCE_FIELDS = (
    "requester_digest", "environment_ref", "scope_ref", "folder_object_ref",
    "folder_ref", "target_object_ref", "target_profile_ref", "template_object_ref",
    "template_ref", "secret_object_ref",
)


def load_target_bound_web_planning_binding(path: Path) -> TargetBoundWebPlanningBinding:
    """Load one owned 0600 file; fixed product settings cannot be overridden."""
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 < info.st_size <= 16384):
                raise ValueError
            content = os.read(descriptor, 16385)
        finally:
            os.close(descriptor)
        if not 0 < len(content) <= 16384:
            raise ValueError
        payload = json.loads(content, object_pairs_hook=unique_object)
        if (type(payload) is not dict
                or set(payload) != {
                    "contract", "folder_path", "secret_name", "target_name", "web_url",
                    *_PLANNING_REFERENCE_FIELDS,
                }
                or any(type(value) is not str for value in payload.values())
                or payload["contract"] != PLANNING_BINDING_CONTRACT):
            raise ValueError
        create_binding = SecretCreate700WebTargetBinding(
            contract_ref="fortipam-700-build29-target-bound-web-create-candidate-v1",
            target_product_version="7.0.0", target_product_build=29,
            # Replaced with the authorized M4 digest when a runner is composed.
            plan_digest="0" * 64,
            folder_path=payload["folder_path"], secret_name=payload["secret_name"],
            template_name="Web Account", session_recording=True,
            target=WebTargetCreateInput(payload["target_name"], payload["web_url"]),
        )
        return TargetBoundWebPlanningBinding(
            create_binding=create_binding,
            **{name: payload[name] for name in _PLANNING_REFERENCE_FIELDS},
        )
    except Exception:
        raise M4AdapterFailure(_UNAVAILABLE) from None
