"""Fixed build-29 Domain readback for the protected M4 runtime."""

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

from .secret_create_191_private_adapter import SecretCreate700DomainBinding
from .secret_metadata_http_transport import DomainSecretMetadataInspection
from .secret_onboarding_projection_source import secret_onboarding_projection_contract


ADAPTER_REF = "fortipam-700-domain-account-create-adapter"
_UNAVAILABLE = "The Domain Secret projection is unavailable."
_FIELDS = (
    "inherit_permission", "non_privileged_account", "services_disabled",
    "target_association_matches",
)


def domain_secret_binding_digest(
    binding: SecretCreate700DomainBinding, object_ref: str, *,
    dependency_refs: tuple[str, ...],
) -> str:
    """Bind all selectors without a circular dependency on the plan digest."""
    if type(binding) is not SecretCreate700DomainBinding:
        raise M4AdapterFailure(_UNAVAILABLE)
    try:
        require_ref(object_ref, "Domain object reference")
        if type(dependency_refs) is not tuple or len(dependency_refs) != 4 or len(set(dependency_refs)) != 4 or dependency_refs[-1] != object_ref:
            raise ValueError
        for ref in dependency_refs:
            require_ref(ref, "Domain dependency reference")
    except (TypeError, ValueError):
        raise M4AdapterFailure(_UNAVAILABLE) from None
    values = asdict(binding)
    values.pop("plan_digest")
    return canonical_digest({
        "profile": binding.contract_ref, "object_ref": object_ref, "binding": values,
        "dependency_refs": list(dependency_refs),
    })


def domain_secret_state_digest(object_ref: str, *, exists: bool) -> str:
    return AuthoritativeProjection.from_mapping(
        contract=secret_onboarding_projection_contract(
            ObjectClass.DOMAIN_SECRET_METADATA,
        ),
        object_ref=object_ref, observed_at=0, fresh_until=1,
        fields={"exists": True, **dict.fromkeys(_FIELDS, True)}
        if exists else {"exists": False},
    ).state_digest


class DomainSecretReadTransport(Protocol):
    def inspect_domain_account_projection(
        self, binding: SecretCreate700DomainBinding, *, expected_secret_id: int | None = None,
    ) -> DomainSecretMetadataInspection: ...


class DomainSecretProjectionReader:
    """Require exact private intent and independent pre/post device evidence."""

    def __init__(
        self, binding: SecretCreate700DomainBinding, object_ref: str,
        transport: DomainSecretReadTransport, *, dependency_refs: tuple[str, ...],
    ) -> None:
        domain_secret_binding_digest(binding, object_ref, dependency_refs=dependency_refs)
        if not callable(getattr(transport, "inspect_domain_account_projection", None)):
            raise M4AdapterFailure(_UNAVAILABLE)
        self._binding = binding
        self._object_ref = object_ref
        self._dependency_refs = dependency_refs
        self._transport = transport

    def inspect_onboarding_binding_digest(self) -> str:
        return domain_secret_binding_digest(self._binding, self._object_ref, dependency_refs=self._dependency_refs)

    def state_digest(self, *, exists: bool) -> str:
        return domain_secret_state_digest(self._object_ref, exists=exists)

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

    def _inspect(self, plan: M4ExecutionPlan) -> DomainSecretMetadataInspection:
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
            return self.state_digest(exists=True)
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None


def _inspect_binding(
    binding: SecretCreate700DomainBinding, transport: DomainSecretReadTransport,
) -> DomainSecretMetadataInspection:
    result = transport.inspect_domain_account_projection(binding)
    if (type(result) is not DomainSecretMetadataInspection
            or any(type(value) is not bool for value in asdict(result).values())):
        raise M4AdapterFailure(_UNAVAILABLE)
    return result


def _require_absent(result: DomainSecretMetadataInspection) -> None:
    if result.secret_exists or result.metadata_verified or result.field_was_redacted:
        raise M4AdapterFailure(_UNAVAILABLE)


def _require_present(result: DomainSecretMetadataInspection) -> None:
    if not result.secret_exists or not result.metadata_verified:
        raise M4AdapterFailure(_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class DomainSecretPlanningBinding:
    """Trusted host binding; never accepted as a caller-controlled Scheme field."""

    create_binding: SecretCreate700DomainBinding
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
            domain_secret_binding_digest(self.create_binding, self.secret_object_ref, dependency_refs=(self.folder_object_ref, self.target_object_ref, self.template_object_ref, self.secret_object_ref))
            require_digest(self.requester_digest, "Domain requester digest")
            for name, value in asdict(self).items():
                if name not in {"create_binding", "requester_digest"}:
                    require_ref(value, "Domain planning reference")
            if len({self.folder_object_ref, self.target_object_ref,
                    self.template_object_ref, self.secret_object_ref}) != 4:
                raise ValueError
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None

    def expected_objects(self) -> dict[str, tuple[ObjectClass, dict[str, bool | str]]]:
        b = self
        return {
            b.folder_object_ref: (ObjectClass.FOLDER_BINDING, {"folder_ref": b.folder_ref}),
            b.target_object_ref: (ObjectClass.DOMAIN_TARGET_BINDING, {
                "profile_ref": b.target_profile_ref, "target_relation_matches": True,
            }),
            b.template_object_ref: (ObjectClass.TEMPLATE_BINDING, {
                "template_ref": b.template_ref, "compatibility": "compatible",
            }),
            b.secret_object_ref: (ObjectClass.DOMAIN_SECRET_METADATA,
                                  dict.fromkeys(_FIELDS, True)),
        }

    def validate_intent(
        self, draft: SchemeDraft, requester: AuthenticatedRequester,
    ) -> DomainSecretPlanningBinding:
        try:
            b = self
            if (
                draft.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.scheme_version != "1.0.0"
                or draft.blueprint_ref != "FPA-BP-014"
                or draft.outcome_code != "onboard_domain_account"
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



class DomainSecretPlanningSource:
    """Observe one private binding without accepting selectors from a draft."""

    mode = "source_backed"
    contract_registered = True

    def __init__(
        self, binding: DomainSecretPlanningBinding, transport: DomainSecretReadTransport,
    ) -> None:
        if type(binding) is not DomainSecretPlanningBinding or not callable(
            getattr(transport, "inspect_domain_account_projection", None),
        ):
            raise M4AdapterFailure(_UNAVAILABLE)
        self._binding = binding
        self._transport = transport

    def _expected(self) -> dict[str, tuple[ObjectClass, dict[str, bool | str]]]:
        return self._binding.expected_objects()

    def resolve_private_binding(
        self, draft: SchemeDraft, requester: AuthenticatedRequester,
    ) -> DomainSecretPlanningBinding:
        return self._binding.validate_intent(draft, requester)

    def inspect_domain_secret_binding_digest(
        self, draft: SchemeDraft, requester: AuthenticatedRequester,
    ) -> str:
        b = self.resolve_private_binding(draft, requester)
        return domain_secret_binding_digest(b.create_binding, b.secret_object_ref,
            dependency_refs=(b.folder_object_ref, b.target_object_ref, b.template_object_ref, b.secret_object_ref))

    def project(
        self, draft: SchemeDraft, requester: AuthenticatedRequester, *, now_epoch: int,
    ) -> tuple[AuthoritativeProjection, ...]:
        from .owner_session_metadata import OwnerSessionMetadataTransport
        if isinstance(self._transport, OwnerSessionMetadataTransport):
            with self._transport.authenticated():
                return self._project(draft, requester, now_epoch=now_epoch)
        return self._project(draft, requester, now_epoch=now_epoch)

    def _project(
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
                            if cls is ObjectClass.DOMAIN_SECRET_METADATA
                            and not result.secret_exists else {"exists": True, **fields}),
                )
                for ref, (cls, fields) in self._expected().items()
            )
        except Exception:
            raise M4AdapterFailure(_UNAVAILABLE) from None


PLANNING_BINDING_CONTRACT = "fortipam-700-domain-account-planning-binding-v1"
_PLANNING_REFERENCE_FIELDS = (
    "requester_digest", "environment_ref", "scope_ref", "folder_object_ref",
    "folder_ref", "target_object_ref", "target_profile_ref", "template_object_ref",
    "template_ref", "secret_object_ref",
)


def load_domain_secret_planning_binding(path: Path) -> DomainSecretPlanningBinding:
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
                    "contract", "folder_path", "secret_name", "target_name",
                    "target_ipv4_address", "domain_dns_root", "target_owner_name",
                    "target_classification_tag",
                    *_PLANNING_REFERENCE_FIELDS,
                }
                or any(type(value) is not str for value in payload.values())
                or payload["contract"] != PLANNING_BINDING_CONTRACT):
            raise ValueError
        create_binding = SecretCreate700DomainBinding(
            contract_ref="fortipam-700-build29-domain-account-create-candidate-v1",
            target_product_version="7.0.0", target_product_build=29,
            # Replaced with the authorized M4 digest when a runner is composed.
            plan_digest="0" * 64,
            folder_path=payload["folder_path"], secret_name=payload["secret_name"],
            template_name="Windows Domain Account",
            **{name: payload[name] for name in (
                "target_name", "target_ipv4_address", "domain_dns_root",
                "target_owner_name", "target_classification_tag",
            )},
        )
        return DomainSecretPlanningBinding(
            create_binding=create_binding,
            **{name: payload[name] for name in _PLANNING_REFERENCE_FIELDS},
        )
    except Exception:
        raise M4AdapterFailure(_UNAVAILABLE) from None
