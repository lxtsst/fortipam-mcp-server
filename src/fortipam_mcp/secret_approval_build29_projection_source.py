"""Unregistered build-29 BP008 categorical projection, with no material reads.

The trusted transports must independently qualify the fixed actual getters.
Binding files and callbacks do not establish runtime or execution maturity.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, fields
import json
import os
from pathlib import Path
import stat
from typing import Protocol, cast

from v4_planning import (
    AuthenticatedRequester, AuthoritativeProjection, FieldKind, FieldRule,
    ObjectClass, ProjectionContract, SchemeDraft, SchemeId,
)

from .approval_and_observe_projection_source import (
    ApprovalAndObserveBinding, ApprovalAndObserveBindingResolver,
    SecretApprovalReadTransport,
)
from .secret_metadata_http_transport import SecretApprovalProjectionInspection


SOURCE_REF = "fortipam-700-build29-approval-observe-projection"
PROJECTION_CONTRACT = "approval-and-observe-build29-state-v1"
PROJECTION_VERSION = "1.0.0"
SOURCE_CONTRACT = "fortipam-700-build29-approval-observe-binding-v1"
SOURCE_VERSION = "1.0.0"
SOURCE_UNAVAILABLE = "FortiPAM build-29 approval projection is unavailable."
_MAX_BINDING_BYTES = 16_384
_BINDING_KEYS = frozenset({
    "contract", "version", "requester_digest", "environment_ref", "scope_ref",
    "approval_profile_object_ref", "approval_profile_ref", "approval_profile_name",
    "secret_approval_object_ref", "folder_path", "secret_name", "secret_id",
})


class SecretApprovalBuild29ProjectionSourceError(RuntimeError):
    """Stable non-disclosing failure of this independent source contract."""


def _deny() -> SecretApprovalBuild29ProjectionSourceError:
    return SecretApprovalBuild29ProjectionSourceError(SOURCE_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class SecretApprovalBuild29ProfileInspection:
    """Private categories for the separately qualified build-29 single Profile.

    Notification/schedule qualification includes empty auto-approval schedule,
    zero maximum duration, disabled remote email, empty email template and no
    approver permission requirement. Source identity and exact first-user
    binding are qualified by the protected actual getter, not inferred here.
    """

    profile_matches: bool
    single_tier_enabled: bool
    first_approval_count_one: bool
    fixed_approver_present: bool
    other_principals_disabled: bool
    self_approval_disabled: bool
    empty_custom_fields: bool
    notifications_schedules_unset: bool

    @property
    def verified(self) -> bool:
        return all(type(value) is bool and value for value in (
            getattr(self, field.name) for field in fields(self)
        ))


class SecretApprovalBuild29ProfileReadTransport(Protocol):
    def readback(self, profile_name: str) -> SecretApprovalBuild29ProfileInspection: ...


class OwnerOnlySecretApprovalBuild29BindingResolver:
    """Resolve one exact owner-only build-29 requester/environment/scope binding."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
            raise _deny()
        self._path = path

    def resolve(
        self, draft: SchemeDraft, requester: AuthenticatedRequester,
    ) -> ApprovalAndObserveBinding:
        try:
            _qualify_scheme(draft, requester)
            payload = self._load()
            if (set(payload) != _BINDING_KEYS
                    or any(type(value) is not str for name, value in payload.items() if name != "secret_id")
                    or payload["contract"] != SOURCE_CONTRACT
                    or payload["version"] != SOURCE_VERSION
                    or payload["requester_digest"] != requester.digest
                    or payload["environment_ref"] != draft.environment_ref
                    or payload["scope_ref"] != draft.scope_ref
                    or type(payload["secret_id"]) is not int):
                raise ValueError
            return ApprovalAndObserveBinding(
                approval_profile_object_ref=cast(str, payload["approval_profile_object_ref"]),
                approval_profile_ref=cast(str, payload["approval_profile_ref"]),
                approval_profile_name=cast(str, payload["approval_profile_name"]),
                secret_approval_object_ref=cast(str, payload["secret_approval_object_ref"]),
                folder_path=cast(str, payload["folder_path"]),
                secret_name=cast(str, payload["secret_name"]),
                secret_id=cast(int, payload["secret_id"]),
            )
        except Exception:
            raise _deny() from None

    def _load(self) -> Mapping[str, object]:
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in self._path.parts[1:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
                os.close(directory)
                directory = child
            descriptor = os.open(
                self._path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory,
            )
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o600
                        or not 0 < info.st_size <= _MAX_BINDING_BYTES):
                    raise ValueError
                content = os.read(descriptor, _MAX_BINDING_BYTES + 1)
                final = os.fstat(descriptor)
                if (not 0 < len(content) <= _MAX_BINDING_BYTES or len(content) != info.st_size
                        or (final.st_size, final.st_mtime_ns, final.st_ctime_ns)
                        != (info.st_size, info.st_mtime_ns, info.st_ctime_ns)):
                    raise ValueError
            finally:
                os.close(descriptor)
        finally:
            os.close(directory)
        value = json.loads(content, object_pairs_hook=_unique_members, parse_constant=_reject_constant)
        if type(value) is not dict:
            raise ValueError
        return cast(Mapping[str, object], value)


class FortiPamSecretApprovalBuild29ProjectionSource:
    """Project only the fixed two-object BP008 interactive-approval outcome."""

    mode = "source_backed"
    contract_registered = False

    def __init__(
        self, secret_transport: SecretApprovalReadTransport,
        approval_profile_transport: SecretApprovalBuild29ProfileReadTransport,
        resolver: ApprovalAndObserveBindingResolver, *, contract_registered: bool = False,
    ) -> None:
        if type(contract_registered) is not bool:
            raise _deny()
        self._secret_transport = secret_transport
        self._approval_profile_transport = approval_profile_transport
        self._resolver = resolver
        # Registration describes only installation of this read-only contract.
        # It neither qualifies transport callbacks nor opens a mutation gate.
        self.contract_registered = contract_registered

    def resolve_private_binding(
        self, draft: SchemeDraft, requester: AuthenticatedRequester,
    ) -> ApprovalAndObserveBinding:
        """Resolve sealed selectors for the separate fixed internal binder."""
        try:
            _qualify_scheme(draft, requester)
            binding = self._resolver.resolve(draft, requester)
            if type(binding) is not ApprovalAndObserveBinding:
                raise ValueError
            _qualify_desired(draft, binding)
            return binding
        except Exception:
            raise _deny() from None

    def project(
        self, draft: SchemeDraft, requester: AuthenticatedRequester, *, now_epoch: int,
    ) -> tuple[AuthoritativeProjection, ...]:
        try:
            if type(now_epoch) is not int or now_epoch < 0:
                raise ValueError
            binding = self.resolve_private_binding(draft, requester)
            profile = self._approval_profile_transport.readback(binding.approval_profile_name)
            if (type(profile) is not SecretApprovalBuild29ProfileInspection
                    or any(type(getattr(profile, field.name)) is not bool for field in fields(profile))
                    or not profile.verified):
                raise ValueError
            secret = self._secret_transport.inspect_approval_projection(
                binding.folder_path, binding.secret_name, binding.approval_profile_name,
                expected_secret_id=binding.secret_id,
            )
            if (type(secret) is not SecretApprovalProjectionInspection
                    or any(type(getattr(secret, field.name)) is not bool for field in fields(secret))
                    or not secret.secret_exists
                    or secret.approval_profile_matches is secret.approval_profile_unset):
                raise ValueError
            values: dict[str, dict[str, bool | str]] = {
                binding.approval_profile_object_ref: {
                    "exists": True, "profile_mode": "single_tier",
                    "profile_ref": binding.approval_profile_ref,
                },
                binding.secret_approval_object_ref: {
                    "exists": True, "approval_profile_attached": secret.approval_profile_matches,
                    "interactive_approval_required": secret.interactive_approval_required,
                    "job_approval_required": secret.job_approval_required,
                    "owner_bypass_allowed": secret.owner_bypass_allowed,
                },
            }
            return tuple(AuthoritativeProjection.from_mapping(
                contract=secret_approval_build29_projection_contract(item.object_class),
                object_ref=item.object_ref, observed_at=now_epoch, fresh_until=now_epoch + 300,
                fields=values[item.object_ref],
            ) for item in draft.desired_objects)
        except Exception:
            raise _deny() from None


def _qualify_scheme(draft: SchemeDraft, requester: AuthenticatedRequester) -> None:
    if (type(draft) is not SchemeDraft or type(requester) is not AuthenticatedRequester
            or requester.principal_class != "operator"
            or draft.scheme_id is not SchemeId.APPROVAL_AND_OBSERVE
            or draft.scheme_version != "1.0.0" or draft.registry_schema_version != "1.1.0"
            or draft.blueprint_ref != "FPA-BP-008"
            or draft.outcome_code != "require_interactive_approval"
            or draft.material_reference_metadata is not None):
        raise ValueError


def _qualify_desired(draft: SchemeDraft, binding: ApprovalAndObserveBinding) -> None:
    expected: dict[str, tuple[ObjectClass, dict[str, bool | str]]] = {
        binding.approval_profile_object_ref: (ObjectClass.APPROVAL_PROFILE_BINDING, {
            "profile_mode": "single_tier", "profile_ref": binding.approval_profile_ref,
        }),
        binding.secret_approval_object_ref: (ObjectClass.SECRET_APPROVAL_BINDING, {
            "approval_profile_attached": True, "interactive_approval_required": True,
            "job_approval_required": False, "owner_bypass_allowed": False,
        }),
    }
    if (len(draft.desired_objects) != 2 or len(expected) != 2
            or {item.object_ref for item in draft.desired_objects} != set(expected)):
        raise ValueError
    for item in draft.desired_objects:
        object_class, expected_fields = expected[item.object_ref]
        actual = dict(item.desired_fields)
        if (item.object_class is not object_class or item.desired_exists is not True
                or set(actual) != set(expected_fields)
                or any(type(actual[name]) is not type(value) or actual[name] != value
                       for name, value in expected_fields.items())):
            raise ValueError


def secret_approval_build29_projection_contract(object_class: ObjectClass) -> ProjectionContract:
    rules: tuple[FieldRule, ...]
    if object_class is ObjectClass.APPROVAL_PROFILE_BINDING:
        rules = (FieldRule("exists", FieldKind.BOOLEAN),
                 FieldRule("profile_mode", FieldKind.ENUM, ("single_tier",)),
                 FieldRule("profile_ref", FieldKind.REFERENCE))
    elif object_class is ObjectClass.SECRET_APPROVAL_BINDING:
        rules = tuple(FieldRule(name, FieldKind.BOOLEAN) for name in (
            "exists", "approval_profile_attached", "interactive_approval_required",
            "job_approval_required", "owner_bypass_allowed",
        ))
    else:
        raise _deny()
    return ProjectionContract(
        contract_id=PROJECTION_CONTRACT, version=PROJECTION_VERSION, source_ref=SOURCE_REF,
        object_class=object_class, field_rules=rules, max_age_seconds=300,
    )


def _unique_members(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError
