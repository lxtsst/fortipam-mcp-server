"""Source-backed BP008 projection for one existing Secret approval binding.

The source proves only an existing fixed single-tier Approval Profile and the
categorical approval fields of one existing Secret. Product selectors stay in
an owner-only binding and no write or approval request is available here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from typing import Literal, Protocol, cast

from v4_planning import (
    AuthenticatedRequester,
    AuthoritativeProjection,
    FieldKind,
    FieldRule,
    ObjectClass,
    ProjectionContract,
    SchemeDraft,
    SchemeId,
)
from v4_planning.models import require_ref

from .approval_profile_ssh_transport import ApprovalProfileReadback
from .secret_metadata_http_transport import SecretApprovalProjectionInspection
from .secret_request_http_transport import SecretRequestObservationBinding


SOURCE_CONTRACT = "fortipam-approval-observe-binding-v1"
SOURCE_VERSION = "1.1.0"
SOURCE_REF = "fortipam-191-approval-observe-projection"
SOURCE_UNAVAILABLE = "FortiPAM approval and observation projection is unavailable."
_MAX_BINDING_BYTES = 16_384


class ApprovalAndObserveProjectionSourceError(RuntimeError):
    """Stable non-disclosing source failure."""


class SecretApprovalReadTransport(Protocol):
    def inspect_approval_projection(
        self,
        folder_path: str,
        secret_name: str,
        approval_profile_name: str,
        *,
        expected_secret_id: int,
    ) -> SecretApprovalProjectionInspection: ...


class ApprovalProfileReadTransport(Protocol):
    def readback(self, profile_name: str) -> ApprovalProfileReadback: ...


@dataclass(frozen=True, slots=True, repr=False)
class ApprovalAndObserveBinding:
    """Owner-protected selectors mapped to two opaque Scheme objects."""

    approval_profile_object_ref: str
    approval_profile_ref: str
    approval_profile_name: str
    secret_approval_object_ref: str
    folder_path: str
    secret_name: str
    secret_id: int

    def __post_init__(self) -> None:
        try:
            require_ref(self.approval_profile_object_ref, "approval profile object_ref")
            require_ref(self.approval_profile_ref, "approval profile_ref")
            require_ref(self.secret_approval_object_ref, "Secret approval object_ref")
        except ValueError as exc:
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        _bounded_text(self.approval_profile_name, 128)
        _bounded_text(self.secret_name, 128)
        _folder_path(self.folder_path)
        if type(self.secret_id) is not int or not 0 < self.secret_id <= 2_147_483_647:
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)


class ApprovalAndObserveBindingResolver(Protocol):
    def resolve(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> ApprovalAndObserveBinding: ...


class OwnerOnlyApprovalAndObserveBindingResolver:
    """Load one exact requester/scope-bound BP008 mapping."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        if not self._path.is_absolute():
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)

    def resolve(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> ApprovalAndObserveBinding:
        payload = self._load()
        exact_keys = {
            "contract",
            "version",
            "requester_digest",
            "environment_ref",
            "scope_ref",
            "approval_profile_object_ref",
            "approval_profile_ref",
            "approval_profile_name",
            "secret_approval_object_ref",
            "folder_path",
            "secret_name",
            "secret_id",
        }
        if (
            set(payload) != exact_keys
            or payload.get("contract") != SOURCE_CONTRACT
            or payload.get("version") != SOURCE_VERSION
            or payload.get("requester_digest") != requester.digest
            or payload.get("environment_ref") != draft.environment_ref
            or payload.get("scope_ref") != draft.scope_ref
        ):
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
        try:
            return ApprovalAndObserveBinding(
                approval_profile_object_ref=_string(
                    payload, "approval_profile_object_ref"
                ),
                approval_profile_ref=_string(payload, "approval_profile_ref"),
                approval_profile_name=_string(payload, "approval_profile_name"),
                secret_approval_object_ref=_string(
                    payload, "secret_approval_object_ref"
                ),
                folder_path=_string(payload, "folder_path"),
                secret_name=_string(payload, "secret_name"),
                secret_id=_positive_int(payload, "secret_id"),
            )
        except (TypeError, ValueError) as exc:
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE) from exc

    def _load(self) -> Mapping[str, object]:
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self._path, flags)
            try:
                info = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) & 0o077
                    or not 0 < info.st_size <= _MAX_BINDING_BYTES
                ):
                    raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
                content = os.read(descriptor, _MAX_BINDING_BYTES + 1)
            finally:
                os.close(descriptor)
            if len(content) > _MAX_BINDING_BYTES:
                raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
            value = json.loads(content)
        except ApprovalAndObserveProjectionSourceError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        if not isinstance(value, Mapping):
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
        return cast(Mapping[str, object], value)


class FortiPamApprovalAndObserveProjectionSource:
    """Reduce one fixed Profile and Secret to an executable-free BP008 preview."""

    mode = "source_backed"
    contract_registered = True

    def __init__(
        self,
        secret_transport: SecretApprovalReadTransport,
        approval_profile_transport: ApprovalProfileReadTransport,
        resolver: ApprovalAndObserveBindingResolver,
    ) -> None:
        self._secret_transport = secret_transport
        self._approval_profile_transport = approval_profile_transport
        self._resolver = resolver

    def project(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        *,
        now_epoch: int,
    ) -> tuple[AuthoritativeProjection, ...]:
        if (
            draft.scheme_id is not SchemeId.APPROVAL_AND_OBSERVE
            or draft.blueprint_ref != "FPA-BP-008"
            or draft.outcome_code != "require_interactive_approval"
            or type(now_epoch) is not int
        ):
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
        binding = self._binding(draft, requester)
        desired = {item.object_ref: item for item in draft.desired_objects}
        expected = {
            binding.approval_profile_object_ref: (
                ObjectClass.APPROVAL_PROFILE_BINDING,
                {
                    "profile_mode": "single_tier",
                    "profile_ref": binding.approval_profile_ref,
                },
            ),
            binding.secret_approval_object_ref: (
                ObjectClass.SECRET_APPROVAL_BINDING,
                {
                    "approval_profile_attached": True,
                    "interactive_approval_required": True,
                    "job_approval_required": False,
                    "owner_bypass_allowed": False,
                },
            ),
        }
        if (
            len(desired) != 2
            or set(desired) != set(expected)
            or any(
                item.object_class is not expected[object_ref][0]
                or not item.desired_exists
                or dict(item.desired_fields) != expected[object_ref][1]
                for object_ref, item in desired.items()
            )
        ):
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)

        profile = self._read_profile(binding.approval_profile_name)
        if not profile.verified:
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
        secret = self._read_secret(binding)
        if (
            not secret.secret_exists
            or (
                not secret.approval_profile_matches
                and not secret.approval_profile_unset
            )
        ):
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)

        fields: dict[str, dict[str, bool | str]] = {
            binding.approval_profile_object_ref: {
                "exists": True,
                "profile_mode": "single_tier",
                "profile_ref": binding.approval_profile_ref,
            },
            binding.secret_approval_object_ref: {
                "exists": True,
                "approval_profile_attached": secret.approval_profile_matches,
                "interactive_approval_required": (
                    secret.interactive_approval_required
                ),
                "job_approval_required": secret.job_approval_required,
                "owner_bypass_allowed": secret.owner_bypass_allowed,
            },
        }
        return tuple(
            AuthoritativeProjection.from_mapping(
                contract=approval_and_observe_projection_contract(
                    desired[item.object_ref].object_class
                ),
                object_ref=item.object_ref,
                observed_at=now_epoch,
                fresh_until=now_epoch + 300,
                fields=fields[item.object_ref],
            )
            for item in draft.desired_objects
        )

    def _binding(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> ApprovalAndObserveBinding:
        try:
            value = self._resolver.resolve(draft, requester)
        except Exception as exc:
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        if not isinstance(value, ApprovalAndObserveBinding):
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
        return value

    def resolve_private_binding(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> ApprovalAndObserveBinding:
        """Resolve protected selectors for the internal fixed-action binder."""

        return self._binding(draft, requester)

    def bind_request_observation(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
        *,
        request_ref: str,
        request_id: int,
        request_type: Literal["launcher", "job"] = "launcher",
    ) -> SecretRequestObservationBinding:
        """Bind one private request ID to this exact BP008 Secret relation."""

        if (
            draft.scheme_id is not SchemeId.APPROVAL_AND_OBSERVE
            or draft.blueprint_ref != "FPA-BP-008"
            or draft.outcome_code != "require_interactive_approval"
        ):
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
        binding = self._binding(draft, requester)
        if request_type not in {"launcher", "job"}:
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
        try:
            return SecretRequestObservationBinding(
                request_ref=request_ref,
                request_id=request_id,
                secret_id=binding.secret_id,
                requester_digest=requester.digest,
                environment_ref=draft.environment_ref,
                scope_ref=draft.scope_ref,
                request_type=request_type,
            )
        except Exception as exc:
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE) from exc

    def _read_profile(self, name: str) -> ApprovalProfileReadback:
        try:
            value = self._approval_profile_transport.readback(name)
        except Exception as exc:
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        if not isinstance(value, ApprovalProfileReadback):
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
        return value

    def _read_secret(
        self,
        binding: ApprovalAndObserveBinding,
    ) -> SecretApprovalProjectionInspection:
        try:
            value = self._secret_transport.inspect_approval_projection(
                binding.folder_path,
                binding.secret_name,
                binding.approval_profile_name,
                expected_secret_id=binding.secret_id,
            )
        except Exception as exc:
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE) from exc
        if not isinstance(value, SecretApprovalProjectionInspection):
            raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
        return value


def approval_and_observe_projection_contract(
    object_class: ObjectClass,
) -> ProjectionContract:
    rules: tuple[FieldRule, ...]
    if object_class is ObjectClass.APPROVAL_PROFILE_BINDING:
        rules = (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("profile_mode", FieldKind.ENUM, ("single_tier",)),
            FieldRule("profile_ref", FieldKind.REFERENCE),
        )
    elif object_class is ObjectClass.SECRET_APPROVAL_BINDING:
        rules = (
            FieldRule("exists", FieldKind.BOOLEAN),
            FieldRule("approval_profile_attached", FieldKind.BOOLEAN),
            FieldRule("interactive_approval_required", FieldKind.BOOLEAN),
            FieldRule("job_approval_required", FieldKind.BOOLEAN),
            FieldRule("owner_bypass_allowed", FieldKind.BOOLEAN),
        )
    else:
        raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
    return ProjectionContract(
        contract_id="approval-and-observe-state-v1",
        version="1.0.0",
        source_ref=SOURCE_REF,
        object_class=object_class,
        field_rules=rules,
        max_age_seconds=300,
    )


def _string(payload: Mapping[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
    return value


def _positive_int(payload: Mapping[str, object], field: str) -> int:
    value = payload.get(field)
    if type(value) is not int or not 0 < value <= 2_147_483_647:
        raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
    return value


def _bounded_text(value: str, maximum: int) -> str:
    if (
        not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
    return value


def _folder_path(value: str) -> str:
    _bounded_text(value, 1024)
    parts = value.split("/")
    if not parts or any(not part or part in {".", ".."} for part in parts):
        raise ApprovalAndObserveProjectionSourceError(SOURCE_UNAVAILABLE)
    return value


__all__ = [
    "ApprovalAndObserveBinding",
    "ApprovalAndObserveBindingResolver",
    "ApprovalAndObserveProjectionSourceError",
    "ApprovalProfileReadTransport",
    "FortiPamApprovalAndObserveProjectionSource",
    "OwnerOnlyApprovalAndObserveBindingResolver",
    "SOURCE_CONTRACT",
    "SOURCE_REF",
    "SOURCE_UNAVAILABLE",
    "SOURCE_VERSION",
    "SecretApprovalReadTransport",
    "approval_and_observe_projection_contract",
]
