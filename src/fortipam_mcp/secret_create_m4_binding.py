"""Owner-only persistent binding for one Secret-create M4 authorization."""

from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
import stat
from typing import Protocol

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan
from v4_planning.material_provider import (
    C3MaterialBinding,
    MaterialLeaseRequest,
    MaterialProviderClass,
    MaterialPurpose,
)

from .secret_create_m4_runtime import (
    SecretCreateM4ExecutionBinding,
    SecretCreateM4RuntimeError,
)


SECRET_CREATE_M4_BINDING_CONTRACT = "fortipam-secret-create-m4-binding-v1"
SECRET_CREATE_M4_BINDING_VERSION = "1.0.0"
_MAX_BYTES = 65_536


class PrivateMaterialBindingResolver(Protocol):
    """Resolve a C3 binding only inside the private runtime."""

    def resolve(
        self,
        binding_ref: str,
        request: MaterialLeaseRequest,
    ) -> C3MaterialBinding: ...


class OwnerOnlySecretCreateM4BindingResolver:
    """Reconstruct one exact M4/C3 binding without persisting material."""

    def __init__(
        self,
        path: Path,
        material_resolver: PrivateMaterialBindingResolver,
    ) -> None:
        self._path = Path(path)
        self._material_resolver = material_resolver
        if not self._path.is_absolute() or not callable(
            getattr(material_resolver, "resolve", None)
        ):
            raise SecretCreateM4RuntimeError(
                "Protected Secret-create execution binding is unavailable."
            )

    def resolve_execution_binding(
        self,
        authorization_ref: str,
    ) -> SecretCreateM4ExecutionBinding:
        try:
            payload = self._load()
            if set(payload) != {
                "contract",
                "version",
                "material_binding_ref",
                "plan",
                "authorization",
                "lease_request",
                "policy_decision_digest",
                "scope_digest",
                "audience_digest",
            } or (
                payload.get("contract") != SECRET_CREATE_M4_BINDING_CONTRACT
                or payload.get("version") != SECRET_CREATE_M4_BINDING_VERSION
            ):
                raise SecretCreateM4RuntimeError(
                    "Protected Secret-create execution binding is unavailable."
                )
            plan = _plan(_mapping(payload, "plan"))
            authorization = _authorization(_mapping(payload, "authorization"))
            request = _request(_mapping(payload, "lease_request"))
            binding_ref = _text(payload, "material_binding_ref")
            if authorization.authorization_ref != authorization_ref:
                raise SecretCreateM4RuntimeError(
                    "Protected Secret-create execution binding is unavailable."
                )
            material_binding = self._material_resolver.resolve(binding_ref, request)
            if not isinstance(material_binding, C3MaterialBinding):
                raise SecretCreateM4RuntimeError(
                    "Protected Secret-create execution binding is unavailable."
                )
            return SecretCreateM4ExecutionBinding(
                plan,
                authorization,
                material_binding,
                request,
                _text(payload, "policy_decision_digest"),
                _text(payload, "scope_digest"),
                _text(payload, "audience_digest"),
            )
        except SecretCreateM4RuntimeError:
            raise
        except Exception as exc:
            raise SecretCreateM4RuntimeError(
                "Protected Secret-create execution binding is unavailable."
            ) from exc

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
                    or info.st_size <= 0
                    or info.st_size > _MAX_BYTES
                ):
                    raise SecretCreateM4RuntimeError(
                        "Protected Secret-create execution binding is unavailable."
                    )
                content = os.read(descriptor, _MAX_BYTES + 1)
            finally:
                os.close(descriptor)
            if len(content) > _MAX_BYTES:
                raise SecretCreateM4RuntimeError(
                    "Protected Secret-create execution binding is unavailable."
                )
            value = json.loads(content)
        except SecretCreateM4RuntimeError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SecretCreateM4RuntimeError(
                "Protected Secret-create execution binding is unavailable."
            ) from exc
        if not isinstance(value, Mapping):
            raise SecretCreateM4RuntimeError(
                "Protected Secret-create execution binding is unavailable."
            )
        return {str(key): item for key, item in value.items()}


def _plan(value: Mapping[str, object]) -> M4ExecutionPlan:
    expected = {
        "plan_ref",
        "revision",
        "action_id",
        "action_version",
        "adapter_ref",
        "target_ref",
        "requester_digest",
        "summary_digest",
        "confirmation_digest",
        "approval_digest",
        "parameters_digest",
        "expected_current_digest",
        "expected_state_digest",
        "idempotency_digest",
        "expires_at",
        "compensation_ref",
        "plan_digest",
    }
    if set(value) != expected:
        raise SecretCreateM4RuntimeError(
            "Protected Secret-create execution binding is unavailable."
        )
    return M4ExecutionPlan(
        plan_ref=_text(value, "plan_ref"),
        revision=_integer(value, "revision"),
        action_id=_text(value, "action_id"),
        action_version=_text(value, "action_version"),
        adapter_ref=_text(value, "adapter_ref"),
        target_ref=_text(value, "target_ref"),
        requester_digest=_text(value, "requester_digest"),
        summary_digest=_text(value, "summary_digest"),
        confirmation_digest=_text(value, "confirmation_digest"),
        approval_digest=_text(value, "approval_digest"),
        parameters_digest=_text(value, "parameters_digest"),
        expected_current_digest=_text(value, "expected_current_digest"),
        expected_state_digest=_text(value, "expected_state_digest"),
        idempotency_digest=_text(value, "idempotency_digest"),
        expires_at=_integer(value, "expires_at"),
        compensation_ref=_optional_text(value, "compensation_ref"),
        plan_digest=_text(value, "plan_digest"),
    )


def _authorization(value: Mapping[str, object]) -> M4ExecutionAuthorization:
    expected = {
        "authorization_ref",
        "plan_ref",
        "plan_digest",
        "requester_digest",
        "confirmation_ref",
        "confirmation_digest",
        "approval_ref",
        "approval_digest",
        "approver_digest",
        "issued_at",
        "expires_at",
        "one_time",
        "execution_authorized",
        "authorization_digest",
    }
    if set(value) != expected:
        raise SecretCreateM4RuntimeError(
            "Protected Secret-create execution binding is unavailable."
        )
    return M4ExecutionAuthorization(
        authorization_ref=_text(value, "authorization_ref"),
        plan_ref=_text(value, "plan_ref"),
        plan_digest=_text(value, "plan_digest"),
        requester_digest=_text(value, "requester_digest"),
        confirmation_ref=_text(value, "confirmation_ref"),
        confirmation_digest=_text(value, "confirmation_digest"),
        approval_ref=_text(value, "approval_ref"),
        approval_digest=_text(value, "approval_digest"),
        approver_digest=_text(value, "approver_digest"),
        issued_at=_integer(value, "issued_at"),
        expires_at=_integer(value, "expires_at"),
        one_time=_boolean(value, "one_time"),
        execution_authorized=_boolean(value, "execution_authorized"),
        authorization_digest=_text(value, "authorization_digest"),
    )


def _request(value: Mapping[str, object]) -> MaterialLeaseRequest:
    expected = {
        "action_id",
        "action_version",
        "plan_digest",
        "policy_decision_digest",
        "authorization_digest",
        "scope_digest",
        "audience_digest",
        "provider_class",
        "purpose",
        "requested_at",
        "expires_at",
    }
    if set(value) != expected:
        raise SecretCreateM4RuntimeError(
            "Protected Secret-create execution binding is unavailable."
        )
    return MaterialLeaseRequest(
        action_id=_text(value, "action_id"),
        action_version=_text(value, "action_version"),
        plan_digest=_text(value, "plan_digest"),
        policy_decision_digest=_text(value, "policy_decision_digest"),
        authorization_digest=_text(value, "authorization_digest"),
        scope_digest=_text(value, "scope_digest"),
        audience_digest=_text(value, "audience_digest"),
        provider_class=MaterialProviderClass(_text(value, "provider_class")),
        purpose=MaterialPurpose(_text(value, "purpose")),
        requested_at=_integer(value, "requested_at"),
        expires_at=_integer(value, "expires_at"),
    )


def _mapping(value: Mapping[str, object], field: str) -> Mapping[str, object]:
    result = value.get(field)
    if not isinstance(result, Mapping):
        raise SecretCreateM4RuntimeError(
            "Protected Secret-create execution binding is unavailable."
        )
    return {str(key): item for key, item in result.items()}


def _text(value: Mapping[str, object], field: str) -> str:
    result = value.get(field)
    if not isinstance(result, str) or not result:
        raise SecretCreateM4RuntimeError(
            "Protected Secret-create execution binding is unavailable."
        )
    return result


def _optional_text(value: Mapping[str, object], field: str) -> str | None:
    result = value.get(field)
    if result is not None and not isinstance(result, str):
        raise SecretCreateM4RuntimeError(
            "Protected Secret-create execution binding is unavailable."
        )
    return result


def _integer(value: Mapping[str, object], field: str) -> int:
    result = value.get(field)
    if type(result) is not int:
        raise SecretCreateM4RuntimeError(
            "Protected Secret-create execution binding is unavailable."
        )
    return result


def _boolean(value: Mapping[str, object], field: str) -> bool:
    result = value.get(field)
    if type(result) is not bool:
        raise SecretCreateM4RuntimeError(
            "Protected Secret-create execution binding is unavailable."
        )
    return result


__all__ = [
    "OwnerOnlySecretCreateM4BindingResolver",
    "PrivateMaterialBindingResolver",
    "SECRET_CREATE_M4_BINDING_CONTRACT",
    "SECRET_CREATE_M4_BINDING_VERSION",
]
