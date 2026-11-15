"""Private independent-material execution inputs, never grants or source proof.

Only classified scalar configuration and opaque binding facts are retained.
Observed protected values are disposed and never become a credential source.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .approval_delivery_contract import _checked_nonmaterial, SCHEMA_METADATA_SHA256
from .approval_delivery_material_contract import (
    ApprovalDeliveryMaterialDraft, prepare_material_approval_delivery, _ROLES,
)
from .approval_delivery_material import ApprovalDeliveryMaterialBinding
from .approval_delivery_source import ApprovalDeliverySource
from .approval_delivery_transition import _nonmaterial_values

CONTRACT = "fortipam-build29-approval-email-independent-material-intent-local/v1"
_ERROR = "The private approval-delivery execution input is unavailable."


@dataclass(frozen=True, slots=True, repr=False, init=False)
class ApprovalDeliveryReadback(_OpaqueC3Object):
    _values: tuple[tuple[str, Any], ...]
    serial_digest: str
    schema_digest: str
    source_digest: str
    observed_at: int
    expires_at: int

    def __init__(self, values: Mapping[str, Any], *, serial_digest: str, source_digest: str,
            observed_at: int, expires_at: int) -> None:
        selected = _checked_nonmaterial(values)
        for digest in (serial_digest, source_digest): require_digest(digest, "Approval Email readback")
        if (type(observed_at) is not int or type(expires_at) is not int
                or not 0 <= observed_at < expires_at <= observed_at + 10):
            raise ValueError(_ERROR)
        for name, value in dict(_values=tuple(selected.items()), serial_digest=serial_digest,
                schema_digest=SCHEMA_METADATA_SHA256, source_digest=source_digest,
                observed_at=observed_at, expires_at=expires_at).items():
            object.__setattr__(self, name, value)

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT, values=dict(self._values),
            serial=self.serial_digest, schema=self.schema_digest, source=self.source_digest))


def readback_from_approval_source(source: ApprovalDeliverySource, *, source_digest: str,
        clock: Callable[[], int]) -> ApprovalDeliveryReadback:
    """Consume an already read source; retain no protected wire value or view."""
    try:
        try:
            if type(source) is not ApprovalDeliverySource or not callable(clock): raise ValueError
            with source._lock:
                projection = source._projection
                if projection is None or projection._closed or source._deadline is None: raise ValueError
                remaining = source._remaining(source._deadline)
                now = clock()
                result = ApprovalDeliveryReadback(dict(projection._values),
                    serial_digest=canonical_digest(dict(serial=source._serial)), source_digest=source_digest,
                    observed_at=now, expires_at=now + min(10, int(remaining)))
                source._remaining(source._deadline)
        finally:
            if type(source) is ApprovalDeliverySource: source.close()
        return result
    except Exception:
        raise ValueError(_ERROR) from None


@dataclass(frozen=True, slots=True, repr=False, init=False)
class ApprovalDeliveryExecutionIntent(_OpaqueC3Object):
    original: ApprovalDeliveryReadback
    original_draft: ApprovalDeliveryMaterialDraft
    proposed: ApprovalDeliveryMaterialDraft

    def __init__(self, original: ApprovalDeliveryReadback, proposed: Mapping[str, Any], *, enabled: bool,
            original_material_bindings: Mapping[str, str], proposed_material_bindings: Mapping[str, str]) -> None:
        try:
            if type(original) is not ApprovalDeliveryReadback: raise ValueError
            values = dict(original._values)
            protocol = values["approval-email-protocol"]
            original_enabled = bool(values["server"]) if protocol == "ms-graph" else bool(values["server"] or values["email-pulling-server"])
            old = prepare_material_approval_delivery(values, enabled=original_enabled,
                material_binding_digests=original_material_bindings)
            if _nonmaterial_values(old) != values: raise ValueError
            new = prepare_material_approval_delivery(proposed, enabled=enabled,
                material_binding_digests=proposed_material_bindings)
            for name, value in dict(original=original, original_draft=old, proposed=new).items():
                object.__setattr__(self, name, value)
        except Exception:
            raise ValueError(_ERROR) from None

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT, original=self.original.digest,
            old=self.original_draft.request_nonmaterial_digest, new=self.proposed.request_nonmaterial_digest))

    def expected_readback(self) -> ApprovalDeliveryReadback:
        return ApprovalDeliveryReadback(_nonmaterial_values(self.proposed), serial_digest=self.original.serial_digest,
            source_digest=self.original.source_digest, observed_at=self.original.observed_at,
            expires_at=self.original.expires_at)

    def material_binding(self, *, restore: bool = False) -> ApprovalDeliveryMaterialBinding:
        return ApprovalDeliveryMaterialBinding(self.original_draft if restore else self.proposed, restore=restore)

    def preview(self) -> dict[str, object]:
        current, expected = dict(self.original._values), _nonmaterial_values(self.proposed)
        changed_roles = [role for role, before, after in zip(_ROLES,
            self.original_draft._binding_digests, self.proposed._binding_digests, strict=True) if before != after]
        return {"contract": CONTRACT,
            "Current State": {"selected_field_count": 14, "complete_singleton_qualified": False},
            "Proposed Changes": {"enabled_intent": self.proposed.enabled, "protocol": self.proposed.protocol,
                "changed_nonmaterial_fields": sorted(key for key in current if current[key] != expected[key]),
                "changed_protected_roles": changed_roles},
            "Expected State": {"nonmaterial_matches_sdk_request": True, "independent_material_required": True,
                "exact_local_nonmaterial_inverse": True},
            "material_binding_is_custody_proof": False, "native_semantics_qualified": False,
            "execution_authorized": False, "independent_restore_authorized": False}
