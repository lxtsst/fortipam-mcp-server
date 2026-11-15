"""Two fixed original-role lab phases; no general role administration."""
from __future__ import annotations

from dataclasses import dataclass

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .ems_tag_identity_contract import _uid
from .ems_tag_role_contract import ProspectiveEmsTagManagerRole

CONTRACT = "ems-7.4.8.2245-original-tag-role-fixture-v1"
VERSION = "1.0.0"
TARGET_REF = "bound-original-ems-tag-role-fixture"
LAB_SCOPE = {"environment_ref": "ems-home-lab", "scope_ref": "ems-tag-role-fixture-lab", "audience_ref": "local-role-fixture"}
_ERROR = "The private original EMS role fixture is unavailable."


def action(phase: str) -> tuple[str, str]:
    if type(phase) is not str or phase not in {"create", "recover"}:
        raise ValueError(_ERROR)
    return "ems-tag-role-fixture-" + phase, CONTRACT + "-" + phase + "-m4"


def current_digest(draft: ProspectiveEmsTagManagerRole, scope: str, source: str, phase: str,
                   original: str | None) -> str:
    action(phase);draft.__post_init__()
    for value in (scope, source):require_digest(value, "role_fixture_scope")
    if original is not None:require_digest(original, "role_fixture_original")
    if (phase == "create") != (original is None):raise ValueError(_ERROR)
    return canonical_digest(dict(contract=CONTRACT, phase=phase, parameters=draft.parameters_digest,
        scope=scope, source=source, original=original))


def expected_digest(draft: ProspectiveEmsTagManagerRole, baseline: str, source: str, phase: str,
                    original: str | None) -> str:
    return canonical_digest(dict(contract=CONTRACT, postcondition="complete-fixed-effect",
        relation=current_digest(draft, baseline, source, phase, original)))


@dataclass(frozen=True, slots=True, repr=False)
class EmsRoleFixturePreview(_OpaqueC3Object):
    nonce: str
    current_digest: str
    scope_digest: str
    created_at: int
    expires_at: int
    signature: str


@dataclass(frozen=True, slots=True, repr=False)
class EmsRoleFixtureIssued(_OpaqueC3Object):
    phase: str
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    source_digest: str
    current_scope_digest: str
    baseline_digest: str
    original_digest: str | None


@dataclass(frozen=True, slots=True, repr=False)
class EmsRoleFixtureOriginal(_OpaqueC3Object):
    context_digest: str
    custody_digest: str
    baseline_digest: str
    created_scope_digest: str
    role_digest: str
    role_uid: str
    role_numeric_id: int

    def __post_init__(self) -> None:
        for value in (self.context_digest, self.custody_digest, self.baseline_digest,
                      self.created_scope_digest, self.role_digest):require_digest(value, "role_original")
        _uid(self.role_uid)
        if type(self.role_numeric_id) is not int or not -(2**63) < self.role_numeric_id < 2**63 or self.role_numeric_id == 0:
            raise ValueError(_ERROR)
