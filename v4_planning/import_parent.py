"""Private file-import parent records for the existing protected plan ledger.

These records are not M2 Schemes or executable plans. Only a trusted, explicitly
enabled laboratory composition may confirm their intent. Every child still
requires its own current-state, permission and M4 authorization checks.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from typing import Any, Mapping, cast

from .canonical import CanonicalValue, canonical_digest
from .material_provider import _OpaqueC3Object
from .models import PlanningContractError, require_digest, require_ref

CONTRACT = 'fortipam-private-file-import-parent-v1'


@dataclass(frozen=True, slots=True, repr=False)
class FileImportPlanLine(_OpaqueC3Object):
    line_ref: str
    kind: str
    effect: str
    index: int
    parameters_digest: str
    current_digest: str
    expected_digest: str
    idempotency_digest: str | None
    depends_on: tuple[str, ...]

    def __post_init__(self) -> None:
        require_ref(self.line_ref, 'import line')
        for value in (self.parameters_digest, self.current_digest, self.expected_digest):
            require_digest(value, 'import line state')
        if (self.kind not in ('target', 'secret') or self.effect not in ('create', 'update', 'reuse')
                or self.kind == 'secret' and self.effect != 'create'
                or type(self.index) is not int or not 0 <= self.index < 256
                or type(self.depends_on) is not tuple or len(self.depends_on) > 2
                or len(set(self.depends_on)) != len(self.depends_on)
                or self.kind == 'target' and self.depends_on):
            raise PlanningContractError('Private import line is invalid.')
        if self.effect == 'reuse':
            if self.idempotency_digest is not None or self.current_digest != self.expected_digest:
                raise PlanningContractError('Private import prerequisite is invalid.')
        else:
            require_digest(self.idempotency_digest, 'import mutation identity')  # type: ignore[arg-type]
        for ref in self.depends_on:
            require_ref(ref, 'import dependency')

    def as_dict(self) -> dict[str, CanonicalValue]:
        return cast(dict[str, CanonicalValue], {**asdict(self), 'depends_on': list(self.depends_on)})


@dataclass(frozen=True, slots=True, repr=False)
class FileImportParentRecord(_OpaqueC3Object):
    plan_ref: str
    requester_digest: str
    environment_digest: str
    scope_digest: str
    audience_digest: str
    parent_idempotency_digest: str
    input_commitment: str
    source_commitment: str
    dependency_commitment: str
    namespace_key_digest: str
    source_policy_digest: str
    owner_decision_digest: str
    intent_policy_digest: str
    row_count: int
    lines: tuple[FileImportPlanLine, ...]
    created_at: int
    expires_at: int
    plan_digest: str

    @property
    def revision(self) -> int:
        return 1

    def canonical_content(self) -> dict[str, CanonicalValue]:
        # Fixed 64-node groups fit the unchanged shared canonical profile.
        # They preserve every atomic node; no group is a dispatchable action.
        value = {field.name: getattr(self, field.name) for field in fields(self)
                 if field.name not in ('lines', 'plan_digest')}
        value.update(contract=CONTRACT, policy_mode='lab_auto', dispatchable=False,
                     line_groups=[[line.as_dict() for line in self.lines[start:start + 64]]
                                  for start in range(0, len(self.lines), 64)])
        return cast(dict[str, CanonicalValue], value)

    def as_dict(self) -> dict[str, CanonicalValue]:
        return {**self.canonical_content(), 'plan_digest': self.plan_digest}

    def __post_init__(self) -> None:
        require_ref(self.plan_ref, 'import parent')
        for field in fields(self):
            if field.name.endswith(('_digest', '_commitment')):
                require_digest(getattr(self, field.name), 'import parent pin')
        if (type(self.row_count) is not int or not 1 <= self.row_count <= 256
                or type(self.created_at) is not int or type(self.expires_at) is not int
                or not 0 <= self.created_at < self.expires_at < 2**31
                or self.expires_at - self.created_at > 60
                or type(self.lines) is not tuple or not self.row_count <= len(self.lines) <= 512):
            raise PlanningContractError('Private import parent is invalid.')
        seen: dict[str, FileImportPlanLine] = {}
        identities: set[str] = set()
        indices: dict[str, set[int]] = {'target': set(), 'secret': set()}
        for line in self.lines:
            if type(line) is not FileImportPlanLine:
                raise PlanningContractError('Private import parent line is invalid.')
            line.__post_init__()
            if (line.line_ref in seen or line.index in indices[line.kind]
                    or any(ref not in seen for ref in line.depends_on)
                    or len({seen[ref].kind for ref in line.depends_on}) != len(line.depends_on)):
                raise PlanningContractError('Private import dependencies are invalid.')
            if line.idempotency_digest is not None:
                if line.idempotency_digest in identities:
                    raise PlanningContractError('Private import mutation identity is duplicated.')
                identities.add(line.idempotency_digest)
            seen[line.line_ref] = line
            indices[line.kind].add(line.index)
        if (indices['secret'] != set(range(self.row_count))
                or indices['target'] != set(range(len(indices['target'])))
                or len(indices['target']) > self.row_count
                or any(line.kind == 'target' and not any(line.line_ref in child.depends_on
                       for child in self.lines if child.kind == 'secret') for line in self.lines)):
            raise PlanningContractError('Private import graph is incomplete.')
        if self.plan_digest != canonical_digest(self.canonical_content()):
            raise PlanningContractError('Private import parent digest is invalid.')

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> FileImportParentRecord:
        expected = {field.name for field in fields(cls)} - {'lines'}
        if (set(payload) != expected | {'contract', 'policy_mode', 'dispatchable', 'line_groups'}
                or payload['contract'] != CONTRACT or payload['policy_mode'] != 'lab_auto'
                or payload['dispatchable'] is not False):
            raise PlanningContractError('Private import parent payload is invalid.')
        groups = payload['line_groups']
        if type(groups) is not list or not 1 <= len(groups) <= 8:
            raise PlanningContractError('Private import groups are invalid.')
        lines = []
        for index, group in enumerate(groups):
            if (type(group) is not list or not 1 <= len(group) <= 64
                    or index < len(groups) - 1 and len(group) != 64):
                raise PlanningContractError('Private import groups are invalid.')
            for item in group:
                if (type(item) is not dict or set(item) != {field.name for field in fields(FileImportPlanLine)}
                        or type(item['depends_on']) is not list):
                    raise PlanningContractError('Private import line payload is invalid.')
                lines.append(FileImportPlanLine(**{**item, 'depends_on': tuple(item['depends_on'])}))
        values = {name: payload[name] for name in expected}
        return cls(**cast(dict[str, Any], {**values, 'lines': tuple(lines)}))
