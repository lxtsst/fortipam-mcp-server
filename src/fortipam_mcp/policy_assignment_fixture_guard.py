"""Private normal-Web custody, complete retention and effective Policy source.

This joins an already admitted original-ACK lifecycle to the existing fixed
readers. It supplies no activity-absence assertion, action grant or Tool.
Baseline qualification is an explicit trusted-composition step; ordinary
metadata previews do not retrieve credentials.
"""
from __future__ import annotations

from collections.abc import Mapping
import json
import hashlib
from typing import Any, Literal
from urllib.parse import quote

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from .isolated_folder_creation_ownership import IsolatedFolderCreationOwnership
from .isolated_folder_policy_transition_contract import IsolatedFolderPolicyTransitionBinding
from .owner_session_metadata import OwnerSessionMetadataTransport
from .policy_assignment_preservation import PolicyAssignmentPreservation
from .policy_assignment_relation import (
    PolicyAssignmentRelation, PolicyAssignmentRelationBinding, _FOLDER, _detail,
    consume_policy_assignment_relation,
)
from .secret_metadata_http_transport import MAX_RESPONSE_BYTES, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .target_preservation_contract import _member_count
from .v4_plan_runtime import V4PlanningPrincipal
from .web_secret_fixture_api_preservation_reader import WebSecretFixtureApiPreservationReader, _PolicyPhase
from .web_secret_fixture_lifecycle import WebSecretFixtureLifecycleFactory

_ERROR = "The private Policy fixture source is unavailable."
_SECRET_FIELDS = "id|name|folder|template|target|uuid|policy|recording|http-service-status|need-approval|need-approval-job"
_FOLDER_FIELDS = ("id|name|folder-type|parent-folder|inherit-policy|inherit-permission|inherit-folder-ztna|"
                  "secret-policy|ztna-ems-tag|ztna-tags-match-logic|user-permission|group-permission")


class PolicyAssignmentFixtureGuardError(ValueError):
    """Categorical refusal without locators, material or partial witnesses."""


class PolicyAssignmentFixtureGuard(_OpaqueC3Object):
    def __init__(self, lifecycle: WebSecretFixtureLifecycleFactory, *,
                 inherited_policy_name: str, assigned_policy_name: str) -> None:
        try:
            if type(lifecycle) is not WebSecretFixtureLifecycleFactory:
                raise ValueError
            lifecycle._current()
            runner = lifecycle._runner
            if runner is None or runner._state != "baseline" or runner._guard_source is None:
                raise ValueError
            guard = runner._guard_source
            guard._guard()
            record = guard._record
            if (guard._state != "baseline" or guard._witness is None
                    or guard._source_observer is not None or guard._reconciled_source is not None
                    or guard._transition_reference is not None or record._ack_capture is None
                    or record._ack_capture.observe_source or inherited_policy_name == assigned_policy_name):
                raise ValueError
            self._lifecycle, self._runner, self._guard, self._record = lifecycle, runner, guard, record
            self._principal = runner._principal
            self._original = record.read_acknowledged_creation()
            self._row = json.loads(self._original.creation.baseline_json)
            self._source, self._original_witness = guard._source, guard._witness
            self._inherited, self._assigned = inherited_policy_name, assigned_policy_name
            for name in (self._inherited, self._assigned):
                self._binding(name).__post_init__()
            phases: dict[_PolicyPhase, str] = {
                "policy-baseline": self._inherited,
                "policy-assign-current": self._inherited, "policy-assign-dispatch": self._inherited,
                "policy-assigned": self._assigned, "policy-restore-current": self._assigned,
                "policy-restore-dispatch": self._assigned, "policy-restored": self._inherited,
            }
            self._readers = {phase: WebSecretFixtureApiPreservationReader(record, instruction_profile_name="",
                credential_envelope=guard._baseline._credential_envelope,
                totp_envelope=guard._baseline._totp_envelope, phase=phase, policy_name=name,
                client_factory=guard._factory, clock=guard._http_clock) for phase, name in phases.items()}
            self._baseline: PolicyAssignmentPreservation | None = None
            self._local()
        except Exception:
            raise PolicyAssignmentFixtureGuardError(_ERROR) from None

    def _binding(self, policy: str) -> PolicyAssignmentRelationBinding:
        return PolicyAssignmentRelationBinding(self._row["id"], self._row["name"], self._row["folder"],
            self._row["uuid"], policy, self._original.creation.serial_digest)

    def _local(self) -> None:
        self._lifecycle._current()
        self._guard._guard()
        if (self._lifecycle._runner is not self._runner or self._runner._guard_source is not self._guard
                or self._runner._principal != self._principal
                or self._runner._state != "baseline" or self._guard._state != "baseline"
                or self._guard._record is not self._record or self._guard._source != self._source
                or self._guard._witness != self._original_witness or self._guard._transition_reference is not None
                or self._guard._source_observer is not None or self._guard._reconciled_source is not None
                or self._record._ack_capture is None or self._record._ack_capture.observe_source
                or self._record.read_acknowledged_creation() != self._original
                or self._row != json.loads(self._original.creation.baseline_json)):
            raise ValueError
        for phase, reader in self._readers.items():
            expected = self._assigned if phase in {"policy-assigned", "policy-restore-current", "policy-restore-dispatch"} else self._inherited
            if (type(reader) is not WebSecretFixtureApiPreservationReader or reader._record is not self._record
                    or reader._config != self._record._config or reader._factory is not self._guard._factory
                    or reader._clock is not self._guard._http_clock or reader._phase != phase
                    or reader._policy_name != expected
                    or reader._credential_envelope != self._guard._baseline._credential_envelope
                    or reader._totp_envelope != self._guard._baseline._totp_envelope):
                raise ValueError
            if reader._started:
                reader._check_attempt()

    def check_binding(self, binding: IsolatedFolderPolicyTransitionBinding,
                      ownership: IsolatedFolderCreationOwnership) -> None:
        try:
            self._local()
            row = json.loads(ownership.baseline_json)
            if (binding.policy_name != self._assigned or binding.membership_binding.secret_id != self._row["id"]
                    or binding.membership_binding.secret_name != self._row["name"]
                    or binding.membership_binding.folder_id != self._row["folder"]
                    or hashlib.sha256(binding.membership_binding.expected_serial.encode("ascii")).hexdigest()
                        != self._original.creation.serial_digest
                    or ownership.native_folder_id != self._row["folder"]
                    or ownership.requester_digest != self._principal.requester.digest
                    or row["secret-policy"] != self._inherited or row["inherit-policy"] != "enable"):
                raise ValueError
        except Exception:
            raise PolicyAssignmentFixtureGuardError(_ERROR) from None

    def qualify_baseline(self, principal: V4PlanningPrincipal) -> PolicyAssignmentPreservation:
        try:
            self.check_principal(principal)
            return self.read_preservation("policy-baseline")
        except Exception:
            raise PolicyAssignmentFixtureGuardError(_ERROR) from None

    def check_principal(self, principal: object) -> None:
        """Pin both the original human and transport before any source operation."""
        if type(principal) is not V4PlanningPrincipal or principal != self._principal:
            raise PolicyAssignmentFixtureGuardError(_ERROR)

    def read_preservation(self, phase: _PolicyPhase) -> PolicyAssignmentPreservation:
        try:
            self._local()
            if phase not in self._readers or (phase == "policy-baseline") != (self._baseline is None):
                raise ValueError
            observed = self._readers[phase].read_policy_assignment_once()
            self._local()
            if self._baseline is None:
                self._baseline = observed
            elif observed != self._baseline:
                raise ValueError
            return observed
        except Exception:
            raise PolicyAssignmentFixtureGuardError(_ERROR) from None

    @property
    def preservation_digest(self) -> str:
        self._local()
        if self._baseline is None:
            raise PolicyAssignmentFixtureGuardError(_ERROR)
        return self._baseline.preservation_digest

    def read_relation(self, owner: OwnerSessionMetadataTransport, *, phase: Literal["inherited", "explicit"],
                      expected_folder: Mapping[str, object]) -> PolicyAssignmentRelation:
        buffers: list[bytearray] = []
        try:
            self._local()
            if (phase not in {"inherited", "explicit"} or owner._config != self._record._config
                    or owner._client is None or owner._clock() >= owner._expires_at):
                raise ValueError
            binding = self._binding(self._inherited if phase == "inherited" else self._assigned)
            routes = ["/api/v2/cmdb/secret/database/" + str(binding.secret_id) + "?format="
                      + quote(_SECRET_FIELDS, safe="") + "&with_meta=true&vdom=root",
                      "/api/v2/cmdb/secret/folder/" + str(binding.folder_id) + "?format="
                      + quote(_FOLDER_FIELDS, safe="") + "&with_meta=true&vdom=root",
                      "/api/v2/cmdb/secret/policy/" + quote(binding.policy_name, safe="") + "?with_meta=true&vdom=root"]
            for route in (*routes, *reversed(routes)):
                raw = bytearray()
                buffers.append(raw)
                with _private_http_logs(), owner._client.stream("GET", route, headers={"Accept": "application/json"}) as response:
                    if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                        raise ValueError
                    for chunk in response.iter_bytes():
                        if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                            raise ValueError
                        raw.extend(chunk)
            for content in (buffers[1], buffers[4]):
                fields = _detail(content, "folder", binding.serial_digest)
                if set(expected_folder) != _FOLDER or any(not _matches(content, fields[key], expected_folder[key]) for key in _FOLDER):
                    raise ValueError
            relation = consume_policy_assignment_relation(binding=binding, secret_before=buffers[0],
                folder_before=buffers[1], policy_before=buffers[2], policy_after=buffers[3],
                folder_after=buffers[4], secret_after=buffers[5])
            if relation.inherited != (phase == "inherited"):
                raise ValueError
            self._local()
            return relation
        except Exception:
            raise PolicyAssignmentFixtureGuardError(_ERROR) from None
        finally:
            for raw in buffers:
                _zeroize_mutable(raw)


def _matches(raw: bytearray, span: tuple[int, int], expected: Any) -> bool:
    """Compare only creation-qualified Folder fields; skip unknown value bytes."""
    if type(expected) is dict:
        fields = metadata._object_spans(raw, *span, frozenset(expected))
        return (set(fields) == set(expected) and _member_count(raw, span) == len(expected)
                and all(_matches(raw, fields[key], value) for key, value in expected.items()))
    if type(expected) is list:
        rows = metadata._array(raw, span, len(expected) + 1)
        return len(rows) == len(expected) and all(_matches(raw, item, value) for item, value in zip(rows, expected, strict=True))
    actual = metadata._scalar(raw, span)
    return type(actual) is type(expected) and actual == expected
