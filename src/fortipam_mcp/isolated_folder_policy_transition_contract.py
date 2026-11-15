"""Pure private Folder Policy transition; no source, HMAC or write authority.

The provider must obtain ownership through the real creation workflow signed
getter for every qualification, plus fresh membership and fixed Policy reads.
This contract only binds those inputs. The original profile binds three session
controls. An explicit complete-definition profile additionally binds the trusted
source's 54-field configuration fingerprint, without granting source authority
or establishing Secret preservation, activity absence or launch/access effects.
Native restore sends inherited Policy with an empty explicit relation. Readback
must match the signed complete creation baseline, including its observed
secret-policy value, which may be nonempty under inheritance.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Literal

from .isolated_folder_creation_ownership import (
    IsolatedFolderCreationOwnership, IsolatedFolderCreationSnapshot, ownership_payload,
    validate_creation_ownership,
)
from .isolated_folder_m4_adapter import IsolatedFolderBinding
from .secret_namespace_ssh_reader import _safe_secret_name
from .single_secret_folder_membership_source import (
    SingleSecretFolderMembershipBinding, SingleSecretFolderMembershipObservation,
)

CONTRACT = "fortipam-build29-isolated-folder-policy-transition-v1"
COMPLETE_POLICY_CONTRACT = "fortipam-build29-isolated-folder-complete-policy-transition-v2"
RETAINED_SECRET_CONTRACT = "fortipam-build29-isolated-folder-retained-secret-transition-v3"
_UNAVAILABLE = "The isolated Folder Policy transition contract is unavailable."
Phase = Literal["inherited", "explicit"]
_CONTROLS = {"recording", "block-clipboard", "rdp-event-filter"}


class IsolatedFolderPolicyTransitionContractError(ValueError):
    """Stable refusal with no private identities, baselines or raw sources."""


@dataclass(frozen=True, slots=True, repr=False)
class IsolatedFolderPolicyTransitionBinding:
    creation_binding: IsolatedFolderBinding
    membership_binding: SingleSecretFolderMembershipBinding
    policy_name: str

    def __post_init__(self) -> None:
        if (type(self.creation_binding) is not IsolatedFolderBinding
            or self.creation_binding.initial_rdp_policy is not None
            or type(self.membership_binding) is not SingleSecretFolderMembershipBinding
            or self.creation_binding.name != self.membership_binding.folder_name
            or type(self.policy_name) is not str or not _safe_secret_name(self.policy_name)):
            raise IsolatedFolderPolicyTransitionContractError(_UNAVAILABLE)


@dataclass(frozen=True, slots=True, repr=False)
class IsolatedFolderPolicyTransitionInspection:
    """Current phase and private native body for the opposite phase."""
    binding: IsolatedFolderPolicyTransitionBinding
    phase: Phase
    creator_digest: str
    creation_digest: str
    preservation_digest: str
    membership_digest: str
    policy_digest: str
    state_digest: str
    baseline_folder_json: str
    current_folder_json: str
    native_body_json: str
    creation_ownership_json: str
    membership_json: str
    policy_definition_json: str
    complete_policy_configuration_digest: str | None = None
    complete_secret_preservation_digest: str | None = None
    effective_policy_configuration_digest: str | None = None


@dataclass(frozen=True, slots=True, repr=False)
class IsolatedFolderPolicyTransitionReadback:
    acknowledged: bool
    logout_verified: bool
    after: IsolatedFolderPolicyTransitionInspection | None


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value).encode("ascii")).hexdigest()


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def qualify_isolated_folder_policy_transition_inspection(
    binding: IsolatedFolderPolicyTransitionBinding, *, ownership: IsolatedFolderCreationOwnership,
    snapshot: IsolatedFolderCreationSnapshot, membership: SingleSecretFolderMembershipObservation,
    policy_definition: Mapping[str, object], phase: Phase,
    complete_policy_configuration_digest: str | None = None,
    complete_secret_preservation_digest: str | None = None,
    effective_policy_configuration_digest: str | None = None,
) -> IsolatedFolderPolicyTransitionInspection:
    """Bind fresh trusted source inputs; never import ownership or verify its HMAC."""
    try:
        if (type(binding) is not IsolatedFolderPolicyTransitionBinding
            or type(snapshot) is not IsolatedFolderCreationSnapshot or type(phase) is not str
            or phase not in {"inherited", "explicit"}
            or type(membership) is not SingleSecretFolderMembershipObservation
            or any(value is not True for value in (membership.no_child_folders, membership.exactly_one_secret,
                membership.bound_secret_folder_matches, membership.observations_stable))
            or type(membership.membership_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", membership.membership_digest) is None
            or not isinstance(policy_definition, Mapping) or set(policy_definition) != {"name"} | _CONTROLS
            or type(policy_definition["name"]) is not str or policy_definition["name"] != binding.policy_name
            or any(type(policy_definition[key]) is not str
                   or policy_definition[key] not in {"enable", "disable", "not-set"} for key in _CONTROLS)
            or complete_policy_configuration_digest is not None
                and (type(complete_policy_configuration_digest) is not str
                     or re.fullmatch(r"[0-9a-f]{64}", complete_policy_configuration_digest) is None)):
            raise ValueError
        retained = (complete_secret_preservation_digest, effective_policy_configuration_digest)
        if any(value is not None for value in retained) and (
                complete_policy_configuration_digest is None
                or any(type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None for value in retained)):
            raise ValueError
        b = binding.membership_binding
        validate_creation_ownership(ownership, binding=binding.creation_binding, expected_serial=b.expected_serial)
        baseline = json.loads(ownership.baseline_json, object_pairs_hook=_unique)
        if (ownership.native_folder_id != b.folder_id
            or type(ownership.requester_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", ownership.requester_digest) is None
            or snapshot.serial != b.expected_serial or type(snapshot.serial) is not str
            or not isinstance(snapshot.folder, Mapping)):
            raise ValueError
        expected = deepcopy(baseline)
        if phase == "explicit":
            expected.update({"inherit-policy": "disable", "secret-policy": binding.policy_name})
        current_json = _canonical(dict(snapshot.folder))
        if current_json != _canonical(expected):
            raise ValueError
        proposed = deepcopy(baseline)
        if phase == "inherited":
            proposed.update({"inherit-policy": "disable", "secret-policy": binding.policy_name})
        else:
            # Native unparse encodes inheritance without an explicit relation;
            # the expected readback remains the original complete signed row.
            proposed["secret-policy"] = ""
        # Exact native full save: 12 read fields minus folder-type. Native
        # relation/principal routing origins are omitted; launcher-all survives.
        del proposed["folder-type"]
        for relation in proposed["user-permission"]:
            relation.pop("q_origin_key", None)
            for principal in relation["user-name"]:
                principal.pop("q_origin_key", None)
        body_json = _canonical(proposed)
        creation_json = ownership_payload(ownership)
        creation_digest = _digest(json.loads(creation_json, object_pairs_hook=_unique))
        membership_json = _canonical(asdict(membership))
        policy_json = _canonical(dict(policy_definition))
        preservation_digest = _digest({"contract": CONTRACT, "baseline": baseline})
        policy_digest = _digest({"name": binding.policy_name,
                                 **{key: policy_definition[key] for key in _CONTROLS}})
        contract = CONTRACT
        if complete_policy_configuration_digest is not None:
            contract = COMPLETE_POLICY_CONTRACT
            policy_digest = _digest({"contract": contract, "controls_digest": policy_digest,
                                    "configuration_digest": complete_policy_configuration_digest})
        state = {"contract": contract, "binding": asdict(binding), "phase": phase,
            "creation_digest": creation_digest,
            "creator_digest": ownership.requester_digest, "preservation_digest": preservation_digest,
            "membership_digest": membership.membership_digest,
            "policy_digest": policy_digest, "current_folder_json": current_json, "native_body_json": body_json}
        if complete_secret_preservation_digest is not None:
            state.update(contract=RETAINED_SECRET_CONTRACT,
                complete_secret_preservation_digest=complete_secret_preservation_digest,
                effective_policy_configuration_digest=effective_policy_configuration_digest)
        state_digest = _digest(state)
        return IsolatedFolderPolicyTransitionInspection(binding, phase, ownership.requester_digest,
            creation_digest, preservation_digest, membership.membership_digest, policy_digest, state_digest,
            ownership.baseline_json, current_json, body_json, creation_json, membership_json, policy_json,
            complete_policy_configuration_digest, complete_secret_preservation_digest,
            effective_policy_configuration_digest)
    except Exception:
        raise IsolatedFolderPolicyTransitionContractError(_UNAVAILABLE) from None


def validate_transition_inspection(value: object) -> IsolatedFolderPolicyTransitionInspection:
    """Recompute private DTO facts; this does not reverify source HMAC or columns."""
    try:
        if (type(value) is not IsolatedFolderPolicyTransitionInspection
            or any(type(payload) is not str or len(payload) > limit for payload, limit in
                ((value.current_folder_json, 16384), (value.creation_ownership_json, 16384),
                 (value.membership_json, 1024), (value.policy_definition_json, 4096)))):
            raise ValueError
        ownership = IsolatedFolderCreationOwnership(**json.loads(value.creation_ownership_json, object_pairs_hook=_unique))
        membership = SingleSecretFolderMembershipObservation(**json.loads(value.membership_json, object_pairs_hook=_unique))
        checked = qualify_isolated_folder_policy_transition_inspection(value.binding, ownership=ownership,
            snapshot=IsolatedFolderCreationSnapshot(value.binding.membership_binding.expected_serial,
                json.loads(value.current_folder_json, object_pairs_hook=_unique)),
            membership=membership, policy_definition=json.loads(value.policy_definition_json, object_pairs_hook=_unique),
            phase=value.phase, complete_policy_configuration_digest=value.complete_policy_configuration_digest,
            complete_secret_preservation_digest=value.complete_secret_preservation_digest,
            effective_policy_configuration_digest=value.effective_policy_configuration_digest)
        if checked != value:
            raise ValueError
        return checked
    except Exception:
        raise IsolatedFolderPolicyTransitionContractError(_UNAVAILABLE) from None


def validate_transition_readback(
    value: object, before: IsolatedFolderPolicyTransitionInspection, operation: Literal["assign", "restore"],
) -> IsolatedFolderPolicyTransitionInspection:
    """Require acknowledged, logged-out, symmetric readback with unchanged anchors."""
    try:
        if (type(value) is not IsolatedFolderPolicyTransitionReadback
            or value.acknowledged is not True or value.logout_verified is not True
            or type(operation) is not str or operation not in {"assign", "restore"}):
            raise ValueError
        original = validate_transition_inspection(before)
        after = validate_transition_inspection(value.after)
        expected_phase = "inherited" if operation == "assign" else "explicit"
        if (original.phase != expected_phase or after.phase == original.phase or after.binding != original.binding
            or any(getattr(after, key) != getattr(original, key) for key in
                ("creator_digest", "creation_digest", "preservation_digest", "membership_digest", "policy_digest",
                 "complete_secret_preservation_digest"))
            or (after.effective_policy_configuration_digest is None) != (original.effective_policy_configuration_digest is None)
            or operation == "assign" and after.effective_policy_configuration_digest is not None
                and after.effective_policy_configuration_digest != after.complete_policy_configuration_digest):
            raise ValueError
        # Restore native 11-field save to the exact full 12-field source shape,
        # retaining creation routing metadata rather than inventing new origins.
        expected_after = json.loads(original.baseline_folder_json, object_pairs_hook=_unique)
        if operation == "assign":
            expected_after.update({"inherit-policy": "disable", "secret-policy": original.binding.policy_name})
        if _canonical(expected_after) != after.current_folder_json:
            raise ValueError
        return after
    except Exception:
        raise IsolatedFolderPolicyTransitionContractError(_UNAVAILABLE) from None
