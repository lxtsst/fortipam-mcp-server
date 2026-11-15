"""Synthetic pure contract facts, not signed-getter or device acceptance."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import json
from typing import Any

import pytest

from fortipam_mcp.isolated_folder_creation_ownership import (
    CONTRACT as CREATION_CONTRACT, IsolatedFolderCreationOwnership, IsolatedFolderCreationSnapshot,
    _canonical, _digest,
)
from fortipam_mcp.isolated_folder_m4_adapter import IsolatedFolderBinding
from fortipam_mcp.isolated_folder_policy_transition_contract import (
    IsolatedFolderPolicyTransitionBinding, IsolatedFolderPolicyTransitionContractError,
    IsolatedFolderPolicyTransitionInspection, IsolatedFolderPolicyTransitionReadback,
    qualify_isolated_folder_policy_transition_inspection, validate_transition_inspection,
    validate_transition_readback,
)
from fortipam_mcp.single_secret_folder_membership_source import (
    SingleSecretFolderMembershipBinding, SingleSecretFolderMembershipObservation,
)

SERIAL = "SYNTHETIC_SERIAL"
POLICY = "Synthetic Fixed Policy"


def folder() -> dict[str, Any]:
    return {"id": 23, "name": "Synthetic Isolated Folder", "folder-type": "public", "parent-folder": 17,
        "inherit-policy": "enable", "inherit-permission": "disable", "inherit-folder-ztna": "enable",
        "secret-policy": "", "ztna-ems-tag": [], "ztna-tags-match-logic": "and", "group-permission": [],
        "user-permission": [{"id": 1, "q_origin_key": 1, "user-name": [{"name": "synthetic-owner",
            "q_origin_key": "synthetic-owner"}], "folder-permission": "owner", "secret-permission": "owner",
            "allowed-launcher-type": "all"}]}


def binding() -> IsolatedFolderPolicyTransitionBinding:
    return IsolatedFolderPolicyTransitionBinding(
        IsolatedFolderBinding("Synthetic Isolated Folder", 17, "synthetic-owner", "a" * 64),
        SingleSecretFolderMembershipBinding(23, "Synthetic Isolated Folder", 42, "Synthetic Bound Secret",
            SERIAL, "Synthetic Folder Witness", "Synthetic Secret Witness"), POLICY,
    )


def ownership(row: dict[str, Any] | None = None) -> IsolatedFolderCreationOwnership:
    baseline = folder() if row is None else row
    return IsolatedFolderCreationOwnership(CREATION_CONTRACT, "folder-preview-synthetic",
        "folder-authorization-synthetic", "b" * 64, binding().creation_binding.parameters_digest,
        "c" * 64, 23, SERIAL, _canonical(baseline), _digest(baseline))


def membership() -> SingleSecretFolderMembershipObservation:
    return SingleSecretFolderMembershipObservation(True, True, True, True, "d" * 64)


def policy() -> dict[str, object]:
    return {"name": POLICY, "recording": "enable", "block-clipboard": "disable", "rdp-event-filter": "not-set"}


def inspect(phase: str = "inherited", **changes: Any) -> IsolatedFolderPolicyTransitionInspection:
    current = folder()
    if phase == "explicit": current.update({"inherit-policy": "disable", "secret-policy": POLICY})
    kwargs: dict[str, Any] = dict(ownership=ownership(), snapshot=IsolatedFolderCreationSnapshot(SERIAL, current),
                  membership=membership(), policy_definition=policy(), phase=phase)
    kwargs.update(changes)
    return qualify_isolated_folder_policy_transition_inspection(binding(), **kwargs)


def test_forward_restore_native_full_save_preserves_owner_and_exact_baseline_without_private_repr() -> None:
    before = inspect()
    explicit = inspect("explicit")
    assert validate_transition_inspection(before) == before
    assert before.creator_digest == ownership().requester_digest
    body = json.loads(before.native_body_json)
    expected = folder()
    del expected["folder-type"]
    expected.update({"inherit-policy": "disable", "secret-policy": POLICY})
    relation = expected["user-permission"][0]
    del relation["q_origin_key"]
    del relation["user-name"][0]["q_origin_key"]
    assert len(body) == 11 and body == expected
    assert body["user-permission"][0]["allowed-launcher-type"] == "all"
    restored_body = json.loads(explicit.native_body_json)
    assert restored_body == {**expected, "inherit-policy": "enable", "secret-policy": ""}
    assert json.loads(before.baseline_folder_json) == json.loads(before.current_folder_json) == folder()
    assert validate_transition_readback(IsolatedFolderPolicyTransitionReadback(True, True, explicit), before, "assign") == explicit
    restored = validate_transition_readback(IsolatedFolderPolicyTransitionReadback(True, True, inspect()), explicit, "restore")
    assert restored.state_digest == before.state_digest
    assert restored.current_folder_json == before.baseline_folder_json
    for private in ("Synthetic Isolated Folder", "synthetic-owner", SERIAL, POLICY, "Synthetic Bound Secret"):
        assert private not in repr(before) and private not in repr(binding())
    with pytest.raises(FrozenInstanceError): before.phase = "explicit"  # type: ignore[misc]


def test_private_json_snapshots_do_not_alias_source_inputs_and_policy_digest_is_only_fixed_controls() -> None:
    row, definition = folder(), policy()
    qualified = inspect(snapshot=IsolatedFolderCreationSnapshot(SERIAL, row), policy_definition=definition)
    row["user-permission"][0]["allowed-launcher-type"] = "changed"
    definition["recording"] = "disable"
    assert json.loads(qualified.current_folder_json)["user-permission"][0]["allowed-launcher-type"] == "all"
    assert json.loads(qualified.policy_definition_json)["recording"] == "enable"
    altered = inspect(policy_definition=definition)
    assert altered.policy_digest != qualified.policy_digest
    assert altered.preservation_digest == qualified.preservation_digest


@pytest.mark.parametrize("fault", (
    "id", "id_bool", "name", "personal", "parent", "permission", "ztna", "tags", "logic", "owner", "group",
    "launcher", "relation_origin", "principal_origin", "nested_extra", "root_extra", "missing",
    "baseline_policy_mismatch", "phase", "snapshot_serial", "receipt_serial", "receipt_namespace", "receipt_id",
))
def test_unqualified_creation_baseline_current_or_namespace_is_never_a_restore_contract(fault: str) -> None:
    baseline = folder()
    current = folder()
    kwargs: dict[str, Any] = {}
    if fault == "baseline_policy_mismatch":
        baseline["secret-policy"] = "Synthetic Inherited Policy"
    elif fault == "receipt_serial": kwargs["ownership"] = replace(ownership(), serial="OTHER")
    elif fault == "receipt_namespace": kwargs["ownership"] = replace(ownership(), contract="foreign")
    elif fault == "receipt_id": kwargs["ownership"] = replace(ownership(), native_folder_id=24)
    elif fault == "snapshot_serial": kwargs["snapshot"] = IsolatedFolderCreationSnapshot("OTHER", current)
    elif fault == "phase": kwargs["phase"] = "explicit"
    elif fault in {"id", "id_bool", "name", "personal", "parent", "permission", "ztna", "tags", "logic"}:
        key, value = {"id": ("id", 24), "id_bool": ("id", True), "name": ("name", "Other"),
            "personal": ("folder-type", "personal"), "parent": ("parent-folder", 18),
            "permission": ("inherit-permission", "enable"), "ztna": ("inherit-folder-ztna", "disable"),
            "tags": ("ztna-ems-tag", ["unexpected"]), "logic": ("ztna-tags-match-logic", "invalid")}[fault]
        baseline[key] = current[key] = value
    elif fault == "owner": baseline["user-permission"][0]["user-name"][0]["name"] = "other"
    elif fault == "group": baseline["group-permission"] = [{}]
    elif fault == "launcher": baseline["user-permission"][0]["allowed-launcher-type"] = "http"
    elif fault == "relation_origin": baseline["user-permission"][0]["q_origin_key"] = "1"
    elif fault == "principal_origin": baseline["user-permission"][0]["user-name"][0]["q_origin_key"] = "other"
    elif fault == "nested_extra": baseline["user-permission"][0]["unexpected"] = True
    elif fault == "root_extra": current["unexpected"] = True
    elif fault == "missing": del current["secret-policy"]
    kwargs.setdefault("ownership", ownership(baseline))
    kwargs.setdefault("snapshot", IsolatedFolderCreationSnapshot(SERIAL, current))
    with pytest.raises(IsolatedFolderPolicyTransitionContractError) as error: inspect(**kwargs)
    assert str(error.value) == "The isolated Folder Policy transition contract is unavailable."
    assert SERIAL not in str(error.value)


@pytest.mark.parametrize("field", ("no_child_folders", "exactly_one_secret", "bound_secret_folder_matches", "observations_stable", "membership_digest"))
def test_membership_requires_exact_qualified_minimal_facts(field: str) -> None:
    mutation: dict[str, Any] = {field: "invalid" if field == "membership_digest" else 1}
    changed = replace(membership(), **mutation)
    with pytest.raises(IsolatedFolderPolicyTransitionContractError): inspect(membership=changed)


@pytest.mark.parametrize("field,value", (
    ("name", "Other"), ("recording", "invalid"), ("block-clipboard", True), ("rdp-event-filter", {}),
    ("extra", "enable"),
))
def test_policy_projection_is_exact_and_never_claims_a_complete_profile(field: str, value: object) -> None:
    definition = policy()
    definition[field] = value
    with pytest.raises(IsolatedFolderPolicyTransitionContractError): inspect(policy_definition=definition)


@pytest.mark.parametrize("field", (
    "creator_digest", "creation_digest", "preservation_digest", "membership_digest", "policy_digest", "state_digest",
    "baseline_folder_json", "current_folder_json", "native_body_json", "creation_ownership_json", "membership_json",
    "policy_definition_json", "phase",
))
def test_self_contained_validator_recomputes_all_json_and_digest_fields(field: str) -> None:
    before = inspect()
    mutation: dict[str, Any] = {field: "foreign"}
    changed = replace(before, **mutation)
    with pytest.raises(IsolatedFolderPolicyTransitionContractError): validate_transition_inspection(changed)


def test_self_contained_validator_rejects_noncanonical_json_duplicates_and_foreign_binding() -> None:
    before = inspect()
    for changed in (
        replace(before, current_folder_json=before.current_folder_json.replace('"id":23', '"id":23,"id":23')),
        replace(before, current_folder_json=json.dumps(folder())),
        replace(before, binding=replace(binding(), membership_binding=replace(binding().membership_binding, folder_id=24))),
        replace(before, binding=replace(binding(), membership_binding=replace(binding().membership_binding, secret_id=99))),
    ):
        with pytest.raises(IsolatedFolderPolicyTransitionContractError): validate_transition_inspection(changed)
    with pytest.raises(IsolatedFolderPolicyTransitionContractError):
        replace(binding(), membership_binding=replace(binding().membership_binding, folder_name="Other Folder"))


@pytest.mark.parametrize("fault", ("ack", "logout", "missing", "same_phase", "operation", "foreign_receipt", "policy", "membership", "creator"))
def test_readback_requires_opposite_phase_same_receipt_creator_and_all_private_anchors(fault: str) -> None:
    before, after = inspect(), inspect("explicit")
    operation: Any = "assign"
    if fault == "same_phase": after = before
    elif fault == "foreign_receipt": after = inspect("explicit", ownership=replace(ownership(), preview_ref="folder-preview-foreign"))
    elif fault == "creator": after = inspect("explicit", ownership=replace(ownership(), requester_digest="e" * 64))
    elif fault == "policy": after = inspect("explicit", policy_definition={**policy(), "recording": "disable"})
    elif fault == "membership": after = inspect("explicit", membership=replace(membership(), membership_digest="e" * 64))
    elif fault == "operation": operation = "restore"
    receipt = IsolatedFolderPolicyTransitionReadback(1 if fault == "ack" else True,  # type: ignore[arg-type]
        1 if fault == "logout" else True, None if fault == "missing" else after)  # type: ignore[arg-type]
    with pytest.raises(IsolatedFolderPolicyTransitionContractError): validate_transition_readback(receipt, before, operation)


def test_explicit_current_accepts_only_the_two_proved_deltas() -> None:
    explicit = json.loads(inspect("explicit").current_folder_json)
    for key, value in (("secret-policy", "Other"), ("inherit-policy", "enable"), ("ztna-tags-match-logic", "or")):
        changed = deepcopy(explicit)
        changed[key] = value
        with pytest.raises(IsolatedFolderPolicyTransitionContractError):
            inspect("explicit", snapshot=IsolatedFolderCreationSnapshot(SERIAL, changed))


def test_nonempty_inherited_signed_baseline_restores_with_empty_native_relation_and_exact_full12() -> None:
    baseline = folder()
    baseline["secret-policy"] = "Synthetic Inherited Policy"
    receipt = ownership(baseline)
    before = inspect(ownership=receipt, snapshot=IsolatedFolderCreationSnapshot(SERIAL, baseline))
    explicit_row = dict(baseline, **{"inherit-policy": "disable", "secret-policy": POLICY})
    explicit = inspect("explicit", ownership=receipt,
                       snapshot=IsolatedFolderCreationSnapshot(SERIAL, explicit_row))
    assert validate_transition_inspection(before) == before
    assert validate_transition_inspection(explicit) == explicit
    assert json.loads(before.native_body_json)["secret-policy"] == POLICY
    restored_body = json.loads(explicit.native_body_json)
    assert restored_body["inherit-policy"] == "enable" and restored_body["secret-policy"] == ""
    assert len(restored_body) == 11 and "folder-type" not in restored_body
    assert validate_transition_readback(IsolatedFolderPolicyTransitionReadback(True, True, explicit),
                                        before, "assign") == explicit
    restored = validate_transition_readback(IsolatedFolderPolicyTransitionReadback(True, True, before),
                                            explicit, "restore")
    assert restored.current_folder_json == receipt.baseline_json
    assert json.loads(restored.current_folder_json)["secret-policy"] == "Synthetic Inherited Policy"
    with pytest.raises(IsolatedFolderPolicyTransitionContractError):
        inspect(ownership=receipt, snapshot=IsolatedFolderCreationSnapshot(SERIAL,
                dict(baseline, **{"secret-policy": ""})))


def test_explicit_empty_creation_optin_still_rejects_nonempty_signed_baseline() -> None:
    baseline = dict(folder(), **{"secret-policy": "Synthetic Inherited Policy"})
    selected = replace(binding(), creation_binding=replace(binding().creation_binding, empty_inactive_policy=True))
    receipt = replace(ownership(baseline), parameters_digest=selected.creation_binding.parameters_digest)
    with pytest.raises(IsolatedFolderPolicyTransitionContractError):
        qualify_isolated_folder_policy_transition_inspection(selected, ownership=receipt,
            snapshot=IsolatedFolderCreationSnapshot(SERIAL, baseline), membership=membership(),
            policy_definition=policy(), phase="inherited")
