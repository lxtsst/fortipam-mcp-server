"""Fixed EMS tag metadata must not become write or recovery authority."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from typing import Any

import pytest

from fortipam_mcp.ems_tag_contract import (
    DisabledLinuxProcessTag,
    EmsTagCatalog,
    EmsTagFullScope,
    EmsTagContractError,
    matches_disabled_process_tag,
    qualify_tag_catalog,
    qualify_tag_detail,
    single_addition_matches,
    full_single_addition_matches,
)


def envelope(data: object) -> dict[str, Any]:
    return {"result": {"retval": 1, "message": ""}, "data": data}


def detail(draft: DisabledLinuxProcessTag) -> dict[str, Any]:
    body = draft._body
    return {
        "tag_id": 101, "tag_name": body["name"], "description": body["description"],
        "status": False, "comments": body["comments"], "rules": body["rules"],
        "use_custom_logic": False, "detection_level": "Low", "error_msg": None,
        "tag_type": 1, "client_count": 0, "tag_detection_type": None,
        **{f"logic_{os}": None for os in ("windows", "mac", "ios", "android")},
        "logic_linux": '{"op":null,"rules":[{"id":1}]}',
    }


def catalog(*rows: dict[str, Any]) -> dict[str, Any]:
    return envelope({"tags": list(rows), "total": len(rows)})


def test_prospective_state_is_disabled_and_does_not_serialize_private_values_in_repr() -> None:
    draft = DisabledLinuxProcessTag("a" * 32)
    raw = detail(draft)
    state = qualify_tag_detail(envelope(raw))
    assert state.disabled_and_unassigned
    assert matches_disabled_process_tag(state, draft)
    assert draft._body["status"] is False
    assert draft._body["use_custom_logic"] is False
    assert len(draft._body["rules"]) == 1
    assert draft._validation_body == {"rules": [{"type": 6, "os": 3, "content": draft._process}]}
    assert draft._name not in repr(draft) + repr(state)
    raw["client_count"] = 9
    assert state.disabled_and_unassigned
    assert json.loads(state._raw)["client_count"] == 0


@pytest.mark.parametrize("field,value", [
    ("status", True), ("client_count", 1), ("use_custom_logic", True),
    ("logic_linux", '{"op":"AND","rules":[{"id":1}]}'),
    ("error_msg", "Unfinished evaluation"), ("tag_name", "another_tag"),
    ("description", "changed"), ("comments", "changed"),
])
def test_disabled_draft_requires_every_effect_relevant_postcondition(field: str, value: object) -> None:
    draft = DisabledLinuxProcessTag("a" * 32)
    raw = detail(draft)
    raw[field] = value
    assert not matches_disabled_process_tag(qualify_tag_detail(envelope(raw)), draft)


@pytest.mark.parametrize("field,value", [
    ("client_count", None), ("client_count", True), ("client_count", -1),
    ("status", 0), ("tag_id", True), ("rules", None),
    ("tag_type", -1), ("use_custom_logic", 0),
])
def test_detail_refuses_missing_or_coerced_impact_evidence(field: str, value: object) -> None:
    raw = detail(DisabledLinuxProcessTag("a" * 32))
    raw[field] = value
    with pytest.raises(EmsTagContractError, match="^The fixed EMS tag evidence is unavailable\\.$"):
        qualify_tag_detail(envelope(raw))


@pytest.mark.parametrize("change", ["missing", "extra", "unknown_rule", "duplicate_rule", "nested_match_type"])
def test_complete_state_and_rule_shape_are_closed(change: str) -> None:
    raw = detail(DisabledLinuxProcessTag("a" * 32))
    if change == "missing":
        del raw["client_count"]
    elif change == "extra":
        raw["new_unqualified_setting"] = False
    elif change == "unknown_rule":
        raw["rules"][0]["unqualified_effect"] = True
    elif change == "duplicate_rule":
        raw["rules"].append(deepcopy(raw["rules"][0]))
    else:
        raw["rules"][0]["match_type_id"] = {"wildcard": True}
    with pytest.raises(EmsTagContractError):
        qualify_tag_detail(envelope(raw))


@pytest.mark.parametrize("value", [0, True, "1", -1])
def test_ems_native_success_one_does_not_accept_other_protocols(value: object) -> None:
    payload = envelope(detail(DisabledLinuxProcessTag("a" * 32)))
    payload["result"]["retval"] = value
    with pytest.raises(EmsTagContractError):
        qualify_tag_detail(payload)


def test_native_null_message_is_not_a_failed_result_or_a_missing_field() -> None:
    payload = envelope(detail(DisabledLinuxProcessTag("a" * 32)))
    payload["result"]["message"] = None
    assert qualify_tag_detail(payload).disabled_and_unassigned
    del payload["result"]["message"]
    with pytest.raises(EmsTagContractError):
        qualify_tag_detail(payload)


@pytest.mark.parametrize("value", [[], {}, True])
def test_message_compatibility_does_not_admit_unqualified_types(value: object) -> None:
    payload = envelope(detail(DisabledLinuxProcessTag("a" * 32)))
    payload["result"]["message"] = value
    with pytest.raises(EmsTagContractError):
        qualify_tag_detail(payload)


def test_single_addition_preserves_whole_prior_rows_and_rejects_adoption() -> None:
    draft = DisabledLinuxProcessTag("a" * 32)
    prior = {"id": 7, "name": "existing_tag", "status": True,
             "opaque_native_metadata": {"items": [1, 2], "flag": False}}
    added = {"id": 101, "name": draft._name, "status": False}
    before = qualify_tag_catalog(catalog(prior))
    after = qualify_tag_catalog(catalog(added, prior))
    state = qualify_tag_detail(envelope(detail(draft)))
    assert single_addition_matches(before, after, state, draft)
    mutated = deepcopy(prior)
    mutated["opaque_native_metadata"]["flag"] = True
    assert not single_addition_matches(before, qualify_tag_catalog(catalog(mutated, added)), state, draft)
    assert not single_addition_matches(after, after, state, draft)
    assert not single_addition_matches(qualify_tag_catalog(catalog(added)), after, state, draft)


@pytest.mark.parametrize("change", ["partial", "duplicate_id", "duplicate_name", "bool_id"])
def test_catalog_completeness_and_collision_checks(change: str) -> None:
    payload = catalog({"id": 7, "name": "existing_tag", "status": True})
    if change == "partial":
        payload["data"]["total"] = 2
    else:
        other = {"id": 8, "name": "other_tag", "status": False}
        if change == "duplicate_id":
            other["id"] = 7
        elif change == "duplicate_name":
            other["name"] = "EXISTING_TAG"
        else:
            other["id"] = True
        payload["data"]["tags"].append(other)
        payload["data"]["total"] = 2
    with pytest.raises(EmsTagContractError):
        qualify_tag_catalog(payload)


def test_catalog_is_immutable_and_order_independent_without_dropping_unknown_fields() -> None:
    one = {"id": 7, "name": "one", "status": True, "extra": [1]}
    two = {"id": 8, "name": "two", "status": False}
    first = qualify_tag_catalog(catalog(one, two))
    assert first.digest == qualify_tag_catalog(catalog(two, one)).digest
    one["extra"].append(2)
    assert first.digest != qualify_tag_catalog(catalog(one, two)).digest


@pytest.mark.parametrize("foreign_match", [None, 1, 2, 3])
def test_optional_neutral_rule_fields_do_not_allow_a_foreign_match_selector(foreign_match: object) -> None:
    draft = DisabledLinuxProcessTag("a" * 32)
    raw = detail(draft)
    raw["rules"][0].update(updates=None)
    assert matches_disabled_process_tag(qualify_tag_detail(envelope(raw)), draft)
    raw["rules"][0]["match_type_id"] = foreign_match
    assert not matches_disabled_process_tag(qualify_tag_detail(envelope(raw)), draft)


def test_invalid_nonce_and_foreign_process_cannot_match() -> None:
    with pytest.raises(EmsTagContractError):
        DisabledLinuxProcessTag("synthetic;not-a-nonce")
    draft = DisabledLinuxProcessTag("a" * 32)
    raw = detail(draft)
    raw["rules"][0]["content"] = "some_other_process"
    assert not matches_disabled_process_tag(qualify_tag_detail(envelope(raw)), draft)


@pytest.mark.parametrize("logic,accepted", [
    (' { "rules" : [{ "id" : 1 }], "op" : null } ', True),
    (None, False), ("", False), ("null", False),
    ('{"op":"and","rules":[{"id":1}]}', False),
    ('{"op":null,"rules":[{"id":true}]}', False),
    ('{"op":null,"rules":[{"id":2}]}', False),
    ('{"op":null,"rules":[{"id":1.0}]}', False),
    ('{"op":null,"rules":[{"id":1}],"extra":null}', False),
    ('{"op":null,"op":null,"rules":[{"id":1}]}', False),
    ('{"op":null,"rules":[{"id":2,"id":1}]}', False),
])
def test_native_single_process_logic_is_exact_and_never_inferred(logic: object, accepted: bool) -> None:
    draft = DisabledLinuxProcessTag("a" * 32)
    raw = detail(draft)
    raw["logic_linux"] = logic
    assert matches_disabled_process_tag(qualify_tag_detail(envelope(raw)), draft) is accepted


def test_cached_client_count_cannot_override_its_complete_snapshot() -> None:
    draft = DisabledLinuxProcessTag("a" * 32)
    raw = detail(draft)
    raw["client_count"] = 9
    state = qualify_tag_detail(envelope(raw))
    with pytest.raises(EmsTagContractError):
        replace(state, _clients=0)
    object.__setattr__(state, "_clients", 0)
    with pytest.raises(EmsTagContractError):
        matches_disabled_process_tag(state, draft)


@pytest.mark.parametrize("field,value", [("_ids", (8,)), ("_ids", (True,)), ("_names", ("different",))])
def test_catalog_indexes_cannot_override_preserved_rows(field: str, value: object) -> None:
    state = qualify_tag_catalog(catalog({"id": 7, "name": "existing_tag", "status": True}))
    with pytest.raises(EmsTagContractError):
        replace(state, **{field: value})
    object.__setattr__(state, field, value)
    with pytest.raises(EmsTagContractError):
        _ = state.digest


def test_catalog_snapshot_size_is_checked_before_decoding(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_decode(*args: object, **kwargs: object) -> object:
        raise AssertionError("Oversized snapshots must not be decoded.")

    with monkeypatch.context() as patch:
        patch.setattr("fortipam_mcp.ems_tag_contract.json.loads", unexpected_decode)
        with pytest.raises(EmsTagContractError):
            EmsTagCatalog((b" " * 262145,), (7,), ("x",))


def full_scope(prior_change: bool = False, *, add: bool = False, shared_rule_set: bool = False) -> EmsTagFullScope:
    prior = detail(DisabledLinuxProcessTag("b" * 32))
    prior["tag_id"] = 7
    prior["status"] = True
    if prior_change:
        prior["rules"][0]["content"] = "changed_prior_process"
    rows = [{"id": 7, "name": prior["tag_name"], "status": True, "rule_set_id": 70}]
    details = [qualify_tag_detail(envelope(prior))]
    if add:
        draft = DisabledLinuxProcessTag("a" * 32)
        added = detail(draft)
        rows.append({"id": 101, "name": draft._name, "status": False,
                     "rule_set_id": 70 if shared_rule_set else 1010})
        details.append(qualify_tag_detail(envelope(added)))
    return EmsTagFullScope(qualify_tag_catalog(catalog(*rows)), tuple(details))


def test_complete_scope_detects_prior_rule_drift_hidden_by_unchanged_catalog() -> None:
    draft = DisabledLinuxProcessTag("a" * 32)
    before = full_scope()
    after = full_scope(add=True)
    assert full_single_addition_matches(before, after, draft)
    changed = full_scope(prior_change=True, add=True)
    assert single_addition_matches(before.catalog, changed.catalog, changed._candidate(draft), draft)
    assert not full_single_addition_matches(before, changed, draft)
    assert not full_single_addition_matches(before, full_scope(add=True, shared_rule_set=True), draft)


def test_full_scope_requires_all_distinct_details_and_rule_set_metadata() -> None:
    current = full_scope(add=True)
    with pytest.raises(EmsTagContractError):
        EmsTagFullScope(current.catalog, current.details[:1])
    with pytest.raises(EmsTagContractError):
        EmsTagFullScope(current.catalog, (current.details[0], current.details[0]))
    rows = [json.loads(row) for row in current.catalog._rows]
    del rows[0]["rule_set_id"]
    with pytest.raises(EmsTagContractError):
        EmsTagFullScope(qualify_tag_catalog(catalog(*rows)), current.details)


def test_passive_existing_rule_preserves_omitted_negative_without_inventing_false() -> None:
    draft = DisabledLinuxProcessTag("a" * 32)
    raw = detail(draft)
    del raw["rules"][0]["negative"]
    state = qualify_tag_detail(envelope(raw))
    assert "negative" not in json.loads(state._raw)["rules"][0]
    assert not matches_disabled_process_tag(state, draft)
    raw["rules"][0]["negative"] = False
    assert state.digest != qualify_tag_detail(envelope(raw)).digest


def test_native_null_rule_content_is_preserved_but_cannot_match_the_new_rule() -> None:
    draft = DisabledLinuxProcessTag("a" * 32)
    raw = detail(draft)
    raw["rules"][0]["content"] = None
    state = qualify_tag_detail(envelope(raw))
    assert json.loads(state._raw)["rules"][0]["content"] is None
    assert not matches_disabled_process_tag(state, draft)
    del raw["rules"][0]["content"]
    with pytest.raises(EmsTagContractError):
        qualify_tag_detail(envelope(raw))
