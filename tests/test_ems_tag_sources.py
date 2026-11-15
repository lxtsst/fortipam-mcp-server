"""Synthetic fixed source joins; no protected HTTP or native EMS execution."""
from copy import deepcopy
from dataclasses import replace
import json

import pytest

from fortipam_mcp.ems_tag_contract import DisabledLinuxProcessTag
from fortipam_mcp.ems_tag_sources import CATALOG_PATH, METADATA_PATH, EmsTagSources, EmsTagSourceError
from test_ems_tag_contract import envelope, full_scope


def metadata():
    return envelope({"consts": {"System": {"VERSION": "7.4.8", "VERSION_FULL": "7.4.8.2245",
        "MATCH_TYPE": {"Simple": 1}, "SITES_ENABLED": False}, "SUCCESS": 1, "Permissions": {"SUPER": "super"},
        "ComplianceVerification": {"RuleType": {"PROCESS": 6}, "OS": {"LINUX": 3},
            "TAG_LENGTH_MAX": 58, "RuleTypeDetails": {"6": {"OS_TYPES": [3]}}}},
        "User": {"name": "synthetic_owner", "role": {"super": True}, "is_global": True},
        "active_vdom": "Default", "show_global": True, "show_vdom": True})


class Channel:
    def __init__(self):
        self.metadata = metadata()
        self.scope = full_scope()
        self.calls = []
        self.mutate = None

    def get(self, path):
        self.calls.append(path)
        if self.mutate:
            self.mutate(self, path)
        if path == METADATA_PATH:
            return deepcopy(self.metadata)
        if path == CATALOG_PATH:
            return envelope({"tags": [json.loads(row) for row in self.scope.catalog._rows],
                             "total": self.scope.catalog.count})
        for detail in self.scope.details:
            if path == f"/api/v1/tags/zero_trust/{detail._id}/get":
                return envelope(json.loads(detail._raw))
        raise AssertionError("Unexpected source route.")


def make(*, key=b"s" * 32, instance="1" * 64, now=None, channel=None):
    channel, now = channel or Channel(), now if now is not None else [1000]
    sources = EmsTagSources(draft=DisabledLinuxProcessTag("a" * 32), owner_name="synthetic_owner",
        instance_scope_digest=instance, source_key=key, get_json=channel.get, clock=lambda: now[0])
    return sources, channel, now


def test_fresh_full_graph_brackets_actor_and_reads_only_fixed_complete_catalog_ids():
    source, channel, now = make()
    observed = source.observe()
    source.check_current(observed)
    assert observed.full_scope.digest == full_scope().digest
    assert len(channel.calls) == 7
    assert channel.calls.count(METADATA_PATH) == 2 and channel.calls.count(CATALOG_PATH) == 3
    assert channel.calls.count("/api/v1/tags/zero_trust/7/get") == 2
    assert "synthetic_owner" not in repr(observed) + repr(source)
    assert observed.expires_at == now[0] + 60
    second = source.observe()
    assert source.current_digest(second) == source.current_digest(second)
    with pytest.raises(EmsTagSourceError):
        source.check_current(observed)


@pytest.mark.parametrize("fault", ["owner", "super", "version", "process", "linux", "simple", "limit", "support", "alias"])
def test_metadata_mismatch_refuses_before_inventory(fault):
    source, channel, _ = make()
    data = channel.metadata["data"]
    system, cv = data["consts"]["System"], data["consts"]["ComplianceVerification"]
    if fault == "owner": data["User"]["name"] = "other"
    elif fault == "super": data["User"]["role"]["super"] = False
    elif fault == "version": system["VERSION_FULL"] = "7.4.9.0001"
    elif fault == "process": cv["RuleType"]["PROCESS"] = True
    elif fault == "linux": cv["OS"]["LINUX"] = True
    elif fault == "simple": system["MATCH_TYPE"]["Simple"] = True
    elif fault == "limit": cv["TAG_LENGTH_MAX"] = 59
    elif fault == "support": cv["RuleTypeDetails"]["6"]["OS_TYPES"] = [True]
    else:
        data["User"]["NAME"] = "conflict"
        data["User"]["username"] = "synthetic_owner"
    with pytest.raises(EmsTagSourceError): source.observe()
    assert channel.calls == [METADATA_PATH]
    with pytest.raises(EmsTagSourceError): source.observe()
    assert len(channel.calls) == 1


@pytest.mark.parametrize("fault", ["prior_full_drift", "actor_drift", "catalog_tail", "timeout", "network"])
def test_interrupted_or_changing_join_closes_source_without_an_observation(fault):
    source, channel, now = make()
    def mutate(current, path):
        count = current.calls.count(path)
        if fault == "prior_full_drift" and path == CATALOG_PATH and count == 2:
            current.scope = full_scope(prior_change=True)
        elif fault == "actor_drift" and path == METADATA_PATH and count == 2:
            current.metadata["data"]["User"]["role"]["another_permission"] = True
        elif fault == "catalog_tail" and path == CATALOG_PATH and count == 3:
            current.scope = full_scope(add=True)
        elif fault == "timeout" and path == METADATA_PATH and count == 2:
            now[0] += 60
        elif fault == "network" and path.endswith("/7/get"):
            raise TimeoutError
    channel.mutate = mutate
    with pytest.raises(EmsTagSourceError): source.observe()
    previous = len(channel.calls)
    with pytest.raises(EmsTagSourceError): source.observe()
    assert len(channel.calls) == previous


@pytest.mark.parametrize("fault", ["clone", "scope_tamper", "expiry", "clock_reversal", "closed"])
def test_observation_is_live_exact_untampered_and_fresh(fault):
    source, _, now = make()
    observed = source.observe()
    if fault == "clone": observed = replace(observed)
    elif fault == "scope_tamper": object.__setattr__(observed, "full_scope", full_scope(prior_change=True))
    elif fault == "expiry": now[0] += 60
    elif fault == "clock_reversal": now[0] -= 1
    else: source.close()
    with pytest.raises(EmsTagSourceError): source.check_current(observed)


def test_source_context_binds_instance_actor_and_key_without_exposing_values():
    contexts = []
    for instance, key, role in (("1" * 64, b"s" * 32, {}), ("2" * 64, b"s" * 32, {}),
                                ("1" * 64, b"t" * 32, {}), ("1" * 64, b"s" * 32, {"other": True})):
        source, channel, _ = make(instance=instance, key=key)
        channel.metadata["data"]["User"]["role"].update(role)
        contexts.append(source.observe().source_context_digest)
        source.close()
    assert len(set(contexts)) == 4


def test_newly_added_row_is_not_used_as_the_prospective_absence_scope():
    source, channel, _ = make()
    channel.scope = full_scope(add=True)
    observed = source.observe()
    assert observed.full_scope.catalog.contains_draft(source._draft)
    assert "/api/v1/tags/zero_trust/101/get" in channel.calls


@pytest.mark.parametrize("field,value", [("sites_enabled", True), ("active_vdom", "other"),
    ("show_global", False), ("show_vdom", False), ("is_global", False), ("sites_enabled", 0)])
def test_actual_builtin_scope_is_required_before_inventory(field, value):
    source, channel, _ = make()
    data = channel.metadata["data"]
    if field == "sites_enabled": data["consts"]["System"]["SITES_ENABLED"] = value
    elif field == "is_global": data["User"][field] = value
    else: data[field] = value
    with pytest.raises(EmsTagSourceError): source.observe()
    assert channel.calls == [METADATA_PATH]
