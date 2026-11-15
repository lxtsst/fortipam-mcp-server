"""Synthetic serial-prefix, label and complete usage contract regressions."""
from copy import deepcopy

import pytest

from fortipam_mcp.ems_tag_contract import DisabledLinuxProcessTag
from fortipam_mcp.ems_tag_fpa_mapping import qualify_fpa_tag_mapping, fpa_address_reference_type

SERIAL = "FCTEMSLAB01"
DRAFT = DisabledLinuxProcessTag("a" * 32)


def row(label="existing", *, mac=False):
    return {"name": ("MAC_" if mac else "") + SERIAL + "_ZTNA_" + label,
        "type": "dynamic", "sub-type": "ems-tag", "obj-tag": label, "obj-type": "mac" if mac else "ip",
        "tag-type": "ztna", "tag-detection-level": "medium", "q_ref": 0, "q_global_entry": False}


def frame(*rows):
    return {"results": list(rows), "matched_count": len(rows), "limit_reached": False}


def qualify(value):
    return qualify_fpa_tag_mapping(value, ems_serial=SERIAL, draft=DRAFT)


def test_exact_status_serial_accepts_alphanumeric_suffix_and_requires_both_owned_address_usages():
    baseline = qualify(frame(row()))
    ip, mac = row(DRAFT._name), row(DRAFT._name, mac=True)
    owned = qualify(frame(row(), ip, mac))
    assert baseline.candidate_absent and owned.without_owned_digest == baseline.digest
    assert not owned.candidate_absent and owned.positive_serial_prefix_count == 3
    usage = {value["name"]: {"mkey": value["name"], "results": {"currently_using": []}} for value in (ip, mac)}
    owned.require_zero_owned_references(usage)
    assert SERIAL not in repr(owned) and DRAFT._name not in repr(owned)
    for fault in ("missing", "wrong_mkey", "unknown", "nonempty", "extra"):
        changed = deepcopy(usage)
        if fault == "missing": changed.pop(mac["name"])
        elif fault == "wrong_mkey": changed[ip["name"]]["mkey"] = "another-object"
        elif fault == "unknown": changed[ip["name"]]["results"] = {}
        elif fault == "nonempty": changed[ip["name"]]["results"]["currently_using"] = [{"reference": "synthetic"}]
        else: changed["foreign"] = {}
        with pytest.raises(ValueError): owned.require_zero_owned_references(changed)


@pytest.mark.parametrize("fault", ["wrong_serial", "wrong_type", "label_case", "missing_label", "unknown_ref",
    "global", "duplicate", "extra_field", "partial", "bool_count", "no_control"])
def test_collision_unknown_scope_and_incomplete_catalog_do_not_admit_owned_tags(fault):
    own = row(DRAFT._name)
    value = frame(row(), own)
    if fault == "wrong_serial": own["name"] = "FOREIGN_ZTNA_" + DRAFT._name
    elif fault == "wrong_type": own["type"] = "ipmask"
    elif fault == "label_case": own["obj-tag"] = DRAFT._name.upper()
    elif fault == "missing_label": own.pop("obj-tag")
    elif fault == "unknown_ref": own.pop("q_ref")
    elif fault == "global": own["q_global_entry"] = True
    elif fault == "duplicate": value = frame(own, own)
    elif fault == "extra_field": own["unknown"] = "drift"
    elif fault == "partial": value["limit_reached"] = True
    elif fault == "bool_count": value["matched_count"] = True
    else: value = frame({**row(), "name": "FOREIGN_ZTNA_existing"})
    with pytest.raises(ValueError): qualify(value)


def test_address_reference_type_is_unique_and_virtual_tag_type_does_not_substitute():
    value = {"results": {"by_type": {"17": {"path": "firewall.address"}, "99": {"path": "firewall.ztna-tag"}}}}
    assert fpa_address_reference_type(value) == 17
    for keys in ({"99": {"path": "firewall.ztna-tag"}}, {"017": {"path": "firewall.address"}},
                 {"17": {"path": "firewall.address"}, "18": {"path": "firewall.address"}}):
        with pytest.raises(ValueError): fpa_address_reference_type({"results": {"by_type": keys}})


def test_nonzero_metadata_reference_and_unrelated_projection_drift_remain_visible():
    baseline = qualify(frame(row()))
    own = row(DRAFT._name); own["q_ref"] = 1
    mapped = qualify(frame(row(), own))
    with pytest.raises(ValueError):
        mapped.require_zero_owned_references({own["name"]: {"mkey": own["name"], "results": {"currently_using": []}}})
    changed = row(); changed["tag-detection-level"] = "high"
    assert qualify(frame(changed, own)).without_owned_digest != baseline.digest
