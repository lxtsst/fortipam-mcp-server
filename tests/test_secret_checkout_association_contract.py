from copy import deepcopy

import pytest

from fortipam_mcp.checkout_script_contract import compile_fixed_checkout_script_body
from fortipam_mcp.secret_checkout_association_contract import (
    CONTROLS, IDLE_FIELD, PREREQUISITES, SecretCheckoutAssociationContractError,
    compile_fixed_secret_checkout_body, project_secret_checkout_metadata,
)


IDENTITY = {"id": 17, "folder": 9, "name": "mcp-v4-bp008-checkout-20261001-r3",
            "template": "Unix Account (SSH Password)"}
BASELINE = {"checkout": "disable", "checkout-script": "", "checkin-script": "",
            "checkout-duration": 60, "checkout-duration-renew": "disable",
            "checkout-renew-times": 3, "checkin-pwd-change": "disable"}
IDLE = 10
EXECUTION_ID = 41
EXECUTION_NAME = "mcp-v4-bp008-checkout-20261001-r2"
EXECUTION_METADATA = {"target-privilege-account": "disable", "associated-secret": EXECUTION_ID,
                      "target-info": {"priv_acct": 0}}
CHECKOUT = "MCPV4Checkout20261001R3"
CHECKIN = "MCPV4Checkin20261001R3"


def envelope(row, *, name="database", method="GET"):
    return {"version": "v7.0.0", "build": 29, "http_status": 200,
            "http_method": method, "status": "OK" if name == "database" else "success", "path": "secret", "name": name,
            "results": row}


def checkout_envelope(row):
    return envelope({**EXECUTION_METADATA, **row})


DEFAULT = envelope({"name": "", "type": "powershell", "comments": "", "script": "",
                    "expect-type": "success", "expect-string": "", "log-trigger": "failure"}, name="script")
SCRIPTS = envelope([
    compile_fixed_checkout_script_body(DEFAULT, hook=hook, target_name=name)
    for hook, name in (("checkout", CHECKOUT), ("checkin", CHECKIN))
], name="script", method="POST")


@pytest.mark.parametrize("restore", [False, True])
def test_fixed_association_and_inverse_preserve_baseline_and_reject_drift(restore):
    bound = {"identity": IDENTITY, "checkout_script": CHECKOUT, "checkin_script": CHECKIN,
             "baseline_controls": BASELINE, "force_idle_time": IDLE, "execution_secret_id": EXECUTION_ID}
    original = checkout_envelope({**IDENTITY, **BASELINE, "proxy": "enable", "recording": "enable", IDLE_FIELD: IDLE, "field": [{"value": "private-material"}],
                         "target": "private-target", "description": "preserve"})
    before = project_secret_checkout_metadata(original)
    associated = compile_fixed_secret_checkout_body(before, SCRIPTS, **bound)
    assert set(associated) == set(IDENTITY) | CONTROLS | PREREQUISITES | {
        IDLE_FIELD, "associated-secret", "target-privilege-account"}
    assert associated["checkout-duration"] == 5 and associated["checkout"] == "enable"
    assert "private-material" not in repr(before) + repr(associated)
    assert original["results"]["checkout"] == "disable"
    if restore:
        before = checkout_envelope(associated)
        result = compile_fixed_secret_checkout_body(before, SCRIPTS, restore=True, **bound)
        assert result == {**IDENTITY, **BASELINE, "proxy": "enable", "recording": "enable", IDLE_FIELD: IDLE,
                          "associated-secret": EXECUTION_ID, "target-privilege-account": "disable"}
    for key, value in (("build", True), ("version", "v1.9.1"), ("http_method", "PUT")):
        bad = deepcopy(before); bad[key] = value
        with pytest.raises(SecretCheckoutAssociationContractError, match="^The fixed Secret checkout association is unavailable.$"):
            compile_fixed_secret_checkout_body(bad, SCRIPTS, restore=restore, **bound)
    for key in CONTROLS | set(IDENTITY) | PREREQUISITES | {IDLE_FIELD}:
        bad = deepcopy(before); bad["results"][key] = "private-drift"
        with pytest.raises(SecretCheckoutAssociationContractError):
            compile_fixed_secret_checkout_body(bad, SCRIPTS, restore=restore, **bound)
    for controls in ({**BASELINE, "checkin-pwd-change": "enable"}, {**BASELINE, "checkout-duration": True}):
        with pytest.raises(SecretCheckoutAssociationContractError):
            compile_fixed_secret_checkout_body(before, SCRIPTS, restore=restore, **{**bound, "baseline_controls": controls})
    changed = deepcopy(SCRIPTS); changed["results"][1]["script"] = "private-command"
    with pytest.raises(SecretCheckoutAssociationContractError):
        compile_fixed_secret_checkout_body(before, changed, restore=restore, **bound)
    with pytest.raises(SecretCheckoutAssociationContractError):
        compile_fixed_secret_checkout_body(before, SCRIPTS, restore=restore, **{**bound, "checkin_script": CHECKIN + "1"})


def test_native_build29_numeric_constraints_reject_invalid_baseline():
    for key, value in (("checkout-duration", 2), ("checkout-duration", 1441),
                       ("checkout-renew-times", 0), ("checkout-renew-times", 6)):
        controls = {**BASELINE, key: value}
        with pytest.raises(SecretCheckoutAssociationContractError):
            compile_fixed_secret_checkout_body(checkout_envelope({**IDENTITY, **controls, "proxy": "enable", "recording": "enable", IDLE_FIELD: IDLE}), SCRIPTS,
                identity=IDENTITY, checkout_script=CHECKOUT, checkin_script=CHECKIN,
                baseline_controls=controls, force_idle_time=IDLE, execution_secret_id=EXECUTION_ID)


@pytest.mark.parametrize("idle", [-1, 31, True, "10"])
def test_idle_binding_rejects_non_native_range_or_type(idle):
    with pytest.raises(SecretCheckoutAssociationContractError):
        compile_fixed_secret_checkout_body(checkout_envelope({**IDENTITY, **BASELINE, "proxy": "enable", "recording": "enable", IDLE_FIELD: idle}), SCRIPTS,
            identity=IDENTITY, checkout_script=CHECKOUT, checkin_script=CHECKIN,
            baseline_controls=BASELINE, force_idle_time=idle, execution_secret_id=EXECUTION_ID)


@pytest.mark.parametrize("field", ["proxy", "recording"])
def test_idle_prerequisite_rejects_disabled_mode_before_any_dispatch(field):
    row = {**IDENTITY, **BASELINE, "proxy": "enable", "recording": "enable", IDLE_FIELD: IDLE}
    row[field] = "disable"
    with pytest.raises(SecretCheckoutAssociationContractError):
        compile_fixed_secret_checkout_body(checkout_envelope(row), SCRIPTS, identity=IDENTITY,
            checkout_script=CHECKOUT, checkin_script=CHECKIN,
            baseline_controls=BASELINE, force_idle_time=IDLE, execution_secret_id=EXECUTION_ID)


@pytest.mark.parametrize("change", [
    {"associated-secret": 0}, {"associated-secret": True}, {"associated-secret": "41"},
    {"associated-secret": 42}, {"associated-secret": IDENTITY["id"]},
    {"target-privilege-account": "enable"}, {"target-info": None},
    {"target-info": {}}, {"target-info": {"priv_acct": True}},
    {"target-info": {"priv_acct": "0"}}, {"target-info": {"priv_acct": 42}},
])
def test_execution_account_relationship_must_be_exact_without_target_privilege(change):
    before = checkout_envelope({**IDENTITY, **BASELINE, "proxy": "enable", "recording": "enable",
                                IDLE_FIELD: IDLE, **change})
    with pytest.raises(SecretCheckoutAssociationContractError):
        compile_fixed_secret_checkout_body(before, SCRIPTS, identity=IDENTITY,
            checkout_script=CHECKOUT, checkin_script=CHECKIN, baseline_controls=BASELINE,
            force_idle_time=IDLE, execution_secret_id=EXECUTION_ID)


def test_script_free_checkout_preserves_relation_and_inverse_without_script_payload():
    before = checkout_envelope({**IDENTITY, **BASELINE, "proxy": "enable", "recording": "enable", IDLE_FIELD: IDLE})
    bound = {"identity": IDENTITY, "checkout_script": "", "checkin_script": "",
             "baseline_controls": BASELINE, "force_idle_time": IDLE, "execution_secret_id": EXECUTION_ID}
    basic = compile_fixed_secret_checkout_body(before, None, **bound)
    assert basic["checkout"] == "enable" and basic["checkout-duration"] == 5
    assert basic["checkout-script"] == basic["checkin-script"] == ""
    assert basic["associated-secret"] == EXECUTION_ID
    restored = compile_fixed_secret_checkout_body(checkout_envelope(basic), None, restore=True, **bound)
    assert all(restored[key] == value for key, value in BASELINE.items())
    for change, scripts in (({}, SCRIPTS), ({"checkout_script": CHECKOUT}, None),
                            ({"checkin_script": CHECKIN}, None), ({"checkout_script": None}, None)):
        with pytest.raises(SecretCheckoutAssociationContractError):
            compile_fixed_secret_checkout_body(before, scripts, **{**bound, **change})
