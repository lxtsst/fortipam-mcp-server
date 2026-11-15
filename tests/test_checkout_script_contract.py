from copy import deepcopy

import pytest

from fortipam_mcp.checkout_script_contract import (
    CheckoutScriptContractError, compile_fixed_checkout_script_body,
    fixed_checkout_script_readback,
    compile_fixed_windows_probe_script_body, fixed_windows_probe_script_readback,
)


def envelope(row, *, method="GET", status="success"):
    return {"version": "v7.0.0", "build": 29, "http_status": 200,
            "http_method": method, "status": status, "path": "secret", "name": "script",
            "results": row}


DEFAULT = envelope({"name": "", "type": "powershell", "comments": "", "script": "",
                    "expect-type": "success", "expect-string": "", "log-trigger": "failure"})


@pytest.mark.parametrize("hook,label", [("checkout", "Checkout"), ("checkin", "Checkin")])
def test_fixed_body_rejects_drift_and_exactly_projects_owned_script(hook, label):
    name = "MCPV4" + label + "20261001R1"
    body = compile_fixed_checkout_script_body(DEFAULT, hook=hook, target_name=name)
    assert set(body) == {"name", "type", "comments", "script", "expect-type", "expect-string", "log-trigger"}
    assert body["script"] == "echo " + body["expect-string"] and body["type"] == "ssh-script"
    assert DEFAULT["results"]["script"] == ""
    collection = envelope([body], method="POST")
    assert fixed_checkout_script_readback(collection, hook=hook, target_name=name)
    assert fixed_checkout_script_readback(envelope(body), hook=hook, target_name=name, detail=True)
    for key, value in (("build", True), ("version", "v1.9.1"), ("http_method", "POST")):
        bad = deepcopy(DEFAULT); bad[key] = value
        with pytest.raises(CheckoutScriptContractError, match="^The fixed checkout Script contract is unavailable.$"):
            compile_fixed_checkout_script_body(bad, hook=hook, target_name=name)
    for key, value in (("type", "ssh-script"), ("script", "private script"), ("comment", ""), ("comments", "private drift")):
        bad = deepcopy(DEFAULT); bad["results"][key] = value
        with pytest.raises(CheckoutScriptContractError):
            compile_fixed_checkout_script_body(bad, hook=hook, target_name=name)
    with pytest.raises(CheckoutScriptContractError):
        compile_fixed_checkout_script_body(DEFAULT, hook=hook, target_name="private-selector")
    assert not fixed_checkout_script_readback(envelope([body, body], method="POST"), hook=hook, target_name=name)
    assert not fixed_checkout_script_readback(envelope([body, {**body, "name": "other"}]), hook=hook, target_name=name, detail=True)
    for key in body:
        bad = deepcopy(body); bad[key] = "private drift"
        assert not fixed_checkout_script_readback(envelope([bad], method="POST"), hook=hook, target_name=name)
    assert not fixed_checkout_script_readback(envelope([body], method="GET"), hook=hook, target_name=name)
    assert not fixed_checkout_script_readback(envelope([body], method="POST", status="OK"), hook=hook, target_name=name)
    singular = {**body, "comment": body["comments"]}
    assert not fixed_checkout_script_readback(envelope([singular], method="POST"), hook=hook, target_name=name)
    del singular["comments"]
    assert not fixed_checkout_script_readback(envelope([singular], method="POST"), hook=hook, target_name=name)


def test_windows_probe_is_one_constant_marker_and_cannot_substitute_for_ssh_hook():
    name = "MCPV4WinrmProbe20261021R1"
    body = compile_fixed_windows_probe_script_body(DEFAULT, target_name=name)
    assert body == {"name": name, "type": "powershell", "comments": "BP019 fixed harmless Windows execution probe",
        "script": "Write-Output 'BP019_WINRM_PROBE_OK'", "expect-type": "success",
        "expect-string": "BP019_WINRM_PROBE_OK", "log-trigger": "any"}
    assert fixed_windows_probe_script_readback(envelope(body), target_name=name, detail=True)
    assert fixed_windows_probe_script_readback(envelope([body], method="POST"), target_name=name)
    assert not fixed_checkout_script_readback(envelope([body], method="POST"), hook="checkout", target_name=name)
    assert not fixed_windows_probe_script_readback(envelope([body, body], method="POST"), target_name=name)
    assert not fixed_windows_probe_script_readback(envelope([body], method="POST", status="OK"), target_name=name)
    assert DEFAULT["results"]["script"] == ""


@pytest.mark.parametrize("field,value", [("type", "ssh-script"), ("script", "Remove-LocalUser -Name private"),
    ("expect-string", "other"), ("comments", "other"), ("log-trigger", "failure"),
    ("name", "MCPV4WinrmProbe20261021R2"), ("expect-type", "failure"), ("comment", "")])
def test_windows_probe_refuses_changed_command_definition_or_native_field_shape(field, value):
    name = "MCPV4WinrmProbe20261021R1"
    body = compile_fixed_windows_probe_script_body(DEFAULT, target_name=name)
    assert not fixed_windows_probe_script_readback(envelope([{**body, field: value}], method="POST"), target_name=name)


@pytest.mark.parametrize("fault", ["nonblank-default", "extra-default", "foreign-name", "foreign-version", "boolean-build"])
def test_windows_probe_cannot_admit_other_defaults_or_a_caller_chosen_command(fault):
    default = deepcopy(DEFAULT); name = "MCPV4WinrmProbe20261021R1"
    if fault == "nonblank-default": default["results"]["script"] = "synthetic-private-command"
    if fault == "extra-default": default["results"]["comment"] = ""
    if fault == "foreign-name": name = "unbounded-selector"
    if fault == "foreign-version": default["version"] = "v1.9.1"
    if fault == "boolean-build": default["build"] = True
    with pytest.raises(CheckoutScriptContractError, match="^The fixed checkout Script contract is unavailable.$"):
        compile_fixed_windows_probe_script_body(default, target_name=name)
