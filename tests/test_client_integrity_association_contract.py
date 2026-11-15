"""Single-field association preserves complete state and grants no dispatch."""
from copy import deepcopy

import pytest

from fortipam_mcp.client_integrity_association_contract import (
    ClientIntegrityAssociationContractError, _digest,
    compile_native_putty_association_body, compile_native_putty_association_restore_body,
    project_native_putty_association_detail,
)

LAUNCHER = "mcp-v4-putty-clone-20261006-r2"
SOFTWARE = "mcp-v4-client-integrity-hash-20261006-r2"


def detail():
    return {
        "version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
        "path": "secret", "name": "launcher", "vdom": "root", "status": "success",
        "results": {
            "name": LAUNCHER, "type": "ssh", "is-file-launcher": "false", "elevation": "none",
            "session-close-log": "false", "launch-timeout": 10, "q_type": 17,
            "q_path": "secret", "q_name": "launcher", "q_global_entry": False,
            "q_mkey_type": "string", "q_no_edit": False, "q_no_rename": False,
            "q_origin_key": LAUNCHER, "q_static": False, "q_ref": 0,
            "os_app": [{"id": 1, "q_origin_key": 1, "name": "synthetic-client",
                        "os_type": "windows", "ua_pattern": "", "exe": "", "parameter": "",
                        "client-software": "", "multiprocess": "false", "fullscreen-record": "false",
                        "init-commands": [], "clean-commands": [], "fct-script": [],
                        "proc-matcher-type": "none", "proc-matcher-pattern": "", "allow-global-match": "false"}],
        },
    }


def compile_body(payload, digest):
    return compile_native_putty_association_body(
        payload, launcher_name=LAUNCHER, software_name=SOFTWARE, expected_configuration_digest=digest,
    )


def test_associate_complete_readback_and_restore_preserve_every_other_field_without_mutating_inputs():
    payload = detail(); original = deepcopy(payload); baseline = _digest(payload["results"])
    body = compile_body(payload, baseline)
    expected = {k: deepcopy(payload["results"][k]) for k in
                ("name", "type", "is-file-launcher", "elevation", "session-close-log", "launch-timeout", "os_app")}
    del expected["os_app"][0]["q_origin_key"]
    expected["$originalName"] = LAUNCHER
    empty_body = deepcopy(expected)
    expected["os_app"][0]["client-software"] = SOFTWARE
    assert body == expected and payload == original
    after = deepcopy(payload); after["results"]["os_app"][0]["client-software"] = SOFTWARE
    after_original = deepcopy(after)
    evidence = project_native_putty_association_detail(
        after, launcher_name=LAUNCHER, software_name=SOFTWARE, baseline_configuration_digest=baseline,
    )
    assert evidence.configuration_digest == _digest(after["results"])
    assert SOFTWARE not in repr(evidence) and LAUNCHER not in repr(evidence)
    restored = compile_native_putty_association_restore_body(
        after, launcher_name=LAUNCHER, software_name=SOFTWARE, baseline_configuration_digest=baseline,
        expected_associated_configuration_digest=evidence.configuration_digest,
    )
    assert restored == empty_body and after == after_original
    after["results"]["launch-timeout"] += 1
    with pytest.raises(ClientIntegrityAssociationContractError):
        compile_native_putty_association_restore_body(
            after, launcher_name=LAUNCHER, software_name=SOFTWARE, baseline_configuration_digest=baseline,
            expected_associated_configuration_digest=evidence.configuration_digest,
        )


@pytest.mark.parametrize("change", [
    {"q_ref": False}, {"q_ref": 1}, {"q_static": True}, {"q_type": True},
    {"q_no_edit": True}, {"q_origin_key": "private-sentinel"}, {"type": "rdp"},
    {"unknown": "private-sentinel"}, {"launch-timeout": True}, {"is-file-launcher": "true"},
])
def test_sealed_digest_does_not_supply_fixture_eligibility_or_disclose_values(change):
    payload = detail(); payload["results"].update(change)
    with pytest.raises(ClientIntegrityAssociationContractError, match="unavailable") as failure:
        compile_body(payload, _digest(payload["results"]))
    assert "private-sentinel" not in str(failure.value)


@pytest.mark.parametrize("change", [
    {"exe": "private-sentinel"}, {"parameter": "private-sentinel"},
    {"init-commands": [{"id": 1, "cmd": "private-sentinel"}]}, {"fct-script": False},
    {"client-software": SOFTWARE}, {"os_type": "linux"}, {"id": True}, {"q_origin_key": 2},
    {"unknown": "private-sentinel"}, {"multiprocess": True},
])
def test_custom_executables_commands_or_preexisting_associations_are_not_admitted(change):
    payload = detail(); payload["results"]["os_app"][0].update(change)
    with pytest.raises(ClientIntegrityAssociationContractError) as failure:
        compile_body(payload, _digest(payload["results"]))
    assert "private-sentinel" not in str(failure.value)


def test_complete_state_drift_wrong_product_and_builtin_or_old_names_are_refused():
    payload = detail(); baseline = _digest(payload["results"])
    changed = deepcopy(payload); changed["results"]["os_app"][0]["name"] = "drift"
    with pytest.raises(ClientIntegrityAssociationContractError): compile_body(changed, baseline)
    for change in ({"build": True}, {"version": "v1.9.1"}, {"http_method": "POST"}, {"status": "error"}):
        with pytest.raises(ClientIntegrityAssociationContractError): compile_body({**payload, **change}, baseline)
    for launcher, software in (("PuTTY", SOFTWARE), ("mcp-v4-launcher-clone-mini-r1", SOFTWARE),
                               (LAUNCHER, "mcp-v4-client-integrity-rest-20261004-r7"),
                               (LAUNCHER + "/escape", SOFTWARE)):
        with pytest.raises(ClientIntegrityAssociationContractError):
            compile_native_putty_association_body(payload, launcher_name=launcher, software_name=software,
                                                  expected_configuration_digest=baseline)
    associated = deepcopy(payload); associated["results"]["os_app"][0]["client-software"] = SOFTWARE
    for scope in ("app", "metadata", "top"):
        changed = deepcopy(associated)
        if scope == "app": changed["results"]["os_app"][0]["fullscreen-record"] = "drift"
        elif scope == "metadata": changed["results"]["q_type"] += 1
        else: changed["results"]["elevation"] = "drift"
        with pytest.raises(ClientIntegrityAssociationContractError):
            project_native_putty_association_detail(changed, launcher_name=LAUNCHER, software_name=SOFTWARE,
                                                    baseline_configuration_digest=baseline)
    for malformed in ("", "a" * 63, "A" * 64, False):
        with pytest.raises(ClientIntegrityAssociationContractError): compile_body(payload, malformed)
