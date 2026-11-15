"""A fixed native custom definition cannot introduce arbitrary commands."""
from copy import deepcopy

import pytest

from fortipam_mcp.client_integrity_association_contract import _digest
from fortipam_mcp.putty_launcher_windows_http_contract import (
    PARAMETERS, WindowsPuttyApplication, WindowsPuttyLauncherContractError,
    compile_native_windows_putty_body, project_native_windows_putty_row,
    compile_native_windows_putty_association_body,
    project_native_windows_putty_association_detail,
    compile_native_windows_putty_association_restore_body,
)
from test_putty_launcher_copy_http_contract import source as implicit_source, NAME


def source():
    payload = implicit_source(); payload["results"].update(**{"launch-timeout":30,"session-close-log":"multiple"})
    payload["results"]["os_app"][0].update(**{"proc-matcher-type":"default","multiprocess":"disable","fullscreen-record":"disable","allow-global-match":"disable"})
    return payload

APPLICATION = WindowsPuttyApplication(r"C:\Windows\Temp\fpam-bp009-putty-candidate-20261006-r1.exe", "a"*64)


def test_fixed_native_windows_body_and_complete_readback_preserve_source():
    payload = source(); before = deepcopy(payload)
    body = compile_native_windows_putty_body(payload, launcher_name=NAME, application=APPLICATION,
        expected_source_configuration_digest=_digest(payload["results"]))
    assert payload == before and "$originalName" not in body
    expected = deepcopy(before["results"]); expected.update(body, q_origin_key=NAME, q_ref=0)
    expected["os_app"][0]["q_origin_key"] = 1
    row = project_native_windows_putty_row(dict(payload, results=expected), launcher_name=NAME,
        application=APPLICATION, expected_configuration_digest=_digest(expected))
    assert row == expected and row["os_app"][0]["exe"] == APPLICATION.executable_path
    assert row["os_app"][0]["parameter"] == PARAMETERS
    assert row["os_app"][0]["client-software"] == ""
    restored = deepcopy(row); restored.update(name="PuTTY", q_origin_key="PuTTY", q_ref=4)
    restored["os_app"][0].update(exe="", parameter="")
    assert restored == before["results"]
    for drift in ("exe", "parameter", "client-software", "proc-matcher-pattern"):
        changed = deepcopy(row); changed["os_app"][0][drift] = "private-sentinel"
        with pytest.raises(WindowsPuttyLauncherContractError) as failure:
            project_native_windows_putty_row(dict(payload,results=changed), launcher_name=NAME,
                application=APPLICATION, expected_configuration_digest=_digest(row))
        assert "private-sentinel" not in str(failure.value)


@pytest.mark.parametrize("path", [r"C:\Windows\System32\cmd.exe", r"C:\Windows\Temp\other.exe",
    r"C:\Windows\Temp\fpam-bp009-putty-candidate-20261006-r1.exe & private-sentinel",
    r"C:\Windows\Temp\fpam-bp009-putty-candidate-20261006-r1.exe\..\other.exe"])
def test_application_cannot_select_arbitrary_paths_or_shell_commands(path):
    with pytest.raises(WindowsPuttyLauncherContractError) as failure:
        WindowsPuttyApplication(path, "a"*64)
    assert "private-sentinel" not in str(failure.value)


def test_source_drift_commands_and_unqualified_application_are_denied():
    payload = source(); digest = _digest(payload["results"])
    for change in ({"parameter":"private-sentinel"}, {"exe":"private-sentinel"},
                   {"init-commands":[{"id":1,"cmd":"private-sentinel"}]}, {"id":2,"q_origin_key":2}):
        changed = deepcopy(payload); changed["results"]["os_app"][0].update(change)
        with pytest.raises(WindowsPuttyLauncherContractError):
            compile_native_windows_putty_body(changed, launcher_name=NAME, application=APPLICATION,
                expected_source_configuration_digest=_digest(changed["results"]))
    payload["results"]["launch-timeout"] += 1
    with pytest.raises(WindowsPuttyLauncherContractError):
        compile_native_windows_putty_body(payload, launcher_name=NAME, application=APPLICATION,
            expected_source_configuration_digest=digest)
    with pytest.raises(WindowsPuttyLauncherContractError):
        compile_native_windows_putty_body(source(), launcher_name=NAME, application=object(),
            expected_source_configuration_digest=digest)


SOFTWARE = "mcp-v4-client-integrity-hash-20261006-r2"


def windows_detail():
    payload = source()
    body = compile_native_windows_putty_body(payload, launcher_name=NAME, application=APPLICATION,
        expected_source_configuration_digest=_digest(payload["results"]))
    row = payload["results"]
    row.update(body, q_origin_key=NAME, q_ref=0)
    row["os_app"][0]["q_origin_key"] = 1
    return payload


def associate(payload, baseline):
    return compile_native_windows_putty_association_body(payload, launcher_name=NAME,
        software_name=SOFTWARE, application=APPLICATION, baseline_configuration_digest=baseline)


def test_fixed_windows_association_readback_and_restore_change_only_one_reference():
    payload = windows_detail(); original = deepcopy(payload); baseline = _digest(payload["results"])
    expected = {k: deepcopy(payload["results"][k]) for k in (
        "name", "type", "is-file-launcher", "elevation", "session-close-log", "launch-timeout", "os_app")}
    del expected["os_app"][0]["q_origin_key"]
    expected["$originalName"] = NAME
    restored_body = deepcopy(expected)
    expected["os_app"][0]["client-software"] = SOFTWARE
    assert associate(payload, baseline) == expected and payload == original
    after = deepcopy(payload); after["results"]["os_app"][0]["client-software"] = SOFTWARE
    evidence = project_native_windows_putty_association_detail(after, launcher_name=NAME,
        software_name=SOFTWARE, application=APPLICATION, baseline_configuration_digest=baseline)
    assert evidence.configuration_digest == _digest(after["results"])
    assert NAME not in repr(evidence) and SOFTWARE not in repr(evidence)
    assert compile_native_windows_putty_association_restore_body(after, launcher_name=NAME,
        software_name=SOFTWARE, application=APPLICATION, baseline_configuration_digest=baseline,
        expected_associated_configuration_digest=evidence.configuration_digest) == restored_body
    assert APPLICATION.executable_path == after["results"]["os_app"][0]["exe"]
    # The old empty-executable contract cannot adopt this distinct Windows profile.
    from fortipam_mcp.client_integrity_association_contract import (
        ClientIntegrityAssociationContractError, compile_native_putty_association_body,
    )
    with pytest.raises(ClientIntegrityAssociationContractError):
        compile_native_putty_association_body(payload, launcher_name=NAME, software_name=SOFTWARE,
            expected_configuration_digest=baseline)


def test_windows_association_rejects_commands_wrong_artifact_and_ineligible_or_drifted_state():
    payload = windows_detail(); baseline = _digest(payload["results"])
    changes = [
        ("top", {"q_ref":1}), ("top", {"q_no_edit":True}), ("top", {"q_ref":False}),
        ("app", {"parameter":"private-sentinel"}), ("app", {"exe":"private-sentinel"}),
        ("app", {"init-commands":[{"id":1,"cmd":"private-sentinel"}]}),
        ("app", {"client-software":SOFTWARE}), ("app", {"id":2,"q_origin_key":2}),
        ("app", {"multiprocess":"enable"}), ("top", {"launch-timeout":14}),
    ]
    for scope, change in changes:
        changed = deepcopy(payload)
        (changed["results"] if scope == "top" else changed["results"]["os_app"][0]).update(change)
        with pytest.raises(WindowsPuttyLauncherContractError) as failure:
            # Even a caller's matching digest cannot override fixed eligibility.
            associate(changed, _digest(changed["results"]))
        assert "private-sentinel" not in str(failure.value)
    payload["results"]["os_app"][0]["name"] = "drift"
    with pytest.raises(WindowsPuttyLauncherContractError): associate(payload, baseline)
    for software in ("PuTTY", "mcp-v4-client-integrity-rest-20261004-r7", SOFTWARE+"/escape"):
        with pytest.raises(WindowsPuttyLauncherContractError):
            compile_native_windows_putty_association_body(windows_detail(), launcher_name=NAME,
                software_name=software, application=APPLICATION, baseline_configuration_digest=baseline)


def test_windows_association_readback_and_restore_refuse_reference_or_complete_state_drift():
    payload = windows_detail(); baseline = _digest(payload["results"])
    payload["results"]["os_app"][0]["client-software"] = SOFTWARE
    associated = _digest(payload["results"])
    for scope, change in (("app", {"client-software":""}), ("app", {"parameter":"drift"}),
                          ("app", {"exe":"drift"}), ("app", {"unknown":False}),
                          ("top", {"q_type":18}), ("top", {"elevation":"all"}),
                          ("top", {"os_app":[]})):
        changed = deepcopy(payload)
        (changed["results"] if scope == "top" else changed["results"]["os_app"][0]).update(change)
        with pytest.raises(WindowsPuttyLauncherContractError):
            project_native_windows_putty_association_detail(changed, launcher_name=NAME,
                software_name=SOFTWARE, application=APPLICATION, baseline_configuration_digest=baseline)
    for seal in ("", "a"*63, "A"*64, False, "b"*64):
        assert seal != associated
        with pytest.raises(WindowsPuttyLauncherContractError):
            compile_native_windows_putty_association_restore_body(payload, launcher_name=NAME,
                software_name=SOFTWARE, application=APPLICATION, baseline_configuration_digest=baseline,
                expected_associated_configuration_digest=seal)
