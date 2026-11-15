"""Complete-form copies cannot reinterpret incomplete clones or source drift."""
from copy import deepcopy

import pytest

from fortipam_mcp.client_integrity_association_contract import _digest
from fortipam_mcp.putty_launcher_copy_http_contract import (
    PuttyLauncherCopyContractError, compile_native_putty_copy_body,
    validate_native_putty_copy_detail,
)
from test_client_integrity_association_contract import detail

NAME = "mcp-v4-putty-clone-20261006-r3"


def source():
    value = detail(); value["results"].update(name="PuTTY", q_origin_key="PuTTY", q_ref=4)
    return value


def test_complete_native_copy_preserves_child_and_source_without_rename_or_association():
    value = source(); before = deepcopy(value)
    body = compile_native_putty_copy_body(value, launcher_name=NAME,
        expected_source_configuration_digest=_digest(value["results"]))
    assert value == before and body["name"] == NAME and "$originalName" not in body
    assert set(body) == {"name", "type", "is-file-launcher", "elevation", "session-close-log", "launch-timeout", "os_app"}
    app = body["os_app"][0]
    assert len(body["os_app"]) == 1 and app["os_type"] == "windows"
    assert app["client-software"] == app["exe"] == app["parameter"] == ""
    assert app["init-commands"] == app["clean-commands"] == app["fct-script"] == []
    expected_app = dict(before["results"]["os_app"][0]); del expected_app["q_origin_key"]
    assert app == expected_app
    for key in set(body) - {"name", "os_app"}: assert body[key] == before["results"][key]
    row = deepcopy(before["results"]); row.update(name=NAME, q_origin_key=NAME, q_ref=0)
    copied = dict(before, results=row)
    validate_native_putty_copy_detail(copied, launcher_name=NAME, expected_configuration_digest=_digest(row))
    copied["results"]["os_app"] = []
    with pytest.raises(PuttyLauncherCopyContractError):
        validate_native_putty_copy_detail(copied, launcher_name=NAME, expected_configuration_digest=_digest(row))


@pytest.mark.parametrize("change", [
    lambda r: r.update(name="private-sentinel"),
    lambda r: r.update(q_ref=True),
    lambda r: r.update(os_app=[]),
    lambda r: r["os_app"][0].update(exe="private-sentinel"),
    lambda r: r["os_app"][0].update(**{"client-software":"private-sentinel"}),
    lambda r: r.update(unexpected="private-sentinel"),
])
def test_copy_refuses_unqualified_source_and_never_discloses_values(change):
    value = source(); change(value["results"])
    with pytest.raises(PuttyLauncherCopyContractError) as result:
        compile_native_putty_copy_body(value, launcher_name=NAME,
            expected_source_configuration_digest=_digest(value["results"]))
    assert "private-sentinel" not in str(result.value)


def test_sealed_source_drift_and_mutable_builtin_or_legacy_names_are_refused():
    value = source(); digest = _digest(value["results"])
    value["results"]["launch-timeout"] += 1
    with pytest.raises(PuttyLauncherCopyContractError):
        compile_native_putty_copy_body(value, launcher_name=NAME,
            expected_source_configuration_digest=digest)
    value = source()
    for name in ("PuTTY", "mcp-v4-launcher-clone-20261006-r3"):
        with pytest.raises(PuttyLauncherCopyContractError):
            compile_native_putty_copy_body(value, launcher_name=name,
                expected_source_configuration_digest=digest)
