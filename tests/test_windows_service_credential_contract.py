"""Closed nonprivileged service proposal and selected native metadata."""
from dataclasses import replace
import json
import hashlib

import pytest

from fortipam_mcp import windows_service_credential_contract as c
from fortipam_mcp import windows_privileged_secret_contract as privileged
from fortipam_mcp import windows_execution_secret_contract as execution
from test_windows_privileged_secret_contract import SERIAL, NATIVE_UUID, defaults


def binding(**changes):
    value = c.WindowsServiceCredentialBinding("MCPV4SvcCred20261024R1", "Existing-Unit-Target",
        "192.0.2.44", "UNIT-WINDOWS", 41, hashlib.sha256(SERIAL.encode()).hexdigest(),
        "a"*64, "b"*64, "c"*64, "d"*64, "e"*64, "f"*64, "0"*64, "1"*64)
    return replace(value, **changes)


def build(profile=None, user=b"UNIT-WINDOWS\\labuser", password=b"synthetic-credential", **kwargs):
    return c.build_windows_service_credential_body(profile or binding(), defaults(), create_uuid=execution.REQUEST_UUID,
        username=memoryview(bytearray(user)).toreadonly(), password=memoryview(bytearray(password)).toreadonly(), **kwargs)


def postcondition():
    body = build()
    try: row = json.loads(body)
    finally: body.clear()
    row.update(id=70, uuid=NATIVE_UUID, subscriber=[], q_origin_key=70,
        **{"target-info": {"priv_acct": 0}, "instruction-profile": "",
           "totp-setting": {"status": "disable", "shared-key": None},
           "future-setting": {"nested-secret-render": "SYNTHETIC_OPAQUE_DO_NOT_DECODE"}})
    row["field"] = [{"id": 1, "name": "Password", "value": "SYNTHETIC_MASK_DO_NOT_DECODE"},
                    {"id": 2, "name": "Username", "value": "UNIT-WINDOWS\\labuser"}]
    return dict(version="v7.0.0", build=29, http_method="GET", http_status=200, status="OK",
                path="secret", name="database", vdom="root", serial=SERIAL, results=row)


def consume(value):
    raw = bytearray(json.dumps(value, separators=(",", ":")).encode())
    try:
        return c.consume_windows_service_credential_metadata(raw, binding(), expected_secret_id=70,
            expected_native_uuid=NATIVE_UUID)
    finally: assert not raw


def test_service_proposal_fixes_nonprivilege_without_interactive_or_automatic_effects():
    body = build()
    try:
        value = json.loads(body)
        assert value["target-privilege-account"] == "disable"
        assert value["target"] == binding().target_name and value["template"] == "Windows Machine"
        assert value["dependency"] == [] and value["associated-secret"] == 0
        assert value["auto-association"] == value["recording"] == value["password-changer"] == "disable"
        for name in ("rdp", "ssh", "sftp", "http", "samba", "telnet", "vnc", "ldaps"):
            assert value[name+"-service-status"] == "down"
        assert [entry["name"] for entry in value["field"]] == ["Password", "Username"]
        assert not binding().summary()["nonadmin_subject_qualified"]
        assert not binding().summary()["original_subject_sid_qualified"]
    finally: body.clear()


@pytest.mark.parametrize("field", ["target_reference_context_digest", "subject_context_digest", "subject_sid_digest",
    "material_source_context_digest", "service_context_digest", "association_context_digest", "folder_context_digest", "private_nonce"])
def test_original_subject_material_service_and_association_contexts_are_bound_not_attested(field):
    assert binding().parameters_digest != binding(**{field: "2"*64}).parameters_digest
    with pytest.raises(c.WindowsServiceCredentialError): binding(**{field: "invalid"})


@pytest.mark.parametrize("changes", [{"secret_name": "MCPV4SvcPriv20261024R1"},
    {"target_name": "MCPV4WinTarget20261022R3"}, {"target_name": " target"}, {"target_name": "target\n"},
    {"folder_id": True}, {"target_address": "127.0.0.1"}, {"machine_name": "domain\\machine"}])
def test_existing_reference_and_closed_service_namespace_cannot_select_old_objects(changes):
    with pytest.raises(c.WindowsServiceCredentialError): binding(**changes)


def test_distinct_exact_binding_types_cannot_switch_privilege_or_reuse_the_execution_profile():
    from test_windows_privileged_secret_contract import binding as privileged_binding
    for profile in (privileged_binding(),):
        with pytest.raises(c.WindowsServiceCredentialError): build(profile=profile)
    user = memoryview(bytearray(b"UNIT-WINDOWS\\labuser")).toreadonly()
    password = memoryview(bytearray(b"synthetic-credential")).toreadonly()
    with pytest.raises(privileged.WindowsPrivilegedSecretError):
        privileged.build_windows_privileged_secret_body(binding(), defaults(), create_uuid=execution.REQUEST_UUID,
            username=user, password=password)
    with pytest.raises(execution.WindowsExecutionSecretError):
        execution.build_windows_execution_secret_body(binding(), defaults(), create_uuid=execution.REQUEST_UUID,
            username=user, password=password)


def test_selected_service_metadata_has_no_source_or_recovery_authority_and_decodes_no_material(monkeypatch):
    scalar = privileged.parser._scalar
    def check(raw, span):
        assert not any(marker in raw[slice(*span)] for marker in (b"DO_NOT_DECODE", b"labuser"))
        return scalar(raw, span)
    monkeypatch.setattr(privileged.parser, "_scalar", check)
    result = consume(postcondition())
    assert result.native_secret_id == 70 and result.native_uuid == NATIVE_UUID
    assert result.summary()["supplied_target_info_privileged_id_is_zero"]
    assert all(not value for name,value in result.summary().items() if name.endswith("_qualified"))


@pytest.mark.parametrize("change", [{"target-privilege-account": "enable"}, {"target-info": {"priv_acct": 70}},
    {"target-info": {"priv_acct": True}}, {"dependency": [{"id": 1}]}, {"subscriber": [{"name": "other"}]},
    {"rdp-service-status": "up"}, {"target": "other"}, {"uuid": execution.REQUEST_UUID}])
def test_service_metadata_rejects_privilege_association_and_other_unplanned_effects(change):
    value = postcondition(); value["results"].update(change)
    with pytest.raises(c.WindowsServiceCredentialError): consume(value)
