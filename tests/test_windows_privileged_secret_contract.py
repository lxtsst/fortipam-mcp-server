"""Synthetic fixed request bounds; no source, credential read or dispatch."""
from dataclasses import replace
import hashlib
import json

import pytest

from fortipam_mcp import windows_privileged_secret_contract as c
from fortipam_mcp import windows_execution_secret_contract as old

SERIAL = "UNITPRIV29"
ERROR = "The private Windows privileged Secret request is unavailable."


def binding(**changes):
    base = c.WindowsPrivilegedSecretBinding(
        "MCPV4SvcPriv20261024R1", "Existing-Unit-Target", "192.0.2.44", "UNIT-WINDOWS", 41,
        hashlib.sha256(SERIAL.encode()).hexdigest(), "a" * 64, "b" * 64, "e" * 64, "c" * 64, "d" * 64,
    )
    return replace(base, **changes)


def defaults():
    raw = bytearray(json.dumps(dict(
        version="v7.0.0", build=29, http_method="GET", http_status=200, status="success",
        path="secret", name="database", vdom="root", serial=SERIAL,
        results={**old._GUARDS, **dict.fromkeys(old._POLICY_DEFAULTS, "enable")},
    )).encode())
    result = old.consume_windows_execution_defaults(raw, expected_serial=SERIAL)
    assert not raw
    return result


def build(profile=None, baseline=None, user=None, password=None, create_uuid=old.REQUEST_UUID):
    return c.build_windows_privileged_secret_body(
        profile or binding(), baseline or defaults(), create_uuid=create_uuid,
        username=user if user is not None else memoryview(bytearray(b"UNIT-WINDOWS\\unituser")).toreadonly(),
        password=password if password is not None else memoryview(bytearray(b"synthetic-password")).toreadonly(),
    )


def test_distinct_request_has_no_interactive_or_automatic_side_effect_options():
    payload = build()
    try:
        value = json.loads(payload)
        assert value["target-privilege-account"] == "enable"
        assert value["template"] == "Windows Machine" and value["target"] == binding().target_name
        assert value["folder"] == binding().folder_id and value["inherit-permission"] == "enable"
        assert value["id"] == 0 and value["uuid"] == old.REQUEST_UUID
        assert value["associated-secret"] == 0
        for name in ("recording", "proxy", "auto-association", "checkout", "checkout-duration-renew",
                     "password-changer", "password-reconciliation", "password-heartbeat", "need-approval",
                     "need-approval-job", "rdp-event-filter", "winappfilter", "ssh-filter", "secret-auth",
                     "checkin-pwd-change", *old._POLICY_DEFAULTS):
            assert value[name] == "disable", name
        for name in ("rdp", "ssh", "sftp", "http", "samba", "telnet", "vnc", "ldaps"):
            assert value[name + "-service-status"] == "down"
        assert value["checkin-script"] == value["checkout-script"] == ""
        assert [(field["id"], field["name"]) for field in value["field"]] == [(0, "Password"), (0, "Username")]
        assert "Host" not in [field["name"] for field in value["field"]]
    finally:
        payload.clear()


def test_old_execution_contract_stays_nonprivileged_and_rejects_new_binding():
    frame = defaults()
    legacy = old.WindowsExecutionSecretBinding(
        "MCPV4WinExec20261024R99", "MCPV4WinTarget20261024R99", "192.0.2.44", "UNIT-WINDOWS", 41,
        binding().serial_digest, "e" * 64,
    )
    user = memoryview(bytearray(b"UNIT-WINDOWS\\unituser")).toreadonly()
    password = memoryview(bytearray(b"synthetic-password")).toreadonly()
    body = old.build_windows_execution_secret_body(legacy, frame, create_uuid=old.REQUEST_UUID,
                                                   username=user, password=password)
    try:
        assert json.loads(body)["target-privilege-account"] == old._GUARDS["target-privilege-account"] == "disable"
        with pytest.raises(c.WindowsPrivilegedSecretError, match="^" + ERROR.replace(".", r"\.") + "$"):
            build(profile=legacy)
        with pytest.raises(old.WindowsExecutionSecretError):
            old.build_windows_execution_secret_body(binding(), frame, create_uuid=old.REQUEST_UUID,
                                                    username=user, password=password)
    finally:
        body.clear()


@pytest.mark.parametrize("changes", [
    {"secret_name": "existing-secret"}, {"target_name": "MCPV4WinTarget20261022R3"},
    {"target_name": "target\n"}, {"target_name": " target"}, {"target_name": "x" * 128},
    {"folder_id": True}, {"folder_id": 0}, {"folder_id": 2147483648},
    {"target_address": "127.0.0.1"}, {"target_address": "0.0.0.0"},
    {"target_address": "169.254.1.1"}, {"target_address": "192.000.2.44"},
    {"machine_name": "lowercase"}, {"machine_name": "UNIT-WINDOWS-TOO-LONG"},
    {"serial_digest": "bad"}, {"target_reference_context_digest": "A" * 64},
    {"subject_context_digest": "bad"}, {"association_context_digest": "bad"},
    {"folder_context_digest": "bad"}, {"private_nonce": "bad"},
])
def test_private_binding_refuses_old_object_chain_and_unbounded_context(changes):
    with pytest.raises(c.WindowsPrivilegedSecretError) as error:
        binding(**changes)
    assert str(error.value) == ERROR


@pytest.mark.parametrize("field,value", [
    ("target_name", "Other-Existing-Target"), ("target_address", "192.0.2.45"),
    ("machine_name", "OTHER-WINDOWS"), ("folder_id", 42),
    ("target_reference_context_digest", "e" * 64), ("subject_context_digest", "f" * 64),
    ("association_context_digest", "f" * 64),
    ("folder_context_digest", "e" * 64), ("private_nonce", "f" * 64),
])
def test_every_selected_source_context_changes_bound_parameters(field, value):
    assert binding().parameters_digest != binding(**{field: value}).parameters_digest


@pytest.mark.parametrize("user,password", [
    (b"OTHER\\unituser", b"synthetic"), (b"unituser", b"synthetic"),
    (b"UNIT-WINDOWS\\unituser@domain", b"synthetic"),
    (b"UNIT-WINDOWS\\toolonglocalusernameover20", b"synthetic"),
    (b"UNIT-WINDOWS\\unituser", b""), (b"UNIT-WINDOWS\\unituser", b"bad\x00value"),
    (b"UNIT-WINDOWS\\unituser", b"\xff"),
])
def test_material_has_to_be_exact_qualified_local_views(user, password):
    u, p = bytearray(user), bytearray(password)
    with pytest.raises(c.WindowsPrivilegedSecretError) as error:
        build(user=memoryview(u).toreadonly(), password=memoryview(p).toreadonly())
    assert str(error.value) == ERROR and u == user and p == password


def test_material_alias_mutability_and_immutable_source_refuse():
    shared = bytearray(b"UNIT-WINDOWS\\unituser")
    view = memoryview(shared).toreadonly()
    for user, password in ((view, view), (memoryview(shared), view),
                           (memoryview(b"UNIT-WINDOWS\\unituser"), view)):
        with pytest.raises(c.WindowsPrivilegedSecretError):
            build(user=user, password=password)


@pytest.mark.parametrize("change", ["serial", "guards", "policy", "uuid"])
def test_defaults_or_creation_token_tamper_refuses(change):
    frame = defaults()
    create_uuid = old.REQUEST_UUID
    if change == "serial": frame = replace(frame, serial_digest="f" * 64)
    if change == "guards": frame = replace(frame, guards_digest="f" * 64)
    if change == "policy": frame = replace(frame, policy_defaults=("enable", "bad"))
    if change == "uuid": create_uuid = "11111111-1111-4111-8111-111111111111"
    with pytest.raises(c.WindowsPrivilegedSecretError):
        build(baseline=frame, create_uuid=create_uuid)


@pytest.mark.parametrize("failure", [ValueError, KeyboardInterrupt])
def test_partial_material_body_clears_on_failure_or_interrupt(monkeypatch, failure):
    captured = []
    def fail(body, material):
        body.extend(b"SYNTHETIC_PARTIAL_BODY")
        captured.append(body._storage)
        raise failure()
    monkeypatch.setattr(c, "_append_material", fail)
    with pytest.raises(c.WindowsPrivilegedSecretError if failure is ValueError else KeyboardInterrupt):
        build()
    assert captured and not any(captured[0])


def test_context_and_request_are_opaque_and_cannot_mint_source_or_recovery_authority():
    b = binding()
    assert b.secret_name not in repr(b) and b.target_name not in repr(b)
    view = b.summary()
    assert view["contract"] == c.CONTRACT and view["fixed_privileged_account_proposal"] is True
    for name in ("existing_target_adoption_authorized", "target_source_qualified", "subject_source_qualified",
                 "privilege_association_scope_qualified", "effective_permission_qualified", "material_source_qualified",
                 "original_birth_qualified", "independent_recovery_qualified", "execution_authorized",
                 "runtime_registered", "private_values_returned"):
        assert view[name] is False


NATIVE_UUID = "11111111-2222-4333-8444-555555555555"


def postcondition():
    body = build()
    try:
        row = json.loads(body)
    finally:
        body.clear()
    row.update(id=70, uuid=NATIVE_UUID, subscriber=[], q_origin_key=70,
               **{"target-info": {"priv_acct": 70}, "opaque-native-field": {"keep": "synthetic-opaque"}})
    row["field"] = [{"id": 1, "name": "Password", "value": "SYNTHETIC_MASK_NEVER_DECODE"},
                    {"id": 2, "name": "Username", "value": "SYNTHETIC_USERNAME_NEVER_DECODE"}]
    return dict(version="v7.0.0", build=29, http_method="GET", http_status=200, status="OK",
                path="secret", name="database", vdom="root", serial=SERIAL, results=row)


def consume(value, **arguments):
    raw = bytearray(json.dumps(value).encode())
    try:
        return c.consume_windows_privileged_secret_metadata(raw, binding(), expected_secret_id=70, **arguments)
    finally:
        assert not raw


def test_fixed_postcondition_matches_own_privileged_reference_without_decoding_values(monkeypatch):
    scalar = c.parser._scalar
    def check(raw, span):
        assert b"NEVER_DECODE" not in raw[slice(*span)] and b"synthetic-opaque" not in raw[slice(*span)]
        return scalar(raw, span)
    monkeypatch.setattr(c.parser, "_scalar", check)
    result = consume(postcondition(), expected_native_uuid=NATIVE_UUID)
    assert result.native_secret_id == 70 and result.native_uuid == NATIVE_UUID and result.password_field_id == 1
    assert result.summary()["supplied_privileged_reference_matches_selected_secret"] is True
    for name in ("source_completeness_qualified", "source_provenance_qualified", "original_birth_qualified",
                 "material_consistency_qualified", "target_preservation_qualified", "effective_permission_qualified",
                 "independent_recovery_qualified", "execution_authorized", "runtime_registered"):
        assert result.summary()[name] is False


@pytest.mark.parametrize("change", [
    {"id": 71}, {"id": True}, {"name": "other"}, {"target": "other"}, {"folder": 42},
    {"target-privilege-account": "disable"}, {"rdp-service-status": "up"}, {"recording": "enable"},
    {"password-changer": "enable"}, {"checkout-script": "synthetic-script"},
    {"dependency": [{"id": 1}]}, {"subscriber": [{"name": "synthetic-subscriber"}]},
    {"uuid": old.REQUEST_UUID}, {"uuid": "invalid"}, {"q_origin_key": 71},
    {"target-info": {}}, {"target-info": {"priv_acct": 0}}, {"target-info": {"priv_acct": True}},
    {"target-info": {"priv_acct": 71}},
])
def test_postcondition_refuses_foreign_active_or_unqualified_association(change):
    value = postcondition()
    value["results"].update(change)
    with pytest.raises(c.WindowsPrivilegedSecretError) as error:
        consume(value)
    assert str(error.value) == ERROR


@pytest.mark.parametrize("change", [
    {"status": "success"}, {"http_method": "POST"}, {"serial": "OTHER"}, {"vdom": "other"},
    {"error": 1}, {"error": True}, {"schema_errors": []}, {"mkey": 71},
    {"limit_reached": True}, {"size": 2}, {"matched_count": 0}, {"next_idx": 2},
])
def test_postcondition_refuses_wrong_or_partial_envelope(change):
    value = postcondition()
    value.update(change)
    with pytest.raises(c.WindowsPrivilegedSecretError):
        consume(value)


@pytest.mark.parametrize("change", ["missing", "duplicate_name", "duplicate_id", "unexpected", "nontext", "wrong_host"])
def test_postcondition_refuses_ambiguous_material_selectors(change):
    value = postcondition()
    fields = value["results"]["field"]
    if change == "missing": fields.pop()
    if change == "duplicate_name": fields[1]["name"] = "Password"
    if change == "duplicate_id": fields[1]["id"] = 1
    if change == "unexpected": fields[1]["name"] = "Other"
    if change == "nontext": fields[0]["value"] = None
    if change == "wrong_host": fields.append(dict(id=3, name="Host", value="192.0.2.45"))
    with pytest.raises(c.WindowsPrivilegedSecretError):
        consume(value)


def test_postcondition_allows_one_native_array_row_and_target_owned_host():
    value = postcondition()
    value["results"]["field"].append(dict(id=3, name="Host", value=binding().target_address))
    value["results"] = [value["results"]]
    consume(value)
    with pytest.raises(c.WindowsPrivilegedSecretError):
        consume(value, expected_native_uuid="22222222-2222-4222-8222-222222222222")
    value["results"].append(value["results"][0])
    with pytest.raises(c.WindowsPrivilegedSecretError):
        consume(value)


def test_postcondition_duplicate_json_and_interrupt_erase_the_entire_response(monkeypatch):
    value = json.dumps(postcondition(), separators=(",", ":")).replace('"priv_acct":70', '"priv_acct":70,"priv_acct":70')
    raw = bytearray(value.encode())
    with pytest.raises(c.WindowsPrivilegedSecretError):
        c.consume_windows_privileged_secret_metadata(raw, binding(), expected_secret_id=70)
    assert not raw
    raw = bytearray(json.dumps(postcondition()).encode())
    monkeypatch.setattr(c, "_spans", lambda _: (_ for _ in ()).throw(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        c.consume_windows_privileged_secret_metadata(raw, binding(), expected_secret_id=70)
    assert not raw
