"""Fixed noninteractive Windows credential profile and existing C3 loader join."""
from dataclasses import replace
import hashlib
import json

import pytest
from v4_planning.material_provider import C3MaterialBinding, MaterialAccessDenied, MaterialBindingStatus

from fortipam_mcp import windows_execution_secret_contract as c
from fortipam_mcp.secret_create_central_lab_provider import CentralLabInventorySecretCreateProvider
from test_secret_create_central_lab_provider import _request

SERIAL = "FPAVUNIT000001"


class Loader:
    def __init__(self, username=b"labuser", password=b"synthetic-credential"):
        self.username, self.password = bytearray(username), bytearray(password)
        self.loads = 0
    def validate_prebound(self): return MaterialBindingStatus.AVAILABLE
    def load_secret_create_material_once(self):
        self.loads += 1
        return self.username, self.password


def binding():
    return c.WindowsExecutionSecretBinding("MCPV4WinExec20261021R1", "MCPV4WinTarget20261021R1",
        "192.0.2.90", "UNIT-WINDOWS", 37, hashlib.sha256(SERIAL.encode()).hexdigest(), "a" * 64)


def defaults(**changes):
    return dict(version="v7.0.0", build=29, http_method="GET", http_status=200, status="success",
        path="secret", name="database", vdom="root", serial=SERIAL,
        results={**c._GUARDS, **dict.fromkeys(c._POLICY_DEFAULTS, "enable"),
                 **changes, "field": [{"value": "synthetic-never-decode"}]})


def raw(value): return bytearray(json.dumps(value, separators=(",", ":")).encode())


def source(**changes):
    return c.consume_windows_execution_defaults(raw(defaults(**changes)), expected_serial=SERIAL)


def build(profile=None, frame=None, username=None, password=None):
    return c.build_windows_execution_secret_body(profile or binding(), frame or source(),
        create_uuid="00000000-0000-0000-0000-000000000000",
        username=memoryview(bytearray(b"UNIT-WINDOWS\\labuser")).toreadonly() if username is None else username,
        password=memoryview(bytearray(b"synthetic-credential")).toreadonly() if password is None else password)


def test_central_local_identity_qualification_joins_existing_provider_and_clears_on_release():
    origin = Loader()
    qualified = c.MachineQualifiedWindowsLocalLoader(origin, machine_name="UNIT-WINDOWS")
    opaque, request = C3MaterialBinding(), _request()
    provider = CentralLabInventorySecretCreateProvider(qualified, binding=opaque, request=request, clock=lambda: 1000)
    assert provider.validate_binding(opaque, request) is MaterialBindingStatus.AVAILABLE
    assert origin.loads == 0
    lease = provider.acquire_lease(opaque, request)
    record = provider._record
    assert record.username == b"UNIT-WINDOWS\\labuser" and record.password is origin.password
    assert not any(origin.username) and origin.password == b"synthetic-credential"
    assert qualified.validate_prebound() is MaterialBindingStatus.UNAVAILABLE
    provider.release_lease(lease)
    assert not any(record.username) and not any(origin.password)
    with pytest.raises(MaterialAccessDenied): provider.acquire_lease(opaque, request)
    assert origin.loads == 1 and "UNIT-WINDOWS" not in repr(qualified)


@pytest.mark.parametrize("username,password", [(b"DOMAIN\\labuser", b"valid"), (b"labuser@domain", b"valid"),
    (b"", b"valid"), (b"toolonglocalusernameover20", b"valid"), (b"labuser", b""),
    (b"labuser", b"bad\x00value"), (b"labuser", b"bad\nvalue"), (b"labuser", b"\xff")])
def test_credential_adaptation_never_tries_another_identity_or_leaves_failed_material(username, password):
    loader = Loader(username, password)
    adapted = c.MachineQualifiedWindowsLocalLoader(loader, machine_name="UNIT-WINDOWS")
    with pytest.raises(c.WindowsExecutionSecretError, match="^The private Windows execution Secret is unavailable.$"):
        adapted.load_secret_create_material_once()
    assert not any(loader.username) and not any(loader.password)
    with pytest.raises(c.WindowsExecutionSecretError): adapted.load_secret_create_material_once()
    assert loader.loads == 1


def test_bad_loader_shape_and_aliased_material_are_erased():
    for mode in ("list", "extra", "alias"):
        loader = Loader()
        def load():
            if mode == "list": return [loader.username, loader.password]
            if mode == "extra": return loader.username, loader.password, bytearray(b"extra")
            return loader.username, loader.username
        loader.load_secret_create_material_once = load
        with pytest.raises(c.WindowsExecutionSecretError):
            c.MachineQualifiedWindowsLocalLoader(loader, machine_name="UNIT-WINDOWS").load_secret_create_material_once()
        assert not any(loader.username)
        if mode != "alias": assert not any(loader.password)


def test_defaults_consumer_decodes_only_selected_nonmaterial_guards_and_erases(monkeypatch):
    from fortipam_mcp import secret_bulk_import_metadata as metadata
    original = metadata._scalar
    def scalar(buffer, span):
        assert b"synthetic-never-decode" not in buffer[slice(*span)]
        return original(buffer, span)
    monkeypatch.setattr(metadata, "_scalar", scalar)
    buffer = raw(defaults())
    frame = c.consume_windows_execution_defaults(buffer, expected_serial=SERIAL)
    assert not any(buffer) and frame.serial_digest == binding().serial_digest


@pytest.mark.parametrize("field,value", [("password-changer", "enable"), ("password-reconciliation", "enable"),
    ("password-heartbeat", "enable"), ("checkin-pwd-change", "enable"), ("checkout-script", "other"),
    ("checkin-script", "other"), ("associated-secret", False), ("associated-secret", 42),
    ("rdp-service-status", "up"), ("vnc-service-status", "up"), ("ldaps-service-status", "up"),
    ("auto-association", "enable"),
    ("checkout", "enable"), ("target-privilege-account", "enable")])
def test_native_defaults_cannot_introduce_rotation_hooks_access_or_references(field, value):
    buffer = raw(defaults(**{field: value}))
    with pytest.raises(c.WindowsExecutionSecretError):
        c.consume_windows_execution_defaults(buffer, expected_serial=SERIAL)
    assert not any(buffer)


@pytest.mark.parametrize("fault", ["missing-guard", "wrong-device", "duplicate", "trailing", "wrong-version", "boolean-build"])
def test_unqualified_or_ambiguous_default_frames_are_not_source_evidence(fault):
    payload = defaults()
    if fault == "missing-guard": del payload["results"]["password-changer"]
    if fault == "wrong-device": payload["serial"] = "FOREIGNUNIT"
    if fault == "wrong-version": payload["version"] = "v1.9.1"
    if fault == "boolean-build": payload["build"] = True
    buffer = raw(payload)
    if fault == "duplicate": buffer[-1:] = b',"serial":"OTHER"}'
    if fault == "trailing": buffer.extend(b"{}")
    with pytest.raises(c.WindowsExecutionSecretError):
        c.consume_windows_execution_defaults(buffer, expected_serial=SERIAL)
    assert not any(buffer)


def test_body_has_no_interactive_service_hooks_or_password_action_and_keeps_material_private():
    origin = Loader(password=b"synthetic-quote'\\\"value")
    username, password = c.MachineQualifiedWindowsLocalLoader(origin, machine_name="UNIT-WINDOWS").load_secret_create_material_once()
    body = build(username=memoryview(username).toreadonly(), password=memoryview(password).toreadonly())
    try:
        value = json.loads(body)
        for field, expected in c._GUARDS.items():
            assert value[field] == expected
        assert value["rdp-event-filter"] == "disable" and value["rdp-event-filter-profile"] == ""
        assert all(value[name] == "disable" for name in c._POLICY_DEFAULTS)
        assert value["template"] == "Windows Machine" and value["server-info"] == "Inherit"
        fields = {field["name"]: field["value"] for field in value["field"]}
        assert fields == {"Username": "UNIT-WINDOWS\\labuser", "Password": "synthetic-quote'\\\"value"}
        assert [field["name"] for field in value["field"]] == ["Password", "Username"]
        assert binding().target_address.encode() not in body and not any(origin.username)
        assert "MCPV4" not in repr(binding())
    finally:
        body[:] = b"\x00" * len(body); username[:] = b"\x00" * len(username); password[:] = b"\x00" * len(password)


@pytest.mark.parametrize("fault", ["foreign-machine", "bare-user", "immutable-user", "mutable-view", "foreign-defaults"])
def test_body_refuses_identity_or_private_buffer_mismatch(fault):
    user = memoryview(bytearray(b"UNIT-WINDOWS\\labuser")).toreadonly()
    frame = source()
    if fault == "foreign-machine": user = memoryview(bytearray(b"FOREIGN\\labuser")).toreadonly()
    if fault == "bare-user": user = memoryview(bytearray(b"labuser")).toreadonly()
    if fault == "immutable-user": user = memoryview(b"UNIT-WINDOWS\\labuser")
    if fault == "mutable-view": user = memoryview(bytearray(b"UNIT-WINDOWS\\labuser"))
    if fault == "foreign-defaults": frame = replace(frame, serial_digest="f" * 64)
    with pytest.raises(c.WindowsExecutionSecretError): build(frame=frame, username=user)


def test_profile_binding_rejects_foreign_names_and_binds_exact_nonmaterial_intent():
    b = binding()
    for change in ({"secret_name": "existing-secret"}, {"target_name": "shared-target"}, {"folder_id": True},
                   {"machine_name": "domain.example"}, {"target_address": "127.0.0.1"}, {"private_nonce": "bad"}):
        with pytest.raises(c.WindowsExecutionSecretError): replace(b, **change)
    assert replace(b, target_address="20.20.20.90").parameters_digest != b.parameters_digest
    assert replace(b, private_nonce="b" * 64).parameters_digest != b.parameters_digest


@pytest.mark.parametrize("policy", [None, True, "unknown"])
def test_policy_inheritance_requires_an_explicit_native_option(policy):
    buffer = raw(defaults(**{"pwd-chg-use-policy-default": policy}))
    with pytest.raises(c.WindowsExecutionSecretError):
        c.consume_windows_execution_defaults(buffer, expected_serial=SERIAL)
    assert not any(buffer)


def postcondition():
    value = json.loads(build())
    value.update(id=43, q_ref=0, q_static=False, q_origin_key=43, uuid="00000000-0000-4000-8000-000000000001",
                 **{"target-info": {"priv_acct": 0}})
    value["field"] = [{"name": "Password", "value": "synthetic-never-decode"}]
    return dict(version="v7.0.0", build=29, http_method="GET", http_status=200, status="OK",
        path="secret", name="database", vdom="root", serial=SERIAL, mkey=43, results=value)


def consume_post(buffer, profile=None):
    return c.consume_windows_execution_secret_metadata(buffer, profile or binding(), expected_secret_id=43,
        create_uuid="00000000-0000-0000-0000-000000000000")


def test_complete_associated_only_metadata_readback_skips_credentials_and_binds_original_context(monkeypatch):
    from fortipam_mcp import secret_bulk_import_metadata as metadata
    original = metadata._scalar
    def scalar(buffer, span):
        assert b"synthetic-never-decode" not in buffer[slice(*span)]
        return original(buffer, span)
    monkeypatch.setattr(metadata, "_scalar", scalar)
    buffer = raw(postcondition())
    observed = consume_post(buffer)
    assert not any(buffer) and len(observed.state_digest) == 64
    assert consume_post(raw(postcondition()), replace(binding(), private_nonce="b" * 64)).state_digest != observed.state_digest


@pytest.mark.parametrize("field,value", [("id", 44), ("target-privilege-account", "enable"),
    ("password-changer", "enable"), ("password-heartbeat", "enable"), ("checkin-pwd-change", "enable"),
    ("rdp-service-status", "up"), ("pwd-chg-use-policy-default", "enable"),
    ("heartbeat-use-policy-default", "enable"), ("q_ref", 1), ("q_ref", False), ("q_static", True),
    ("target", "shared-existing-target"), ("folder", 38)])
def test_any_expanded_control_reference_or_identity_refuses_metadata_readback(field, value):
    payload = postcondition(); payload["results"][field] = value
    buffer = raw(payload)
    with pytest.raises(c.WindowsExecutionSecretError): consume_post(buffer)
    assert not any(buffer)


@pytest.mark.parametrize("fault", ["missing-control", "missing-target-info", "unknown-target-account",
    "wrong-device", "wrong-status", "other-action", "boolean-id", "schema-error"])
def test_incomplete_foreign_or_non_detail_read_cannot_prove_new_secret_state(fault):
    payload = postcondition()
    if fault == "missing-control": del payload["results"]["checkout-script"]
    if fault == "missing-target-info": del payload["results"]["target-info"]
    if fault == "unknown-target-account": payload["results"]["target-info"]["priv_acct"] = False
    if fault == "wrong-device": payload["serial"] = "FOREIGNUNIT"
    if fault == "wrong-status": payload["status"] = "success"
    if fault == "other-action": payload["action"] = "default"
    if fault == "boolean-id": payload["mkey"] = True
    if fault == "schema-error": payload["schema_errors"] = {"private": "synthetic-never-decode"}
    buffer = raw(payload)
    with pytest.raises(c.WindowsExecutionSecretError): consume_post(buffer)
    assert not any(buffer)
