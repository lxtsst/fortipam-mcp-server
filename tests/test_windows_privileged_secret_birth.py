"""Original privileged birth custody with synthetic source and real M4/C3."""
from dataclasses import replace
import json

import pytest

from fortipam_mcp import windows_privileged_secret_birth as b
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.secret_instruction_build29_api_preservation import consume_secret_instruction_build29_credential_response
from fortipam_mcp.secret_approval_build29_totp_boundary import consume_secret_approval_build29_totp_response
from test_windows_privileged_secret_contract import SERIAL, NATIVE_UUID, postcondition
from test_windows_privileged_secret_material import Peer as MaterialPeer, components, execute
from v4_planning import M4Outcome
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome


def raw(value):
    return bytearray(json.dumps(value, separators=(",", ":")).encode())


def full_row():
    value = postcondition()
    row = value["results"]
    row["field"][1]["value"] = "UNIT-WINDOWS\\labuser"
    row.update({"instruction-profile": "", "totp-setting": {"status": "disable", "shared-key": None},
                "future-setting": {"nested-secret-render": "SYNTHETIC_OPAQUE_DO_NOT_DECODE"}})
    return value


def witnesses(custody, *, password="synthetic-credential", secret_id=70, field_id=1, totp="", key=None):
    key = key if key is not None else custody._material_key()
    envelope = dict(version="v7.0.0", build=29, serial=SERIAL, http_method="POST", http_status=200,
                    status="OK", **{"secret-id": secret_id}, msg="Success")
    password_envelope = {**envelope, "field-id": field_id}
    p = consume_secret_instruction_build29_credential_response(raw({**password_envelope, "results": password}),
        expected_secret_id=secret_id, expected_field_id=field_id, http_status=200,
        content_type="application/json", expected_envelope=password_envelope, witness_key=key)
    t = consume_secret_approval_build29_totp_response(raw({**envelope, "results": totp}),
        http_status=200, content_type="application/json", expected_envelope=envelope, witness_key=key)
    return dict(password_before=p, password_after=p, totp_before=t, totp_after=t)


class Peer(MaterialPeer):
    def __init__(self, fault=None):
        super().__init__()
        self.fault = fault
        self.custody = None
        self.ack = self.before = self.after = None
        self.arguments = None

    def _windows_privileged_secret_ready(self, profile, request):
        return self.custody is not None and not any(self.custody._directory.iterdir())

    def _create_windows_privileged_secret(self, profile, request, body):
        self.custody.begin_original_send(body)
        self.calls += 1
        self.body = body.obj
        if self.fault == "before-ack": raise KeyboardInterrupt
        ack = dict(version="v7.0.0", build=29, http_method="POST", http_status=200,
            status="success", path="secret", name="database", vdom="root", serial=SERIAL,
            mkey=70, error=0, results={"value": "SYNTHETIC_ACK_DO_NOT_DECODE"})
        if self.fault == "invalid-ack": ack["status"] = "OK"
        self.ack = raw(ack)
        self.custody.capture_original_ack(self.ack, http_status=200, content_type="application/json")
        if self.fault == "after-ack": raise KeyboardInterrupt
        self.custody.capture_original_frame(raw(full_row()))
        before, after = full_row(), full_row()
        after["results"]["totp-setting"]["shared-key"] = "SYNTHETIC_VOLATILE_RENDER"
        self.arguments = witnesses(self.custody)
        if self.fault == "unknown-drift": after["results"]["future-setting"]["nested-secret-render"] = "changed"
        if self.fault == "missing-field": del after["results"]["future-setting"]
        if self.fault == "undeclared-field": after["results"]["undeclared"] = {"data": "opaque"}
        if self.fault == "same-wrong-password": self.arguments = witnesses(self.custody, password="different")
        if self.fault == "wrong-username":
            for value in (before, after): value["results"]["field"][1]["value"] = "UNIT-WINDOWS\\another"
        if self.fault == "foreign-witness": self.arguments = witnesses(self.custody, secret_id=71)
        if self.fault == "foreign-key": self.arguments = witnesses(self.custody, key=b"x"*32)
        if self.fault == "foreign-field": self.arguments = witnesses(self.custody, field_id=3)
        if self.fault == "nonempty-totp": self.arguments = witnesses(self.custody, totp="ABCD2345")
        if self.fault == "totp-enabled": after["results"]["totp-setting"]["status"] = "enable"
        if self.fault == "foreign-uuid": after["results"]["uuid"] = "22222222-2222-4333-8444-555555555555"
        if self.fault == "wrong-association": after["results"]["target-info"]["priv_acct"] = 0
        if self.fault == "dependency": after["results"]["dependency"] = [{"id": 1}]
        if self.fault == "instruction": after["results"]["instruction-profile"] = "other"
        if self.fault == "totp-unknown-drift": after["results"]["totp-setting"]["opaque"] = "new"
        self.before, self.after = raw(before), raw(after)
        if self.fault == "same-buffer": self.after = self.before
        self.custody.capture_original_birth(self.before, self.after, **self.arguments)
        if self.fault == "after-birth": raise KeyboardInterrupt
        return SecretCreateAdapterOutcome.VERIFIED_CREATED


def fixture(tmp_path, *, fault=None):
    cmp = components(tmp_path, peer=Peer(fault))
    directory = tmp_path/"birth"; directory.mkdir(mode=0o700)
    key = tmp_path/"birth.key"; key.write_bytes(b"b"*32); key.chmod(0o600)
    kwargs = {name: cmp["kwargs"][name] for name in ("profile", "defaults", "plan", "authorization",
              "request", "execution_store", "material_store", "clock")}
    kwargs.update(config=SecretMetadataHttpTransportConfig("https://lab.example.test", "synthetic-api-token", 15, None),
                  full_row_fields=frozenset(full_row()["results"]))
    custody = b.WindowsPrivilegedSecretBirthCustody(directory, key, **kwargs)
    cmp["peer"].custody = custody
    cmp.update(custody=custody, directory=directory, key=key, birth_kwargs=kwargs)
    return cmp


def test_original_complete_birth_is_sealed_with_native_id_uuid_materials_and_unknown_tokens(tmp_path, monkeypatch):
    cmp = fixture(tmp_path)
    scalar = b.parser._scalar
    def check(buffer, span):
        assert not any(value in buffer[slice(*span)] for value in (
            b"synthetic-credential", b"labuser", b"SYNTHETIC_OPAQUE", b"SYNTHETIC_ACK", b"SYNTHETIC_VOLATILE"))
        return scalar(buffer, span)
    monkeypatch.setattr(b.parser, "_scalar", check)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    original = cmp["custody"].inspect_original_creation()
    assert original.native_secret_id == 70 and original.native_uuid == NATIVE_UUID
    assert len(original.state_digest) == 64 and original.original_outcome == "succeeded"
    assert all(not value for value in (cmp["peer"].body, cmp["peer"].ack, cmp["peer"].before, cmp["peer"].after))
    snapshot = {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}
    assert set(snapshot) == {b._SEND, b._ACK, b._FRAME, b._BIRTH}
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in cmp["directory"].iterdir())
    stored = b"".join(snapshot.values())
    for marker in (b"synthetic-credential", b"labuser", b"SYNTHETIC_", b"MCPV4", b"Existing-Unit", b"synthetic-api-token"):
        assert marker not in stored
    assert execute(cmp).idempotent_replay
    assert cmp["peer"].calls == cmp["loader"].loads == 1
    assert snapshot == {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}
    cmp["now"][0] = 9999
    assert cmp["custody"].inspect_original_creation() == original
    reconstructed = b.WindowsPrivilegedSecretBirthCustody(cmp["directory"], cmp["key"], **cmp["birth_kwargs"])
    assert reconstructed.inspect_original_creation() == original
    first, last = raw(full_row()), raw(full_row())
    with pytest.raises(b.WindowsPrivilegedSecretBirthError):
        reconstructed.capture_original_birth(first, last, **cmp["peer"].arguments)
    assert not first and not last
    assert snapshot == {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}


@pytest.mark.parametrize("fault", ["unknown-drift", "missing-field", "undeclared-field", "same-wrong-password",
    "wrong-username", "foreign-witness", "foreign-key", "foreign-field", "nonempty-totp", "totp-enabled",
    "foreign-uuid", "wrong-association", "dependency", "instruction", "totp-unknown-drift", "same-buffer"])
def test_incomplete_or_foreign_birth_refuses_and_keeps_original_ack_without_replay(tmp_path, fault):
    cmp = fixture(tmp_path, fault=fault)
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    original = cmp["custody"].inspect_original_creation()
    assert original.native_secret_id == 70 and original.native_uuid == NATIVE_UUID and original.state_digest is None
    assert original.original_outcome == "reconciliation_required"
    assert not (cmp["directory"]/b._BIRTH).exists()
    assert not cmp["peer"].before and not cmp["peer"].after
    snapshot = {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}
    execute(cmp)
    assert cmp["peer"].calls == cmp["loader"].loads == 1
    before, after = raw(full_row()), raw(full_row())
    with pytest.raises(b.WindowsPrivilegedSecretBirthError):
        cmp["custody"].capture_original_birth(before, after, **cmp["peer"].arguments)
    assert not before and not after
    assert snapshot == {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}


@pytest.mark.parametrize("fault", ["before-ack", "after-ack", "after-birth", "invalid-ack"])
def test_original_interruption_never_adopts_later_metadata_or_resends(tmp_path, fault):
    cmp = fixture(tmp_path, fault=fault)
    if fault == "invalid-ack":
        assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    else:
        with pytest.raises(KeyboardInterrupt): execute(cmp)
    snapshot = {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}
    execute(cmp)
    assert cmp["peer"].calls == cmp["loader"].loads == 1
    assert not cmp["loader"].username and not cmp["loader"].password and not cmp["peer"].body
    if fault in ("before-ack", "invalid-ack"):
        with pytest.raises(b.WindowsPrivilegedSecretBirthError): cmp["custody"].inspect_original_creation()
    else:
        observed = cmp["custody"].inspect_original_creation()
        assert observed.original_outcome == "in_progress"
        assert (observed.state_digest is not None) == (fault == "after-birth")
    assert snapshot == {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}


def test_custody_cannot_seal_before_original_claim_or_material_acquisition(tmp_path):
    cmp = fixture(tmp_path)
    first, last = raw(full_row()), raw(full_row())
    arguments = witnesses(cmp["custody"])
    with pytest.raises(b.WindowsPrivilegedSecretBirthError): cmp["custody"].capture_original_birth(first, last, **arguments)
    assert not first and not last and not list(cmp["directory"].iterdir())
    assert cmp["execution"].claim_count == cmp["material"].claim_count == 0


@pytest.mark.parametrize("fault", ["key", "directory", "record", "source", "fields", "profile"])
def test_original_custody_rejects_storage_source_and_parameters_drift(tmp_path, fault):
    cmp = fixture(tmp_path)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    if fault == "key": cmp["key"].write_bytes(b"z"*32)
    if fault == "directory": cmp["directory"].chmod(0o755)
    if fault == "record":
        path = cmp["directory"]/b._BIRTH
        value = json.loads(path.read_bytes()); value["state_digest"] = "f"*64; path.write_text(json.dumps(value))
    if fault == "source": cmp["custody"]._config = replace(cmp["custody"]._config, bearer_token="different")
    if fault == "fields": cmp["custody"]._row_fields = cmp["custody"]._row_fields | {"extra"}
    if fault == "profile": cmp["custody"]._profile = replace(cmp["custody"]._profile, association_context_digest="f"*64)
    with pytest.raises(b.WindowsPrivilegedSecretBirthError): cmp["custody"].inspect_original_creation()


@pytest.mark.parametrize("fault", [None, "stable-unknown-drift", "password", "fields", "uuid", "totp"])
def test_independent_pristine_comparison_after_expiry_never_repairs_original_records(tmp_path, fault):
    cmp = fixture(tmp_path)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    original = cmp["custody"].inspect_original_creation()
    snapshot = {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}
    key_buffer = cmp["custody"]._key
    cmp["custody"].close()
    assert not key_buffer
    cmp["now"][0] = 9999
    independent = b.WindowsPrivilegedSecretBirthCustody(cmp["directory"], cmp["key"], **cmp["birth_kwargs"])
    first, last = full_row(), full_row()
    arguments = witnesses(independent)
    if fault == "stable-unknown-drift":
        for value in (first, last): value["results"]["future-setting"]["nested-secret-render"] = "different"
    if fault == "password": arguments = witnesses(independent, password="different")
    if fault == "fields":
        for value in (first, last): del value["results"]["future-setting"]
    if fault == "uuid":
        for value in (first, last): value["results"]["uuid"] = "22222222-2222-4333-8444-555555555555"
    if fault == "totp": arguments = witnesses(independent, totp="ABCD2345")
    before, after = raw(first), raw(last)
    if fault is None:
        assert independent.consume_pristine_birth(before, after, **arguments) == original
    else:
        with pytest.raises(b.WindowsPrivilegedSecretBirthError):
            independent.consume_pristine_birth(before, after, **arguments)
    assert not before and not after
    assert independent.inspect_original_creation() == original
    assert cmp["execution"].claim_count == cmp["material"].claim_count == 1
    assert snapshot == {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}
    independent.close()


def test_reconstructed_custody_cannot_late_seal_even_inside_the_original_m4_scope(tmp_path, monkeypatch):
    cmp = fixture(tmp_path)
    independent = b.WindowsPrivilegedSecretBirthCustody(cmp["directory"], cmp["key"], **cmp["birth_kwargs"])
    monkeypatch.setattr(cmp["custody"], "capture_original_birth", independent.capture_original_birth)
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert not (cmp["directory"]/b._BIRTH).exists()
    assert not cmp["peer"].before and not cmp["peer"].after
    assert cmp["custody"].inspect_original_creation().state_digest is None
    independent.close()


@pytest.mark.parametrize("failure", [KeyboardInterrupt, ValueError])
def test_capture_failure_clears_both_original_rows_and_closes_write_path(tmp_path, monkeypatch, failure):
    cmp = fixture(tmp_path)
    def fail(*args, **kwargs): raise failure()
    monkeypatch.setattr(cmp["custody"], "_complete_state", fail)
    if failure is KeyboardInterrupt:
        with pytest.raises(KeyboardInterrupt): execute(cmp)
    else:
        assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert not cmp["peer"].before and not cmp["peer"].after
    assert not (cmp["directory"]/b._BIRTH).exists()
    assert cmp["custody"]._closed


def test_expired_original_lease_refuses_full_birth_before_any_seal(tmp_path, monkeypatch):
    cmp = fixture(tmp_path)
    capture = cmp["custody"].capture_original_birth
    def expire(first, last, **kwargs):
        cmp["now"][0] = 9999
        return capture(first, last, **kwargs)
    monkeypatch.setattr(cmp["custody"], "capture_original_birth", expire)
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert not cmp["peer"].before and not cmp["peer"].after
    assert not (cmp["directory"]/b._BIRTH).exists()
    assert cmp["custody"].inspect_original_creation().state_digest is None


@pytest.mark.parametrize("fault", ["shared-key", "incomplete-fields", "mutable-fields", "old-profile"])
def test_constructor_refuses_key_reuse_and_unqualified_shape_before_claims(tmp_path, fault):
    cmp = fixture(tmp_path)
    kwargs = dict(cmp["birth_kwargs"])
    if fault == "shared-key": cmp["key"].write_bytes((tmp_path/"m4.key").read_bytes())
    if fault == "incomplete-fields": kwargs["full_row_fields"] = kwargs["full_row_fields"] - {"totp-setting"}
    if fault == "mutable-fields": kwargs["full_row_fields"] = set(kwargs["full_row_fields"])
    if fault == "old-profile":
        from test_windows_execution_secret_contract import binding as old_binding
        kwargs["profile"] = old_binding()
    with pytest.raises(b.WindowsPrivilegedSecretBirthError):
        b.WindowsPrivilegedSecretBirthCustody(cmp["directory"], cmp["key"], **kwargs)
    assert cmp["execution"].claim_count == cmp["material"].claim_count == 0
    assert not list(cmp["directory"].iterdir())
