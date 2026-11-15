"""Original ACK custody through real persistent M4/C3 and a synthetic peer."""
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from fortipam_mcp import windows_execution_secret_ack as a
from fortipam_mcp import windows_execution_secret_contract as c
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.windows_execution_secret_material import windows_execution_secret_material_runtime
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from test_windows_execution_secret_contract import SERIAL, postcondition, raw
from test_windows_execution_secret_material import components, execute
from test_secret_create_m4_runtime import _Resolver, _Verifier, _Reader
from v4_planning import M4AdapterAmbiguous, M4Outcome
from v4_planning.material_provider import MaterialProviderClass


class Peer:
    def __init__(self, fault="none"):
        self.custody = None
        self.calls = 0
        self.fault = fault
        self.body = self.ack = self.metadata = None

    def _create_windows_execution_secret(self, profile, request, body):
        self.custody.begin_original_send(body)
        self.calls += 1
        self.body = body.obj
        if self.fault == "before-ack": raise KeyboardInterrupt
        value = dict(version="v7.0.0", build=29, http_method="POST", http_status=200,
            status="success", path="secret", name="database", vdom="root", serial=SERIAL,
            mkey=43, error=0, results={"field":[{"value":"synthetic-never-decode"}]})
        if self.fault == "invalid-ack": value["status"] = "OK"
        self.ack = raw(value)
        self.custody.capture_original_ack(self.ack, http_status=200, content_type="application/json")
        if self.fault == "after-ack": raise KeyboardInterrupt
        value = postcondition()
        if self.fault == "invalid-metadata": value["results"]["q_ref"] = 1
        self.metadata = raw(value)
        self.custody.capture_original_metadata(self.metadata)
        if self.fault == "after-metadata": raise KeyboardInterrupt
        from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome
        return SecretCreateAdapterOutcome.VERIFIED_CREATED

    def _windows_execution_secret_ready(self, profile, request):
        return self.custody is not None and not any(self.custody._directory.iterdir())


def custody_kwargs(cmp):
    values = cmp["kwargs"]
    return {key:values[key] for key in ("profile", "defaults", "plan", "authorization", "request",
        "execution_store", "material_store", "clock")}


def fixture(tmp_path, *, fault="none", reader=None):
    cmp = components(tmp_path, peer=Peer(fault), reader=reader)
    directory = tmp_path/"custody";directory.mkdir(mode=0o700)
    key = tmp_path/"custody.key";key.write_bytes(b"a"*32);key.chmod(0o600)
    kwargs = dict(config=SecretMetadataHttpTransportConfig("https://lab.example.test", "synthetic-api-token", 15, None),
        **custody_kwargs(cmp))
    custody = a.WindowsExecutionSecretAckCustody(directory, key, **kwargs)
    cmp["peer"].custody = custody
    cmp.update(custody=custody, custody_kwargs=kwargs, directory=directory, custody_key=key)
    return cmp


def test_original_ack_and_native_uuid_are_sealed_before_post_read_without_material_persistence(tmp_path, monkeypatch):
    cmp = fixture(tmp_path)
    original = a.parser._scalar
    def scalar(buffer, span):
        assert b"synthetic-never-decode" not in buffer[slice(*span)]
        # The live request Password/Username values are never scalar-decoded either.
        assert b"synthetic-credential" not in buffer[slice(*span)]
        assert b"labuser" not in buffer[slice(*span)]
        return original(buffer, span)
    monkeypatch.setattr(a.parser, "_scalar", scalar)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    observed = cmp["custody"].inspect_original_creation()
    assert observed.native_secret_id == 43 and observed.native_uuid == "00000000-0000-4000-8000-000000000001"
    assert observed.original_outcome == "succeeded" and len(observed.state_digest) == 64
    assert not any(cmp["peer"].body) and not any(cmp["peer"].ack) and not any(cmp["peer"].metadata)
    files = {p.name:p.read_bytes() for p in cmp["directory"].iterdir()}
    assert set(files) == {a._SEND, a._ACK, a._METADATA}
    data = b"".join(files.values())
    for marker in (b"synthetic-credential", b"labuser", b"MCPV4Win", b"synthetic-api-token"):
        assert marker not in data
    execute(cmp)
    assert cmp["peer"].calls == cmp["loader"].loads == 1
    assert {p.name:p.read_bytes() for p in cmp["directory"].iterdir()} == files


@pytest.mark.parametrize("fault", ["before-ack", "invalid-ack", "after-ack", "invalid-metadata", "after-metadata"])
def test_missing_or_interrupted_original_response_cannot_be_replayed_or_backfilled(tmp_path, fault):
    cmp = fixture(tmp_path, fault=fault)
    if fault in ("before-ack", "after-ack", "after-metadata"):
        with pytest.raises(KeyboardInterrupt): execute(cmp)
    else:
        assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert not any(cmp["peer"].body) and not any(cmp["loader"].password)
    cmp["now"][0] = 2000
    fresh = a.WindowsExecutionSecretAckCustody(cmp["directory"], cmp["custody_key"], **cmp["custody_kwargs"])
    before = {p.name:p.read_bytes() for p in cmp["directory"].iterdir()}
    if fault in ("before-ack", "invalid-ack"):
        with pytest.raises(a.WindowsExecutionSecretAckError): fresh.inspect_original_creation()
    else:
        observation = fresh.inspect_original_creation()
        assert observation.original_outcome != "succeeded"
        assert (observation.native_uuid is not None) == (fault == "after-metadata")
    buffer = raw(postcondition())
    with pytest.raises(a.WindowsExecutionSecretAckError): fresh.capture_original_metadata(buffer)
    assert not any(buffer)
    assert {p.name:p.read_bytes() for p in cmp["directory"].iterdir()} == before
    assert cmp["peer"].calls == cmp["loader"].loads == 1


def test_ack_metadata_survive_an_unknown_outer_read_without_promoting_the_original_m4(tmp_path):
    reader = _Reader()
    reader.read_postcondition = lambda plan: (_ for _ in ()).throw(M4AdapterAmbiguous("Synthetic unavailable read."))
    cmp = fixture(tmp_path, reader=reader)
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    original = cmp["custody"].inspect_original_creation()
    assert original.native_uuid is not None and original.original_outcome == "reconciliation_required"
    assert original.original_verification == "unknown"
    cmp["now"][0] = 2000
    observed = a.WindowsExecutionSecretAckCustody(cmp["directory"], cmp["custody_key"], **cmp["custody_kwargs"]).inspect_original_creation()
    assert observed == original


def test_standalone_custody_cannot_mint_send_or_ack_from_an_existing_ledger(tmp_path):
    cmp = fixture(tmp_path)
    body = bytearray(b"{}")
    with pytest.raises(a.WindowsExecutionSecretAckError):
        cmp["custody"].begin_original_send(memoryview(body).toreadonly())
    assert list(cmp["directory"].iterdir()) == []
    assert cmp["execution"].claim_count == cmp["material"].claim_count == 0


def test_another_provider_class_cannot_import_this_original_ack_contract(tmp_path):
    cmp = fixture(tmp_path)
    kwargs = {**cmp["custody_kwargs"], "request":replace(cmp["kwargs"]["request"],
        provider_class=MaterialProviderClass.EXTERNAL_VAULT_LEASE)}
    with pytest.raises(a.WindowsExecutionSecretAckError):
        a.WindowsExecutionSecretAckCustody(cmp["directory"], cmp["custody_key"], **kwargs)
    assert not list(cmp["directory"].iterdir()) and cmp["loader"].loads == 0


@pytest.mark.parametrize("record", [a._SEND, a._ACK, a._METADATA])
def test_record_tampering_or_missing_original_record_is_not_adopted(tmp_path, record):
    cmp = fixture(tmp_path)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    file = cmp["directory"]/record
    data = bytearray(file.read_bytes());data[-3] ^= 1;file.write_bytes(data)
    with pytest.raises(a.WindowsExecutionSecretAckError): cmp["custody"].inspect_original_creation()
    assert cmp["peer"].calls == 1


def test_coherent_selector_drift_and_key_replacement_invalidate_original_custody(tmp_path):
    cmp = fixture(tmp_path)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    custody = cmp["custody"]
    custody._profile = replace(custody._profile, private_nonce="b"*64)
    with pytest.raises(a.WindowsExecutionSecretAckError): custody.inspect_original_creation()
    custody._profile = cmp["kwargs"]["profile"]
    cmp["custody_key"].write_bytes(b"z"*32)
    with pytest.raises(a.WindowsExecutionSecretAckError): custody.inspect_original_creation()


def test_a_missing_metadata_seal_cannot_describe_a_successful_original_creation(tmp_path):
    cmp = fixture(tmp_path)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    (cmp["directory"]/a._METADATA).unlink()
    with pytest.raises(a.WindowsExecutionSecretAckError): cmp["custody"].inspect_original_creation()
    assert cmp["execution"].claim_count == 1 and cmp["loader"].loads == 1


@pytest.mark.parametrize("which", [a._SEND, a._ACK, a._METADATA])
def test_write_completion_uncertainty_retains_evidence_and_never_replays(tmp_path, monkeypatch, which):
    cmp = fixture(tmp_path)
    write = cmp["custody"]._write
    def uncertain(name, value):
        write(name, value)
        if name == which: raise OSError("Synthetic write completion uncertainty.")
    monkeypatch.setattr(cmp["custody"], "_write", uncertain)
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    before = {p.name:p.read_bytes() for p in cmp["directory"].iterdir()}
    execute(cmp)
    assert {p.name:p.read_bytes() for p in cmp["directory"].iterdir()} == before
    assert cmp["loader"].loads == 1 and cmp["peer"].calls <= 1


def test_orphan_ack_cannot_allow_a_new_send_even_if_its_marker_is_missing(tmp_path):
    cmp = fixture(tmp_path)
    (cmp["directory"]/a._ACK).write_text('{}')
    (cmp["directory"]/a._ACK).chmod(0o600)
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert cmp["peer"].calls == 0 and not (cmp["directory"]/a._SEND).exists()


@pytest.mark.parametrize("native_uuid", [c.REQUEST_UUID, "bad", "00000000-0000-4000-8000-000000000002"])
def test_zero_invalid_or_replaced_native_uuid_refuses_later_metadata(native_uuid):
    value = postcondition();value["results"]["uuid"] = native_uuid
    buffer = raw(value)
    with pytest.raises(c.WindowsExecutionSecretError):
        c.consume_windows_execution_secret_metadata(buffer, c.WindowsExecutionSecretBinding(
            "MCPV4WinExec20261021R1", "MCPV4WinTarget20261021R1", "192.0.2.90", "UNIT-WINDOWS", 37,
            hashlib.sha256(SERIAL.encode()).hexdigest(), "a"*64), expected_secret_id=43,
            create_uuid=c.REQUEST_UUID, expected_native_uuid="00000000-0000-4000-8000-000000000001")
    assert not any(buffer)


def test_independent_process_after_expiry_observes_seals_without_replaying_or_promoting_unknown(tmp_path):
    reader = _Reader()
    reader.read_postcondition = lambda plan: (_ for _ in ()).throw(M4AdapterAmbiguous("Synthetic unavailable read."))
    cmp = fixture(tmp_path, reader=reader)
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    original = cmp["custody"].inspect_original_creation()
    values = cmp["kwargs"]
    request = {key:getattr(values["request"], key) for key in values["request"].__dataclass_fields__}
    payload = dict(root=str(tmp_path), plan=asdict(values["plan"]), authorization=asdict(values["authorization"]),
        request=request, profile=asdict(values["profile"]), defaults=asdict(values["defaults"]),
        m4_tail=asdict(cmp["m4_checkpoint"].tail), c3_tail=asdict(cmp["c3_checkpoint"].tail))
    script = """
import json,sys
from pathlib import Path
from fortipam_mcp.windows_execution_secret_ack import WindowsExecutionSecretAckCustody
from fortipam_mcp.windows_execution_secret_contract import WindowsExecutionSecretBinding,WindowsExecutionSecretDefaults
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore,M4ExecutionStoreTail
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning import M4ExecutionPlan,M4ExecutionAuthorization
from v4_planning.material_provider import MaterialLeaseRequest,MaterialProviderClass,MaterialPurpose
from v4_planning.material_persistence import PersistentMaterialUseStateStore,MaterialUseStoreTail
from test_m4_execution_store import _ExternalM4Checkpoint,CHECKPOINT_STORE_REF
from test_v4_material_persistence import _ExternalMaterialCheckpoint
value=json.load(sys.stdin);root=Path(value['root'])
m4=_ExternalM4Checkpoint();m4.tail=M4ExecutionStoreTail(**value['m4_tail'])
c3=_ExternalMaterialCheckpoint('windows-c3-state');c3.tail=MaterialUseStoreTail(**value['c3_tail'])
execution=PersistentM4ExecutionStateStore(root/'m4.sqlite',root/'m4.key',monotonic_checkpoint=m4,
 checkpoint_store_ref=CHECKPOINT_STORE_REF,read_only=True)
material=PersistentMaterialUseStateStore(root/'material.sqlite',root/'material.key',monotonic_checkpoint=c3,
 checkpoint_store_ref='windows-c3-state')
request=value['request'];request['provider_class']=MaterialProviderClass(request['provider_class']);request['purpose']=MaterialPurpose(request['purpose'])
defaults=value['defaults'];defaults['policy_defaults']=tuple(defaults['policy_defaults'])
custody=WindowsExecutionSecretAckCustody(root/'custody',root/'custody.key',
 config=SecretMetadataHttpTransportConfig('https://lab.example.test','synthetic-api-token',15,None),
 profile=WindowsExecutionSecretBinding(**value['profile']),defaults=WindowsExecutionSecretDefaults(**defaults),
 plan=M4ExecutionPlan(**value['plan']),authorization=M4ExecutionAuthorization(**value['authorization']),
 request=MaterialLeaseRequest(**request),execution_store=execution,material_store=material,clock=lambda:2000)
observed=custody.inspect_original_creation()
assert observed.original_outcome=='reconciliation_required' and observed.original_verification=='unknown'
assert observed.native_uuid is not None and execution.claim_count==material.claim_count==1
print(observed.custody_digest)
"""
    before = {p.name:p.read_bytes() for p in cmp["directory"].iterdir()}
    env = {**os.environ, "PYTHONPATH":os.pathsep.join((str(Path(__file__).parent), os.environ.get("PYTHONPATH", "")))}
    result = subprocess.run([sys.executable, "-c", script], input=json.dumps(payload),
        capture_output=True, text=True, timeout=20, env=env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == original.custody_digest
    assert {p.name:p.read_bytes() for p in cmp["directory"].iterdir()} == before
    assert cmp["loader"].loads == cmp["peer"].calls == 1
