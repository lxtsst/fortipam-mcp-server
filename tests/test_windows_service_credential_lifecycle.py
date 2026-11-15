"""Service credential with synthetic peer and real persistent M4/C3 custody."""
from dataclasses import replace
import json

import pytest

from fortipam_mcp import windows_service_credential_material as m
from fortipam_mcp import windows_service_credential_birth as b
from fortipam_mcp import windows_privileged_secret_material as privileged
from fortipam_mcp.windows_privileged_secret_birth import WindowsPrivilegedSecretBirthCustody
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_secret_create_m4_runtime import _secret_plan, _authorization, _binding, _Resolver, _Verifier, _Reader
from test_v4_material_persistence import _ExternalMaterialCheckpoint
from test_windows_execution_secret_contract import Loader
from test_windows_privileged_secret_contract import defaults
from test_windows_privileged_secret_birth import witnesses, raw
from test_windows_service_credential_contract import binding, postcondition, SERIAL
from v4_planning import M4Outcome, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import MaterialProviderClass
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome

UUID = "00000000-0000-0000-0000-000000000000"


class Peer:
    def __init__(self, fault=None):
        self.fault = fault
        self.custody = None
        self.calls = 0
        self.body = self.ack = self.before = self.after = None

    def _windows_service_credential_ready(self, profile, request):
        return self.custody is not None and not any(self.custody._directory.iterdir())

    def _create_windows_service_credential(self, profile, request, body):
        self.custody.begin_original_send(body)
        self.calls += 1; self.body = body.obj
        assert b'"target-privilege-account":"disable"' in body.obj
        assert b'"rdp-service-status":"down"' in body.obj
        self.ack = raw(dict(version="v7.0.0", build=29, http_method="POST", http_status=200,
            status="success", path="secret", name="database", vdom="root", serial=SERIAL,
            mkey=70, error=0, results={"opaque": "SYNTHETIC_ACK_DO_NOT_DECODE"}))
        self.custody.capture_original_ack(self.ack, http_status=200, content_type="application/json")
        if self.fault == "after-ack": raise KeyboardInterrupt
        self.custody.capture_original_frame(raw(postcondition()))
        before, after = postcondition(), postcondition()
        after["results"]["totp-setting"]["shared-key"] = "SYNTHETIC_VOLATILE_RENDER"
        arguments = witnesses(self.custody)
        if self.fault == "privilege": after["results"]["target-privilege-account"] = "enable"
        if self.fault == "association": after["results"]["target-info"]["priv_acct"] = 70
        if self.fault == "subject":
            for value in (before, after): value["results"]["field"][1]["value"] = "UNIT-WINDOWS\\other"
        if self.fault == "unknown": after["results"]["future-setting"]["nested-secret-render"] = "different"
        if self.fault == "password": arguments = witnesses(self.custody, password="different")
        self.before, self.after = raw(before), raw(after)
        self.custody.capture_original_birth(self.before, self.after, **arguments)
        return SecretCreateAdapterOutcome.VERIFIED_CREATED


def fixture(tmp_path, *, fault=None, peer=None):
    tmp_path.chmod(0o700)
    for name,value in (("m4.key", b"e"*32), ("material.key", b"m"*32), ("birth.key", b"b"*32)):
        path=tmp_path/name; path.write_bytes(value); path.chmod(0o600)
    execution = PersistentM4ExecutionStateStore(tmp_path/"m4.sqlite", tmp_path/"m4.key",
        monotonic_checkpoint=_ExternalM4Checkpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
    material = PersistentMaterialUseStateStore(tmp_path/"material.sqlite", tmp_path/"material.key",
        monotonic_checkpoint=_ExternalMaterialCheckpoint("windows-service-c3-state"),
        checkpoint_store_ref="windows-service-c3-state")
    profile, baseline = binding(), defaults()
    base = _secret_plan()
    parameters = m.windows_service_credential_parameters_digest(profile, baseline, create_uuid=UUID)
    fields = {**base.canonical_content(), "adapter_ref": m.ADAPTER_REF, "target_ref": m.TARGET_REF,
              "parameters_digest": parameters}
    plan = replace(base, adapter_ref=m.ADAPTER_REF, target_ref=m.TARGET_REF,
        parameters_digest=parameters, plan_digest=canonical_digest(fields))
    authorization = _authorization(plan)
    bound = _binding(plan, authorization)
    bound = replace(bound, lease_request=replace(bound.lease_request,
        provider_class=MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE))
    loader, peer, now = Loader(), peer or Peer(fault), [1000]
    kwargs = dict(profile=profile, defaults=baseline, create_uuid=UUID, plan=plan, authorization=authorization,
        execution_store=execution, material_store=material, material_binding=bound.material_binding,
        request=bound.lease_request, loader=loader, transport=peer, clock=lambda: now[0])
    directory = tmp_path/"birth"; directory.mkdir(mode=0o700)
    birth_kwargs = {name: kwargs[name] for name in ("profile", "defaults", "plan", "authorization", "request",
                   "execution_store", "material_store", "clock")}
    birth_kwargs.update(config=SecretMetadataHttpTransportConfig("https://lab.example.test", "synthetic-token", 15, None),
                       full_row_fields=frozenset(postcondition()["results"]))
    custody = b.WindowsServiceCredentialBirthCustody(directory, tmp_path/"birth.key", **birth_kwargs)
    peer.custody = custody
    runtime = m.windows_service_credential_material_runtime(**kwargs)
    outer = ProtectedSecretCreateM4Runtime(_Resolver(bound), _Verifier(), execution, runtime, _Reader(),
        authenticated_requester_digest=plan.requester_digest, clock=lambda: now[0])
    return dict(kwargs=kwargs, birth_kwargs=birth_kwargs, directory=directory, key=tmp_path/"birth.key",
        runtime=runtime, outer=outer, bound=bound, loader=loader, peer=peer, now=now, custody=custody,
        execution=execution, material=material)


def execute(cmp):
    return cmp["outer"].execute_bound(cmp["bound"].authorization.authorization_ref)


def test_fixed_service_runtime_and_original_full_birth_match_independent_pristine_state_after_expiry(tmp_path):
    cmp = fixture(tmp_path)
    assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    original = cmp["custody"].inspect_original_creation()
    assert original.native_secret_id == 70 and original.native_uuid and original.state_digest
    assert cmp["execution"].claim_count == cmp["material"].claim_count == 1
    assert cmp["loader"].loads == cmp["peer"].calls == 1
    assert all(not value for value in (cmp["peer"].body, cmp["peer"].ack, cmp["peer"].before,
                                       cmp["peer"].after, cmp["loader"].username, cmp["loader"].password))
    snapshot = {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}
    stored = b"".join(snapshot.values())
    assert all(value not in stored for value in (b"labuser", b"synthetic-credential", b"SYNTHETIC_", b"MCPV4Svc"))
    assert execute(cmp).idempotent_replay and cmp["peer"].calls == 1
    cmp["custody"].close(); cmp["now"][0] = 9999
    independent = b.WindowsServiceCredentialBirthCustody(cmp["directory"], cmp["key"], **cmp["birth_kwargs"])
    before, after = raw(postcondition()), raw(postcondition())
    assert independent.consume_pristine_birth(before, after, **witnesses(independent)) == original
    assert not before and not after
    assert snapshot == {p.name: p.read_bytes() for p in cmp["directory"].iterdir()}
    independent.close()


@pytest.mark.parametrize("fault", ["privilege", "association", "subject", "unknown", "password", "after-ack"])
def test_original_service_failure_is_consumed_and_cannot_be_adopted_or_replayed(tmp_path, fault):
    cmp = fixture(tmp_path, fault=fault)
    if fault == "after-ack":
        with pytest.raises(KeyboardInterrupt): execute(cmp)
    else:
        assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    original = cmp["custody"].inspect_original_creation()
    assert original.state_digest is None
    assert (original.native_uuid is None) == (fault == "after-ack")
    assert not (cmp["directory"]/"create.full-birth.json").exists()
    assert not cmp["peer"].before and not cmp["peer"].after
    execute(cmp)
    assert cmp["loader"].loads == cmp["peer"].calls == 1
    assert not cmp["loader"].password and not cmp["peer"].body


@pytest.mark.parametrize("fault", ["sid", "material-source", "service-context", "transport-method"])
def test_source_and_fixed_transport_drift_during_material_acquisition_refuse_before_send(tmp_path, fault):
    cmp = fixture(tmp_path)
    load = cmp["loader"].load_secret_create_material_once
    def drift():
        value = load()
        if fault == "transport-method":
            cmp["peer"]._create_windows_service_credential = lambda *args: pytest.fail("unbound transport called")
        else:
            field = {"sid": "subject_sid_digest", "material-source": "material_source_context_digest",
                     "service-context": "service_context_digest"}[fault]
            profile = cmp["kwargs"]["profile"]
            object.__setattr__(profile, field, "2"*64)
        return value
    cmp["loader"].load_secret_create_material_once = drift
    assert execute(cmp).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert cmp["peer"].calls == 0 and not list(cmp["directory"].iterdir())
    assert not cmp["loader"].username and not cmp["loader"].password


def test_fixed_service_and_privileged_entries_cannot_cross_profiles_refs_or_birth_custody(tmp_path):
    cmp = fixture(tmp_path)
    with pytest.raises(privileged.WindowsPrivilegedSecretError):
        privileged.windows_privileged_secret_material_runtime(**cmp["kwargs"])
    with pytest.raises(b.WindowsServiceCredentialBirthError):
        WindowsPrivilegedSecretBirthCustody(cmp["directory"], cmp["key"], **cmp["birth_kwargs"])
    from test_windows_privileged_secret_contract import binding as privileged_binding
    kwargs={**cmp["kwargs"], "profile": privileged_binding()}
    with pytest.raises(m.WindowsServiceCredentialError): m.windows_service_credential_material_runtime(**kwargs)
    kwargs={**cmp["kwargs"], "transport": object()}
    with pytest.raises(m.WindowsServiceCredentialError): m.windows_service_credential_material_runtime(**kwargs)
    assert cmp["execution"].claim_count == cmp["material"].claim_count == cmp["loader"].loads == 0
    assert not list(cmp["directory"].iterdir())
