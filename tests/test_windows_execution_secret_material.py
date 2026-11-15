"""Synthetic product peer with the real persistent M4/C3 execution engines."""
from contextvars import copy_context
from dataclasses import replace
from threading import Thread

import pytest

from fortipam_mcp import windows_execution_secret_material as m
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_secret_create_m4_runtime import _secret_plan, _authorization, _binding, _Resolver, _Verifier, _Reader
from test_v4_material_persistence import _ExternalMaterialCheckpoint
from test_windows_execution_secret_contract import Loader, binding, source
from v4_planning import M4Outcome, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import MaterialProviderClass
from v4_planning.material_runtime import material_lease_request_digest
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome

UUID = "00000000-0000-0000-0000-000000000000"


class Peer:
    def __init__(self, outcome=SecretCreateAdapterOutcome.VERIFIED_CREATED):
        self.calls = 0
        self.outcome = outcome
        self.body = self.view = self.context = None
        self.before_return = lambda: None

    def _create_windows_execution_secret(self, profile, request, body):
        self.calls += 1
        assert body.readonly and body.c_contiguous and type(body.obj) is bytearray
        assert b'UNIT-WINDOWS\\\\labuser' in body.obj
        assert b'synthetic-credential' in body.obj and b'"Host"' not in body.obj
        self.body, self.view = body.obj, body
        self.context = copy_context()
        self.before_return()
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome

    def _windows_execution_secret_ready(self, profile, request): return True


def components(tmp_path, *, peer=None, loader=None, reader=None):
    tmp_path.chmod(0o700)
    for name, value in (("m4.key", b"e"*32), ("material.key", b"m"*32)):
        path = tmp_path/name
        path.write_bytes(value)
        path.chmod(0o600)
    m4_checkpoint, c3_checkpoint = _ExternalM4Checkpoint(), _ExternalMaterialCheckpoint("windows-c3-state")
    execution = PersistentM4ExecutionStateStore(tmp_path/"m4.sqlite", tmp_path/"m4.key",
        monotonic_checkpoint=m4_checkpoint, checkpoint_store_ref=CHECKPOINT_STORE_REF)
    material = PersistentMaterialUseStateStore(tmp_path/"material.sqlite", tmp_path/"material.key",
        monotonic_checkpoint=c3_checkpoint, checkpoint_store_ref="windows-c3-state")
    profile, defaults = binding(), source()
    base = _secret_plan()
    fields = {**base.canonical_content(), "adapter_ref": m.ADAPTER_REF, "target_ref": m.TARGET_REF,
        "parameters_digest": m.windows_execution_secret_parameters_digest(profile, defaults, create_uuid=UUID)}
    plan = replace(base, adapter_ref=m.ADAPTER_REF, target_ref=m.TARGET_REF,
        parameters_digest=fields["parameters_digest"], plan_digest=canonical_digest(fields))
    authorization = _authorization(plan)
    bound = _binding(plan, authorization)
    bound = replace(bound, lease_request=replace(bound.lease_request,
        provider_class=MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE))
    loader, peer, reader = loader or Loader(), peer or Peer(), reader or _Reader()
    now = [1000]
    kwargs = dict(profile=profile, defaults=defaults, create_uuid=UUID, plan=plan, authorization=authorization,
        execution_store=execution, material_store=material, material_binding=bound.material_binding,
        request=bound.lease_request, loader=loader, transport=peer, clock=lambda: now[0])
    runtime = m.windows_execution_secret_material_runtime(**kwargs)
    outer = ProtectedSecretCreateM4Runtime(_Resolver(bound), _Verifier(), execution, runtime, reader,
        authenticated_requester_digest=plan.requester_digest, clock=lambda: now[0])
    return dict(kwargs=kwargs, runtime=runtime, outer=outer, bound=bound, loader=loader, peer=peer,
        reader=reader, now=now, execution=execution, material=material,
        m4_checkpoint=m4_checkpoint, c3_checkpoint=c3_checkpoint)


def execute(c):
    return c["outer"].execute_bound(c["bound"].authorization.authorization_ref)


def test_real_persistent_m4_c3_join_uses_machine_qualified_material_and_clears_every_buffer(tmp_path):
    c = components(tmp_path)
    result = execute(c)
    assert result.outcome is M4Outcome.SUCCEEDED
    assert c["loader"].loads == c["peer"].calls == 1
    assert c["execution"].claim_count == c["material"].claim_count == 1
    assert c["reader"].calls == ["current", "post"]
    assert not any(c["loader"].username) and not any(c["loader"].password) and not any(c["peer"].body)
    with pytest.raises(ValueError): len(c["peer"].view)
    replay = execute(c)
    assert replay.idempotent_replay and c["loader"].loads == c["peer"].calls == 1
    for path in (tmp_path/"m4.sqlite", tmp_path/"material.sqlite"):
        data = path.read_bytes()
        assert b"synthetic-credential" not in data and b"labuser" not in data and b"MCPV4WinExec" not in data


def test_direct_c3_call_without_original_m4_scope_cannot_load_or_reserve_material(tmp_path):
    c = components(tmp_path)
    with pytest.raises(Exception):
        c["runtime"].execute_once(c["bound"].material_binding, c["bound"].lease_request, now_epoch=1000)
    assert c["loader"].loads == c["peer"].calls == c["execution"].claim_count == c["material"].claim_count == 0


@pytest.mark.parametrize("outcome", [SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED,
    "verified_created", None, RuntimeError("synthetic private failure"), KeyboardInterrupt()])
def test_uncertain_or_interrupted_dispatch_erases_material_and_is_never_replayed(tmp_path, outcome):
    c = components(tmp_path, peer=Peer(outcome))
    if isinstance(outcome, KeyboardInterrupt):
        with pytest.raises(KeyboardInterrupt): execute(c)
    else:
        assert execute(c).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert c["reader"].calls == ["current"]
    assert not any(c["loader"].password) and not any(c["peer"].body)
    assert c["loader"].loads == c["peer"].calls == 1
    execute(c)
    assert c["loader"].loads == c["peer"].calls == 1
    assert c["material"].claim_count == c["execution"].claim_count == 1


def test_current_state_drift_stops_before_material_or_transport(tmp_path):
    reader = _Reader()
    reader.read_current = lambda plan: "0"*64
    c = components(tmp_path, reader=reader)
    assert execute(c).outcome is not M4Outcome.SUCCEEDED
    assert c["loader"].loads == c["peer"].calls == c["material"].claim_count == 0


def test_postcondition_drift_retains_original_verification_failure_and_consumed_material(tmp_path):
    c = components(tmp_path, reader=_Reader(post="0"*64))
    assert execute(c).outcome is M4Outcome.VERIFICATION_FAILED
    assert c["reader"].calls == ["current", "post"]
    execute(c)
    assert c["loader"].loads == c["peer"].calls == 1 and not any(c["peer"].body)


@pytest.mark.parametrize("clock", [999, 1060, True, "1000"])
def test_clock_drift_after_source_load_erases_transferred_pair_without_sending(tmp_path, clock):
    c = components(tmp_path)
    original = c["loader"].load_secret_create_material_once
    def load():
        pair = original()
        c["now"][0] = clock
        return pair
    c["loader"].load_secret_create_material_once = load
    assert execute(c).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert c["loader"].loads == 1 and c["peer"].calls == 0
    assert not any(c["loader"].username) and not any(c["loader"].password)
    assert c["material"].claim_count == 1


def test_a_persisted_unfinished_c3_claim_never_substitutes_for_acquisition(tmp_path):
    c = components(tmp_path)
    request = c["bound"].lease_request
    c["material"].claim(request_digest=material_lease_request_digest(request),
        authorization_digest=request.authorization_digest)
    assert execute(c).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert c["loader"].loads == c["peer"].calls == 0 and c["material"].claim_count == 1


def test_reconstructed_composition_cannot_resume_an_interrupted_original_dispatch(tmp_path):
    c = components(tmp_path, peer=Peer(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt): execute(c)
    fresh_loader, fresh_peer = Loader(), Peer()
    kwargs = {**c["kwargs"], "loader": fresh_loader, "transport": fresh_peer}
    runtime = m.windows_execution_secret_material_runtime(**kwargs)
    rebuilt = ProtectedSecretCreateM4Runtime(_Resolver(c["bound"]), _Verifier(), c["execution"],
        runtime, _Reader(), authenticated_requester_digest=c["bound"].plan.requester_digest, clock=lambda: 1000)
    result = rebuilt.execute_bound(c["bound"].authorization.authorization_ref)
    assert result.outcome is not M4Outcome.SUCCEEDED
    assert fresh_loader.loads == fresh_peer.calls == 0
    assert c["material"].claim_count == c["execution"].claim_count == 1


def test_expiry_during_product_call_cannot_be_reported_as_success(tmp_path):
    c = components(tmp_path)
    c["peer"].before_return = lambda: c["now"].__setitem__(0, 1060)
    assert execute(c).outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert c["peer"].calls == c["loader"].loads == 1
    assert not any(c["loader"].password) and not any(c["peer"].body)
    assert c["reader"].calls == ["current"]


def test_copied_context_cannot_authorize_another_thread_or_survive_dispatch(tmp_path):
    c = components(tmp_path)
    guard = c["runtime"]._adapter.guard
    denied = []
    def attempt():
        try: guard.require(claimed=True, acquired=True)
        except Exception: denied.append(True)
    def during():
        context = copy_context()
        thread = Thread(target=lambda: context.run(attempt))
        thread.start();thread.join(timeout=5)
        assert not thread.is_alive() and denied == [True]
    c["peer"].before_return = during
    assert execute(c).outcome is M4Outcome.SUCCEEDED
    c["peer"].context.run(attempt)
    assert denied == [True, True]


@pytest.mark.parametrize("fault", ["profile", "defaults", "uuid", "request", "uncheckpointed", "shared-key"])
def test_incompatible_private_bindings_are_rejected_before_material(tmp_path, fault):
    c = components(tmp_path)
    kwargs = dict(c["kwargs"])
    if fault == "profile": kwargs["profile"] = replace(kwargs["profile"], private_nonce="b"*64)
    if fault == "defaults": kwargs["defaults"] = replace(kwargs["defaults"], guards_digest="b"*64)
    if fault == "uuid": kwargs["create_uuid"] = "00000000-0000-4000-8000-000000000002"
    if fault == "request": kwargs["request"] = replace(kwargs["request"], authorization_digest="f"*64)
    if fault == "uncheckpointed":
        path = tmp_path/"other.key";path.write_bytes(b"x"*32);path.chmod(0o600)
        kwargs["material_store"] = PersistentMaterialUseStateStore(tmp_path/"other.sqlite", path)
    if fault == "shared-key":
        path = tmp_path/"other.key";path.write_bytes(b"e"*32);path.chmod(0o600)
        kwargs["material_store"] = PersistentMaterialUseStateStore(tmp_path/"other.sqlite", path,
            monotonic_checkpoint=_ExternalMaterialCheckpoint("other-c3-store"), checkpoint_store_ref="other-c3-store")
    with pytest.raises(m.WindowsExecutionSecretError): m.windows_execution_secret_material_runtime(**kwargs)
    assert c["loader"].loads == c["peer"].calls == c["material"].claim_count == c["execution"].claim_count == 0
