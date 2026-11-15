from dataclasses import replace
import hashlib
import json
import shutil

import pytest

from fortipam_mcp import secret_bulk_import_metadata as metadata
from fortipam_mcp.web_secret_fixture_creation import join_web_secret_fixture_creation, WebSecretFixtureCreationError
from test_m4_execution_store import _store, _event
from test_secret_create_m4_runtime import _secret_plan, _binding
from test_v4_execution_kernel import _authorization, NOW, _Verifier
from test_web_secret_create_dispatch_observation import _web_binding, _transport, _Connection, _create
from test_secret_create_191_http_transport import _MetadataTransport
from v4_planning import (M4ExecutionKernel, M4ExecutionResult, M4Outcome, M4Verification,
                         M4Compensation, canonical_digest)
from v4_planning.material_provider import MaterialProviderClass

SERIAL = "unit-appliance"
SERIAL_DIGEST = hashlib.sha256(SERIAL.encode()).hexdigest()


def _response(binding, **changes):
    row = {"id": 37, "name": binding.secret_name, "folder": 17, "template": "Web Account", "target": "",
           "inherit-permission": "enable", "recording": "enable", "http-service-status": "up",
           "uuid": "11111111-2222-4333-8444-555555555555", "instruction-profile": "",
           "field": [{"name": "Password", "value": "UNIT_PROTECTED_PASSWORD"}],
           "totp": {"seed": "UNIT_PROTECTED_TOTP"}}
    row.update(changes)
    envelope = {"version": "v7.0.0", "build": 29, "path": "secret", "name": "database",
                "http_method": "GET", "status": "OK", "http_status": 200, "vdom": "root",
                "serial": SERIAL, "results": [row], "limit_reached": False, "next_idx": 0}
    return bytearray(json.dumps(envelope).encode())


def _setup(tmp_path, monkeypatch, mode="success"):
    plan = _secret_plan()
    authorization = _authorization(plan)
    execution = _binding(plan, authorization)
    execution = replace(execution, lease_request=replace(execution.lease_request,
                        provider_class=MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE))
    binding = replace(_web_binding(), plan_digest=plan.plan_digest)
    store = _store(tmp_path)
    pinned = canonical_digest({"database": str(store._path), "key_file": str(store._key_path),
                               "key_digest": hashlib.sha256(store._key).hexdigest()})
    connection = _Connection()
    class Metadata(_MetadataTransport):
        def resolve_secret_create_uuid(self):
            return "00000000-0000-0000-0000-000000000000"

    transport = _transport(monkeypatch, connection, Metadata())

    class Adapter:
        def read_current(self, plan):
            return plan.expected_current_digest

        def dispatch(self, plan):
            if mode != "missing_ack":
                _create(transport, binding, execution.lease_request)

        def read_postcondition(self, plan):
            return "e" * 64 if mode == "post_mismatch" else plan.expected_state_digest

    if mode in {"missing_claim", "unfinished", "unknown"}:
        _create(transport, binding, execution.lease_request)
        if mode != "missing_claim":
            context = canonical_digest({"authorization_digest": authorization.authorization_digest,
                                        "plan_digest": plan.plan_digest, "revision": plan.revision})
            store.claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
                        idempotency_digest=plan.idempotency_digest, context_digest=context,
                        authorization_digest=authorization.authorization_digest)
            if mode == "unknown":
                store.finalize(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
                    idempotency_digest=plan.idempotency_digest, context_digest=context,
                    result=M4ExecutionResult(M4Outcome.RECONCILIATION_REQUIRED, M4Verification.UNKNOWN,
                                             M4Compensation.NOT_REQUESTED, False),
                    event=_event(authorization="dispatch_unknown", outcome=M4Outcome.RECONCILIATION_REQUIRED,
                                 verification=M4Verification.UNKNOWN))
    else:
        M4ExecutionKernel(Adapter(), _Verifier(), store).execute(plan, authorization, now_epoch=NOW)
    return dict(transport=transport, create_binding=binding, execution_binding=execution,
                execution_store=store, serial_digest=SERIAL_DIGEST, expected_store_digest=pinned), connection


def test_original_three_way_join_uses_real_ledger_without_dispatch_or_material_decode(tmp_path, monkeypatch):
    inputs, connection = _setup(tmp_path, monkeypatch)
    raw = _response(inputs["create_binding"])
    original_scalar = metadata._scalar
    decoded = []

    def scalar(*args):
        result = original_scalar(*args)
        decoded.append(result)
        return result

    monkeypatch.setattr(metadata, "_scalar", scalar)
    store = inputs["execution_store"]
    before = (store.claim_count, store.audit_events, store._path.read_bytes())
    proof = join_web_secret_fixture_creation(**inputs, response=raw)
    assert proof.native_secret_id == 37 and proof.serial_digest == SERIAL_DIGEST
    assert not any(raw) and connection.posts == 1
    assert (store.claim_count, store.audit_events, store._path.read_bytes()) == before
    assert "UNIT_PROTECTED_PASSWORD" not in decoded and "UNIT_PROTECTED_TOTP" not in decoded
    baseline = json.loads(proof.baseline_json)
    observation = inputs["transport"].read_web_create_dispatch_observation(
        inputs["create_binding"], inputs["execution_binding"].lease_request)
    assert observation.create_uuid == "00000000-0000-0000-0000-000000000000"
    assert baseline["uuid"] != observation.create_uuid
    assert "field" not in baseline and "totp" not in baseline
    assert proof.baseline_digest == hashlib.sha256(
        b"private-web-fixture-baseline/v1\0" + proof.baseline_json.encode("ascii"),
    ).hexdigest()
    assert repr(proof) == str(proof) == "<WebSecretFixtureCreationEvidence redacted>"


@pytest.mark.parametrize("mode", ["missing_ack", "missing_claim", "unfinished", "unknown", "post_mismatch"])
def test_http_or_terminal_m4_alone_is_insufficient(tmp_path, monkeypatch, mode):
    inputs, connection = _setup(tmp_path, monkeypatch, mode)
    raw = _response(inputs["create_binding"])
    count, events, posts = inputs["execution_store"].claim_count, inputs["execution_store"].audit_events, connection.posts
    with pytest.raises(WebSecretFixtureCreationError, match="evidence is unavailable"):
        join_web_secret_fixture_creation(**inputs, response=raw)
    assert not any(raw) and connection.posts == posts
    assert (inputs["execution_store"].claim_count, inputs["execution_store"].audit_events) == (count, events)


@pytest.mark.parametrize("change", [{"folder": True}, {"folder": 18}, {"name": "other-secret"},
    {"template": "Other"}, {"target": "other-target"}, {"recording": "disable"},
    {"uuid": "00000000-0000-0000-0000-000000000000"}, {"uuid": "invalid-uuid"},
    {"uuid": True}, {"instruction-profile": "assigned-profile"},
    {"q_origin_key": 38}, {"q_origin_key": True}])
def test_fixed_readback_drift_cannot_join(tmp_path, monkeypatch, change):
    inputs, connection = _setup(tmp_path, monkeypatch)
    raw = _response(inputs["create_binding"], **change)
    with pytest.raises(WebSecretFixtureCreationError):
        join_web_secret_fixture_creation(**inputs, response=raw)
    assert not any(raw) and connection.posts == 1


def test_copied_ledger_cannot_replace_startup_bound_original(tmp_path, monkeypatch):
    inputs, _ = _setup(tmp_path, monkeypatch)
    other = _store(tmp_path / "other")
    shutil.copyfile(inputs["execution_store"]._path, other._path)
    raw = _response(inputs["create_binding"])
    with pytest.raises(WebSecretFixtureCreationError):
        join_web_secret_fixture_creation(**{**inputs, "execution_store": other}, response=raw)
    assert not any(raw)


def test_missing_original_ledger_is_not_recreated(tmp_path, monkeypatch):
    inputs, _ = _setup(tmp_path, monkeypatch)
    path = inputs["execution_store"]._path
    path.unlink()
    raw = _response(inputs["create_binding"])
    with pytest.raises(WebSecretFixtureCreationError):
        join_web_secret_fixture_creation(**inputs, response=raw)
    assert not path.exists() and not any(raw)


def test_request_context_mismatch_refuses_before_any_scalar_decode(tmp_path, monkeypatch):
    inputs, connection = _setup(tmp_path, monkeypatch)
    execution = inputs["execution_binding"]
    request = replace(execution.lease_request, audience_digest="e" * 64)
    execution = replace(execution, lease_request=request, audience_digest=request.audience_digest)
    raw = _response(inputs["create_binding"])
    monkeypatch.setattr(metadata, "_scalar", lambda *_args: pytest.fail("Context must qualify before decoding."))
    with pytest.raises(WebSecretFixtureCreationError):
        join_web_secret_fixture_creation(**{**inputs, "execution_binding": execution}, response=raw)
    assert not any(raw) and connection.posts == 1


@pytest.mark.parametrize("kind", ["serial", "duplicate", "pagination", "unknown_field", "selected_duplicate"])
def test_wrong_device_or_ambiguous_response_refuses_and_clears(tmp_path, monkeypatch, kind):
    inputs, _ = _setup(tmp_path, monkeypatch)
    value = json.loads(_response(inputs["create_binding"]))
    if kind == "serial": value["serial"] = "other-appliance"
    elif kind == "duplicate": value["results"] *= 2
    elif kind == "pagination": value["limit_reached"] = True
    elif kind == "unknown_field": value["results"][0]["instruction-profile"] = {"password": "UNIT_PROTECTED_PASSWORD"}
    raw = bytearray(json.dumps(value).encode())
    if kind == "selected_duplicate": raw = raw.replace(b'"folder": 17', b'"folder": 17, "folder": 18')
    with pytest.raises(WebSecretFixtureCreationError):
        join_web_secret_fixture_creation(**inputs, response=raw)
    assert not any(raw)
