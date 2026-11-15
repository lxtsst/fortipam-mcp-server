from dataclasses import replace
import json
import hashlib
import os

import pytest

from fortipam_mcp.secret_request_create_invocation_witness import (
    OwnerOnlySecretRequestCreateInvocationWitnessStore as Store,
    SecretRequestCreateInvocationWitness as Witness,
    SecretRequestCreateInvocationWitnessError as Error,
)
from fortipam_mcp.secret_request_create_http_transport import (
    FortiPamSecretRequestCreateHttpTransport, OwnerOnlySecretRequestCreateBindingResolver,
    OwnerOnlySecretRequestCreateDispatchClaim, SecretRequestCreateTransportOutcome,
)
from fortipam_mcp.secret_request_collection_http_transport import SecretRequestCollectionRecord, SecretRequestCreatorSnapshot
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_secret_request_create_http_transport import (
    _principal, _binding, _request, _write_binding, _ActorInspector,
    _DefaultInspector, _Collection, _DetailObserver, _FailingFinalizeClaim,
)


def _witness():
    principal = _principal()
    binding = _binding(principal)
    return Witness(binding.intent_ref, principal.requester.digest, principal.transport_namespace_digest,
                   binding.fortipam_requester, binding.environment_ref, binding.scope_ref,
                   SecretRequestCollectionRecord(71, 83, "launcher", 1790000001), 1790000000.0, 1790000002.0, "a" * 64)


def test_store_roundtrip_independent_key_immutable_and_private(tmp_path):
    path = tmp_path / "witness.json"
    store = Store(path, b"w" * 32)
    witness = _witness()
    store.assert_available()
    store.publish(witness)
    assert store.load() == witness
    assert path.stat().st_mode & 0o777 == 0o600
    original = path.read_bytes()
    assert b"wwww" not in original
    assert "synthetic-requester" not in repr(witness)
    for action in [store.assert_available, lambda: store.publish(witness), lambda: Store(path, b"x" * 32).load()]:
        with pytest.raises(Error):
            action()
    assert path.read_bytes() == original
    with pytest.raises(Error):
        replace(witness, create_finished_at=0)


@pytest.mark.parametrize("fault", ["file_symlink", "parent_symlink", "mode", "hardlink", "oversize", "tamper"])
def test_store_rejects_unsafe_and_untrusted_inputs(tmp_path, fault):
    folder = tmp_path / "owner"
    folder.mkdir(mode=0o700)
    path = folder / "witness.json"
    store = Store(path, b"w" * 32)
    store.publish(_witness())
    if fault == "file_symlink":
        alias = folder / "alias"
        alias.symlink_to(path)
        store = Store(alias, b"w" * 32)
    elif fault == "parent_symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(folder, target_is_directory=True)
        store = Store(alias / path.name, b"w" * 32)
    elif fault == "mode":
        path.chmod(0o644)
    elif fault == "hardlink":
        os.link(path, folder / "alias")
    elif fault == "oversize":
        path.write_bytes(b"x" * 8193)
    else:
        payload = json.loads(path.read_bytes())
        payload["payload"]["transport_digest"] = "f" * 64
        path.write_text(json.dumps(payload))
    with pytest.raises(Error):
        store.load()


@pytest.mark.parametrize("failure", ["none", "preflight", "cleanup", "finalize", "publish", "published_then_failed"])
def test_transport_witness_order_failure_closed_and_no_replay(tmp_path, failure, caplog):
    principal = _principal()
    binding = _binding(principal)
    binding_path = tmp_path / "binding.json"
    _write_binding(binding_path, binding, _request())
    claim_path = tmp_path / "claim.json"
    calls = []
    store = Store(tmp_path / "witness.json", b"w" * 32)

    class Sink:
        def assert_available(self):
            calls.append("preflight")
            if failure == "preflight":
                raise RuntimeError("private-error")
            store.assert_available()

        def publish(self, witness):
            calls.append("publish")
            assert calls.index("cleanup") < calls.index("publish")
            assert json.loads(claim_path.read_bytes())["terminal_outcome"] == "bound"
            expected_digest = hashlib.sha256(json.dumps(json.loads(claim_path.read_bytes()), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
            assert witness == replace(_witness(), create_claim_digest=expected_digest)
            if failure == "publish":
                raise RuntimeError("private-error")
            store.publish(witness)
            if failure == "published_then_failed":
                raise RuntimeError("private-error")

    def cleanup():
        calls.append("cleanup")
        return failure != "cleanup"

    def dispatch(body):
        calls.append("post")
        return 200

    claim_cls = _FailingFinalizeClaim if failure == "finalize" else OwnerOnlySecretRequestCreateDispatchClaim
    clock = iter([1790000000.0, 1790000002.0])
    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig("https://fpa.example", "synthetic", 5, None),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(binding_path),
        dispatch_claim=claim_cls(claim_path, b"k" * 32),
        authorized_environment_ref=binding.environment_ref, authorized_scope_ref=binding.scope_ref,
        actor_inspector=_ActorInspector(), default_inspector=_DefaultInspector(calls),
        collection=_Collection(calls, [SecretRequestCreatorSnapshot(()), SecretRequestCreatorSnapshot((_witness().created_record,))]),
        detail_observer=_DetailObserver(calls), session_finalizer=cleanup, request_dispatcher=dispatch,
        invocation_witness_sink=Sink(), witness_clock=lambda: next(clock),
    )
    result = transport.create(binding.intent_ref, principal=principal)
    assert result.outcome == (SecretRequestCreateTransportOutcome.BOUND if failure == "none" else SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED)
    assert transport.create(binding.intent_ref, principal=principal) is result
    assert calls.count("post") == (0 if failure == "preflight" else 1)
    assert calls.count("publish") == (1 if failure in {"none", "publish", "published_then_failed"} else 0)
    assert "private-error" not in caplog.text
    if failure in {"publish", "published_then_failed"}:
        claim = json.loads(claim_path.read_bytes())
        assert claim["terminal_outcome"] == "reconciliation_required"
        assert claim["retry_allowed"] is False
        assert claim["failure_stage"] == "invocation_witness"


def test_failed_directory_fsync_retracts_publication(tmp_path, monkeypatch):
    import fortipam_mcp.secret_request_create_invocation_witness as module
    path = tmp_path / "witness.json"
    store = Store(path, b"w" * 32)
    original = module.os.fsync
    count = 0

    def fsync(fd):
        nonlocal count
        count += 1
        if count == 2:
            raise OSError("private-path")
        original(fd)

    monkeypatch.setattr(module.os, "fsync", fsync)
    with pytest.raises(Error, match="unavailable"):
        store.publish(_witness())
    assert not path.exists()
    assert not list(tmp_path.iterdir())


def test_unknown_material_rejected_before_value_decode(tmp_path, monkeypatch):
    import fortipam_mcp.secret_request_create_invocation_witness as module
    path = tmp_path / "witness.json"
    path.write_bytes(b'{"payload":{"field":"synthetic-protected-material"},"hmac_sha256":"fake"}')
    path.chmod(0o600)

    original = module.json.loads

    def forbidden(raw, *args, **kwargs):
        assert bytes(raw).startswith(b'"')
        assert b"synthetic-protected-material" not in raw
        return original(raw, *args, **kwargs)

    monkeypatch.setattr(module.json, "loads", forbidden)
    with pytest.raises(Error):
        Store(path, b"w" * 32).load()


@pytest.mark.parametrize("fault", ["none", "duplicate", "float_status", "false_dispatch", "reconciliation", "foreign_intent", "hardlink", "mode", "oversize", "initial", "restarted_instance"])
def test_bound_claim_digest_requires_actual_exact_terminal_claim(tmp_path, fault):
    from fortipam_mcp.secret_request_create_http_transport import SecretRequestCreateDispatchClaimError
    path = tmp_path / "claim.json"
    claim = OwnerOnlySecretRequestCreateDispatchClaim(path, b"c" * 32)
    claim.claim(memoryview(b'{"synthetic":true}'), binding=_binding(_principal()))
    if fault != "initial":
        claim.finalize(terminal_outcome="bound", failure_stage="none", http_status_class="none", post_http_status=200)
    payload = json.loads(path.read_bytes())
    if fault == "duplicate":
        path.write_text(path.read_text().strip()[:-1] + ',"post_http_status":200}')
    elif fault == "float_status":
        payload["post_http_status"] = 200.0
        path.write_text(json.dumps(payload))
    elif fault == "false_dispatch":
        payload["dispatch_attempted"] = 1
        path.write_text(json.dumps(payload))
    elif fault == "reconciliation":
        payload["terminal_outcome"] = "reconciliation_required"
        path.write_text(json.dumps(payload))
    elif fault == "foreign_intent":
        payload["intent_binding_hmac"] = "e" * 64
        path.write_text(json.dumps(payload))
    elif fault == "hardlink":
        os.link(path, tmp_path / "alias")
    elif fault == "mode":
        path.chmod(0o644)
    elif fault == "oversize":
        path.write_bytes(b" " * 4097)
    elif fault == "restarted_instance":
        claim = OwnerOnlySecretRequestCreateDispatchClaim(path, b"c" * 32)
    if fault == "none":
        assert claim.bound_digest() == hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
    else:
        with pytest.raises(SecretRequestCreateDispatchClaimError):
            claim.bound_digest()


def test_store_rejects_prior_contract_without_claim_digest(tmp_path):
    import hmac
    path = tmp_path / "witness.json"
    store = Store(path, b"w" * 32)
    store.publish(_witness())
    value = json.loads(path.read_bytes())
    value["payload"].pop("create_claim_digest")
    value["payload"]["contract"] = "fortipam-secret-request-create-invocation-witness-v1"
    canonical = json.dumps(value["payload"], sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    value["hmac_sha256"] = hmac.new(b"w" * 32, canonical, hashlib.sha256).hexdigest()
    path.write_text(json.dumps(value))
    with pytest.raises(Error):
        store.load()
