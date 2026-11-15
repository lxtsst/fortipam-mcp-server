"""Synthetic-only login acceptance, one-attempt protection and pointer promotion."""

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import ssl
from types import SimpleNamespace
from urllib.parse import parse_qs

import httpx
import pytest

from fortipam_mcp.local_user_reset_http_transport import LocalUserResetBinding, _dispose_password
from fortipam_mcp.local_user_reset_login_acceptance import finalize_verified_reset_login
import fortipam_mcp.local_user_reset_login_acceptance as acceptance_module
from fortipam_mcp.local_user_reset_material_source import (
    OwnerOnlyLocalUserResetMaterialSource, _read_current_login_selection, stage_next_password_once,
)
from fortipam_mcp.local_user_reset_fixture_preflight import _ACTOR
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import SYSTEM_STATUS_PATH, SecretMetadataHttpTransportConfig
from v4_planning import M4AuditEvent, M4Compensation, M4ExecutionResult, M4Outcome, M4Verification, canonical_digest

from test_local_user_reset_material_source import _source, _record_current_login
from test_local_user_reset_metadata_reader import _monitor


def _write(path, value):
    path.write_bytes(json.dumps(value, sort_keys=True).encode())
    path.chmod(0o600)


@pytest.fixture
def harness(tmp_path, monkeypatch):
    prior, _, _ = _source(tmp_path)
    _record_current_login(tmp_path, prior)
    binding = LocalUserResetBinding(replace(prior._binding.expected, status="enable"))
    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "never-send-api-token", 5, None)
    inspector = SimpleNamespace(_config=config, read_nonmaterial_baseline=lambda: binding.expected,
        verify_initial_material_view=lambda *args, **kwargs: True)
    reset = tmp_path / "reset-login"
    reset.mkdir(mode=0o700)
    digest = stage_next_password_once(reset, fixture_directory=tmp_path / "fixture", binding=binding, enabled=True)
    source = OwnerOnlyLocalUserResetMaterialSource.from_current_login_binding(fixture_directory=tmp_path / "fixture",
        reset_directory=reset, binding=binding, inspector=inspector, expected_binding_digest=digest, enabled=True)
    acceptance_source = OwnerOnlyLocalUserResetMaterialSource.from_current_login_binding(
        fixture_directory=tmp_path / "fixture", reset_directory=reset, binding=binding,
        inspector=inspector, expected_binding_digest=digest, enabled=False)
    source._reserve_transition_once()
    old, new = source()._consume()
    _dispose_password(old)
    _dispose_password(new)
    source = acceptance_source
    key = reset / "execution.key"
    key.write_bytes(b"synthetic-acceptance-execution-key-0001")
    key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(reset / "execution.sqlite3", key)
    claim = dict(plan_ref="bp002-local-user-reset-synthetic", requester_digest="1" * 64,
        idempotency_digest="2" * 64, context_digest="3" * 64)
    store.claim(**claim, authorization_digest="4" * 64)
    execution = M4ExecutionResult(M4Outcome.SUCCEEDED, M4Verification.VERIFIED, M4Compensation.NOT_REQUESTED, False)
    store.finalize(**claim, result=execution, event=M4AuditEvent(0, "verified", execution.outcome,
        execution.verification, execution.compensation, canonical_digest({"context": claim["context_digest"],
                                                                        "result": execution.as_dict()})))
    _write(reset / "dispatch-invocation", dict(contract=acceptance_module._CONTRACT,
        plan_ref=claim["plan_ref"], context_digest=claim["context_digest"]))
    _write(reset / "result.json", execution.as_dict())
    state = SimpleNamespace(source=source, store=store, config=config, calls=[], clients=[], active=False,
        now=1000, failure="", pointer=(source._fixture / "current-login-binding.json").read_bytes(),
        pending=(source._fixture / "current-login-transition.json").read_bytes(), after_identity=None, waits=[])
    monkeypatch.setattr(acceptance_module, "sleep", state.waits.append)

    class FailingStream(httpx.SyncByteStream):
        def __iter__(self):
            if state.failure.startswith("body_"):
                raise httpx.ReadError("synthetic-private-body-detail")
            yield b""

        def close(self):
            if state.failure == "close_landing":
                raise httpx.ReadError("synthetic-private-close-detail")

    def respond(request):
        assert "authorization" not in request.headers
        assert request.url.host == "pam.example.test" and request.url.scheme == "https"
        path = request.url.path
        state.calls.append((request.method, path))
        if path == "/remote/login":
            return httpx.Response(200, text="bad form" if state.failure == "form" else
                                  '<form action="/XX/YY/ZZ/AUTH" method="post">')
        if path == "/XX/YY/ZZ/AUTH":
            fields = parse_qs(request.content.decode())
            assert fields["username"] == [source._binding.expected.username]
            assert fields["password"] == [(source._reset / "next-password").read_text()]
            state.active = True
            if state.failure == "post_exception":
                raise RuntimeError("synthetic-private-exception")
            if state.failure == "body_post":
                return httpx.Response(303, headers={"location": "/"}, stream=FailingStream())
            return httpx.Response(200 if state.failure == "login" else 303,
                headers={"location": "https://untrusted.example/" if state.failure == "redirect" else "/",
                         "set-cookie": "session=synthetic; Secure; HttpOnly; Path=/"})
        if path == "/":
            if state.failure in {"body_landing", "close_landing"}:
                return httpx.Response(200, stream=FailingStream())
            return httpx.Response(200)
        if path == SYSTEM_STATUS_PATH:
            if state.active and state.failure == "body_status":
                return httpx.Response(200, headers={"content-type": "application/json"}, stream=FailingStream())
            return httpx.Response(200 if state.active and state.failure != "status" else 403,
                                  json={"version": "v7.0.0", "build": 29})
        if path == _ACTOR:
            name = "different-synthetic-user" if state.failure == "identity" else source._binding.expected.username
            body = _monitor("web-ui/state", {"admin": {"name": name, "login_name": name,
                "sponsored_group_name": "", "guest_admin": False}})
            if state.after_identity is not None:
                state.after_identity()
            return httpx.Response(200, content=bytes(body), headers={"content-type": "application/json"})
        if path == "/logout":
            if state.failure == "logout_exception" or state.failure.startswith("body_") or state.failure == "close_landing":
                raise RuntimeError("synthetic-private-logout-exception")
            state.active = state.failure == "logout"
            return httpx.Response(200)
        raise AssertionError("Unexpected route")

    def client(**kwargs):
        assert kwargs["verify"].verify_mode == ssl.CERT_REQUIRED and kwargs["verify"].check_hostname
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        value = httpx.Client(**kwargs, transport=httpx.MockTransport(respond))
        state.clients.append(value)
        return value

    state.client = client
    state.run = lambda **kwargs: finalize_verified_reset_login(source, store, config, client_factory=client,
        clock=lambda: state.now, **kwargs)
    return state


def test_success_promotes_only_verified_material_and_cannot_login_twice(harness):
    h = harness
    assert not h.source._enabled and not h.source._consumed
    execution = (h.source._reset / "result.json").read_bytes()
    audit = h.store.audit_events
    result = h.run(enabled=True)
    assert result == {"outcome": "succeeded", "reason": "verified", "login_post_attempted": True,
        "login_verified": True, "logout_verified": True, "current_binding_updated": True,
        "login_diagnostic": {"phase": "verified", "exception_category": "none", "http_status": {
            "login_page": 200, "login_post": 303, "landing": 200, "status": 200, "identity": 200}},
        "logout_diagnostic": {"phase": "verified", "exception_category": "none", "http_status": {
            "logout": 200, "logout_status": 403}}}
    assert h.calls == [("GET", "/remote/login"), ("POST", "/XX/YY/ZZ/AUTH"), ("GET", "/"),
        ("GET", SYSTEM_STATUS_PATH), ("GET", _ACTOR), ("GET", "/logout"), ("GET", SYSTEM_STATUS_PATH)]
    assert h.clients[0].is_closed and not h.clients[0].cookies
    assert not (h.source._fixture / "current-login-transition.json").exists()
    current, manifest, _ = _read_current_login_selection(h.source._fixture, h.source._binding)
    assert current == h.source._reset and manifest == h.source._staged_binding_digest
    acceptance = json.loads((h.source._reset / "acceptance.json").read_bytes())
    assert acceptance["execution_result_sha256"] == hashlib.sha256(execution).hexdigest()
    assert acceptance["logout_verified"] is True
    assert (h.source._reset / "result.json").read_bytes() == execution and h.store.audit_events == audit
    assert h.run(enabled=True)["outcome"] == "reconciliation_required"
    assert h.calls.count(("POST", "/XX/YY/ZZ/AUTH")) == 1
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in (
        h.source._reset / "acceptance.json", h.source._reset / "login-invocation",
        h.source._fixture / "current-login-binding.json"))
    assert not list(h.source._fixture.glob(".current-login-binding-*.json"))


def test_settle_wait_is_reserved_once_before_authentication(harness, monkeypatch):
    h = harness

    def wait(seconds):
        assert seconds == 2.0
        assert (h.source._reset / "login-invocation").exists()
        assert not h.calls
        h.waits.append(seconds)

    monkeypatch.setattr(acceptance_module, "sleep", wait)
    assert h.run(enabled=True)["outcome"] == "succeeded"
    assert h.run(enabled=True)["outcome"] == "reconciliation_required"
    assert h.waits == [2.0]
    assert h.calls.count(("POST", "/XX/YY/ZZ/AUTH")) == 1


def test_readonly_reconciliation_promotes_without_replaying_consumed_finalizer(harness):
    h = harness
    h.failure = "login"
    failed = h.run(enabled=True)
    assert failed["reason"] == "login_failed" and not failed["current_binding_updated"]
    invocation = (h.source._reset / "login-invocation").read_bytes()
    execution = (h.source._reset / "result.json").read_bytes()
    audit = h.store.audit_events
    recovered = OwnerOnlyLocalUserResetMaterialSource.from_pending_login_binding(
        fixture_directory=h.source._fixture, reset_directory=h.source._reset,
        binding=h.source._binding, inspector=h.source._inspector,
        expected_binding_digest=h.source._staged_binding_digest)
    denied = finalize_verified_reset_login(recovered, h.store, h.config, enabled=True,
        client_factory=h.client, clock=lambda: h.now)
    assert denied["reason"] == "already_attempted"
    assert h.calls.count(("POST", "/XX/YY/ZZ/AUTH")) == 1
    # A separately qualified reconciliation can authenticate the same material;
    # the consumed finalizer and original execution record remain immutable.
    h.failure = ""
    result = {"login_post_attempted": False, "login_verified": False,
              "logout_verified": False, "current_binding_updated": False}
    material, length = acceptance_module._new_material(recovered)
    try:
        acceptance_module._login(recovered, h.config, material, length, h.client, result)
    finally:
        material[:] = bytes(len(material))
    assert result["login_verified"] and result["logout_verified"]
    digest = acceptance_module._evidence(recovered, h.store)
    acceptance_module._promote(recovered, h.store, digest, h.now, result)
    assert result["current_binding_updated"]
    assert (h.source._reset / "login-invocation").read_bytes() == invocation
    assert (h.source._reset / "result.json").read_bytes() == execution
    assert h.store.audit_events == audit and h.store.claim_count == 1
    assert not (h.source._fixture / "current-login-transition.json").exists()


@pytest.mark.parametrize("legacy", [False, True])
def test_complete_mcp_response_uses_only_m4_fields_for_ledger_evidence(harness, legacy):
    h = harness
    path = h.source._reset / "result.json"
    m4_result = json.loads(path.read_bytes())
    document = {**m4_result, "contract": acceptance_module._CONTRACT, "password_change_confirmed": legacy,
        "current_login_reconciliation_required": True, "login_verified": False,
        "credential_values_returned": False, "raw_cli_returned": False}
    if not legacy:
        document["password_write_acknowledged"] = True
    _write(path, document)
    original_bytes = path.read_bytes()
    assert h.run(enabled=True)["outcome"] == "succeeded"
    acceptance = json.loads((h.source._reset / "acceptance.json").read_bytes())
    assert acceptance["execution_result_sha256"] == hashlib.sha256(original_bytes).hexdigest()
    assert path.read_bytes() == original_bytes


@pytest.mark.parametrize("invalid", ["partial_legacy", "partial_current", "confirmed_current", "ack_false",
                                    "ack_integer", "verified_login", "extra_field", "missing_m4"])
def test_incomplete_or_conflicting_mcp_envelope_rejects_before_login(harness, invalid):
    h = harness
    path = h.source._reset / "result.json"
    document = {**json.loads(path.read_bytes()), "contract": acceptance_module._CONTRACT,
        "password_change_confirmed": False, "password_write_acknowledged": True,
        "current_login_reconciliation_required": True, "login_verified": False,
        "credential_values_returned": False, "raw_cli_returned": False}
    if invalid == "partial_legacy":
        document.pop("password_write_acknowledged")
        document["password_change_confirmed"] = True
        document.pop("raw_cli_returned")
    elif invalid == "partial_current":
        document.pop("raw_cli_returned")
    elif invalid == "confirmed_current":
        document["password_change_confirmed"] = True
    elif invalid == "ack_false":
        document["password_write_acknowledged"] = False
    elif invalid == "ack_integer":
        document["password_write_acknowledged"] = 1
    elif invalid == "verified_login":
        document["login_verified"] = True
    elif invalid == "extra_field":
        document["unknown_claim"] = True
    else:
        document.pop("verification")
    _write(path, document)
    original_bytes = path.read_bytes()
    result = h.run(enabled=True)
    assert result["reason"] == "precondition_failed" and not result["login_post_attempted"]
    assert not h.calls and not (h.source._reset / "login-invocation").exists()
    assert path.read_bytes() == original_bytes
    assert (h.source._fixture / "current-login-binding.json").read_bytes() == h.pointer
    assert (h.source._fixture / "current-login-transition.json").read_bytes() == h.pending


def test_concurrent_finalizers_can_post_only_one_login(harness):
    h = harness
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: h.run(enabled=True), range(2)))
    assert sum(result["outcome"] == "succeeded" for result in results) == 1
    assert h.calls.count(("POST", "/XX/YY/ZZ/AUTH")) == 1


def test_disabled_finalizer_has_no_effect(harness):
    h = harness
    assert h.run()["reason"] == "gate_closed"
    assert h.calls == [] and not (h.source._reset / "login-invocation").exists()
    assert (h.source._fixture / "current-login-transition.json").read_bytes() == h.pending


@pytest.mark.parametrize("failure", ["missing_result", "nested_result", "false_success", "plan", "context",
                                    "pending", "pointer", "manifest", "material", "second_claim", "symlink"])
def test_invalid_evidence_rejects_before_login(harness, failure):
    h = harness
    reset = h.source._reset
    if failure == "missing_result":
        (reset / "result.json").unlink()
    elif failure in {"nested_result", "false_success"}:
        value = json.loads((reset / "result.json").read_bytes())
        _write(reset / "result.json", {"m4": value} if failure == "nested_result" else {**value, "verification": "unknown"})
    elif failure in {"plan", "context"}:
        value = json.loads((reset / "dispatch-invocation").read_bytes())
        value["plan_ref" if failure == "plan" else "context_digest"] = "bp002-different-synthetic-plan" if failure == "plan" else "a" * 64
        _write(reset / "dispatch-invocation", value)
    elif failure == "pending":
        value = json.loads(h.pending)
        _write(h.source._fixture / "current-login-transition.json", {**value, "material_pair_digest": "a" * 64})
    elif failure == "pointer":
        value = json.loads(h.pointer)
        _write(h.source._fixture / "current-login-binding.json", {**value, "verified_at": 101})
    elif failure == "manifest":
        _write(reset / "material-binding.json", {})
    elif failure == "material":
        (reset / "next-password").write_bytes(b"synthetic-tampered-material")
    elif failure == "second_claim":
        h.store.claim(plan_ref="bp002-other-claim", requester_digest="5" * 64, idempotency_digest="6" * 64,
                      context_digest="7" * 64, authorization_digest="8" * 64)
    else:
        (reset / "result.json").rename(reset / "held-result.json")
        (reset / "result.json").symlink_to(reset / "held-result.json")
    result = h.run(enabled=True)
    assert result["reason"] == "precondition_failed" and not result["login_post_attempted"]
    assert not h.calls and not (reset / "login-invocation").exists()
    assert (h.source._fixture / "current-login-transition.json").exists()


@pytest.mark.parametrize("failure, reason", [("form", "login_failed"), ("login", "login_failed"),
    ("redirect", "login_failed"), ("status", "login_failed"), ("identity", "identity_failed"),
    ("post_exception", "login_failed"), ("logout", "logout_failed"), ("logout_exception", "logout_failed")])
def test_failed_login_or_cleanup_preserves_pointer_pending_and_attempt(harness, failure, reason):
    h = harness
    h.failure = failure
    result = h.run(enabled=True)
    assert result["outcome"] == "reconciliation_required" and result["reason"] == reason
    assert not result["current_binding_updated"]
    assert "synthetic-private" not in json.dumps(result)
    assert (h.source._fixture / "current-login-binding.json").read_bytes() == h.pointer
    assert (h.source._fixture / "current-login-transition.json").read_bytes() == h.pending
    assert not (h.source._reset / "acceptance.json").exists()
    assert h.clients[0].is_closed and not h.clients[0].cookies
    calls = len(h.calls)
    assert h.run(enabled=True)["reason"] == "already_attempted" and len(h.calls) == calls


@pytest.mark.parametrize("failure, phase, status", [("body_post", "login_post", 303),
    ("body_landing", "landing", 200), ("body_status", "status", 200), ("close_landing", "landing", 200)])
def test_received_status_and_primary_phase_survive_body_close_and_logout_failure(harness, failure, phase, status):
    h = harness
    h.failure = failure
    result = h.run(enabled=True)
    diagnostic = result["login_diagnostic"]
    assert diagnostic["phase"] == phase and diagnostic["http_status"][phase] == status
    assert diagnostic["exception_category"] == "transport"
    assert result["logout_diagnostic"] == {"phase": "logout", "http_status": {"logout": "not_received"},
                                           "exception_category": "unexpected"}
    assert result["reason"] == "login_failed" and result["outcome"] == "reconciliation_required"
    assert not result["login_verified"] and not result["logout_verified"] and not result["current_binding_updated"]
    assert (h.source._fixture / "current-login-binding.json").read_bytes() == h.pointer
    assert (h.source._fixture / "current-login-transition.json").read_bytes() == h.pending
    serialized = json.dumps(result)
    assert all(value not in serialized for value in (
        "synthetic-private", "pam.example.test", h.source._binding.expected.username,
        (h.source._reset / "next-password").read_text(), "/XX/YY/ZZ/AUTH"))


@pytest.mark.parametrize("drift", ["pointer", "pending", "result", "material"])
def test_postlogin_drift_cannot_promote(harness, drift):
    h = harness

    def change():
        if drift == "pointer":
            value = json.loads(h.pointer)
            _write(h.source._fixture / "current-login-binding.json", {**value, "verified_at": 101})
        elif drift == "pending":
            value = json.loads(h.pending)
            _write(h.source._fixture / "current-login-transition.json", {**value, "version": 2})
        elif drift == "result":
            _write(h.source._reset / "result.json", {"outcome": "reconciliation_required"})
        else:
            (h.source._reset / "next-password").write_bytes(b"synthetic-changed-material")

    h.after_identity = change
    result = h.run(enabled=True)
    assert result["reason"] == "persistence_failed" and result["login_verified"] and result["logout_verified"]
    assert not result["current_binding_updated"]
    assert (h.source._fixture / "current-login-transition.json").exists()
    assert not (h.source._reset / "acceptance.json").exists()


def test_atomic_replace_failure_preserves_pending_and_old_pointer(harness, monkeypatch):
    h = harness

    def fail(*args, **kwargs):
        raise OSError("synthetic-private-filesystem-detail")

    monkeypatch.setattr(acceptance_module.os, "replace", fail)
    result = h.run(enabled=True)
    assert result["reason"] == "persistence_failed" and not result["current_binding_updated"]
    assert (h.source._fixture / "current-login-binding.json").read_bytes() == h.pointer
    assert (h.source._fixture / "current-login-transition.json").read_bytes() == h.pending
    assert not list(h.source._fixture.glob(".current-login-binding-*.json"))
    assert "synthetic-private" not in json.dumps(result)


@pytest.mark.parametrize("stage", ["before_replace", "after_replace"])
@pytest.mark.parametrize("drift", ["material", "result"])
def test_late_drift_keeps_pending_until_promoted_material_is_verified(harness, monkeypatch, stage, drift):
    h = harness
    original_write = acceptance_module._write_once
    original_replace = acceptance_module.os.replace

    def change():
        if drift == "material":
            (h.source._reset / "next-password").write_bytes(b"synthetic-late-material-drift")
        else:
            _write(h.source._reset / "result.json", {"outcome": "reconciliation_required"})

    def write(directory, identity, name, content):
        original_write(directory, identity, name, content)
        if stage == "before_replace" and name.startswith(".current-login-binding-"):
            change()

    def replace(*args, **kwargs):
        original_replace(*args, **kwargs)
        if stage == "after_replace":
            change()

    monkeypatch.setattr(acceptance_module, "_write_once", write)
    monkeypatch.setattr(acceptance_module.os, "replace", replace)
    result = h.run(enabled=True)
    assert result["outcome"] == "reconciliation_required" and result["reason"] == "persistence_failed"
    assert result["login_verified"] and result["logout_verified"]
    assert result["current_binding_updated"] is (stage == "after_replace")
    assert (h.source._fixture / "current-login-transition.json").read_bytes() == h.pending
    if stage == "before_replace":
        assert (h.source._fixture / "current-login-binding.json").read_bytes() == h.pointer
    assert h.calls.count(("POST", "/XX/YY/ZZ/AUTH")) == 1
    assert not list(h.source._fixture.glob(".current-login-binding-*.json"))
