from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import httpx
import pytest

from fortipam_mcp.secret_event_subscription_http_transport import (
    FortiPamSecretEventSubscriptionHttpTransport, SecretEventSubscriptionHttpTransportError,
    _record_spans,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_secret_event_subscription_contract import BINDING, OTHER, PAYLOAD, PORTAL


def fixture(tmp_path, case="success"):
    tmp_path.chmod(0o700)
    key = tmp_path / "key"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    state = deepcopy(PAYLOAD)
    state["results"].update({"field": [{"name": "Password", "value": "SYNTHETIC_MATERIAL_SENTINEL"}],
        "credentials-history": {"history0": "SYNTHETIC_MATERIAL_SENTINEL"}, "recording": "enable",
        "description": "synthetic-description", "totp-setting": {"key": "SYNTHETIC_MATERIAL_SENTINEL"}, "invitation": [],
        "dependency": [], "last-approval-script-result": ""})
    portal = dict(PORTAL)
    calls, posts = [], []
    response = {"version": "v7.0.0", "build": 29, "http_status": 200, "http_method": "POST",
                "status": "success", "path": "internal", "name": "subscribe", "results": {}}

    def handler(request):
        calls.append((request.method, request.url.path))
        assert request.url.host == "synthetic.invalid"
        assert request.headers["Authorization"] == "Bearer synthetic-token"
        if request.method == "GET" and request.url.path == "/api/v2/internal/user-portal":
            return httpx.Response(200, json={"results": portal})
        if request.method == "GET" and request.url.path == "/api/v2/cmdb/secret/database/7":
            if posts and case == "readback_denied":
                return httpx.Response(403, json={"error": "private upstream value"})
            return httpx.Response(200, json=state)
        if request.method == "POST" and request.url.path == "/api/v2/internal/subscribe":
            body = json.loads(request.content)
            assert body == {"secret-id": 7, "event": "cfg-chg" if not posts else ""}
            claim = tmp_path / ("subscribe.json" if body["event"] else "restore.json")
            assert claim.exists() and claim.stat().st_mode & 0o777 == 0o600
            posts.append(body)
            if case not in {"no_effect", "native_no_effect", "http_rejected"}:
                state["results"]["subscriber"] = [deepcopy(OTHER)] + (
                    [{"name": BINDING.owner_name, "event": "cfg-chg"}] if body["event"] else [])
            if case == "metadata_changed": state["results"]["recording"] = "disable"
            if case == "other_changed": state["results"]["subscriber"][0]["event"] = "cfg-chg"
            if case == "credential_changed": state["results"]["field"][0]["value"] += "changed"
            if case == "email_changed": portal["email"] = "synthetic@example.invalid"
            if case == "ambiguous": raise httpx.ReadTimeout("private ambiguous response")
            if case == "http_rejected": return httpx.Response(403, json={"status": "error", "message": "SYNTHETIC_MATERIAL_SENTINEL"})
            if case == "body_error": return httpx.Response(200, json={**response, "status": "error"})
            if case == "body_material": return httpx.Response(200, json={**response, "status": {"secret": "SYNTHETIC_MATERIAL_SENTINEL"}})
            if case == "response_unqualified": return httpx.Response(200, json={"results": {}})
            if case == "response_empty": return httpx.Response(200)
            if case.startswith("native_"):
                native = {"http_method":"POST", "http_status":200, "status":"success",
                          "msg":"SYNTHETIC_MATERIAL_SENTINEL"}
                if case == "native_error": native["status"] = "error"
                if case == "native_extra": native["unexpected"] = "SYNTHETIC_MATERIAL_SENTINEL"
                return httpx.Response(200, json=native)
            if case == "diagnostic_shape":
                return httpx.Response(200, json={"http_method":"POST", "http_status":200,
                    "status":"success", "msg":"SYNTHETIC_MATERIAL_SENTINEL",
                    "unknown-sensitive-name":"SYNTHETIC_MATERIAL_SENTINEL"})
            if case.startswith("minimal_"):
                minimal = {"http_method": "POST", "http_status": 200, "status": "success", "cli_error": ""}
                if case == "minimal_error": minimal["cli_error"] = "SYNTHETIC_MATERIAL_SENTINEL"
                if case == "minimal_extra": minimal["unexpected"] = "SYNTHETIC_MATERIAL_SENTINEL"
                if case == "minimal_missing": del minimal["cli_error"]
                if case == "minimal_wrong_status": minimal["status"] = "error"
                return httpx.Response(200, json=minimal)
            return httpx.Response(200, json=response)
        pytest.fail("Unexpected fixed-route request")

    def factory(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        return httpx.Client(**kwargs, transport=httpx.MockTransport(handler))

    config = SecretMetadataHttpTransportConfig("https://synthetic.invalid", "synthetic-token", 1, None)

    def transport(operation="subscribe", *, factory_override=None, gate=lambda: True, binding=BINDING, config_override=None,
                  expected_email=""):
        return FortiPamSecretEventSubscriptionHttpTransport(config_override or config, binding, operation=operation,
            claim_path=tmp_path / (operation + ".json"), hmac_key_file=key,
            subscribe_claim_path=tmp_path / "subscribe.json" if operation == "restore" else None,
            client_factory=factory_override or factory, execution_enabled=gate, sleep=lambda _: None,
            expected_email=expected_email)

    return transport, state, portal, calls, posts


def test_private_recipient_requires_exact_email_and_preserves_old_consumed_claims(tmp_path):
    import hashlib
    import hmac
    from dataclasses import asdict

    make, _, portal, _, posts = fixture(tmp_path)
    address = "notification-fixture@example.invalid"
    portal["email"] = address
    default = make()
    original_scope = {"binding": asdict(BINDING), "api_origin": "https://synthetic.invalid"}
    original_digest = hmac.new(b"k" * 32, b"subscription-700:binding:" + json.dumps(
        original_scope, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    assert default._binding_digest == original_digest
    with pytest.raises(SecretEventSubscriptionHttpTransportError): default.inspect()
    enable = make(expected_email=address)
    assert enable._binding_digest != original_digest
    preview = enable.inspect()
    portal["email"] = "unapproved@example.invalid"
    with pytest.raises(SecretEventSubscriptionHttpTransportError): enable.apply_and_readback(preview)
    assert not posts and not (tmp_path / "subscribe.json").exists()
    portal["email"] = address
    assert enable.apply_and_readback(enable.inspect()).verified
    claim = (tmp_path / "subscribe.json").read_bytes()
    assert address.encode() not in claim
    with pytest.raises(SecretEventSubscriptionHttpTransportError): default.inspect()
    with pytest.raises(SecretEventSubscriptionHttpTransportError):
        make("restore", expected_email="unapproved@example.invalid").inspect()
    assert (tmp_path / "subscribe.json").read_bytes() == claim and len(posts) == 1
    portal["email"] = "unapproved@example.invalid"
    restore = make("restore", expected_email=address)
    assert restore.apply_and_readback(restore.inspect()).verified
    assert len(posts) == 2 and (tmp_path / "subscribe.json").read_bytes() == claim


def test_recipient_drift_after_post_cannot_be_verified(tmp_path):
    make, _, portal, _, posts = fixture(tmp_path, "email_changed")
    address = "notification-fixture@example.invalid"
    portal["email"] = address
    enable = make(expected_email=address)
    result = enable.apply_and_readback(enable.inspect())
    assert not result.verified and not result.email_guard_preserved and len(posts) == 1
    assert enable.reconcile()["redispatch_permitted"] is False
    with pytest.raises(SecretEventSubscriptionHttpTransportError): enable.inspect()


@pytest.mark.parametrize("case", ["native_message", "native_error", "native_extra", "native_no_effect"])
def test_native_message_is_opaque_and_cannot_replace_independent_readback(tmp_path, case, monkeypatch):
    transport, _, _, _, posts = fixture(tmp_path, case)
    loads = json.loads

    def no_material_decode(value, *args, **kwargs):
        assert b"SYNTHETIC_MATERIAL_SENTINEL" not in (value.encode() if isinstance(value, str) else bytes(value))
        return loads(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", no_material_decode)
    enable = transport()
    result = enable.apply_and_readback(enable.inspect())
    assert result.response_qualified == (case in {"native_message", "native_no_effect"})
    assert result.verified == (case == "native_message") and len(posts) == 1
    assert result.subscription_matches == (case != "native_no_effect")
    assert "SYNTHETIC_MATERIAL_SENTINEL" not in (tmp_path / "subscribe.response.json").read_text()
    with pytest.raises(SecretEventSubscriptionHttpTransportError): enable.inspect()


def test_finite_reply_diagnostics_keep_unknown_names_values_and_success_out(tmp_path, monkeypatch):
    transport, _, _, _, posts = fixture(tmp_path, "diagnostic_shape")
    loads = json.loads

    def no_material_decode(value, *args, **kwargs):
        assert b"SYNTHETIC_MATERIAL_SENTINEL" not in (value.encode() if isinstance(value, str) else bytes(value))
        return loads(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", no_material_decode)
    enable = transport()
    result = enable.apply_and_readback(enable.inspect())
    assert not result.verified and len(posts) == 1
    path = tmp_path / "subscribe.response.json"
    record = loads(path.read_bytes())
    assert record["known_root_members"] == ["http_method", "http_status", "msg", "status"]
    assert record["diagnostic_field_shapes"] == {"msg":{"kind":"string", "empty_or_zero":False}}
    assert record["unknown_root_member_count"] == 1 and record["unknown_member_kinds"] == {"string":1}
    assert record["response_success_proven"] is False
    assert all(value not in path.read_text() for value in ("unknown-sensitive-name", "SYNTHETIC_MATERIAL_SENTINEL"))


@pytest.mark.parametrize("case", ["minimal_success", "minimal_error", "minimal_extra", "minimal_missing", "minimal_wrong_status"])
def test_unqualified_short_internal_replies_cannot_become_success_or_decode_values(tmp_path, case, monkeypatch):
    transport, _, _, _, posts = fixture(tmp_path, case)
    loads = json.loads

    def no_material_decode(value, *args, **kwargs):
        assert b"SYNTHETIC_MATERIAL_SENTINEL" not in (value.encode() if isinstance(value, str) else bytes(value))
        return loads(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", no_material_decode)
    enable = transport()
    result = enable.apply_and_readback(enable.inspect())
    assert result.verified is False and result.response_qualified is False and len(posts) == 1
    shape = loads((tmp_path / "subscribe.response.json").read_bytes())
    assert shape["response_body_complete"] and shape["response_success_proven"] is False
    assert "SYNTHETIC_MATERIAL_SENTINEL" not in (tmp_path / "subscribe.response.json").read_text()
    if case != "minimal_missing":
        assert shape["fixed_constant_matches"]["cli_error"] == (case != "minimal_error")
    with pytest.raises(SecretEventSubscriptionHttpTransportError): enable.apply_and_readback(enable.inspect())
    assert len(posts) == 1


@pytest.mark.parametrize("case", ["success", "ambiguous", "no_effect", "metadata_changed", "other_changed",
    "credential_changed", "email_changed", "body_error", "response_unqualified", "response_empty", "readback_denied", "body_material", "http_rejected"])
def test_claim_precedes_one_post_and_ambiguous_outcomes_never_replay(tmp_path, case, monkeypatch):
    transport, _, _, calls, posts = fixture(tmp_path, case)
    loads = json.loads

    def no_material_decode(value, *args, **kwargs):
        assert b"SYNTHETIC_MATERIAL_SENTINEL" not in (value.encode() if isinstance(value, str) else bytes(value))
        return loads(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", no_material_decode)
    enable = transport()
    expected = enable.inspect()
    result = enable.apply_and_readback(expected)
    assert result.dispatch_consumed and len(posts) == 1
    assert result.verified == (case == "success")
    assert result.subscription_matches == (case not in {"no_effect", "other_changed", "readback_denied", "http_rejected"})
    assert result.other_metadata_preserved == (case not in {"metadata_changed", "readback_denied"})
    assert result.returned_credential_bytes_preserved == (case not in {"credential_changed", "readback_denied"})
    assert result.email_guard_preserved == (case not in {"email_changed", "readback_denied"})
    size = len(calls)
    restarted = transport(factory_override=lambda **kw: pytest.fail("Replay opened a network client"))
    with pytest.raises(SecretEventSubscriptionHttpTransportError): restarted.apply_and_readback(expected)
    with pytest.raises(SecretEventSubscriptionHttpTransportError): restarted.inspect()
    assert len(calls) == size and len(posts) == 1
    claim = (tmp_path / "subscribe.json").read_text()
    evidence_path = tmp_path / "subscribe.response.json"
    assert evidence_path.stat().st_mode & 0o777 == 0o600
    evidence = loads(evidence_path.read_bytes())
    assert evidence["raw_values_retained"] is False and evidence["response_success_proven"] is False
    assert evidence["response_body_complete"] == (case != "ambiguous")
    if case not in {"ambiguous", "response_empty"}:
        assert evidence["body_class"] == "object"
    if case == "body_material": assert evidence["fixed_constant_matches"]["status"] is False
    if case == "http_rejected":
        assert evidence["http_status"] == 403 and evidence["known_root_members"] == ["message", "status"]
        assert result.http_accepted is False and result.response_class == "http_rejected"
    for value in (BINDING.owner_name, BINDING.secret_name, "synthetic-token", "SYNTHETIC_MATERIAL_SENTINEL"):
        assert value not in claim
        assert value not in evidence_path.read_text()
    if case != "readback_denied":
        readback = enable.reconcile()
        assert readback["dispatch_remains_consumed"] and readback["redispatch_permitted"] is False
        assert readback["credential_values_returned"] is False


@pytest.mark.parametrize("drift", ["metadata", "other_subscriber", "owner", "email", "material_table", "unknown_field"])
def test_fresh_drift_invalidates_before_reservation_or_post(tmp_path, drift):
    transport, state, portal, _, posts = fixture(tmp_path)
    enable = transport()
    expected = enable.inspect()
    if drift == "metadata": state["results"]["recording"] = "disable"
    if drift == "other_subscriber": state["results"]["subscriber"][0]["event"] = "cfg-chg"
    if drift == "owner": portal["name"] = "synthetic-other-owner"
    if drift == "email": portal["email"] = "synthetic@example.invalid"
    if drift == "material_table": state["results"]["invitation"] = [{"secret": "SYNTHETIC_MATERIAL_SENTINEL"}]
    if drift == "unknown_field": state["results"]["unknown-secret"] = "SYNTHETIC_MATERIAL_SENTINEL"
    with pytest.raises(SecretEventSubscriptionHttpTransportError): enable.apply_and_readback(expected)
    assert not posts and not (tmp_path / "subscribe.json").exists()


def test_restore_requires_authenticated_enable_claim_and_exact_original_scope(tmp_path):
    transport, state, portal, _, posts = fixture(tmp_path)
    restore = transport("restore")
    with pytest.raises(SecretEventSubscriptionHttpTransportError): restore.inspect()
    enable = transport()
    assert enable.apply_and_readback(enable.inspect()).verified
    portal["email"] = "synthetic@example.invalid"
    expected = restore.inspect()
    state["results"]["description"] = "changed"
    with pytest.raises(SecretEventSubscriptionHttpTransportError): restore.apply_and_readback(expected)
    assert not (tmp_path / "restore.json").exists() and len(posts) == 1
    state["results"]["description"] = "synthetic-description"
    result = restore.apply_and_readback(restore.inspect())
    assert result.verified and len(posts) == 2 and state["results"]["subscriber"] == [OTHER]
    count = len(posts)
    with pytest.raises(SecretEventSubscriptionHttpTransportError): transport("restore").apply_and_readback(expected)
    assert len(posts) == count


def test_closed_gate_and_tampered_recovery_claim_refuse_without_post(tmp_path):
    transport, _, _, calls, posts = fixture(tmp_path)
    enable = transport()
    expected = enable.inspect()
    count = len(calls)
    with pytest.raises(SecretEventSubscriptionHttpTransportError): transport(gate=lambda: False).apply_and_readback(expected)
    assert len(calls) == count and not posts
    assert enable.apply_and_readback(expected).verified
    path = tmp_path / "subscribe.json"
    original = path.read_bytes()
    record = json.loads(original)
    record["metadata_digest"] = "a" * 64
    path.write_text(json.dumps(record))
    with pytest.raises(SecretEventSubscriptionHttpTransportError): transport("restore").inspect()
    path.write_bytes(original)
    path.chmod(0o644)
    with pytest.raises(SecretEventSubscriptionHttpTransportError): transport("restore").inspect()
    assert len(posts) == 1


def test_same_nonselected_duplicate_is_witnessed_but_conflicts_and_selected_duplicates_refuse(tmp_path):
    raw = bytearray(json.dumps({**PAYLOAD, "results": {**PAYLOAD["results"], "description": "same"}}).encode())
    same = raw.replace(b'"description": "same"', b'"description": "same", "description": "same"')
    assert "description" in _record_spans(same)
    conflict = raw.replace(b'"description": "same"', b'"description": "same", "description": "different"')
    with pytest.raises(ValueError): _record_spans(conflict)


def test_fsync_failure_retains_claim_and_prevents_later_dispatch(tmp_path, monkeypatch):
    import fortipam_mcp.secret_event_subscription_http_transport as module
    transport, _, _, _, posts = fixture(tmp_path)
    enable = transport()
    expected = enable.inspect()
    monkeypatch.setattr(module.os, "fsync", lambda fd: (_ for _ in ()).throw(OSError("synthetic failure")))
    with pytest.raises(SecretEventSubscriptionHttpTransportError): enable.apply_and_readback(expected)
    assert (tmp_path / "subscribe.json").exists() and not posts
    with pytest.raises(SecretEventSubscriptionHttpTransportError): transport().apply_and_readback(expected)


def test_recovery_claim_cannot_be_rebound_to_another_api_origin(tmp_path):
    make, _, _, _, posts = fixture(tmp_path)
    enable = make()
    assert enable.apply_and_readback(enable.inspect()).verified
    changed = replace(enable._config, base_url="https://other-synthetic.invalid")
    restore = make("restore", config_override=changed)
    with pytest.raises(ValueError): restore._read_claim(tmp_path / "subscribe.json", "subscribe")
    assert len(posts) == 1 and not (tmp_path / "restore.json").exists()
