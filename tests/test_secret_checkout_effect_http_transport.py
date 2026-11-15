from contextlib import contextmanager
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from fortipam_mcp.secret_checkout_association_http_transport import SecretCheckoutBinding
from fortipam_mcp.secret_checkout_effect_http_transport import SecretCheckoutEffectHttpTransport
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_secret_checkout_effect_contract import ROW, payload


@pytest.mark.parametrize("mode", [
    "checkout", "checkin", "closed", "baseline_drift", "companion_drift",
    "other_metadata_change", "other_permission_change", "companion_change",
    "timeout_after_effect", "no_effect", "missing_csrf", "logout_failure", "wrong_lease_time", "qualified_checkout", "qualified_checkin",
])
def test_fixed_single_dispatch_requires_exact_response_and_preservation(tmp_path, mode):
    tmp_path.chmod(0o700)
    claim = tmp_path / "effect.json"
    subject_name = "mcp-v4-bp008-checkout-20261001-r10"
    companion_name = "mcp-v4-bp008-checkout-20261001-r6"
    row = {**deepcopy(ROW), "name": subject_name, "force-checkout-idle-time": 0,
           "description": "preserve", "ssh-service-status": "up",
           "field": [{"name": "Password", "value": "synthetic-private-value"}]}
    if mode in {"checkin", "qualified_checkin"}:
        row["permissions"] = {"checkout_status": "not-renewable", "passwd_change": "allowed"}
        row.update({"checkout-user": "synthetic-owner", "checkout-admin": "synthetic-owner", "checkout-time": 1000})
    companion = {**deepcopy(row), "id": 41, "name": companion_name,
                 "associated-secret": 0, "checkout": "disable",
                 "permissions": {"checkout_status": "none", "passwd_change": "allowed"}}
    calls = []

    class Client:
        cookies = {} if mode == "missing_csrf" else {"ccsrftoken": '"synthetic-csrf"'}

        @contextmanager
        def stream(self, method, path, **kwargs):
            calls.append(method)
            if method == "POST":
                assert claim.exists()
                assert json.loads(claim.read_text())["replay_permitted"] is False
                assert kwargs["json"] == {"secret-id": 17}
                assert kwargs["headers"]["X-CSRFTOKEN"] == "synthetic-csrf"
                assert path == "/api/v2/internal/secret-" + ("checkin" if mode in {"checkin", "qualified_checkin"} else "checkout")
                if mode != "no_effect":
                    row["permissions"] = {"checkout_status": "required" if mode in {"checkin", "qualified_checkin"} else "not-renewable",
                                          "passwd_change": "forbidden" if mode in {"checkin", "qualified_checkin"} else "allowed"}
                    row.update({"checkout-user": "" if mode in {"checkin", "qualified_checkin"} else "synthetic-owner",
                                "checkout-admin": "" if mode in {"checkin", "qualified_checkin"} else "synthetic-owner",
                                "checkout-time": 0 if mode in {"checkin", "qualified_checkin"} else 1000})
                if mode == "wrong_lease_time": row["checkout-time"] = 500
                if mode == "other_metadata_change": row["description"] = "changed"
                if mode == "other_permission_change": row["permissions"]["edit"] = False
                if mode == "companion_change": companion["description"] = "changed"
                if mode == "timeout_after_effect": raise TimeoutError("synthetic-private-error")
                if mode.startswith("qualified_"):
                    yield SimpleNamespace(status_code=200, headers={"content-type": "application/json"},
                        iter_bytes=lambda: iter([b'{"http_status":200,"http_method":"POST","status":"OK",'
                                                  b'"msg":"synthetic-private-error","secret-id":17}']))
                    return
                yield SimpleNamespace(status_code=200, headers={"content-type": "application/json"},
                    iter_bytes=lambda: iter([b'{"msg":"synthetic-private-error","script_status":"failed",'
                                              b'"field":[{"value":"synthetic-private-value"}]}']))
                return
            assert method == "GET"
            selected = companion if path.endswith("/41") else row
            yield SimpleNamespace(status_code=200, headers={"content-type": "application/json"},
                                  iter_bytes=lambda: iter([json.dumps(payload(deepcopy(selected))).encode()]))

    class Owner:
        def __init__(self): self._client = Client(); self.logout_verified = False

        @contextmanager
        def authenticated(self):
            calls.append("login")
            try: yield self
            finally: self.logout_verified = mode != "logout_failure"

        def resolve_folder_id(self, path): return 9

        def _lookup_id(self, kind, path): return 41 if path.endswith("/" + companion_name) else 17

    binding = SecretCheckoutBinding(owner_name="synthetic-owner", folder_path="synthetic-folder",
        secret_name=subject_name, target_name="synthetic-target", template_name="Unix Account (SSH Password)",
        execution_secret_name=companion_name, checkout_script="", checkin_script="",
        baseline_controls=(), force_checkout_idle_time=0)
    config = SecretMetadataHttpTransportConfig("https://example.test", "synthetic-token", 15, None)

    def factory(enabled=True):
        return SecretCheckoutEffectHttpTransport(config, binding,
            lambda: pytest.fail("Injected Owner must not load account material"),
            operation="checkin" if mode in {"checkin", "qualified_checkin"} else "checkout", claim_path=claim,
            execution_enabled=enabled, owner_factory=Owner, wall_clock=lambda:1000)

    transport = factory()
    if mode == "logout_failure":
        with pytest.raises(RuntimeError): transport.inspect()
        assert not claim.exists()
        return
    expected = transport.inspect()
    if mode == "closed":
        before = list(calls)
        with pytest.raises(RuntimeError): factory(False).execute_and_readback(expected)
        assert calls == before and not claim.exists()
        return
    if mode == "baseline_drift": row["description"] = "changed before dispatch"
    if mode == "companion_drift": companion["description"] = "changed before dispatch"
    if mode in {"baseline_drift", "companion_drift", "missing_csrf", "timeout_after_effect", "no_effect"}:
        with pytest.raises(RuntimeError) as error: transport.execute_and_readback(expected)
        assert "synthetic-private" not in str(error.value)
        assert claim.exists() == (mode in {"timeout_after_effect", "no_effect"})
    else:
        result = transport.execute_and_readback(expected)
        assert result.dispatch_consumed and result.http_ok_observed
        assert result.same_owner_state_matches == (mode != "wrong_lease_time")
        assert result.other_metadata_preserved == (mode not in {"other_metadata_change", "other_permission_change"})
        assert result.execution_account_preserved == (mode != "companion_change")
        assert result.owner_logout_verified
        assert result.native_response_qualified == mode.startswith("qualified_")
        assert result.verified == mode.startswith("qualified_")
    if claim.exists():
        before = list(calls)
        # New instances also refuse consumed attempts before Owner construction/login.
        with pytest.raises(RuntimeError): factory().inspect()
        with pytest.raises(RuntimeError): factory().execute_and_readback(expected)
        assert calls == before and calls.count("POST") == 1
        evidence = "".join(p.read_text() for p in tmp_path.iterdir())
        for value in (subject_name, companion_name, "synthetic-private-value", "synthetic-csrf", "synthetic-private-error"):
            assert value not in evidence


def test_native_response_projection_skips_material_and_records_only_categories():
    from fortipam_mcp.secret_checkout_effect_http_transport import _project_native_response_diagnostics
    raw = bytearray(b'{"version":"v7.0.0","build":29,"http_status":200,"http_method":"POST",'
                    b'"status":"success","script_status":"failed","msg":"private text",'
                    b'"field":[{"value":"private material"}],"results":{"private selector":17}}')
    evidence = _project_native_response_diagnostics(raw)
    expected = {"root_object_scanned": True, "unrecognized_member_count": 1, "msg_present": True, "msg_valid_string_shape": True,
        "status_category": "success", "script_status_category": "failed",
        "results_present": True, "results_shape_category": "object",
        **{key + suffix: True for key in ("version", "build", "http_status", "http_method", "status", "script_status")
           for suffix in ("_present", "_expected_category")}}
    expected["status_expected_category"] = False
    assert evidence == expected
    assert "private" not in repr(evidence)
    mismatch = _project_native_response_diagnostics(bytearray(b'{"build":true,"status":"private text"}'))
    assert not mismatch["build_expected_category"] and not mismatch["status_expected_category"]


@pytest.mark.parametrize("raw", [
    b'[]', b'null', b'{"status":"success","status":"success"}', b'{"status":"success",}',
    b'{"msg":"unfinished}', b'{"msg":[]] }', b'{}{}', b'{"msg":}', b'{"status" "success"}',
])
def test_response_observer_rejects_ambiguous_root_or_members(raw):
    from fortipam_mcp.secret_checkout_effect_http_transport import _project_native_response_diagnostics
    with pytest.raises(Exception):
        _project_native_response_diagnostics(bytearray(raw))


def test_response_reader_rejects_html_and_oversize_and_zeroizes_retained_buffer(monkeypatch):
    import fortipam_mcp.secret_checkout_effect_http_transport as module
    with pytest.raises(ValueError):
        module._read_native_response_diagnostics(SimpleNamespace(headers={"content-type": "text/html"},
            iter_bytes=lambda: pytest.fail("HTML must not be read")))
    monkeypatch.setattr(module, "MAX_RESPONSE_BYTES", 20)
    buffers = []
    original = module._zeroize_mutable
    def observe(buffer):
        original(buffer)
        buffers.append(bytes(buffer))
    monkeypatch.setattr(module, "_zeroize_mutable", observe)
    with pytest.raises(ValueError):
        module._read_native_response_diagnostics(SimpleNamespace(headers={"content-type": "application/json"},
            iter_bytes=lambda: iter([b'{"msg":"private', b'oversize value"}'])))
    assert buffers and all(not any(buffer) for buffer in buffers)


def test_internal_native_categories_remain_diagnostics_without_decoding_results():
    from fortipam_mcp.secret_checkout_effect_http_transport import _project_native_response_diagnostics
    evidence = _project_native_response_diagnostics(bytearray(
        b'{"status":"OK","http_method":"POST","http_status":200,"error":0,'
        b'"results":{"private selector":"private material"}}'))
    assert evidence["status_category"] == "OK" and evidence["status_expected_category"]
    assert evidence["error_expected_category"] and evidence["results_shape_category"] == "object"
    assert evidence["unrecognized_member_count"] == 0
    assert "private" not in repr(evidence)
    mismatch = _project_native_response_diagnostics(bytearray(b'{"status":"private text","error":false}'))
    assert mismatch["status_category"] == "unrecognized" and not mismatch["error_expected_category"]


def test_finite_native_route_diagnostics_never_publish_an_unknown_identifier():
    from fortipam_mcp.secret_checkout_effect_http_transport import _project_native_response_diagnostics
    result = _project_native_response_diagnostics(bytearray(b'{"path":"secret-checkout","name":""}'))
    assert result["path_category"] == "secret-checkout" and result["name_category"] == ""
    result = _project_native_response_diagnostics(bytearray(b'{"path":"private selector","name":"private identifier"}'))
    assert result["path_category"] == result["name_category"] == "unrecognized"
    assert "private" not in repr(result)


@pytest.mark.parametrize("message", [b'""', b'"synthetic-private-material"', '"中文 😀"'.encode(),
    b'"\\uD83D\\uDE00"', b'"\\\\\\/\\b\\f\\n\\r\\t\\\""'])
def test_exact_native_envelope_accepts_only_bound_identity_without_decoding_message(message, monkeypatch):
    import fortipam_mcp.secret_checkout_effect_http_transport as module
    decoded=[];loads=module.json.loads
    def key_only(value,*args,**kwargs):
        decoded.append(bytes(value));return loads(value,*args,**kwargs)
    monkeypatch.setattr(module.json,"loads",key_only)
    raw=bytearray(b'{"http_method":"POST","status":"OK","http_status":200,"secret-id":17,"msg":'+message+b'}')
    assert module._qualify_fixed_native_response(raw,17)
    assert decoded and all(value in {b'"http_method"',b'"status"',b'"http_status"',b'"secret-id"',b'"msg"'} for value in decoded)
    assert not module._qualify_fixed_native_response(raw,18)


@pytest.mark.parametrize("mutation", [
    (b'"POST"',b'"GET"'),(b'200',b'true'),(b'"OK"',b'"success"'),
    (b'"secret-id":17',b'"secret-id":17.0'),(b'"secret-id":17',b'"secret-id":true'),
    (b'"msg":"text"',b'"msg":null'),(b'"msg":"text"',b'"msg":[]'),
    (b'"msg":"text"',b'"msg":{"private":"text"}'),
    (b'"msg":"text"',b'"msg":"\\x"'),(b'"msg":"text"',b'"msg":"\x01"'),
    (b'"msg":"text"',b'"msg":"\xff"'),(b'"msg":"text"',b'"msg":"\xc0\x80"'),
    (b'"msg":"text"',b'"msg":"\xed\xa0\x80"'),(b'"msg":"text"',b'"msg":"\xf4\x90\x80\x80"'),
    (b'"msg":"text"',b'"msg":"\\uD800"'),(b'"msg":"text"',b'"msg":"\\uDC00"'),
    (b'"msg":"text"',b'"msg":"\\uD800\\u0041"'),(b'"msg":"text"',b'"msg":"\\uZZZZ"'),
    (b'}',b',"script_status":"failed"}'),(b'}',b',"field":[]}'),
    (b'}',b',"status":"OK"}'),(b'}',b',}'),(b'}',b'}{}'),
    (b'"msg":"text"',b'"msg":"'+b'x'*4096+b'"'),
])
def test_native_response_rejects_ambiguous_extra_or_invalid_values(mutation):
    from fortipam_mcp.secret_checkout_effect_http_transport import _qualify_fixed_native_response
    raw=bytearray(b'{"http_method":"POST","status":"OK","http_status":200,"secret-id":17,"msg":"text"}')
    assert not _qualify_fixed_native_response(raw.replace(*mutation),17)


@pytest.mark.parametrize("secret_id", [None, True, 0, -1, 2147483648])
def test_native_response_binding_rejects_invalid_identifier(secret_id):
    from fortipam_mcp.secret_checkout_effect_http_transport import _qualify_fixed_native_response
    assert not _qualify_fixed_native_response(bytearray(b'{}'),secret_id)
