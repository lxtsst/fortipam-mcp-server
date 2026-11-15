"""Focused 7.0 Discovery reference envelope regression."""

from __future__ import annotations

import httpx
import pytest

from fortipam_mcp.discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from fortipam_mcp.discovery_entry_create_http_transport import FortiPamDiscoveryEntryCreateHttpTransport
from fortipam_mcp.discovery_entry_create_http_transport import DiscoveryEntryCreateHttpTransportError
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.discovery_entry_http_transport import DiscoveryEntryHttpTransportError, inspect_discovery_entry_detail


def _ad_dependency_fixture(monkeypatch, defect=None, *, binding_changes=None, secret_id=23):
    import io
    import json
    from dataclasses import replace

    import fortipam_mcp.secret_metadata_http_transport as metadata_module
    from fortipam_mcp.secret_create_191_private_adapter import SecretCreate700DomainBinding
    from fortipam_mcp.target_contract import DOMAIN_TEMPLATE_FIELD_TYPES

    binding = SecretCreate700DomainBinding(
        "fortipam-700-build29-domain-account-create-candidate-v1", "7.0.0", "1" * 64,
        "Public/domain-folder", "domain-secret", "Windows Domain Account", "domain-target",
        "192.0.2.10", "ad.example.test", "domain-owner",
    )
    binding = replace(binding, **(binding_changes or {}))
    target = {
        "name": binding.target_name, "address": binding.target_ipv4_address,
        "domain": binding.domain_dns_root, "template": binding.template_name,
        "class": binding.target_classification_tag, "ldaps-port": 636,
        "user-naming-attribute": "sAMAccountName", "user-base": "", "access": "customized",
        "web-proxy-status": "disable",
        "user-permission": [{"permission": "owner", "user-name": [{"name": binding.target_owner_name}]}],
    }
    template = {
        "name": binding.template_name,
        "field": [{"name": name, "type": kind} for name, kind in DOMAIN_TEMPLATE_FIELD_TYPES],
    }
    sentinel = "synthetic-domain-material-must-not-be-decoded"
    detail = {
        "id": secret_id, "name": binding.secret_name, "folder": 17, "template": binding.template_name,
        "target": binding.target_name, "inherit-permission": "enable", "target-privilege-account": "disable",
        **{service + "-service-status": "down" for service in ("rdp", "ssh", "sftp", "http", "samba", "telnet")},
        "field": [{"name": "Password", "value": sentinel}],
    }
    if defect and defect.startswith("target:"):
        key = defect.split(":", 1)[1]
        target[key] = 389 if key == "ldaps-port" else "changed"
    elif defect == "owner":
        target["user-permission"][0]["user-name"][0]["name"] = "different-owner"
    elif defect == "template-field":
        template["field"][0]["type"] = "changed"
    elif defect == "template-name":
        template["name"] = "Unix Account (SSH Password)"
    elif defect and defect.startswith("secret:"):
        key = defect.split(":", 1)[1]
        detail[key] = 24 if key in {"id", "folder"} else "changed"
    elif defect == "field-omitted":
        del detail["field"]
    calls = []

    def respond(request):
        assert request.method == "GET" and request.content == b""
        calls.append({"method": request.method, "path": str(request.url)})
        envelope = {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
                    "status": "success", "path": "secret", "vdom": "root"}
        if request.url.path.endswith("/target/" + binding.target_name):
            return httpx.Response(200, json={**envelope, "name": "target", "results": [target]})
        if request.url.path.endswith("/template/Windows Domain Account"):
            return httpx.Response(200, json={**envelope, "name": "template", "results": [template]})
        if request.url.params.get("type") == "folder":
            assert request.url.path.endswith("/" + binding.folder_path)
            return httpx.Response(200, json={"results": {"id": 17}})
        assert request.url.params.get("type") == "secret"
        assert request.url.path.endswith("/" + binding.folder_path + "/" + binding.secret_name)
        if defect == "absent":
            return httpx.Response(404, json={"results": []})
        if defect == "unreadable":
            return httpx.Response(403, json={})
        return httpx.Response(200, json={"results": {"id": 24 if defect == "lookup-id" else secret_id}})

    class DetailResponse(io.BytesIO):
        status = 200

        def getheader(self, name, default=""):
            return "application/json" if name == "content-type" else default

    response = DetailResponse(json.dumps({"results": [detail]}).encode())

    class DetailConnection:
        closed = False

        def request(self, method, path, **kwargs):
            assert method == "GET" and "body" not in kwargs
            calls.append({"method": method, "path": path})

        def getresponse(self):
            return response

        def close(self):
            self.closed = True

    connection = DetailConnection()
    config = SecretMetadataHttpTransportConfig(
        base_url="https://example.test", bearer_token="test-token",
        timeout_seconds=5, ca_file=None,
    )
    monkeypatch.setattr(metadata_module, "_ssl_context", lambda _: True)
    transport = metadata_module.FortiPamSecretMetadataHttpTransport(
        config, bound_secret_name=binding.secret_name,
        client_factory=lambda **kwargs: httpx.Client(**kwargs, transport=httpx.MockTransport(respond)),
        detail_connection_factory=lambda *_args, **_kwargs: connection,
    )
    original_loads = json.loads

    def decode_without_material(value, *args, **kwargs):
        assert sentinel not in str(value)
        return original_loads(value, *args, **kwargs)

    monkeypatch.setattr(metadata_module.json, "loads", decode_without_material)
    return binding, transport, calls, response, connection


@pytest.mark.parametrize("defect", [
    None, "field-omitted", "target:name", "target:address", "target:domain", "target:template",
    "target:class", "target:ldaps-port", "owner", "template-field", "template-name",
    "secret:id", "secret:name", "secret:folder", "secret:template", "secret:target",
    "secret:inherit-permission", "secret:target-privilege-account", "secret:ssh-service-status",
    "lookup-id", "absent", "unreadable",
])
def test_ad_dependency_uses_fixed_domain_projection_without_dispatch(monkeypatch, defect):
    from fortipam_mcp.discovery_entry_create_contract import DisabledAdDiscoveryCreateInput
    from fortipam_mcp.discovery_entry_create_http_transport import inspect_ad_credential_dependency
    import fortipam_mcp.secret_metadata_http_transport as metadata_module

    binding, transport, calls, response, connection = _ad_dependency_fixture(monkeypatch, defect)
    request = DisabledAdDiscoveryCreateInput("bp014-discovery-ad-disabled-20261006-r1", 23)
    if defect in {None, "field-omitted"}:
        digest = inspect_ad_credential_dependency(request, binding, transport)
        assert len(digest) == 64
        assert binding.secret_name not in digest and binding.target_name not in digest
    else:
        with pytest.raises(DiscoveryEntryCreateHttpTransportError) as error:
            inspect_ad_credential_dependency(request, binding, transport)
        assert str(error.value) == "FortiPAM Discovery create transport is unavailable."
    assert calls and all(call["method"] == "GET" for call in calls)
    detail_calls = [call for call in calls if "/secret/database/" in call["path"]]
    if detail_calls:
        assert detail_calls == [{"method": "GET", "path": (
            "/api/v2/cmdb/secret/database/23?" + metadata_module._DOMAIN_ACCOUNT_DETAIL_QUERY)}]
        assert response.closed and connection.closed
        assert "field" not in detail_calls[0]["path"] and "target-info" not in detail_calls[0]["path"]


@pytest.mark.parametrize("binding_changes", [
    {"plan_digest": "2" * 64}, {"secret_name": "different-secret"},
    {"folder_path": "Public/different-folder"}, {"target_name": "different-target"},
    {"target_ipv4_address": "192.0.2.11"}, {"domain_dns_root": "different.example.test"},
    {"target_owner_name": "different-owner"}, {"target_classification_tag": "Different Tag"},
])
def test_ad_dependency_digest_binds_exact_private_domain_intent(monkeypatch, binding_changes):
    from fortipam_mcp.discovery_entry_create_contract import DisabledAdDiscoveryCreateInput
    from fortipam_mcp.discovery_entry_create_http_transport import inspect_ad_credential_dependency

    request = DisabledAdDiscoveryCreateInput("bp014-discovery-ad-disabled-20261006-r1", 23)
    with monkeypatch.context() as original:
        binding, transport, *_ = _ad_dependency_fixture(original)
        digest = inspect_ad_credential_dependency(request, binding, transport)
    with monkeypatch.context() as changed:
        binding, transport, *_ = _ad_dependency_fixture(changed, binding_changes=binding_changes)
        assert inspect_ad_credential_dependency(request, binding, transport) != digest


@pytest.mark.parametrize("source_name,secret_id", [
    ("bp014-discovery-ad-disabled-20261006-r2", 23),
    ("bp014-discovery-ad-disabled-20261006-r1", 24),
])
def test_ad_dependency_digest_binds_exact_source_and_secret_id(monkeypatch, source_name, secret_id):
    from fortipam_mcp.discovery_entry_create_contract import DisabledAdDiscoveryCreateInput
    from fortipam_mcp.discovery_entry_create_http_transport import inspect_ad_credential_dependency

    with monkeypatch.context() as original:
        binding, transport, *_ = _ad_dependency_fixture(original)
        request = DisabledAdDiscoveryCreateInput("bp014-discovery-ad-disabled-20261006-r1", 23)
        digest = inspect_ad_credential_dependency(request, binding, transport)
    with monkeypatch.context() as changed:
        binding, transport, *_ = _ad_dependency_fixture(changed, secret_id=secret_id)
        request = DisabledAdDiscoveryCreateInput(source_name, secret_id)
        assert inspect_ad_credential_dependency(request, binding, transport) != digest


@pytest.mark.parametrize("defect", ["request", "binding", "transport", "source-name"])
def test_ad_dependency_rejects_invalid_inputs_without_reads(monkeypatch, defect):
    from fortipam_mcp.discovery_entry_create_contract import DisabledAdDiscoveryCreateInput
    from fortipam_mcp.discovery_entry_create_http_transport import inspect_ad_credential_dependency

    binding, transport, calls, *_ = _ad_dependency_fixture(monkeypatch)
    request = DisabledAdDiscoveryCreateInput("bp014-discovery-ad-disabled-20261006-r1", 23)
    if defect == "request":
        request = object()
    elif defect == "binding":
        binding = object()
    elif defect == "transport":
        transport = object()
    else:
        request = DisabledAdDiscoveryCreateInput("ad-source-outside-disposable-scope", 23)
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        inspect_ad_credential_dependency(request, binding, transport)
    assert calls == []


@pytest.mark.parametrize("invalid_result", [
    None, object(),
    (False, True, False), (True, False, False),
    (1, True, False), (True, 1, False), (True, True, 0),
])
def test_ad_dependency_rejects_unqualified_or_malformed_projection(monkeypatch, invalid_result):
    from fortipam_mcp.discovery_entry_create_contract import DisabledAdDiscoveryCreateInput
    from fortipam_mcp.discovery_entry_create_http_transport import inspect_ad_credential_dependency
    from fortipam_mcp.secret_metadata_http_transport import DomainSecretMetadataInspection

    binding, transport, calls, *_ = _ad_dependency_fixture(monkeypatch)
    result = (DomainSecretMetadataInspection(*invalid_result)
              if isinstance(invalid_result, tuple) else invalid_result)
    monkeypatch.setattr(transport, "inspect_domain_account_projection", lambda *_args, **_kwargs: result)
    request = DisabledAdDiscoveryCreateInput("bp014-discovery-ad-disabled-20261006-r1", 23)
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        inspect_ad_credential_dependency(request, binding, transport)
    assert calls == []


def test_ad_dependency_rejects_unix_or_mismatched_secret_id(monkeypatch):
    from fortipam_mcp.discovery_entry_create_contract import DisabledAdDiscoveryCreateInput
    from fortipam_mcp.discovery_entry_create_http_transport import inspect_ad_credential_dependency

    binding, transport, calls, *_ = _ad_dependency_fixture(monkeypatch)
    unix = DisabledUnixDiscoveryCreateInput("bp014-discovery-unix-disabled-20261006-r1", 23)
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        inspect_ad_credential_dependency(unix, binding, transport)
    assert calls == []
    ad = DisabledAdDiscoveryCreateInput("bp014-discovery-ad-disabled-20261006-r1", 24)
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        inspect_ad_credential_dependency(ad, binding, transport)
    assert not any("/secret/database/" in call["path"] for call in calls)


def test_reference_preflight_accepts_exact_secret_with_non_success_status(monkeypatch) -> None:
    calls: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/v2/cmdb/secret/database/17":
            payload = {"http_method": "GET", "http_status": 200,
                       "status": 0, "results": [{"id": 17, "name": "unix-secret",
                                                "target": "unix-target"}]}
        elif request.url.path == "/api/v2/cmdb/secret/target/unix-target":
            payload = {"http_method": "GET", "http_status": 200,
                       "status": "success", "results": [{"name": "unix-target",
                                                          "type": "Linux"}]}
        else:
            raise AssertionError("unexpected route")
        return httpx.Response(200, json=payload)

    original_client = httpx.Client
    monkeypatch.setattr(
        "fortipam_mcp.discovery_entry_create_http_transport.httpx.Client",
        lambda **kwargs: original_client(**kwargs, transport=httpx.MockTransport(respond)),
    )
    monkeypatch.setattr(
        "fortipam_mcp.discovery_entry_create_http_transport._ssl_context",
        lambda _config: True,
    )
    config = SecretMetadataHttpTransportConfig(
        base_url="https://example.test", bearer_token="test-token",
        timeout_seconds=5, ca_file=None,
    )
    request = DisabledUnixDiscoveryCreateInput(
        "bp014-discovery-unix-disabled-20260930-r5", 17,
    )

    digest = FortiPamDiscoveryEntryCreateHttpTransport(config).inspect_credential_reference(request)

    assert len(digest) == 64
    assert calls == [
        "/api/v2/cmdb/secret/database/17",
        "/api/v2/cmdb/secret/target/unix-target",
    ]


def _fixture_transport(monkeypatch, *, ack_change=None):
    source = DisabledUnixDiscoveryCreateInput("bp014-discovery-unix-disabled-20261002-r1", 17)
    state = {"row": None, "deletes": 0, "calls": 0}

    def envelope(method, code):
        return {"http_method": method, "http_status": code, "status": "success" if code == 200 else "error",
                "path": "secret", "name": "discovery", "vdom": "root", "version": "v7.0.0", "build": 29}

    def respond(request):
        state["calls"] += 1
        path = request.url.path
        if path.endswith("/database/17"):
            return httpx.Response(200, json={"http_method": "GET", "http_status": 200,
                                           "results": [{"id": 17, "name": "unix-secret", "target": "unix-target"}]})
        if path.endswith("/target/unix-target"):
            return httpx.Response(200, json={"http_method": "GET", "http_status": 200,
                                           "results": [{"name": "unix-target"}]})
        if request.method == "POST":
            import json
            state["row"] = json.loads(request.content)
            state["row"].update({"last-discovery-time": "0000-00-00 00:00:00", "q_origin_key": source.source_name})
            return httpx.Response(200, json=envelope("POST", 200))
        assert path.endswith("/discovery/" + source.source_name)
        if request.method == "DELETE":
            assert request.content == b""
            state["deletes"] += 1
            state["row"] = None
            ack = envelope("DELETE", 200)
            if ack_change:
                ack.update(ack_change)
            return httpx.Response(200, json=ack)
        assert request.method == "GET"
        if state["row"] is None:
            return httpx.Response(404, json={**envelope("GET", 404), "results": []})
        row = dict(state["row"])
        if "format" in request.url.params:
            keys = set(request.url.params["format"].split("|")) | {"q_origin_key"}
            row = {key: value for key, value in row.items() if key in keys}
        return httpx.Response(200, json={**envelope("GET", 200), "results": [row]})

    original_client = httpx.Client
    monkeypatch.setattr("fortipam_mcp.discovery_entry_create_http_transport.httpx.Client",
                        lambda **kwargs: original_client(**kwargs, transport=httpx.MockTransport(respond)))
    monkeypatch.setattr("fortipam_mcp.discovery_entry_create_http_transport._ssl_context", lambda _config: True)
    monkeypatch.setattr("fortipam_mcp.discovery_entry_http_transport._ssl_context", lambda _config: True)
    config = SecretMetadataHttpTransportConfig("https://example.test", "test-token", 5, None)
    return FortiPamDiscoveryEntryCreateHttpTransport(config), source, state


def test_cleanup_requires_same_created_unchanged_fixture_and_never_replays(monkeypatch):
    transport, source, state = _fixture_transport(monkeypatch)
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        transport.cleanup_bound_disposable()
    assert transport.create_and_readback(source).verified
    # This field is outside the minimized create readback.
    state["row"]["owner"] = "changed-owner"
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        transport.cleanup_bound_disposable()
    assert state["deletes"] == 0
    state["row"]["owner"] = ""
    result = transport.cleanup_bound_disposable()
    assert result.verified
    assert state["deletes"] == 1
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        transport.cleanup_bound_disposable()
    assert state["deletes"] == 1


def test_reconciled_cleanup_claim_survives_new_process_and_checks_drift_before_consumption(monkeypatch, tmp_path):
    original, source, state = _fixture_transport(monkeypatch)
    assert original.create_and_readback(source).verified
    accepted = original._read_cleanup_digest(source)
    tmp_path.chmod(0o700)
    path = tmp_path / "delete-claim.json"
    config = SecretMetadataHttpTransportConfig("https://example.test", "test-token", 5, None)
    recovery = FortiPamDiscoveryEntryCreateHttpTransport.for_reconciled_cleanup(
        config, source, accepted_digest=accepted, claim_path=path,
    )
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        recovery.create_and_readback(source)
    state["row"]["owner"] = "changed-owner"
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        recovery.cleanup_bound_disposable()
    assert not path.exists()
    assert state["deletes"] == 0
    state["row"]["owner"] = ""
    assert recovery.cleanup_bound_disposable().verified
    assert path.stat().st_mode & 0o777 == 0o600
    assert state["deletes"] == 1
    before = state["calls"]
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        FortiPamDiscoveryEntryCreateHttpTransport.for_reconciled_cleanup(
            config, source, accepted_digest=accepted, claim_path=path,
        )
    assert state["calls"] == before
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        recovery.cleanup_bound_disposable()
    assert state["deletes"] == 1


@pytest.mark.parametrize("ack_change", [
    {"status": "error"}, {"http_method": "POST"}, {"build": 30},
    {"error": -1}, {"error": False}, {"name": "target"},
])
def test_cleanup_unknown_ack_is_consumed_even_when_fixed_read_proves_absence(monkeypatch, ack_change):
    transport, source, state = _fixture_transport(monkeypatch, ack_change=ack_change)
    assert transport.create_and_readback(source).verified
    result = transport.cleanup_bound_disposable()
    assert not result.verified
    assert result.delete_category == "ambiguous"
    assert result.exact_get_404_after_delete
    assert state["deletes"] == 1
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        transport.cleanup_bound_disposable()
    assert state["deletes"] == 1


@pytest.mark.parametrize("results", [None, [], [{"name": "unexpected-entry"}]])
def test_absence_reader_rejects_populated_missing_object_reply(monkeypatch, results):
    payload = {"status": "error", "http_method": "GET", "http_status": 404,
               "path": "secret", "name": "discovery", "vdom": "root", "version": "v7.0.0", "build": 29}
    if results is not None:
        payload["results"] = results
    monkeypatch.setattr("fortipam_mcp.discovery_entry_http_transport._get_detail", lambda *_args: (404, payload))
    config = SecretMetadataHttpTransportConfig("https://example.test", "test-token", 5, None)
    if results:
        with pytest.raises(DiscoveryEntryHttpTransportError):
            inspect_discovery_entry_detail(config, expected_name="test-source")
    else:
        assert inspect_discovery_entry_detail(config, expected_name="test-source") is None


@pytest.mark.parametrize("unsafe", ["existing", "symlink", "wide_parent"])
def test_reconciled_cleanup_refuses_unsafe_claim_without_network(monkeypatch, tmp_path, unsafe):
    original, source, state = _fixture_transport(monkeypatch)
    assert original.create_and_readback(source).verified
    accepted = original._read_cleanup_digest(source)
    tmp_path.chmod(0o700)
    path = tmp_path / "claim.json"
    if unsafe == "existing":
        path.write_text("consumed")
    elif unsafe == "symlink":
        path.symlink_to(tmp_path / "missing.json")
    else:
        tmp_path.chmod(0o755)
    before = state["calls"]
    config = SecretMetadataHttpTransportConfig("https://example.test", "test-token", 5, None)
    with pytest.raises(DiscoveryEntryCreateHttpTransportError):
        FortiPamDiscoveryEntryCreateHttpTransport.for_reconciled_cleanup(
            config, source, accepted_digest=accepted, claim_path=path,
        )
    assert state["calls"] == before
