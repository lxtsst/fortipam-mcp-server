"""Qualified namespace absence remains inside the pinned Owner read lifetime."""

from dataclasses import replace

import httpx
import pytest

from fortipam_mcp.owner_domain_runtime import owner_domain_transport
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_create_191_private_adapter import SecretCreate700DomainBinding
from fortipam_mcp.secret_metadata_http_transport import (
    DomainSecretMetadataInspection, SecretMetadataHttpTransportConfig,
    SecretMetadataHttpTransportError, SYSTEM_STATUS_PATH,
)
from fortipam_mcp.secret_namespace_ssh_reader import SecretNamespaceObservation
from fortipam_mcp.target_contract import DOMAIN_TEMPLATE_FIELD_TYPES
from test_secret_metadata_http_transport import _DetailConnection, _DetailResponse


ABSENT = SecretNamespaceObservation("name_absent", 64, 2, "a" * 64, True)
PRESENT = replace(ABSENT, status="name_present", global_name_absent=False)


def _context(monkeypatch, *, observation=ABSENT, use_observer=True, lookup_status=404,
             defect=None):
    binding = SecretCreate700DomainBinding(
        "fortipam-700-build29-domain-account-create-candidate-v1", "7.0.0", "1" * 64,
        "Public/domain-folder", "mcp-v4-domain-secret", "Windows Domain Account",
        "domain-target", "192.0.2.10", "ad.example.test", "domain-owner",
    )
    config = SecretMetadataHttpTransportConfig("https://example.test", "synthetic-token", 5, None)
    state = {"calls": [], "credentials": 0, "observations": [], "raw": [], "active": False}
    envelope = {"http_method": "GET", "http_status": 200, "status": "success",
                "path": "secret", "vdom": "root", "version": "v7.0.0", "build": 29}

    def credentials():
        state["credentials"] += 1
        return binding.target_owner_name, "synthetic-password"

    def observer(actual_binding, folder_id):
        state["observations"].append((actual_binding, folder_id))
        if defect == "observer_error":
            raise RuntimeError("private observer failure marker")
        return observation

    def respond(request):
        state["calls"].append((request.method, request.url.path, request.url.params.get("type")))
        assert "authorization" not in request.headers
        path = request.url.path
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            state["active"] = True
            return httpx.Response(303, headers={"location": "/", "set-cookie": "testsession=synthetic; Secure; HttpOnly; Path=/"})
        if path == "/":
            return httpx.Response(200)
        if path == "/logout":
            state["active"] = False
            return httpx.Response(200)
        if not state["active"]:
            return httpx.Response(401, json={})
        assert request.method == "GET"
        if path == SYSTEM_STATUS_PATH:
            return httpx.Response(200, json={"version": "v7.0.0", "build": 29})
        if path.endswith("/target/" + binding.target_name):
            target = {"name": binding.target_name, "address": binding.target_ipv4_address,
                      "domain": binding.domain_dns_root, "template": binding.template_name,
                      "class": "Wrong" if defect == "target" else binding.target_classification_tag,
                      "ldaps-port": 636, "user-naming-attribute": "sAMAccountName",
                      "user-base": "", "access": "customized", "web-proxy-status": "disable",
                      "user-permission": [{"permission": "owner", "user-name": [{"name": binding.target_owner_name}]}]}
            return httpx.Response(200, json={**envelope, "name": "target", "results": [target]})
        if path.endswith("/template/" + binding.template_name):
            return httpx.Response(200, json={**envelope, "name": "template", "results": [{
                "name": binding.template_name,
                "field": [{"name": name, "type": kind} for name, kind in DOMAIN_TEMPLATE_FIELD_TYPES],
            }]})
        if request.url.params.get("type") == "folder":
            return httpx.Response(404 if defect == "folder" else 200, json={"results": {"id": 17}})
        if path.endswith("/folder/17"):
            acl = {"id": 17, "inherit-permission": "disable", "group-permission": [],
                   "user-permission": [{"id": 3, "user-name": [binding.target_owner_name],
                       "folder-permission": "owner", "secret-permission": "owner", "allowed-launcher-type": "all"}]}
            if defect == "acl_group":
                acl["group-permission"] = [{"group-name": ["other-group"]}]
            if defect == "acl_inherited":
                acl["inherit-permission"] = "enable"
            if defect == "acl_owner":
                acl["user-permission"][0]["user-name"] = ["other-owner"]
            return httpx.Response(200, json={"results": [acl]})
        assert request.url.params.get("type") == "secret"
        return httpx.Response(lookup_status, json={"results": {"id": 23} if lookup_status == 200 else {}})

    owner = owner_domain_transport(
        config, binding, credentials, namespace_observer=observer if use_observer else None,
    )
    client = httpx.Client
    owner._session_factory = lambda **kwargs: client(**kwargs, transport=httpx.MockTransport(respond))

    def raw(*args, **kwargs):
        detail = {"id": 23, "name": binding.secret_name, "folder": 17,
                  "template": binding.template_name, "target": binding.target_name,
                  "inherit-permission": "enable", "target-privilege-account": "disable",
                  **{service + "-service-status": "down" for service in ("rdp", "ssh", "sftp", "http", "samba", "telnet")},
                  "field": [{"name": "Password", "value": "synthetic-material-erased-before-decode"}]}
        connection = _DetailConnection(_DetailResponse({"results": [detail]}), state["raw"])
        return connection

    owner._raw_connection_factory = raw
    return owner, binding, state


def _assert_closed(owner, state):
    assert owner._client is None and owner.logout_verified
    assert state["active"] is False
    assert all(method == "GET" or path == "/XX/YY/ZZ/AUTH" for method, path, _ in state["calls"])


def test_explicit_namespace_binding_startup_is_inert_and_qualified_absence_skips_secret_lookup(monkeypatch):
    owner, binding, state = _context(monkeypatch)
    assert state["calls"] == [] and state["credentials"] == 0 and state["observations"] == []
    assert owner._allow_secret_create is False
    with owner.authenticated():
        result = owner.inspect_domain_account_projection(binding)
    assert result == DomainSecretMetadataInspection(False, False, False)
    assert state["observations"] == [(binding, 17)]
    assert not any(kind == "secret" for _, _, kind in state["calls"])
    assert state["raw"] == []
    assert any(path.endswith("/folder/17") for _, path, _ in state["calls"])
    _assert_closed(owner, state)


@pytest.mark.parametrize("lookup_status", [200, 404])
@pytest.mark.parametrize("use_observer", [False, True])
def test_present_or_default_namespace_never_turns_404_into_absence(monkeypatch, lookup_status, use_observer):
    owner, binding, state = _context(monkeypatch, observation=PRESENT,
                                    use_observer=use_observer, lookup_status=lookup_status)
    if not use_observer:
        assert type(owner) is OwnerSessionMetadataTransport
    with owner.authenticated():
        if lookup_status == 404:
            with pytest.raises(SecretMetadataHttpTransportError):
                owner.inspect_domain_account_projection(binding)
        else:
            assert owner.inspect_domain_account_projection(binding) == DomainSecretMetadataInspection(True, True, True)
    assert len(state["observations"]) == (1 if use_observer else 0)
    _assert_closed(owner, state)


@pytest.mark.parametrize("lookup_status", [200, 404])
def test_fixed_postcondition_id_cannot_consume_namespace_absence(monkeypatch, lookup_status):
    owner, binding, state = _context(monkeypatch, lookup_status=lookup_status)
    with owner.authenticated():
        if lookup_status == 404:
            with pytest.raises(SecretMetadataHttpTransportError):
                owner.inspect_domain_account_projection(binding, expected_secret_id=23)
        else:
            assert owner.inspect_domain_account_projection(binding, expected_secret_id=23).metadata_verified
    assert state["observations"] == []
    assert any(kind == "secret" for _, _, kind in state["calls"])
    _assert_closed(owner, state)


@pytest.mark.parametrize("defect", ["target", "folder", "acl_group", "acl_inherited", "acl_owner"])
def test_preflight_and_exact_owner_only_acl_failure_precedes_namespace_callback(monkeypatch, defect):
    owner, binding, state = _context(monkeypatch, defect=defect)
    with owner.authenticated():
        with pytest.raises(SecretMetadataHttpTransportError):
            owner.inspect_domain_account_projection(binding)
    assert state["observations"] == [] and state["raw"] == []
    _assert_closed(owner, state)


@pytest.mark.parametrize("observation", [
    object(), None, True,
    replace(ABSENT, status="qualified"), replace(ABSENT, status=True),
    replace(ABSENT, global_name_absent=1), replace(ABSENT, global_name_absent=False),
    replace(PRESENT, global_name_absent=True),
    replace(ABSENT, secret_count=True), replace(ABSENT, secret_count=64.0),
    replace(ABSENT, secret_count=1), replace(ABSENT, secret_count=2_147_483_648),
    replace(ABSENT, positive_witness_count=True), replace(ABSENT, positive_witness_count=2.0),
    replace(ABSENT, positive_witness_count=0), replace(ABSENT, positive_witness_count=1),
    replace(ABSENT, positive_witness_count=65),
    replace(ABSENT, namespace_digest=None), replace(ABSENT, namespace_digest="A" * 64),
    replace(ABSENT, namespace_digest="wrong-digest"),
])
def test_namespace_observation_contract_is_closed_and_native(monkeypatch, observation):
    owner, binding, state = _context(monkeypatch, observation=observation)
    with owner.authenticated():
        with pytest.raises(SecretMetadataHttpTransportError):
            owner.inspect_domain_account_projection(binding)
    assert len(state["observations"]) == 1
    assert not any(kind == "secret" for _, _, kind in state["calls"])
    assert state["raw"] == []
    _assert_closed(owner, state)


def test_callback_error_is_stable_and_session_closes(monkeypatch):
    owner, binding, state = _context(monkeypatch, defect="observer_error")
    with pytest.raises(SecretMetadataHttpTransportError) as caught:
        with owner.authenticated():
            owner.inspect_domain_account_projection(binding)
    assert "private observer failure marker" not in str(caught.value)
    assert caught.value.__suppress_context__
    _assert_closed(owner, state)


@pytest.mark.parametrize("field,value", [
    ("folder_path", "Public/other-folder"), ("secret_name", "mcp-v4-other-secret"),
    ("target_name", "other-target"), ("target_ipv4_address", "192.0.2.11"),
    ("domain_dns_root", "other.example.test"), ("target_owner_name", "other-owner"),
    ("target_classification_tag", "Changed Tag"),
])
def test_namespace_hook_rejects_changed_private_selector_before_acl_or_observer(monkeypatch, field, value):
    owner, binding, state = _context(monkeypatch)
    with owner.authenticated():
        assert owner.resolve_folder_id(binding.folder_path) == 17
        before = len(state["calls"])
        with pytest.raises(SecretMetadataHttpTransportError):
            owner._domain_secret_globally_absent(replace(binding, **{field: value}), 17)
        assert len(state["calls"]) == before
    assert state["observations"] == []
    _assert_closed(owner, state)


@pytest.mark.parametrize("folder_id", [None, True, 17.0, 0, 18])
def test_namespace_hook_rejects_wrong_exact_folder_id_before_observer(monkeypatch, folder_id):
    owner, binding, state = _context(monkeypatch)
    with owner.authenticated():
        assert owner.resolve_folder_id(binding.folder_path) == 17
        with pytest.raises(SecretMetadataHttpTransportError):
            owner._domain_secret_globally_absent(binding, folder_id)
    assert state["observations"] == []
    _assert_closed(owner, state)


def test_same_private_selectors_allow_authorized_m4_plan_digest_replacement(monkeypatch):
    owner, binding, state = _context(monkeypatch)
    execution_binding = replace(binding, plan_digest="9" * 64)
    with owner.authenticated():
        assert owner.inspect_domain_account_projection(execution_binding).secret_exists is False
    assert state["observations"] == [(execution_binding, 17)]
    _assert_closed(owner, state)


@pytest.mark.parametrize("field,value", [
    ("_bound_secret_name", "mcp-v4-other-secret"), ("_owner_name", "other-owner"),
    ("_folder_lookup_path", "/api/v2/utility/id/Public/other-folder"), ("_folder_id", 18),
])
def test_owner_selector_drift_cannot_borrow_the_pinned_namespace_observer(monkeypatch, field, value):
    owner, binding, state = _context(monkeypatch)
    with owner.authenticated():
        assert owner.resolve_folder_id(binding.folder_path) == 17
        setattr(owner, field, value)
        with pytest.raises(SecretMetadataHttpTransportError):
            owner._domain_secret_globally_absent(binding, 17)
    assert state["observations"] == []
    _assert_closed(owner, state)


def test_namespace_evidence_is_read_fresh_and_presence_drift_is_not_cached(monkeypatch):
    owner, binding, state = _context(monkeypatch)
    observations = iter((ABSENT, PRESENT))

    def changing_observer(actual_binding, folder_id):
        state["observations"].append((actual_binding, folder_id))
        return next(observations)

    owner._namespace_observer = changing_observer
    with owner.authenticated():
        assert owner.inspect_domain_account_projection(binding).secret_exists is False
        with pytest.raises(SecretMetadataHttpTransportError):
            owner.inspect_domain_account_projection(binding)
    assert state["observations"] == [(binding, 17), (binding, 17)]
    assert sum(kind == "secret" for _, _, kind in state["calls"]) == 1
    _assert_closed(owner, state)


def test_non_boolean_acl_attestation_cannot_invoke_namespace_observer(monkeypatch):
    owner, binding, state = _context(monkeypatch)
    monkeypatch.setattr(owner, "_verify_collector_folder_acl", lambda *_: 1)
    with owner.authenticated():
        with pytest.raises(SecretMetadataHttpTransportError):
            owner.inspect_domain_account_projection(binding)
    assert state["observations"] == []
    _assert_closed(owner, state)


@pytest.mark.parametrize("observer", [True, object()])
def test_invalid_observer_configuration_rejected_without_credentials(monkeypatch, observer):
    _, binding, state = _context(monkeypatch)
    config = SecretMetadataHttpTransportConfig("https://example.test", "synthetic-token", 5, None)
    with pytest.raises(ValueError):
        owner_domain_transport(config, binding, lambda: pytest.fail("Credential resolution must not run"),
                               namespace_observer=observer)
    assert state["calls"] == [] and state["credentials"] == 0
