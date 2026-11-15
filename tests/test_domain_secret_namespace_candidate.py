from dataclasses import replace
import json
from pathlib import Path

import httpx
import pytest

from fortipam_mcp import domain_secret_namespace_candidate as module
from fortipam_mcp import secret_namespace_ssh_reader as reader_module
from fortipam_mcp.owner_domain_runtime import owner_domain_transport
from fortipam_mcp.secret_create_191_private_adapter import SecretCreate700DomainBinding
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


def envelope(path, name, **changes):
    value = {"version": "v7.0.0", "build": 29, "serial": "SYNTHETIC_SERIAL",
        "http_status": 200, "http_method": "GET", "status": "OK", "path": path, "name": name}
    value.update(changes)
    return value


@pytest.fixture
def source(tmp_path, monkeypatch):
    hosts = tmp_path / "known_hosts"
    hosts.write_text("synthetic-pin"); hosts.chmod(0o600)
    settings = module.DomainSecretNamespaceSettings(17, (51, 52), "example.test", 22, hosts)
    binding = SecretCreate700DomainBinding(
        "fortipam-700-build29-domain-account-create-candidate-v1", "7.0.0", "a" * 64,
        "Public/domain-folder", "mcp-v4-domain-secret", "Windows Domain Account",
        "domain-target", "192.0.2.10", "ad.example.test", "domain-owner")
    config = SecretMetadataHttpTransportConfig("https://example.test", "synthetic-token", 5, None)
    state = {"credentials": 0, "calls": [], "ssh": [], "actor": binding.target_owner_name}
    role = envelope("system", "admin", results=[dict(name=binding.target_owner_name,
        accprofile="super_admin", status="enable", **{"remote-auth":"disable", "wildcard":"disable"})])
    folder = envelope("secret", "folder", results=[dict(id=17, name="domain-folder",
        **{"folder-type":"public", "parent-folder":3, "inherit-permission":"disable",
        "group-permission":[], "user-permission":[{"id":1,"user-name":[{"name":binding.target_owner_name}],
            "folder-permission":"owner", "secret-permission":"owner"}]})])
    collection = envelope("secret", "database", results=[
        {"id":51,"name":"KnownOne","folder":3},{"id":52,"name":"KnownTwo","folder":4}],
        matched_count=2, limit_reached=False)
    def credentials():
        state["credentials"] += 1
        return state["actor"], "synthetic-password"
    def respond(request):
        state["calls"].append((request.method, request.url.path))
        assert request.method == "GET" and "authorization" not in request.headers
        if request.url.path == "/api/v2/monitor/web-ui/state":
            return httpx.Response(200,json=envelope("web-ui","state",status="success",
                results={"admin":{"name":state["actor"],"login_name":state["actor"],
                    "sponsored_group_name":"","guest_admin":False}}))
        if request.url.path == "/api/v2/cmdb/system/admin/domain-owner":
            return httpx.Response(200,json=role)
        if request.url.path == "/api/v2/cmdb/secret/folder/17":
            return httpx.Response(200,json=folder)
        if request.url.path == "/api/v2/cmdb/secret/database":
            assert request.url.params["format"] == "id|name|folder"
            return httpx.Response(200,json=collection)
        raise AssertionError("Uncompiled metadata request")
    owner = owner_domain_transport(config,binding,credentials)
    owner._client = httpx.Client(base_url=config.base_url,transport=httpx.MockTransport(respond))
    owner._clock = lambda:100.0
    owner._expires_at = 500.0
    owner._folder_id = 17
    class Reader:
        def __init__(self, config, **kwargs):
            state["ssh"].append((config,kwargs))
        def read_namespace(self):
            return reader_module.SecretNamespaceObservation("name_absent",64,2,"b"*64,True)
    monkeypatch.setattr(reader_module,"FortiPamSecretNamespaceSshReader",Reader)
    observer = module.build_domain_secret_namespace_observer(config,binding,credentials,settings,
        owner_transport=lambda:owner)
    yield observer,binding,owner,settings,state,role,folder,collection
    owner._client.close()


def test_lazy_source_uses_same_active_owner_and_one_ssh_credential_snapshot(source):
    observer,binding,owner,settings,state,*_ = source
    assert state["calls"] == [] and state["credentials"] == 0
    for plan in (binding,replace(binding,plan_digest="c"*64)):
        result = observer(plan,17)
        assert result.global_name_absent
    assert state["credentials"] == 2 and len(state["ssh"]) == 2
    assert all(method=="GET" for method,path in state["calls"])
    assert all(path not in {"/logout","/remote/login"} for method,path in state["calls"])
    assert state["ssh"][0][1]["positive_witness_names"] == ("KnownOne","KnownTwo")


def test_composed_owner_hook_is_lazy_and_uses_its_own_active_session(source):
    _,binding,owner,settings,state,*_ = source
    credentials=lambda:(binding.target_owner_name,"synthetic-password")
    composed=module.owner_domain_namespace_transport(owner._config,binding,credentials,namespace_settings=settings)
    assert state["calls"] == [] and state["ssh"] == []
    composed._client=owner._client
    composed._clock=owner._clock
    composed._expires_at=owner._expires_at
    composed._folder_id=17
    assert composed._domain_secret_globally_absent(binding,17) is True
    assert len(state["ssh"]) == 1


@pytest.mark.parametrize("fault", ["actor","role","serial","folder-id","folder-name","folder-type",
    "parent","inherit","group","owner","permission","witness","duplicate-id","duplicate-name",
    "matched","limit","build","closed","expired","binding","wrong-folder","snapshot"])
def test_source_refuses_unqualified_evidence_before_ssh(source,fault):
    observer,binding,owner,settings,state,role,folder,collection = source
    row=folder["results"][0]
    if fault=="actor": state["actor"]="other-owner"
    if fault=="role": role["results"][0]["accprofile"]="read_only"
    if fault=="serial": folder["serial"]="OTHER_SERIAL"
    if fault=="folder-id": row["id"]=True
    if fault=="folder-name": row["name"]="other-folder"
    if fault=="folder-type": row["folder-type"]="personal"
    if fault=="parent": row["parent-folder"]=0
    if fault=="inherit": row["inherit-permission"]="enable"
    if fault=="group": row["group-permission"]=[{}]
    if fault=="owner": row["user-permission"][0]["user-name"][0]["name"]="other-owner"
    if fault=="permission": row["user-permission"][0]["secret-permission"]="view"
    if fault=="witness": collection["results"][1]["id"]=53
    if fault=="duplicate-id": collection["results"][1]["id"]=51
    if fault=="duplicate-name": collection["results"][1]["name"]="KnownOne"
    if fault=="matched": collection["matched_count"]=3
    if fault=="limit": collection["limit_reached"]=True
    if fault=="build": role["build"]=30
    if fault=="expired": owner._expires_at=100.0
    if fault=="binding": binding=replace(binding,secret_name="mcp-v4-other-secret")
    folder_id=18 if fault=="wrong-folder" else 17
    if fault=="closed":
        owner._client.close(); closed=owner._client;owner._client=None
    if fault=="snapshot":
        def changed():
            state["actor"]="other-owner"
            return "other-owner","synthetic-password"
        observer=module.build_domain_secret_namespace_observer(owner._config,binding,changed,settings,owner_transport=lambda:owner)
    with pytest.raises(ValueError,match="namespace evidence is unavailable"):
        observer(binding,folder_id)
    assert state["ssh"] == []
    if fault=="closed": owner._client=closed


def test_settings_default_closed_and_protected_exact_binding(tmp_path):
    assert module.load_domain_secret_namespace_settings({}) is None
    pin=tmp_path/"pin";pin.write_text("synthetic");pin.chmod(0o600)
    binding=tmp_path/"binding.json"
    value={"contract":module.CONTRACT,"folder_id":17,"witness_secret_ids":[51,52]}
    binding.write_text(json.dumps(value));binding.chmod(0o600)
    env={module.PREFIX+"ENABLED":"true",module.PREFIX+"BINDING_FILE":str(binding),
        module.PREFIX+"SSH_HOST":"example.test",module.PREFIX+"SSH_KNOWN_HOSTS_FILE":str(pin)}
    assert module.load_domain_secret_namespace_settings(env).folder_id == 17
    for malformed in ({**value,"extra":True},{**value,"folder_id":True},{**value,"witness_secret_ids":[51,51]}):
        binding.write_text(json.dumps(malformed))
        with pytest.raises(ValueError):module.load_domain_secret_namespace_settings(env)
    binding.write_text(json.dumps(value));binding.chmod(0o644)
    with pytest.raises(ValueError):module.load_domain_secret_namespace_settings(env)
    binding.chmod(0o600);binding.write_text('{"contract":"x","contract":"y"}')
    with pytest.raises(ValueError):module.load_domain_secret_namespace_settings(env)
