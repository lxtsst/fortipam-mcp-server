"""Exact Owner attenuation, independent absence and unchanged CREATE authority."""
from contextlib import contextmanager
from dataclasses import asdict, replace
import hashlib
import json
from pathlib import Path

import httpx
import pytest

from fortipam_mcp import owner_rdp_runtime as module
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig, SecretMetadataHttpTransportError
from fortipam_mcp.secret_namespace_ssh_reader import SecretNamespaceObservation
from test_domain_secret_namespace_candidate import envelope
from test_isolated_folder_creation_ownership import folder
from test_policy_assignment_definition import response
from test_secret_onboarding_projection_source import _rdp_binding, _rdp_draft


def settings(tmp_path):
    hosts = tmp_path / "known_hosts"
    hosts.write_text("synthetic-pinned-peer"); hosts.chmod(0o600)
    b = _rdp_binding()
    return module.RdpOwnerSettings(b.folder_path, 17, "synthetic-owner", b.secret_name,
        b.target_name, b.policy_profile_name, "SYNTHETIC_SERIAL", "a" * 64, "b" * 64,
        (51, 52), "pam.example.test", 22, hosts)


@pytest.fixture
def source(tmp_path, monkeypatch):
    b = replace(_rdp_binding(), template_name="Windows Machine")
    s = settings(tmp_path)
    current = folder()
    current.update(id=17, name="folder", **{"parent-folder":3, "inherit-policy":"disable", "secret-policy":s.policy_name})
    def change(v):
        v.update(serial=s.expected_serial, mkey=s.policy_name)
        v["results"][0].update(name=s.policy_name, q_origin_key=s.policy_name,
            recording="enable", **{"block-clipboard":"enable"})
    policy = json.loads(response(change))
    observed = module.consume_policy_assignment_definition(bytearray(json.dumps(policy).encode()),
        policy_name=s.policy_name, serial_digest=hashlib.sha256(s.expected_serial.encode()).hexdigest())
    s = replace(s, folder_state_digest=module.folder_snapshot_digest(current), policy_configuration_digest=observed.configuration_digest)
    state = dict(calls=[], ssh=[], credentials=0, role="super_admin", absent=True)
    role = envelope("system", "admin", results=[dict(name=s.owner_name, accprofile="super_admin",
        status="enable", **{"remote-auth":"disable", "wildcard":"disable"})])
    collection = envelope("secret", "database", results=[{"id":51,"name":"KnownOne","folder":3},
        {"id":52,"name":"KnownTwo","folder":4}], matched_count=2, limit_reached=False)
    def credentials():
        state["credentials"] += 1
        return s.owner_name, "synthetic-password"
    owner = module.OwnerRdpSessionMetadataTransport(SecretMetadataHttpTransportConfig(
        "https://pam.example.test", "api-token-must-not-be-used", 5, None), s, credentials)
    def handle(request):
        state["calls"].append(request.url.path)
        assert request.method == "GET" and "authorization" not in request.headers
        if request.url.path == "/api/v2/monitor/web-ui/state":
            return httpx.Response(200,json=envelope("web-ui","state",status="success",results={"admin":{
                "name":s.owner_name,"login_name":s.owner_name,"sponsored_group_name":"","guest_admin":False}}))
        if request.url.path == "/api/v2/cmdb/system/admin/" + s.owner_name: return httpx.Response(200,json=role)
        if request.url.path.endswith("/folder/17"): return httpx.Response(200,json=envelope("secret","folder",results=[current]))
        if request.url.path.endswith("/policy/" + s.policy_name): return httpx.Response(200,json=policy)
        if request.url.path == "/api/v2/cmdb/secret/database": return httpx.Response(200,json=collection)
        if request.url.path == owner._folder_lookup_path: return httpx.Response(200,json={"results":{"id":17}})
        if request.url.path == owner._secret_lookup_path: return httpx.Response(404,json={})
        pytest.fail("Uncompiled route")
    owner._client = httpx.Client(base_url=owner._config.base_url,transport=httpx.MockTransport(handle))
    owner._clock = lambda:100.0; owner._expires_at=500.0
    class Reader:
        def __init__(self, config, **kwargs): state["ssh"].append((config,kwargs))
        def read_namespace(self): return SecretNamespaceObservation(
            "name_absent" if state["absent"] else "name_present", 10, 2, "c"*64, state["absent"])
    monkeypatch.setattr(module,"FortiPamSecretNamespaceSshReader",Reader)
    def inspect(self,*args,**kwargs):
        assert self is owner and state["ssh"]
        return "synthetic-projection"
    monkeypatch.setattr(module.FortiPamSecretMetadataHttpTransport,"inspect_projection",inspect)
    yield owner,s,b,state,current,policy,role,collection
    owner._client.close()


def test_absent_projection_requires_complete_owner_state_policy_and_independent_namespace(source):
    owner,s,b,state,*_ = source
    assert owner.inspect_projection(s.folder_path,s.secret_name,"Windows Machine",s.target_name) == "synthetic-projection"
    assert state["credentials"] == len(state["ssh"]) == 1
    config,parameters=state["ssh"][0]
    assert config.username==s.owner_name and parameters == dict(candidate_name=s.secret_name,
        positive_witness_names=("KnownOne","KnownTwo"),expected_device_serial=s.expected_serial)
    assert state["calls"].index("/api/v2/cmdb/secret/policy/"+s.policy_name) < state["calls"].index(owner._secret_lookup_path)


@pytest.mark.parametrize("fault", ["role","serial","folder","acl","policy-other-field","clipboard","namespace-present","missing-witness","pagination"])
def test_no_api_invisibility_or_partial_evidence_can_qualify_absence(source,fault):
    owner,s,b,state,current,policy,role,collection=source
    if fault=="role": role["results"][0]["accprofile"]="read_only"
    elif fault=="serial": role["serial"]="OTHER_SERIAL"
    elif fault=="folder": current["inherit-policy"]="enable"
    elif fault=="acl": current["user-permission"][0]["secret-permission"]="viewer"
    elif fault=="policy-other-field": policy["results"][0]["need-approval"]="enable"
    elif fault=="clipboard": policy["results"][0]["block-clipboard"]="disable"
    elif fault=="namespace-present": state["absent"]=False
    elif fault=="missing-witness": collection["results"][1]["id"]=53
    elif fault=="pagination": collection["limit_reached"]=True
    with pytest.raises(SecretMetadataHttpTransportError):
        owner.inspect_projection(s.folder_path,s.secret_name,"Windows Machine",s.target_name)
    assert len(state["ssh"]) == int(fault=="namespace-present")


@pytest.mark.parametrize("fault",['private','root','launcher'])
def test_matching_configured_digest_cannot_widen_the_public_child_profile(source,fault):
    owner,s,b,state,current,*_=source
    if fault=='private':current['folder-type']='private'
    elif fault=='root':current['parent-folder']=0
    else:current['user-permission'][0]['allowed-launcher-type']='selected'
    owner._rdp=replace(s,folder_state_digest=module.folder_snapshot_digest(current))
    with pytest.raises(SecretMetadataHttpTransportError):owner.inspect_projection(s.folder_path,s.secret_name,'Windows Machine',s.target_name)
    assert state['ssh']==[]


@pytest.mark.parametrize("field,value", [("folder_path","other/folder"),("secret_name","mcp-v4-secret-metadata-other"),
    ("target_name","other-target"),("template_name","Unix Account"),("target_protocol","ssh"),("policy_folder_id",18)])
def test_binding_attenuation_rejects_before_owner_login(tmp_path,field,value):
    s=settings(tmp_path);b=replace(_rdp_binding(),template_name="Windows Machine")
    s.check_binding(b)
    with pytest.raises(ValueError):s.check_binding(replace(b,**{field:value}))


@pytest.mark.parametrize("fault", [None,"duplicate","mode","unknown","witness-bool","contract"])
def test_owner_settings_loader_is_opt_in_private_and_closed(tmp_path,fault):
    assert module.load_rdp_owner_settings({})is None
    s=settings(tmp_path);body=asdict(s);body["ssh_known_hosts_file"]=str(s.ssh_known_hosts_file)
    body["witness_secret_ids"]=list(s.witness_secret_ids);body["contract"]=module.CONTRACT
    if fault=="unknown":body["password"]="must-not-be-accepted"
    if fault=="witness-bool":body["witness_secret_ids"]=[True,52]
    if fault=="contract":body["contract"]="another-contract"
    raw=json.dumps(body)
    if fault=="duplicate":raw=raw.replace('"folder_id": 17','"folder_id": 17,"folder_id": 17')
    path=tmp_path/"binding.json";path.write_text(raw);path.chmod(0o644 if fault=="mode"else 0o600)
    env={module.PREFIX+"ENABLED":"true",module.PREFIX+"BINDING_FILE":str(path)}
    if fault:
        with pytest.raises(ValueError):module.load_rdp_owner_settings(env)
    else:assert module.load_rdp_owner_settings(env)==s


@pytest.mark.parametrize("fault", [None,"host","method","id","query","body","expired"])
def test_rdp_detail_connection_preserves_fixed_route_cookie_and_tls_boundary(tmp_path,fault):
    s=settings(tmp_path);calls=[]
    class Raw:
        def __init__(self,*args,**kwargs):calls.append(("construct",args,kwargs))
        def request(self,*args,**kwargs):calls.append(("request",args,kwargs))
    owner=module.OwnerRdpSessionMetadataTransport(SecretMetadataHttpTransportConfig("https://pam.example.test","api-token",5,None),
        s,lambda:pytest.fail("no credentials during construction"),connection_factory=Raw)
    owner._client=httpx.Client(base_url=owner._config.base_url,cookies={"session":"synthetic-cookie"})
    owner._secret_id=99;owner._clock=lambda:100;owner._expires_at=90 if fault=="expired"else 500
    try:
        if fault in {"host","expired"}:
            with pytest.raises(SecretMetadataHttpTransportError):owner._metadata_connection("other.test"if fault=="host"else"pam.example.test",443)
            assert not calls;return
        connection=owner._metadata_connection("pam.example.test",443,context="caller-TLS-must-be-ignored")
        assert calls[0][1]==("pam.example.test",443)and calls[0][2]["context"]!="caller-TLS-must-be-ignored"
        path=f'{module.COLLECTION_PATH}/{98 if fault=="id"else 99}?{module._SECRET_METADATA_DETAIL_QUERY}'
        if fault=="query":path+='&password=reveal'
        args=("POST"if fault=="method"else"GET",path)
        kwargs=dict(body=memoryview(b"x")if fault=="body"else None,headers={"Authorization":"must-not-pass"})
        if fault:
            with pytest.raises(SecretMetadataHttpTransportError):connection.request(*args,**kwargs)
            assert len(calls)==1
        else:
            connection.request(*args,**kwargs)
            assert "Authorization"not in calls[1][2]["headers"]and calls[1][2]["headers"]["Cookie"]=="session=synthetic-cookie"
    finally:owner._client.close()


def test_planning_source_authenticates_only_after_original_binding_validation(source,monkeypatch):
    owner,s,b,state,*_=source
    events=[]
    @contextmanager
    def authenticated():events.append("login");yield owner;events.append("logout")
    monkeypatch.setattr(owner,"authenticated",authenticated)
    class Resolver:
        binding=b
        def resolve(self,*args):events.append("resolve");return self.binding
    resolver=Resolver()
    planning=module.OwnerRdpPlanningSource(owner,None,None,resolver)
    monkeypatch.setattr(module.FortiPamSecretOnboardingProjectionSource,"project",lambda *a,**k:events.append("project")or())
    assert planning.project(_rdp_draft(),object(),now_epoch=1000)==()
    assert events==["resolve","login","project","logout"]
    resolver.binding=replace(b,target_name="foreign")
    events.clear()
    with pytest.raises(ValueError):planning.project(_rdp_draft(),object(),now_epoch=1000)
    assert events==["resolve"]


@pytest.mark.parametrize("fault", [None,"profile","provider","foreign-binding"])
def test_actual_runner_factory_binds_owner_to_exact_rdp_plan_without_reading_material(tmp_path,fault):
    from fortipam_mcp.secret_create_lab_auto_runtime import (
        FortiPam191LabAutoSecretCreateRunnerFactory, LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE,
    )
    from fortipam_mcp.owner_collector_runtime import OwnerAuthenticatedCollectorRuntime
    from fortipam_mcp.onboarding_action_coordinator import FixedActionResolutionError,OnboardingActionCoordinatorError
    from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
    from test_secret_create_lab_auto_runtime import _promoter
    from test_secret_onboarding_action_sequence import _Services
    from v4_planning import InMemoryM4ExecutionStateStore,MaterialReferenceMetadata
    from v4_planning.material_runtime import InMemoryMaterialUseStateStore
    services=_Services();s=settings(tmp_path)
    path=tmp_path/'bindings.yaml'
    path.write_text('schema_version: credential-bindings-v1\nbindings:\n  - id: fixed-secret-create\n    provider: env-file\n    variables:\n      username: FIXED_TEST_USERNAME\n      password: FIXED_TEST_PASSWORD\n');path.chmod(0o600)
    missing=tmp_path/'material-must-remain-unread.env'
    kwargs=dict(promoter=_promoter(services,'fortipam-191'if fault=='profile'else LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE),
        credential_bindings_path=path,secret_env_path=missing,material_binding_ref='private-material-binding-ref01',
        credential_binding_id='fixed-secret-create',transport_config=SecretMetadataHttpTransportConfig('https://pam.example.test','token',5,None),
        material_state_store=InMemoryMaterialUseStateStore(),execution_store=InMemoryM4ExecutionStateStore(),
        rdp_owner_settings=s,owner_credentials=None if fault=='provider'else lambda:pytest.fail('binding must not load Owner credentials'),
        clock=lambda:services.plan.created_at+1)
    if fault in {'profile','provider'}:
        with pytest.raises(OnboardingActionCoordinatorError):FortiPam191LabAutoSecretCreateRunnerFactory(**kwargs)
        return
    factory=FortiPam191LabAutoSecretCreateRunnerFactory(**kwargs)
    binding=replace(_rdp_binding(),template_name='Windows Machine',target_name='foreign'if fault=='foreign-binding'else s.target_name)
    draft=replace(_rdp_draft(),material_reference_metadata=MaterialReferenceMetadata(
        provider_class='central_lab_inventory_reference',purpose='initial_onboarding',lifecycle='available'))
    args=(services.plan,services.plan.lines[0].line_ref,V4PlanningPrincipal(services.requester,'a'*64))
    if fault:
        with pytest.raises(FixedActionResolutionError):factory.bind(*args,draft=draft,onboarding_binding=binding)
    else:
        runner=factory.bind(*args,draft=draft,onboarding_binding=binding)
        assert type(runner.runtime)is OwnerAuthenticatedCollectorRuntime
        session=runner.runtime._session
        assert type(session)is module.OwnerRdpSessionMetadataTransport and session._rdp is s
        assert session._allow_secret_create is True and session._create_dispatched is False
    assert not missing.exists()


@pytest.mark.parametrize("fault", [None,'profile','provider','secret'])
def test_genuine_main_selects_rdp_owner_source_only_for_the_bound_profile(tmp_path,monkeypatch,fault):
    from types import SimpleNamespace
    from fortipam_mcp import http_server as host,owner_collector_runtime
    from fortipam_mcp.secret_create_lab_auto_runtime import LAB_AUTO_SECRET_CREATE_ENV_PREFIX,LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE
    s=settings(tmp_path)
    monkeypatch.setenv(LAB_AUTO_SECRET_CREATE_ENV_PREFIX+'PROFILE','fortipam-191'if fault=='profile'else LAB_AUTO_SECRET_CREATE_RDP_700_CANDIDATE_PROFILE)
    selected=SimpleNamespace(v4_confirmation=object())
    hs=SimpleNamespace(host_mode='source-backed-secret-onboarding',secret_onboarding_binding_path=tmp_path/'binding.json')
    resolver=SimpleNamespace(bound_secret_name=lambda:'other'if fault=='secret'else s.secret_name)
    monkeypatch.setattr(host,'load_http_runtime_environment',lambda:False)
    monkeypatch.setattr(host.HttpServerSettings,'from_environment',classmethod(lambda cls:selected))
    monkeypatch.setattr(host,'synthetic_host_settings_from_environment',lambda env:hs)
    monkeypatch.setattr(host,'OwnerOnlySecretOnboardingBindingResolver',lambda path:resolver)
    monkeypatch.setattr(host,'load_secret_metadata_http_transport_config',lambda env:SecretMetadataHttpTransportConfig('https://pam.example.test','token',5,None))
    monkeypatch.setattr(host,'load_target_http_transport_config',lambda env:'target-config')
    monkeypatch.setattr(host,'FortiPamTargetHttpTransport',lambda config:'target-reader')
    monkeypatch.setattr(module,'load_rdp_owner_settings',lambda env:s)
    monkeypatch.setattr(owner_collector_runtime,'owner_login_provider',lambda env:None if fault=='provider'else lambda:pytest.fail('startup cannot resolve Owner credentials'))
    class Selected(Exception):pass
    def factory(actual,**kwargs):
        assert actual is hs and kwargs['binding_resolver']is resolver
        assert type(kwargs['secret_transport'])is module.OwnerRdpSessionMetadataTransport
        assert kwargs['secret_transport']._rdp is s and kwargs['folder_policy_transport']is kwargs['secret_transport']
        assert kwargs['target_transport']=='target-reader'
        raise Selected
    monkeypatch.setattr(host,'secret_onboarding_v4_plan_host_factory',factory)
    if fault:
        with pytest.raises(SystemExit,match='fixed RDP Owner profile'):host.main()
    else:
        with pytest.raises(Selected):host.main()
