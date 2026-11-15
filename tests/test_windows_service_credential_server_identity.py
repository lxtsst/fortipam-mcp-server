"""Verified requester boundary; synthetic identities/product IO, real local stores."""
import asyncio
import ipaddress
from dataclasses import replace
import pickle
import ssl

import pytest
from mcp.server.auth.provider import AccessToken
from starlette.testclient import TestClient

from fortipam_mcp import http_server
from fortipam_mcp import windows_service_credential_http_transport as wire
from fortipam_mcp import windows_service_credential_readback as readback
from fortipam_mcp import windows_service_credential_recovery as recovery
from fortipam_mcp import windows_service_credential_server_identity as identity
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings
from fortipam_mcp.windows_service_credential_authority import windows_service_credential_state_digest
from fortipam_mcp.windows_service_credential_birth import WindowsServiceCredentialBirthCustody
from fortipam_mcp.windows_service_credential_folder_dependencies import service_credential_folder_context_digest
from fortipam_mcp.windows_service_credential_material import windows_service_credential_material_runtime
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_http_server import (_v4_controlled_environment, _register_public_client,
    _authorize_and_login, _request_headers, V4_FOLDER_ACTION_FEATURE_ENV)
from test_m4_execution_store import _ExternalM4Checkpoint
from test_secret_create_m4_runtime import _Reader
from test_windows_service_credential_authority import key
from test_windows_service_credential_http_transport import Source
from test_windows_service_credential_lifecycle import execute
from test_windows_service_credential_owner_auth import Login, OwnerWire, owner_birth
from test_windows_service_credential_recovery import Source as RemovalSource
from test_windows_service_credential_folder_dependencies import setup as folder_setup
from v4_planning import M4AuthorizationDenied, M4Outcome


def token(**overrides):
    return AccessToken(**{**dict(token="PRIVATE_SDK_TOKEN_SENTINEL", client_id="synthetic-client-one",
        subject="synthetic-human-one", resource="https://mcp.example.test/mcp", expires_at=5000,
        scopes=["fortipam:read", "fortipam:plan", "fortipam:operate"],
        claims={"iss":"https://mcp.example.test/oauth"}), **overrides})


def setup(*, enabled=True, value=None):
    current, now = [token() if value is None else value], [1000]
    options = dict(settings=V4PlanningAuthorizationSettings("https://mcp.example.test/mcp", b"p"*32),
        runtime_profile=RuntimeProfile.V4_CONTROLLED, environment_ref="owner-lab-development",
        scope_ref="one-service-credential", audience_ref="fixed-client", enabled=enabled,
        token_provider=lambda:current[0], clock=lambda:now[0])
    return identity.WindowsServiceCredentialServerIdentity(**options), current, now, options


@pytest.mark.parametrize("fault", ["none", "dict", "plan-only", "operate-only", "approval", "resource",
    "issuer", "subject", "client", "expired", "no-expiry"])
def test_unqualified_identity_refuses_before_native_source(fault):
    boundary, current, _, _ = setup()
    if fault == "none": current[0] = None
    elif fault == "dict": current[0] = token().model_dump()
    elif fault == "plan-only": current[0] = token(scopes=["fortipam:plan"])
    elif fault == "operate-only": current[0] = token(scopes=["fortipam:operate"])
    elif fault == "approval": current[0] = token(scopes=token().scopes+["fortipam:approve"])
    elif fault == "resource": current[0] = token(resource="https://different.example.test/mcp")
    elif fault == "issuer": current[0] = token(claims={})
    elif fault == "subject": current[0] = token(subject=None)
    elif fault == "client": current[0] = token(client_id="")
    elif fault == "expired": current[0] = token(expires_at=1000)
    elif fault == "no-expiry": current[0] = token(expires_at=None)
    with pytest.raises(identity.WindowsServiceCredentialServerIdentityError): boundary.capture(purpose="create")
    boundary.close()
    assert not boundary._key


@pytest.mark.parametrize("fault", ["disabled", "readonly", "plan-only", "string-profile", "insecure"])
def test_default_closed_and_transport_profile_refuse(fault):
    _, _, _, options = setup()
    if fault == "disabled": options.pop("enabled")
    elif fault == "readonly": options["runtime_profile"] = RuntimeProfile.READONLY
    elif fault == "plan-only": options["runtime_profile"] = RuntimeProfile.V4_PLAN_ONLY
    elif fault == "string-profile": options["runtime_profile"] = "v4-controlled"
    elif fault == "insecure":
        # The planner admits this synthetic test-only CIDR; the service
        # boundary must still reject its insecure transport.
        lab_host = str(ipaddress.IPv4Address(0x0A000001))
        options["settings"] = V4PlanningAuthorizationSettings(f"http://{lab_host}/mcp", b"p"*32, True)
    with pytest.raises(identity.WindowsServiceCredentialServerIdentityError):
        boundary = identity.WindowsServiceCredentialServerIdentity(**options)
        boundary.capture(purpose="create")


@pytest.mark.parametrize("fault", ["human", "client", "token", "expiry", "time", "rollback", "clock",
    "provider", "scope", "key", "copy", "tamper", "purpose", "foreign-boundary", "close"])
def test_snapshot_is_bound_to_current_request_client_token_and_instance(fault):
    boundary, current, now, options = setup()
    snapshot = boundary.capture(purpose="create")
    purpose = "create"
    if fault == "human": current[0] = token(subject="another-human")
    elif fault == "client": current[0] = token(client_id="another-client")
    elif fault == "token": current[0] = token(token="another-verified-token")
    elif fault == "expiry": current[0] = token(expires_at=5001)
    elif fault == "time": now[0] = 5000
    elif fault == "rollback": now[0] = 999
    elif fault == "clock": boundary._clock = lambda:1000
    elif fault == "provider": boundary._provider = lambda:token()
    elif fault == "scope": boundary._scope = "changed-scope"
    elif fault == "key": object.__setattr__(boundary._settings, "namespace_hmac_key", b"k"*32)
    elif fault == "copy": snapshot = replace(snapshot)
    elif fault == "tamper": object.__setattr__(snapshot, "context_digest", "f"*64)
    elif fault == "purpose": purpose = "recovery"
    elif fault == "foreign-boundary": boundary = identity.WindowsServiceCredentialServerIdentity(**options)
    elif fault == "close": boundary.close()
    with pytest.raises(identity.WindowsServiceCredentialServerIdentityError): boundary.require_current(snapshot,purpose=purpose)
    if fault == "rollback":
        now[0] = 1001
        with pytest.raises(identity.WindowsServiceCredentialServerIdentityError): boundary.capture(purpose="create")


def test_stable_human_has_distinct_client_and_fresh_recovery_context_and_opaque_snapshots():
    boundary, current, _, _ = setup()
    first = boundary.capture(purpose="create")
    current[0] = token(client_id="independent-client", token="independent-verified-token")
    second = boundary.capture(purpose="recovery")
    assert first.requester_digest == second.requester_digest
    assert first.transport_digest != second.transport_digest and first.context_digest != second.context_digest
    boundary.require_original_requester(second, original_requester_digest=first.requester_digest)
    with pytest.raises(identity.WindowsServiceCredentialServerIdentityError):
        boundary.require_original_requester(second, original_requester_digest="b"*64)
    for value in (boundary,first,second):
        assert all(sentinel not in repr(value) for sentinel in ("PRIVATE_SDK", "synthetic-human", "synthetic-client"))
        with pytest.raises(Exception): pickle.dumps(value)


def test_source_guard_checks_identity_before_and_after_native_guard_and_exact_boolean():
    boundary, current, _, _ = setup()
    snapshot = boundary.capture(purpose="create")
    calls = []
    def native():
        calls.append(True)
        current[0] = token(client_id="changed-during-read")
        return True
    guarded = boundary.source_guard(snapshot,purpose="create",native_guard=native)
    assert guarded() is False and calls == [True]
    assert guarded() is False and calls == [True]
    current[0] = token()
    assert boundary.source_guard(snapshot,purpose="create",native_guard=lambda:1)() is False
    assert boundary.source_guard(snapshot,purpose="create",native_guard=lambda:True,grant_expiry=lambda:5001)() is False


@pytest.mark.parametrize("expires", [999,1000,5001,True])
def test_a_grant_cannot_outlive_the_verified_token_or_use_an_expired_window(expires):
    boundary, _, _, _ = setup()
    snapshot = boundary.capture(purpose="create")
    with pytest.raises(identity.WindowsServiceCredentialServerIdentityError):
        boundary.require_current(snapshot,purpose="create",grant_expires_at=expires)
    boundary.require_current(snapshot,purpose="create",grant_expires_at=5000)


def compose_create(tmp_path, monkeypatch, *, read_fault=None):
    cmp = owner_birth(tmp_path)
    boundary, current, now, _ = setup()
    source, login, log, available = Source(read_fault=read_fault), Login(), [], [True]
    snapshot = boundary.capture(purpose="create")
    authority = boundary.create_authority(snapshot,profile=cmp["kwargs"]["profile"],defaults=cmp["kwargs"]["defaults"],
        material_binding=cmp["kwargs"]["material_binding"], execution_store=cmp["execution"],material_store=cmp["material"],
        authority_key_file=key(tmp_path/"authority.key",b"a"*32),witness_key_file=cmp["key"],
        native_source_context_digest="c"*64, check_native_source=lambda:available[0] and source.guard(),
        owner_binding=cmp["owner_binding"],execution_enabled=True)
    actor = dict(requester_digest=snapshot.requester_digest, transport_digest=snapshot.transport_digest)
    preview = authority.preview(current_digest=windows_service_credential_state_digest(cmp["kwargs"]["profile"],exists=False), **actor)
    issued = authority.issue(preview,**actor)
    cmp["custody"].close()
    cmp["kwargs"].update(plan=issued.plan,authorization=issued.authorization,request=issued.lease_request,material_binding=issued.material_binding)
    cmp["birth_kwargs"].update(plan=issued.plan,authorization=issued.authorization,request=issued.lease_request)
    custody = WindowsServiceCredentialBirthCustody(cmp["directory"],cmp["key"],**cmp["birth_kwargs"])
    session = login.session(cmp["birth_kwargs"]["config"],cmp["owner_binding"])
    monkeypatch.setattr(wire,"_ssl_context",lambda config:ssl.create_default_context())
    monkeypatch.setattr(readback,"_ssl_context",lambda config:ssl.create_default_context())
    transport = wire.WindowsServiceCredentialHttpTransport(cmp["birth_kwargs"]["config"],custody,
        execution_enabled=True,source_guard=source.guard,owner_session=session,owner_authority=authority,
        connection_factory=lambda *args,**kwargs:OwnerWire(source.factory(*args,**kwargs),source,log),http_clock=lambda:0)
    material = windows_service_credential_material_runtime(**{**cmp["kwargs"],"transport":transport})
    reader = _Reader(post=issued.plan.expected_state_digest,onboarding_binding_digest=cmp["kwargs"]["profile"].parameters_digest)
    reader.read_current = lambda plan:plan.expected_current_digest
    outer = ProtectedSecretCreateM4Runtime(authority,authority,cmp["execution"],material,reader,
        authenticated_requester_digest=snapshot.requester_digest,clock=lambda:now[0])
    cmp.update(bound=issued,custody=custody,authority=authority,outer=outer,boundary=boundary,current=current,
        identity_now=now,snapshot=snapshot,session=session,login=login,source=source,wire=log,available=available)
    return cmp


@pytest.mark.parametrize("fault", ["token", "human", "client", "expired", "source", "closed"])
def test_changed_identity_refuses_actual_create_before_material_or_product_write(tmp_path,monkeypatch,fault):
    cmp = compose_create(tmp_path,monkeypatch)
    if fault == "token": cmp["current"][0] = token(token="new-token")
    elif fault == "human": cmp["current"][0] = token(subject="different-human")
    elif fault == "client": cmp["current"][0] = token(client_id="different-client")
    elif fault == "expired": cmp["identity_now"][0] = 5000
    elif fault == "source": cmp["available"][0] = False
    elif fault == "closed": cmp["boundary"].close()
    with cmp["session"].authenticated():
        try: result = execute(cmp)
        except M4AuthorizationDenied: result = None
        assert result is None or result.outcome is not M4Outcome.SUCCEEDED
    assert cmp["loader"].loads == cmp["material"].claim_count == 0 and not cmp["wire"]


@pytest.mark.parametrize("read_fault", [None,"password"])
def test_real_issuers_create_and_independently_recover_same_human_with_new_client(tmp_path,monkeypatch,read_fault):
    cmp = compose_create(tmp_path,monkeypatch,read_fault=read_fault)
    with cmp["session"].authenticated():
        assert execute(cmp).outcome is (M4Outcome.RECONCILIATION_REQUIRED if read_fault else M4Outcome.SUCCEEDED)
    original = cmp["custody"].inspect_original_creation()
    before = {p.name:p.read_bytes() for p in cmp["directory"].iterdir()}
    cmp["authority"].close(); cmp["custody"].close(); cmp["boundary"].close()
    boundary, current, now, _ = setup(value=token(client_id="independent-client",token="independent-token"))
    now[0] = cmp["now"][0] = 2000
    custody = WindowsServiceCredentialBirthCustody(cmp["directory"],cmp["key"],**cmp["birth_kwargs"])
    store = PersistentM4ExecutionStateStore(tmp_path/"remove.sqlite",key(tmp_path/"remove.key",b"r"*32),
        monotonic_checkpoint=_ExternalM4Checkpoint("server-identity-recovery"),checkpoint_store_ref="server-identity-recovery")
    source, login, log = RemovalSource(), Login(), []
    config = replace(cmp["birth_kwargs"]["config"],bearer_token="independent-synthetic-token")
    session = login.session(config,cmp["owner_binding"],purpose="recovery")
    snapshot = boundary.capture(purpose="recovery")
    monkeypatch.setattr(recovery,"_ssl_context",lambda config:ssl.create_default_context())
    authority,runtime = boundary.recovery_components(snapshot,custody=custody,execution_store=store,
        authority_key_file=key(tmp_path/"remove-authority.key",b"h"*32),
        witness_key_file=key(tmp_path/"remove-witness.key",b"w"*32),config=config,owner_session=session,
        check_native_source=source.guard,execution_enabled=True,
        connection_factory=lambda *args,**kwargs:OwnerWire(source.factory(*args,**kwargs),source,log),http_clock=lambda:0)
    actor = dict(requester_digest=snapshot.requester_digest,transport_digest=snapshot.transport_digest)
    assert actor["requester_digest"] == cmp["snapshot"].requester_digest
    assert actor["transport_digest"] != cmp["snapshot"].transport_digest
    with session.authenticated():
        grant = authority.issue(runtime,**actor)
        current[0] = token(client_id="changed-client",token="independent-token")
        with pytest.raises(ValueError): runtime._check_source()
        with pytest.raises(M4AuthorizationDenied): authority.verify(grant.plan,grant.authorization,now_epoch=now[0])
        assert not source.methods and store.claim_count == 0
        current[0] = token(client_id="independent-client",token="independent-token")
        assert runtime.execute(grant.plan,grant.authorization).outcome is M4Outcome.SUCCEEDED
    assert len(cmp["wire"]) == 8 and len(log) == 16 and source.methods == ["DELETE","GET"]
    assert cmp["execution"].claim_count == cmp["material"].claim_count == cmp["loader"].loads == store.claim_count == 1
    assert custody.inspect_original_creation() == original
    assert all((cmp["directory"]/name).read_bytes() == content for name,content in before.items())
    assert (cmp["directory"]/"create.full-birth.json").exists() == (read_fault is None)
    runtime.close(); authority.close(); boundary.close()
    assert not runtime._key and not authority._key and not boundary._key


def test_existing_configured_folder_requester_cannot_be_relabelled_as_oauth_human(tmp_path,monkeypatch):
    cmp = folder_setup(tmp_path,monkeypatch)
    boundary, _, _, _ = setup()
    snapshot = boundary.capture(purpose="create")
    before = {p:p.read_bytes() for item in (cmp["parent"],cmp["original"]) for p in item._directory.iterdir()}
    calls = len(cmp["api"].base.calls), list(cmp["native"].calls)
    with pytest.raises(identity.WindowsServiceCredentialServerIdentityError):
        boundary.require_original_requester(snapshot,original_requester_digest=cmp["original"]._plan.requester_digest)
    with pytest.raises(ValueError):
        service_credential_folder_context_digest(requester_digest=snapshot.requester_digest,
            sources=cmp["source"],original_folder=cmp["original"])
    assert calls == (len(cmp["api"].base.calls),cmp["native"].calls)
    assert all(p.read_bytes() == content for p,content in before.items())


def test_actual_local_oauth_and_mcp_sdk_context_carries_into_worker_thread(tmp_path,monkeypatch):
    environment = _v4_controlled_environment(tmp_path)
    environment[V4_FOLDER_ACTION_FEATURE_ENV] = "false"
    settings = http_server.HttpServerSettings.from_environment(environment)
    boundary = identity.WindowsServiceCredentialServerIdentity(settings.v4_planning_authorization,
        runtime_profile=settings.runtime_profile,environment_ref="local-protocol-lab",scope_ref="one-service-credential",
        audience_ref="protocol-test",enabled=True)
    snapshots = []
    original = http_server.FortiPamMcpServer
    def server_with_private_probe(*args,**kwargs):
        server = original(*args,**kwargs)
        @server.mcp.tool(name="private_test_service_requester")
        async def probe() -> dict[str,bool]:
            snapshot = boundary.capture(purpose="create")
            await asyncio.to_thread(boundary.require_current,snapshot,purpose="create")
            snapshots.append(snapshot)
            return {"accepted":True}
        return server
    monkeypatch.setattr(http_server,"FortiPamMcpServer",server_with_private_probe)
    def headers(client,scope):
        client_id = _register_public_client(client,scope)
        code,verifier = _authorize_and_login(client,client_id,scope)
        response = client.post("/fpamcp/oauth/token",data={"grant_type":"authorization_code","client_id":client_id,
            "code":code,"code_verifier":verifier,"redirect_uri":"https://client.example/callback",
            "resource":"https://mcp.example.com/fpamcp"})
        assert response.status_code == 200
        return {**_request_headers(response.json()["access_token"]),"host":"mcp.example.com"}
    def call(client,auth):
        return client.post("/fpamcp",headers=auth,json={"jsonrpc":"2.0","id":"identity-test",
            "method":"tools/call","params":{"name":"private_test_service_requester","arguments":{}}})
    with TestClient(http_server.create_http_app(settings),base_url="https://mcp.example.com") as client:
        assert call(client,{**_request_headers("invalid-token"),"host":"mcp.example.com"}).status_code == 401
        plan = headers(client,"fortipam:read fortipam:plan")
        assert call(client,plan).json()["result"]["isError"]
        assert not snapshots
        for _ in range(2):
            operate = headers(client,"fortipam:read fortipam:plan fortipam:operate")
            assert not call(client,operate).json()["result"]["isError"]
    assert len(snapshots) == 2 and snapshots[0].requester_digest == snapshots[1].requester_digest
    assert snapshots[0].transport_digest != snapshots[1].transport_digest
    with pytest.raises(identity.WindowsServiceCredentialServerIdentityError): boundary.capture(purpose="create")
