"""Actual v2 M4, fresh one-use next material and fixed synthetic target session."""
import json
from urllib.parse import parse_qs

import httpx
import pytest
from v4_planning import M4AuthorizationDenied,M4ExecutionKernel

from fortipam_mcp.local_user_reset_owned_adapter import LocalResetOwnedAdapter
from fortipam_mcp.local_user_reset_owned_login import LocalResetOwnedLogin
from fortipam_mcp.local_user_reset_owned_material import LOGIN_ACTION_ID,LOGIN_ADAPTER_REF,LOGIN_ACTION_VERSION
from fortipam_mcp.local_user_reset_owned_mcp import LocalResetOwnedMcpAction,LOGIN_CONTRACT
from fortipam_mcp.secret_metadata_http_transport import SYSTEM_STATUS_PATH
from test_local_user_reset_owned_material import Harness
from test_local_user_reset_owned_authority import authority,issue
from test_local_user_reset_owned_adapter import Native
from test_local_user_reset_fixture_custody import NAME,SERIAL
from test_local_user_reset_metadata_reader import _monitor


@pytest.fixture(autouse=True)
def no_wall_clock_settle(monkeypatch):
    monkeypatch.setattr('fortipam_mcp.local_user_reset_owned_login.sleep',lambda seconds:None)


class LoginPeer:
    def __init__(self,h,*,fault=None):
        self.h,self.fault=h,fault;self.calls=[];self.clients=[];self.active=False;self.posts=0
        schema=json.loads(h.h.network.schema)
        schema['results']['children']['login-time']={'children':{
            'last-failed-login':{'type':'datetime'},'last-login':{'type':'datetime'},
            'last-login-ip':{'type':'string'},'usr-name':{'type':'string'}}}
        h.h.network.schema=bytearray(json.dumps(schema).encode());h.h.network.record['login-time']=[]
    def factory(self,**kwargs):
        client=httpx.Client(**kwargs,transport=httpx.MockTransport(self.respond));self.clients.append(client);return client
    def respond(self,request):
        path=request.url.path;self.calls.append((request.method,path))
        assert 'authorization' not in request.headers
        if path=='/remote/login':
            return httpx.Response(200,text='no form' if self.fault=='form' else '<form action="/XX/YY/ZZ/AUTH">')
        if path=='/XX/YY/ZZ/AUTH':
            self.posts+=1;assert self.posts==1
            values=parse_qs(request.content.decode());assert set(values)=={'username','password','magic','4Tredir','4Tmthd'}
            assert values['username']==[NAME] and values['password']==[(self.h.root/'material/next-password').read_text()]
            assert not any(self.h.material._buffers[0]) and not any(self.h.material._buffers[1])
            if self.fault=='wire':raise httpx.ReadTimeout('Synthetic failure.')
            self.active=True
            return httpx.Response(403 if self.fault=='rejected' else 303,headers={'location':'https://foreign.test/' if self.fault=='redirect' else '/ng/'})
        if path=='/ng/':return httpx.Response(200)
        if path=='/logout':
            if self.fault!='logout':self.active=False
            return httpx.Response(200)
        if not self.active:return httpx.Response(401)
        if path==SYSTEM_STATUS_PATH:
            if self.fault=='status':return httpx.Response(403)
            return httpx.Response(200,json=dict(version='v7.0.0',build=29,serial='FOREIGN01' if self.fault=='serial' else SERIAL))
        assert path=='/api/v2/monitor/web-ui/state'
        self.h.h.network.record['login-time']=[{'last-failed-login':'','last-login':'2026-10-22 12:00:00',
            'last-login-ip':'192.0.2.10','usr-name':NAME,'q_origin_key':NAME}]
        if self.fault=='configuration':self.h.h.network.record['comments']='foreign'
        if self.fault=='expiry':self.h.now=1060
        name='foreign' if self.fault=='identity' else NAME
        return httpx.Response(200,content=bytes(_monitor('web-ui/state',dict(admin=dict(name=name,login_name=name,
            sponsored_group_name='',guest_admin=False)),serial=SERIAL)),headers={'content-type':'application/json'})


def prepare(root,monkeypatch,*,fault=None,verify_login=True):
    h=Harness(root,monkeypatch,verify_login=verify_login);h.stage();issuer=authority(h);_,packet=issue(h,issuer)
    native=Native(h);login=LoginPeer(h,fault=fault)
    adapter=LocalResetOwnedAdapter(h.material,issuer,packet,execution_enabled=True,connection_factory=native.factory,
        login_client_factory=login.factory)
    return h,issuer,packet,native,login,adapter


def execute(h,issuer,packet,adapter):
    return M4ExecutionKernel(adapter,issuer,h.store,clock=lambda:h.now).execute(packet.plan,packet.authorization)


def test_v2_one_m4_resets_logs_in_as_exact_target_logs_out_and_preserves_original(tmp_path,monkeypatch):
    h,issuer,packet,native,login,adapter=prepare(tmp_path,monkeypatch)
    original=h.inspector._original;before={p.name:p.read_bytes()for p in original._directory.iterdir()}
    assert (packet.plan.action_id,packet.plan.adapter_ref,packet.plan.action_version)==(LOGIN_ACTION_ID,LOGIN_ADAPTER_REF,LOGIN_ACTION_VERSION)
    result=execute(h,issuer,packet,adapter)
    assert str(result.outcome)=='succeeded' and str(result.verification)=='verified'
    assert len(native.calls)==2 and login.posts==1 and h.store.claim_count==1
    assert adapter._record('reset-result.json')['login_verified']is True
    assert h.h.network.record['login-time'] and h.h.source._state._current.state_digest==h.inspector._sealed.state_digest
    assert adapter._record('login-result.json')['logout_verified']is True
    assert all(client.is_closed and not client.cookies for client in login.clients)
    assert all(not any(raw)for raw in h.material._buffers) and adapter._login._client is None
    assert (h.root/'material/login-material.used.json').is_file()
    assert before=={p.name:p.read_bytes()for p in original._directory.iterdir()}
    calls=len(login.calls);replay=execute(h,issuer,packet,adapter)
    assert replay.idempotent_replay and len(login.calls)==calls and login.posts==1
    with pytest.raises(ValueError):h.material.acquire_login(adapter)
    assert login.posts==1


@pytest.mark.parametrize('fault',['form','wire','rejected','redirect','status','serial','identity','logout','configuration','expiry'])
def test_login_or_following_state_failure_cannot_complete_promote_or_retry(tmp_path,monkeypatch,fault):
    h,issuer,packet,native,login,adapter=prepare(tmp_path,monkeypatch,fault=fault)
    result=execute(h,issuer,packet,adapter)
    assert str(result.verification)=='unknown' and len(native.calls)==2 and h.store.claim_count==1
    assert login.posts==(0 if fault=='form' else 1)
    assert not (h.root/'material/reset-result.json').exists() and (h.root/'material/reset-failure.json').is_file()
    assert all(client.is_closed and not client.cookies for client in login.clients)
    assert all(not any(raw)for raw in h.material._buffers)
    if login.posts:
        record=adapter._record('login-result.json')
        assert record['login_verified']is (fault in {'logout','configuration','expiry'})
    calls=len(login.calls)
    if fault=='expiry':
        with pytest.raises(M4AuthorizationDenied):execute(h,issuer,packet,adapter)
    else:assert execute(h,issuer,packet,adapter).idempotent_replay
    assert len(login.calls)==calls


def test_v1_contract_cannot_construct_or_acquire_target_login(tmp_path,monkeypatch):
    h,issuer,packet,native,login,adapter=prepare(tmp_path,monkeypatch,verify_login=False)
    with pytest.raises(ValueError):LocalResetOwnedLogin(adapter,client_factory=login.factory)
    assert str(execute(h,issuer,packet,adapter).outcome)=='succeeded'
    assert not login.calls and not (h.root/'material/login-material.used.json').exists()
    with pytest.raises(ValueError):h.material.acquire_login(adapter)


def test_detached_v2_invocation_cannot_load_material_or_send_login(tmp_path,monkeypatch):
    h,issuer,packet,native,login,adapter=prepare(tmp_path,monkeypatch)
    result=LocalResetOwnedLogin(adapter,client_factory=login.factory).run()
    assert not result['login_verified'] and not login.calls
    assert not (h.root/'material/login-material.used.json').exists() and h.store.claim_count==0


def test_execution_mode_drift_is_rejected_before_authority_or_material(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch,verify_login=True);h.stage();h.material._verify_login=False
    with pytest.raises(ValueError):h.material.check_staged()
    assert h.store.claim_count==0 and not h.material._loaded


@pytest.mark.parametrize('fault',[None,'identity','configuration','logout'])
def test_v2_mcp_preview_binds_login_effect_and_distinguishes_authentication_from_other_failure(tmp_path,monkeypatch,fault):
    from v4_planning import AuthenticatedRequester
    from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
    h=Harness(tmp_path,monkeypatch,verify_login=True);h.stage();native=Native(h);login=LoginPeer(h,fault=fault)
    action=LocalResetOwnedMcpAction(h.material,authority_key=b'j'*32,environment_ref='owned-reset-mcp-environment',
        scope_ref='owned-reset-mcp-scope',audience_ref='owned-reset-mcp-audience',transport_digest='c'*64,
        execution_enabled=True,clock=lambda:h.now,connection_factory=native.factory,login_client_factory=login.factory)
    principal=V4PlanningPrincipal(AuthenticatedRequester('owned-reset-operator-0001','operator'),'b'*64)
    preview=action.preview(principal)
    assert preview['contract']==LOGIN_CONTRACT and preview['authentication_verified']is False
    assert preview['Proposed Changes']['new_password_login_attempts']==1
    assert preview['Expected State']['authentication_verified']is True
    issued=action.authorize(preview['preview_ref'],principal);result=action.execute(issued['authorization_ref'],principal)
    assert result['contract']==LOGIN_CONTRACT and result['backend_change_acknowledged']is True
    assert result['authentication_verified']is (fault!='identity')
    assert result['complete_nonmaterial_state_preserved']is (True if fault is None else None)
    assert result['target_logout_verified']is (fault!='logout')
    assert result['outcome']==('succeeded'if fault is None else 'reconciliation_required')
    public=json.dumps((preview,issued,result))
    for private in (NAME,SERIAL,str(tmp_path),'initial-password','next-password','synthetic-token'):
        assert private not in public
    calls=len(login.calls);assert action.execute(issued['authorization_ref'],principal)['idempotent_replay']
    assert len(login.calls)==calls and h.store.claim_count==1
    action.close();assert not action._enabled and adapter_closed(action)


def adapter_closed(action):
    record=next(iter(action._records.values()))
    return record.adapter._closed and record.adapter._login._client is None


def test_next_material_tamper_after_successful_change_never_sends_target_login(tmp_path,monkeypatch):
    from fortipam_mcp.local_user_reset_http_transport import _CHANGE_PATH
    h,issuer,packet,native,login,adapter=prepare(tmp_path,monkeypatch)
    original=native.factory
    def factory(*args,**kwargs):
        raw=original(*args,**kwargs);request=raw.request
        def send(method,path,**values):
            request(method,path,**values)
            if path==_CHANGE_PATH:(h.root/'material/next-password').write_bytes(b'ForeignSyntheticNextMaterial12345!')
        raw.request=send;return raw
    adapter._factory=factory
    result=execute(h,issuer,packet,adapter)
    assert str(result.verification)=='unknown' and len(native.calls)==2 and not login.posts
    assert (h.root/'material/login-material.used.json').exists()
    assert not (h.root/'material/reset-result.json').exists() and all(not any(raw)for raw in h.material._buffers)


def test_target_client_close_failure_stays_unknown_and_shutdown_closes_retained_resource(tmp_path,monkeypatch):
    h,issuer,packet,native,login,adapter=prepare(tmp_path,monkeypatch)
    factory=login.factory
    def fragile(**kwargs):
        client=factory(**kwargs);close=client.close;attempts=[]
        def closing():
            attempts.append(True)
            if len(attempts)==1:raise OSError('Synthetic first close failure.')
            close()
        client.close=closing;return client
    adapter._login_factory=fragile
    result=execute(h,issuer,packet,adapter)
    assert str(result.verification)=='unknown' and login.posts==1
    assert adapter._record('login-result.json')['resources_closed']is False
    assert adapter._login._client is not None
    calls=len(login.calls);adapter.close()
    assert adapter._login._client is None and adapter._login._resources_closed
    assert len(login.calls)==calls and all(client.is_closed for client in login.clients)
    assert adapter._record('login-result.json')['resources_closed']is False


def test_interrupt_during_target_auth_retains_one_claim_and_original_send_without_retry(tmp_path,monkeypatch):
    h,issuer,packet,native,login,adapter=prepare(tmp_path,monkeypatch)
    respond=login.respond
    def interrupted(request):
        response=respond(request)
        if request.url.path=='/XX/YY/ZZ/AUTH':raise KeyboardInterrupt
        return response
    def factory(**kwargs):
        client=httpx.Client(**kwargs,transport=httpx.MockTransport(interrupted));login.clients.append(client);return client
    adapter._login_factory=factory
    with pytest.raises(KeyboardInterrupt):execute(h,issuer,packet,adapter)
    assert len(native.calls)==2 and login.posts==1 and h.store.claim_count==1
    assert (h.root/'material/login-send.json').exists() and not (h.root/'material/reset-result.json').exists()
    assert adapter._record('login-result.json')['login_verified']is False
    assert all(client.is_closed for client in login.clients) and all(not any(raw)for raw in h.material._buffers)
    calls=len(login.calls);adapter.close();assert len(login.calls)==calls
