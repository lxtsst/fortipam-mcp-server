"""One original fixed POST joins real authority/material/custody in actual M4."""
import http.client

import pytest
from v4_planning import M4AdapterDenied, M4ExecutionKernel

from fortipam_mcp.local_user_reset_fixture_create_adapter import LocalResetFixtureCreateAdapter, _POST
from fortipam_mcp.local_user_reset_fixture_custody import _ABSENCE, _ACK, _STATE
from test_local_user_reset_fixture_authority import authority, issue, custody
from test_local_user_reset_fixture_material import Harness
from test_local_user_reset_fixture_custody import response as ack_body


class Native:
    def __init__(self,h,*,fault=None):
        self.h,self.fault=h,fault
        self.calls=[];self.resources=[];self.buffers=[]

    def factory(self,host,port,*,timeout,context):
        assert host=="pam.example.test" and port==9443 and timeout>0 and context.check_hostname
        n=self
        class Response:
            status=403 if n.fault=="status" else 200
            closed=False
            offset=0
            def getheader(self,name,default=""):
                return {"content-type":"text/html" if n.fault=="content-type" else "application/json",
                    "content-encoding":"gzip" if n.fault=="encoding" else "identity"}.get(name.lower(),default)
            def readinto(self,view):
                n.buffers.append(view.obj)
                raw=ack_body(mkey="mcp-v4-user-reset-foreign") if n.fault=="ack" else ack_body()
                count=min(len(view),len(raw)-self.offset);view[:count]=raw[self.offset:self.offset+count];self.offset+=count
                return count
            def close(self):self.closed=True
        class Connection:
            sock=None
            closed=False
            def connect(self):
                if n.fault=="connect":raise OSError
                if n.fault=="source-after-tls":n.h.network.failure="role"
            def request(self,method,path,*,body,headers):
                assert method=="POST" and path==_POST and body.readonly
                assert headers["Authorization"]=="Bearer synthetic-token" and headers["User-Agent"]
                assert b'"password":' in body.obj
                assert (n.h.root/"custody"/_ABSENCE).exists() and (n.h.directory/"initial-material.used.json").exists()
                n.calls.append((method,path));n.buffers.append(body.obj);n.h.network.present=True
                if n.fault=="post":raise http.client.RemoteDisconnected
                if n.fault=="interrupt":raise KeyboardInterrupt
                if n.fault=="full-state":n.h.network.record["q_ref"]=1
            def getresponse(self):
                n.resources.append(response)
                return response
            def close(self):
                self.closed=True
                if n.fault=="close":raise OSError
        response=Response();connection=Connection();self.resources.append(connection);return connection


def make(root,monkeypatch,*,fault=None,enabled=True):
    h=Harness(root,monkeypatch);h.stage();issuer=authority(h);_,packet=issue(h,issuer);original=custody(h,packet)
    native=Native(h,fault=fault)
    adapter=LocalResetFixtureCreateAdapter(h.source,original,h.material,issuer,packet,
        execution_enabled=enabled,connection_factory=native.factory)
    return h,issuer,packet,original,native,adapter


def execute(h,issuer,packet,adapter):
    return M4ExecutionKernel(adapter,issuer,h.store,clock=lambda:h.now).execute(packet.plan,packet.authorization)


def test_fixed_original_http_and_exact_global_delta_qualify_once(tmp_path,monkeypatch):
    h,issuer,packet,original,native,adapter=make(tmp_path,monkeypatch)
    result=execute(h,issuer,packet,adapter)
    assert str(result.outcome)=="succeeded" and len(native.calls)==h.store.claim_count==1
    assert original.inspect_original_full_state().original_ack.original_verification=="verified"
    assert original.inspect_original_absence().presence_namespace_digest==h.source._current.namespace_digest
    assert all(r.closed for r in native.resources) and all(not any(b) for b in native.buffers)
    with pytest.raises(M4AdapterDenied):adapter.dispatch(packet.plan)
    assert len(native.calls)==h.store.claim_count==1
    adapter.close();issuer.close();h.material.close();original.close();h.source.close()


@pytest.mark.parametrize("fault",["status","content-type","encoding","ack","post","full-state","close"])
def test_consumed_or_uncertain_post_never_replays_or_promotes_original(tmp_path,monkeypatch,fault):
    h,issuer,packet,original,native,adapter=make(tmp_path,monkeypatch,fault=fault)
    result=execute(h,issuer,packet,adapter)
    assert str(result.verification)=="unknown" and len(native.calls)==h.store.claim_count==1
    assert all(r.closed for r in native.resources) and all(not any(b) for b in native.buffers)
    if fault=="close":
        assert original.inspect_original_full_state().original_ack.original_verification=="unknown"
        assert authority(h,phase="recover",original=original)
    else:
        with pytest.raises(ValueError):original.inspect_original_full_state()
    with pytest.raises(M4AdapterDenied):adapter.dispatch(packet.plan)
    assert len(native.calls)==1


@pytest.mark.parametrize("fault",["connect","source-after-tls","gate","detached"])
def test_unqualified_prerequisites_do_not_send_a_post(tmp_path,monkeypatch,fault):
    h,issuer,packet,original,native,adapter=make(tmp_path,monkeypatch,fault=fault,enabled=fault!="gate")
    if fault=="detached":
        with pytest.raises(M4AdapterDenied):adapter.dispatch(packet.plan)
        assert h.store.claim_count==0 and not list(original._directory.iterdir())
    else:
        result=execute(h,issuer,packet,adapter)
        assert str(result.verification)=="not_started" and h.store.claim_count==1
    assert not native.calls and not (original._directory/_ACK).exists()
    assert not (h.directory/"initial-material.used.json").exists()
    assert all(r.closed for r in native.resources)


def test_original_dispatch_interruption_retains_in_progress_and_clears_buffers(tmp_path,monkeypatch):
    h,issuer,packet,original,native,adapter=make(tmp_path,monkeypatch,fault="interrupt")
    with pytest.raises(KeyboardInterrupt):execute(h,issuer,packet,adapter)
    assert len(native.calls)==h.store.claim_count==1
    assert not (original._directory/_ACK).exists() and not (original._directory/_STATE).exists()
    assert all(r.closed for r in native.resources) and all(not any(b) for b in native.buffers)
    with pytest.raises(M4AdapterDenied):adapter.dispatch(packet.plan)
