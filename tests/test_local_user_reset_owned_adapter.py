"""Actual M4 drives the fixed Owner session, two REST requests and original ACKs."""
import io
import json

import pytest
from v4_planning import M4AdapterDenied,M4ExecutionKernel

from fortipam_mcp.local_user_reset_owned_adapter import LocalResetOwnedAdapter
from fortipam_mcp.local_user_reset_http_transport import _POLICY_PATH,_CHANGE_PATH
from test_local_user_reset_owned_material import Harness
from test_local_user_reset_owned_authority import authority,issue
from test_local_user_reset_fixture_custody import NAME,SERIAL


class Native:
    def __init__(self,h,*,fault=None):
        self.h,self.fault=h,fault;self.calls=[];self.resources=[];self.buffers=[]
    def factory(self,*args,**kwargs):
        n=self
        class Response:
            closed=False;status=403 if n.fault=="http403" else 200
            def __init__(self,path):
                result={"valid":n.fault!="policy","reused":n.fault=="policy"} if path==_POLICY_PATH else {"changed":n.fault!="change"}
                value=dict(results=result,version="v7.0.0",build=29,http_method="POST",status="success",serial=SERIAL,mkey=NAME)
                if n.fault=="serial":value["serial"]="FOREIGN01"
                if n.fault=="target":value["mkey"]=NAME+"-other"
                if n.fault=="echo":value["password"]="SYNTHETIC_C3_ECHO"
                self.body=io.BytesIO(json.dumps(value).encode())
            def getheader(self,name,default=""):
                return {"content-type":"application/json","content-encoding":"gzip" if n.fault=="encoding" else "identity"}.get(name,default)
            def readinto(self,view):n.buffers.append(view.obj);return self.body.readinto(view)
            def close(self):
                self.closed=True
                if n.fault=="response-close":raise OSError
        class Raw:
            closed=False;sock=None;path=None
            def connect(self):
                if n.fault=="connect":raise OSError
                if n.fault=="tls-drift":n.h.h.rules["minimum-length"]=64
                if n.fault=="tls-expiry":n.h.now=1060
            def request(self,method,path,*,body,headers):
                assert method=="POST" and path in {_POLICY_PATH,_CHANGE_PATH}
                assert headers["Cookie"] and headers["X-CSRFTOKEN"]=="synthetic"
                assert "Authorization" not in headers and b'"old_password":""' in body.obj
                assert b'"apply_to":"admin"' in body.obj if path==_POLICY_PATH else b'"new_password":' in body.obj
                self.path=path;n.calls.append(path);n.buffers.append(body.obj)
                if n.fault=="wire":raise OSError
                if n.fault=="interrupt":raise KeyboardInterrupt
                if path==_CHANGE_PATH:
                    if n.fault=="metadata":n.h.h.network.record["comments"]="foreign"
                    if n.fault=="logout":n.h.h.network.failure="logout"
            def getresponse(self):
                response=Response(self.path);n.resources.append(response);return response
            def close(self):
                self.closed=True
                if n.fault=="close":raise OSError
        raw=Raw();n.resources.append(raw);return raw


def prepare(root,monkeypatch,*,fault=None,enabled=True):
    h=Harness(root,monkeypatch);h.stage();issuer=authority(h);_,packet=issue(h,issuer);native=Native(h,fault=fault)
    adapter=LocalResetOwnedAdapter(h.material,issuer,packet,execution_enabled=enabled,connection_factory=native.factory)
    return h,issuer,packet,native,adapter


def execute(h,issuer,packet,adapter):
    return M4ExecutionKernel(adapter,issuer,h.store,clock=lambda:h.now).execute(packet.plan,packet.authorization)


def test_original_two_post_owner_rest_reset_is_one_m4_with_opaque_original_records(tmp_path,monkeypatch):
    h,issuer,packet,native,adapter=prepare(tmp_path,monkeypatch)
    original=h.inspector._original;before={p.name:p.read_bytes() for p in original._directory.iterdir()}
    result=execute(h,issuer,packet,adapter)
    assert str(result.outcome)=="succeeded" and native.calls==[_POLICY_PATH,_CHANGE_PATH] and h.store.claim_count==1
    assert adapter._owner.logout_verified and adapter._owner._client is None
    assert all(resource.closed for resource in native.resources) and all(not any(raw) for raw in native.buffers)
    assert all(not any(raw) for raw in h.material._buffers)
    record=adapter._record("reset-result.json")
    assert record["backend_changed"] is record["metadata_preserved"] is True and record["login_verified"] is False
    assert before=={p.name:p.read_bytes() for p in original._directory.iterdir()}
    with pytest.raises(M4AdapterDenied):adapter.dispatch(packet.plan)
    assert len(native.calls)==2
    adapter.close();issuer.close();h.material.close()


@pytest.mark.parametrize("fault",["policy","change","serial","target","echo","wire","metadata","logout","close","response-close","http403","encoding"])
def test_uncertain_rejected_or_changed_originals_cannot_promote_or_replay(tmp_path,monkeypatch,fault):
    h,issuer,packet,native,adapter=prepare(tmp_path,monkeypatch,fault=fault)
    original=h.inspector._original;before={p.name:p.read_bytes() for p in original._directory.iterdir()}
    result=execute(h,issuer,packet,adapter)
    assert str(result.verification)=="unknown" and 1<=len(native.calls)<=2 and h.store.claim_count==1
    assert not (h.root/"material"/"reset-result.json").exists()
    assert (h.root/"material"/"reset-failure.json").exists()
    assert all(resource.closed for resource in native.resources) and all(not any(raw) for raw in native.buffers)
    assert all(not any(raw) for raw in h.material._buffers)
    assert before=={p.name:p.read_bytes() for p in original._directory.iterdir()}
    with pytest.raises(M4AdapterDenied):adapter.dispatch(packet.plan)
    assert len(native.calls)<=2
    if fault in {"serial","target"}:
        identity=adapter._record("policy-identity.json")
        assert identity[("serial" if fault=="serial" else "mkey")+"_matched"] is False
    if fault=="metadata":assert adapter._record("reset-failure.json")["state_failure_stage"] is not None


@pytest.mark.parametrize("fault",["connect","tls-drift","tls-expiry","gate","detached"])
def test_closed_gate_or_after_tls_drift_cannot_submit_either_post(tmp_path,monkeypatch,fault):
    h,issuer,packet,native,adapter=prepare(tmp_path,monkeypatch,fault=fault,enabled=fault!="gate")
    if fault=="detached":
        with pytest.raises(M4AdapterDenied):adapter.dispatch(packet.plan)
        assert h.store.claim_count==0
    else:assert str(execute(h,issuer,packet,adapter).verification)=="not_started"
    assert not native.calls and all(resource.closed for resource in native.resources)
    assert all(not any(raw) for raw in h.material._buffers)


def test_interrupt_after_original_policy_send_retains_claim_without_late_ack_or_retry(tmp_path,monkeypatch):
    h,issuer,packet,native,adapter=prepare(tmp_path,monkeypatch,fault="interrupt")
    with pytest.raises(KeyboardInterrupt):execute(h,issuer,packet,adapter)
    assert native.calls==[_POLICY_PATH] and h.store.claim_count==1
    assert (h.root/"material"/"policy-send.json").exists() and not (h.root/"material"/"policy-ack.json").exists()
    assert all(not any(raw) for raw in h.material._buffers)
    assert all(resource.closed for resource in native.resources)
    with pytest.raises(M4AdapterDenied):adapter.dispatch(packet.plan)
