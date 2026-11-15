"""Independent recovery has its own authorization, M4, key and exact ACK."""
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
from v4_planning import M4AdapterDenied, M4ExecutionKernel

from fortipam_mcp.local_user_reset_fixture_recovery_ack import consume_reset_fixture_delete_ack
from fortipam_mcp.local_user_reset_fixture_recovery_adapter import LocalResetFixtureRecoveryM4Adapter
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_local_user_reset_fixture_authority import creation, authority, IDENTITY
from test_local_user_reset_fixture_custody import NAME, SERIAL
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF


def envelope(**changes):
    return dict(version="v7.0.0",build=29,http_method="DELETE",http_status=200,status="success",
        path="system",name="admin",vdom="root",serial=SERIAL,mkey=NAME,error=0)|changes


@pytest.mark.parametrize("changes",[{}, {"http_method":"POST"},{"status":"OK"},{"path":"secret"},
    {"serial":"OTHER"},{"mkey":NAME+"-other"},{"error":False},{"results":[]},{"schema_errors":[]},{"action":""}])
def test_exact_original_delete_ack_never_infers_success_from_missing_state(changes):
    raw=bytearray(json.dumps(envelope(**changes)).encode())
    args=dict(username=NAME,serial_digest=hashlib.sha256(SERIAL.encode()).hexdigest(),context_digest="a"*64,
        http_status=200,content_type="application/json",witness_key=b"k"*32)
    if changes:
        with pytest.raises(ValueError):consume_reset_fixture_delete_ack(raw,**args)
    else:assert len(consume_reset_fixture_delete_ack(raw,**args))==64
    assert not any(raw)


class Native:
    def __init__(self,h,*,fault=None):
        self.h,self.fault=h,fault;self.calls=[];self.resources=[];self.buffers=[];self.hook=lambda:None
    def factory(self,*args,**kwargs):
        n=self
        class Response:
            status=403 if n.fault=="http403" else 200
            closed=False
            def __init__(self):
                changes={}
                if n.fault=="wrong-ack":changes["mkey"]=NAME+"-other"
                if n.fault=="http403":changes.update(http_status=403,status="error",error=2)
                self.body=io.BytesIO(json.dumps(envelope(**changes)).encode())
            def getheader(self,name,default=""):
                return {"content-type":"application/json","content-encoding":"gzip" if n.fault=="encoded" else "identity"}.get(name.lower(),default)
            def readinto(self,view):n.buffers.append(view.obj);return self.body.readinto(view)
            def close(self):
                self.closed=True
                if n.fault=="close":raise OSError
        class Connection:
            sock=None;closed=False
            def connect(self):n.hook()
            def request(self,method,path,body,headers):
                assert method=="DELETE" and path=="/api/v2/cmdb/system/admin/"+NAME+"?vdom=root" and body is None
                assert headers["Authorization"]=="Bearer synthetic-token" and headers["Content-Length"]=="0"
                assert "Cookie" not in headers
                n.calls.append((method,path))
                if n.fault!="http403":n.h.network.present=False
                if n.fault=="absence":n.h.network.failure="role"
                if n.fault=="interrupt":raise KeyboardInterrupt
            def getresponse(self):
                if n.fault=="lost-ack":raise OSError
                response=Response();n.resources.append(response);return response
            def close(self):self.closed=True
        connection=Connection();self.resources.append(connection);return connection


def prepare(root,monkeypatch,*,unknown=False,fault=None,enabled=True):
    h,create,_,original=creation(root,monkeypatch,unknown=unknown)
    issuer=authority(h,phase="recover",original=original)
    args={key:IDENTITY[key] for key in ("requester_digest","transport_digest")}
    preview=issuer.preview(h.source._current,**args);packet=issuer.issue(preview,h.source.observe_presence(),**args)
    directory=root/"recovery";directory.mkdir(mode=0o700);(directory/"state").mkdir(mode=0o700)
    for name,value in (("store.key",b"r"*32),("witness.key",b"z"*32)):
        path=directory/name;path.write_bytes(value);path.chmod(0o600)
    store=PersistentM4ExecutionStateStore(directory/"ledger.sqlite",directory/"store.key",
        monotonic_checkpoint=_ExternalM4Checkpoint(),checkpoint_store_ref=CHECKPOINT_STORE_REF)
    native=Native(h,fault=fault)
    kwargs=dict(directory=directory/"state",witness_key_file=directory/"witness.key",execution_enabled=enabled,connection_factory=native.factory)
    adapter=LocalResetFixtureRecoveryM4Adapter(h.source,original,issuer,packet,store,**kwargs)
    return h,create,original,issuer,packet,store,native,adapter,kwargs


def execute(h,issuer,packet,store,adapter):
    return M4ExecutionKernel(adapter,issuer,store,clock=lambda:h.now).execute(packet.plan,packet.authorization)


@pytest.mark.parametrize("unknown",[False,True])
def test_separate_original_recovery_preserves_original_receipts_and_unknown(tmp_path,monkeypatch,unknown):
    h,create,original,issuer,packet,store,native,adapter,_=prepare(tmp_path,monkeypatch,unknown=unknown)
    before={p.name:p.read_bytes() for p in original._directory.iterdir()}
    sealed=original.inspect_original_full_state()
    result=execute(h,issuer,packet,store,adapter)
    assert str(result.outcome)=="succeeded" and str(result.verification)=="verified"
    assert len(native.calls)==store.claim_count==h.store.claim_count==1 and h.source._current.absent
    assert original.inspect_original_full_state()==sealed
    assert before=={p.name:p.read_bytes() for p in original._directory.iterdir()}
    assert all(r.closed for r in native.resources) and all(not any(b) for b in native.buffers)
    assert set(p.name for p in adapter._directory.iterdir())=={"recover.claim.json","recover.response.json","recover.ack.json","recover.absence.json"}
    with pytest.raises(M4AdapterDenied):adapter.dispatch(packet.plan)
    assert len(native.calls)==1
    adapter.close();issuer.close();create.close();original.close();h.material.close();h.source.close()


@pytest.mark.parametrize("fault",["http403","wrong-ack","lost-ack","encoded","absence","close"])
def test_consumed_recovery_never_replays_even_if_object_is_absent(tmp_path,monkeypatch,fault):
    h,_,original,issuer,packet,store,native,adapter,kwargs=prepare(tmp_path,monkeypatch,fault=fault)
    before={p.name:p.read_bytes() for p in original._directory.iterdir()}
    result=execute(h,issuer,packet,store,adapter)
    assert str(result.verification)=="unknown" and len(native.calls)==store.claim_count==1
    assert before=={p.name:p.read_bytes() for p in original._directory.iterdir()}
    assert all(r.closed for r in native.resources) and all(not any(b) for b in native.buffers)
    with pytest.raises(M4AdapterDenied):LocalResetFixtureRecoveryM4Adapter(h.source,original,issuer,packet,store,**kwargs)
    assert len(native.calls)==1


@pytest.mark.parametrize("fault",["role","store-key","gate","detached"])
def test_after_tls_drift_or_missing_gate_does_not_dispatch_delete(tmp_path,monkeypatch,fault):
    h,_,_,issuer,packet,store,native,adapter,_=prepare(tmp_path,monkeypatch,enabled=fault!="gate")
    if fault=="role":native.hook=lambda:setattr(h.network,"failure","role")
    elif fault=="store-key":native.hook=lambda:store._key_path.write_bytes(b"t"*32)
    if fault=="detached":
        with pytest.raises(M4AdapterDenied):adapter.dispatch(packet.plan)
    else:assert str(execute(h,issuer,packet,store,adapter).verification)=="not_started"
    assert not native.calls and h.network.present and not list(adapter._directory.iterdir())
    assert all(r.closed for r in native.resources)


def test_original_delete_interruption_stays_in_progress_without_late_ack(tmp_path,monkeypatch):
    h,_,_,issuer,packet,store,native,adapter,kwargs=prepare(tmp_path,monkeypatch,fault="interrupt")
    with pytest.raises(KeyboardInterrupt):execute(h,issuer,packet,store,adapter)
    assert len(native.calls)==store.claim_count==1
    assert set(p.name for p in adapter._directory.iterdir())=={"recover.claim.json"}
    with pytest.raises(M4AdapterDenied):LocalResetFixtureRecoveryM4Adapter(h.source,adapter._original,issuer,packet,store,**kwargs)
    assert all(r.closed for r in native.resources)


def test_independent_process_recovers_from_readonly_original_after_original_authorization_expiry(tmp_path,monkeypatch):
    h,_,_,original=creation(tmp_path,monkeypatch,unknown=True)
    before={p.name:p.read_bytes() for p in original._directory.iterdir()}
    sealed=original.inspect_original_full_state()
    script='''
from dataclasses import replace
import json,sys
from pathlib import Path
from types import SimpleNamespace
import pytest
from v4_planning import M4ExecutionPlan,M4ExecutionAuthorization,M4ExecutionKernel
from fortipam_mcp.local_user_reset_fixture_custody import LocalResetFixtureAckCustody
from fortipam_mcp.local_user_reset_fixture_sources import LocalResetFixtureSources
from fortipam_mcp.local_user_reset_fixture_authority import LocalResetFixtureM4Authority
from fortipam_mcp.local_user_reset_fixture_recovery_adapter import LocalResetFixtureRecoveryM4Adapter
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore,M4ExecutionStoreTail
from test_m4_execution_store import _ExternalM4Checkpoint,CHECKPOINT_STORE_REF
from test_local_user_reset_fixture_sources import make,SERIAL
from test_local_user_reset_fixture_recovery import Native
from test_local_user_reset_fixture_authority import IDENTITY
root=Path(sys.argv[1]);packet=json.loads((root/'constructor.private.json').read_bytes())
cp=_ExternalM4Checkpoint();cp.tail=M4ExecutionStoreTail(cp.tail.store_ref,int(sys.argv[2]),sys.argv[3])
original_store=PersistentM4ExecutionStateStore(root/'ledger.sqlite',root/'store.key',read_only=True,
    monotonic_checkpoint=cp,checkpoint_store_ref=CHECKPOINT_STORE_REF)
original=LocalResetFixtureAckCustody(directory=root/'custody',packet_file=root/'constructor.private.json',
    witness_key_file=root/'custody.key',plan=M4ExecutionPlan(**packet['plan']),
    authorization=M4ExecutionAuthorization(**packet['authorization']),store=original_store,expected_vdom='root',clock=lambda:5000)
peer=root/'independent-peer';peer.mkdir(mode=0o700);patch=pytest.MonkeyPatch()
old,network,_=make(peer,patch);old.close();network.present=True
source=LocalResetFixtureSources(state_reader=network.complete,owner=old._owner,
    ssh=replace(old._ssh,known_hosts_file=root/'known_hosts'),expected_serial=SERIAL,
    client_factory=network.factory,clock=lambda:network.now)
issuer=LocalResetFixtureM4Authority(source,phase='recover',original=original,authority_key=b'n'*32,
    execution_enabled=True,clock=lambda:5000,**IDENTITY)
args={key:IDENTITY[key] for key in ('requester_digest','transport_digest')}
preview=issuer.preview(source.observe_presence(),**args)
issued=issuer.issue(preview,source.observe_presence(),**args)
directory=root/'independent-recovery';directory.mkdir(mode=0o700);(directory/'state').mkdir(mode=0o700)
for name,value in (('store.key',b'r'*32),('witness.key',b'z'*32)):
    path=directory/name;path.write_bytes(value);path.chmod(0o600)
store=PersistentM4ExecutionStateStore(directory/'ledger.sqlite',directory/'store.key',
    monotonic_checkpoint=_ExternalM4Checkpoint(),checkpoint_store_ref=CHECKPOINT_STORE_REF)
native=Native(SimpleNamespace(network=network))
adapter=LocalResetFixtureRecoveryM4Adapter(source,original,issuer,issued,store,
    directory=directory/'state',witness_key_file=directory/'witness.key',execution_enabled=True,connection_factory=native.factory)
result=M4ExecutionKernel(adapter,issuer,store,clock=lambda:5000).execute(issued.plan,issued.authorization)
assert str(result.outcome)=='succeeded' and source._current.absent
assert len(native.calls)==store.claim_count==original_store.claim_count==1
assert original.inspect_original_full_state().original_ack.original_verification=='unknown'
adapter.close();issuer.close();source.close();network.complete.close();original.close();patch.undo()
print('independent-recovery-qualified')
'''
    env={**os.environ,"PYTHONPATH":os.pathsep.join((str(Path(__file__).parent),os.environ.get("PYTHONPATH","")))}
    child=subprocess.run([sys.executable,"-c",script,str(tmp_path),str(h.cp.tail.sequence),h.cp.tail.chain_hmac],
        env=env,text=True,capture_output=True,timeout=30)
    assert child.returncode==0,child.stderr
    assert child.stdout.strip()=="independent-recovery-qualified"
    assert before=={p.name:p.read_bytes() for p in original._directory.iterdir()}
    assert original.inspect_original_full_state()==sealed and h.store.claim_count==1
