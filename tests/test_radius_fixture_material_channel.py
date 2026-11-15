"""Synthetic local files and pipes for the fixed fixture channel; no SSH or device."""
from __future__ import annotations

from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest

from fortipam_mcp import radius_fixture_material_worker as worker
from fortipam_mcp import radius_fixture_material_loader as loader_module
from fortipam_mcp.radius_fixture_material_loader import RadiusFixtureMaterialLoader
from v4_planning import canonical_digest
from v4_planning.material_provider import (
    DenyAllMaterialProvider, MaterialAccessDenied, MaterialBindingStatus, MaterialContractError,
    MaterialProviderClass, MaterialPurpose,
)
from test_radius_server_contract import binding
from test_radius_server_material_runtime import (
    IDENTITY, MATERIAL, Peer, authorized, request, workflow,
)


def write(path: Path, content: object) -> None:
    raw = content if isinstance(content,bytes) else json.dumps(content,sort_keys=True,separators=(",",":")).encode()
    path.write_bytes(raw)
    path.chmod(0o600)


def fixture(root: Path, req: Any = None) -> tuple[Any, Any]:
    req = request() if req is None else req
    root.mkdir(mode=0o700)
    for name in ("config","material"): (root/name).mkdir(mode=0o700)
    bound = {"created_at":1,"expires_at":200,"device_ip":"192.0.2.10","server_ip":"192.0.2.11",
        "fixture_nonce":"b"*64,"image_id":"sha256:"+"c"*64,"name":"synthetic-radius"}
    ack = {"acknowledged_at":2,"container_id":"d"*64,"nonce":bound["fixture_nonce"]}
    main = b"synthetic-radius-config"
    policy = {"contract":worker.CONTRACT,"parameters_digest":binding().parameters_digest,
        "scope_digest":req.scope_digest,"audience_digest":req.audience_digest,"expires_at":200,
        "fixture":{"binding":bound,"ack":ack,"config_digest":hashlib.sha256(main).hexdigest()}}
    write(root/"binding.private.json",bound)
    write(root/"start.ack.json",ack)
    write(root/"create-material-policy.json",policy)
    write(root/"config/radiusd.conf",main)
    write(root/"material/primary-secret",MATERIAL)
    clients = bytearray()
    for ordinal,address in enumerate((bound["device_ip"],bound["server_ip"])):
        clients.extend(("client fixture_"+str(ordinal)+" {\n ipaddr = "+address+
            "/32\n proto = udp\n require_message_authenticator = yes\n limit_proxy_state = yes\n secret = \"").encode())
        clients.extend(MATERIAL);clients.extend(b'"\n}\n')
    write(root/"config/clients.conf",bytes(clients))
    incoming = {"contract":worker.CONTRACT,"operation":"validate","parameters_digest":binding().parameters_digest,
        "source_policy_digest":hashlib.sha256(json.dumps(policy,sort_keys=True,separators=(",",":")).encode()).hexdigest(),"request":asdict(req)}
    inspection = {"Id":ack["container_id"],"State":{"Running":True},"Image":bound["image_id"],
        "Config":{"Labels":{"fortipam.radius.fixture":bound["fixture_nonce"]},"User":"10001:10001"},
        "HostConfig":{"ReadonlyRootfs":True,"LogConfig":{"Type":"none"}},
        "Mounts":[{"Source":str(root/"config"),"Destination":"/radius-config","Type":"bind","RW":False}]}
    return incoming,inspection


def handle(root: Path, incoming: Any, inspection: Any, clock: Any = lambda:100) -> bytearray:
    return worker._handle(root,incoming,clock=clock,inspector=lambda _:inspection,
                          owner_uid=os.getuid(),config_uid=os.getuid())


def test_worker_validation_never_reads_material_and_acquisition_is_durable_once(tmp_path: Path,monkeypatch: Any) -> None:
    root=tmp_path/"fixture"
    incoming,inspection=fixture(root)
    reads=[]
    original=worker._read
    def observe(directory: int,name: str,*args: Any) -> bytearray:
        reads.append(name)
        return original(directory,name,*args)
    monkeypatch.setattr(worker,"_read",observe)
    assert handle(root,incoming,inspection)==b"available\n"
    assert "primary-secret" not in reads and "clients.conf" not in reads
    assert not (root/"create-material.claim.json").exists()
    incoming["operation"]="acquire"
    result=handle(root,incoming,inspection)
    assert result==MATERIAL and (root/"create-material.claim.json").exists()
    result[:]=bytes(len(result))
    count=len(reads)
    for operation in ("validate","acquire"):
        incoming["operation"]=operation
        with pytest.raises(ValueError): handle(root,incoming,inspection)
    assert reads[count:].count("primary-secret")==0


@pytest.mark.parametrize("fault",["scope","audience","provider","purpose","action","extra","policy_digest",
    "expired","wrong_ack","config_drift","running","mount","symlink","mode"])
def test_worker_denies_before_claim_or_material(tmp_path: Path,fault: str,monkeypatch: Any) -> None:
    root=tmp_path/"fixture";incoming,inspection=fixture(root)
    incoming["operation"]="acquire"
    now=100
    if fault in ("scope","audience"): incoming["request"][fault+"_digest"]="f"*64
    elif fault=="provider": incoming["request"]["provider_class"]="central_lab_inventory_reference"
    elif fault=="purpose": incoming["request"]["purpose"]="credential_rotation"
    elif fault=="action": incoming["request"]["action_id"]="ldap-server-create"
    elif fault=="extra": incoming["path"]="synthetic-other"
    elif fault=="policy_digest": incoming["source_policy_digest"]="e"*64
    elif fault=="expired": now=160
    elif fault=="wrong_ack": write(root/"start.ack.json",{"nonce":"f"*64})
    elif fault=="config_drift": write(root/"config/radiusd.conf",b"changed")
    elif fault=="running": inspection["State"]["Running"]=False
    elif fault=="mount": inspection["Mounts"][0]["RW"]=True
    elif fault=="symlink":
        path=root/"material/primary-secret";path.rename(path.with_name("other"));path.symlink_to("other")
    elif fault=="mode": (root/"material/primary-secret").chmod(0o644)
    original=worker._read
    def read(directory: int,name: str,*args: Any) -> bytearray:
        assert name not in {"primary-secret","clients.conf"}
        return original(directory,name,*args)
    monkeypatch.setattr(worker,"_read",read)
    with pytest.raises((ValueError,OSError)): handle(root,incoming,inspection,lambda:now)
    assert not (root/"create-material.claim.json").exists()


@pytest.mark.parametrize("fault",["client_mismatch","invalid_material","expiry_after_read","clock_rollback"])
def test_worker_failure_after_claim_is_consumed_and_wipes_buffers(tmp_path: Path,fault: str,monkeypatch: Any) -> None:
    root=tmp_path/"fixture";incoming,inspection=fixture(root);incoming["operation"]="acquire"
    if fault=="client_mismatch": write(root/"config/clients.conf",b"synthetic mismatch")
    if fault=="invalid_material": write(root/"material/primary-secret",b"!"*32)
    now=[100];buffers=[];original=worker._read
    def read(directory: int,name: str,*args: Any) -> bytearray:
        value=original(directory,name,*args)
        if name in {"primary-secret","clients.conf"}: buffers.append(value)
        if name=="clients.conf" and fault in {"expiry_after_read","clock_rollback"}:
            now[0]=160 if fault=="expiry_after_read" else 99
        return value
    monkeypatch.setattr(worker,"_read",read)
    with pytest.raises(ValueError): handle(root,incoming,inspection,lambda:now[0])
    assert buffers and all(not any(value) for value in buffers)
    assert (root/"create-material.claim.json").exists()
    with pytest.raises(ValueError): handle(root,incoming,inspection)


def client(tmp_path: Path,*,factory: Any,guard: Any=lambda *args:None,enabled: bool=True,now: Any=None,
           selected: Any=None,digest: str="a"*64) -> RadiusFixtureMaterialLoader:
    selected=binding() if selected is None else selected
    for name in ("identity","known_hosts"):
        p=tmp_path/name
        if not p.exists(): write(p,b"synthetic-identity-metadata")
    return RadiusFixtureMaterialLoader(selected,host="fixture.example",identity_file=tmp_path/"identity",
        known_hosts_file=tmp_path/"known_hosts",source_policy_digest=digest,execution_guard=guard,
        acquisition_enabled=enabled,clock=(lambda:100) if now is None else lambda:now[0],process_factory=factory)


class PipeFactory:
    def __init__(self,script: str) -> None: self.script,self.calls=script,[]
    def __call__(self,args: list[str],**kwargs: Any) -> Any:
        self.calls.append(args)
        assert args[:4]==["/usr/bin/ssh","-F","/dev/null","-T"] and args[-1]=="fixture.example"
        assert "fp-radius-material" in args and "IdentityAgent=none" in args
        assert "StrictHostKeyChecking=yes" in args and kwargs["stderr"] is subprocess.DEVNULL
        return subprocess.Popen([sys.executable,"-c",self.script],**kwargs)


@pytest.mark.parametrize("fault",["short","excess","invalid","nonzero","closed_without_response"])
def test_client_pipe_failure_is_terminal_and_never_retried(tmp_path: Path,fault: str) -> None:
    output={"short":b"x"*31,"excess":b"x"*33,"invalid":b"!"*32,"nonzero":b"x"*32,"closed_without_response":b""}[fault]
    factory=PipeFactory("import sys;sys.stdin.buffer.read();sys.stdout.buffer.write("+repr(output)+");sys.stdout.flush();sys.exit("+str(1 if fault=="nonzero" else 0)+")")
    selected=client(tmp_path,factory=factory)
    for _ in range(2):
        with pytest.raises(MaterialAccessDenied): selected.load_radius_material_once(selected._binding,request())
    assert len(factory.calls)==1


@pytest.mark.parametrize("fault",["guard","gate","key_changed","host_key_changed","request_changed"])
def test_client_refuses_before_process_start(tmp_path: Path,fault: str) -> None:
    factory=PipeFactory("raise AssertionError")
    def deny(*args: Any) -> None: raise ValueError
    selected=client(tmp_path,factory=factory,guard=deny if fault=="guard" else lambda *args:None,enabled=fault!="gate")
    req=request()
    if fault=="key_changed": write(tmp_path/"identity",b"changed")
    elif fault=="host_key_changed": write(tmp_path/"known_hosts",b"changed")
    elif fault=="request_changed":
        selected._check(selected._binding,req)
        req=replace(req,authorization_digest="e"*64)
    with pytest.raises(MaterialAccessDenied): selected.load_radius_material_once(selected._binding,req)
    assert not factory.calls


def test_concrete_client_worker_and_m4_pipeline(tmp_path: Path) -> None:
    peer,now=Peer(),[100]
    execution=tmp_path/"execution-root";execution.mkdir(mode=0o700)
    # HMAC authority fixes these private source policy namespace digests.
    req=replace(request(),scope_digest=canonical_digest("synthetic-radius-scope"),
                audience_digest=canonical_digest("synthetic-radius-audience"))
    root=tmp_path/"fixture";incoming,inspection=fixture(root,req)
    script=("import json,os,sys;from pathlib import Path;from fortipam_mcp import radius_fixture_material_worker as w;"
        "value=w._handle(Path("+repr(str(root))+"),json.load(sys.stdin),clock=lambda:100,inspector=lambda _:"+repr(inspection)+
        ",owner_uid=os.getuid(),config_uid=os.getuid());"
        "sys.stdout.buffer.write(value);sys.stdout.flush();w._wipe(value)")
    factory=PipeFactory(script)
    holder=[]
    source=client(tmp_path,factory=factory,selected=peer.binding,digest=incoming["source_policy_digest"],
                  guard=lambda b,r:holder[0]._guard_material_source(b,r),now=now)
    selected,_=workflow(execution,peer,now,loader=source)
    holder.append(selected)
    ref=authorized(selected)
    assert not factory.calls
    issued=selected._authority._issued
    assert source.validate_prebound(peer.binding,issued.lease_request) is MaterialBindingStatus.UNAVAILABLE
    assert not factory.calls
    result=selected.execute(ref,**IDENTITY)
    assert result["outcome"]=="succeeded" and peer.posts==1 and len(factory.calls)==3
    claim=json.loads((root/"create-material.claim.json").read_bytes())
    assert set(claim)=={"contract","parameters_digest","request_digest","claimed_at"}
    assert selected.execute(ref,**IDENTITY)["idempotent_replay"] is True and len(factory.calls)==3


@pytest.mark.parametrize("change",[{"action_id":"secret-create-from-reference"},{"action_version":"2.0.0"},
    {"purpose":MaterialPurpose.CREDENTIAL_ROTATION},{"expires_at":161}])
def test_fixture_provider_type_cannot_expand_other_actions_or_purposes(change: Any) -> None:
    with pytest.raises(MaterialContractError): replace(request(),**change)


def test_new_provider_type_does_not_enable_default_runtime() -> None:
    assert request().provider_class is MaterialProviderClass.OWNED_LAB_FIXTURE_REFERENCE
    with pytest.raises(MaterialAccessDenied): DenyAllMaterialProvider().acquire_lease(binding(),request())


def test_worker_claim_persistence_failure_never_reads_material(tmp_path: Path,monkeypatch: Any) -> None:
    root=tmp_path/"fixture";incoming,inspection=fixture(root);incoming["operation"]="acquire"
    def fail(*args: Any) -> None: raise OSError
    monkeypatch.setattr(worker.os,"fsync",fail)
    original=worker._read
    def read(directory: int,name: str,*args: Any) -> bytearray:
        assert name not in {"primary-secret","clients.conf"}
        return original(directory,name,*args)
    monkeypatch.setattr(worker,"_read",read)
    with pytest.raises(OSError): handle(root,incoming,inspection)
    assert (root/"create-material.claim.json").exists()
    with pytest.raises(ValueError): handle(root,incoming,inspection)


def test_worker_concurrent_acquisition_reads_once(tmp_path: Path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    root=tmp_path/"fixture";incoming,inspection=fixture(root);incoming["operation"]="acquire"
    def acquire() -> bool:
        try:
            material=handle(root,incoming,inspection)
            assert material==MATERIAL
            worker._wipe(material)
            return True
        except (ValueError,FileExistsError): return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _:acquire(),range(2)))==[False,True]


def test_client_deadline_consumes_attempt_and_terminates_child(tmp_path: Path,monkeypatch: Any) -> None:
    factory=PipeFactory("import time;time.sleep(20)")
    selected=client(tmp_path,factory=factory)
    ticks=iter([0,20])
    with monkeypatch.context() as context:
        context.setattr(loader_module.time,"monotonic",lambda:next(ticks,20))
        with pytest.raises(MaterialAccessDenied): selected.load_radius_material_once(selected._binding,request())
    with pytest.raises(MaterialAccessDenied): selected.load_radius_material_once(selected._binding,request())
    assert len(factory.calls)==1


def test_client_expiry_after_pipe_read_clears_material(tmp_path: Path,monkeypatch: Any) -> None:
    factory=PipeFactory("import sys;sys.stdin.buffer.read();sys.stdout.buffer.write("+repr(MATERIAL)+");sys.stdout.flush()")
    now=[100];selected=client(tmp_path,factory=factory,now=now);captured=[]
    original=RadiusFixtureMaterialLoader._exchange
    def exchange(self: Any,*args: Any) -> bytearray:
        raw=original(self,*args);captured.append(raw);now[0]=160;return raw
    monkeypatch.setattr(RadiusFixtureMaterialLoader,"_exchange",exchange)
    with pytest.raises(MaterialAccessDenied): selected.load_radius_material_once(selected._binding,request())
    assert captured and not any(captured[0]) and len(factory.calls)==1


@pytest.mark.parametrize("field",["identity_file","known_hosts_file"])
@pytest.mark.parametrize("name",["has space","has\ttab","%h","${USER}","has\\slash",'has"quote',"has'quote"])
def test_ssh_paths_must_have_only_literal_semantics(tmp_path: Path,field: str,name: str) -> None:
    factory=PipeFactory("raise AssertionError")
    unsafe=tmp_path/name;safe=tmp_path/"literal-file"
    write(unsafe,b"synthetic-key");write(safe,b"synthetic-key")
    values={"identity_file":safe,"known_hosts_file":safe,field:unsafe}
    with pytest.raises(MaterialAccessDenied):
        RadiusFixtureMaterialLoader(binding(),host="fixture.example",source_policy_digest="a"*64,
            execution_guard=lambda *args:None,acquisition_enabled=True,process_factory=factory,**values)
    assert not factory.calls


@pytest.mark.parametrize('during_exchange', [False, True])
def test_close_denies_intake_and_clears_inflight_output(tmp_path: Path, monkeypatch: Any,
                                                      during_exchange: bool) -> None:
    factory = PipeFactory('import sys;sys.stdout.buffer.write(' + repr(MATERIAL) + ')')
    selected = binding()
    holder: list[RadiusFixtureMaterialLoader] = []
    calls = 0
    retained: list[bytearray] = []
    def guard(*args: Any) -> None:
        nonlocal calls
        calls += 1
        if during_exchange and calls == 2:
            holder[0].close()
    source = client(tmp_path, factory=factory, selected=selected, guard=guard)
    holder.append(source)
    original = RadiusFixtureMaterialLoader._exchange
    def exchange(self: Any, *args: Any) -> bytearray:
        raw = original(self, *args)
        retained.append(raw)
        return raw
    monkeypatch.setattr(RadiusFixtureMaterialLoader, '_exchange', exchange)
    if not during_exchange:
        source.close()
    with pytest.raises(MaterialAccessDenied):
        source.load_radius_material_once(selected, request())
    source.close()
    assert source.validate_prebound(selected, request()) is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied):
        source.load_radius_material_once(selected, request())
    assert len(factory.calls) == int(during_exchange)
    assert all(not raw for raw in retained)
    assert source._attempted is during_exchange
