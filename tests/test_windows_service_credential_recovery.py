"""Independent service Secret removal with synthetic native source and real M4."""
from dataclasses import replace
import ssl

import pytest

from fortipam_mcp import windows_service_credential_recovery as r
from fortipam_mcp import windows_service_credential_readback as readback
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.windows_service_credential_birth import WindowsServiceCredentialBirthCustody
from test_m4_execution_store import _ExternalM4Checkpoint
from test_windows_service_credential_lifecycle import fixture, execute, raw, SERIAL
from test_windows_service_credential_readback import Source as ReadSource, Connection as ReadConnection
from test_windows_execution_secret_recovery import Verifier, Socket
from test_web_secret_create_ack import AckResponse
from test_secret_create_m4_runtime import _secret_plan, _authorization
from v4_planning import M4Outcome, canonical_digest


class Source(ReadSource):
    def __init__(self,fault=None):
        super().__init__(token="independent-synthetic-token")
        self.remove_fault=fault; self.methods=[]

    def factory(self,host,port,**kwargs):
        assert host=="lab.example.test" and port==443
        assert kwargs["context"].check_hostname and kwargs["context"].verify_mode==ssl.CERT_REQUIRED
        connection=Connection(self); self.connections.append(connection); return connection


class Connection(ReadConnection):
    def __init__(self,source): super().__init__(source); self.sock=None
    def connect(self): self.sock=Socket(); super().connect()
    def request(self,method,path,*,body=None,headers=None):
        if method!="DELETE" and "format=id" not in path:
            return super().request(method,path,body=body,headers=headers)
        assert method in {"DELETE","GET"} and body is None
        assert headers["Authorization"]=="Bearer independent-synthetic-token"
        expected="/api/v2/cmdb/secret/database/70"+("?format=id&vdom=root" if method=="GET" else "?vdom=root")
        assert path==expected
        self.source.methods.append(method); self.source.requests.append((method,path,None))
        if self.source.remove_fault=="send": raise OSError("Synthetic deletion uncertainty")
        value=dict(version="v7.0.0",build=29,http_method=method,http_status=404 if method=="GET" else 200,
            status="Not Found" if method=="GET" else "success",path="secret",name="database",vdom="root",serial=SERIAL)
        if method=="GET": value["error"]=2
        else: value.update(mkey=71 if self.source.remove_fault=="wrong-id" else 70,error=0)
        self.response=AckResponse(raw(value)); self.source.responses.append(self.response)
        self.response.status=value["http_status"]
        self.response.headers["Content-Length"]=str(len(self.response.payload))
        if self.source.remove_fault=="length":
            self.response.headers["Content-Length"]=str(len(self.response.payload)+1)
        if self.source.remove_fault=="absence" and method=="GET": self.response.status=200
        if self.source.remove_fault=="close": self.response.failure="response_close"


def setup(tmp_path,monkeypatch,*,fault=None,enabled=True,verifier=True,guard=True,missing_material_seal=False):
    cmp=fixture(tmp_path,fault="password" if missing_material_seal else None)
    result=execute(cmp)
    assert result.outcome is (M4Outcome.RECONCILIATION_REQUIRED if missing_material_seal else M4Outcome.SUCCEEDED)
    original=cmp["custody"].inspect_original_creation()
    cmp["custody"].close(); cmp["now"][0]=2000
    custody=WindowsServiceCredentialBirthCustody(cmp["directory"],cmp["key"],**cmp["birth_kwargs"])
    for name,value in (("recovery.key",b"r"*32),("recovery-witness.key",b"w"*32)):
        path=tmp_path/name; path.write_bytes(value); path.chmod(0o600)
    store=PersistentM4ExecutionStateStore(tmp_path/"recovery.sqlite",tmp_path/"recovery.key",
        monotonic_checkpoint=_ExternalM4Checkpoint("service-recovery-state"),checkpoint_store_ref="service-recovery-state")
    source=Source(fault)
    config=replace(cmp["birth_kwargs"]["config"],bearer_token="independent-synthetic-token")
    monkeypatch.setattr(r,"_ssl_context",lambda config:ssl.create_default_context())
    monkeypatch.setattr(readback,"_ssl_context",lambda config:ssl.create_default_context())
    authority=Verifier() if verifier else None
    kwargs=dict(execution_store=store,witness_key_file=tmp_path/"recovery-witness.key",config=config,
        source_guard=source.guard if guard else None,authorization_verifier=authority,execution_enabled=enabled,
        connection_factory=source.factory,clock=lambda:2000,http_clock=lambda:0)
    recovery=r.WindowsServiceCredentialRecovery(custody,**kwargs)
    cmp.update(recovery=recovery,recovery_kwargs=kwargs,recovery_store=store,source=source,original=original,
        independent_custody=custody,verifier=authority)
    return cmp


def authorize(cmp):
    preview=cmp["recovery"].preview(); base=_secret_plan()
    fields={**base.canonical_content(),"action_id":r.ACTION_ID,"action_version":"1.0.0",
        "adapter_ref":r.ADAPTER_REF,"target_ref":r.TARGET_REF,"parameters_digest":preview.parameters_digest,
        "expected_current_digest":preview.current_digest,"expected_state_digest":preview.expected_digest,
        "expires_at":preview.expires_at}
    plan=replace(base,**{key:fields[key] for key in ("action_id","action_version","adapter_ref","target_ref",
        "parameters_digest","expected_current_digest","expected_state_digest","expires_at")},plan_digest=canonical_digest(fields))
    authorization=_authorization(plan)
    values={**authorization.canonical_content(),"issued_at":1999,"expires_at":plan.expires_at}
    authorization=replace(authorization,issued_at=1999,expires_at=plan.expires_at,authorization_digest=canonical_digest(values))
    return plan,authorization


def test_native_peer_requires_user_agent_for_create_readback_and_independent_recovery(tmp_path,monkeypatch):
    from test_windows_service_credential_http_transport import CreateConnection, setup as create_setup

    observed=[]
    def require_user_agent(original):
        def request(connection,method,path,*,body=None,headers=None):
            if headers.get("User-Agent")!="fortipam-mcp-service-credential/1":
                raise ConnectionResetError("Synthetic native peer requires an identifying User-Agent")
            observed.append((method,path))
            return original(connection,method,path,body=body,headers=headers)
        return request
    for connection in (CreateConnection,ReadConnection,Connection):
        monkeypatch.setattr(connection,"request",require_user_agent(connection.request))
    create_root=tmp_path/"create"; create_root.mkdir()
    created=create_setup(create_root,monkeypatch)
    assert execute(created).outcome is M4Outcome.SUCCEEDED
    recovery_root=tmp_path/"recover"; recovery_root.mkdir()
    recovered=setup(recovery_root,monkeypatch)
    plan,authorization=authorize(recovered)
    assert recovered["recovery"].execute(plan,authorization).outcome is M4Outcome.SUCCEEDED
    assert ("POST","/api/v2/cmdb/secret/database?vdom=root") in observed
    assert ("POST","/api/v2/internal/secret-clear-text") in observed
    assert ("DELETE","/api/v2/cmdb/secret/database/70?vdom=root") in observed
    assert ("GET","/api/v2/cmdb/secret/database/70?format=id&vdom=root") in observed


@pytest.mark.parametrize("missing_material_seal",[False,True])
def test_independent_recovery_preserves_original_success_or_unknown_and_never_reloads_central_material(tmp_path,monkeypatch,missing_material_seal):
    cmp=setup(tmp_path,monkeypatch,missing_material_seal=missing_material_seal)
    original=cmp["original"]
    snapshot={p.name:p.read_bytes() for p in cmp["directory"].iterdir()}
    plan,authorization=authorize(cmp)
    result=cmp["recovery"].execute(plan,authorization)
    assert result.outcome is M4Outcome.SUCCEEDED
    assert cmp["source"].methods==["DELETE","GET"]
    assert len(cmp["source"].requests)==16  # two seven-read brackets, DELETE, absence GET
    assert cmp["recovery_store"].claim_count==1 and cmp["loader"].loads==1
    assert all(connection.closed for connection in cmp["source"].connections)
    assert all(response.closed for response in cmp["source"].responses)
    assert all(not any(buffer) for response in cmp["source"].responses for buffer in response.buffers)
    assert cmp["independent_custody"].inspect_original_creation()==original
    assert all((cmp["directory"]/name).read_bytes()==data for name,data in snapshot.items())
    assert (cmp["directory"]/"create.full-birth.json").exists()!=missing_material_seal
    count=len(cmp["source"].requests)
    with pytest.raises(r.WindowsServiceCredentialRecoveryError): cmp["recovery"].execute(plan,authorization)
    assert len(cmp["source"].requests)==count
    cmp["recovery"].close()
    assert not cmp["recovery"]._key


@pytest.mark.parametrize("fault",["send","wrong-id","length","absence","close"])
def test_consumed_uncertain_delete_or_readback_never_reissues_the_original_action(tmp_path,monkeypatch,fault):
    cmp=setup(tmp_path,monkeypatch,fault=fault); plan,authorization=authorize(cmp)
    result=cmp["recovery"].execute(plan,authorization)
    assert result.outcome is M4Outcome.RECONCILIATION_REQUIRED
    assert cmp["source"].methods.count("DELETE")==1
    assert (cmp["directory"]/"recovery.delete.attempt.json").exists()
    count=len(cmp["source"].requests)
    reconstructed=r.WindowsServiceCredentialRecovery(cmp["independent_custody"],**cmp["recovery_kwargs"])
    with pytest.raises(r.WindowsServiceCredentialRecoveryError): reconstructed.preview()
    assert len(cmp["source"].requests)==count
    assert cmp["independent_custody"].inspect_original_creation()==cmp["original"]
    assert all(connection.closed for connection in cmp["source"].connections)


@pytest.mark.parametrize("enabled,verifier,guard",[(False,True,True),(True,False,True),(True,True,False)])
def test_disabled_missing_authority_or_missing_source_performs_no_material_reads(tmp_path,monkeypatch,enabled,verifier,guard):
    cmp=setup(tmp_path,monkeypatch,enabled=enabled,verifier=verifier,guard=guard)
    with pytest.raises(r.WindowsServiceCredentialRecoveryError): cmp["recovery"].preview()
    assert not cmp["source"].requests and cmp["recovery_store"].claim_count==0


def test_full_state_drift_after_preview_denies_before_material_or_delete(tmp_path,monkeypatch):
    cmp=setup(tmp_path,monkeypatch); plan,authorization=authorize(cmp)
    cmp["source"].fault="stable-row-drift"
    result=cmp["recovery"].execute(plan,authorization)
    assert result.outcome is not M4Outcome.SUCCEEDED
    assert cmp["source"].methods==[]
    assert len(cmp["source"].requests)==8 and cmp["source"].passwords==2
    assert not (cmp["directory"]/"recovery.delete.attempt.json").exists()
    assert all(connection.closed for connection in cmp["source"].connections)


@pytest.mark.parametrize("fault",["source","configuration","plan"])
def test_source_configuration_or_plan_drift_after_preview_denies_without_more_material_reads(tmp_path,monkeypatch,fault):
    cmp=setup(tmp_path,monkeypatch); plan,authorization=authorize(cmp)
    if fault=="source": cmp["source"].available=False
    if fault=="configuration":
        cmp["recovery"]._config=replace(cmp["recovery"]._config,bearer_token="different-synthetic-token")
    if fault=="plan":
        fields={**plan.canonical_content(),"parameters_digest":"f"*64}
        plan=replace(plan,parameters_digest="f"*64,plan_digest=canonical_digest(fields))
    with pytest.raises(r.WindowsServiceCredentialRecoveryError): cmp["recovery"].execute(plan,authorization)
    assert len(cmp["source"].requests)==7 and not cmp["source"].methods
    assert cmp["recovery_store"].claim_count==0


def test_missing_original_material_seal_does_not_allow_current_password_mismatch_or_birth_backfill(tmp_path,monkeypatch):
    cmp=setup(tmp_path,monkeypatch,missing_material_seal=True)
    cmp["source"].fault="password"
    with pytest.raises(r.WindowsServiceCredentialRecoveryError): cmp["recovery"].preview()
    assert not cmp["source"].methods and cmp["recovery_store"].claim_count==0
    assert not (cmp["directory"]/"create.full-birth.json").exists()
    assert cmp["independent_custody"].inspect_original_creation()==cmp["original"]
