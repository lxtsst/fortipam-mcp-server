"""Actual original custody, Owner source and independent persistent phase M4s."""
from copy import deepcopy
from datetime import datetime,timezone
from email.utils import format_datetime
import json
from pathlib import Path

import httpx
import pytest

from fortipam_mcp.jwt_manual_key_contract import _digest
from fortipam_mcp.jwt_manual_key_owner_http import JwtManualKeyOwnerHttp
from fortipam_mcp.jwt_rotation_owner_source import JwtRotationOriginalCreation,JwtRotationOwnerSource,JwtRotationOwnerSourceError
from fortipam_mcp.jwt_rotation_phase import JwtRotationPhase
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_jwt_manual_key_owner_http import Lab
from test_jwt_manual_key_owner_workflow import workflow,run,IDENTITY
from test_jwt_manual_rotation_contract import fixture,replacement
from test_jwt_manual_key_contract import synthetic_key
from test_jwt_manual_key_preflight import packet,inputs
from test_jwt_rotation_dependency_projection import user_row,collection


class RotationLab(Lab):
    def __init__(self,root,old,new,monkeypatch):
        super().__init__(root,old,monkeypatch)
        self.binding,self.keys = fixture(old,new)
        self.rotation = root/"rotation-native"; self.rotation.mkdir(mode=0o700)
        self.user = None; self.user_posts = self.user_deletes = self.puts = 0
        self.key_generations = 0; self.key_initialized = False
        self.rotation_fault = "none"
        self.user_schema = {name:{"name":name,"type":"synthetic"}for name in self.binding.user_config()}
        self.user_defaults = {name:"synthetic" for name in self.user_schema}

    def handler(self,req):
        path,query = req.url.path,req.url.query
        date = {"Date":format_datetime(datetime.now(timezone.utc),usegmt=True)}
        if path == "/api/v2/monitor/system/api-user/generate-key":
            self.calls.append((req.method,str(req.url)))
            assert req.method == "POST" and not query and self.user is not None
            assert (self.rotation/"user-initialize.claim.json").is_file()
            assert json.loads(req.content) == {"api-user":self.binding._user_name}
            self.key_generations += 1
            if self.rotation_fault == "init-403":
                return httpx.Response(403,json=packet("api-user",None,http_method="POST",http_status=403,status="error",action="generate-key"),headers=date)
            self.key_initialized = True
            if self.rotation_fault == "init-timeout": raise httpx.ReadTimeout("PRIVATE_INITIALIZATION_DETAIL")
            return httpx.Response(200,json=packet("api-user",{"access_token":"SYNTHETIC_UNUSED_API_KEY_123456789","opaque":"SYNTHETIC_SUPPLEMENTARY_CREDENTIAL_RESULT"},http_method="POST",action="generate-key"),headers=date)
        if path == "/api/v2/cmdb/system/api-user" and query in (b"action=schema&with_meta=true",b"action=default&with_meta=true"):
            self.calls.append((req.method,str(req.url)))
            schema = query.startswith(b"action=schema")
            return httpx.Response(200,json=packet("api-user",{"children":self.user_schema}if schema else self.user_defaults,action="schema"if schema else"default"),headers=date)
        if path == "/api/v2/cmdb/system/api-user" and req.method == "GET":
            self.calls.append((req.method,str(req.url))); assert query == b"format=name%7Ctype%7Cjwt-key&with_meta=true"
            rows = deepcopy(inputs()[3]["results"])
            if self.user is not None: rows.append({"name":self.binding._user_name,"type":"jwt","jwt-key":self.binding._key_name})
            return httpx.Response(200,json=collection("api-user",rows),headers=date)
        if path == "/api/v2/cmdb/system/api-user" and req.method == "POST":
            self.calls.append((req.method,str(req.url))); assert query == b"with_meta=true"
            assert (self.rotation/"user-create.claim.json").is_file() and req.headers["X-CSRFTOKEN"] == "synthetic-csrf"
            self.user_posts += 1
            if self.rotation_fault == "403": return httpx.Response(403,json=packet("api-user",None,http_method="POST",http_status=403,status="error"),headers=date)
            body = json.loads(req.content); assert body.pop("$originalName") == "" and body == self.binding.user_config()
            self.user = user_row(self.binding); self.row["q_ref"] = 1
            if self.rotation_fault == "timeout": raise httpx.ReadTimeout("PRIVATE_DETAIL")
            if self.rotation_fault == "source-inflight": self.source = False
            return httpx.Response(200,json=packet("api-user",[],http_method="POST",mkey=self.binding._user_name),headers=date)
        if path == "/api/v2/cmdb/system/api-user/"+self.binding._user_name:
            self.calls.append((req.method,str(req.url)))
            if req.method == "DELETE":
                assert not query and (self.rotation/"user-remove.claim.json").is_file() and self.user is not None
                self.user_deletes += 1; self.user = None; self.row["q_ref"] = 0
                return httpx.Response(200,json=packet("api-user",[],http_method="DELETE",mkey=self.binding._user_name),headers=date)
            assert req.method == "GET"
            if self.user is None:
                assert query == b"format=name%7Ctype%7Cjwt-key&with_meta=true"
                return httpx.Response(404,json=packet("api-user",None,http_status=404,status="error",mkey=self.binding._user_name),headers=date)
            assert query.startswith(b"format=name%7Ccomments") and (self.rotation/"user-create.ack.json").is_file()
            row = deepcopy(self.user)
            if self.rotation_fault == "bad-user-post": row["unqualified-field"] = "PRIVATE_DETAIL"
            return httpx.Response(200,json=packet("api-user",[row],mkey=self.binding._user_name),headers=date)
        if path.endswith("/secret/jwt-key/"+self.binding._key_name) and req.method == "PUT":
            self.calls.append((req.method,str(req.url))); assert query == b"with_meta=true" and self.user is not None
            value = json.loads(req.content); self.puts += 1; assert len(value) == 8 and value["q_origin_key"] == self.binding._key_name
            phase = "overlap" if len(value["key"]) == 2 else "cutover" if value["key"] == self.keys.members("cutover") else "restore"
            assert (self.rotation/(phase+".claim.json")).is_file()
            self.row["key"] = value["key"]
            if self.rotation_fault == "reorder-overlap" and phase == "overlap": self.row["key"].reverse()
            if self.rotation_fault == "time-drift": self.row["last-update-time"] = "synthetic-modified"
            return httpx.Response(200,json=packet("jwt-key",[],http_method="PUT",mkey=self.binding._key_name),headers=date)
        return super().handler(req)


def keyfile(path,value):
    path.write_bytes(value); path.chmod(0o600); return path


def source(lab,owner,creator,*,enabled=True):
    original = PersistentM4ExecutionStateStore(creator._store._path,creator._store._key_path,read_only=True,
        monotonic_checkpoint=creator._store._monotonic_checkpoint,checkpoint_store_ref=creator._store._checkpoint_store_ref)
    custody = JwtRotationOriginalCreation(owner,original,creator._directory,creator._key_file,**IDENTITY)
    return JwtRotationOwnerSource(custody,lab.binding,lab.keys,directory=lab.rotation,
        witness_key_file=keyfile(lab.root/"rotation-witness.key",b"W"*32),
        user_schema_digest=_digest(lab.user_schema),user_defaults_digest=_digest(lab.user_defaults),execution_enabled=enabled)


def phase(lab,source,name,*,enabled=True,recovery=False):
    directory = lab.root/("phase-"+name); directory.mkdir(mode=0o700)
    index = ("user-create","user-initialize","overlap","cutover","restore","user-remove").index(name)
    authority = keyfile(directory/"authority.key",bytes([65+index])*32)
    execution = keyfile(directory/"execution.key",bytes([80+index])*32)
    store = PersistentM4ExecutionStateStore(directory/"execution.sqlite3",execution)
    return JwtRotationPhase(source,store,phase=name,directory=directory,authority_key_file=authority,
        parent_digest="f"*64,**IDENTITY,execution_enabled=enabled,recovery=recovery)


def invoke(child):
    plan,authorization = child.issue(); return child.execute(plan,authorization),plan,authorization


def test_independent_six_m4s_preserve_original_key_and_original_readonly_creation_records(tmp_path,synthetic_key,replacement,monkeypatch):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create"); run(creator)
        original_row = deepcopy(lab.row); original_grant = (creator._directory/"grant.json").read_bytes()
        scoped = source(lab,owner,creator)
        children = []
        for name in ("user-create","user-initialize","overlap","cutover","restore","user-remove"):
            child = phase(lab,scoped,name); result,plan,auth = invoke(child)
            assert result.outcome == "succeeded" and result.verification == "verified"
            assert child.store.claim_count == 1 and child._consumed
            replay = child.execute(plan,auth); assert replay.idempotent_replay
            child.close(); children.append(child)
        assert lab.user_posts == lab.user_deletes == lab.key_generations == 1 and lab.puts == 3
        assert lab.user is None and lab.row == original_row
        assert (creator._directory/"grant.json").read_bytes() == original_grant
        assert scoped.original.store._read_only
        scoped.close()
    assert owner.logout_verified


@pytest.mark.parametrize("fault", ["403","timeout","bad-user-post","source-inflight"])
def test_uncertain_user_creation_retains_once_only_claim_and_original_ack_when_known(tmp_path,synthetic_key,replacement,monkeypatch,fault):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create"); run(creator); scoped = source(lab,owner,creator)
        child = phase(lab,scoped,"user-create"); lab.rotation_fault = fault
        result,plan,auth = invoke(child)
        assert result.outcome == "reconciliation_required" and lab.user_posts == 1 and lab.puts == 0
        assert (lab.rotation/"user-create.claim.json").is_file() and (lab.rotation/"user-create.response.json").is_file()
        assert (lab.rotation/"user-create.ack.json").exists() is (fault in {"bad-user-post","source-inflight"})
        assert not (lab.rotation/"user-create.state.json").exists()
        lab.source = True; lab.rotation_fault = "none"
        with pytest.raises(Exception): scoped.dispatch("user-create",plan,auth,child.store)
        assert lab.user_posts == 1
        if fault in {"bad-user-post","source-inflight"}:
            cleanup = phase(lab,scoped,"user-remove",recovery=True)
            removed,_,_ = invoke(cleanup); assert removed.outcome == "succeeded" and lab.user_deletes == 1
        else:
            with pytest.raises(Exception): scoped.current("user-remove",recovery=True)
            assert lab.user_deletes == 0


def test_existing_ledger_claim_is_insufficient_without_active_kernel_dispatch(tmp_path,synthetic_key,replacement,monkeypatch):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create"); run(creator); scoped = source(lab,owner,creator)
        child = phase(lab,scoped,"user-create"); plan,auth = child.issue()
        child.store.claim(plan_ref=plan.plan_ref,requester_digest=plan.requester_digest,idempotency_digest=plan.idempotency_digest,
            authorization_digest=auth.authorization_digest,context_digest=__import__('v4_planning').canonical_digest({"plan_digest":plan.plan_digest,"authorization_digest":auth.authorization_digest,"revision":plan.revision}))
        with pytest.raises(Exception): scoped.dispatch("user-create",plan,auth,child.store)
        assert lab.user_posts == 0 and not (lab.rotation/"user-create.claim.json").exists()


@pytest.mark.parametrize("fault", ["closed","schema-drift","authority-key","native-key","original-grant","body-drift"])
def test_closed_or_changed_authority_and_source_never_dispatch(tmp_path,synthetic_key,replacement,monkeypatch,fault):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create"); run(creator); scoped = source(lab,owner,creator)
        child = phase(lab,scoped,"user-create",enabled=fault != "closed")
        if fault == "closed":
            with pytest.raises(Exception): child.issue()
        else:
            plan,auth = child.issue()
            if fault == "schema-drift": lab.user_schema["type"]["type"] = "changed"
            if fault == "authority-key": child._key_file.write_bytes(b"z"*32)
            if fault == "native-key": scoped._key_file.write_bytes(b"z"*32)
            if fault == "original-grant": (creator._directory/"grant.json").write_bytes(b'{}')
            if fault == "body-drift": lab.row["ca"] = "foreign"
            try: result = child.execute(plan,auth)
            except Exception: pass
            else: assert result.outcome != "succeeded"
        assert lab.user_posts == lab.puts == lab.user_deletes == 0


@pytest.mark.parametrize("fault", ["none","missing-ack","foreign-member","metadata-drift"])
def test_reordered_unknown_overlap_allows_only_original_ack_bound_restore(tmp_path,synthetic_key,replacement,monkeypatch,fault):
    lab = RotationLab(tmp_path,synthetic_key,replacement,monkeypatch)
    with lab.session() as owner:
        creator = workflow(lab,owner,lab.store("create"),"create");run(creator);scoped = source(lab,owner,creator)
        for name in ("user-create","user-initialize"):
            assert invoke(phase(lab,scoped,name))[0].outcome == "succeeded"
        lab.rotation_fault = "reorder-overlap";overlap = phase(lab,scoped,"overlap")
        from fortipam_mcp import jwt_rotation_owner_source as source_module
        from fortipam_mcp.jwt_manual_rotation_contract import JwtManualRotationContractError
        current_consumer = source_module.consume_jwt_rotation_key_state
        def legacy_ordered_reader(*args,**kwargs):
            if json.loads(args[0])["results"][0]["key"] != kwargs["keys"].members(kwargs["phase"]):
                raise JwtManualRotationContractError("Synthetic legacy ordered reader.")
            return current_consumer(*args,**kwargs)
        with monkeypatch.context() as legacy:
            legacy.setattr(source_module,"consume_jwt_rotation_key_state",legacy_ordered_reader)
            result,_,_ = invoke(overlap)
        assert (result.outcome,result.verification) == ("reconciliation_required","unknown")
        assert not(lab.rotation/"overlap.state.json").exists() and lab.puts == 1
        original = {p:p.read_bytes()for p in lab.rotation.iterdir()if p.is_file()}
        if fault == "missing-ack": (lab.rotation/"overlap.ack.json").unlink()
        if fault == "foreign-member": lab.row["key"][1]["key-name"] = "SYNTHETIC_FOREIGN_KEY"
        if fault == "metadata-drift": lab.row["last-update-time"] = "synthetic-drift"
        if fault == "none":
            with pytest.raises((JwtRotationOwnerSourceError,FileNotFoundError)): scoped.current("cutover")
            restore = phase(lab,scoped,"restore",recovery=True)
            restored,_,_ = invoke(restore)
            assert (restored.outcome,restored.verification) == ("succeeded","verified") and lab.puts == 2
            assert all(p.read_bytes() == value for p,value in original.items())
            assert overlap.store.claim_count == restore.store.claim_count == 1
            assert not(lab.rotation/"overlap.state.json").exists()
        else:
            with pytest.raises((JwtRotationOwnerSourceError,FileNotFoundError)): scoped.current("restore",recovery=True)
            assert lab.puts == 1
