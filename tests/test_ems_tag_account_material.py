"""Initial Account material with synthetic central files and a real M4 ledger."""
from copy import deepcopy
from dataclasses import asdict
import json
import os

import pytest
from v4_planning import M4AdapterAmbiguous,M4ExecutionKernel,M4ExecutionPlan,M4ExecutionAuthorization,canonical_digest
from v4_planning.material_provider import MaterialAccessDenied

from fortipam_mcp.ems_tag_account_contract import (ACTION_ID,ACTION_VERSION,ADAPTER_REF,TARGET_REF,
    current_digest,expected_digest,_generate_password,_password_valid)
from fortipam_mcp.ems_tag_account_enrollment import EmsAccountCentralEnrollment
from fortipam_mcp.ems_tag_account_material import EmsAccountInitialMaterialSource
from fortipam_mcp.ems_tag_admin_contract import ProspectiveEmsTagManagerAccount
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.secret_metadata_http_transport import _zeroize_mutable
from test_ems_tag_identity_sources import make as identity_source
from test_ems_tag_role_fixture import make as parent_fixture,execute as execute_parent,readonly_original,close as close_parent,CALLER
from test_m4_execution_store import _ExternalM4Checkpoint,CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _Verifier


class Harness:
    def __init__(self,root,monkeypatch,*,enabled=True):
        root.chmod(0o700);self.root=root
        self.parent_env=parent_fixture(root/'parent',monkeypatch)
        assert str(execute_parent(self.parent_env).outcome)=='succeeded'
        self.parent=readonly_original(self.parent_env)
        folder=root/'owner';folder.mkdir(mode=0o700)
        self.source,self.transport,_,_,self.data,self.now=identity_source(folder,monkeypatch,
            shared_config=self.parent_env['transport']._config,source_key=b't'*32,session_value='separate-synthetic-session')
        self.data.update(deepcopy(self.parent_env['data']));self.source.observe()
        base=root/'fortipam-local-inventory';base.mkdir(mode=0o700)
        (base/'secrets').mkdir(mode=0o700);(base/'inventory').mkdir(mode=0o700)
        self.env=base/'secrets/fortinet_lab_secrets.local.env'
        self.original=b'EXISTING_USERNAME=synthetic_only\nEXISTING_PASSWORD=NoProduct-SyntheticValue7\n'
        self.env.write_bytes(self.original);self.env.chmod(0o600)
        self.directory=root/'enrollment';self.directory.mkdir(mode=0o700)
        self.key=root/'enrollment.key';self.key.write_bytes(b'm'*32);self.key.chmod(0o600)
        self.draft=ProspectiveEmsTagManagerAccount(self.parent.inspect_verified_original().role_uid,'c'*32,
            self.transport._config.local_address+'/32')
        self.enrollment=self.reopen(enabled=enabled)
        self.loads=0;self.before_encode=None;self.lease=None;self.wire=bytearray();self.raw=bytearray();self.username=bytearray();self.encoded=False
        loader=type(self.enrollment._loader);old=loader.load_secret_create_material_once
        def load(instance):
            if instance._secret_env_path==self.env:self.loads+=1
            return old(instance)
        monkeypatch.setattr(loader,'load_secret_create_material_once',load)

    def reopen(self,*,enabled=False):
        return EmsAccountCentralEnrollment(self.source,self.draft,self.parent,requester_digest=CALLER['requester_digest'],
            env_file=self.env,directory=self.directory,witness_key_file=self.key,execution_enabled=enabled,clock=lambda:self.now[0])

    def stage(self,monkeypatch):
        self.enrollment.prepare_once();self.enrollment.register_once()
        key=self.root/'account-store.key';key.write_bytes(b'g'*32);key.chmod(0o600)
        self.store=PersistentM4ExecutionStateStore(self.root/'account.sqlite',key,
            monotonic_checkpoint=_ExternalM4Checkpoint(),checkpoint_store_ref=CHECKPOINT_STORE_REF)
        self.material=EmsAccountInitialMaterialSource(self.enrollment,self.store,execution_enabled=True,clock=lambda:self.now[0])
        observed=self.source._current;reference=self.enrollment.reference;parent=self.enrollment._owned.custody_digest
        values=dict(plan_ref='ems-account-synthetic-plan',revision=1,action_id=ACTION_ID,action_version=ACTION_VERSION,
            adapter_ref=ADAPTER_REF,target_ref=TARGET_REF,requester_digest=CALLER['requester_digest'],summary_digest='9'*64,
            confirmation_digest='d'*64,approval_digest='e'*64,parameters_digest=self.material.parameters_digest,
            expected_current_digest=current_digest(self.draft,reference,parent,observed.full_scope.digest,observed.source_context_digest),
            expected_state_digest=expected_digest(self.draft,reference,parent,observed.full_scope.digest,observed.source_context_digest),
            idempotency_digest='8'*64,expires_at=1060,compensation_ref=None)
        self.plan=M4ExecutionPlan(**values,plan_digest=canonical_digest(values));self.authorize()

    def authorize(self):
        plan=self.plan
        values=dict(authorization_ref='ems-account-synthetic-auth',plan_ref=plan.plan_ref,plan_digest=plan.plan_digest,
            requester_digest=plan.requester_digest,confirmation_ref='ems-account-intent',confirmation_digest=plan.confirmation_digest,
            approval_ref='ems-account-policy',approval_digest=plan.approval_digest,approver_digest='7'*64,
            issued_at=1000,expires_at=1060,one_time=True,execution_authorized=True)
        self.auth=M4ExecutionAuthorization(**values,authorization_digest=canonical_digest(values))

    def read_current(self,plan):return plan.expected_current_digest
    def read_postcondition(self,plan):return plan.expected_state_digest
    def dispatch(self,plan):
        try:
            self.lease=self.material.acquire_original(plan,self.auth);self.raw=self.lease._password;self.username=self.lease._username
            if self.before_encode:self.before_encode()
            self.wire=self.lease.encode_once()
            body=json.loads(self.wire);assert len(body['password'])==44
            assert {k:v for k,v in body.items() if k!='password'}==self.draft._metadata_body
            self.encoded=True
            with pytest.raises(MaterialAccessDenied):self.lease.encode_once()
        except (ValueError,MaterialAccessDenied):raise M4AdapterAmbiguous('Synthetic material rejection.') from None
        finally:
            if self.lease:self.lease.close()
            _zeroize_mutable(self.wire)
    def execute(self):return M4ExecutionKernel(self,_Verifier(),self.store,clock=lambda:self.now[0]).execute(self.plan,self.auth)
    def close(self):
        if hasattr(self,'material'):self.material.close()
        self.enrollment.close();self.source.close();assert self.transport.close().next_session_check_401
        self.parent.close();close_parent(self.parent_env)


def test_enrollment_preserves_prefix_has_only_whole_append_macs_and_can_retire_unused(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);reference=h.enrollment.prepare_once()
    assert h.env.read_bytes()==h.original and h.loads==0
    h.enrollment.register_once();h.enrollment.check_registered()
    assert h.loads==0 and h.env.read_bytes().startswith(h.original)
    assert h.reopen().reference==reference
    claim=h.enrollment._record('append.claim.json')
    assert set(claim)=={'reference','tail_length','tail_mac'} and type(claim['tail_mac']) is str
    assert not h.enrollment._writer_lock.exists()
    assert all((p.stat().st_mode&0o777)==0o600 for p in h.directory.iterdir())
    h.enrollment.retire_unused_once();assert h.env.read_bytes()==h.original
    with pytest.raises(ValueError):h.enrollment.check_registered()
    assert not h.enrollment._writer_lock.exists();h.close()


def test_cached_path_timestamps_do_not_override_stable_descriptor_metadata(tmp_path,monkeypatch):
    from pathlib import Path
    from types import SimpleNamespace
    h=Harness(tmp_path,monkeypatch);original=Path.lstat;calls=[0]
    def cached(path):
        info=original(path)
        if path!=h.env:return info
        calls[0]+=1
        fields={name:getattr(info,name) for name in ('st_mode','st_uid','st_nlink','st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')}
        fields['st_mtime_ns']-=calls[0];fields['st_ctime_ns']-=calls[0]
        return SimpleNamespace(**fields)
    monkeypatch.setattr(Path,'lstat',cached)
    h.enrollment.prepare_once();h.enrollment.register_once();h.enrollment.check_registered()
    h.enrollment.retire_unused_once()
    assert h.env.read_bytes()==h.original and h.loads==0;h.close()


@pytest.mark.parametrize('fault',['record_signature','parent_custody','witness_key'])
def test_registration_batch_rejects_signed_record_or_closing_boundary_drift(tmp_path,monkeypatch,fault):
    h=Harness(tmp_path,monkeypatch);h.enrollment.prepare_once();h.enrollment.register_once()
    entry=h.enrollment;buffers=[];read_env=entry._read_env
    def capture_env():
        raw,info=read_env();buffers.append(raw);return raw,info
    monkeypatch.setattr(entry,'_read_env',capture_env)
    if fault=='record_signature':
        path=h.directory/'append.ack.json';packet=json.loads(path.read_bytes());packet['signature']='0'*64
        path.write_text(json.dumps(packet))
    else:
        loader=entry._loader;validate=type(loader).validate_prebound
        def change_after_validation(instance):
            result=validate(instance)
            if instance is not loader:return result
            if fault=='witness_key':h.key.write_bytes(b'changed-registration-witness-key!')
            else:
                path=h.parent._directory/'effect.json';packet=json.loads(path.read_bytes());packet['signature']='0'*64
                path.write_text(json.dumps(packet))
            return result
        monkeypatch.setattr(type(loader),'validate_prebound',change_after_validation)
    try:
        with pytest.raises(ValueError):entry.check_registered()
        assert all(not raw for raw in buffers) and h.loads==0
    finally:h.close()


def test_default_off_never_generates_or_appends_credentials(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch,enabled=False);h.enrollment.prepare_once()
    with pytest.raises(ValueError):h.enrollment.register_once()
    assert h.env.read_bytes()==h.original and h.loads==0
    assert not (h.directory/'append.claim.json').exists();h.close()


def test_absent_or_restored_parent_role_cannot_prepare_material(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch)
    uid=h.enrollment._owned.role_uid
    h.data['roles']=[r for r in h.data['roles'] if r['uid']!=uid];h.data['details'].pop(uid);h.source.observe()
    with pytest.raises(ValueError):h.enrollment.prepare_once()
    assert not list(h.directory.iterdir()) and h.env.read_bytes()==h.original and h.loads==0;h.close()


@pytest.mark.parametrize('fault',['foreign_prefix','foreign_tail','partial_tail','replaced_inode','existing_lock'])
def test_unrecognized_central_state_never_replays_or_truncates(tmp_path,monkeypatch,fault):
    h=Harness(tmp_path,monkeypatch);h.enrollment.prepare_once()
    if fault=='existing_lock':
        h.enrollment._writer_lock.write_bytes(b'foreign-writer');h.enrollment._writer_lock.chmod(0o600)
        with pytest.raises(ValueError):h.enrollment.register_once()
        assert h.enrollment._writer_lock.read_bytes()==b'foreign-writer' and h.env.read_bytes()==h.original
    elif fault=='partial_tail':
        old=os.write
        def short(fd,raw):
            if bytes(raw).startswith(h.enrollment._variables[0].encode()+b'='):return old(fd,raw[:len(raw)//2])
            return old(fd,raw)
        monkeypatch.setattr(os,'write',short)
        with pytest.raises(ValueError):h.enrollment.register_once()
        current=h.env.read_bytes()
        assert (h.directory/'append.claim.json').exists() and not (h.directory/'append.ack.json').exists()
        with pytest.raises(ValueError):h.reopen(enabled=True).retire_unused_once()
        assert h.env.read_bytes()==current
    else:
        h.enrollment.register_once()
        if fault=='foreign_prefix':h.env.write_bytes(h.env.read_bytes().replace(b'EXISTING_USERNAME',b'CHANGEDX_USERNAME'))
        elif fault=='foreign_tail':
            with h.env.open('ab') as f:f.write(b'FOREIGN_TAIL=synthetic\n')
        else:
            # Keep the original inode allocated until the replacement exists.
            # Unlink/recreate may immediately reuse its inode on Linux.
            replacement=h.env.with_name(h.env.name+'.replacement')
            replacement.write_bytes(h.env.read_bytes());replacement.chmod(0o600)
            assert replacement.stat().st_ino != h.env.stat().st_ino
            replacement.replace(h.env)
        current=h.env.read_bytes()
        with pytest.raises(ValueError):h.enrollment.retire_unused_once()
        assert h.env.read_bytes()==current
    h.close()


def test_actual_m4_binds_one_use_material_and_clears_buffers_without_leaking_into_records(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.stage(monkeypatch)
    synthetic_secret=h.env.read_bytes().splitlines()[-1].split(b'=',1)[1]
    result=h.execute();assert str(result.outcome)=='succeeded' and h.encoded and h.loads==1
    assert not h.raw and not h.username and not h.wire
    assert (h.directory/'material.used.json').exists()
    assert synthetic_secret not in json.dumps(asdict(h.plan)).encode()+json.dumps(asdict(h.auth)).encode()
    assert all(synthetic_secret not in p.read_bytes() for p in h.directory.iterdir())
    assert h.execute().idempotent_replay and h.loads==1
    with pytest.raises(ValueError):h.enrollment.retire_unused_once()
    h.close()


def test_detached_or_disabled_material_never_loads_and_cannot_resume_that_instance(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.stage(monkeypatch)
    with pytest.raises(MaterialAccessDenied):h.material.acquire_original(h.plan,h.auth)
    assert h.loads==0 and not (h.directory/'material.used.json').exists()
    assert str(h.execute().verification)=='unknown' and h.loads==0
    h.material=EmsAccountInitialMaterialSource(h.enrollment,h.store)
    with pytest.raises(MaterialAccessDenied):h.material.acquire_original(h.plan,h.auth)
    h.close()


@pytest.mark.parametrize('field',['parameters_digest','expected_current_digest','action_id','adapter_ref','target_ref'])
def test_foreign_m4_context_refuses_before_material_resolution(tmp_path,monkeypatch,field):
    h=Harness(tmp_path,monkeypatch);h.stage(monkeypatch)
    values=asdict(h.plan);values.pop('plan_digest')
    values[field]='0'*64 if field.endswith('digest') else 'foreign-binding'
    h.plan=M4ExecutionPlan(**values,plan_digest=canonical_digest(values));h.authorize()
    assert str(h.execute().verification)=='unknown' and h.loads==0
    assert not (h.directory/'material.used.json').exists();h.close()


@pytest.mark.parametrize('fault',['expiry','env_drift','role_drift','loader_failure'])
def test_post_acquisition_drift_or_failure_clears_material_and_leaves_use_consumed(tmp_path,monkeypatch,fault):
    h=Harness(tmp_path,monkeypatch);h.stage(monkeypatch)
    def change():
        if fault=='expiry':h.now[0]=1060
        elif fault=='env_drift':
            with h.env.open('ab') as f:f.write(b'FOREIGN=synthetic\n')
        else:
            h.data['details']['synthetic-role']['manage_server_settings']=True;h.source.observe()
    if fault=='loader_failure':
        def fail(_):raise MaterialAccessDenied('Synthetic failure.')
        monkeypatch.setattr(type(h.enrollment._loader),'load_secret_create_material_once',fail)
    else:h.before_encode=change
    assert str(h.execute().verification)=='unknown' and not h.encoded and not h.raw and not h.username and not h.wire
    assert (h.directory/'material.used.json').exists()
    with pytest.raises(MaterialAccessDenied):h.material.acquire_original(h.plan,h.auth)
    h.close()


def test_generated_password_is_fixed_ascii_and_native_complexity_subset():
    raw=_generate_password()
    try:
        with memoryview(raw) as view:assert len(raw)==44 and _password_valid(view)
        for value in [b'a'*44,b'Ab0_'+b'a'*67,b'Ab0_\\bad',b'Ab0_"bad']:
            with memoryview(value) as view:assert not _password_valid(view)
    finally:_zeroize_mutable(raw)


def test_acquisition_and_unused_retirement_share_the_same_writer_barrier(tmp_path,monkeypatch):
    first=tmp_path/'first';first.mkdir(mode=0o700)
    h=Harness(first,monkeypatch);h.stage(monkeypatch)
    lock=h.enrollment._writer_lock;lock.write_bytes(b'foreign-writer');lock.chmod(0o600)
    assert str(h.execute().verification)=='unknown' and h.loads==0
    assert lock.read_bytes()==b'foreign-writer' and not (h.directory/'material.used.json').exists();h.close()
    second=tmp_path/'second';second.mkdir(mode=0o700)
    h=Harness(second,monkeypatch);h.enrollment.prepare_once();h.enrollment.register_once()
    original=h.enrollment._take_writer
    def concurrent_use(reference):
        writer=original(reference)
        h.enrollment._write('material.used.json',dict(reference=reference,plan_digest='1'*64,authorization_digest='2'*64,claimed_at=1000))
        return writer
    monkeypatch.setattr(h.enrollment,'_take_writer',concurrent_use)
    before=h.env.read_bytes()
    with pytest.raises(ValueError):h.enrollment.retire_unused_once()
    assert h.env.read_bytes()==before and not h.enrollment._writer_lock.exists();h.close()


@pytest.mark.parametrize('fault',['record','key','mode','symlink','foreign_loader'])
def test_enrollment_tamper_refuses_before_password_loading(tmp_path,monkeypatch,fault):
    h=Harness(tmp_path,monkeypatch);h.stage(monkeypatch)
    path=h.directory/'prepare.json'
    if fault=='record':
        value=json.loads(path.read_bytes());value['body']['value']['reference']+='0';path.write_text(json.dumps(value))
    elif fault=='key':h.key.write_bytes(b'z'*32)
    elif fault=='mode':path.chmod(0o644)
    elif fault=='symlink':
        other=h.root/'saved-prepare.json';path.rename(other);path.symlink_to(other)
    else:h.enrollment._loader._password_variable_name=b'FOREIGN_PASSWORD'
    assert str(h.execute().verification)=='unknown' and h.loads==0
    assert not (h.directory/'material.used.json').exists();h.close()


def test_expired_unused_enrollment_can_be_retired_after_fresh_parent_scope(tmp_path,monkeypatch):
    h=Harness(tmp_path,monkeypatch);h.enrollment.prepare_once();h.enrollment.register_once()
    h.now[0]=2801;h.source.observe()
    with pytest.raises(ValueError):h.enrollment.check_registered()
    h.enrollment.retire_unused_once()
    assert h.env.read_bytes()==h.original and h.loads==0;h.close()
