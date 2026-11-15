"""Original metadata, real SDK identity guards and persistent M4/C3 ownership."""
from dataclasses import replace
import hashlib
import hmac
import json

import pytest

from fortipam_mcp import windows_service_credential_subject_sources as s
from fortipam_mcp.secret_create_central_lab_provider import OwnerOnlyCentralLabSecretCreateEnvFileLoader
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from fortipam_mcp.windows_execution_secret_contract import MachineQualifiedWindowsLocalLoader
from fortipam_mcp.windows_service_credential_material import windows_service_credential_material_runtime, windows_service_credential_parameters_digest, ADAPTER_REF, TARGET_REF
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_secret_create_m4_runtime import _secret_plan, _authorization, _binding, _Resolver, _Verifier, _Reader
from test_v4_material_persistence import _ExternalMaterialCheckpoint
from test_windows_service_credential_contract import binding
from test_windows_service_credential_server_identity import setup as identity_setup, token
from test_windows_service_credential_target_sources import Harness
from test_windows_privileged_secret_contract import defaults
from v4_planning import canonical_digest, M4Outcome
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import MaterialAccessDenied, MaterialBindingStatus, MaterialProviderClass
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome


def private(path,raw):
    path.write_bytes(raw);path.chmod(0o600);return path


def signed(path,record,key=b's'*32):
    raw=json.dumps(record,sort_keys=True,separators=(',',':')).encode()
    mac=hmac.new(key,s.DOMAIN+raw,hashlib.sha256).hexdigest()
    private(path,b'{"record":'+raw+b',"mac":"'+mac.encode()+b'"}')


def setup(tmp_path,monkeypatch,*,record_fault=None):
    tmp_path.chmod(0o700)
    identity,current,now,_=identity_setup();snapshot=identity.capture(purpose='create')
    peer=Harness();target=peer.reader();observed=target.read_once()
    env=private(tmp_path/'env',b'UNIT_USERNAME=labuser\nUNIT_PASSWORD=synthetic-credential\n')
    key=private(tmp_path/'source.key',b's'*32);record_file=tmp_path/'enrollment.json';retired=tmp_path/'retired';claim=tmp_path/'product-use.json'
    record={field:hashlib.sha256(field.encode()).hexdigest()for field in s._DIGESTS}
    record.update(contract=s.CONTRACT,machine_name='UNIT-WINDOWS',user_name='labuser',created_at=999,subject_expires_at=8000,
        requester_digest=snapshot.requester_digest,creator_transport_digest=snapshot.transport_digest,
        target_reference_context_digest=observed.target_reference_context_digest,
        username_mac=hmac.new(b's'*32,b'labuser',hashlib.sha256).hexdigest(),
        password_mac=hmac.new(b's'*32,b'synthetic-credential',hashlib.sha256).hexdigest(),
        retired_marker_digest=s._path_digest(retired),material_claim_path_digest=s._path_digest(claim))
    if record_fault:record_fault(record)
    signed(record_file,record)
    response={**{field:record[field]for field in s._INSPECT_DIGESTS},**dict.fromkeys(s._INSPECT_FLAGS,True)}
    raw_buffers=[];loaded=[];calls={'inspect':0,'load':0};registration=[True]
    def inspect():
        calls['inspect']+=1;raw=bytearray(json.dumps(response).encode());raw_buffers.append(raw);return raw
    original=OwnerOnlyCentralLabSecretCreateEnvFileLoader.load_secret_create_material_once
    def load(self):
        calls['load']+=1;pair=original(self);loaded.extend(pair);return pair
    monkeypatch.setattr(OwnerOnlyCentralLabSecretCreateEnvFileLoader,'load_secret_create_material_once',load)
    loader=OwnerOnlyCentralLabSecretCreateEnvFileLoader(secret_env_path=env,username_variable_name='UNIT_USERNAME',password_variable_name='UNIT_PASSWORD')
    kwargs=dict(identity=identity,snapshot=snapshot,target_source=target,target_observation=observed,enrollment_file=record_file,
        enrollment_key_file=key,retired_marker=retired,material_use_claim_file=claim,loader=loader,inspect_original=inspect,
        registration_current=lambda:registration[0],enabled=True)
    return dict(kwargs=kwargs,identity=identity,current=current,now=now,peer=peer,target=target,observed=observed,record=record,
        response=response,raw_buffers=raw_buffers,loaded=loaded,calls=calls,registration=registration,
        env=env,key=key,file=record_file,retired=retired,claim=claim)


def test_original_source_qualifies_without_values_and_material_denies_without_real_m4(tmp_path,monkeypatch):
    c=setup(tmp_path,monkeypatch);source=s.WindowsServiceCredentialSubjectSources(**c['kwargs'])
    observed=source.qualify_once();source.check_current(observed)
    assert source.validate_prebound()is MaterialBindingStatus.AVAILABLE
    assert c['calls']==dict(inspect=1,load=0)and all(not raw for raw in c['raw_buffers'])
    with pytest.raises(MaterialAccessDenied):source.load_secret_create_material_once()
    assert c['calls']['load']==0 and not c['claim'].exists()
    assert observed.summary()['activity_qualified']is observed.summary()['c3_lease_issued']is False
    assert 'labuser'not in repr(observed)and 'synthetic-credential'not in repr(source)
    with pytest.raises(MaterialAccessDenied):source.qualify_once()
    source.close();assert not source._key and not c['target']._closed
    c['target'].close();c['identity'].close()


@pytest.mark.parametrize('fault',['disabled','retired','foreign-human','changed-target','bad-mac','wrong-path','foreign-inspection',
    'admin','running','profile','hive','rights','wrong-address','missing-authentication','unknown-field','invalid-bool'])
def test_unqualified_or_retired_input_refuses_without_loading_material(tmp_path,monkeypatch,fault):
    c=setup(tmp_path,monkeypatch)
    if fault=='disabled':c['kwargs']['enabled']=False
    if fault=='retired':c['retired'].write_text('retired')
    if fault=='foreign-human':
        c['record']['requester_digest']='f'*64;signed(c['file'],c['record'])
    if fault=='changed-target':
        c['record']['target_reference_context_digest']='f'*64;signed(c['file'],c['record'])
    if fault=='bad-mac':c['file'].write_bytes(c['file'].read_bytes().replace(b'"mac":"',b'"mac":"0'))
    if fault=='wrong-path':c['kwargs']['retired_marker']=tmp_path/'another-retired'
    if fault=='foreign-inspection':c['response']['subject_sid_digest']='f'*64
    for label,key in {'admin':'nonadmin','running':'service_stopped','profile':'profile_absent','hive':'hive_absent',
        'rights':'service_right_only','wrong-address':'target_address_matches','missing-authentication':'original_credential_verification_retained'}.items():
        if fault==label:c['response'][key]=False
    if fault=='unknown-field':c['response']['password']='PRIVATE_UNKNOWN_SENTINEL'
    if fault=='invalid-bool':c['response']['nonadmin']=1
    with pytest.raises(MaterialAccessDenied):
        source=s.WindowsServiceCredentialSubjectSources(**c['kwargs']);source.qualify_once()
    assert c['calls']['load']==0 and not c['claim'].exists()and all(not raw for raw in c['raw_buffers'])
    c['target'].close();c['identity'].close()


@pytest.mark.parametrize('fault',['copy','tamper','expiry','retire','registration','target-close','identity-close','changed-client',
    'key','enrollment','path-remap'])
def test_metadata_admission_stays_bound_to_live_identity_and_original_files(tmp_path,monkeypatch,fault):
    c=setup(tmp_path,monkeypatch);source=s.WindowsServiceCredentialSubjectSources(**c['kwargs']);observed=source.qualify_once()
    if fault=='copy':observed=replace(observed)
    if fault=='tamper':object.__setattr__(observed,'subject_sid_digest','f'*64)
    if fault=='expiry':c['now'][0]=1030
    if fault=='retire':c['retired'].write_text('retired')
    if fault=='registration':c['registration'][0]=False
    if fault=='target-close':c['target'].close()
    if fault=='identity-close':c['identity'].close()
    if fault=='changed-client':c['current'][0]=token(client_id='different-client')
    if fault=='key':c['key'].write_bytes(b'x'*32)
    if fault=='enrollment':c['file'].write_bytes(c['file'].read_bytes()+b' ')
    if fault=='path-remap':source._retired=tmp_path/'another-marker'
    with pytest.raises(MaterialAccessDenied):source.check_current(observed)
    assert source.validate_prebound()is MaterialBindingStatus.UNAVAILABLE and c['calls']['load']==0
    source.close();c['target'].close();c['identity'].close()


def components(tmp_path,monkeypatch,*,wrong_mac=False):
    c=setup(tmp_path,monkeypatch,record_fault=(lambda record:record.update(password_mac='f'*64))if wrong_mac else None)
    source=s.WindowsServiceCredentialSubjectSources(**c['kwargs']);observed=source.qualify_once()
    baseline=replace(defaults(),serial_digest=c['target']._serial)
    profile=replace(binding(),target_name=c['target']._name,target_address=c['target']._address,serial_digest=c['target']._serial,
        target_reference_context_digest=observed.target_reference_context_digest,subject_context_digest=observed.subject_context_digest,
        subject_sid_digest=observed.subject_sid_digest,service_context_digest=observed.service_context_digest,
        material_source_context_digest=observed.material_source_context_digest)
    private(tmp_path/'m4.key',b'e'*32);private(tmp_path/'material.key',b'm'*32)
    execution=PersistentM4ExecutionStateStore(tmp_path/'m4.sqlite',tmp_path/'m4.key',monotonic_checkpoint=_ExternalM4Checkpoint(),checkpoint_store_ref=CHECKPOINT_STORE_REF)
    material=PersistentMaterialUseStateStore(tmp_path/'material.sqlite',tmp_path/'material.key',monotonic_checkpoint=_ExternalMaterialCheckpoint('service-subject-c3'),checkpoint_store_ref='service-subject-c3')
    parameters=windows_service_credential_parameters_digest(profile,baseline,create_uuid='00000000-0000-0000-0000-000000000000')
    base=_secret_plan();fields={**base.canonical_content(),'requester_digest':c['kwargs']['snapshot'].requester_digest,
        'adapter_ref':ADAPTER_REF,'target_ref':TARGET_REF,'parameters_digest':parameters}
    plan=replace(base,requester_digest=fields['requester_digest'],adapter_ref=ADAPTER_REF,target_ref=TARGET_REF,parameters_digest=parameters,plan_digest=canonical_digest(fields))
    original_authorization=_authorization(plan)
    content={**original_authorization.canonical_content(),'requester_digest':plan.requester_digest}
    authorization=replace(original_authorization,requester_digest=plan.requester_digest,authorization_digest=canonical_digest(content))
    bound=_binding(plan,authorization)
    bound=replace(bound,material_binding=source.material_binding,lease_request=replace(bound.lease_request,provider_class=MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE))
    source.bind_original_dispatch(profile=profile,defaults=baseline,plan=plan,authorization=authorization,request=bound.lease_request,
        execution_store=execution,material_store=material,material_binding=source.material_binding)
    class Peer:
        calls=0;body=None
        def _windows_service_credential_ready(self,profile,request):return True
        def _create_windows_service_credential(self,profile,request,body):
            self.calls+=1;self.body=body.obj
            assert b'UNIT-WINDOWS\\\\labuser'in body.obj and b'synthetic-credential'in body.obj
            return SecretCreateAdapterOutcome.VERIFIED_CREATED
    peer=Peer()
    runtime=windows_service_credential_material_runtime(profile=profile,defaults=baseline,create_uuid='00000000-0000-0000-0000-000000000000',
        plan=plan,authorization=authorization,execution_store=execution,material_store=material,material_binding=source.material_binding,
        request=bound.lease_request,loader=source,transport=peer,clock=lambda:c['now'][0])
    outer=ProtectedSecretCreateM4Runtime(_Resolver(bound),_Verifier(),execution,runtime,_Reader(),authenticated_requester_digest=plan.requester_digest,clock=lambda:c['now'][0])
    c.update(source=source,peer=peer,outer=outer,bound=bound,execution=execution,material=material)
    return c


@pytest.mark.parametrize('wrong_mac',[False,True])
def test_native_bare_username_source_uses_real_original_m4_c3_and_retains_consumed_marker(tmp_path,monkeypatch,wrong_mac):
    c=components(tmp_path,monkeypatch,wrong_mac=wrong_mac)
    with pytest.raises(MaterialAccessDenied):c['source'].load_secret_create_material_once()
    assert c['calls']['load']==0 and not c['claim'].exists()
    result=c['outer'].execute_bound(c['bound'].authorization.authorization_ref)
    assert result.outcome is(M4Outcome.RECONCILIATION_REQUIRED if wrong_mac else M4Outcome.SUCCEEDED)
    assert c['calls']['load']==1 and c['claim'].is_file()and c['execution'].claim_count==c['material'].claim_count==1
    assert c['peer'].calls==(0 if wrong_mac else 1)
    assert all(not raw for raw in c['raw_buffers']+c['loaded'])
    assert c['peer'].body is None or not c['peer'].body
    c['outer'].execute_bound(c['bound'].authorization.authorization_ref)
    assert c['calls']['load']==1
    c['source'].close();assert c['claim'].is_file();c['target'].close();c['identity'].close()


def test_existing_machine_qualifier_rejects_bootstrap_only_prefixed_source(tmp_path):
    env=private(tmp_path/'env',b'UNIT_USERNAME=UNIT-WINDOWS\\labuser\nUNIT_PASSWORD=synthetic-credential\n')
    loader=OwnerOnlyCentralLabSecretCreateEnvFileLoader(secret_env_path=env,username_variable_name='UNIT_USERNAME',password_variable_name='UNIT_PASSWORD')
    qualified=MachineQualifiedWindowsLocalLoader(loader,machine_name='UNIT-WINDOWS')
    with pytest.raises(Exception):qualified.load_secret_create_material_once()
