"""Synthetic license bytes only; no device, credential, upload or reboot."""
import base64
import hashlib
import json

import pytest

import fortipam_mcp.license_artifact_source as source_module
import fortipam_mcp.license_upload_contract as module
from fortipam_mcp.license_artifact_source import LicenseArtifactSource,MAX_LICENSE_BYTES
from test_system_email_authority import owner_file
from v4_planning.material_provider import MaterialAccessDenied

SCOPE,AUDIENCE='1'*64,'2'*64


def source_for(root,*,data=b'SYNTHETIC_LICENSE\x00\xff',filename='synthetic.lic',guard=lambda:True):
    path=owner_file(root/filename,data)
    return LicenseArtifactSource(path,expected_sha256=hashlib.sha256(data).hexdigest(),
        scope_digest=SCOPE,audience_digest=AUDIENCE,source_guard=guard),path


def compile(source,**kwargs):
    return module._compile_license_upload(source,scope_digest=kwargs.get('scope',SCOPE),audience_digest=kwargs.get('audience',AUDIENCE))


@pytest.mark.parametrize('size',[1,2,3,4,5,255,256,257,MAX_LICENSE_BYTES])
def test_exact_native_two_field_body_matches_reference_base64_then_clears_every_owned_buffer(tmp_path,size):
    data=(bytes(range(256))*((size+255)//256))[:size]
    source,path=source_for(tmp_path,data=data,filename='synthetic "许可".lic')
    with compile(source) as view:
        assert view.readonly
        body,material=view.obj,source._buffer
        value=json.loads(bytes(view))
        assert value==dict(filename=path.name,file_content=base64.b64encode(data).decode('ascii'))
        assert base64.b64decode(value['file_content'],validate=True)==data
    assert not any(body) and not any(material) and source._buffer is None
    assert path.read_bytes()==data
    with pytest.raises(ValueError): bytes(view)
    with pytest.raises(MaterialAccessDenied):
        with compile(source): pytest.fail('The consumed file cannot compile twice.')


@pytest.mark.parametrize('guard',[None,lambda:False,lambda:1])
def test_closed_guard_precedes_material_read_and_consumes_source(tmp_path,monkeypatch,guard):
    source,_=source_for(tmp_path,guard=guard)
    monkeypatch.setattr(source_module,'_read',lambda *_:pytest.fail('Closed guard must not read license bytes.'))
    with pytest.raises(MaterialAccessDenied):
        with compile(source): pass
    assert source._used


@pytest.mark.parametrize('context',[dict(scope='3'*64),dict(audience='3'*64)])
def test_wrong_private_context_does_not_read_or_consume(tmp_path,monkeypatch,context):
    source,_=source_for(tmp_path)
    monkeypatch.setattr(source_module,'_read',lambda *_:pytest.fail('Wrong context must not read license bytes.'))
    with pytest.raises(MaterialAccessDenied):
        with compile(source,**context): pass
    assert not source._used


def test_control_character_filename_refuses_before_material_read(tmp_path,monkeypatch):
    source,_=source_for(tmp_path,filename='synthetic\n.lic')
    monkeypatch.setattr(source_module,'_read',lambda *_:pytest.fail('Unsupported filename must precede material loading.'))
    with pytest.raises(MaterialAccessDenied):
        with compile(source): pass
    assert not source._used


def test_filename_path_binding_cannot_change_inside_material_guard(tmp_path,monkeypatch):
    holder=[]; buffers=[]; original_read=source_module._read
    def guard():
        source=holder[0]
        source._path=type(source._path)(str(source._path))
        return True
    source,_=source_for(tmp_path,guard=guard);holder.append(source)
    def read(*args):
        raw=original_read(*args);buffers.append(raw);return raw
    monkeypatch.setattr(source_module,'_read',read)
    with pytest.raises(MaterialAccessDenied):
        with compile(source): pytest.fail('A changed filename binding cannot publish a body.')
    assert source._used and buffers and all(not any(raw) for raw in buffers)


@pytest.mark.parametrize('change',['close','replace-guard'])
def test_final_guard_callback_cannot_publish_encoded_body_after_revocation(tmp_path,monkeypatch,change):
    holder=[];calls=[];cleared=[];clear=module._zeroize_mutable
    def guard():
        calls.append(True)
        if len(calls)==3:
            if change=='close': holder[0].close()
            else: holder[0]._guard=lambda:True
        return True
    source,path=source_for(tmp_path,guard=guard);holder.append(source)
    def tracked(raw): clear(raw);cleared.append(raw)
    monkeypatch.setattr(module,'_zeroize_mutable',tracked)
    with pytest.raises(MaterialAccessDenied):
        with compile(source): pytest.fail('Revocation must precede delivery of the encoded body.')
    assert len(calls)==3 and source._used and source._buffer is None
    assert cleared and all(not any(raw) for raw in cleared)
    assert path.exists()


@pytest.mark.parametrize('failure',['consumer','interrupt','system-exit','guard','close','path'])
def test_all_consumer_exits_clear_material_and_compiled_body(tmp_path,failure):
    allowed=[True]; source,path=source_for(tmp_path,guard=lambda:allowed[0])
    expected=KeyboardInterrupt if failure=='interrupt' else SystemExit if failure=='system-exit' else MaterialAccessDenied
    with pytest.raises(expected) as error:
        with compile(source) as view:
            body,material=view.obj,source._buffer
            if failure=='consumer': raise RuntimeError('SYNTHETIC_LICENSE')
            if failure=='interrupt': raise KeyboardInterrupt()
            if failure=='system-exit': raise SystemExit()
            if failure=='guard': allowed[0]=False
            elif failure=='close': source.close()
            else: source._path=path.with_name('foreign.lic')
    assert not any(body) and not any(material) and source._buffer is None and source._used
    assert 'SYNTHETIC_LICENSE' not in str(error.value) and str(path) not in str(error.value)
    with pytest.raises(ValueError): bytes(view)


@pytest.mark.parametrize('failure',[OSError,KeyboardInterrupt,SystemExit])
def test_encoder_interruption_clears_partial_body_and_source(tmp_path,monkeypatch,failure):
    source,_=source_for(tmp_path); cleared=[]; original_clear=module._zeroize_mutable
    class FailingAlphabet:
        calls=0
        def __getitem__(self,index):
            self.calls+=1
            if self.calls==4: raise failure()
            return 65
    def clear(raw): original_clear(raw); cleared.append(raw)
    monkeypatch.setattr(module,'_B64',FailingAlphabet());monkeypatch.setattr(module,'_zeroize_mutable',clear)
    with pytest.raises(MaterialAccessDenied if failure is OSError else failure):
        with compile(source): pytest.fail('Partial body must not be lent.')
    assert cleared and all(not any(raw) for raw in cleared) and source._buffer is None and source._used


def test_boundary_contains_no_private_file_facts_or_execution_authority():
    boundary=module.license_upload_request_boundary()
    assert boundary['json_fields']==['filename','file_content']
    assert boundary['file_content_encoding']=='standard_base64'
    for field in ('native_request_accepted','strict_ack_contract_verified','execution_authorized','http_transport_registered','device_contacted'):
        assert boundary[field] is False


def test_material_body_never_resizes_after_first_in_place_write(tmp_path,monkeypatch):
    class FixedMaterialBody(bytearray):
        sealed=False
        def __setitem__(self,key,value):
            self.sealed=True
            return super().__setitem__(key,value)
        def extend(self,value):
            if self.sealed: raise AssertionError('Material-bearing allocations must never grow.')
            return super().extend(value)
    source,_=source_for(tmp_path,data=b'1234')
    monkeypatch.setattr(module,'bytearray',FixedMaterialBody,raising=False)
    with compile(source) as view:
        body=view.obj
        assert json.loads(bytes(view))['file_content']=='MTIzNA=='
    assert body.sealed and not any(body)


@pytest.mark.parametrize('error_type', (MemoryError, RuntimeError, KeyboardInterrupt, SystemExit))
@pytest.mark.parametrize('release_completed', (False, True))
def test_view_release_failure_cannot_skip_encoded_body_erasure(tmp_path, monkeypatch, error_type, release_completed):
    source, path = source_for(tmp_path)
    views, bodies, material = [], [], []
    class FailingReleaseView:
        def __init__(self, raw):
            self.real = memoryview(raw).toreadonly()
            views.append(self.real); bodies.append(raw)
        def toreadonly(self): return self
        def release(self):
            if release_completed: self.real.release()
            raise error_type('Synthetic encoded-view release failure')
    monkeypatch.setattr(module, 'memoryview', FailingReleaseView, raising=False)
    try:
        with pytest.raises(error_type):
            with compile(source):
                material.append(source._buffer)
        assert bodies and all(not any(raw) for raw in bodies)
        assert material and all(not any(raw) for raw in material)
        assert source._buffer is None and source._used and path.exists()
        with pytest.raises(MaterialAccessDenied):
            with compile(source): pytest.fail('Cleanup failure cannot reopen the original file.')
    finally:
        for view in views: view.release()
        for raw in bodies: module._zeroize_mutable(raw)
        source.close()
