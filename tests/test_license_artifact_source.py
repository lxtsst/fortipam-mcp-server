"""Synthetic opaque license material only; no appliance, entitlement or upload."""
import copy
import hashlib
import os
from pathlib import Path
import pickle

import pytest

import fortipam_mcp.license_artifact_source as module
from fortipam_mcp.license_artifact_source import LicenseArtifactSource,MAX_LICENSE_BYTES
from test_system_email_authority import owner_file
from v4_planning.material_provider import MaterialAccessDenied,MaterialBindingStatus

MATERIAL=b'SYNTHETIC_OPAQUE_LICENSE_MUST_NEVER_REACH_MCP\x00\xff'
SCOPE,AUDIENCE='1'*64,'2'*64


def create(root,*,data=MATERIAL,guard=lambda:True,digest=None):
    path=owner_file(root/'synthetic.lic',data)
    source=LicenseArtifactSource(path,expected_sha256=digest or hashlib.sha256(data).hexdigest(),
        scope_digest=SCOPE,audience_digest=AUDIENCE,source_guard=guard)
    return source,path


def borrow(source,**kwargs): return source._borrow_once(scope_digest=kwargs.get('scope',SCOPE),audience_digest=kwargs.get('audience',AUDIENCE))


def test_startup_availability_is_metadata_only_then_one_readonly_borrow_clears_buffer(tmp_path,monkeypatch):
    read=module._read; buffers=[]
    def tracked(*args):
        raw=read(*args); buffers.append(raw); return raw
    monkeypatch.setattr(module,'_read',tracked); source,path=create(tmp_path)
    assert source.validate_prebound() is MaterialBindingStatus.AVAILABLE and buffers==[]
    with borrow(source) as view:
        assert view.readonly and bytes(view)==MATERIAL and len(buffers)==1
        with pytest.raises(TypeError): view[0]=0
        assert source.validate_prebound() is MaterialBindingStatus.UNAVAILABLE
    assert not any(buffers[0]) and source._buffer is None and path.read_bytes()==MATERIAL
    with pytest.raises(ValueError): bytes(view)
    with pytest.raises(MaterialAccessDenied):
        with borrow(source): pass
    assert len(buffers)==1


@pytest.mark.parametrize('guard',[None,lambda:False,lambda:1])
def test_default_and_non_boolean_guards_cannot_load_or_retry_same_borrow(tmp_path,monkeypatch,guard):
    source,_=create(tmp_path,guard=guard)
    monkeypatch.setattr(module,'_read',lambda *_:pytest.fail('Closed guard must precede material loading.'))
    assert source.validate_prebound() is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied):
        with borrow(source): pass
    assert source._used


@pytest.mark.parametrize('caller',[dict(scope='3'*64),dict(audience='3'*64),dict(scope=True),dict(audience=[]),dict(scope=None)])
def test_wrong_material_context_refuses_without_consuming_or_reading(tmp_path,monkeypatch,caller):
    source,_=create(tmp_path); read=module._read; calls=[]
    def tracked(*args): calls.append(True); return read(*args)
    monkeypatch.setattr(module,'_read',tracked)
    with pytest.raises(MaterialAccessDenied):
        with borrow(source,**caller): pass
    assert calls==[] and not source._used
    with borrow(source) as view: assert bytes(view)==MATERIAL
    assert calls==[True]


@pytest.mark.parametrize('change',['mode','replace','content','hardlink','symlink','parent-symlink'])
def test_metadata_drift_refuses_before_material_open(tmp_path,monkeypatch,change):
    directory=tmp_path/'private'; directory.mkdir(mode=0o700); source,path=create(directory)
    if change=='mode': path.chmod(0o644)
    elif change=='replace':
        path.unlink(); owner_file(path,MATERIAL)
    elif change=='content': path.write_bytes(b'x'*len(MATERIAL))
    elif change=='hardlink': os.link(path,directory/'alias')
    elif change=='symlink':
        other=owner_file(directory/'other.lic',MATERIAL); path.unlink(); path.symlink_to(other)
    else:
        moved=tmp_path/'moved'; directory.rename(moved); directory.symlink_to(moved,target_is_directory=True)
    monkeypatch.setattr(module,'_read',lambda *_:pytest.fail('File drift must precede material opening.'))
    assert source.validate_prebound() is MaterialBindingStatus.UNAVAILABLE
    with pytest.raises(MaterialAccessDenied):
        with borrow(source): pass


@pytest.mark.parametrize('fault',['digest','guard-after-read','replacement-after-read','read-failure'])
def test_failed_load_clears_owned_bytes_and_consumes_attempt(tmp_path,monkeypatch,fault):
    allowed=[True]; source,path=create(tmp_path,guard=lambda:allowed[0],digest='f'*64 if fault=='digest' else None)
    read=module._read; buffers=[]
    def tracked(*args):
        if fault=='read-failure': raise OSError(str(path))
        raw=read(*args); buffers.append(raw)
        if fault=='guard-after-read': allowed[0]=False
        elif fault=='replacement-after-read': path.unlink(); owner_file(path,MATERIAL)
        return raw
    monkeypatch.setattr(module,'_read',tracked)
    with pytest.raises(MaterialAccessDenied) as error:
        with borrow(source): pytest.fail('Unverified bytes must not be lent.')
    assert str(path) not in str(error.value) and MATERIAL.decode('ascii',errors='ignore') not in str(error.value)
    assert source._used and source._buffer is None and all(not any(raw) for raw in buffers)
    allowed[0]=True
    with pytest.raises(MaterialAccessDenied):
        with borrow(source): pass


@pytest.mark.parametrize('fault',['consumer','interrupt','close','guard','file-drift'])
def test_every_consumer_exit_releases_view_and_clears_material_without_deleting_file(tmp_path,fault):
    allowed=[True]; source,path=create(tmp_path,guard=lambda:allowed[0]); raw=None
    expected=KeyboardInterrupt if fault=='interrupt' else MaterialAccessDenied
    with pytest.raises(expected):
        with borrow(source) as view:
            raw=view.obj
            if fault=='consumer': raise RuntimeError(MATERIAL)
            if fault=='interrupt': raise KeyboardInterrupt()
            if fault=='close': source.close()
            elif fault=='guard': allowed[0]=False
            else: path.write_bytes(MATERIAL)
    assert raw is not None and not any(raw) and source._buffer is None and path.exists()
    with pytest.raises(ValueError): bytes(view)
    assert source.validate_prebound() is MaterialBindingStatus.UNAVAILABLE


def test_reentrant_guard_cannot_acquire_a_second_borrow(tmp_path,monkeypatch):
    armed=[False]; holder=[]; reads=[]; read=module._read
    def guard():
        if armed[0]:
            armed[0]=False
            with pytest.raises(MaterialAccessDenied):
                with borrow(holder[0]): pass
        return True
    source,_=create(tmp_path,guard=guard); holder.append(source); armed[0]=True
    def tracked(*args): reads.append(True); return read(*args)
    monkeypatch.setattr(module,'_read',tracked)
    with borrow(source) as view: assert bytes(view)==MATERIAL
    assert reads==[True]


@pytest.mark.parametrize('stage',['availability','before-read','after-read'])
@pytest.mark.parametrize('change',['close','replace-guard'])
def test_guard_callback_changes_refuse_before_availability_or_material_publication(tmp_path,monkeypatch,stage,change):
    holder=[];calls=[];buffers=[];read=module._read
    trigger=2 if stage=='after-read' else 1
    def guard():
        calls.append(True)
        if len(calls)==trigger:
            if change=='close': holder[0].close()
            else: holder[0]._guard=lambda:True
        return True
    source,_=create(tmp_path,guard=guard);holder.append(source)
    def tracked(*args):
        raw=read(*args);buffers.append(raw);return raw
    monkeypatch.setattr(module,'_read',tracked)
    if stage=='availability':
        assert source.validate_prebound() is MaterialBindingStatus.UNAVAILABLE
        assert not source._used and not buffers
    else:
        with pytest.raises(MaterialAccessDenied):
            with borrow(source): pytest.fail('Revoked source must not lend a material view.')
        assert source._used and source._buffer is None
        assert len(buffers)==(1 if stage=='after-read' else 0)
        assert all(not any(raw) for raw in buffers)
    assert len(calls)==trigger


@pytest.mark.parametrize('failure',[KeyboardInterrupt,SystemExit])
def test_interrupt_inside_shared_reader_clears_its_buffer_and_closes_both_descriptors(tmp_path,monkeypatch,failure):
    source,_=create(tmp_path); readv=os.readv; close=os.close; buffers=[]; descriptors=[]; closed=[]
    def interrupted(descriptor,views):
        count=readv(descriptor,views); buffers.append(views[0]); descriptors.append(descriptor)
        assert count==len(MATERIAL) and bytes(views[0][:count])==MATERIAL
        raise failure()
    def tracked_close(descriptor): closed.append(descriptor); close(descriptor)
    monkeypatch.setattr(os,'readv',interrupted); monkeypatch.setattr(os,'close',tracked_close)
    with pytest.raises(failure):
        with borrow(source): pytest.fail('Interrupted bytes must not be lent.')
    assert buffers and all(not any(raw) for raw in buffers) and source._buffer is None and source._used
    assert descriptors[0] in closed and len(closed)>=2
    for descriptor in closed[-2:]:
        with pytest.raises(OSError): os.fstat(descriptor)


@pytest.mark.parametrize('stage',['file-close','parent-close'])
@pytest.mark.parametrize('failure',[OSError,KeyboardInterrupt,SystemExit])
def test_shared_reader_close_failure_clears_material_and_attempts_other_descriptor(tmp_path,monkeypatch,stage,failure):
    source,_=create(tmp_path); opened=[]; buffers=[]; file_descriptor=[]; closed=[]; fired=[]
    open_file,readv,close=os.open,os.readv,os.close
    def tracked_open(*args,**kwargs):
        descriptor=open_file(*args,**kwargs); opened.append(descriptor); return descriptor
    def tracked_readv(descriptor,views):
        file_descriptor.append(descriptor); buffers.append(views[0]); return readv(descriptor,views)
    def failed_close(descriptor):
        closed.append(descriptor); close(descriptor)
        if file_descriptor and not fired and descriptor==(file_descriptor[0] if stage=='file-close' else opened[-2]):
            fired.append(True); raise failure()
    monkeypatch.setattr(os,'open',tracked_open); monkeypatch.setattr(os,'readv',tracked_readv); monkeypatch.setattr(os,'close',failed_close)
    with pytest.raises(MaterialAccessDenied if failure is OSError else failure):
        with borrow(source): pytest.fail('Cleanup failure must not lend material.')
    assert fired==[True] and buffers and all(not any(raw) for raw in buffers) and source._used and source._buffer is None
    assert file_descriptor[0] in closed and opened[-2] in closed
    for descriptor in (file_descriptor[0],opened[-2]):
        with pytest.raises(OSError): os.fstat(descriptor)


def test_path_walk_close_failure_still_closes_new_directory_handle(tmp_path,monkeypatch):
    source,_=create(tmp_path); opened=[]; closed=[]; fired=[]; open_file,close=os.open,os.close
    def tracked_open(*args,**kwargs):
        descriptor=open_file(*args,**kwargs); opened.append(descriptor); return descriptor
    def failed_close(descriptor):
        closed.append(descriptor); close(descriptor)
        if not fired: fired.append(True); raise OSError()
    monkeypatch.setattr(os,'open',tracked_open); monkeypatch.setattr(os,'close',failed_close)
    monkeypatch.setattr(os,'readv',lambda *_:pytest.fail('A failed directory walk must not read material.'))
    with pytest.raises(MaterialAccessDenied):
        with borrow(source): pass
    assert len(opened)==2 and closed==opened and source._used and source._buffer is None
    for descriptor in opened:
        with pytest.raises(OSError): os.fstat(descriptor)


def test_close_before_use_does_not_load_and_private_objects_cannot_be_serialized(tmp_path,monkeypatch):
    source,path=create(tmp_path); source.close()
    monkeypatch.setattr(module,'_read',lambda *_:pytest.fail('Closed source must never load.'))
    with pytest.raises(MaterialAccessDenied):
        with borrow(source): pass
    for operation in (copy.copy,copy.deepcopy,pickle.dumps):
        with pytest.raises(MaterialAccessDenied): operation(source)


@pytest.mark.parametrize('error_type',[MemoryError,RuntimeError,KeyboardInterrupt,SystemExit])
def test_borrow_cleanup_failure_still_clears_material_and_drops_private_reference(tmp_path,monkeypatch,error_type):
    from fortipam_mcp import mutable_json_buffer
    source,path=create(tmp_path);retained=[]
    def failure(_raw): raise error_type('Synthetic cleanup failure')
    # Exercise the existing block eraser's scalar fallback through the real
    # material source, including the reference release after it rethrows.
    with pytest.raises(error_type):
        with borrow(source) as view:
            retained.append(view.obj)
            monkeypatch.setattr(mutable_json_buffer,'_wipe',failure)
    assert retained and not any(retained[0]) and source._buffer is None and source._used
    with pytest.raises(ValueError): bytes(view)
    assert path.read_bytes()==MATERIAL


@pytest.mark.parametrize('error_type',[BufferError,KeyboardInterrupt,SystemExit])
@pytest.mark.parametrize('release_first',[False,True])
def test_view_release_failure_cannot_skip_independent_material_erasure(tmp_path,monkeypatch,error_type,release_first):
    source,path=create(tmp_path);views=[];retained=[];native_view=memoryview
    class View:
        def __init__(self,raw): self.actual=native_view(raw).toreadonly();views.append(self.actual)
        def toreadonly(self): return self
        @property
        def obj(self): return self.actual.obj
        def release(self):
            if release_first: self.actual.release()
            raise error_type('Synthetic view-release failure')
    monkeypatch.setattr(module,'memoryview',View,raising=False)
    try:
        with pytest.raises(error_type):
            with borrow(source) as view: retained.append(view.obj)
        assert retained and not any(retained[0]) and source._buffer is None and source._used
        assert path.read_bytes()==MATERIAL
    finally:
        for view in views: view.release()


@pytest.mark.parametrize('error_type',[MemoryError,RuntimeError,KeyboardInterrupt,SystemExit])
def test_close_during_borrow_releases_its_reference_even_if_eraser_rethrows(tmp_path,monkeypatch,error_type):
    source,path=create(tmp_path);erase=module._erase_transfer_storage;calls=[];retained=[]
    def failure(raw):
        calls.append(raw);erase(raw)
        if len(calls)==1: raise error_type('Synthetic close failure')
    monkeypatch.setattr(module,'_erase_transfer_storage',failure)
    with pytest.raises(MaterialAccessDenied):
        with borrow(source) as view:
            retained.append(view.obj)
            with pytest.raises(error_type): source.close()
            assert source._closed and source._buffer is None and not any(retained[0])
    assert len(calls)==2 and not any(retained[0]) and source._used
    assert path.read_bytes()==MATERIAL
    assert str(path) not in repr(source) and MATERIAL.decode('ascii',errors='ignore') not in str(source)


@pytest.mark.parametrize('fault',['empty','oversize','file-mode','directory-mode','git','relative','traversal','hash'])
def test_invalid_binding_has_no_native_or_material_effect(tmp_path,monkeypatch,fault):
    directory=tmp_path/'private'; directory.mkdir(mode=0o700)
    data=b'' if fault=='empty' else b'x'*(MAX_LICENSE_BYTES+1) if fault=='oversize' else MATERIAL
    path=owner_file(directory/'synthetic.lic',data)
    if fault=='file-mode': path.chmod(0o644)
    elif fault=='directory-mode': directory.chmod(0o755)
    elif fault=='git': (directory/'.git').write_text('Synthetic checkout marker')
    elif fault=='relative': path=Path('synthetic.lic')
    elif fault=='traversal': path=directory/'..'/'private'/'synthetic.lic'
    monkeypatch.setattr(module,'_read',lambda *_:pytest.fail('Construction must not read material.'))
    with pytest.raises(MaterialAccessDenied) as error:
        LicenseArtifactSource(path,expected_sha256='invalid' if fault=='hash' else hashlib.sha256(data).hexdigest(),
            scope_digest=SCOPE,audience_digest=AUDIENCE)
    assert str(path) not in str(error.value)
