"""Folder authority consumes only the concrete source's current observation."""
from dataclasses import replace

import pytest
from v4_planning import M4AuthorizationDenied

from fortipam_mcp.windows_execution_folder_authority import WindowsFolderM4Authority
from test_windows_execution_folder_sources import make
from test_windows_execution_folder_lifecycle import IDENTITY


def test_exact_preview_plan_authorization_and_current_source_identity(tmp_path,monkeypatch):
    source,api,policy,*_=make(tmp_path,monkeypatch)
    authority=WindowsFolderM4Authority(source,phase='create',authority_key=b'j'*32,
        execution_enabled=True,clock=lambda:1000,**IDENTITY)
    observed=source.observe_absence()
    with pytest.raises(M4AuthorizationDenied):
        authority.preview(replace(observed),requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    preview=authority.preview(observed,requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    issued=authority.issue(preview,source.observe_absence(),
        requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    authority.verify(issued.plan,issued.authorization,now_epoch=1000)
    with pytest.raises(M4AuthorizationDenied):authority.verify(replace(issued.plan),issued.authorization,now_epoch=1000)
    with pytest.raises(M4AuthorizationDenied):authority.verify(issued.plan,replace(issued.authorization),now_epoch=1000)
    authority.check_current(issued,source._current)
    authority.close()
    with pytest.raises(M4AuthorizationDenied):authority.verify(issued.plan,issued.authorization,now_epoch=1000)
    source.close();policy.close()


def test_requester_expiry_and_preview_hmac_cannot_be_supplied_or_mutated(tmp_path,monkeypatch):
    source,api,policy,*_=make(tmp_path,monkeypatch);now=[1000]
    authority=WindowsFolderM4Authority(source,phase='create',authority_key=b'j'*32,
        execution_enabled=True,clock=lambda:now[0],**IDENTITY)
    observed=source.observe_absence()
    with pytest.raises(M4AuthorizationDenied):
        authority.preview(observed,requester_digest='f'*64,transport_digest=IDENTITY['transport_digest'])
    preview=authority.preview(observed,requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    object.__setattr__(preview,'nonce','f'*48)
    with pytest.raises(M4AuthorizationDenied):
        authority.issue(preview,observed,requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    preview=authority.preview(observed,requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    now[0]=preview.expires_at
    with pytest.raises(M4AuthorizationDenied):
        authority.issue(preview,observed,requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    authority.close();source.close();policy.close()


def test_no_original_full_folder_custody_means_no_recovery_authority(tmp_path,monkeypatch):
    source,api,policy,*_=make(tmp_path,monkeypatch)
    with pytest.raises(M4AuthorizationDenied):
        WindowsFolderM4Authority(source,phase='recover',authority_key=b'z'*32,execution_enabled=True,**IDENTITY)
    source.close();policy.close()
