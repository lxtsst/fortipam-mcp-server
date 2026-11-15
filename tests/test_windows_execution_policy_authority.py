"""Fresh source-bound Policy authorization refuses copied identity or drift."""
from dataclasses import replace

import pytest
from v4_planning import M4AuthorizationDenied

from fortipam_mcp.windows_execution_policy_authority import WindowsPolicyM4Authority
from fortipam_mcp.windows_execution_policy_sources import WindowsPolicySourceObservation
from test_windows_execution_policy_sources import make
from test_windows_execution_policy_lifecycle import IDENTITY


def test_authority_requires_live_source_identity_and_unchanged_observation(tmp_path,monkeypatch):
    source,*_=make(tmp_path,monkeypatch)
    now=[1000]
    authority=WindowsPolicyM4Authority(source,phase='create',authority_key=b'a'*32,
        execution_enabled=True,clock=lambda:now[0],**IDENTITY)
    observed=source.observe_absence()
    with pytest.raises(M4AuthorizationDenied):authority.preview(observed,requester_digest='d'*64,transport_digest=IDENTITY['transport_digest'])
    preview=authority.preview(observed,requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    issued=authority.issue(preview,source.observe_absence(),requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    authority.verify(issued.plan,issued.authorization,now_epoch=now[0])
    for plan,auth in ((replace(issued.plan),issued.authorization),(issued.plan,replace(issued.authorization))):
        with pytest.raises(M4AuthorizationDenied):authority.verify(plan,auth,now_epoch=now[0])
    authority.check_current(issued,source.observe_absence())
    with pytest.raises(M4AuthorizationDenied):authority.issue(preview,source._current,
        requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    now[0]=1060
    with pytest.raises(M4AuthorizationDenied):authority.verify(issued.plan,issued.authorization,now_epoch=now[0])
    authority.close();source.close()


def test_detached_observation_cannot_issue_or_preview_authority(tmp_path,monkeypatch):
    source,*_=make(tmp_path,monkeypatch)
    authority=WindowsPolicyM4Authority(source,phase='create',authority_key=b'a'*32,execution_enabled=True,
        clock=lambda:1000,**IDENTITY)
    observed=source.observe_absence()
    fake=replace(observed)
    with pytest.raises(M4AuthorizationDenied):authority.preview(fake,requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    preview=authority.preview(observed,requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    changed=replace(preview,current_digest='e'*64)
    with pytest.raises(M4AuthorizationDenied):authority.issue(changed,observed,
        requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    source.close()


def test_closed_or_changed_source_disables_issued_authority(tmp_path,monkeypatch):
    source,*_=make(tmp_path,monkeypatch)
    authority=WindowsPolicyM4Authority(source,phase='create',authority_key=b'a'*32,execution_enabled=True,
        clock=lambda:1000,**IDENTITY)
    observed=source.observe_absence()
    preview=authority.preview(observed,requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    issued=authority.issue(preview,observed,requester_digest=IDENTITY['requester_digest'],transport_digest=IDENTITY['transport_digest'])
    authority.close()
    with pytest.raises(M4AuthorizationDenied):authority.verify(issued.plan,issued.authorization,now_epoch=1000)
    source.close()
