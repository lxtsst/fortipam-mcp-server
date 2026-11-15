"""Account authority joined to a real M4 ledger and synthetic material only."""
from dataclasses import asdict, replace

import pytest
from v4_planning import M4AuthorizationDenied, M4ExecutionKernel

from fortipam_mcp.ems_tag_account_authority import EmsAccountFixtureAuthority, LAB_SCOPE
from test_ems_tag_account_material import Harness
from test_ems_tag_role_fixture import CALLER


def authority(h, *, enabled=True, **changes):
    fields = dict(authority_key=b'v' * 32, **LAB_SCOPE, requester_digest=CALLER['requester_digest'],
                  transport_digest='f' * 64, execution_enabled=enabled, clock=lambda: h.now[0])
    fields.update(changes)
    return EmsAccountFixtureAuthority(h.enrollment, **fields)


def preview(a, h):
    return a.preview(h.source._current, requester_digest=CALLER['requester_digest'], transport_digest='f' * 64)


def issue(a, h, value):
    return a.issue(value, h.source._current, requester_digest=CALLER['requester_digest'], transport_digest='f' * 64)


def test_exact_authority_joins_active_m4_material_once_without_disclosing_material(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch);h.stage(monkeypatch)
    a = authority(h);value = preview(a, h);issued = issue(a, h, value)
    assert issued.plan.parameters_digest == h.material.parameters_digest
    assert issued.scope_digest == h.source._current.full_scope.digest
    assert issued.parent_digest == h.parent.inspect_verified_original().custody_digest
    a.check_current(h.source._current)
    h.plan, h.auth = issued.plan, issued.authorization
    result = M4ExecutionKernel(h, a, h.store, clock=lambda: h.now[0]).execute(h.plan, h.auth)
    assert str(result.outcome) == 'succeeded' and h.loads == 1 and h.encoded
    assert h.raw == bytearray(len(h.raw)) and h.username == bytearray(len(h.username))
    packet = repr(asdict(issued.plan)) + repr(asdict(issued.authorization)) + repr(value)
    assert 'password' not in packet.lower() and h.draft._metadata_body['name'] not in packet
    with pytest.raises(M4AuthorizationDenied):issue(a, h, value)
    with pytest.raises(M4AuthorizationDenied):preview(a, h)
    a.close();h.close()


def test_preview_replacement_caller_and_default_closed_policy(tmp_path, monkeypatch):
    h = Harness(tmp_path, monkeypatch);h.stage(monkeypatch)
    a = authority(h, enabled=False)
    first = preview(a, h);second = preview(a, h)
    with pytest.raises(M4AuthorizationDenied):issue(a, h, first)
    with pytest.raises(M4AuthorizationDenied):issue(a, h, second)
    with pytest.raises(M4AuthorizationDenied):a.preview(h.source._current, requester_digest='0' * 64, transport_digest='f' * 64)
    assert h.loads == 0 and not (h.directory / 'material.used.json').exists()
    a.close();h.close()


@pytest.mark.parametrize('fault', ['changed_scope', 'expired', 'foreign_preview', 'foreign_plan', 'closed'])
def test_authority_refuses_drift_expiry_and_foreign_context_before_material(tmp_path, monkeypatch, fault):
    h = Harness(tmp_path, monkeypatch);h.stage(monkeypatch)
    a = authority(h);value = preview(a, h)
    if fault == 'changed_scope':
        h.data['user']['other_config']['enabled'] = True;h.source.observe()
        with pytest.raises(M4AuthorizationDenied):issue(a, h, value)
    elif fault == 'expired':
        h.now[0] = value.expires_at
        with pytest.raises(M4AuthorizationDenied):issue(a, h, value)
    elif fault == 'foreign_preview':
        with pytest.raises(M4AuthorizationDenied):issue(a, h, replace(value))
    elif fault == 'foreign_plan':
        issued = issue(a, h, value)
        with pytest.raises(M4AuthorizationDenied):a.verify(replace(issued.plan), issued.authorization, now_epoch=h.now[0])
    else:
        a.close()
        with pytest.raises(M4AuthorizationDenied):issue(a, h, value)
    assert h.loads == 0 and not (h.directory / 'material.used.json').exists()
    a.close();h.close()


@pytest.mark.parametrize('field,value', [('scope_ref', 'other-lab'), ('authority_key', b'm' * 32),
                                         ('requester_digest', '0' * 64)])
def test_foreign_policy_key_or_requester_cannot_construct_authority(tmp_path, monkeypatch, field, value):
    h = Harness(tmp_path, monkeypatch);h.stage(monkeypatch)
    with pytest.raises(M4AuthorizationDenied):authority(h, **{field: value})
    assert h.loads == 0 and not (h.directory / 'material.used.json').exists()
    h.close()
