"""Exact complete unused append recovery never promotes the failed registration."""
import pytest

from fortipam_mcp.ems_tag_account_enrollment_recovery import retire_complete_unused_registration_once
from test_ems_tag_account_material import Harness


def failed_ack(h, monkeypatch):
    original=h.enrollment._write
    def write(name,value):
        if name=='append.ack.json':raise OSError('Synthetic missing ACK')
        return original(name,value)
    monkeypatch.setattr(h.enrollment,'_write',write)
    h.enrollment.prepare_once()
    with pytest.raises(ValueError):h.enrollment.register_once()
    assert not(h.directory/'append.ack.json').exists()
    return h.reopen(enabled=True)


@pytest.mark.parametrize('expired',[False,True])
def test_complete_unused_append_can_restore_prefix_without_repairing_original_ack(tmp_path,monkeypatch,expired):
    h=Harness(tmp_path,monkeypatch);entry=failed_ack(h,monkeypatch)
    original={p:p.read_bytes() for p in h.directory.iterdir()}
    if expired:h.now[0]=3000;h.source.observe()
    retire_complete_unused_registration_once(entry,execution_enabled=True)
    assert h.env.read_bytes()==h.original and h.loads==0 and not entry._writer_lock.exists()
    assert not(h.directory/'append.ack.json').exists() and not(h.directory/'material.used.json').exists()
    assert entry._record('retire.ack.json')['original_registration_unverified'] is True
    assert all(p.read_bytes()==value for p,value in original.items())
    with pytest.raises(ValueError):retire_complete_unused_registration_once(entry,execution_enabled=True)
    entry.close();h.close()


@pytest.mark.parametrize('fault',['default_off','foreign_tail','partial_tail','foreign_prefix','used','ack_present','parent_drift'])
def test_unknown_partial_foreign_or_used_registration_never_truncates(tmp_path,monkeypatch,fault):
    h=Harness(tmp_path,monkeypatch);entry=failed_ack(h,monkeypatch)
    if fault=='foreign_tail':
        with h.env.open('ab') as stream:stream.write(b'UNRELATED=value\n')
    elif fault=='partial_tail':h.env.write_bytes(h.env.read_bytes()[:-1])
    elif fault=='foreign_prefix':h.env.write_bytes(b'X'+h.env.read_bytes()[1:])
    elif fault=='used':entry._write('material.used.json',dict(reference=entry.reference))
    elif fault=='ack_present':entry._write('append.ack.json',dict(reference=entry.reference))
    elif fault=='parent_drift':
        h.data['details'][h.draft.role_uid]['manage_host_verification_rules']=False;h.source.observe()
    before=h.env.read_bytes()
    with pytest.raises(ValueError):retire_complete_unused_registration_once(entry,execution_enabled=fault!='default_off')
    assert h.env.read_bytes()==before and h.loads==0 and not entry._writer_lock.exists()
    assert not(h.directory/'retire.claim.json').exists();entry.close();h.close()
