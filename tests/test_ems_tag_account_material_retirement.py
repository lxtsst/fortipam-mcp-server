"""Central cleanup requires the exact independently verified Account recovery."""
import json

import pytest

from fortipam_mcp.ems_tag_account_custody import EmsAccountCustody
from fortipam_mcp.ems_tag_account_enrollment import EmsAccountCentralEnrollment
from fortipam_mcp.ems_tag_account_material_retirement import retire_recovered_account_material_once
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_ems_tag_account_lifecycle import make, execute, reopen, recovery, close, close_recovery
from test_ems_tag_role_fixture import CALLER


def prepare(root, monkeypatch, *, expired=False):
    create = root / 'create';create.mkdir(mode=0o700)
    env = make(create, monkeypatch);assert str(execute(env).outcome) == 'succeeded'
    original = reopen(env);recover = recovery(root / 'recover', monkeypatch, env, original)
    assert str(recover['kernel'].execute(recover['issued'].plan, recover['issued'].authorization).outcome) == 'succeeded'
    store = recover['store']
    reader = PersistentM4ExecutionStateStore(store._path, store._key_path, monotonic_checkpoint=store._monotonic_checkpoint,
        checkpoint_store_ref=store._checkpoint_store_ref, read_only=True)
    recovered = EmsAccountCustody.open_recovery(recover['custody']._directory, recover['custody']._key_file, reader, original)
    if expired:recover['now'][0] = 2801;recover['source'].observe()
    h = env['h']
    enrollment = EmsAccountCentralEnrollment(recover['source'], h.draft, h.parent, requester_digest=CALLER['requester_digest'],
        env_file=h.env, directory=h.directory, witness_key_file=h.key, execution_enabled=True, clock=lambda: recover['now'][0])
    return env, original, recover, recovered, enrollment


def finish(env, original, recover, recovered, enrollment):
    enrollment.close();recovered.close();close_recovery(recover);original.close();close(env)


@pytest.mark.parametrize('expired', [False, True])
def test_recovered_account_retires_only_its_whole_append_after_fresh_original_role_scope(tmp_path, monkeypatch, expired):
    env, original, recover, recovered, enrollment = prepare(tmp_path, monkeypatch, expired=expired);h = env['h']
    protected = {p: p.read_bytes() for p in original._directory.iterdir()}
    retire_recovered_account_material_once(enrollment, recovered, execution_enabled=True)
    assert h.env.read_bytes() == h.original and h.loads == 1
    assert not enrollment._writer_lock.exists()
    claim = enrollment._record('retire.claim.json');ack = enrollment._record('retire.ack.json')
    assert claim['unused'] is False and claim['recovery_context'] == recovered._context
    assert ack['original_prefix_restored'] is True and ack['recovery_effect'] == claim['recovery_effect']
    assert (h.directory / 'material.used.json').is_file() and all(p.read_bytes() == raw for p, raw in protected.items())
    with pytest.raises(ValueError):retire_recovered_account_material_once(enrollment, recovered, execution_enabled=True)
    assert h.env.read_bytes() == h.original;finish(env, original, recover, recovered, enrollment)


@pytest.mark.parametrize('fault', ['default_off', 'writable_proof', 'foreign_tail', 'used_record_tamper', 'role_drift'])
def test_unbound_retirement_never_truncates_central_material(tmp_path, monkeypatch, fault):
    env, original, recover, recovered, enrollment = prepare(tmp_path, monkeypatch);h = env['h']
    if fault == 'foreign_tail':
        with h.env.open('ab') as stream:stream.write(b'UNRELATED=value\n')
    elif fault == 'used_record_tamper':
        path = h.directory / 'material.used.json';packet = json.loads(path.read_bytes())
        packet['body']['value']['plan_digest'] = '0' * 64;path.write_text(json.dumps(packet))
    elif fault == 'role_drift':
        recover['data']['details'][h.draft.role_uid]['manage_host_verification_rules'] = False
        recover['source'].observe()
    before = h.env.read_bytes()
    with pytest.raises(ValueError):retire_recovered_account_material_once(enrollment,
        recover['custody'] if fault == 'writable_proof' else recovered, execution_enabled=fault != 'default_off')
    assert h.env.read_bytes() == before and h.loads == 1 and not enrollment._writer_lock.exists()
    assert not (h.directory / 'retire.claim.json').exists();finish(env, original, recover, recovered, enrollment)
