"""Original Owner C2 compilation with no live intake session or source file."""

from dataclasses import replace
import time

import pytest

from fortipam_mcp.secret_bulk_import_dependencies import ResolvedImportDependencies, dependency_catalog_digest
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_row_action_worker import _compile_original_channel_action_pins
from fortipam_mcp.secret_bulk_import_row_conversion import _Build29OriginalRowConversion
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
from test_m4_execution_store import _Adapter, _Verifier
from test_secret_bulk_import_row_channel import channel
from test_secret_bulk_import_row_wire import SERIAL, project
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4Verification
from v4_planning.execution_kernel import _ACTIVE_DISPATCH


@pytest.fixture
def original(tmp_path, monkeypatch):
    graph, defaults = {}, project()
    local, session, state, _, root, handle, owner, _, reference, transport, uds, _, _ = channel(
        tmp_path, monkeypatch, material=True, capture=graph,
        ack_capture=WebSecretCreateAckCapture(SERIAL, 'success'), ack_defaults_digest=defaults.digest())
    session.close()
    assert not any(session._password) and not session._watchdog.is_alive()
    owner._binding.source.path.unlink()
    case = dict(local=local, state=state, root=root, handle=handle, owner=owner,
        defaults=defaults, key=local._rows._key.path, graph=graph, index=0)
    try:
        with reference:
            yield case
    finally:
        session.close(); transport.close(); uds.close()


def compile_pins(case):
    return _compile_original_channel_action_pins(case['owner'], case['graph']['catalog'],
        case['graph']['projected'], case['defaults'], namespace_key_path=case['key'], index=case['index'],
        target_name='Synthetic resolved target', associated_secret_id=None)


def run_original(case, check):
    calls = []
    class Dispatch(_Adapter):
        def dispatch(self, plan):
            calls.append(True)
            check()
            # Compilation alone must never claim a verified product result.
            raise M4AdapterAmbiguous('Synthetic compile-only dispatch')
    local, state = case['local'], case['state']
    kernel = M4ExecutionKernel(Dispatch(), _Verifier(), state)
    result = kernel.execute(local._plan, local._authorization, now_epoch=1000)
    assert result.verification is M4Verification.UNKNOWN
    assert kernel.execute(local._plan, local._authorization, now_epoch=1000).idempotent_replay
    assert calls == [True]


def test_original_c2_compiler_needs_neither_source_nor_unlock_and_cannot_revive_dispatch(original):
    owner = original['owner']
    before = {path: path.read_bytes() for path in (owner._parent._path, owner._material_store._path)}
    with pytest.raises(BulkImportIntakeError):
        compile_pins(original)
    def check():
        pins = compile_pins(original)
        assert pins.capture == owner._ack_pins.capture and pins.defaults_digest == owner._ack_pins.defaults_digest
        assert len(pins.metadata) == 93 and dict(pins.metadata)['name'] == 'Original first row'
        assert time.monotonic() < pins.deadline <= original['graph']['catalog'].expires_at
        assert owner._scope is None and owner._material_claim is None and owner._load_nonce is None
        assert not _ACTIVE_DISPATCH.get().material_reserved and not _ACTIVE_DISPATCH.get().product_reserved
    run_original(original, check)
    with pytest.raises(BulkImportIntakeError):
        compile_pins(original)
    assert all(path.read_bytes() == raw for path, raw in before.items())
    assert not owner._binding.source.path.exists() and not original['local']._used


@pytest.mark.parametrize('fault', ['graph', 'key', 'defaults', 'ack-binding', 'revoked', 'expired', 'row', 'armed', 'late-permission', 'late-record'])
def test_original_c2_compiler_rejects_unproven_or_consumed_inputs(original, monkeypatch, fault):
    owner = original['owner']
    if fault == 'graph':
        catalog = original['graph']['catalog']
        rows, targets, order = original['graph']['projected']._inspect_private(
            _Build29OriginalRowConversion._graph, file_digest=owner._binding.source.file_sha256,
            catalog_digest=dependency_catalog_digest(catalog))
        original['graph']['projected'] = ResolvedImportDependencies(
            (replace(rows[0], name='Substituted row'), *rows[1:]), targets, order,
            file_digest=owner._binding.source.file_sha256, catalog_digest=dependency_catalog_digest(catalog),
            expires=catalog.expires_at)
    elif fault == 'key':
        original['key'].write_bytes(b'x' * 32)
    elif fault == 'defaults':
        original['defaults'] = replace(original['defaults'], serial_digest='8' * 64)
    elif fault == 'ack-binding':
        owner._binding = replace(owner._binding, ack_pins_digest='8' * 64)
    elif fault == 'revoked':
        original['root'].revoke(original['handle'], now_epoch=1000)
    elif fault == 'expired':
        monkeypatch.setattr(owner, '_clock', lambda: 1060)
    elif fault == 'row':
        original['index'] = 1
    elif fault == 'late-permission':
        observe = owner._permission.verify_row_acquisition
        def late(*args, **kwargs):
            observe(*args, **kwargs)
            owner._clock = lambda: 1060
        monkeypatch.setattr(owner._permission, 'verify_row_acquisition', late)
    elif fault == 'late-record':
        read_record, calls = owner._record, []
        def delayed_record():
            result = read_record()
            calls.append(True)
            if len(calls) == 2:
                owner._clock = lambda: 1060
            return result
        monkeypatch.setattr(owner, '_record', delayed_record)
    def check():
        if fault == 'armed':
            owner.arm_original_dispatch()
        with pytest.raises(BulkImportIntakeError):
            compile_pins(original)
        assert not _ACTIVE_DISPATCH.get().product_reserved
    run_original(original, check)
    assert owner._material_claim is None and owner._load_nonce is None
