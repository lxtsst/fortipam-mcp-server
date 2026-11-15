"""Global multiplicity and same-device identity never imply association authority."""
import asyncio
import copy
from dataclasses import replace
import hashlib
import pickle

import pytest
from fortipam_mcp import secret_bulk_import_namespace_reader as m
from test_target_qualified_reference_reader import Peer, SERIAL, ROOT, frame

CONTEXT = ROOT[:-2] + b' (database) #'
NAMES = ('Visible A', 'Visible B', 'Hidden', 'Visible A')


@pytest.fixture
def setup(tmp_path, monkeypatch):
    pin = tmp_path / 'known_hosts'
    pin.write_text('synthetic pin\n')
    pin.chmod(0o600)
    config = m.TargetSshTransportConfig('synthetic.invalid', 22, 'synthetic', 'synthetic-password', pin, 10)
    peer = Peer()
    peer.names, peer.second, peer.folders = NAMES, None, (1, 2, 3, 1)
    peer.projections, peer.returned, peer.context = 0, ROOT, CONTEXT
    now = [100.0]
    async def read(process, command, prompt, deadline):
        if command not in (m._NAMES, m._FOLDERS):
            return await peer.read(process, command, prompt, deadline)
        assert prompt == CONTEXT
        peer.commands.append(command)
        if command == m._NAMES:
            peer.projections += 1
            names = peer.second if peer.projections == 2 and peer.second is not None else peer.names
            lines = [b'        set name "' + value.encode() + b'"' for value in names]
        else:
            lines = [b'        set folder ' + str(value).encode() for value in peer.folders]
        return frame(command, lines, prompt=CONTEXT)
    async def dynamic(process, command, prompt, deadline):
        peer.commands.append(command)
        return peer.context if command == 'config secret database' else peer.returned
    monkeypatch.setattr(m, 'FortiPamTargetReferenceSshTransport', lambda config: peer)
    monkeypatch.setattr(m, '_complete_pre_login', peer.login)
    monkeypatch.setattr(m, '_send_and_read', read)
    monkeypatch.setattr(m, '_send_and_read_dynamic_prompt', dynamic)
    serial = hashlib.sha256(SERIAL).hexdigest()
    reader = m.SecretBulkImportNamespaceReader(config, serial_digest=serial, clock=lambda: now[0])
    view = m.m.NativeImportMetadataCollection('database', (
        m.m.ImportMetadataSecret(1, 'Visible A', 'owner'),
        m.m.ImportMetadataSecret(2, 'Visible B', 'view'),
        m.m.ImportMetadataSecret(3, 'Visible A', None)), 4, 3, 'revision', serial)
    return reader, peer, now, view


def test_complete_names_preserve_duplicates_and_hide_representation(setup):
    reader, peer, now, view = setup
    result = reader.read_namespace(view)
    reader.check_current(result, api_view=view)
    assert result.names == tuple(sorted(NAMES)) and result.names.count('Visible A') == 2
    assert 'Hidden' not in repr(result) and 'Visible A' not in repr(result)
    assert not hasattr(result, 'can_associate')
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(RuntimeError): operation(result)
    assert peer.commands == [m.r._SERIAL, m.r._VERSION, 'config secret database',
        m._NAMES, m._FOLDERS, m._NAMES, 'end', m.r._SERIAL, m.r._VERSION]
    assert (peer.closed, peer.waited, peer.disconnected) == (1, 1, 1)


@pytest.mark.parametrize('fault', ['drift', 'missing-multiplicity', 'count', 'folder-count',
    'folder-invalid', 'escape', 'control', 'context', 'return', 'serial-after', 'version-after', 'login', 'late-close'])
def test_failed_projection_never_returns_partial_names(setup, fault):
    reader, peer, now, view = setup
    if fault == 'drift': peer.second = tuple(reversed(NAMES))
    elif fault == 'missing-multiplicity': peer.names = ('Visible A', 'Visible B', 'Hidden', 'Other')
    elif fault == 'count': peer.names = NAMES + ('Extra',)
    elif fault == 'folder-count': peer.folders = (1,)
    elif fault == 'folder-invalid': peer.folders = (1, 2, -1, 1)
    elif fault == 'escape': peer.names = NAMES[:-1] + ('unsafe\\name',)
    elif fault == 'control': peer.names = NAMES[:-1] + ('unsafe\u200bname',)
    elif fault == 'context': peer.context = b'WRONG #'
    elif fault == 'return': peer.returned = b'WRONG #'
    elif fault == 'serial-after': peer.overrides[8] = frame(m.r._SERIAL, [b'Serial-Number: OTHER'])
    elif fault == 'version-after': peer.overrides[9] = frame(m.r._VERSION, [b'Version: FortiPAM v7.0.1,build0029'])
    elif fault == 'login': peer.raise_login = True
    else:
        original = peer.wait_closed
        async def close():
            await original()
            now[0] += 11
        peer.wait_closed = close
    with pytest.raises(m.BulkImportNamespaceError) as error: reader.read_namespace(view)
    assert str(error.value) == 'Protected Secret import namespace unavailable.'
    assert reader._current is None and (peer.closed, peer.waited, peer.disconnected) == (1, 1, 1)


@pytest.mark.parametrize('fault', ['copy', 'expired', 'rollback', 'closed', 'superseded', 'view-drift', 'failed-read'])
def test_current_binding_and_revocation(setup, fault):
    reader, peer, now, view = setup
    result = reader.read_namespace(view)
    if fault == 'copy': result = replace(result)
    elif fault == 'expired': now[0] = 110
    elif fault == 'rollback': now[0] = 99
    elif fault == 'closed': reader.close()
    elif fault == 'superseded': reader.read_namespace(view)
    elif fault == 'view-drift': view = replace(view, revision='other')
    else:
        with pytest.raises(m.BulkImportNamespaceError): reader.read_namespace(replace(view, size=None))
    with pytest.raises(m.BulkImportNamespaceError): reader.check_current(result, api_view=view)
    if fault == 'rollback':
        now[0] = 100
        with pytest.raises(m.BulkImportNamespaceError): reader.check_current(result, api_view=view)


@pytest.mark.parametrize('changes', [dict(table='folder'), dict(size=None), dict(size=True),
    dict(size=4097), dict(filtered_count=None), dict(filtered_count=2), dict(serial_digest='0'*64),
    dict(rows=()), dict(rows=(m.m.ImportMetadataSecret(1, 'Same', None),)*2)])
def test_invalid_witnesses_fail_before_connection(setup, changes):
    reader, peer, now, view = setup
    with pytest.raises(m.BulkImportNamespaceError): reader.read_namespace(replace(view, **changes))
    assert peer.connected == 0


def test_cleanup_timeout_aborts_connection(setup):
    reader, peer, now, view = setup
    async def hang(): await asyncio.Event().wait()
    peer.wait_closed = hang
    with pytest.raises(m.BulkImportNamespaceError): reader.read_namespace(view)
    assert peer.disconnected == 1 and reader._current is None
