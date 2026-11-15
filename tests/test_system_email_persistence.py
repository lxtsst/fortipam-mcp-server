"""Real process-separated CAS binding; synthetic product/authorization only."""
from contextlib import contextmanager
from dataclasses import replace
import os
from pathlib import Path
import subprocess
import stat
import sys
import tempfile
import time

import pytest

from fortipam_mcp.m4_checkpoint_client import UnixM4ExecutionCheckpoint
from fortipam_mcp.m4_execution_store import M4ExecutionStoreTail, M4MonotonicCheckpointError, PersistentM4ExecutionStoreError
from fortipam_mcp.planning_checkpoint_sidecar import UnixPlanningCheckpointClient, UnixPlanningCheckpointClientSettings
from fortipam_mcp.system_email_delivery_contract import SystemEmailDeliveryBinding
from fortipam_mcp.system_email_local_workflow import SystemEmailLocalWorkflow
from fortipam_mcp.system_email_m4_adapter import system_email_execution_digests
from fortipam_mcp.system_email_persistence import SystemEmailExecutionStoreSettings, open_system_email_execution_stores
from test_system_email_delivery_workflow import DeliveryBackend
from test_system_email_local_workflow import Authority, IDENTITY, run
from test_system_email_m4_adapter import BINDING, REQUESTER, Backend, Clock, transition
from v4_planning import PlanningStoreTail, canonical_digest


def settings(root, socket_path, *, key=None, reference='configuration'):
    root.mkdir(mode=0o700)
    key_path = root/'execution.key'
    key_path.write_bytes(key or b'synthetic-email-ledger-key-' + reference.encode())
    key_path.chmod(0o600)
    return SystemEmailExecutionStoreSettings(root/'execution.db', key_path,
        UnixPlanningCheckpointClientSettings(socket_path, 'system-email-cas-authority-test'),
        'system-email-'+reference+'-test')


def workflow(configuration_store, delivery_store, backend, clock, fault='none', *, change=None):
    change = change or transition(backend)
    context = canonical_digest({'binding': BINDING, 'requester': REQUESTER, 'transport': IDENTITY['transport_digest']})
    binding = SystemEmailDeliveryBinding('a'*48, 'b'*64, change.original.source_serial_digest,
        system_email_execution_digests(change, context)[1])
    delivery = DeliveryBackend(backend, clock, fault)
    value = SystemEmailLocalWorkflow(change, backend, configuration_store, binding_digest=BINDING,
        allowed_requester_digest=REQUESTER, allowed_transport_digest=IDENTITY['transport_digest'],
        authority=Authority(), update_enabled=True, restore_enabled=True, clock=clock,
        delivery_binding=binding, delivery_backend=delivery, delivery_store=delivery_store, delivery_enabled=True)
    return value, delivery


class SidecarProcess:
    def __init__(self, root, socket_path):
        root.mkdir(mode=0o700)
        key = root/'authority.key'; key.write_bytes(b'synthetic-separate-cas-authority-key'); key.chmod(0o600)
        repo = Path(__file__).resolve().parents[1]
        self.environment = {
            'PATH': os.environ['PATH'], 'PYTHONPATH': str(repo/'src') + os.pathsep + str(repo),
            'FORTIPAM_MCP_V4_CHECKPOINT_DATABASE': str(root/'authority.db'),
            'FORTIPAM_MCP_V4_CHECKPOINT_HMAC_KEY_FILE': str(key),
            'FORTIPAM_MCP_V4_CHECKPOINT_AUTHORITY_REF': 'system-email-cas-authority-test',
            'FORTIPAM_MCP_V4_CHECKPOINT_SOCKET': str(socket_path),
        }
        self.socket_path = socket_path; self.process = None; self.socket_identity = None
    def start(self):
        assert self.process is None
        self.process = subprocess.Popen([sys.executable, '-m', 'fortipam_mcp.planning_checkpoint_sidecar'],
            env=self.environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        client = UnixPlanningCheckpointClient(UnixPlanningCheckpointClientSettings(
            self.socket_path, 'system-email-cas-authority-test'))
        deadline = time.monotonic()+8
        while time.monotonic() < deadline:
            assert self.process.poll() is None, 'Checkpoint fixture exited before readiness.'
            try:
                client.verify(PlanningStoreTail('system-email-cas-readiness-test', 0, 'chain-root'))
                metadata = self.socket_path.lstat()
                self.socket_identity = (metadata.st_dev, metadata.st_ino)
                return
            except Exception:
                time.sleep(0.02)
        raise AssertionError('Checkpoint fixture did not become ready.')
    def stop(self):
        if self.process is not None:
            process, self.process = self.process, None
            process.terminate()
            try: process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=2)
                raise AssertionError('Checkpoint fixture did not stop within its budget.')
            assert process.returncode is not None
        # Existing sidecar lifecycle: Uvicorn may re-raise SIGTERM after server
        # shutdown. Remove only our socket after the owned process is terminal;
        # the checkpoint database/key and execution stores are never cleared.
        if self.socket_path.exists() or self.socket_path.is_symlink():
            metadata = self.socket_path.lstat()
            assert stat.S_ISSOCK(metadata.st_mode) and not self.socket_path.is_symlink()
            assert (metadata.st_dev, metadata.st_ino) == self.socket_identity
            self.socket_path.unlink()
        assert not self.socket_path.exists()


@contextmanager
def sidecar(tmp_path):
    with tempfile.TemporaryDirectory(prefix='emcp-', dir='/private/tmp') as directory:
        process = SidecarProcess(tmp_path/'checkpoint', Path(directory)/'cp.sock')
        try:
            process.start()
            yield process
        finally:
            process.stop()


def test_extracted_bridge_preserves_bulk_import_alias_and_exact_m4_tail(monkeypatch):
    from fortipam_mcp.secret_bulk_import_runtime import _M4PlanningCheckpoint
    assert _M4PlanningCheckpoint is UnixM4ExecutionCheckpoint
    client = UnixPlanningCheckpointClient(UnixPlanningCheckpointClientSettings(
        Path('/private/tmp/email-cas-unit.sock'), 'system-email-cas-authority-test'))
    monkeypatch.setattr(client, 'verify_ready', lambda: None)
    calls = []
    monkeypatch.setattr(client, '_request', lambda path, payload: calls.append((path, payload)))
    bridge = UnixM4ExecutionCheckpoint(client, 'system-email-cas-unit-store')
    empty = M4ExecutionStoreTail.empty('system-email-cas-unit-store')
    first = M4ExecutionStoreTail(empty.store_ref, 1, 'a'*64)
    bridge.verify(empty); bridge.advance(empty, first)
    assert calls[0][1]['tail']['chain_hmac'] == 'chain-root'
    assert calls[1][1]['current'] == {'store_ref': empty.store_ref, 'sequence': 1, 'chain_hmac': 'a'*64}
    before = len(calls)
    with pytest.raises(M4MonotonicCheckpointError): bridge.verify(M4ExecutionStoreTail('foreign-email-cas-store', 1, 'a'*64))
    assert len(calls) == before


@pytest.mark.parametrize('fault', ['namespace', 'database', 'key-path'])
def test_overlapping_binding_rejected_before_any_checkpoint_or_database(tmp_path, fault):
    configuration = settings(tmp_path/'configuration', Path('/private/tmp/email-cas-missing.sock'))
    delivery = settings(tmp_path/'delivery', Path('/private/tmp/email-cas-missing.sock'), reference='delivery')
    changes = {'checkpoint_store_ref': configuration.checkpoint_store_ref} if fault == 'namespace' else {
        'database_path' if fault == 'database' else 'hmac_key_path':
        configuration.database_path if fault == 'database' else configuration.hmac_key_path}
    with pytest.raises(ValueError): open_system_email_execution_stores(configuration, replace(delivery, **changes))
    assert not configuration.database_path.exists() and not delivery.database_path.exists()


def test_missing_checkpoint_never_falls_back_to_memory_or_creates_a_dispatch_slot(tmp_path):
    configuration = settings(tmp_path/'configuration', Path('/private/tmp/email-cas-missing.sock'))
    delivery = settings(tmp_path/'delivery', Path('/private/tmp/email-cas-missing.sock'), reference='delivery')
    with pytest.raises(ValueError): open_system_email_execution_stores(configuration, delivery)
    assert not configuration.database_path.exists() and not delivery.database_path.exists()


@pytest.mark.parametrize('fault', ['none', 'timeout'])
@pytest.mark.parametrize('rolled', ['configuration', 'delivery'])
def test_real_unix_process_restart_preserves_consumed_results_and_rejects_old_ledger(tmp_path, fault, rolled):
    with sidecar(tmp_path) as authority:
        configuration = settings(tmp_path/'configuration', authority.socket_path)
        delivery = settings(tmp_path/'delivery', authority.socket_path, reference='delivery')
        stores = open_system_email_execution_stores(configuration, delivery)
        selected = configuration if rolled == 'configuration' else delivery
        original = {path: path.read_bytes() for path in selected.database_path.parent.iterdir() if path.is_file()}
        backend = Backend(); clock = Clock(); value, sender = workflow(*stores, backend, clock, fault)
        for phase in ('update', 'test-delivery', 'restore'):
            result, _ = run(value, phase)
            assert (result['outcome'] == 'succeeded') is (phase != 'test-delivery' or fault == 'none')
        outcome = value.outcome(**IDENTITY)
        assert outcome['workflow_outcome'] == ('verified_locally' if fault == 'none' else 'reconciliation_required')
        assert stores[0].claim_count == 2 and stores[1].claim_count == 1
        authority.stop()
        with pytest.raises(PersistentM4ExecutionStoreError): stores[0].verify_ready()
        with pytest.raises(ValueError): value.preview('update', **IDENTITY)
        assert len(backend.submissions) == 2 and sender.sends == 1
        authority.start()  # Same Authority database/key/socket, no reseeding.
        reopened = open_system_email_execution_stores(configuration, delivery)
        assert reopened[0].claim_count == 2 and reopened[1].claim_count == 1
        restarted, new_sender = workflow(*reopened, backend, clock, fault)
        reads = backend.reads
        for phase in ('update', 'test-delivery', 'restore'):
            with pytest.raises(ValueError): restarted.preview(phase, **IDENTITY)
        assert backend.reads == reads and new_sender.sends == 0
        assert restarted.outcome(**IDENTITY)['workflow_outcome'] == 'reconciliation_required'
        for path, raw in original.items(): path.write_bytes(raw)
        with pytest.raises(ValueError): open_system_email_execution_stores(configuration, delivery)
        with pytest.raises(PersistentM4ExecutionStoreError): reopened[0 if rolled == 'configuration' else 1].verify_ready()
        assert len(backend.submissions) == 2 and sender.sends == 1 and new_sender.sends == 0


def test_real_unix_binding_rejects_reused_key_material_and_missing_endpoint(tmp_path):
    with sidecar(tmp_path) as authority:
        key = b'synthetic-reused-system-email-ledger-key'
        configuration = settings(tmp_path/'configuration', authority.socket_path, key=key)
        delivery = settings(tmp_path/'delivery', authority.socket_path, key=key, reference='delivery')
        with pytest.raises(ValueError): open_system_email_execution_stores(configuration, delivery)
        assert configuration.database_path.exists() and delivery.database_path.exists()
        authority.stop()
        with pytest.raises(ValueError): open_system_email_execution_stores(configuration, delivery)


def test_real_unix_restart_does_not_adopt_an_original_receipt_in_a_new_host(tmp_path):
    with sidecar(tmp_path) as authority:
        configuration = settings(tmp_path/'configuration', authority.socket_path)
        delivery = settings(tmp_path/'delivery', authority.socket_path, reference='delivery')
        stores = open_system_email_execution_stores(configuration, delivery)
        backend = Backend(); clock = Clock(); original, _ = workflow(*stores, backend, clock)
        assert run(original, 'update')[0]['outcome'] == 'succeeded'
        authority.stop(); authority.start()
        reopened = open_system_email_execution_stores(configuration, delivery)
        restarted, sender = workflow(*reopened, backend, clock, change=original._transition)
        reads = backend.reads
        for phase in ('update', 'test-delivery', 'restore'):
            with pytest.raises(ValueError): restarted.preview(phase, **IDENTITY)
        assert reopened[0].claim_count == 1 and reopened[1].claim_count == 0
        assert backend.reads == reads and sender.sends == 0
        # Restarting only the CAS service does not revoke the original live
        # host's receipt, nor grant that receipt to a replacement workflow.
        assert run(original, 'restore')[0]['outcome'] == 'succeeded'
        assert len(backend.submissions) == 2
