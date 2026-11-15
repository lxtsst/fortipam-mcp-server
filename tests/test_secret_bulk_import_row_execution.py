"""Original signed row/C3 execution with an inherited synthetic TLS product peer."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import socket
import sys

import pytest

from fortipam_mcp.secret_bulk_import_action_process import (
    _ProductSource, _launch_original_channel_action_process,
)
from fortipam_mcp.secret_bulk_import_dependencies import ImportTemplate, ImportTemplateField
from fortipam_mcp.secret_bulk_import_row_action_worker import _receive
from fortipam_mcp.secret_bulk_import_row_execution import _OriginalTextRowExecution, _serve_original_text_row_once
from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
from test_secret_bulk_import_action_process import synthetic_product_endpoint
from test_secret_bulk_import_dependencies import catalog, item
from test_secret_bulk_import_row_channel import channel
from test_secret_bulk_import_row_wire import project
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4Verification
from v4_planning.material_runtime import MaterialRuntimeOutcome


@pytest.mark.skipif(sys.platform != 'darwin', reason='Native product workload restriction')
@pytest.mark.parametrize('fault', [None, 'lost-ack'])
def test_original_text_row_uses_existing_projection_and_inherited_product_once(tmp_path, monkeypatch, capfd, fault):
    serial = hashlib.sha256(b'SYNTHETIC01').hexdigest()
    defaults = replace(project(), serial_digest=serial)
    capture = WebSecretCreateAckCapture(serial, 'success')
    snapshot = replace(catalog(), templates=(ImportTemplate('Synthetic Note', (ImportTemplateField('Contents', 'text', True),)),))
    values = [item(Name='Original Text', **{'Secret Template': 'Synthetic Note', 'URL': '', 'Username': '',
        'Password/Passphrase': '', 'Text': 'synthetic private text', 'Service Type': '', 'Port': ''})]
    graph = {}
    parts = channel(tmp_path, monkeypatch, material=True, file_parent=True, values=values,
        snapshot=snapshot, capture=graph, ack_capture=capture, ack_defaults_digest=defaults.digest())
    local, session, state, _, _, _, owner, client, reference, api, uds, _, _ = parts
    reader = owner._permission._reader
    original_read = type(reader).read_current
    original_before_create = type(owner._permission)._verify_before_create
    sealed = []

    def read_before_post(self, plan):
        assert not sealed, 'Acquisition current cannot be reread after the POST boundary'
        return original_read(self, plan)

    def verify_before_post(self, *args, **kwargs):
        result = original_before_create(self, *args, **kwargs)
        assert self is owner._permission and not sealed
        sealed.append(True)
        return result

    monkeypatch.setattr(type(reader), 'read_current', read_before_post)
    monkeypatch.setattr(type(owner._permission), '_verify_before_create', verify_before_post)
    handles, units, results = [], [], []
    initialize = _OriginalTextRowExecution.__init__

    def retain_execution(self, *args, **kwargs):
        initialize(self, *args, **kwargs)
        units.append(self)

    monkeypatch.setattr(_OriginalTextRowExecution, '__init__', retain_execution)
    product_dir = tmp_path / 'product'
    product_dir.mkdir(mode=0o700)
    monkeypatch.setattr(type(session), 'project_dependencies_once',
        lambda *_a, **_k: pytest.fail('The admitted projection must not be repeated'))
    monkeypatch.setattr(_ProductSource, '_load_product_config',
        lambda *_: pytest.fail('Source workload loaded product credentials'))
    try:
        with reference, api, synthetic_product_endpoint(product_dir, fault) as (source, digest, requests, posts):
            with ThreadPoolExecutor(max_workers=1) as pool:
                class Adapter:
                    def read_current(self, plan):
                        return local._authority._reader.read_current(plan)

                    def read_postcondition(self, plan):
                        return local._authority._reader.read_postcondition(plan)

                    def dispatch(self, plan):
                        handle = _launch_original_channel_action_process(owner, snapshot, graph['projected'], defaults,
                            namespace_key_path=local._rows._key.path, index=0, target_name=None,
                            associated_secret_id=None, source_path=source, source_digest=digest)
                        handles.append(handle)
                        owner.arm_original_dispatch()
                        sender, receiver = socket.socketpair()

                        def use_received_product():
                            return _serve_original_text_row_once(receiver, session, snapshot, graph['projected'], client,
                                defaults, capture, index=0, namespace_key_path=local._rows._key.path, now_epoch=1000)

                        try:
                            future = pool.submit(use_received_product)
                            handle._transfer_client_once(sender.dup())
                            outcome = future.result(timeout=10)
                            results.append(outcome)
                            if outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED:
                                with pytest.raises(ValueError):
                                    _receive(sender, handle.client._pins.deadline, 65)
                                raise M4AdapterAmbiguous('Synthetic product result unavailable')
                            assert _receive(sender, handle.client._pins.deadline, 65) == (
                                b'V' + client._binding.context_digest().encode('ascii'))
                        finally:
                            sender.close()
                            receiver.close()
                            handle.close()

                owner.prepare_original_dispatch()
                result = M4ExecutionKernel(Adapter(), local._issuer, state, clock=lambda: 1000).execute(
                    local._plan, local._authorization, now_epoch=1000)
            assert result.verification is (M4Verification.UNKNOWN if fault else M4Verification.VERIFIED)
            assert results == [MaterialRuntimeOutcome.RECONCILIATION_REQUIRED if fault
                else MaterialRuntimeOutcome.VERIFIED_AND_RELEASED]
            assert len(handles) == len(units) == len(posts) == state.claim_count == 1
            assert sealed == [True] and owner._create_check_attempted
            unit = units[0]
            bridge = unit._runtime._provider._bridge
            assert bridge._transport._config is None and unit._product._phase == 'closed'
            assert bridge._transport._encoder._converter._projected is graph['projected']
            assert all(not any(buffer) for buffer in bridge._owned._buffers)
            if fault:
                assert session._transaction._closed.is_set() and not any(session._password)
            else:
                assert owner._inspect_verified_ack().native_secret_id == 71
                assert not session._transaction._closed.is_set()
                before = len(requests)
                assert unit.execute_once(now_epoch=1000) is MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
                assert session._transaction._closed.is_set() and len(requests) == before
            assert capfd.readouterr() == ('', '')
    finally:
        for handle in handles:
            handle.close()
        session.close()
        uds.close()
