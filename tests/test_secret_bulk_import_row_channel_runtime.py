"""Real signed Unix requests with fresh native-current algorithms, no device."""

import hashlib
import logging
from pathlib import Path
import socket
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_row_channel import UnixOriginalRowChannelClient
from fortipam_mcp.secret_bulk_import_row_channel_runtime import _OriginalRowChannelRuntime
from test_secret_bulk_import_row_current import NativeSources
from test_secret_bulk_import_row_dispatch import original_owner
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4Verification
from v4_planning.execution_kernel import _ACTIVE_DISPATCH


def write(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)
    return hashlib.sha256(raw).hexdigest()


@pytest.mark.parametrize('occupied', [False, True])
def test_original_signed_channel_closes_and_reuses_only_its_fixed_socket(tmp_path, monkeypatch, capfd, occupied):
    loggers = [logging.getLogger(name) for name in ('uvicorn.error', 'uvicorn.access', 'uvicorn.asgi')]
    logging_before = [(logger.level, tuple(logger.handlers), logger.propagate) for logger in loggers]
    with tempfile.TemporaryDirectory(prefix='fp-row-run-', dir='/private/tmp') as directory:
        root = Path(directory)
        path = root / 'row.sock'
        request, signer, public = root / 'request.key', root / 'signer.key', root / 'public.key'
        request_digest, signer_digest = write(request, b'q' * 32), write(signer, b'z' * 32)
        public_digest = write(public, Ed25519PrivateKey.from_private_bytes(b'z' * 32).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        settings = dict(socket_path=path, request_key_path=request, request_key_sha256=request_digest,
            public_key_path=public, public_key_sha256=public_digest, clock=lambda: 1000)
        previous = None
        for index in range(2):
            local = tmp_path / str(index)
            local.mkdir(mode=0o700)
            with monkeypatch.context() as patch:
                native = NativeSources(local, patch)
                owner, current, issuer, reference = original_owner(local, patch, native)
                runtime = _OriginalRowChannelRuntime(owner, socket_path=path,
                    request_key_path=request, request_key_sha256=request_digest,
                    signing_key_path=signer, signing_key_sha256=signer_digest)
                assert not path.exists() and runtime._thread is None
                blocker = None
                if occupied and index == 0:
                    blocker = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    blocker.bind(str(path)); path.chmod(0o600); blocker.listen(1)
                    blocked_inode = path.lstat().st_ino
                patch.setattr(PinnedBulkImportFile, 'decode',
                    lambda *_a, **_k: pytest.fail('Channel decoded protected row material'))
                observed = []

                class Adapter:
                    def read_current(self, plan):
                        return current.read_current(plan)

                    def read_postcondition(self, plan):
                        pytest.fail('Read-only channel fixture cannot assert a create postcondition')

                    def dispatch(self, plan):
                        nonlocal previous
                        try:
                            owner.arm_original_dispatch()
                            scope = _ACTIVE_DISPATCH.get()
                            assert scope is owner._scope and scope.active
                            runtime.start_once()
                            assert runtime._thread.is_alive() and _ACTIVE_DISPATCH.get() is scope
                            client = UnixOriginalRowChannelClient(owner._binding, **settings)
                            if previous is not None:
                                with pytest.raises(BulkImportIntakeError):
                                    previous._call('resolve')
                            before = len(native.peers)
                            response = client._call('resolve')
                            assert response['record']['plan_ref'] == owner._binding.plan.plan_ref
                            # This executes namespace_reader.asyncio.run through the actual ASGI server.
                            assert len(native.peers) == before + 1 and _ACTIVE_DISPATCH.get() is scope
                            observed.append(client)
                            previous = client
                        except Exception:
                            raise M4AdapterAmbiguous('Synthetic row channel unavailable') from None
                        finally:
                            runtime.close()
                        # This fixture reads signed metadata only; it grants no create success.
                        raise M4AdapterAmbiguous('Synthetic read-only channel fixture complete')

                try:
                    with reference:
                        owner.prepare_original_dispatch()
                        result = M4ExecutionKernel(Adapter(), issuer, owner._execution, clock=lambda: 1000).execute(
                            owner._binding.plan, owner._binding.authorization, now_epoch=1000)
                        assert result.verification is M4Verification.UNKNOWN
                    assert owner._scope is not None and not owner._scope.active
                    assert runtime._listener is None or runtime._listener.fileno() == -1
                    assert runtime._thread is None or not runtime._thread.is_alive()
                    assert len(observed) == (0 if blocker is not None else 1)
                    if blocker is not None:
                        assert path.lstat().st_ino == blocked_inode and blocker.fileno() >= 0
                    else:
                        assert not path.exists()
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe, pytest.raises(OSError):
                            probe.connect(str(path))
                    native.disposed()
                finally:
                    runtime.close()
                    current.close()
                    if blocker is not None:
                        blocker.close()
                        path.unlink()
        assert capfd.readouterr() == ('', '')
        assert [(logger.level, tuple(logger.handlers), logger.propagate) for logger in loggers] == logging_before
