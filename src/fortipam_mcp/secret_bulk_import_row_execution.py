"""Fixed Text-row composition inside an already admitted source workload.

The original projection is retained from submission. This module has no file
admission, product configuration, listener or authority inputs; product custody
arrives through the existing inherited action client.
"""

from __future__ import annotations

from pathlib import Path
import socket
import threading

from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.material_runtime import MaterialRuntimeOutcome
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome

from .secret_bulk_import_dependencies import ImportDependencyCatalog, ResolvedImportDependencies
from .secret_bulk_import_intake import BulkImportIntakeError, _ERROR
from .secret_bulk_import_row_action_worker import _OriginalRowActionClient, _send
from .secret_bulk_import_row_adapter import _OriginalRowSecretCreateAdapter, _OriginalRowUseContext
from .secret_bulk_import_row_channel import (
    UnixOriginalRowChannelClient, _OriginalRowMaterialStateClient, _RemoteOriginalImportRowLoader,
)
from .secret_bulk_import_row_conversion import _Build29OriginalRowConversion
from .secret_bulk_import_row_http_transport import _Build29OriginalRowHttpTransport
from .secret_bulk_import_row_provider import _OriginalRowMaterialRuntime
from .secret_bulk_import_row_wire import _Build29OriginalRowWireEncoder, _Build29SecretWireDefaults
from .secret_bulk_import_session import _OwnerFileSourceSession
from .web_secret_create_ack import WebSecretCreateAckCapture


class _UnboundRowTransport:
    """Deny until the private constructor has bound the exact native transport."""

    def _create_and_verify_with_original_row(self, context: _OriginalRowUseContext,
                                            columns: tuple[memoryview, ...], *,
                                            deadline: float) -> SecretCreateAdapterOutcome:
        raise BulkImportIntakeError(_ERROR)


class _OriginalTextRowExecution(_OpaqueC3Object):
    """One fixed source-side C3 use; the Owner retains M4 and ACK authority."""

    def __init__(self, session: _OwnerFileSourceSession, catalog: ImportDependencyCatalog,
                 projected: ResolvedImportDependencies, client: UnixOriginalRowChannelClient,
                 defaults: _Build29SecretWireDefaults, capture: WebSecretCreateAckCapture,
                 product_client: _OriginalRowActionClient, *, index: int,
                 namespace_key_path: Path) -> None:
        try:
            if (type(session) is not _OwnerFileSourceSession or type(catalog) is not ImportDependencyCatalog
                    or type(projected) is not ResolvedImportDependencies
                    or type(client) is not UnixOriginalRowChannelClient
                    or type(defaults) is not _Build29SecretWireDefaults
                    or type(capture) is not WebSecretCreateAckCapture
                    or type(product_client) is not _OriginalRowActionClient):
                raise ValueError
            binding = client._binding
            if (binding.material_requested_at is None or binding.material_expires_at is None
                    or binding.ack_pins_digest is None or product_client._phase != 'new'):
                raise ValueError
            loader = _RemoteOriginalImportRowLoader(session, client, index=index,
                key_path=namespace_key_path, key_sha256=binding.namespace_key_digest)
            context = _OriginalRowUseContext(loader._row, binding.permission,
                binding.material_requested_at, binding.material_expires_at)
            bridge = _OriginalRowSecretCreateAdapter(loader, context, _UnboundRowTransport())
            converter = _Build29OriginalRowConversion(bridge, catalog, projected,
                target_name=None, associated_secret_id=None)
            row, template = converter._dependency, converter._template
            if (len(catalog.templates) != 1 or template != catalog.templates[0]
                    or row.template != template.name or row.target_group is not None
                    or row.association_row is not None or row.association_id is not None or row.services
                    or len(template.fields) != 1 or template.fields[0].kind != 'text'):
                raise ValueError
            encoder = _Build29OriginalRowWireEncoder(converter, defaults,
                expected_defaults_digest=defaults.digest(), expected_serial_digest=capture.serial_digest)
            bridge._transport = _Build29OriginalRowHttpTransport(None, encoder, capture,
                product_client=product_client)
            self._runtime = _OriginalRowMaterialRuntime(bridge, _OriginalRowMaterialStateClient(client, context, session))
            self._session, self._product = session, product_client
            self._used, self._lock = False, threading.Lock()
        except BaseException as error:
            if type(product_client) is _OriginalRowActionClient:
                product_client.close()
            if type(session) is _OwnerFileSourceSession:
                session.close()
            if not isinstance(error, Exception):
                raise
            raise BulkImportIntakeError(_ERROR) from None

    def close(self) -> None:
        self._product.close()
        self._session.close()

    def execute_once(self, *, now_epoch: int) -> MaterialRuntimeOutcome:
        if not self._lock.acquire(blocking=False):
            self.close()
            return MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
        try:
            if self._used:
                raise ValueError
            self._used = True
            outcome = self._runtime.execute_once(now_epoch=now_epoch)
            if outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED:
                self._session.close()
                return MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
            return outcome
        except BaseException as error:
            self._session.close()
            if not isinstance(error, Exception):
                raise
            return MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
        finally:
            self._product.close()
            self._lock.release()


def _serve_original_text_row_once(peer: socket.socket, session: _OwnerFileSourceSession,
                                  catalog: ImportDependencyCatalog, projected: ResolvedImportDependencies,
                                  client: UnixOriginalRowChannelClient, defaults: _Build29SecretWireDefaults,
                                  capture: WebSecretCreateAckCapture, *, index: int,
                                  namespace_key_path: Path, now_epoch: int) -> MaterialRuntimeOutcome:
    """One prebound inherited handoff; only a completed C3 use sends a receipt."""
    from .secret_bulk_import_action_process import _receive_original_action_client

    product: _OriginalRowActionClient | None = None
    outcome = MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
    try:
        if (type(peer) is not socket.socket or peer.family != socket.AF_UNIX
                or peer.type != socket.SOCK_STREAM):
            raise ValueError
        product = _receive_original_action_client(peer.dup())
        execution = _OriginalTextRowExecution(session, catalog, projected, client, defaults, capture,
            product, index=index, namespace_key_path=namespace_key_path)
        outcome = execution.execute_once(now_epoch=now_epoch)
        if outcome is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED:
            _send(peer, product._deadline, b'V' + client._binding.context_digest().encode('ascii'))
        return outcome
    except BaseException as error:
        outcome = MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
        if not isinstance(error, Exception):
            raise
        return outcome
    finally:
        if product is not None:
            product.close()
        if type(peer) is socket.socket:
            peer.close()
        if outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED and type(session) is _OwnerFileSourceSession:
            session.close()
