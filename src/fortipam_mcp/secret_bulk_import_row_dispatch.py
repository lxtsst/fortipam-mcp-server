"""Private Owner adapter joining one original Text row to its fixed intake.

The existing M4 dispatch, C3 claim and retained ACK remain the only authorities.
The inherited socket carries a product descriptor and a bounded completion frame;
neither that frame nor a product process exit can establish successful creation.
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import socket
from threading import RLock

from v4_planning import M4AdapterAmbiguous, M4ExecutionPlan
from v4_planning.execution_kernel import M4ClaimState, _require_m4_dispatch_ownership
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.material_runtime import MaterialRuntimeOutcome, MaterialUseClaimState

from .secret_bulk_import_action_process import (
    _OriginalActionProcess, _ProductSource, _launch_original_channel_action_process,
)
from .secret_bulk_import_file import _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, _ERROR
from .secret_bulk_import_row_action_worker import _receive
from .secret_bulk_import_row_channel import OriginalRowChannelOwner
from .secret_bulk_import_row_channel_runtime import _OriginalRowChannelRuntime
from .secret_bulk_import_row_current import _OriginalRowNativeCurrent
from .secret_bulk_import_row_readback import _OriginalRowNativeReadback
from .target_preservation_contract import _api_source_context


class _OriginalRowOwnerAdapter(_OpaqueC3Object):
    """One original dispatch; the caller prepares the Owner before kernel entry."""

    def __init__(self, owner: OriginalRowChannelOwner, current: _OriginalRowNativeCurrent, *,
                 intake_peer: socket.socket, source_path: Path, source_digest: str,
                 channel: _OriginalRowChannelRuntime | None = None) -> None:
        try:
            if (type(owner) is not OriginalRowChannelOwner or type(current) is not _OriginalRowNativeCurrent
                    or type(intake_peer) is not socket.socket or intake_peer.family != socket.AF_UNIX
                    or intake_peer.type != socket.SOCK_STREAM or intake_peer.get_inheritable()
                    or current._post is not None or owner._scope is not None
                    or channel is not None and (type(channel) is not _OriginalRowChannelRuntime
                        or channel._owner is not owner or channel._binding != owner._binding)):
                raise ValueError
            intake_peer.getpeername()
            self._owner, self._current, self._peer = owner, current, intake_peer
            self._channel = channel
            self._binding = owner._binding
            self._lock = RLock()
            self._used = self._finished = self._failed = self._closed = False
            self._source = _ProductSource(source_path, source_digest)
            self._check(self._binding.plan)
            current._check_original()
            self._check_product_source()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _check(self, plan: M4ExecutionPlan) -> None:
        owner, current, binding = self._owner, self._current, self._binding
        permission_reader: object = owner._permission._reader
        if (self._closed or self._failed or type(plan) is not M4ExecutionPlan or plan != binding.plan
                or owner._binding != binding or current._plan != plan
                or owner._parent is not current._parent_store or owner._execution is not current._execution
                or binding.source != current._source or binding.parent_digest != current._parent_digest
                or binding.namespace_key_digest != current._original._key.digest
                or permission_reader is not current or owner._permission._source != current._source
                or owner._permission._pins != binding.permission
                or owner._ack_pins is None or owner._ack_pins.row != current._row
                or owner._ack_pins.defaults_digest != current._defaults_digest):
            raise ValueError
        binding.__post_init__()
        current._check_plan(plan)
        current._now()

    def _check_product_source(self) -> None:
        current, source = self._current, self._source
        folders, namespace = current._profile._folder_reader, current._profile._namespace_reader
        config, actor = folders._config, namespace._binding
        folders._guard._require_config(config)
        namespace._guard._require_config(namespace._config)
        product = source._load_product_config()
        if (source.actor != actor or source.username != actor.expected_actor
                or folders._guard._binding != actor or config.ca_file is None
                or product.ca_file != config.ca_file
                or product.base_url.rstrip('/') != config.base_url.rstrip('/')
                or not hmac.compare_digest(product.bearer_token.encode(), config.bearer_token.encode())
                or not 0 < product.timeout_seconds <= config.timeout_seconds
                or _api_source_context(config.base_url, hashlib.sha256(product.bearer_token.encode()).hexdigest(),
                    folders._guard._ca_digest, folders._guard.serial_digest)
                    != current._profile._folders.source_context_digest):
            raise ValueError
        source._verify()
        current._now()

    def read_current(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            try:
                self._check(plan)
                if self._used:
                    raise ValueError
                self._check_product_source()
                return self._current._read_for_kernel(plan, self._binding.authorization)
            except Exception:
                self._failed = True
                self._peer.close()
                raise M4AdapterAmbiguous(_ERROR) from None

    def dispatch(self, plan: M4ExecutionPlan) -> None:
        with self._lock:
            product: _OriginalActionProcess | None = None
            raw = bytearray()
            try:
                self._check(plan)
                if self._used:
                    raise ValueError
                self._used = True
                owner, current = self._owner, self._current
                binding = self._binding
                _require_m4_dispatch_ownership(plan, binding.authorization, owner._execution)
                current._bind_current_scope(plan, binding.authorization)
                current._check_original()
                self._check_product_source()
                folders = current._profile._folder_reader
                readback = _OriginalRowNativeReadback(owner, current._catalog, current._projected,
                    current._defaults, folders._config, current._profile._namespace_reader._binding,
                    namespace_key_path=current._original._key.path, index=current._row.index,
                    target_name=None, associated_secret_id=None,
                    connection_factory=folders._guard._factory, clock=current._now)
                readback._guard._guard._context = folders._guard._tls_for_transport(folders._config)
                current.bind_postcondition(readback)
                product = _launch_original_channel_action_process(owner, current._catalog, current._projected,
                    current._defaults, namespace_key_path=current._original._key.path, index=current._row.index,
                    target_name=None, associated_secret_id=None,
                    source_path=self._source.path, source_digest=self._source.digest)
                self._check_product_source()
                assert current._deadline is not None
                deadline = min(current._deadline, readback._pins.deadline, product.client._pins.deadline)
                owner.arm_original_dispatch()
                if self._channel is not None:
                    self._channel.start_once()
                from .secret_bulk_import_intake_execution import _send_original_text_row
                _send_original_text_row(self._peer, binding, current._row.index, deadline=deadline)
                product._transfer_client_once(self._peer.dup())
                expected = b'V' + binding.context_digest().encode('ascii')
                raw = _receive(self._peer, deadline, len(expected))
                if raw != expected:
                    raise ValueError
                self._check(plan)
                self._check_product_source()
                _require_m4_dispatch_ownership(plan, binding.authorization, owner._execution)
                _, original, material = owner._inspect_ack_claims()
                if (original.state is not M4ClaimState.IN_PROGRESS
                        or material.state is not MaterialUseClaimState.REPLAY
                        or material.outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED):
                    raise ValueError
            except BaseException as error:
                self._failed = True
                if not isinstance(error, Exception):
                    raise
                raise M4AdapterAmbiguous(_ERROR) from None
            finally:
                self._current._discard_current_scope()
                _wipe(raw)
                try:
                    try:
                        self._peer.close()
                    finally:
                        try:
                            if product is not None:
                                product.close()
                        finally:
                            if self._channel is not None:
                                self._channel.close()
                except Exception:
                    self._failed = True
                    raise M4AdapterAmbiguous(_ERROR) from None
            self._finished = True

    def read_postcondition(self, plan: M4ExecutionPlan) -> str:
        with self._lock:
            try:
                self._check(plan)
                if not self._finished:
                    raise ValueError
                self._check_product_source()
                return self._current.read_postcondition(plan)
            except Exception:
                self._failed = True
                raise M4AdapterAmbiguous(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            try:
                self._peer.close()
                self._current.close()
            finally:
                if self._channel is not None:
                    self._channel.close()
