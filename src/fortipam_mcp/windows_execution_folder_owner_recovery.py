"""One exact original-ID Folder recovery through the existing Owner/CSRF wire.

The inherited Archive constructor keeps its own name grammar. This separate
private source candidate binds the new grammar to original custody and an active
recovery M4; no generic Owner mutation or public Tool is added.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

import httpx
from v4_planning import M4ExecutionPlan, M4ExecutionAuthorization
from v4_planning.execution_kernel import _require_m4_dispatch_ownership

from .folder_archive_owner_session import FixedFolderArchiveOwnerSession, FolderArchiveOwnerSessionError
from .folder_http_transport import FolderTransportConfig
from .m4_execution_store import PersistentM4ExecutionStateStore
from .windows_execution_folder_authority import RECOVER_ACTION, RECOVER_ADAPTER
from .windows_execution_folder_custody import WindowsExecutionFolderCustody
from .windows_execution_folder_sources import WindowsExecutionFolderSources

_ERROR = "The private original Folder Owner recovery is unavailable."


class WindowsFolderOwnerRecoverySession(FixedFolderArchiveOwnerSession):
    def __init__(self, sources: WindowsExecutionFolderSources, original: WindowsExecutionFolderCustody, *,
            plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, store: PersistentM4ExecutionStateStore,
            client_factory: Callable[..., Any] = httpx.Client) -> None:
        try:
            if (type(sources) is not WindowsExecutionFolderSources or type(original) is not WindowsExecutionFolderCustody
                    or type(plan) is not M4ExecutionPlan or type(authorization) is not M4ExecutionAuthorization
                    or type(store) is not PersistentM4ExecutionStateStore or store.monotonic_checkpoint_protocol_bound is not True):
                raise ValueError
            sources._request.validate()
            owned = original.inspect_created_state()
            if (original._request != sources._request or owned.source_context_digest != sources.source_context_digest
                    or plan.action_id != RECOVER_ACTION or plan.adapter_ref != RECOVER_ADAPTER
                    or plan.action_version != "1.0.0" or plan.target_ref != "bound-explicit-windows-folder"
                    or authorization.plan_ref != plan.plan_ref or authorization.plan_digest != plan.plan_digest):
                raise ValueError
            self._sources, self._original = sources, original
            self._plan, self._authorization, self._store = plan, authorization, store
            self._original_observation = owned
            config = sources._policy._config
            self._initialize_owner_binding(
                FolderTransportConfig(config.base_url, config.bearer_token, config.timeout_seconds,
                    config.ca_file, explicitly_enabled=True),
                owner_name=sources._request.binding.owner_name, folder_name=sources._request.binding.name,
                credentials=sources._policy._credentials, client_factory=client_factory)
        except Exception:
            raise FolderArchiveOwnerSessionError(_ERROR) from None

    def delete_empty_folder(self, folder_id: int) -> Mapping[str, object]:
        raise FolderArchiveOwnerSessionError(_ERROR)

    def delete_empty_folder_original(self, folder_id: int, *, before_dispatch: Callable[[], None],
            observe_response: Callable[[int, str, str], None],
            consume_original_ack: Callable[[bytearray, int, str], object]) -> object:
        try:
            _require_m4_dispatch_ownership(self._plan, self._authorization, self._store)
            owned = self._original.inspect_created_state()
            if (owned != self._original_observation or type(folder_id) is not int or folder_id != owned.native_folder_id
                    or owned.source_context_digest != self._sources.source_context_digest):
                raise ValueError
            observed = self._sources._current
            if observed is None or observed.native_folder_id != folder_id or observed.state_digest != owned.created_state_digest:
                raise ValueError
            self._sources.check_current(observed)
            return super().delete_empty_folder_original(folder_id, before_dispatch=before_dispatch,
                observe_response=observe_response, consume_original_ack=consume_original_ack)
        except Exception:
            raise FolderArchiveOwnerSessionError(_ERROR) from None
