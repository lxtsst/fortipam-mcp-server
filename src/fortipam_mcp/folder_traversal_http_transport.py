"""Private fixed PUT candidate; ordinary Folder update remains child-only."""
from __future__ import annotations

import json
from .folder_http_transport import MAX_REQUEST_BYTES, COLLECTION_PATH
from .isolated_folder_http_transport import IsolatedFolderHttpTransport
from .folder_traversal_candidate import prepare_folder_traversal
from .folder_traversal_m4_adapter import FolderTraversalBinding


class FolderTraversalHttpTransport(IsolatedFolderHttpTransport):
    """Reuse pinned TLS, bounded metadata reads and exact private path binding."""

    def read_folder(self, folder_id: int) -> dict[str, object]:
        self._parent_matches(folder_id)
        return self._detail(folder_id)

    def update_traversal(self, binding: FolderTraversalBinding) -> None:
        version, build = self.read_product_version_and_build()
        if self.owner_is_available(binding.username) is not True:
            raise ValueError("Folder traversal owner unavailable.")
        candidate = prepare_folder_traversal(self.read_folder(binding.folder_id),
            folder_id=binding.folder_id, parent_id=binding.parent_id,
            username=binding.username, version=version, build=build)
        if (candidate.current_digest != binding.current_digest
            or candidate.proposed_digest != binding.expected_digest):
            raise ValueError("Folder traversal state changed.")
        encoded = json.dumps(candidate.body, ensure_ascii=True, allow_nan=False,
                             sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_REQUEST_BYTES:
            raise ValueError("Folder traversal request exceeds limit.")
        response = self._folders._request("PUT", f"{COLLECTION_PATH}/{binding.folder_id}", encoded)
        payload = response.data
        if (response.status_code != 200 or not isinstance(payload, dict)
            or payload.get("status") not in {"success", None}
            or payload.get("http_status", 200) != 200):
            raise ValueError("Folder traversal update was not acknowledged.")
