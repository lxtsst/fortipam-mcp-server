"""Lazy private Owner/API qualification for one fixed Folder namespace reader."""
from __future__ import annotations

from collections.abc import Callable, Mapping
import hmac
import json
import os
from pathlib import Path
import re
from typing import Any
from urllib.parse import quote

import httpx
from v4_planning import canonical_digest

from .folder_http_transport import FolderTransportConfig
from .folder_namespace_ssh_reader import FolderNamespaceObservation, FortiPamFolderNamespaceSshReader
from .isolated_folder_m4_adapter import IsolatedFolderBinding
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _record, _zeroize_mutable
from .target_ssh_transport import TargetSshTransportConfig, _private_regular_file, _safe_host


_UNAVAILABLE = "The private Folder namespace candidate is unavailable."
_SENTINEL = "mcp-v4-archive-namespace-readonly"
_ROLE_FIELDS = "name|accprofile|status|remote-auth|wildcard"
NamespaceObserver = Callable[[str, int, str], FolderNamespaceObservation]


def build_folder_namespace_observer(
    config: SecretMetadataHttpTransportConfig, *, binding: IsolatedFolderBinding, parent_path: str,
    credentials: Callable[[], tuple[str, str]], ssh_host: str, ssh_port: int,
    ssh_known_hosts_file: Path, witness_folder_id: int,
    client_factory: Callable[..., Any] = httpx.Client,
) -> NamespaceObserver:
    """Validate local configuration only; defer credentials and network until observed."""
    try:
        if (not callable(credentials) or not _safe_host(ssh_host)
            or type(ssh_port) is not int or not 1 <= ssh_port <= 65535
            or not ssh_known_hosts_file.is_absolute()
            or type(witness_folder_id) is not int or not 0 < witness_folder_id <= 2_147_483_647
            or witness_folder_id == binding.parent_folder_id
            or not 1 <= config.timeout_seconds <= 60
            or not parent_path or parent_path.startswith("/")
            or any(part in {"", ".", ".."} for part in parent_path.split("/"))
            or re.fullmatch(r"mcp-v4-[A-Za-z0-9][A-Za-z0-9._-]*", binding.name) is None
            or len(binding.name) > 64):
            raise ValueError
        _private_regular_file(ssh_known_hosts_file, "known_hosts")
        info = ssh_known_hosts_file.stat()
        if info.st_uid != os.getuid() or info.st_size == 0:
            raise ValueError
    except Exception:
        raise ValueError(_UNAVAILABLE) from None

    def observe(name: str, parent_folder_id: int, owner_name: str) -> FolderNamespaceObservation:
        try:
            if (name != binding.name or type(parent_folder_id) is not int
                or parent_folder_id != binding.parent_folder_id or owner_name != binding.owner_name):
                raise ValueError
            snapshot = credentials()
            if (not isinstance(snapshot, tuple) or len(snapshot) != 2
                or snapshot[0] != binding.owner_name or not isinstance(snapshot[1], str) or not snapshot[1]):
                raise ValueError
            ssh_config = TargetSshTransportConfig(
                ssh_host, ssh_port, snapshot[0], snapshot[1], ssh_known_hosts_file, config.timeout_seconds,
            )
            # Local import preserves the existing isolated-fields/archive dependency.
            from .folder_archive_owner_session import FixedFolderArchiveOwnerSession
            from .isolated_folder_http_transport import _FOLDER_FIELDS
            session = FixedFolderArchiveOwnerSession(
                FolderTransportConfig(config.base_url, config.bearer_token, config.timeout_seconds,
                                      config.ca_file, explicitly_enabled=True),
                owner_name=binding.owner_name, folder_name=_SENTINEL,
                credentials=lambda: snapshot, client_factory=client_factory,
            )
            collection = session.read_collection()
            if not session.logout_verified:
                raise ValueError
            serial = _envelope(collection, path="secret", name="folder")
            rows = collection.get("results")
            if (not isinstance(rows, list) or not 0 < len(rows) < 512
                or type(collection.get("matched_count")) is not int
                or collection["matched_count"] != len(rows)
                or collection.get("limit_reached", False) is not False):
                raise ValueError
            ids: set[int] = set()
            selected: dict[int, Mapping[str, object]] = {}
            for row in rows:
                if not isinstance(row, Mapping):
                    raise ValueError
                identifier, parent = row.get("id"), row.get("parent-folder")
                if (type(identifier) is not int or not 0 < identifier <= 2_147_483_647
                    or identifier in ids or type(parent) is not int or not 0 <= parent <= 2_147_483_647
                    or row.get("name") == _SENTINEL):
                    raise ValueError
                ids.add(identifier)
                if identifier in {binding.parent_folder_id, witness_folder_id}:
                    if not set(_FOLDER_FIELDS.split("|")) <= set(row) or row.get("folder-type") != "public":
                        raise ValueError
                    selected[identifier] = {key: row[key] for key in _FOLDER_FIELDS.split("|")}
            parent_row, witness_row = selected[binding.parent_folder_id], selected[witness_folder_id]
            witness_parent = witness_row.get("parent-folder")
            if (parent_row.get("name") != parent_path.split("/")[-1]
                or not hmac.compare_digest(canonical_digest(parent_row), binding.parent_digest)
                or type(witness_parent) is not int or witness_parent <= 0):
                raise ValueError
            witnesses = (parent_row.get("name"), witness_row.get("name"))
            if not all(isinstance(value, str) and value for value in witnesses) or witnesses[0] == witnesses[1]:
                raise ValueError
            raw = bytearray()
            try:
                with session._session.authenticated():
                    session._verify_actor()
                    raw = session._read_bytes("GET", "/api/v2/cmdb/system/admin/" + quote(binding.owner_name, safe="")
                                              + "?format=" + quote(_ROLE_FIELDS, safe=""))
                    role = json.loads(raw)
                    if not isinstance(role, Mapping) or not hmac.compare_digest(
                        _envelope(role, path="system", name="admin"), serial,
                    ):
                        raise ValueError
                    record = _record(role)
                    if (record is None or record.get("name") != binding.owner_name
                        or record.get("accprofile") != "super_admin" or record.get("status") != "enable"
                        or record.get("remote-auth") != "disable" or record.get("wildcard") != "disable"):
                        raise ValueError
                if not session.logout_verified:
                    raise ValueError
            finally:
                _zeroize_mutable(raw)
            assert isinstance(witnesses[0], str) and isinstance(witnesses[1], str)
            return FortiPamFolderNamespaceSshReader(
                ssh_config, candidate_name=binding.name, positive_witness_names=(witnesses[0], witnesses[1]),
                expected_device_serial=serial,
            ).read_namespace()
        except Exception:
            raise ValueError(_UNAVAILABLE) from None

    return observe


def _envelope(body: Mapping[str, object], *, path: str, name: str) -> str:
    serial = body.get("serial")
    if (body.get("version") != "v7.0.0" or type(body.get("build")) is not int or body["build"] != 29
        or type(body.get("http_status")) is not int or body["http_status"] != 200
        or body.get("http_method") != "GET" or body.get("path") != path or body.get("name") != name
        or body.get("status") not in {"OK", "success"}
        or not isinstance(serial, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", serial) is None
        or ("error" in body and (type(body["error"]) is not int or body["error"] != 0))):
        raise ValueError(_UNAVAILABLE)
    return serial
