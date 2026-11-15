"""Explicit lazy Owner/API qualification for a fixed Web Target namespace read."""
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

from .folder_namespace_candidate import _envelope
from .local_user_reset_fixture_preflight import _actor_context
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig, _record, _zeroize_mutable,
)
from .target_contract import WebTargetCreateInput
from .target_http_transport import TargetHttpTransportConfig
from .target_namespace_ssh_reader import (
    FortiPamTargetNamespaceSshReader, TargetNamespaceObservation, _MAX_NAMES, _qualified_names,
)
from .target_ssh_transport import TargetSshTransportConfig, _private_regular_file, _safe_host


_UNAVAILABLE = "The private Target namespace candidate is unavailable."
_ROLE_FIELDS = "name|accprofile|status|remote-auth|wildcard"
_COLLECTION_PATH = "/api/v2/cmdb/secret/target?format=name"
_MAX_RESPONSE_BYTES = 64 * 1024
TargetNamespaceObserver = Callable[[str], TargetNamespaceObservation]


def build_target_namespace_observer(
    config: TargetHttpTransportConfig, *, binding: WebTargetCreateInput,
    credentials: Callable[[], tuple[str, str]], ssh_host: str, ssh_port: int,
    ssh_known_hosts_file: Path, positive_witness_names: tuple[str, ...],
    client_factory: Callable[..., Any] = httpx.Client,
) -> TargetNamespaceObserver:
    """Bind local selectors only; each observation freshly qualifies the Owner."""
    try:
        owner = config.owner_username
        if (type(config) is not TargetHttpTransportConfig or type(binding) is not WebTargetCreateInput
            or not isinstance(owner, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", owner) is None
            or not callable(credentials) or not _safe_host(ssh_host)
            or type(ssh_port) is not int or not 1 <= ssh_port <= 65535
            or not isinstance(ssh_known_hosts_file, Path) or not ssh_known_hosts_file.is_absolute()
            or not _qualified_names(positive_witness_names) or len(positive_witness_names) < 2
            or binding.target_name in positive_witness_names):
            raise ValueError
        _private_regular_file(ssh_known_hosts_file, "known_hosts")
        info = ssh_known_hosts_file.stat()
        if info.st_uid != os.getuid() or info.st_size == 0:
            raise ValueError
    except Exception:
        raise ValueError(_UNAVAILABLE) from None

    def observe(name: str) -> TargetNamespaceObservation:
        try:
            if type(name) is not str or name != binding.target_name:
                raise ValueError
            snapshot = credentials()
            if (not isinstance(snapshot, tuple) or len(snapshot) != 2 or snapshot[0] != owner
                or not isinstance(snapshot[1], str) or not snapshot[1]):
                raise ValueError
            metadata = SecretMetadataHttpTransportConfig(
                config.base_url, config.bearer_token, config.timeout_seconds, config.ca_file,
            )
            session = OwnerSessionMetadataTransport(
                metadata, owner_name=owner, credentials=lambda: snapshot,
                folder_path="target-namespace", secret_name="target-namespace", target_name=binding.target_name,
                witness=FortiPamSecretMetadataHttpTransport(metadata), client_factory=client_factory,
            )
            with session.authenticated():
                raw = _read_bytes(session, "/api/v2/monitor/web-ui/state")
                try:
                    _actor_context(raw, expected_name=owner)
                finally:
                    _zeroize_mutable(raw)
                role = _read_json(session, "/api/v2/cmdb/system/admin/" + quote(owner, safe="")
                                  + "?format=" + quote(_ROLE_FIELDS, safe=""))
                serial = _envelope(role, path="system", name="admin")
                record = _record(role)
                if (record is None or record.get("name") != owner or record.get("accprofile") != "super_admin"
                    or record.get("status") != "enable" or record.get("remote-auth") != "disable"
                    or record.get("wildcard") != "disable"):
                    raise ValueError
                collection = _read_json(session, _COLLECTION_PATH)
                if not hmac.compare_digest(_envelope(collection, path="secret", name="target"), serial):
                    raise ValueError
                names = _collection_names(collection)
                if not set(positive_witness_names) <= set(names):
                    raise ValueError
            if not session.logout_verified:
                raise ValueError
            observation = FortiPamTargetNamespaceSshReader(
                TargetSshTransportConfig(ssh_host, ssh_port, snapshot[0], snapshot[1], ssh_known_hosts_file,
                                         config.timeout_seconds),
                candidate_name=binding.target_name, positive_witness_names=positive_witness_names,
                expected_device_serial=serial, expected_api_names=names,
            ).read_namespace()
            if (type(observation) is not TargetNamespaceObservation or not observation.matches_candidate(name)
                or type(observation.global_name_absent) is not bool
                or observation.status != ("name_absent" if observation.global_name_absent else "name_present")
                or type(observation.target_count) is not int or observation.target_count != len(names)
                or type(observation.positive_witness_count) is not int
                or observation.positive_witness_count != len(positive_witness_names)
                or not isinstance(observation.namespace_digest, str)
                or re.fullmatch(r"[0-9a-f]{64}", observation.namespace_digest) is None
                or observation.global_name_absent != (name not in names)):
                raise ValueError
            return observation
        except Exception:
            raise ValueError(_UNAVAILABLE) from None

    return observe


def _read_bytes(session: OwnerSessionMetadataTransport, path: str) -> bytearray:
    raw = bytearray()
    try:
        with session._client.stream("GET", path) as response:
            if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                raise ValueError
            for chunk in response.iter_bytes():
                if len(raw) + len(chunk) > _MAX_RESPONSE_BYTES:
                    raise ValueError
                raw.extend(chunk)
        return raw
    except Exception:
        _zeroize_mutable(raw)
        raise


def _read_json(session: OwnerSessionMetadataTransport, path: str) -> Mapping[str, object]:
    raw = _read_bytes(session, path)
    try:
        value = json.loads(raw)
        if not isinstance(value, Mapping):
            raise ValueError
        return value
    finally:
        _zeroize_mutable(raw)


def _collection_names(collection: Mapping[str, object]) -> tuple[str, ...]:
    rows = collection.get("results")
    if (not isinstance(rows, list) or not 2 <= len(rows) <= _MAX_NAMES
        or type(collection.get("size")) is not int or collection["size"] != len(rows)
        or type(collection.get("matched_count")) is not int or collection["matched_count"] != len(rows)
        or collection.get("limit_reached", False) is not False):
        raise ValueError
    for key in ("next_idx", "next_index"):
        if key in collection and (type(collection[key]) is not int or collection[key] != 0):
            raise ValueError
    for key in ("total", "total_count"):
        if key in collection and (type(collection[key]) is not int or collection[key] != len(rows)):
            raise ValueError
    names: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("name"), str):
            raise ValueError
        names.append(row["name"])
    if not _qualified_names(tuple(names)):
        raise ValueError
    return tuple(names)
