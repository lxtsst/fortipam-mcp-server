"""Owned private startup input for the fixed disabled AD Discovery binding."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat

from .ad_discovery_projection_source import AdDiscoveryPlanningBinding
from .discovery_entry_create_contract import DisabledAdDiscoveryCreateInput
from .discovery_entry_m4_adapter import DiscoveryEntryBinding
from .domain_secret_projection_reader import load_domain_secret_planning_binding


AD_DISCOVERY_RUNTIME_BINDING_CONTRACT = "fortipam-700-ad-discovery-runtime-binding-v1"
_UNAVAILABLE = "The fixed AD Discovery runtime binding is unavailable."
_MAX_BYTES = 16384
_FIELDS = frozenset({
    "contract", "domain_binding_file", "source_name", "discovery_secret_id",
    "source_object_ref",
})
# A stable server-owned digest salt, not an authorization secret. The binding
# separately hashes the complete Source body and exact private Domain relation.
_PRIVATE_NONCE = hashlib.sha256(
    (AD_DISCOVERY_RUNTIME_BINDING_CONTRACT + ":private-nonce-v1").encode("ascii"),
).hexdigest()


class AdDiscoveryRuntimeBindingConfigurationError(ValueError):
    """Configuration denial without private paths, names or values."""


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _valid_info(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o600
        and 0 < info.st_size <= _MAX_BYTES
    )


def _read_binding_file(path: Path) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not _valid_info(before):
            raise ValueError
        content = bytearray()
        while len(content) <= _MAX_BYTES:
            chunk = os.read(descriptor, min(8192, _MAX_BYTES + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if (not _valid_info(after) or len(content) != before.st_size
            or len(content) > _MAX_BYTES or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns):
            raise ValueError
        return bytes(content)
    finally:
        os.close(descriptor)


def load_ad_discovery_runtime_binding(path: Path) -> AdDiscoveryPlanningBinding:
    """Load only fixed private selectors; qualification remains reader-owned."""
    try:
        payload = json.loads(_read_binding_file(path), object_pairs_hook=_unique_object)
        if (type(payload) is not dict or set(payload) != _FIELDS
            or any(type(payload[name]) is not str for name in _FIELDS - {"discovery_secret_id"})
            or payload["contract"] != AD_DISCOVERY_RUNTIME_BINDING_CONTRACT
            or type(payload["discovery_secret_id"]) is not int):
            raise ValueError
        domain_path = Path(payload["domain_binding_file"])
        if not domain_path.is_absolute():
            raise ValueError
        request = DisabledAdDiscoveryCreateInput(
            source_name=payload["source_name"],
            discovery_secret_id=payload["discovery_secret_id"],
        )
        domain = load_domain_secret_planning_binding(domain_path)
        return AdDiscoveryPlanningBinding(
            source=DiscoveryEntryBinding(request, _PRIVATE_NONCE, domain.create_binding),
            domain=domain, source_object_ref=payload["source_object_ref"],
        )
    except Exception:
        raise AdDiscoveryRuntimeBindingConfigurationError(_UNAVAILABLE) from None


__all__ = [
    "AD_DISCOVERY_RUNTIME_BINDING_CONTRACT",
    "AdDiscoveryRuntimeBindingConfigurationError",
    "load_ad_discovery_runtime_binding",
]
