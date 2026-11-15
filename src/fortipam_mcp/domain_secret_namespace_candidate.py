"""Opt-in fixed Secret namespace evidence inside the active Domain Owner session."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import TYPE_CHECKING
from urllib.parse import quote

from .folder_acl_live_workflow import _relations
from .local_user_reset_fixture_preflight import _actor_context
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_create_191_private_adapter import SecretCreate700DomainBinding
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, SecretMetadataHttpTransportConfig, _record,
    _redact_json_field_values, _zeroize_mutable,
)
from .target_ssh_transport import TargetSshTransportConfig, _private_regular_file, _safe_host

if TYPE_CHECKING:
    from .secret_namespace_ssh_reader import SecretNamespaceObservation

PREFIX = "FORTIPAM_MCP_V4_SECRET_CREATE_LAB_AUTO_DOMAIN_NAMESPACE_"
CONTRACT = "fortipam-700-build29-domain-secret-namespace-candidate-v1"
_UNAVAILABLE = "The fixed Domain Secret namespace evidence is unavailable."


@dataclass(frozen=True, slots=True)
class DomainSecretNamespaceSettings:
    folder_id: int
    witness_secret_ids: tuple[int, int]
    ssh_host: str
    ssh_port: int
    ssh_known_hosts_file: Path

    def __post_init__(self) -> None:
        if (type(self.folder_id) is not int or not 0 < self.folder_id <= 2_147_483_647
            or not isinstance(self.witness_secret_ids, tuple) or len(self.witness_secret_ids) != 2
            or any(type(item) is not int or not 0 < item <= 2_147_483_647 for item in self.witness_secret_ids)
            or self.witness_secret_ids[0] == self.witness_secret_ids[1]
            or not _safe_host(self.ssh_host) or type(self.ssh_port) is not int
            or not 1 <= self.ssh_port <= 65535 or not self.ssh_known_hosts_file.is_absolute()):
            raise ValueError(_UNAVAILABLE)
        _private_regular_file(self.ssh_known_hosts_file, "known_hosts")
        info = self.ssh_known_hosts_file.stat()
        if info.st_uid != os.getuid() or info.st_size == 0:
            raise ValueError(_UNAVAILABLE)


def load_domain_secret_namespace_settings(environment: Mapping[str, str]) -> DomainSecretNamespaceSettings | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    if enabled not in {"true", "false"}:
        raise ValueError(_UNAVAILABLE)
    if enabled == "false":
        return None
    try:
        path = Path(environment[PREFIX + "BINDING_FILE"])
        if not path.is_absolute():
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 16384):
                raise ValueError
            raw = os.read(descriptor, 16385)
        finally:
            os.close(descriptor)
        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        body = json.loads(raw, object_pairs_hook=unique)
        if (len(raw) > 16384 or not isinstance(body, dict)
            or set(body) != {"contract", "folder_id", "witness_secret_ids"}
            or body["contract"] != CONTRACT or not isinstance(body["witness_secret_ids"], list)
            or len(body["witness_secret_ids"]) != 2):
            raise ValueError
        return DomainSecretNamespaceSettings(body["folder_id"], tuple(body["witness_secret_ids"]),
            environment[PREFIX + "SSH_HOST"], int(environment.get(PREFIX + "SSH_PORT", "22")),
            Path(environment[PREFIX + "SSH_KNOWN_HOSTS_FILE"]))
    except Exception:
        raise ValueError(_UNAVAILABLE) from None


def _envelope(body: object, path: str, name: str) -> str:
    if (not isinstance(body, Mapping) or body.get("version") != "v7.0.0"
        or type(body.get("build")) is not int or body["build"] != 29
        or type(body.get("http_status")) is not int or body["http_status"] != 200
        or body.get("http_method") != "GET" or body.get("path") != path or body.get("name") != name
        or body.get("status") not in {"OK", "success"}
        or not isinstance(body.get("serial"), str)
        or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", body["serial"]) is None
        or ("error" in body and (type(body["error"]) is not int or body["error"] != 0))):
        raise ValueError(_UNAVAILABLE)
    serial = body["serial"]
    assert isinstance(serial, str)
    return serial


def _fixed_read(owner: OwnerSessionMetadataTransport, path: str) -> object:
    raw = bytearray()
    try:
        if owner._client is None or owner._clock() >= owner._expires_at:
            raise ValueError
        with owner._client.stream("GET", path) as response:
            if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                raise ValueError
            for chunk in response.iter_bytes():
                if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise ValueError
                raw.extend(chunk)
        if path == "/api/v2/monitor/web-ui/state":
            _actor_context(raw, expected_name=owner._owner_name)
            return None
        _redact_json_field_values(raw)
        return json.loads(raw)
    finally:
        _zeroize_mutable(raw)


def build_domain_secret_namespace_observer(
    config: SecretMetadataHttpTransportConfig, binding: SecretCreate700DomainBinding,
    credentials: Callable[[], tuple[str, str]], settings: DomainSecretNamespaceSettings,
    *, owner_transport: Callable[[], OwnerSessionMetadataTransport],
) -> Callable[[SecretCreate700DomainBinding, int], SecretNamespaceObservation]:
    if (type(binding) is not SecretCreate700DomainBinding or type(settings) is not DomainSecretNamespaceSettings
        or not callable(credentials) or not callable(owner_transport)
        or len(binding.secret_name) > 64
        or re.fullmatch(r"mcp-v4-[A-Za-z0-9][A-Za-z0-9._-]*", binding.secret_name) is None):
        raise ValueError(_UNAVAILABLE)

    def observe(current: SecretCreate700DomainBinding, folder_id: int) -> SecretNamespaceObservation:
        try:
            if (type(current) is not SecretCreate700DomainBinding
                or replace(current, plan_digest=binding.plan_digest) != binding
                or type(folder_id) is not int or folder_id != settings.folder_id):
                raise ValueError
            owner = owner_transport()
            if (not isinstance(owner, OwnerSessionMetadataTransport) or owner._config != config
                or owner._owner_name != binding.target_owner_name or owner._folder_id != folder_id):
                raise ValueError
            _fixed_read(owner, "/api/v2/monitor/web-ui/state")
            role = _fixed_read(owner, "/api/v2/cmdb/system/admin/" + quote(binding.target_owner_name, safe="")
                + "?format=name%7Caccprofile%7Cstatus%7Cremote-auth%7Cwildcard")
            serial = _envelope(role, "system", "admin")
            record = _record(role)
            if (record is None or record.get("name") != binding.target_owner_name
                or record.get("accprofile") != "super_admin" or record.get("status") != "enable"
                or record.get("remote-auth") != "disable" or record.get("wildcard") != "disable"):
                raise ValueError
            fields = "id|name|folder-type|parent-folder|inherit-permission|user-permission|group-permission"
            payload = _fixed_read(owner, f"/api/v2/cmdb/secret/folder/{folder_id}?format=" + quote(fields, safe=""))
            if not hmac.compare_digest(_envelope(payload, "secret", "folder"), serial):
                raise ValueError
            folder = _record(payload)
            parent = folder.get("parent-folder") if folder is not None else None
            if (folder is None or type(folder.get("id")) is not int or folder["id"] != folder_id
                or folder.get("name") != binding.folder_path.rsplit("/", 1)[-1]
                or folder.get("folder-type") != "public" or type(parent) is not int
                or parent <= 0 or folder.get("inherit-permission") != "disable"
                or folder.get("group-permission") != []):
                raise ValueError
            owners = _relations(folder, principal_key="user-name")
            if (len(owners) != 1 or owners[0].relation_id <= 0
                or owners[0].names != (binding.target_owner_name,)
                or owners[0].folder_permission != "owner" or owners[0].secret_permission != "owner"):
                raise ValueError
            collection = _fixed_read(owner, "/api/v2/cmdb/secret/database?format=id%7Cname%7Cfolder&count=512&start=0")
            if not hmac.compare_digest(_envelope(collection, "secret", "database"), serial):
                raise ValueError
            assert isinstance(collection, Mapping)
            rows = collection.get("results")
            if (not isinstance(rows, list) or not 2 <= len(rows) < 512
                or type(collection.get("matched_count")) is not int
                or collection["matched_count"] != len(rows) or collection.get("limit_reached", False) is not False):
                raise ValueError
            selected: dict[int, str] = {}
            ids: set[int] = set()
            for row in rows:
                if not isinstance(row, Mapping) or type(row.get("id")) is not int or not 0 < row["id"] <= 2_147_483_647:
                    raise ValueError
                if row["id"] in ids:
                    raise ValueError
                ids.add(row["id"])
                if row["id"] in settings.witness_secret_ids:
                    if (not isinstance(row.get("name"), str) or not row["name"]
                        or type(row.get("folder")) is not int or not 0 <= row["folder"] <= 2_147_483_647):
                        raise ValueError
                    selected[row["id"]] = row["name"]
            witnesses = tuple(selected[identifier] for identifier in settings.witness_secret_ids)
            if witnesses[0] == witnesses[1]:
                raise ValueError
            _fixed_read(owner, "/api/v2/monitor/web-ui/state")
            snapshot = credentials()
            if not isinstance(snapshot, tuple) or len(snapshot) != 2 or snapshot[0] != binding.target_owner_name:
                raise ValueError
            from .secret_namespace_ssh_reader import FortiPamSecretNamespaceSshReader
            ssh = TargetSshTransportConfig(settings.ssh_host, settings.ssh_port, snapshot[0], snapshot[1],
                settings.ssh_known_hosts_file, config.timeout_seconds)
            return FortiPamSecretNamespaceSshReader(ssh, candidate_name=binding.secret_name,
                positive_witness_names=witnesses, expected_device_serial=serial).read_namespace()
        except Exception:
            raise ValueError(_UNAVAILABLE) from None
    return observe


def owner_domain_namespace_transport(
    config: SecretMetadataHttpTransportConfig, binding: SecretCreate700DomainBinding,
    credentials: Callable[[], tuple[str, str]], *, namespace_settings: DomainSecretNamespaceSettings | None = None,
    allow_secret_create: bool = False,
) -> OwnerSessionMetadataTransport:
    from .owner_domain_runtime import owner_domain_transport
    if namespace_settings is None:
        return owner_domain_transport(config, binding, credentials, allow_secret_create=allow_secret_create)
    holder: dict[str, OwnerSessionMetadataTransport] = {}
    observer = build_domain_secret_namespace_observer(config, binding, credentials, namespace_settings,
        owner_transport=lambda: holder["owner"])
    result = owner_domain_transport(config, binding, credentials, allow_secret_create=allow_secret_create,
        namespace_observer=observer)
    holder["owner"] = result
    return result
