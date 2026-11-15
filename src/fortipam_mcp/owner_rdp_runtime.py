"""Default-off build29 RDP Owner reads and the existing fixed CREATE bridge.

No new authority or credential input is introduced. Server-owned selectors,
complete Folder/Policy state and independent namespace witnesses attenuate the
existing protected Owner provider to one ordinary BP006 CREATE workflow.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import time
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from v4_planning import AuthenticatedRequester, AuthoritativeProjection, SchemeDraft
from v4_planning.material_provider import _OpaqueC3Object

from .domain_secret_namespace_candidate import _envelope, _fixed_read
from .isolated_folder_creation_ownership import _digest as folder_snapshot_digest
from .isolated_folder_http_transport import _FOLDER_FIELDS
from .ldap_server_runtime import _read
from .owner_session_metadata import OwnerSessionMetadataTransport, _OwnerConnection, _DOMAIN_TEMPLATE_PATH
from .policy_assignment_definition import consume_policy_assignment_definition
from .secret_metadata_http_transport import (
    COLLECTION_PATH, MAX_RESPONSE_BYTES, FortiPamSecretMetadataHttpTransport,
    SecretMetadataHttpTransportConfig, SecretMetadataHttpTransportError,
    SecretMetadataProjectionInspection, _SECRET_METADATA_DETAIL_QUERY,
    _bounded_name, _folder_path, _record, _secret_name, _segment, _ssl_context, _zeroize_mutable,
)
from .secret_namespace_ssh_reader import FortiPamSecretNamespaceSshReader, SecretNamespaceObservation
from .secret_onboarding_projection_source import (
    FortiPamSecretOnboardingProjectionSource, SecretOnboardingBinding,
)
from .target_api_dependency_reader import _private_http_logs
from .target_ssh_transport import TargetSshTransportConfig, _private_regular_file, _safe_host

PREFIX = "FORTIPAM_MCP_V4_SECRET_CREATE_LAB_AUTO_RDP_OWNER_"
CONTRACT = "fortipam-700-build29-rdp-owner-binding-v1"
_ERROR = "The fixed RDP Owner runtime is unavailable."
_FIELDS = frozenset({"folder_path", "folder_id", "owner_name", "secret_name", "target_name", "policy_name",
    "expected_serial", "folder_state_digest", "policy_configuration_digest", "witness_secret_ids",
    "ssh_host", "ssh_port", "ssh_known_hosts_file"})


@dataclass(frozen=True, slots=True, repr=False)
class RdpOwnerSettings(_OpaqueC3Object):
    folder_path: str
    folder_id: int
    owner_name: str
    secret_name: str
    target_name: str
    policy_name: str
    expected_serial: str
    folder_state_digest: str
    policy_configuration_digest: str
    witness_secret_ids: tuple[int, int]
    ssh_host: str
    ssh_port: int
    ssh_known_hosts_file: Path

    def __post_init__(self) -> None:
        try:
            _folder_path(self.folder_path)
            _segment(self.owner_name)
            _secret_name(self.secret_name, bound_name=self.secret_name)
            _bounded_name(self.target_name, maximum=255)
            if (type(self.folder_id) is not int or not 0 < self.folder_id <= 2147483647
                or type(self.policy_name) is not str or re.fullmatch(
                    r"mcp-v4-secret-policy-[A-Za-z0-9][A-Za-z0-9._-]{0,42}", self.policy_name) is None
                or type(self.expected_serial) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", self.expected_serial) is None
                or any(type(v) is not str or re.fullmatch(r"[a-f0-9]{64}", v) is None for v in
                       (self.folder_state_digest, self.policy_configuration_digest))
                or type(self.witness_secret_ids) is not tuple or len(self.witness_secret_ids) != 2
                or any(type(v) is not int or not 0 < v <= 2147483647 for v in self.witness_secret_ids)
                or len(set(self.witness_secret_ids)) != 2 or not _safe_host(self.ssh_host)
                or type(self.ssh_port) is not int or not 1 <= self.ssh_port <= 65535
                or not self.ssh_known_hosts_file.is_absolute()):
                raise ValueError
            _private_regular_file(self.ssh_known_hosts_file, "known_hosts")
            info = self.ssh_known_hosts_file.stat()
            if info.st_uid != os.getuid() or info.st_size == 0:
                raise ValueError
        except Exception:
            raise ValueError(_ERROR) from None

    def check_binding(self, binding: object) -> None:
        if (type(binding) is not SecretOnboardingBinding or binding.target_protocol != "rdp"
            or binding.template_name != "Windows Machine" or binding.existing_secret_id is not None
            or binding.secret_session_controls_object_ref is not None or binding.launcher_name is None
            or binding.policy_object_ref is None or binding.folder_path != self.folder_path
            or binding.secret_name != self.secret_name or binding.target_name != self.target_name
            or binding.policy_folder_id != self.folder_id or binding.policy_profile_name != self.policy_name
            or binding.policy_folder_name != self.folder_path.rsplit("/", 1)[-1]):
            raise ValueError(_ERROR)


def load_rdp_owner_settings(environment: Mapping[str, str]) -> RdpOwnerSettings | None:
    enabled = environment.get(PREFIX + "ENABLED", "false")
    if enabled == "false":
        return None
    if enabled != "true":
        raise ValueError(_ERROR)
    raw = bytearray()
    try:
        path = Path(environment[PREFIX + "BINDING_FILE"])
        if not path.is_absolute():
            raise ValueError
        raw = _read(path, 16384)
        def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        body = json.loads(raw, object_pairs_hook=unique)
        if (type(body) is not dict or set(body) != _FIELDS | {"contract"} or body.pop("contract") != CONTRACT
            or type(body["witness_secret_ids"]) is not list):
            raise ValueError
        body["witness_secret_ids"] = tuple(body["witness_secret_ids"])
        body["ssh_known_hosts_file"] = Path(body["ssh_known_hosts_file"])
        return RdpOwnerSettings(**body)
    except Exception:
        raise ValueError(_ERROR) from None
    finally:
        _zeroize_mutable(raw)


class _RdpDetailConnection(_OwnerConnection):
    """Only the fixed redacted RDP detail GET; CREATE stays in the original bridge."""
    def __init__(self, owner: OwnerRdpSessionMetadataTransport, connection: Any) -> None:
        super().__init__(owner, connection, False)

    def request(self, method: str, url: str, body: memoryview | None = None,
            headers: dict[str, str] | None = None) -> None:
        owner = self._owner
        if (owner._client is None or owner._clock() >= owner._expires_at
            or type(owner._secret_id) is not int or owner._secret_id <= 0
            or method != "GET" or body is not None
            or url != f"{COLLECTION_PATH}/{owner._secret_id}?{_SECRET_METADATA_DETAIL_QUERY}"):
            raise SecretMetadataHttpTransportError(_ERROR)
        cookie = owner._client.build_request("GET", owner._config.base_url + url).headers.get("cookie")
        if not cookie:
            raise SecretMetadataHttpTransportError(_ERROR)
        self._connection.request("GET", url, headers={"Accept": "application/json", "Cookie": cookie,
            "Connection": "close", "Cache-Control": "no-cache, no-store", "Pragma": "no-cache",
            "User-Agent": owner._client.headers["User-Agent"]})

class OwnerRdpSessionMetadataTransport(OwnerSessionMetadataTransport):
    def __init__(self, config: SecretMetadataHttpTransportConfig, settings: RdpOwnerSettings,
            credentials: Callable[[], tuple[str, str]], *, allow_secret_create: bool = False,
            client_factory: Callable[..., Any] = httpx.Client,
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
            clock: Callable[[], float] = time.monotonic) -> None:
        if (type(settings) is not RdpOwnerSettings or not callable(credentials)
            or type(allow_secret_create) is not bool):
            raise ValueError(_ERROR)
        settings.__post_init__()
        self._rdp = settings
        super().__init__(config, owner_name=settings.owner_name, credentials=credentials,
            folder_path=settings.folder_path, secret_name=settings.secret_name, target_name=settings.target_name,
            witness=FortiPamSecretMetadataHttpTransport(config, bound_secret_name=settings.secret_name),
            allow_secret_create=allow_secret_create, client_factory=client_factory,
            connection_factory=connection_factory, clock=clock)
        self._allowed_paths.discard(_DOMAIN_TEMPLATE_PATH)

    def _metadata_connection(self, *args: Any, **kwargs: Any) -> _RdpDetailConnection:
        parsed = urlsplit(self._config.base_url)
        if (args != (parsed.hostname, parsed.port or 443) or self._client is None
            or self._clock() >= self._expires_at):
            raise SecretMetadataHttpTransportError(_ERROR)
        connection = self._raw_connection_factory(parsed.hostname, parsed.port or 443,
            timeout=self._config.timeout_seconds, context=_ssl_context(self._config))
        return _RdpDetailConnection(self, connection)

    def _request_projection_detail(self, secret_id: int, *, winrm_collector: bool = False,
            domain_account: bool = False) -> tuple[int, object | None, bool]:
        if (type(secret_id) is not int or secret_id != self._secret_id
            or winrm_collector is not False or domain_account is not False):
            raise SecretMetadataHttpTransportError(_ERROR)
        return FortiPamSecretMetadataHttpTransport._request_projection_detail(self, secret_id)

    def _verify_folder_and_policy(self) -> None:
        b = self._rdp
        _fixed_read(self, "/api/v2/monitor/web-ui/state")
        role = _fixed_read(self, "/api/v2/cmdb/system/admin/" + quote(b.owner_name, safe="")
            + "?format=name%7Caccprofile%7Cstatus%7Cremote-auth%7Cwildcard")
        row = _record(role)
        if (_envelope(role, "system", "admin") != b.expected_serial or row is None
            or any(row.get(k) != v for k, v in {"name": b.owner_name, "accprofile": "super_admin",
                "status": "enable", "remote-auth": "disable", "wildcard": "disable"}.items())
            or self._lookup_id("folder", b.folder_path) != b.folder_id):
            raise ValueError(_ERROR)
        folder = _fixed_read(self, f"/api/v2/cmdb/secret/folder/{b.folder_id}?format=" + quote(_FOLDER_FIELDS, safe=""))
        current = _record(folder)
        parent = current.get("parent-folder") if current is not None else None
        if (_envelope(folder, "secret", "folder") != b.expected_serial or current is None
            or not set(_FOLDER_FIELDS.split("|")) <= set(current)
            or type(current.get("id")) is not int or current["id"] != b.folder_id
            or current.get("name") != b.folder_path.rsplit("/", 1)[-1]
            or current.get("folder-type") != "public" or type(parent) is not int
            or parent <= 0 or current.get("inherit-folder-ztna") != "enable"
            or folder_snapshot_digest({k: current[k] for k in _FOLDER_FIELDS.split("|")}) != b.folder_state_digest
            or current.get("inherit-policy") != "disable" or current.get("secret-policy") != b.policy_name
            or self._verify_collector_folder_acl(b.folder_id, b.owner_name) is not True):
            raise ValueError(_ERROR)
        users = current["user-permission"]
        if (not isinstance(users, list) or len(users) != 1 or not isinstance(users[0], Mapping)
            or users[0].get("allowed-launcher-type") != "all"):
            raise ValueError(_ERROR)
        raw = bytearray()
        try:
            if self._client is None or self._clock() >= self._expires_at:
                raise ValueError
            with _private_http_logs(), self._client.stream("GET", "/api/v2/cmdb/secret/policy/" + quote(b.policy_name, safe="")
                    + "?with_meta=true&vdom=root", headers={"Accept": "application/json"}) as response:
                if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            policy = consume_policy_assignment_definition(raw, policy_name=b.policy_name,
                serial_digest=hashlib.sha256(b.expected_serial.encode("ascii")).hexdigest())
            if policy.configuration_digest != b.policy_configuration_digest or policy.controls[:2] != ("enable", "enable"):
                raise ValueError
        finally:
            _zeroize_mutable(raw)

    def _verify_global_absence(self) -> None:
        b = self._rdp
        collection = _fixed_read(self, "/api/v2/cmdb/secret/database?format=id%7Cname%7Cfolder&count=512&start=0")
        if _envelope(collection, "secret", "database") != b.expected_serial or not isinstance(collection, Mapping):
            raise ValueError(_ERROR)
        rows = collection.get("results")
        if (not isinstance(rows, list) or not 2 <= len(rows) < 512
            or type(collection.get("matched_count")) is not int or collection["matched_count"] != len(rows)
            or collection.get("limit_reached", False) is not False):
            raise ValueError(_ERROR)
        selected: dict[int, str] = {}
        seen: set[int] = set()
        for row in rows:
            if (not isinstance(row, Mapping) or type(row.get("id")) is not int
                or not 0 < row["id"] <= 2147483647 or row["id"] in seen):
                raise ValueError(_ERROR)
            seen.add(row["id"])
            if row["id"] in b.witness_secret_ids:
                if (type(row.get("name")) is not str or not row["name"] or type(row.get("folder")) is not int
                    or not 0 <= row["folder"] <= 2147483647):
                    raise ValueError(_ERROR)
                selected[row["id"]] = row["name"]
        witnesses = tuple(selected[identifier] for identifier in b.witness_secret_ids)
        _fixed_read(self, "/api/v2/monitor/web-ui/state")
        username, password = self._credentials()
        if username != b.owner_name:
            raise ValueError(_ERROR)
        config = TargetSshTransportConfig(b.ssh_host, b.ssh_port, username, password,
            b.ssh_known_hosts_file, self._config.timeout_seconds)
        del username, password
        observed = FortiPamSecretNamespaceSshReader(config, candidate_name=b.secret_name,
            positive_witness_names=witnesses, expected_device_serial=b.expected_serial).read_namespace()
        if (type(observed) is not SecretNamespaceObservation or observed.global_name_absent is not True
            or type(observed.positive_witness_count) is not int or observed.positive_witness_count != 2
            or observed.status != "name_absent" or type(observed.namespace_digest) is not str
            or re.fullmatch(r"[a-f0-9]{64}", observed.namespace_digest) is None):
            raise ValueError(_ERROR)

    def inspect_projection(self, folder_path: str, secret_name: str, template: str, target_name: str,
            *, expected_rdp_event_filter_profile: str | None = None) -> SecretMetadataProjectionInspection:
        b = self._rdp
        if (folder_path, secret_name, template, target_name) != (b.folder_path, b.secret_name, "Windows Machine", b.target_name):
            raise SecretMetadataHttpTransportError(_ERROR)
        try:
            self._verify_folder_and_policy()
            if self._lookup_id("secret", b.folder_path + "/" + b.secret_name) is None:
                self._verify_global_absence()
            return super().inspect_projection(folder_path, secret_name, template, target_name,
                expected_rdp_event_filter_profile=expected_rdp_event_filter_profile)
        except Exception:
            raise SecretMetadataHttpTransportError(_ERROR) from None

    def verify_folder_policy_binding(self, folder_path: str, *, expected_folder_id: int,
            expected_folder_name: str, expected_policy_name: str) -> bool:
        b = self._rdp
        if (folder_path, expected_folder_id, expected_folder_name, expected_policy_name) != (
                b.folder_path, b.folder_id, b.folder_path.rsplit("/", 1)[-1], b.policy_name):
            raise SecretMetadataHttpTransportError(_ERROR)
        return super().verify_folder_policy_binding(folder_path, expected_folder_id=expected_folder_id,
            expected_folder_name=expected_folder_name, expected_policy_name=expected_policy_name)


class OwnerRdpPlanningSource(FortiPamSecretOnboardingProjectionSource):
    """Authenticate only after the original resolver validates the exact Draft."""
    def project(self, draft: SchemeDraft, requester: AuthenticatedRequester, *,
            now_epoch: int) -> tuple[AuthoritativeProjection, ...]:
        transport = self._secret_transport
        if type(transport) is not OwnerRdpSessionMetadataTransport:
            raise ValueError(_ERROR)
        transport._rdp.check_binding(self.resolve_private_binding(draft, requester))
        with transport.authenticated():
            return super().project(draft, requester, now_epoch=now_epoch)
