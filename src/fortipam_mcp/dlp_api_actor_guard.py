"""Private fresh build-29 API-actor binding for the bounded DLP lab policy.

This reader proves the selected API identity and role projection. It neither
opens a gate nor claims production least privilege or Sensor ownership.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
import hashlib
import hmac
import http.client
import json
import re
import ssl
from typing import Any
from urllib.parse import quote, urlsplit

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .dlp_sensor_delete_http_transport import DlpSensorDeleteHttpTransportConfig, _ssl_context
from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_metadata_reader import _validate_value
from .local_user_reset_name_reader import _ENVELOPE
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

_MAX_BYTES = 1_048_576
_DENIED = "FortiPAM DLP API actor evidence is unavailable."
_ACTOR = "/api/v2/monitor/web-ui/state"
_USER_AGENT = "fortipam-bp005-dlp-api-actor/1"
_ROLE_FIELDS = ("name", "secretgrp", "secretgrp-permission", "sysgrp", "sysgrp-permission")
_SECRET_PERMISSIONS = frozenset({
    "approval-prof", "classification-tag", "client-software", "create-personal-folder",
    "create-root-folder", "dependency-updater", "event-filter-profile", "folder-table",
    "launcher", "modify-personal-folder", "playback-video", "pwd-changer", "pwd-charset",
    "pwd-policy", "rdp-remote-app-profile", "request", "secret-discovery", "secret-job",
    "secret-policy", "secret-script", "secret-table", "ssh-challenge", "target", "template",
    "view-clear-information", "view-secret-log", "view-secret-recording", "winappfilter-profile",
})
_SYSTEM_PERMISSIONS = frozenset({"accprofile", "admin", "cfg", "mnt", "mnt-mode", "upd"})
_PERMISSIONS = frozenset({"none", "read", "read-write"})
_SOURCE_SHA256 = "0c2bf35bb5cde1a5154012d6bf2f529d8d59e782a35aebe0bd29976ca9da434f"


class DlpApiActorGuardError(RuntimeError):
    """Stable, non-disclosing identity, qualification or transport refusal."""


@dataclass(frozen=True, slots=True, repr=False)
class DlpApiActorGuardBinding:
    """Programmatic private snapshot; no environment or public-name loader."""

    expected_actor: str = field(repr=False)
    expected_profile: str = field(repr=False)
    expected_serial: str = field(repr=False)
    expected_role_projection_digest: str

    def __post_init__(self) -> None:
        if (
            not _name(self.expected_actor) or not _name(self.expected_profile)
            or type(self.expected_serial) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.expected_serial) is None
            or type(self.expected_role_projection_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.expected_role_projection_digest) is None
        ):
            raise DlpApiActorGuardError(_DENIED)


@dataclass(frozen=True, slots=True, repr=False)
class DlpApiActorEvidence:
    """Fresh private identity/role evidence, not an authorization boolean."""

    actor: str = field(repr=False)
    profile: str = field(repr=False)
    device_serial: str = field(repr=False)
    version: str
    build: int
    role_projection_digest: str
    evidence_digest: str


class DlpApiActorGuard:
    """Observe only three constructor-bound GETs using one verified TLS config."""

    def __init__(
        self, config: DlpSensorDeleteHttpTransportConfig, binding: DlpApiActorGuardBinding,
        *, connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
    ) -> None:
        try:
            if type(config) is not DlpSensorDeleteHttpTransportConfig or type(binding) is not DlpApiActorGuardBinding:
                raise ValueError
            origin = urlsplit(config.base_url)
            port = origin.port or 443
            if (origin.scheme != "https" or not origin.hostname or origin.username is not None
                or origin.password is not None or origin.path not in {"", "/"}
                or origin.query or origin.fragment or not 1 <= port <= 65535
                or not callable(connection_factory)):
                raise ValueError
            context = _ssl_context(config)
            if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
                raise ValueError
        except Exception:
            raise DlpApiActorGuardError(_DENIED) from None
        self._config, self._binding, self._factory = config, binding, connection_factory
        self._host, self._port, self._context = origin.hostname, port, context
        self._user_path = ("/api/v2/cmdb/system/api-user/" + quote(binding.expected_actor, safe="")
                           + "?format=" + quote("name|accprofile", safe=""))
        self._role_path = ("/api/v2/cmdb/system/accprofile/" + quote(binding.expected_profile, safe="")
                           + "?format=" + quote("|".join(_ROLE_FIELDS), safe=""))

    def require_same_config(self, config: DlpSensorDeleteHttpTransportConfig) -> None:
        """A guard from another token/origin/config cannot qualify a transport."""
        if config is not self._config:
            raise DlpApiActorGuardError(_DENIED)

    def observe(self) -> DlpApiActorEvidence:
        """Re-read actor, API-user and complete selected Role on every invocation."""
        buffers: list[bytearray] = []
        try:
            actor = self._read(_ACTOR); buffers.append(actor)
            actor_digest = _actor_context(actor, expected_name=self._binding.expected_actor)
            _envelope(actor, "web-ui", "state", self._binding.expected_serial, monitor=True)
            user = self._read(self._user_path); buffers.append(user)
            row = _selected_row(user, "api-user", self._binding.expected_actor,
                                self._binding.expected_serial, frozenset({"name", "accprofile"}))
            if type(row["accprofile"]) is not str or row["accprofile"] != self._binding.expected_profile:
                raise ValueError
            role = self._read(self._role_path); buffers.append(role)
            projection = _selected_row(role, "accprofile", self._binding.expected_profile,
                                       self._binding.expected_serial, frozenset(_ROLE_FIELDS))
            _role_policy(projection)
            role_digest = _digest(projection)
            if not hmac.compare_digest(role_digest, self._binding.expected_role_projection_digest):
                raise ValueError
            evidence_digest = _digest({
                "contract": "bp005-build29-dlp-api-actor/v1", "source_sha256": _SOURCE_SHA256,
                "origin": self._config.base_url, "actor_context": actor_digest,
                "actor": self._binding.expected_actor, "profile": self._binding.expected_profile,
                "serial": self._binding.expected_serial, "version": "v7.0.0", "build": 29,
                "api_user": _digest(row), "role_projection": role_digest,
            })
            return DlpApiActorEvidence(self._binding.expected_actor, self._binding.expected_profile,
                                       self._binding.expected_serial, "v7.0.0", 29, role_digest, evidence_digest)
        except Exception:
            raise DlpApiActorGuardError(_DENIED) from None
        finally:
            for content in buffers:
                _zeroize_mutable(content)

    def _read(self, path: str) -> bytearray:
        content = bytearray()
        try:
            content = bytearray(_MAX_BYTES + 1)
            response = connection = None
            transferred = False
            try:
                if path not in {_ACTOR, self._user_path, self._role_path}:
                    raise ValueError
                connection = self._factory(self._host, self._port, timeout=self._config.timeout_seconds,
                                           context=self._context)
                connection.request("GET", path, headers={
                    "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close",
                    "Authorization": f"Bearer {self._config.bearer_token}", "Cache-Control": "no-cache, no-store",
                    "User-Agent": _USER_AGENT,
                })
                response = connection.getresponse()
                if (type(response.status) is not int or response.status != 200
                    or response.getheader("content-type", "").split(";", 1)[0].strip().lower() != "application/json"
                    or response.getheader("content-encoding", "identity").strip().lower() != "identity"):
                    raise ValueError
                total = 0
                while total < len(content):
                    with memoryview(content)[total:] as view:
                        count = response.readinto(view)
                    if type(count) is not int or not 0 <= count <= len(content) - total:
                        raise ValueError
                    if count == 0:
                        break
                    total += count
                if total > _MAX_BYTES:
                    raise ValueError
                content = _take_mutable_prefix(content, total)
                transferred = True
                return content
            finally:
                if not transferred:
                    _zeroize_mutable(content)
                for resource in (response, connection):
                    if resource is not None:
                        try:
                            resource.close()
                        except Exception:
                            pass
        except BaseException:
            _erase_transfer_storage(content)
            raise


def _name(value: object) -> bool:
    return (type(value) is str and 0 < len(value) <= 255
            and all(ord(c) >= 32 and ord(c) != 127 for c in value))


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                     separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()


def _envelope(content: bytearray, path: str, table: str, serial: str,
              *, monitor: bool = False) -> dict[str, tuple[int, int]]:
    left = _skip_json_space(content, 0); right = _json_value_end(content, left)
    if _skip_json_space(content, right) != len(content):
        raise ValueError
    envelope = _object_spans(content, left, right)
    if not envelope.keys() <= _ENVELOPE | {"mkey"}:
        raise ValueError
    _validate_value(content, left, right, depth=0)
    expected: dict[str, object] = {"http_method": "GET", "status": "success", "version": "v7.0.0",
                                   "build": 29, "serial": serial, "path": path, "name": table}
    if not monitor or "http_status" in envelope:
        expected["http_status"] = 200
    for key, value in expected.items():
        if content[slice(*envelope[key])] != json.dumps(value, ensure_ascii=True).encode("ascii"):
            raise ValueError
    if "action" in envelope and content[slice(*envelope["action"])] != b'""':
        raise ValueError
    if "vdom" in envelope and content[slice(*envelope["vdom"])] != b'"root"':
        raise ValueError
    for key in ("size", "matched_count"):
        if key in envelope and content[slice(*envelope[key])] != b"1":
            raise ValueError
    if "limit_reached" in envelope and content[slice(*envelope["limit_reached"])] != b"false":
        raise ValueError
    if "next_idx" in envelope:
        raise ValueError
    return envelope


def _selected_row(content: bytearray, table: str, name: str, serial: str,
                  fields: frozenset[str]) -> dict[str, Any]:
    envelope = _envelope(content, "system", table, serial)
    if "mkey" in envelope and content[slice(*envelope["mkey"])] != json.dumps(name, ensure_ascii=True).encode("ascii"):
        raise ValueError
    left, right = envelope["results"]
    if content[left] == 91:
        left = _skip_json_space(content, left + 1); end = _json_value_end(content, left)
        if _skip_json_space(content, end) != right - 1:
            raise ValueError
        right = end
    row = _object_spans(content, left, right)
    if not fields <= row.keys() or not row.keys() <= fields | {"q_origin_key"}:
        raise ValueError
    for key in {"name", "q_origin_key"} & row.keys():
        if content[slice(*row[key])] != json.dumps(name, ensure_ascii=True).encode("ascii"):
            raise ValueError
    return {key: json.loads(content[slice(*row[key])]) for key in fields}


def _role_policy(role: Mapping[str, Any]) -> None:
    for group in ("sysgrp", "secretgrp"):
        if type(role[group]) is not str or role[group] not in _PERMISSIONS | {"custom"}:
            raise ValueError
    for field_name, keys in (("secretgrp-permission", _SECRET_PERMISSIONS),
                             ("sysgrp-permission", _SYSTEM_PERMISSIONS)):
        value = role[field_name]
        if type(value) is not dict or set(value) != keys:
            raise ValueError
        if any(type(permission) is not str or permission not in _PERMISSIONS for permission in value.values()):
            raise ValueError
    if role["sysgrp"] != "read-write" or not (
        role["secretgrp"] == "read-write" or
        (role["secretgrp"] == "custom" and role["secretgrp-permission"]["secret-policy"] == "read-write")
    ):
        raise ValueError
