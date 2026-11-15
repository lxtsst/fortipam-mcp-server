"""Private, default-closed build-29 Launcher clone and owned-clone recovery.

Separate native fixed RDP and commandless built-in PuTTY profiles are admitted. Names and complete
preservation digests are private bindings, never MCP inputs. Native experiment
operations remain consumed; this adapter cannot reuse their destination.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
from urllib.parse import quote, urlencode

from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context
from .client_integrity_association_contract import _row as _association_row
from .putty_launcher_copy_http_contract import compile_native_putty_copy_body
from .putty_launcher_windows_http_contract import (
    WindowsPuttyApplication, compile_native_windows_putty_body, project_native_windows_putty_row,
)

CONTRACT = "fortipam_v4_launcher_clone_700_transport_v1"
PUTTY_CONTRACT = "fortipam_v4_putty_launcher_clone_700_transport_v1"
COPY_CONTRACT = "fortipam_v4_putty_launcher_copy_700_transport_v1"
WINDOWS_CONTRACT = "fortipam_v4_putty_launcher_windows_700_transport_v1"
_PATH = "/api/v2/cmdb/secret/launcher"
_UNAVAILABLE = "FortiPAM Launcher clone or recovery is unavailable."
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_SOURCE = re.compile(r"mcp-v4-launcher-[A-Za-z0-9][A-Za-z0-9._-]{0,46}\Z")
_DESTINATION = re.compile(r"mcp-v4-launcher-clone-[A-Za-z0-9][A-Za-z0-9._-]{0,35}\Z")
_RETIRED = frozenset({"mcp-v4-launcher-clone-mini-r1"})
_PUTTY_DESTINATION = re.compile(r"mcp-v4-putty-clone-[0-9]{8}-r[1-9][0-9]{0,3}\Z")


class LauncherCloneTransportError(RuntimeError):
    """Stable failure without names, payloads, parameters or credentials."""


def configuration_digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class LauncherCloneBinding:
    source_name: str
    destination_name: str
    source_digest: str
    clone_digest: str
    collection_digest: str

    def __post_init__(self) -> None:
        if (not isinstance(self.source_name, str) or not _SOURCE.fullmatch(self.source_name)
                or not isinstance(self.destination_name, str) or not _DESTINATION.fullmatch(self.destination_name)
                or self.destination_name in _RETIRED or self.source_name == self.destination_name
                or any(not isinstance(v, str) or not _DIGEST.fullmatch(v)
                       for v in (self.source_digest, self.clone_digest, self.collection_digest))):
            raise LauncherCloneTransportError(_UNAVAILABLE)

    @property
    def digest(self) -> str:
        return configuration_digest({key: getattr(self, key) for key in self.__slots__})


@dataclass(frozen=True, slots=True, repr=False)
class PuttyLauncherCloneBinding:
    source_name: str
    destination_name: str
    source_digest: str
    clone_digest: str
    collection_digest: str
    device_identity_digest: str

    def __post_init__(self) -> None:
        if (type(self.source_name) is not str or self.source_name != "PuTTY" or type(self.destination_name) is not str
                or _PUTTY_DESTINATION.fullmatch(self.destination_name) is None
                or any(type(v) is not str or _DIGEST.fullmatch(v) is None for v in
                       (self.source_digest, self.clone_digest, self.collection_digest, self.device_identity_digest))):
            raise LauncherCloneTransportError(_UNAVAILABLE)

    @property
    def digest(self) -> str:
        return configuration_digest({key: getattr(self, key) for key in self.__slots__})


@dataclass(frozen=True, slots=True, repr=False)
class PuttyLauncherCopyBinding:
    source_name: str
    destination_name: str
    source_digest: str
    clone_digest: str
    collection_digest: str
    device_identity_digest: str

    def __post_init__(self) -> None:
        # Reuse the same fixed source and commandless destination-name rules.
        PuttyLauncherCloneBinding(**{key: getattr(self, key) for key in self.__slots__})

    @property
    def digest(self) -> str:
        return configuration_digest({"contract": COPY_CONTRACT,
                                     **{key: getattr(self, key) for key in self.__slots__}})


@dataclass(frozen=True, slots=True, repr=False)
class PuttyLauncherWindowsBinding:
    source_name: str
    destination_name: str
    source_digest: str
    clone_digest: str
    collection_digest: str
    device_identity_digest: str
    executable_path: str
    executable_sha256: str

    def __post_init__(self) -> None:
        try:
            PuttyLauncherCloneBinding(**{key:getattr(self,key) for key in PuttyLauncherCloneBinding.__slots__})
            WindowsPuttyApplication(self.executable_path, self.executable_sha256)
        except Exception:
            raise LauncherCloneTransportError(_UNAVAILABLE) from None

    @property
    def application(self) -> WindowsPuttyApplication:
        return WindowsPuttyApplication(self.executable_path, self.executable_sha256)

    @property
    def digest(self) -> str:
        return configuration_digest({"contract":WINDOWS_CONTRACT,
                                     **{key:getattr(self,key) for key in self.__slots__}})


def _private_parent(path: Path) -> None:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError
    info = path.parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or path.parent.resolve() != path.parent):
        raise ValueError


def _read_private(path: Path) -> dict[str, Any]:
    _private_parent(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= 4096):
            raise ValueError
        value = json.loads(stream.read(4097))
    if not isinstance(value, dict):
        raise ValueError
    return value


def load_launcher_clone_binding(path: Path) -> LauncherCloneBinding:
    try:
        value = _read_private(path)
        if set(value) != {"contract", *LauncherCloneBinding.__slots__} or value.pop("contract") != CONTRACT:
            raise ValueError
        return LauncherCloneBinding(**value)
    except Exception:
        raise LauncherCloneTransportError(_UNAVAILABLE) from None


def load_putty_launcher_clone_binding(path: Path) -> PuttyLauncherCloneBinding:
    try:
        value = _read_private(path)
        if set(value) != {"contract", *PuttyLauncherCloneBinding.__slots__} or value.pop("contract") != PUTTY_CONTRACT:
            raise ValueError
        return PuttyLauncherCloneBinding(**value)
    except Exception:
        raise LauncherCloneTransportError(_UNAVAILABLE) from None


def load_putty_launcher_copy_binding(path: Path) -> PuttyLauncherCopyBinding:
    try:
        value = _read_private(path)
        if set(value) != {"contract", *PuttyLauncherCopyBinding.__slots__} or value.pop("contract") != COPY_CONTRACT:
            raise ValueError
        return PuttyLauncherCopyBinding(**value)
    except Exception:
        raise LauncherCloneTransportError(_UNAVAILABLE) from None


def load_putty_launcher_windows_binding(path: Path) -> PuttyLauncherWindowsBinding:
    try:
        value = _read_private(path)
        if set(value) != {"contract", *PuttyLauncherWindowsBinding.__slots__} or value.pop("contract") != WINDOWS_CONTRACT:
            raise ValueError
        return PuttyLauncherWindowsBinding(**value)
    except Exception:
        raise LauncherCloneTransportError(_UNAVAILABLE) from None


class FortiPamLauncherCloneHttpTransport:
    """Two fixed effects with separate durable claims; no caller-defined route."""

    def __init__(self, config: SecretMetadataHttpTransportConfig,
                 binding: LauncherCloneBinding | PuttyLauncherCloneBinding | PuttyLauncherCopyBinding | PuttyLauncherWindowsBinding,
                 state_directory: Path, *, client_factory: Callable[..., Any] | None = None,
                 clone_enabled: bool = False, recovery_enabled: bool = False) -> None:
        try:
            if (type(binding) not in {LauncherCloneBinding, PuttyLauncherCloneBinding, PuttyLauncherCopyBinding, PuttyLauncherWindowsBinding}
                    or type(config) is not SecretMetadataHttpTransportConfig
                    or type(clone_enabled) is not bool or type(recovery_enabled) is not bool):
                raise ValueError
            _private_parent(state_directory / "clone.claim.json")
        except Exception:
            raise LauncherCloneTransportError(_UNAVAILABLE) from None
        self._config, self._binding, self._state = config, binding, state_directory
        self._factory = client_factory
        self._clone_enabled, self._recovery_enabled = clone_enabled, recovery_enabled

    @property
    def putty_profile(self) -> bool:
        return type(self._binding) in {PuttyLauncherCloneBinding, PuttyLauncherCopyBinding, PuttyLauncherWindowsBinding}

    @property
    def putty_copy_profile(self) -> bool:
        return type(self._binding) is PuttyLauncherCopyBinding

    @property
    def putty_windows_profile(self) -> bool:
        return type(self._binding) is PuttyLauncherWindowsBinding

    @property
    def _putty_form_profile(self) -> bool:
        return self.putty_copy_profile or self.putty_windows_profile

    def _path(self, name: str) -> str:
        if name not in (self._binding.source_name, self._binding.destination_name):
            raise ValueError
        return f"{_PATH}/{quote(name, safe='')}"

    def _request(self, method: str, path: str) -> tuple[int, dict[str, Any]]:
        import httpx
        raw = bytearray()
        try:
            body = None
            if self._putty_form_profile and method == "POST":
                if path != _PATH + "?vdom=root":
                    raise ValueError
                code, source = self._request("GET", self._path(self._binding.source_name) + "?with_meta=true&vdom=root")
                if code != 200:
                    raise ValueError
                if isinstance(self._binding, PuttyLauncherWindowsBinding):
                    body = compile_native_windows_putty_body(source, launcher_name=self._binding.destination_name,
                        application=self._binding.application, expected_source_configuration_digest=self._binding.source_digest)
                else:
                    body = compile_native_putty_copy_body(source, launcher_name=self._binding.destination_name,
                        expected_source_configuration_digest=self._binding.source_digest)
            factory = self._factory or httpx.Client
            with factory(base_url=self._config.base_url, verify=_ssl_context(self._config),
                         timeout=self._config.timeout_seconds, trust_env=False, follow_redirects=False) as client:
                with client.stream(method, path, headers={"Authorization": "Bearer " + self._config.bearer_token,
                        "Accept": "application/json", "Accept-Encoding": "identity",
                        "Cache-Control": "no-cache, no-store"}, json=body) as response:
                    status = response.status_code
                    if "json" not in response.headers.get("content-type", ""):
                        raise ValueError
                    for chunk in response.iter_bytes():
                        if len(raw) + len(chunk) > 1_048_576:
                            raise ValueError
                        raw.extend(chunk)
                value = json.loads(raw)
            if self._putty_form_profile and method in {"POST", "DELETE"}:
                from .client_integrity_http_transport import _ACK_FIELDS
                metadata = value if isinstance(value, dict) else {}
                serial = metadata.get("serial")
                assert isinstance(self._binding, (PuttyLauncherCopyBinding, PuttyLauncherWindowsBinding))
                diagnostics = {
                    "json_object": isinstance(value, dict),
                    "known_root_members": set(metadata) <= _ACK_FIELDS,
                    "fixed_envelope_matches": all(metadata.get(k) == v for k, v in {
                        "version": "v7.0.0", "build": 29, "http_method": method,
                        "http_status": status, "path": "secret", "name": "launcher", "vdom": "root"}.items()),
                    "device_matches": type(serial) is str and
                        hashlib.sha256(serial.encode()).hexdigest() == self._binding.device_identity_digest,
                    "declared_success": metadata.get("status") in {"success", "OK"},
                    "mkey_matches": "mkey" not in metadata or metadata["mkey"] == self._binding.destination_name,
                    "action_matches": "action" not in metadata or metadata["action"] == "",
                    "business_error_clear": "error" not in metadata or
                        type(metadata["error"]) is int and metadata["error"] == 0,
                    "revision_changed_true": "revision_changed" not in metadata or metadata["revision_changed"] is True,
                }
                direction = "clone" if method == "POST" else "recover"
                self._save(direction + ".response.json", {
                    **self._record(direction, "response_observed"), "http_status": str(status),
                    **{key: "true" if flag else "false" for key, flag in diagnostics.items()},
                })
            if (not isinstance(value, dict) or value.get("version") != "v7.0.0"
                    or type(value.get("build")) is not int or value["build"] != 29
                    or value.get("path") != "secret" or value.get("name") != "launcher"
                    or value.get("http_method") != method or value.get("http_status") != status
                    or value.get("vdom") != "root"):
                raise ValueError
            if isinstance(self._binding, (PuttyLauncherCloneBinding, PuttyLauncherCopyBinding, PuttyLauncherWindowsBinding)):
                serial = value.get("serial")
                if (type(serial) is not str or not 8 <= len(serial) <= 64
                        or hashlib.sha256(serial.encode()).hexdigest() != self._binding.device_identity_digest):
                    raise ValueError
                if method in {"POST", "DELETE"}:
                    from .client_integrity_http_transport import _ACK_FIELDS
                    if (not set(value) <= _ACK_FIELDS or value.get("status") not in {"success", "OK"}
                            or "error" in value and (type(value["error"]) is not int or value["error"] != 0)
                            or "revision_changed" in value and value["revision_changed"] is not True
                            or "mkey" in value and value["mkey"] not in
                            ({self._binding.destination_name} if self._putty_form_profile else
                             {self._binding.source_name, self._binding.destination_name})
                            or "action" in value and value["action"] not in
                            ({"", "clone"} if method == "POST" and not self._putty_form_profile else {""})):
                        raise ValueError
                    for key in ("revision", "old_revision"):
                        if key in value and (type(value[key]) is not str or len(value[key]) > 255
                                or any(ord(c) < 32 or ord(c) == 127 for c in value[key])):
                            raise ValueError
            return status, value
        finally:
            raw[:] = b"\0" * len(raw)

    def _detail(self, name: str) -> dict[str, Any] | None:
        code, p = self._request("GET", self._path(name) + "?with_meta=true&vdom=root")
        if code == 404 and p.get("status") == "error":
            return None
        row = p.get("results")
        if isinstance(row, list) and len(row) == 1:
            row = row[0]
        if (code != 200 or p.get("status") not in ({"success", "OK"} if self.putty_profile else {"success"})
                or not isinstance(row, dict) or row.get("name") != name):
            raise ValueError
        return row

    def _collection(self) -> dict[str, str]:
        code, p = self._request("GET", _PATH + "?count=200&start=0&format=name%7Ctype&with_meta=true&vdom=root")
        rows = p.get("results")
        if (code != 200 or p.get("status") not in ({"success", "OK"} if self.putty_profile else {"success"})
                or p.get("limit_reached", False) is not False
                or not isinstance(rows, list) or len(rows) >= 200 or type(p.get("matched_count")) is not int
                or p["matched_count"] != len(rows)):
            raise ValueError
        if self.putty_profile and (type(p.get("size")) is not int or p["size"] != len(rows)
                or type(p.get("next_idx")) is not int or p["next_idx"] != len(rows)-1):
            raise ValueError
        result: dict[str, str] = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str) or row["name"] in result:
                raise ValueError
            result[row["name"]] = configuration_digest(row)
        return result

    def _source(self) -> None:
        b = self._binding
        row = self._detail(b.source_name)
        if isinstance(b, (PuttyLauncherCloneBinding, PuttyLauncherCopyBinding, PuttyLauncherWindowsBinding)):
            if (row is None or configuration_digest(row) != b.source_digest
                    or type(row.get("q_ref")) is not int or row["q_ref"] < 0
                    or row.get("q_origin_key") != "PuTTY"):
                raise ValueError
            # Only the clone gets a fresh identity/reference count. The source
            # may already be used; no source or existing association is changed.
            proposed = dict(row, name=b.destination_name, q_origin_key=b.destination_name, q_ref=0)
            _association_row({"version":"v7.0.0","build":29,"http_method":"GET","http_status":200,
                              "path":"secret","name":"launcher","vdom":"root","status":"success",
                              "results":proposed}, launcher_name=b.destination_name, software_name="")
            # Build-29 custom OS forms require an executable. Built-in PuTTY's
            # empty value is valid only while its configuration is disabled.
            # Serialization equality alone cannot qualify a custom copy.
            if self.putty_copy_profile and not proposed["os_app"][0]["exe"]:
                raise ValueError
            if isinstance(b, PuttyLauncherWindowsBinding):
                body = compile_native_windows_putty_body(
                    {"version":"v7.0.0","build":29,"http_method":"GET","http_status":200,
                     "path":"secret","name":"launcher","vdom":"root","status":"success","results":row},
                    launcher_name=b.destination_name, application=b.application,
                    expected_source_configuration_digest=b.source_digest)
                proposed.update(body)
                proposed["os_app"][0]["q_origin_key"] = 1
            if configuration_digest(proposed) != b.clone_digest:
                raise ValueError
            return
        if (row is None or configuration_digest(row) != b.source_digest or row.get("q_static") is not False
                or type(row.get("q_ref")) is not int or row["q_ref"] != 0
                or row.get("q_origin_key") != b.source_name or row.get("type") != "rdp"
                or type(row.get("launch-timeout")) is not int or row["launch-timeout"] != 30):
            raise ValueError
        apps = row.get("os_app")
        if not isinstance(apps, list) or len(apps) != 1 or not isinstance(apps[0], dict):
            raise ValueError
        app = apps[0]
        if app.get("exe") != "mstsc.exe" or app.get("parameter") != "/V:$HOST:$PORT /noConsentPrompt":
            raise ValueError
        for field, command in (("init-commands", "cmdkey /generic:$HOST /user:$USER /pass:$PASSWORD"),
                               ("clean-commands", "cmdkey /del:$HOST")):
            if app.get(field) != [{"id": 1, "q_origin_key": 1, "cmd": command}]:
                raise ValueError
        proposed = dict(row, name=b.destination_name, q_origin_key=b.destination_name)
        if configuration_digest(proposed) != b.clone_digest:
            raise ValueError

    def _record(self, direction: str, state: str) -> dict[str, str]:
        return {"contract": WINDOWS_CONTRACT if self.putty_windows_profile else COPY_CONTRACT if self.putty_copy_profile else PUTTY_CONTRACT if self.putty_profile else CONTRACT,
                "binding_digest": self._binding.digest,
                "direction": direction, "state": state}

    def intent_consumed(self, *, recovery: bool) -> bool:
        """Observe the durable workflow reservation without contacting the device."""
        if type(recovery) is not bool:
            raise LauncherCloneTransportError(_UNAVAILABLE)
        return os.path.lexists(self._state / ("recover.intent.json" if recovery else "clone.intent.json"))

    def reserve_intent(self, requester_digest: str, authorization_digest: str, *, recovery: bool) -> None:
        """Seal one requester-bound workflow authorization before transport dispatch."""
        try:
            if (type(recovery) is not bool or any(not isinstance(v, str) or not _DIGEST.fullmatch(v)
                    for v in (requester_digest, authorization_digest))):
                raise ValueError
            direction = "recover" if recovery else "clone"
            self._save(direction + ".intent.json", {
                **self._record(direction, "intent_reserved"), "requester_digest": requester_digest,
                "authorization_digest": authorization_digest,
            })
        except Exception:
            raise LauncherCloneTransportError(_UNAVAILABLE) from None

    def _save(self, filename: str, value: Mapping[str, str]) -> None:
        path = self._state / filename
        _private_parent(path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            fd = os.open(path.name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(fd, "w") as stream:
                json.dump(value, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)

    def inspect(self, *, recovery: bool = False) -> dict[str, bool]:
        try:
            if type(recovery) is not bool:
                raise ValueError
            direction = "recover" if recovery else "clone"
            claim = self._state / (direction + ".claim.json")
            _private_parent(claim)
            if os.path.lexists(claim):
                raise ValueError
            if recovery:
                for filename, state in (("clone.claim.json", "reserved"), ("clone.verified.json", "verified")):
                    if _read_private(self._state / filename) != self._record("clone", state):
                        raise ValueError
            elif any(os.path.lexists(self._state / n) for n in ("clone.verified.json", "recover.claim.json")):
                raise ValueError
            self._verify_state(clone_present=recovery)
            return {"source_preserved": True, "destination_matches_expected_state": True,
                    "unrelated_launcher_metadata_preserved": True, "device_write_executed": False}
        except Exception:
            raise LauncherCloneTransportError(_UNAVAILABLE) from None

    def _verify_state(self, *, clone_present: bool) -> None:
        self._source()
        destination = self._detail(self._binding.destination_name)
        if clone_present:
            if (destination is None or configuration_digest(destination) != self._binding.clone_digest
                    or type(destination.get("q_ref")) is not int or destination["q_ref"] != 0):
                raise ValueError
            if isinstance(self._binding, PuttyLauncherWindowsBinding):
                project_native_windows_putty_row(
                    {"version":"v7.0.0","build":29,"http_method":"GET","http_status":200,
                     "path":"secret","name":"launcher","vdom":"root","status":"success","results":destination},
                    launcher_name=self._binding.destination_name, application=self._binding.application,
                    expected_configuration_digest=self._binding.clone_digest)
            if self.putty_profile:
                self._usage_empty(destination["q_type"])
        elif destination is not None:
            raise ValueError
        rows = self._collection()
        if clone_present:
            if self._binding.destination_name not in rows:
                raise ValueError
            del rows[self._binding.destination_name]
        elif self._binding.destination_name in rows:
            raise ValueError
        if configuration_digest(rows) != self._binding.collection_digest:
            raise ValueError

    def _usage_empty(self, object_type: int) -> None:
        """Require fresh reported empty usage; never infer global completeness."""
        import httpx
        from .local_user_reset_metadata_reader import _monitor_results, _array_count, _validate_value
        from .local_user_reset_projection import _object_spans
        from .secret_metadata_http_transport import _skip_json_space, _json_value_end

        raw = bytearray()
        try:
            if (not isinstance(self._binding, (PuttyLauncherCloneBinding, PuttyLauncherCopyBinding, PuttyLauncherWindowsBinding))
                    or type(object_type) is not int):
                raise ValueError
            query = urlencode({"mkey": self._binding.destination_name,
                               "qtypes": json.dumps([object_type], separators=(",", ":"))})
            factory = self._factory or httpx.Client
            with factory(base_url=self._config.base_url, verify=_ssl_context(self._config),
                         timeout=self._config.timeout_seconds, trust_env=False, follow_redirects=False) as client:
                with client.stream("GET", "/api/v2/monitor/system/object/usage?" + query,
                        headers={"Authorization": "Bearer " + self._config.bearer_token,
                                 "Accept": "application/json", "Accept-Encoding": "identity"}) as response:
                    if response.status_code != 200 or "json" not in response.headers.get("content-type", ""):
                        raise ValueError
                    for chunk in response.iter_bytes():
                        if len(raw) + len(chunk) > 1_048_576:
                            raise ValueError
                        raw.extend(chunk)
            left, right = _monitor_results(raw, expected_route="system/object/usage",
                                           expected_mkey=self._binding.destination_name)
            root = _object_spans(raw, _skip_json_space(raw, 0), _json_value_end(raw, _skip_json_space(raw, 0)))
            serial = json.loads(raw[slice(*root["serial"])])
            if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != self._binding.device_identity_digest:
                raise ValueError
            fields = _object_spans(raw, left, right)
            if "currently_using" not in fields:
                raise ValueError
            for start, end in fields.values():
                _validate_value(raw, start, end, depth=0)
            if _array_count(raw, *fields["currently_using"], depth=0, objects_only=True) != 0:
                raise ValueError
        finally:
            raw[:] = b"\0" * len(raw)

    def execute(self, *, recovery: bool = False) -> dict[str, bool]:
        try:
            if type(recovery) is not bool or not (self._recovery_enabled if recovery else self._clone_enabled):
                raise ValueError
            self.inspect(recovery=recovery)
            direction = "recover" if recovery else "clone"
            self._save(direction + ".claim.json", self._record(direction, "reserved"))
            method = "DELETE" if recovery else "POST"
            path = (self._path(self._binding.destination_name) + "?vdom=root" if recovery else
                    _PATH + "?vdom=root" if self._putty_form_profile else
                    self._path(self._binding.source_name) + "?action=clone&nkey="
                    + quote(self._binding.destination_name, safe="") + "&vdom=root")
            code, response = self._request(method, path)
            if code != 200 or response.get("status") not in ({"success", "OK"} if self.putty_profile else {"success"}):
                raise ValueError
            self._verify_state(clone_present=not recovery)
            self._save(direction + ".verified.json", self._record(direction, "verified"))
            return {"verified": True, "source_preserved": True, "clone_present": not recovery,
                    "associations_or_sessions_changed": False}
        except Exception:
            raise LauncherCloneTransportError(_UNAVAILABLE) from None
