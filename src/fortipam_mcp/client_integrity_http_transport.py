"""Default-closed native package create and verified-owned recovery transport.

This is an unregistered build-29 candidate. Public operations accept no caller route,
package, certificate, URL, command or arbitrary body. Reported usage is not a
complete global reference scan or signature-enforcement acceptance.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any
from urllib.parse import quote, urlencode

from .client_integrity_http_contract import (
    CERTIFICATE_NAME, _name, _hash_name, _package, _native_metadata,
    NativeClientIntegrityReadback, compile_native_client_integrity_create_body,
    compile_native_client_integrity_hash_create_body, project_native_client_integrity_detail,
    project_native_client_integrity_hash_detail, validate_native_client_integrity_recovery_state,
    validate_native_client_integrity_hash_recovery_state,
)
from .launcher_clone_http_transport import _private_parent, _read_private
from .local_user_reset_metadata_reader import _monitor_results
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _ssl_context, _skip_json_space, _json_value_end, _zeroize_mutable,
)

CONTRACT = "fortipam_v4_client_integrity_native_700_transport_v3"
HASH_CONTRACT = "fortipam_v4_client_integrity_native_hash_700_transport_v1"
_PATH = "/api/v2/cmdb/secret/client-software"
_TYPES = "/api/v2/monitor/web-ui/object-urls"
_USAGE = "/api/v2/monitor/system/object/usage"
_CERT = "/api/v2/cmdb/vpn.certificate/local/" + CERTIFICATE_NAME + "?format=name"
_AVAILABLE_CERTIFICATES = "/api/v2/monitor/system/available-certificates?with_ca=1&with_crl=1&with_remote=1"
_ACK_FIELDS = frozenset({"version", "build", "http_method", "http_status", "status", "path", "name", "vdom",
                         "serial", "revision", "old_revision", "revision_changed", "mkey", "action", "error"})
_UNAVAILABLE = "The native Client Software transport is unavailable."
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class ClientIntegrityHttpTransportError(RuntimeError):
    """Stable non-disclosing transport, state or preservation failure."""


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class NativeClientIntegrityBinding:
    software_name: str
    visible_collection_digest: str
    certificate_metadata_digest: str
    device_identity_digest: str
    object_type: int

    def __post_init__(self) -> None:
        try:
            _name(self.software_name)
            if (any(not isinstance(v, str) or not _DIGEST.fullmatch(v) for v in
                    (self.visible_collection_digest, self.certificate_metadata_digest, self.device_identity_digest))
                    or type(self.object_type) is not int or not 0 <= self.object_type <= 999_999_999):
                raise ValueError
        except Exception:
            raise ClientIntegrityHttpTransportError(_UNAVAILABLE) from None

    @property
    def digest(self) -> str:
        return _digest({key: getattr(self, key) for key in self.__slots__})


def load_native_client_integrity_binding(path: Path) -> NativeClientIntegrityBinding:
    """Load only the exact owner-only private native profile binding."""
    try:
        value = _read_private(path)
        if set(value) != {"contract", *NativeClientIntegrityBinding.__slots__} or value.pop("contract") != CONTRACT:
            raise ValueError
        return NativeClientIntegrityBinding(**value)
    except Exception:
        raise ClientIntegrityHttpTransportError(_UNAVAILABLE) from None


@dataclass(frozen=True, slots=True, repr=False)
class NativeHashClientIntegrityBinding:
    software_name: str
    visible_collection_digest: str
    executable_sha256: str
    device_identity_digest: str
    object_type: int

    def __post_init__(self) -> None:
        try:
            _hash_name(self.software_name)
            if (any(not isinstance(v, str) or not _DIGEST.fullmatch(v) for v in
                    (self.visible_collection_digest, self.executable_sha256, self.device_identity_digest))
                    or type(self.object_type) is not int or not 0 <= self.object_type <= 999_999_999):
                raise ValueError
        except Exception:
            raise ClientIntegrityHttpTransportError(_UNAVAILABLE) from None

    @property
    def digest(self) -> str:
        return _digest({key: getattr(self, key) for key in self.__slots__})


def load_native_hash_client_integrity_binding(path: Path) -> NativeHashClientIntegrityBinding:
    """Refuse certificate bindings or fallback to a different profile."""
    try:
        value = _read_private(path)
        if set(value) != {"contract", *NativeHashClientIntegrityBinding.__slots__} or value.pop("contract") != HASH_CONTRACT:
            raise ValueError
        return NativeHashClientIntegrityBinding(**value)
    except Exception:
        raise ClientIntegrityHttpTransportError(_UNAVAILABLE) from None


class FortiPamNativeClientIntegrityHttpTransport:
    """Separate signed intent/dispatch/verified records for each direction."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, binding: NativeClientIntegrityBinding | NativeHashClientIntegrityBinding,
                 state_directory: Path, authorization_key_file: Path, *, create_enabled: bool = False,
                 recovery_enabled: bool = False, client_factory: Callable[..., Any] | None = None,
                 clock: Callable[[], int] | None = None) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or type(binding) not in {NativeClientIntegrityBinding, NativeHashClientIntegrityBinding}
                    or type(create_enabled) is not bool or type(recovery_enabled) is not bool):
                raise ValueError
            _private_parent(state_directory / "create.claim.json")
            _private_parent(authorization_key_file)
            fd = os.open(authorization_key_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                    raise ValueError
                key = stream.read(33)
            if len(key) != 32:
                raise ValueError
        except Exception:
            raise ClientIntegrityHttpTransportError(_UNAVAILABLE) from None
        self._config, self._binding, self._state, self._key = config, binding, state_directory, key
        self._create, self._recovery, self._factory = create_enabled, recovery_enabled, client_factory
        self._clock = clock or (lambda: int(time.time()))
        self._record_contract = HASH_CONTRACT if type(binding) is NativeHashClientIntegrityBinding else CONTRACT
        self._mac_domain = b"client-integrity-hash-record:" if type(binding) is NativeHashClientIntegrityBinding else b"client-integrity-record:"
        self._namespace = _digest({"binding": binding.digest, "origin": config.base_url})
        self._detail = _PATH + "/" + quote(binding.software_name, safe="") + "?with_meta=true&vdom=root"

    @property
    def hash_profile(self) -> bool:
        """Non-secret profile identity derived only from the exact private binding."""
        return type(self._binding) is NativeHashClientIntegrityBinding

    def _record(self, direction: str, state: str, **fields: object) -> dict[str, Any]:
        return {"contract": self._record_contract, "namespace": self._namespace, "direction": direction, "state": state, **fields}

    def _save(self, filename: str, value: Mapping[str, object]) -> None:
        path = self._state / filename
        _private_parent(path)
        body = dict(value)
        body["mac"] = hmac.new(self._key, self._mac_domain + json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(parent)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            fd = os.open(path.name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(fd, "w") as stream:
                json.dump(body, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)

    def _load(self, filename: str, direction: str, state: str) -> dict[str, Any]:
        value = _read_private(self._state / filename)
        signature = value.pop("mac")
        expected = hmac.new(self._key, self._mac_domain + json.dumps(value, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        if (not isinstance(signature, str) or not hmac.compare_digest(signature, expected)
                or any(value.get(k) != v for k, v in self._record(direction, state).items())):
            raise ValueError
        return value

    def intent_consumed(self, *, recovery: bool = False) -> bool:
        if type(recovery) is not bool:
            raise ClientIntegrityHttpTransportError(_UNAVAILABLE)
        return os.path.lexists(self._state / (("recover" if recovery else "create") + ".intent.json"))

    def reserve_intent(self, requester_digest: str, authorization_digest: str, *, expires_at: int,
                       recovery: bool = False) -> None:
        try:
            now = self._clock()
            if (type(recovery) is not bool or type(expires_at) is not int or type(now) is not int
                    or not now < expires_at <= now + 600
                    or any(not isinstance(v, str) or not _DIGEST.fullmatch(v) for v in (requester_digest, authorization_digest))):
                raise ValueError
            self.inspect(recovery=recovery)
            direction = "recover" if recovery else "create"
            self._save(direction + ".intent.json", self._record(direction, "intent_reserved",
                requester_digest=requester_digest, authorization_digest=authorization_digest,
                issued_at=now, expires_at=expires_at))
        except Exception:
            raise ClientIntegrityHttpTransportError(_UNAVAILABLE) from None

    def _guard(self, direction: str) -> None:
        if not (self._recovery if direction == "recover" else self._create):
            raise ValueError
        record = self._load(direction + ".intent.json", direction, "intent_reserved")
        now = self._clock()
        if (type(now) is not int or type(record.get("issued_at")) is not int
                or type(record.get("expires_at")) is not int or not record["issued_at"] <= now < record["expires_at"]):
            raise ValueError

    def _request(self, method: str, path: str, *, body: Mapping[str, object] | None = None,
                 direction: str | None = None, expected_status: int = 200) -> bytearray:
        import httpx
        raw = bytearray()
        try:
            if (type(expected_status) is not int or expected_status not in {200, 404}
                    or expected_status == 404 and (method != "GET" or path != self._detail)):
                raise ValueError
            if method in {"POST", "DELETE"}:
                if direction not in {"create", "recover"}:
                    raise ValueError
                expected = ("DELETE", _PATH + "/" + quote(self._binding.software_name, safe="") + "?vdom=root") if direction == "recover" else ("POST", _PATH + "?vdom=root")
                if (method, path) != expected or method == "DELETE" and body is not None:
                    raise ValueError
                self._guard(direction)
            else:
                query = urlencode({"mkey": self._binding.software_name,
                    "qtypes": json.dumps([self._binding.object_type], separators=(",", ":"))})
                allowed = {_PATH + "?action=default&with_meta=true&vdom=root",
                           _PATH + "?count=200&start=0&with_meta=true&vdom=root", self._detail,
                           _TYPES, _USAGE + "?" + query}
                if type(self._binding) is NativeClientIntegrityBinding:
                    allowed.update({_CERT, _AVAILABLE_CERTIFICATES})
                if method != "GET" or body is not None or direction is not None or path not in allowed:
                    raise ValueError
            factory = self._factory or httpx.Client
            with factory(base_url=self._config.base_url, verify=_ssl_context(self._config),
                         timeout=self._config.timeout_seconds, trust_env=False, follow_redirects=False) as client:
                if direction is not None:
                    self._guard(direction)
                kwargs: dict[str, Any] = {}
                if body is not None:
                    kwargs["content"] = json.dumps(body, separators=(",", ":")).encode()
                with client.stream(method, path, headers={"Authorization": "Bearer " + self._config.bearer_token,
                        "Accept": "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-cache,no-store",
                        **({"Content-Type": "application/json"} if body is not None else {})}, **kwargs) as response:
                    is_json = "json" in response.headers.get("content-type", "")
                    if direction is None and (response.status_code != expected_status or not is_json):
                        raise ValueError
                    if is_json:
                        for chunk in response.iter_bytes():
                            if len(raw) + len(chunk) > 1_048_576:
                                raise ValueError
                            raw.extend(chunk)
                    if direction is not None:
                        self._observe_write_response(direction, response.status_code, is_json, raw)
                    if response.status_code != expected_status or not is_json:
                        raise ValueError
            return raw
        except Exception:
            _zeroize_mutable(raw)
            raise

    def _observe_write_response(self, direction: str, http_status: int, is_json: bool, raw: bytearray) -> None:
        """Retain only bounded response diagnostics; never supply ownership."""
        self._load(direction + ".claim.json", direction, "reserved")
        observation: dict[str, object] = {"http_status": http_status, "json_content_type": is_json,
            "body_received": bool(raw), "envelope_parsed": False,
            "declared_success": False, "declared_failure": False,
            "business_error_code": None, "results_present": False,
            "strict_acknowledgement_verified": False}
        try:
            fields = self._spans(raw)
            observation["envelope_parsed"] = True
            observation["results_present"] = "results" in fields
            known = _ACK_FIELDS | {"results", "cli_error", "message", "msg", "q_origin_key", "q_ref", "q_static",
                                   *_native_metadata(self._binding.object_type)}
            observation["known_root_members"] = sorted(set(fields) & known)
            observation["unknown_root_member_count"] = len(set(fields) - known)
            observation["acknowledgement_unexpected_member_count"] = len(set(fields) - _ACK_FIELDS)
            method = "DELETE" if direction == "recover" else "POST"
            fixed: dict[str, object] = {"version": "v7.0.0", "build": 29, "http_method": method,
                "http_status": 200, "path": "secret", "name": "client-software", "vdom": "root"}
            observation["missing_fixed_members"] = sorted(set(fixed) - set(fields))
            observation["fixed_constant_matches"] = {
                key: raw[slice(*fields[key])] == json.dumps(value).encode() for key, value in fixed.items() if key in fields}
            observation["known_diagnostic_empty"] = {
                key: raw[slice(*fields[key])] == b'""' for key in ("cli_error", "message", "msg") if key in fields}
            observation["optional_binding_matches"] = {
                "mkey": "mkey" not in fields or raw[slice(*fields["mkey"])] == json.dumps(self._binding.software_name).encode(),
                "action": "action" not in fields or raw[slice(*fields["action"])] == b'""'}
            serial_matches = "serial" not in fields
            if "serial" in fields and raw[fields["serial"][0]] == 34:
                serial = json.loads(raw[slice(*fields["serial"])])
                serial_matches = isinstance(serial, str) and hashlib.sha256(serial.encode()).hexdigest() == self._binding.device_identity_digest
            observation["serial_matches_bound_device"] = serial_matches
            if "status" in fields:
                token = raw[slice(*fields["status"])]
                observation["declared_success"] = token == b'"success"' or token == b'"OK"'
                observation["declared_failure"] = token == b'"error"'
            if "error" in fields:
                token = raw[slice(*fields["error"])]
                if re.fullmatch(rb"-?(?:0|[1-9][0-9]{0,5})", token):
                    observation["business_error_code"] = int(token)
            self._acknowledgement(raw, method)
            observation["strict_acknowledgement_verified"] = True
        except Exception:
            pass
        self._save(direction + ".response.json", self._record(direction, "response_observed", **observation))

    def _acknowledgement(self, raw: bytearray, method: str) -> None:
        fields = self._spans(raw)
        if method not in {"POST", "DELETE"} or not set(fields) <= _ACK_FIELDS:
            raise ValueError
        acknowledgement = self._envelope(raw, method)
        for key in ("revision", "old_revision"):
            if key in acknowledgement:
                value = acknowledgement[key]
                if (not isinstance(value, str) or len(value) > 255
                        or any(ord(character) < 32 or ord(character) == 127 for character in value)):
                    raise ValueError
        if "revision_changed" in acknowledgement and acknowledgement["revision_changed"] is not True:
            raise ValueError
        if "mkey" in acknowledgement and acknowledgement["mkey"] != self._binding.software_name:
            raise ValueError
        if "serial" in acknowledgement and (not isinstance(acknowledgement["serial"], str)
                or hashlib.sha256(acknowledgement["serial"].encode()).hexdigest() != self._binding.device_identity_digest):
            raise ValueError

    @staticmethod
    def _spans(raw: bytearray) -> dict[str, tuple[int, int]]:
        start = _skip_json_space(raw, 0); end = _json_value_end(raw, start)
        if _skip_json_space(raw, end) != len(raw):
            raise ValueError
        return _object_spans(raw, start, end)

    @classmethod
    def _envelope(cls, raw: bytearray, method: str = "GET", *, action: str = "",
                  http_status: int = 200) -> dict[str, Any]:
        spans = cls._spans(raw)
        allowed = {"version", "build", "http_method", "http_status", "status", "path", "name", "vdom",
                "serial", "revision", "revision_changed", "mkey", "results", "matched_count", "size", "next_idx", "limit_reached", "action", "error"}
        if method in {"POST", "DELETE"}:
            allowed.add("old_revision")
        if not set(spans) <= allowed:
            raise ValueError
        payload = {key: json.loads(raw[left:right]) for key, (left, right) in spans.items() if key != "results"}
        fixed = {"version": "v7.0.0", "build": 29, "http_method": method,
                 "http_status": http_status, "path": "secret", "name": "client-software", "vdom": "root"}
        if (any(type(payload.get(k)) is not type(v) or payload[k] != v for k, v in fixed.items())
                or payload.get("status") not in ({"error"} if http_status == 404 else {"success", "OK"})
                or "action" in payload and payload["action"] != action
                or "error" in payload and (type(payload["error"]) is not int
                    or (payload["error"] >= 0 if http_status == 404 else payload["error"] != 0))):
            raise ValueError
        return payload

    @staticmethod
    def _rows(raw: bytearray, left: int, right: int) -> list[tuple[int, int]]:
        if raw[left] != 91 or raw[right - 1] != 93:
            raise ValueError
        cursor = _skip_json_space(raw, left + 1)
        rows: list[tuple[int, int]] = []
        while cursor < right - 1:
            if raw[cursor] != 123 or len(rows) >= 200:
                raise ValueError
            end = _json_value_end(raw, cursor); rows.append((cursor, end)); cursor = _skip_json_space(raw, end)
            if cursor == right - 1:
                break
            if raw[cursor] != 44:
                raise ValueError
            cursor = _skip_json_space(raw, cursor + 1)
            if cursor == right - 1:
                raise ValueError
        return rows

    def _collection(self, raw: bytearray) -> tuple[dict[str, str], tuple[int, int] | None]:
        envelope = self._envelope(raw); spans = self._spans(raw)
        rows = self._rows(raw, *spans["results"])
        if (len(rows) >= 200 or any(type(envelope.get(k)) is not int or envelope[k] != len(rows) for k in ("matched_count", "size"))
                or type(envelope.get("next_idx")) is not int or envelope["next_idx"] != len(rows) - 1
                or "limit_reached" in envelope and envelope["limit_reached"] is not False):
            raise ValueError
        witnesses = {}; selected = None
        for left, right in rows:
            members = _object_spans(raw, left, right)
            name = json.loads(raw[slice(*members["name"])])
            if not isinstance(name, str) or not name or len(name) > 79 or name in witnesses:
                raise ValueError
            witnesses[name] = hashlib.sha256(raw[left:right]).hexdigest()
            if name == self._binding.software_name:
                selected = (left, right)
        return witnesses, selected

    def _project(self, raw: bytearray, bounds: tuple[int, int]) -> dict[str, Any]:
        left, right = bounds; members = _object_spans(raw, left, right)
        metadata = _native_metadata(self._binding.object_type)
        if (not set(members) <= {"name", "pkg", "q_origin_key", "q_ref", "q_static", *metadata}
                or not set(metadata) <= set(members)):
            raise ValueError
        for key, value in metadata.items():
            current = json.loads(raw[slice(*members[key])])
            if type(current) is not type(value) or current != value:
                raise ValueError
        packages = self._rows(raw, *members["pkg"])
        if len(packages) != 1:
            raise ValueError
        package = _object_spans(raw, *packages[0])
        if set(package) != {*_package(), "q_origin_key", "client-name", "description", "file-size",
                            "package-content", "state", "uuid"}:
            raise ValueError
        if raw[slice(*package["package-content"])] != b'""':
            raise ValueError
        payload = self._envelope(raw)
        payload["results"] = json.loads(raw[left:right])
        return payload

    def _certificate(self, raw: bytearray) -> str:
        spans = self._spans(raw)
        metadata = {k: json.loads(raw[slice(*spans[k])]) for k in ("version", "build", "http_method", "http_status", "status")}
        if metadata != {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200, "status": "success"} or type(metadata["build"]) is not int:
            raise ValueError
        left, right = spans["results"]
        if raw[left] == 91:
            rows = self._rows(raw, left, right)
            if len(rows) != 1:
                raise ValueError
            left, right = rows[0]
        fields = _object_spans(raw, left, right)
        name = json.loads(raw[slice(*fields["name"])])
        if name != CERTIFICATE_NAME:
            raise ValueError
        # Name-selector metadata only; certificate/key material is never decoded.
        return _digest({"name": name, "type": "local-ca"})

    def _native_ca_selector(self, raw: bytearray) -> None:
        """Require the fixed local CA to satisfy the native editor's type filter."""
        left, right = _monitor_results(raw, expected_route="system/available-certificates")
        rows = self._rows(raw, left, right)
        if len(rows) >= 200:
            raise ValueError
        matches = 0
        for bounds in rows:
            fields = _object_spans(raw, *bounds)
            name = json.loads(raw[slice(*fields["name"])])
            if not isinstance(name, str) or not name or len(name) > 79:
                raise ValueError
            if name == CERTIFICATE_NAME:
                if json.loads(raw[slice(*fields["type"])]) != "local-ca":
                    raise ValueError
                matches += 1
        if matches != 1:
            raise ValueError

    def _object_type(self, raw: bytearray) -> int:
        left, right = _monitor_results(raw, expected_route="web-ui/object-urls")
        mapping = json.loads(raw[left:right])["by_type"]
        if not isinstance(mapping, dict):
            raise ValueError
        matches = [k for k, v in mapping.items() if isinstance(v, dict) and v.get("path") == "secret.client-software"]
        if len(matches) != 1 or re.fullmatch(r"0|[1-9][0-9]{0,8}", matches[0]) is None:
            raise ValueError
        return int(matches[0])

    def _readback(self, payload: object) -> NativeClientIntegrityReadback:
        if isinstance(self._binding, NativeHashClientIntegrityBinding):
            return project_native_client_integrity_hash_detail(
                payload, software_name=self._binding.software_name,
                executable_sha256=self._binding.executable_sha256,
            )
        return project_native_client_integrity_detail(payload, software_name=self._binding.software_name)

    def _snapshot(self, recovery: bool) -> tuple[dict[str, object], str | None]:
        buffers: list[bytearray] = []
        def read(path: str, *, expected_status: int = 200) -> bytearray:
            raw = self._request("GET", path, expected_status=expected_status); buffers.append(raw); return raw
        try:
            defaults = read(_PATH + "?action=default&with_meta=true&vdom=root")
            payload = self._envelope(defaults, action="default"); spans = self._spans(defaults)
            if set(_object_spans(defaults, *spans["results"])) != {"name", "pkg"}:
                raise ValueError
            payload["results"] = json.loads(defaults[slice(*spans["results"])])
            serial = payload.get("serial")
            if (not isinstance(serial, str) or not re.fullmatch(r"[A-Za-z0-9-]{8,64}", serial)
                    or hashlib.sha256(serial.encode()).hexdigest() != self._binding.device_identity_digest):
                raise ValueError
            if isinstance(self._binding, NativeHashClientIntegrityBinding):
                body = compile_native_client_integrity_hash_create_body(
                    payload, software_name=self._binding.software_name,
                    executable_sha256=self._binding.executable_sha256,
                )
            else:
                body = compile_native_client_integrity_create_body(payload, software_name=self._binding.software_name)
                if self._certificate(read(_CERT)) != self._binding.certificate_metadata_digest:
                    raise ValueError
                self._native_ca_selector(read(_AVAILABLE_CERTIFICATES))
            collection = read(_PATH + "?count=200&start=0&with_meta=true&vdom=root")
            rows, selected = self._collection(collection)
            if recovery != (selected is not None):
                raise ValueError
            configuration = None
            if selected is not None:
                detail = self._project(collection, selected)
                configuration = self._readback(detail).configuration_digest
                direct = read(self._detail); direct_spans = self._spans(direct); left, right = direct_spans["results"]
                if direct[left] == 91:
                    records = self._rows(direct, left, right)
                    if len(records) != 1:
                        raise ValueError
                    left, right = records[0]
                projected = self._project(direct, (left, right))
                if self._readback(projected).configuration_digest != configuration:
                    raise ValueError
                if self._object_type(read(_TYPES)) != self._binding.object_type:
                    raise ValueError
                query = urlencode({"mkey": self._binding.software_name, "qtypes": json.dumps([self._binding.object_type], separators=(",", ":"))})
                usage = read(_USAGE + "?" + query)
                if isinstance(self._binding, NativeHashClientIntegrityBinding):
                    validate_native_client_integrity_hash_recovery_state(
                        projected, usage, software_name=self._binding.software_name,
                        executable_sha256=self._binding.executable_sha256,
                        expected_configuration_digest=configuration,
                    )
                else:
                    validate_native_client_integrity_recovery_state(
                        projected, usage, software_name=self._binding.software_name,
                        expected_configuration_digest=configuration,
                    )
                del rows[self._binding.software_name]
            else:
                absence_raw = read(self._detail, expected_status=404)
                absent = self._envelope(absence_raw, http_status=404)
                absence_spans = self._spans(absence_raw)
                if "results" in absence_spans:
                    left, right = absence_spans["results"]
                    if absence_raw[left] == 123:
                        if _object_spans(absence_raw, left, right):
                            raise ValueError
                    elif absence_raw[left] == 91:
                        if self._rows(absence_raw, left, right):
                            raise ValueError
                    elif absence_raw[left:right] != b"null":
                        raise ValueError
                absent_serial = absent.get("serial")
                if (not isinstance(absent_serial, str)
                        or hashlib.sha256(absent_serial.encode()).hexdigest() != self._binding.device_identity_digest
                        or "mkey" in absent and absent["mkey"] != self._binding.software_name):
                    raise ValueError
            if _digest(rows) != self._binding.visible_collection_digest:
                raise ValueError
            return body, configuration
        finally:
            for raw in buffers:
                _zeroize_mutable(raw)

    def inspect(self, *, recovery: bool = False) -> dict[str, bool]:
        try:
            if type(recovery) is not bool:
                raise ValueError
            direction = "recover" if recovery else "create"
            if os.path.lexists(self._state / (direction + ".claim.json")):
                raise ValueError
            if recovery:
                self._load("create.claim.json", "create", "reserved")
                verified = self._load("create.verified.json", "create", "verified")
            elif any(os.path.lexists(self._state / k) for k in ("create.verified.json", "recover.intent.json", "recover.claim.json")):
                raise ValueError
            _, configuration = self._snapshot(recovery)
            if recovery and configuration != verified.get("configuration_digest"):
                raise ValueError
            return {"fixed_native_profile_verified": True, "visible_collection_preserved": True,
                    "reported_usage_empty": recovery, "verified_creation_required": recovery,
                    "device_write_executed": False}
        except Exception:
            raise ClientIntegrityHttpTransportError(_UNAVAILABLE) from None

    def execute(self, *, recovery: bool = False) -> dict[str, bool]:
        try:
            if type(recovery) is not bool:
                raise ValueError
            direction = "recover" if recovery else "create"
            self._guard(direction)
            self.inspect(recovery=recovery)
            body, _ = self._snapshot(recovery)
            self._guard(direction)
            self._save(direction + ".claim.json", self._record(direction, "reserved"))
            method = "DELETE" if recovery else "POST"
            path = _PATH + "/" + quote(self._binding.software_name, safe="") + "?vdom=root" if recovery else _PATH + "?vdom=root"
            raw = self._request(method, path, body=None if recovery else body, direction=direction)
            try:
                self._acknowledgement(raw, method)
            finally:
                _zeroize_mutable(raw)
            _, configuration = self._snapshot(not recovery)
            self._save(direction + ".verified.json", self._record(direction, "verified", configuration_digest=configuration))
            return {"verified": True, "software_present": not recovery,
                    "visible_collection_preserved": True, "upload_or_download_dispatched": False}
        except Exception:
            raise ClientIntegrityHttpTransportError(_UNAVAILABLE) from None
