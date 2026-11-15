"""Fixed read-only existing-Target window for a service credential proposal.

Keep configuration and runtime representations distinct. The exact Bearer actor
brackets two full configuration reads and two native exact-name filtered reads.
This entry supplies no Target ownership, Secret association, activity or write
authority, and cannot resume an old owned-Target execution profile.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
import hashlib
import hmac
import ipaddress
import json
import math
from pathlib import Path
import ssl
from threading import RLock
import time
from urllib.parse import quote, urlsplit

import httpx
from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as m
from . import target_preservation_contract as c
from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space, _zeroize_mutable,
)
from .target_api_dependency_reader import _private_http_logs
from .target_lifecycle_dependencies import _one, _spans
from .windows_privileged_secret_contract import _SELECTOR
from .windows_service_credential_contract import WindowsServiceCredentialBinding

_CONTRACT = "fortipam-build29-service-credential-existing-target-source-v1"
_ERROR = "The private service credential Target source is unavailable."
_ACTOR = "/api/v2/monitor/web-ui/state"
_TARGET = "/api/v2/cmdb/secret/target"
_RUNTIME = _TARGET + "?format=name%7Caddress%7Cpermissions%7Cpriv_acct&with_meta=true&vdom=root"
_MAX_BYTES = 262144
_PAGING = frozenset({"has_more", "next_index", "offset", "start", "limit", "total", "total_count"})


class WindowsServiceCredentialTargetSourceError(ValueError):
    """No selector, identity, response or partial admission in errors."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceCredentialTargetObservation(_OpaqueC3Object):
    source_context_digest: str
    target_reference_context_digest: str
    actor_context_digest: str
    configuration: c.TargetState
    runtime_digest: str
    runtime_field_count: int
    observed_at: float
    expires_at: float


class WindowsServiceCredentialTargetSources(_OpaqueC3Object):
    """One six-read window, with no unfiltered collection or configuration IO."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, *, target_name: str,
            target_address: str, serial_digest: str, expected_actor_context_digest: str,
            clock: Callable[[], float] = time.monotonic,
            client_factory: Callable[..., httpx.Client] = httpx.Client) -> None:
        try:
            if type(config) is not SecretMetadataHttpTransportConfig:
                raise ValueError
            config.__post_init__()
            require_digest(serial_digest, "service_target_serial")
            require_digest(expected_actor_context_digest, "service_target_actor")
            if (type(target_name) is not str or _SELECTOR.fullmatch(target_name) is None
                    or target_name != target_name.strip() or target_name.startswith("MCPV4WinTarget")
                    or target_name in {".", ".."} or any(char in target_name for char in "/\\?#")
                    or len(target_name.encode()) > 127 or not callable(clock) or not callable(client_factory)):
                raise ValueError
            address = ipaddress.IPv4Address(target_address)
            if (str(address) != target_address or address.is_loopback or address.is_unspecified
                    or address.is_multicast or address.is_link_local):
                raise ValueError
            url = urlsplit(config.base_url)
            if not url.hostname or url.username is not None or url.password is not None:
                raise ValueError
            self._config, self._serial = config, serial_digest
            self._name, self._address, self._actor = target_name, target_address, expected_actor_context_digest
            self._clock, self._factory = clock, client_factory
            self._source = self._source_digest()
            ca = self._ca()
            self._tls = ssl.create_default_context(cadata=ca.decode("ascii")) if ca is not None else ssl.create_default_context()
            self._tls.minimum_version = ssl.TLSVersion.TLSv1_2
            self._detail = _TARGET + "/" + quote(target_name, safe="") + "?with_meta=true&vdom=root"
            self._body = json.dumps({"json_filter": [{"logic": "or", "filters": [{
                "key": "name", "type": "string", "operator": "exact", "negate": False,
                "pattern": target_name}]}]}, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            self._binding = self._context()
            self._identities = (clock, client_factory, self._tls)
            self._used = self._closed = self._failed = False
            self._last = 0.0
            self._deadline: float | None = None
            self._current: WindowsServiceCredentialTargetObservation | None = None
            self._seal: str | None = None
            self._lock = RLock()
            self._guard()
        except Exception:
            raise WindowsServiceCredentialTargetSourceError(_ERROR) from None

    def _ca(self) -> bytes | None:
        if self._config.ca_file is None:
            return None
        with Path(self._config.ca_file).open("rb") as stream:
            value = stream.read(1048577)
        if not 0 < len(value) <= 1048576:
            raise ValueError
        return value

    def _source_digest(self) -> str:
        self._config.__post_init__()
        ca = self._ca()
        return c._api_source_context(self._config.base_url,
            hashlib.sha256(self._config.bearer_token.encode()).hexdigest(),
            hashlib.sha256(ca).hexdigest() if ca is not None else None, self._serial)

    def _context(self) -> str:
        return canonical_digest({"contract": _CONTRACT, "source": self._source,
            "name": self._name, "address": self._address, "actor": self._actor,
            "detail": hashlib.sha256(self._detail.encode()).hexdigest(),
            "runtime": hashlib.sha256(_RUNTIME.encode()).hexdigest(),
            "filter": hashlib.sha256(self._body).hexdigest(), "timeout": str(self._config.timeout_seconds)})

    def _now(self) -> float:
        value = self._clock()
        if (type(value) not in (int, float) or not math.isfinite(value) or value < self._last
                or self._deadline is not None and value >= self._deadline):
            raise ValueError
        self._last = float(value)
        return self._last

    def _guard(self) -> float:
        if (self._closed or self._failed or self._source_digest() != self._source
                or self._context() != self._binding
                or any(a is not b for a, b in zip(self._identities, (self._clock, self._factory, self._tls)))
                or not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2):
            raise ValueError
        return self._now()

    def _receive(self, client: httpx.Client, path: str) -> bytearray:
        raw = bytearray()
        transfer = False
        try:
            if path not in (_ACTOR, self._detail, _RUNTIME) or self._deadline is None:
                raise ValueError
            now = self._guard()
            headers = {"Authorization": "Bearer " + self._config.bearer_token,
                "Accept": "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-store"}
            filtered = path == _RUNTIME
            if filtered:
                headers.update({"X-HTTP-Method-Override": "GET", "Content-Type": "application/json"})
            client.cookies.clear()
            with client.stream("POST" if filtered else "GET", self._config.base_url.rstrip("/") + path,
                    headers=headers, content=self._body if filtered else None,
                    timeout=min(float(self._config.timeout_seconds), self._deadline - now)) as response:
                self._guard()
                length_headers = response.headers.get_list("content-length")
                if (response.status_code != 200
                        or response.headers.get("content-type", "").split(";")[0].lower() != "application/json"
                        or response.headers.get("content-encoding", "identity") not in ("", "identity")
                        or len(length_headers) > 1
                        or length_headers and (not length_headers[0].isascii() or not length_headers[0].isdigit())
                        or length_headers and "transfer-encoding" in response.headers):
                    raise ValueError
                expected_length = int(length_headers[0]) if length_headers else None
                if expected_length is not None and not 0 < expected_length <= _MAX_BYTES:
                    raise ValueError
                iterator = response.iter_raw()
                while True:
                    self._guard()
                    try:
                        chunk = next(iterator)
                    except StopIteration:
                        self._guard()
                        break
                    self._guard()
                    if len(raw) + len(chunk) > _MAX_BYTES:
                        raise ValueError
                    raw.extend(chunk)
                if expected_length is not None and len(raw) != expected_length:
                    raise ValueError
            client.cookies.clear()
            self._guard()
            _spans(raw)
            transfer = True
            return raw
        finally:
            if not transfer:
                _zeroize_mutable(raw)

    def _envelope(self, raw: bytearray, *, runtime: bool = False, actor: bool = False) -> dict[str, tuple[int, int]]:
        _spans(raw)
        start = _skip_json_space(raw, 0)
        fields = _object_spans(raw, start, _json_value_end(raw, start))
        expected: dict[str, object] = dict(version="v7.0.0", build=29,
            path="web-ui" if actor else "secret", name="state" if actor else "target",
            http_method="POST" if runtime else "GET", status="OK" if runtime else "success")
        if not actor or "http_status" in fields:
            expected["http_status"] = 200
        if not actor or "vdom" in fields:
            expected["vdom"] = "root"
        for name, value in expected.items():
            actual = m._scalar(raw, fields[name])
            if type(actual) is not type(value) or actual != value:
                raise ValueError
        serial = m._text(m._scalar(raw, fields["serial"]), maximum=128)
        if not hmac.compare_digest(hashlib.sha256(serial.encode()).hexdigest(), self._serial):
            raise ValueError
        if "schema_errors" in fields or _PAGING & fields.keys():
            raise ValueError
        if not actor and "mkey" in fields and m._scalar(raw, fields["mkey"]) != self._name:
            raise ValueError
        if "action" in fields and m._scalar(raw, fields["action"]) != "":
            raise ValueError
        if "error" in fields:
            error = m._scalar(raw, fields["error"])
            if error is not None and (type(error) is not int or error != 0):
                raise ValueError
        if "limit_reached" in fields and m._scalar(raw, fields["limit_reached"]) is not False:
            raise ValueError
        for name in ("size", "matched_count", "filtered_count", "next_idx"):
            if name in fields:
                value = m._scalar(raw, fields[name])
                if type(value) is not int or value not in ((0, 1) if name == "next_idx" else (1,)):
                    raise ValueError
        return fields

    def _read_actor(self, raw: bytearray) -> str:
        top = self._envelope(raw, actor=True)
        root = _object_spans(raw, *top["results"])
        admin = _object_spans(raw, *root["admin"])
        name = m._text(m._scalar(raw, admin["name"]), maximum=128)
        profile = _object_spans(raw, *admin["profile"])
        m._text(m._scalar(raw, profile["name"]), maximum=128)
        maintenance = _object_spans(raw, *root["maintenance_mode"])
        if (m._scalar(raw, admin["global_admin"]) is not True
                or m._scalar(raw, root["vdom_mode"]) != ""
                or m._scalar(raw, maintenance["mode"]) != "disable"):
            raise ValueError
        identity = _actor_context(raw, expected_name=name)
        if not hmac.compare_digest(identity, self._actor):
            raise ValueError
        return canonical_digest((identity, c._token_digest(raw, admin["profile"])))

    def _read_configuration(self, raw: bytearray) -> c.TargetState:
        top = self._envelope(raw)
        row = _object_spans(raw, *_one(raw, top["results"]))
        if (m._scalar(raw, row["address"]) != self._address
                or m._scalar(raw, row["domain"]) != "" or m._scalar(raw, row["url"]) != ""):
            raise ValueError
        return c.capture_target_state(raw, expected_name=self._name, expected_serial_digest=self._serial)

    def _read_runtime(self, raw: bytearray, configuration: c.TargetState) -> tuple[str, int]:
        top = self._envelope(raw, runtime=True)
        rows = m._array(raw, top["results"], 1)
        if len(rows) != 1:
            raise ValueError
        row = _object_spans(raw, *rows[0])
        expected = {"name": self._name, "address": self._address, "domain": "", "url": "",
            "template": configuration.coordinates.template, "is_service_addr": False, "priv_acct": 0}
        for name, value in expected.items():
            actual = m._scalar(raw, row[name])
            if type(actual) is not type(value) or actual != value:
                raise ValueError
        permissions = _object_spans(raw, *row["permissions"])
        if m._scalar(raw, permissions["user"]) != "owner":
            raise ValueError
        return c._digest(tuple((name, c._token_digest(raw, row[name])) for name in sorted(row))), len(row)

    def read_once(self) -> WindowsServiceCredentialTargetObservation:
        buffers: list[bytearray] = []
        try:
            with self._lock:
                started = self._guard()
                if self._used:
                    raise ValueError
                self._used = True
                self._deadline = started + 30.0
                with _private_http_logs(), self._factory(verify=self._tls,
                        follow_redirects=False, trust_env=False) as client:
                    def read(path: str) -> bytearray:
                        value = self._receive(client, path)
                        buffers.append(value)
                        return value
                    actor = self._read_actor(read(_ACTOR))
                    configuration = self._read_configuration(read(self._detail))
                    runtime, count = self._read_runtime(read(_RUNTIME), configuration)
                    if self._read_runtime(read(_RUNTIME), configuration) != (runtime, count):
                        raise ValueError
                    if self._read_configuration(read(self._detail)) != configuration:
                        raise ValueError
                    if self._read_actor(read(_ACTOR)) != actor:
                        raise ValueError
                self._guard()
                context = canonical_digest({"binding": self._binding, "actor": actor,
                    "configuration": configuration.state_digest, "runtime": runtime})
                observed = WindowsServiceCredentialTargetObservation(self._source, context, actor,
                    configuration, runtime, count, started, self._deadline)
                self._current, self._seal = observed, c._digest(asdict(observed))
                return observed
        except BaseException as error:
            self._failed, self._current, self._seal = True, None, None
            if isinstance(error, Exception):
                raise WindowsServiceCredentialTargetSourceError(_ERROR) from None
            raise
        finally:
            for raw in buffers:
                _zeroize_mutable(raw)

    def check_current(self, observation: WindowsServiceCredentialTargetObservation) -> None:
        try:
            with self._lock:
                now = self._guard()
                if (type(observation) is not WindowsServiceCredentialTargetObservation
                        or observation is not self._current
                        or self._seal != c._digest(asdict(observation))
                        or not observation.observed_at <= now < observation.expires_at):
                    raise ValueError
        except Exception:
            self._failed, self._current, self._seal = True, None, None
            raise WindowsServiceCredentialTargetSourceError(_ERROR) from None

    def check_profile(self, observation: WindowsServiceCredentialTargetObservation,
            profile: WindowsServiceCredentialBinding) -> None:
        try:
            self.check_current(observation)
            if type(profile) is not WindowsServiceCredentialBinding:
                raise ValueError
            profile.__post_init__()
            if (profile.serial_digest != self._serial or profile.target_name != self._name
                    or profile.target_address != self._address
                    or profile.target_reference_context_digest != observation.target_reference_context_digest):
                raise ValueError
        except Exception:
            self._failed, self._current, self._seal = True, None, None
            raise WindowsServiceCredentialTargetSourceError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current, self._seal = None, None
