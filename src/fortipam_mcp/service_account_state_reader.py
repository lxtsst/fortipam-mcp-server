"""One private fixed eight-GET build29 state observation, never write authority.

The trusted composition supplies protected source credentials and an eligible
selection. This reader cannot establish original ownership, least privilege,
credential preservation, service effects or recovery. No login/material/action
route, arbitrary request interface or MCP registration is provided.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import math
from pathlib import Path
import re
import ssl
from threading import RLock
import time
from urllib.parse import quote, urlsplit

import httpx

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as m
from .local_user_reset_fixture_preflight import _actor_context
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _redact_json_field_values,
    _skip_json_space, _zeroize_mutable,
)
from .service_account_state_projection import (
    ServiceAccountStateBinding, ServiceAccountStateProjection, _ENVELOPE, _exact,
    consume_service_account_state,
)
from .target_api_dependency_reader import _private_http_logs
from .target_lifecycle_dependencies import _envelope, _spans
from .target_preservation_contract import _api_source_context, _digest

CONTRACT = "fortipam-build29-service-account-state-reader-private-v1"
_ERROR = "The private service-account state source is unavailable."
_ACTOR = "/api/v2/monitor/web-ui/state"
_PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}\Z")
_TTL = 30.0


class ServiceAccountStateReadError(ValueError):
    """Fixed value-free refusal; partial source results are never returned."""


@dataclass(frozen=True, slots=True, repr=False)
class ServiceAccountStateObservation(_OpaqueC3Object):
    projection: ServiceAccountStateProjection
    source_context_digest: str
    observed_at: float
    expires_at: float


def _observation_seal(observation: ServiceAccountStateObservation) -> str:
    state = observation.projection
    if type(state) is not ServiceAccountStateProjection:
        raise ValueError
    return _digest((CONTRACT, observation.source_context_digest, observation.observed_at,
        observation.expires_at, state.dependency_count, state.dependency_digest,
        state.target_state_digest, state.updater_state_digest, state.relation_digest,
        state.bounded_windows_service_profile))


def _selection(binding: ServiceAccountStateBinding) -> tuple[object, ...]:
    binding.__post_init__()
    return (binding.secret_id, binding.secret_name, binding.secret_uuid,
        binding.dependency_id, binding.target_name, binding.updater_name,
        binding.serial_digest, binding.source_context_digest)


def _paths(binding: ServiceAccountStateBinding) -> tuple[str, str, str]:
    for name in (binding.target_name, binding.updater_name):
        m._text(name, maximum=79)
        if name in {".", ".."} or any(char in name for char in "/\\?#%"):
            raise ValueError
    secret = ("/api/v2/cmdb/secret/database/" + str(binding.secret_id) +
        "?format=id%7Cname%7Cuuid%7Cdependency&with_meta=true&vdom=root")
    return (secret, "/api/v2/cmdb/secret/target/" + quote(binding.target_name, safe="") +
        "?with_meta=true&vdom=root", "/api/v2/cmdb/secret/dependency-updater/" +
        quote(binding.updater_name, safe="") + "?with_meta=true&vdom=root")


def _ca(config: SecretMetadataHttpTransportConfig) -> bytes | None:
    if config.ca_file is None:
        return None
    with Path(config.ca_file).open("rb") as stream:
        value = stream.read(1_048_577)
    if not 0 < len(value) <= 1_048_576:
        raise ValueError
    return value


class ServiceAccountStateReader(_OpaqueC3Object):
    """One attempt/one client; source guards do not confer dispatch authority."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, *,
            binding: ServiceAccountStateBinding, actor_name: str, actor_profile: str,
            witness_key: bytes, clock: Callable[[], float] = time.monotonic,
            client_factory: Callable[..., httpx.Client] = httpx.Client) -> None:
        self._key = bytearray()
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                    or type(binding) is not ServiceAccountStateBinding
                    or any(type(value) is not str or _PRINCIPAL.fullmatch(value) is None
                           for value in (actor_name, actor_profile))
                    or type(witness_key) is not bytes or len(witness_key) != 32
                    or not callable(clock) or not callable(client_factory)):
                raise ValueError
            config.__post_init__()
            parsed = urlsplit(config.base_url)
            if (not parsed.hostname or parsed.username is not None or parsed.password is not None
                    or type(config.timeout_seconds) not in (int, float)
                    or not math.isfinite(config.timeout_seconds)):
                raise ValueError
            ca = _ca(config)
            self._tls = ssl.create_default_context() if ca is None else ssl.create_default_context(cadata=ca.decode("ascii"))
            self._tls.minimum_version = ssl.TLSVersion.TLSv1_2
            self._config, self._binding = config, binding
            self._actor_name, self._actor_profile = actor_name, actor_profile
            self._clock, self._factory = clock, client_factory
            self._key.extend(witness_key)
            self._routes = _paths(binding)
            self._identities = (config, binding, clock, client_factory, self._tls)
            self._source = self._context()
            self._last = -1.0
            self._started = self._failed = self._closed = False
            self._current: ServiceAccountStateObservation | None = None
            self._seal: str | None = None
            self._lock = RLock()
        except Exception:
            _zeroize_mutable(self._key)
            raise ServiceAccountStateReadError(_ERROR) from None

    def _context(self) -> str:
        if (any(current is not pinned for current, pinned in zip(
                (self._config, self._binding, self._clock, self._factory, self._tls), self._identities, strict=True))
                or type(self._config) is not SecretMetadataHttpTransportConfig
                or type(self._binding) is not ServiceAccountStateBinding
                or type(self._key) is not bytearray or len(self._key) != 32
                or not self._tls.check_hostname or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version != ssl.TLSVersion.TLSv1_2
                or self._routes != _paths(self._binding)):
            raise ValueError
        self._config.__post_init__()
        ca = _ca(self._config)
        api = _api_source_context(self._config.base_url,
            hashlib.sha256(self._config.bearer_token.encode()).hexdigest(),
            None if ca is None else hashlib.sha256(ca).hexdigest(), self._binding.serial_digest)
        return _digest((CONTRACT, api, self._config.timeout_seconds, self._config.ca_file,
            _selection(self._binding), self._routes, self._actor_name, self._actor_profile,
            hashlib.sha256(self._key).hexdigest(), "eight-get-global-root-metadata-only"))

    def _now(self) -> float:
        value = self._clock()
        if (self._closed or self._failed or type(value) not in (int, float)
                or not math.isfinite(value) or value < 0 or value < self._last
                or self._context() != self._source):
            raise ValueError
        self._last = float(value)
        return float(value)

    def _remaining(self, deadline: float) -> float:
        remaining = deadline - self._now()
        if remaining <= 0:
            raise ValueError
        return min(10.0, float(self._config.timeout_seconds), remaining)

    def _get(self, client: httpx.Client, path: str, deadline: float) -> bytearray:
        raw = bytearray()
        try:
            if path not in (_ACTOR, *self._routes):
                raise ValueError
            headers = {"Accept": "application/json", "Accept-Encoding": "identity",
                "Cache-Control": "no-cache, no-store", "Authorization": "Bearer " + self._config.bearer_token}
            with client.stream("GET", self._config.base_url.rstrip("/") + path,
                    headers=headers, timeout=self._remaining(deadline)) as response:
                self._remaining(deadline)
                if (response.status_code != 200
                        or response.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json"
                        or response.headers.get("content-encoding", "identity").strip().lower() not in ("", "identity")):
                    raise ValueError
                iterator = response.iter_raw()
                while True:
                    self._remaining(deadline)
                    try:
                        chunk = next(iterator)
                    except StopIteration:
                        self._remaining(deadline)
                        break
                    self._remaining(deadline)
                    if len(raw) + len(chunk) > m._MAX_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            self._remaining(deadline)
            if path == self._routes[0]:
                _redact_json_field_values(raw)
            _spans(raw)
            result, raw = raw, bytearray()
            return result
        finally:
            _zeroize_mutable(raw)

    def _actor(self, raw: bytearray) -> str:
        span = _envelope(raw, path="web-ui", name="state",
            serial_digest=self._binding.serial_digest, monitor=True)
        envelope = _spans(raw)
        start = _skip_json_space(raw, 0)
        _exact(raw, (start, _json_value_end(raw, start)), frozenset({"serial", "results"}), _ENVELOPE)
        if "action" in envelope:
            raise ValueError
        serial = m._text(m._scalar(raw, envelope["serial"]), maximum=128)
        if hashlib.sha256(serial.encode()).hexdigest() != self._binding.serial_digest:
            raise ValueError
        identity = _actor_context(raw, expected_name=self._actor_name)
        root = m._object_spans(raw, *span, frozenset({"admin", "vdom_mode", "maintenance_mode"}))
        admin = m._object_spans(raw, *root["admin"], frozenset({"profile", "global_admin"}))
        profile = m._object_spans(raw, *admin["profile"], frozenset({"name"}))
        maintenance = m._object_spans(raw, *root["maintenance_mode"], frozenset({"mode"}))
        if (m._scalar(raw, profile["name"]) != self._actor_profile
                or m._scalar(raw, admin["global_admin"]) is not True
                or m._scalar(raw, root["vdom_mode"]) != ""
                or m._scalar(raw, maintenance["mode"]) != "disable"):
            raise ValueError
        return _digest((identity, self._actor_profile, "global", "vdom-disabled", "maintenance-off"))

    def read_once(self) -> ServiceAccountStateObservation:
        buffers: list[bytearray] = []
        client: httpx.Client | None = None
        with self._lock:
            try:
                if self._started:
                    raise ValueError
                self._started = True
                started = self._now()
                deadline = started + _TTL
                with _private_http_logs():
                    client = self._factory(verify=self._tls, follow_redirects=False,
                        trust_env=False, timeout=self._config.timeout_seconds)
                    try:
                        with client:
                            actor = self._get(client, _ACTOR, deadline); buffers.append(actor)
                            actor_digest = self._actor(actor)
                            secret, target, updater = self._routes
                            for route in (secret, target, updater, updater, target, secret):
                                buffers.append(self._get(client, route, deadline))
                            actor = self._get(client, _ACTOR, deadline); buffers.append(actor)
                            if self._actor(actor) != actor_digest:
                                raise ValueError
                    finally:
                        if not client.is_closed:
                            client.close()
                self._remaining(deadline)
                if not client.is_closed:
                    raise ValueError
                source_binding = replace(self._binding, source_context_digest=self._source)
                result = consume_service_account_state(binding=source_binding, witness_key=bytes(self._key),
                    **dict(zip(("secret_before", "target_before", "updater_before", "updater_after",
                        "target_after", "secret_after"), buffers[1:7], strict=True)))
                self._remaining(deadline)
                observed = ServiceAccountStateObservation(result, self._source, started, deadline)
                self._current = observed
                self._seal = _observation_seal(observed)
                return observed
            except Exception:
                self._failed = True
                self._current = None
                self._seal = None
                _zeroize_mutable(self._key)
                raise ServiceAccountStateReadError(_ERROR) from None
            finally:
                for raw in buffers:
                    _zeroize_mutable(raw)

    def check_current(self, observation: ServiceAccountStateObservation) -> None:
        with self._lock:
            try:
                if (type(observation) is not ServiceAccountStateObservation or observation is not self._current
                        or observation.source_context_digest != self._source
                        or _observation_seal(observation) != self._seal
                        or not observation.observed_at <= self._now() < observation.expires_at):
                    raise ValueError
            except Exception:
                self._failed = True
                self._current = None
                self._seal = None
                _zeroize_mutable(self._key)
                raise ServiceAccountStateReadError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current = None
            self._seal = None
            _zeroize_mutable(self._key)
