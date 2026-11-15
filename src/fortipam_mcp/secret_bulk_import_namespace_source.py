"""Private API-actor and SSH-Owner namespace source; no catalog or grant.

Fresh API actor/Role and enabled local Owner observations bracket the native
database/SSH/database sequence. Names and visible IDs remain opaque metadata;
neither readable records nor global names establish association eligibility.
The SSH Owner's privileges never qualify the separate API actor's permissions.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import http.client
import math
from threading import RLock
import time
from typing import Any
from urllib.parse import quote

import httpx
from v4_planning.material_provider import _OpaqueC3Object

from . import dlp_api_actor_guard as a
from . import secret_bulk_import_metadata as m
from .secret_bulk_import_namespace_reader import (
    ImportSecretNamespaceObservation, SecretBulkImportNamespaceReader,
)
from .secret_bulk_import_reference_reader import _COLLECTION, _QUERY
from .secret_bulk_import_row_actor import _OriginalRowApiActorGuard
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable
from .target_api_dependency_reader import _private_http_logs
from .target_preservation_contract import _api_source_context
from .target_ssh_transport import TargetSshTransportConfig

_ERROR = "Protected bulk-import namespace source unavailable."
_OWNER_FIELDS = frozenset({"name", "accprofile", "status", "remote-auth", "wildcard"})
_OWNER_QUERY = "?format=name%7Caccprofile%7Cstatus%7Cremote-auth%7Cwildcard"
_BODY = b'{"json_filter":[]}'


class BulkImportNamespaceSourceError(ValueError):
    """Fixed non-disclosing refusal without a partial source observation."""


@dataclass(frozen=True, slots=True, repr=False)
class ImportSecretNamespaceSourceObservation(_OpaqueC3Object):
    """One actual Owner's current namespace, not complete import coverage."""

    api_view: m.NativeImportMetadataCollection
    namespace: ImportSecretNamespaceObservation
    source_context_digest: str
    actor_evidence_digest: str
    owner_evidence_digest: str
    ssh_source_digest: str
    serial_digest: str
    observed_at: float
    expires_at: float


class ImportSecretNamespaceSourceReader(_OpaqueC3Object):
    """One fixed source window, with no retry, renewal or caller-selected route."""

    def __init__(self, config: SecretMetadataHttpTransportConfig,
                 ssh_config: TargetSshTransportConfig, actor_binding: a.DlpApiActorGuardBinding, *,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
                 client_factory: Callable[..., httpx.Client] = httpx.Client,
                 clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig or config.ca_file is None
                    or type(ssh_config) is not TargetSshTransportConfig
                    or type(actor_binding) is not a.DlpApiActorGuardBinding
                    or not callable(connection_factory) or not callable(client_factory) or not callable(clock)):
                raise ValueError
            config.__post_init__()
            actor_binding.__post_init__()
            self._config, self._ssh_config, self._binding = config, ssh_config, actor_binding
            self._owner_name = ssh_config.username
            self._factory, self._clock, self._lock = client_factory, clock, RLock()
            self._used = self._closed = self._failed = False
            self._last: float | None = None
            self._started: float | None = None
            self._deadline: float | None = None
            self._namespace: SecretBulkImportNamespaceReader | None = None
            self._current: ImportSecretNamespaceSourceObservation | None = None
            self._actor_pin = (actor_binding.expected_actor, actor_binding.expected_profile,
                actor_binding.expected_serial, actor_binding.expected_role_projection_digest)
            self._ssh_source = self._ssh_snapshot()
            self._guard = _OriginalRowApiActorGuard(config, actor_binding,
                connection_factory=connection_factory, clock=self._now)
            self._source = _api_source_context(config.base_url,
                hashlib.sha256(config.bearer_token.encode()).hexdigest(), self._guard._ca_digest,
                self._guard.serial_digest)
            self._owner_path = "/api/v2/cmdb/system/admin/" + quote(self._owner_name, safe="") + _OWNER_QUERY
            self._require_pins()
        except Exception:
            raise BulkImportNamespaceSourceError(_ERROR) from None

    def _ssh_snapshot(self) -> str:
        config = self._ssh_config
        config.__post_init__()
        if (type(config.port) is not int or type(config.timeout_seconds) not in (int, float)
                or not math.isfinite(config.timeout_seconds)):
            raise ValueError
        with config.known_hosts_file.open("rb") as stream:
            content = stream.read(1048577)
        if not 0 < len(content) <= 1048576:
            raise ValueError
        return a._digest({"host": config.host, "port": config.port, "username": config.username,
            "credential_sha256": hashlib.sha256(config.password.encode()).hexdigest(),
            "known_hosts_path": str(config.known_hosts_file), "known_hosts_sha256": hashlib.sha256(content).hexdigest(),
            "timeout_seconds": config.timeout_seconds})

    def _require_pins(self) -> None:
        self._guard._require_config(self._config)
        binding = self._binding
        if ((binding.expected_actor, binding.expected_profile, binding.expected_serial,
                binding.expected_role_projection_digest) != self._actor_pin
                or self._ssh_config.username != self._owner_name
                or self._ssh_snapshot() != self._ssh_source):
            raise ValueError

    def _now(self) -> float:
        try:
            value = self._clock()
            if (type(value) not in (int, float) or not math.isfinite(value) or value < 0
                    or self._closed or self._failed or self._last is not None and value < self._last
                    or self._deadline is not None and value >= self._deadline):
                raise ValueError
            self._last = float(value)
            return float(value)
        except Exception:
            self._failed = True
            raise BulkImportNamespaceSourceError(_ERROR) from None

    def _remaining(self) -> float:
        now = self._now()
        if self._deadline is None:
            raise ValueError
        return self._deadline - now

    def _fetch(self, client: httpx.Client, *, database: bool) -> bytearray:
        """Only the compiled native database or exact Owner metadata request."""
        raw = bytearray()
        transferred = False
        try:
            self._require_pins()
            headers = {"Authorization": "Bearer " + self._config.bearer_token,
                "Accept": "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-store",
                "User-Agent": "fortipam-mcp-bulk-import-namespace-source/1"}
            if database:
                headers.update({"X-HTTP-Method-Override": "GET", "Content-Type": "application/json"})
            client.cookies.clear()
            with client.stream("POST" if database else "GET", self._config.base_url.rstrip("/")
                    + (_COLLECTION + _QUERY if database else self._owner_path), headers=headers,
                    content=_BODY if database else None, timeout=min(10.0, self._remaining())) as response:
                self._now()
                if (response.status_code != 200
                        or response.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json"
                        or response.headers.get("content-encoding", "identity").strip().lower() != "identity"):
                    raise ValueError
                iterator = response.iter_raw()
                while True:
                    self._now()
                    try:
                        chunk = next(iterator)
                    except StopIteration:
                        self._now()
                        break
                    self._now()
                    if len(raw) + len(chunk) > m._MAX_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            self._require_pins()
            self._now()
            transferred = True
            return raw
        finally:
            if not transferred:
                _zeroize_mutable(raw)

    def _owner(self, client: httpx.Client) -> str:
        raw = self._fetch(client, database=False)
        try:
            row = a._selected_row(raw, "admin", self._owner_name,
                self._binding.expected_serial, _OWNER_FIELDS)
            if row != {"name": self._owner_name, "accprofile": "super_admin",
                    "status": "enable", "remote-auth": "disable", "wildcard": "disable"}:
                raise ValueError
            return a._digest(row)
        finally:
            _zeroize_mutable(raw)

    def _database(self, client: httpx.Client) -> m.NativeImportMetadataCollection:
        raw = self._fetch(client, database=True)
        try:
            return m.project_native_import_metadata(raw, table="database",
                expected_serial_digest=self._guard.serial_digest)
        finally:
            _zeroize_mutable(raw)

    def read_once(self) -> ImportSecretNamespaceSourceObservation:
        with self._lock:
            try:
                if self._used:
                    raise ValueError
                self._used = True
                started = self._now()
                self._started = started
                deadline = started + min(30.0, self._config.timeout_seconds, self._ssh_config.timeout_seconds)
                self._deadline = deadline
                self._require_pins()
                self._guard._observe(completed=False, deadline=deadline)
                with _private_http_logs(), self._factory(verify=self._guard._tls_for_transport(self._config),
                        timeout=min(10.0, self._remaining()), follow_redirects=False, trust_env=False) as client:
                    try:
                        owner = self._owner(client)
                        view = self._database(client)
                        self._require_pins()
                        # Bound the existing SSH reader to this source's remaining window.
                        ssh = replace(self._ssh_config, timeout_seconds=self._remaining())
                        self._namespace = SecretBulkImportNamespaceReader(ssh,
                            serial_digest=self._guard.serial_digest, clock=self._now)
                        namespace = self._namespace.read_namespace(view)
                        self._require_pins()
                        if self._database(client) != view or self._owner(client) != owner:
                            raise ValueError
                    finally:
                        client.cookies.clear()
                if not client.is_closed:
                    raise ValueError
                self._guard._observe(completed=True, deadline=deadline)
                actor = self._guard._before
                if (actor is None or not self._guard._completed
                        or not started <= namespace.observed_at <= self._now() < deadline):
                    raise ValueError
                owner_evidence = a._digest({"contract": "build29-bulk-import-owner-namespace/v2",
                    "api_actor_name": actor.actor, "ssh_owner_name": self._owner_name,
                    "owner_projection": owner, "api_actor": actor.evidence_digest,
                    "api_source": self._source, "ssh_source": self._ssh_source})
                result = ImportSecretNamespaceSourceObservation(view, namespace, self._source,
                    actor.evidence_digest, owner_evidence, self._ssh_source,
                    self._guard.serial_digest, started, deadline)
                self._current = result
                self.check_current(result)
                return result
            except BaseException as error:
                self._failed = True
                self._current = None
                if self._namespace is not None:
                    self._namespace.close()
                if isinstance(error, Exception):
                    raise BulkImportNamespaceSourceError(_ERROR) from None
                raise

    def check_current(self, observation: ImportSecretNamespaceSourceObservation) -> None:
        """Recheck only original local pins and expiry; never read or renew source."""
        with self._lock:
            try:
                if (type(observation) is not ImportSecretNamespaceSourceObservation
                        or observation is not self._current or self._namespace is None
                        or observation.source_context_digest != self._source
                        or observation.ssh_source_digest != self._ssh_source
                        or observation.serial_digest != self._guard.serial_digest
                        or observation.observed_at != self._started or observation.expires_at != self._deadline
                        or observation.namespace.api_view is not observation.api_view
                        or not observation.observed_at <= self._now() < observation.expires_at):
                    raise ValueError
                self._require_pins()
                self._namespace.check_current(observation.namespace, api_view=observation.api_view)
                self._now()
            except Exception:
                self._failed = True
                self._current = None
                if self._namespace is not None:
                    self._namespace.close()
                raise BulkImportNamespaceSourceError(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._current = None
            if self._namespace is not None:
                self._namespace.close()
