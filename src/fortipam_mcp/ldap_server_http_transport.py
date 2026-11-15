"""Private fixed LDAPS creation and owned recovery; no runtime registration.

The server-held caller supplies authorization and material leases. This adapter
keeps a separate durable one-shot dispatch boundary, never returns a native
response, and cannot adopt an object after an unacknowledged POST.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict
from enum import Enum
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import threading
import time
from typing import Protocol
from urllib.parse import quote, quote_from_bytes, urlsplit

from v4_planning.material_provider import C3MaterialBinding, MaterialLeaseRequest

from .ldap_server_contract import (
    ACTION_ID, ACTION_VERSION, CONTRACT, LdapServerCandidateError,
    LdapServerCreateBinding, LdapServerCreateOutcome,
)
from .ldap_server_projection import (
    LdapServerDefaults, LdapServerDetail, LdapServerSchema,
    project_ldap_absence, project_ldap_ack, project_ldap_defaults,
    project_ldap_detail, project_ldap_info, project_ldap_schema,
)
from .mutable_json_buffer import _MutableJSONBuffer, _take_mutable_prefix, _erase_transfer_storage
from .secret_create_191_http_transport import _append_material, _valid_material_view
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable

_UNAVAILABLE = "The private LDAP server transport is unavailable."
_PATH = "/api/v2/cmdb/user/ldap"
_INFO = "/api/v2/monitor/service/ldap/query"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class _CreateStage(str, Enum):
    DIRECTORY_TEST = "directory_test"
    REFRESH = "refresh"
    POST = "post"
    ACK_PERSIST = "ack_persist"
    READBACK = "readback"
    CREATED_PERSIST = "created_persist"


class _Response(Protocol):
    status: int
    def readinto(self, buffer: memoryview) -> int: ...
    def getheader(self, name: str, default: str = "") -> str: ...
    def close(self) -> None: ...


class _Connection(Protocol):
    def connect(self) -> None: ...
    def request(self, method: str, url: str, body: memoryview | None,
                headers: dict[str, str]) -> None: ...
    def getresponse(self) -> _Response: ...
    def close(self) -> None: ...


class LdapServerReadiness(C3MaterialBinding):
    """Protected C/P/E observation; only its salted digest enters execution."""

    __slots__ = ("schema", "defaults", "state_digest", "observed_at")

    def __init__(self, schema: LdapServerSchema, defaults: LdapServerDefaults,
                 state_digest: str, observed_at: int) -> None:
        self.schema, self.defaults = schema, defaults
        self.state_digest, self.observed_at = state_digest, observed_at


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     allow_nan=False).encode()).hexdigest()


class FortiPamLdapServerHttpTransport(C3MaterialBinding):
    """One private create profile and its exact acknowledged-object recovery."""

    __slots__ = ("_config", "_binding", "_serial", "_directory", "_directory_identity",
                 "_request", "_expected", "_execution_enabled", "_recovery_enabled", "_clock",
                 "_last_clock", "_clock_failed", "_clock_lock", "_factory")

    def __init__(self, config: SecretMetadataHttpTransportConfig,
                 binding: LdapServerCreateBinding, *, expected_serial: str,
                 state_directory: Path, execution_request: MaterialLeaseRequest | None = None,
                 expected_current_digest: str | None = None, execution_enabled: bool = False,
                 recovery_enabled: bool = False, clock: Callable[[], int] | None = None,
                 connection_factory: Callable[..., _Connection] | None = None) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                or type(binding) is not LdapServerCreateBinding
                or type(expected_serial) is not str
                or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None
                or type(execution_enabled) is not bool or type(recovery_enabled) is not bool
                or not isinstance(state_directory, Path) or not state_directory.is_absolute()):
                raise ValueError
            config.__post_init__()
            binding.__post_init__()
            parsed = urlsplit(config.base_url)
            if not parsed.hostname or parsed.username is not None or parsed.password is not None:
                raise ValueError
            info = state_directory.lstat()
            if (state_directory.is_symlink() or not stat.S_ISDIR(info.st_mode)
                or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.getuid()):
                raise ValueError
            if execution_enabled and (type(execution_request) is not MaterialLeaseRequest
                or expected_current_digest is None or _DIGEST.fullmatch(expected_current_digest) is None):
                raise ValueError
        except Exception:
            raise LdapServerCandidateError(_UNAVAILABLE) from None
        self._config, self._binding, self._serial = config, binding, expected_serial
        self._directory, self._directory_identity = state_directory, (info.st_dev, info.st_ino)
        self._request, self._expected = execution_request, expected_current_digest
        self._execution_enabled, self._recovery_enabled = execution_enabled, recovery_enabled
        self._clock = clock or (lambda: int(time.time()))
        self._last_clock: int | None = None
        self._clock_failed = False
        self._clock_lock = threading.RLock()
        self._factory = connection_factory or http.client.HTTPSConnection

    def __repr__(self) -> str:
        return "<FortiPamLdapServerHttpTransport protected>"

    def _now(self) -> int:
        with self._clock_lock:
            value = self._clock()
            if (self._clock_failed or type(value) is not int or value < 0
                or self._last_clock is not None and value < self._last_clock):
                self._clock_failed = True
                raise LdapServerCandidateError(_UNAVAILABLE)
            self._last_clock = value
            return value

    def _directory_fd(self) -> int:
        descriptor = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if ((info.st_dev, info.st_ino) != self._directory_identity
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            os.close(descriptor)
            raise LdapServerCandidateError(_UNAVAILABLE)
        return descriptor

    def _write_once(self, name: str, value: object) -> None:
        directory = self._directory_fd()
        try:
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "w") as stream:
                json.dump(value, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
                stream.flush()
                os.fsync(stream.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _read_state(self, name: str) -> dict[str, object]:
        directory = self._directory_fd()
        descriptor = None
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid() or info.st_nlink != 1 or not 0 < info.st_size <= 8192):
                raise ValueError
            raw = os.read(descriptor, 8193)
            result = json.loads(raw)
            if type(result) is not dict or len(raw) != info.st_size:
                raise ValueError
            return result
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)

    def _exchange(self, method: str, path: str, *, body: bytearray | None = None,
                  certificate: bool = False, limit: int = 1048576,
                  before_send: Callable[[], None] | None = None,
                  deadline: int | None = None) -> tuple[int, bytearray]:
        """Private fixed callers only; no generic route is exposed to a Tool."""
        raw = bytearray()
        try:
            connection = response = body_view = None
            raw = bytearray(limit + 1)
            try:
                parsed = urlsplit(self._config.base_url)
                if parsed.hostname is None:
                    raise ValueError
                context = _ssl_context(self._config)
                if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                    raise ValueError
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                timeout = self._config.timeout_seconds
                if deadline is not None:
                    remaining = deadline - self._now()
                    if remaining <= 0:
                        raise ValueError
                    timeout = min(timeout, remaining)
                connection = self._factory(parsed.hostname, parsed.port or 443,
                    timeout=timeout, context=context)
                if body is not None:
                    body_view = memoryview(body).toreadonly()
                if before_send is not None:
                    before_send()
                    connection.connect()
                    before_send()
                connection.request(method, path, body_view, {
                    "Authorization": "Bearer " + self._config.bearer_token,
                    "Accept": "*/*" if certificate else "application/json", "Accept-Encoding": "identity",
                    "User-Agent": "fortipam-mcp-v4-ldap-server/1",
                    "Connection": "close", "Content-Type": "application/json", "Cache-Control": "no-store"})
                response = connection.getresponse()
                if not certificate and "json" not in response.getheader("Content-Type", ""):
                    raise ValueError
                used = 0
                while used <= limit:
                    with memoryview(raw)[used:] as destination:
                        count = response.readinto(destination)
                    if type(count) is not int or count < 0 or used + count > limit:
                        raise ValueError
                    if not count:
                        break
                    used += count
                raw = _take_mutable_prefix(raw, used)
                return response.status, raw
            except Exception:
                _zeroize_mutable(raw)
                raise LdapServerCandidateError(_UNAVAILABLE) from None
            finally:
                if body_view is not None:
                    body_view.release()
                for resource in (response, connection):
                    if resource is not None:
                        try:
                            resource.close()
                        except Exception:
                            pass
        except BaseException:
            _erase_transfer_storage(raw)
            raise

    def _ca_matches(self) -> None:
        raw = bytearray()
        try:
            code, raw = self._exchange("GET", "/api/v2/monitor/system/certificate/download/"
                + quote(self._binding.ca_name, safe="") + "?scope=vdom&type=remote-ca", certificate=True)
            if (code != 200 or raw.count(b"-----BEGIN CERTIFICATE-----") != 1
                or raw.count(b"-----END CERTIFICATE-----") != 1 or b"PRIVATE KEY" in raw):
                raise ValueError
            der = ssl.PEM_cert_to_DER_cert(raw.decode("ascii"))
            if not hmac.compare_digest(hashlib.sha256(der).hexdigest(), self._binding.ca_certificate_sha256):
                raise ValueError
        finally:
            _zeroize_mutable(raw)

    def _components(self) -> LdapServerReadiness:
        before = self._now()
        code, raw = self._exchange("GET", _PATH + "?action=schema&with_meta=true")
        if code != 200:
            _zeroize_mutable(raw)
            raise LdapServerCandidateError(_UNAVAILABLE)
        schema = project_ldap_schema(raw, expected_serial=self._serial)
        code, raw = self._exchange("GET", _PATH + "?action=default&with_meta=true")
        if code != 200:
            _zeroize_mutable(raw)
            raise LdapServerCandidateError(_UNAVAILABLE)
        defaults = project_ldap_defaults(raw, schema, expected_serial=self._serial)
        self._ca_matches()
        if self._now() < before or self._now() - before >= 60:
            raise LdapServerCandidateError(_UNAVAILABLE)
        digest = _digest({"contract": CONTRACT, "parameters": self._binding.parameters_digest,
            "schema": schema.state_digest, "defaults": defaults.state_digest,
            "serial": hashlib.sha256(self._serial.encode()).hexdigest()})
        return LdapServerReadiness(schema, defaults, digest, before)

    def _absence(self) -> None:
        for path, collection in ((_PATH + "?format=name&with_meta=true", True),
                                 (_PATH + "/" + quote(self._binding.name, safe="") + "?with_meta=true", False)):
            code, raw = self._exchange("GET", path)
            if not project_ldap_absence(raw, self._binding, expected_serial=self._serial,
                                       http_status=code, collection=collection):
                raise LdapServerCandidateError(_UNAVAILABLE)

    def inspect_create(self) -> LdapServerReadiness:
        try:
            # A claim, even from an uncertain response, forbids a new create.
            if any(os.path.lexists(self._directory / name) for name in (
                "create.claim.json", "create-ack.json", "created.json", "delete.claim.json", "deleted.json")):
                raise ValueError
            observation = self._components()
            self._absence()
            if not 0 <= self._now() - observation.observed_at < 60:
                raise ValueError
            return observation
        except Exception:
            raise LdapServerCandidateError(_UNAVAILABLE) from None

    def _detail(self, observation: LdapServerReadiness) -> LdapServerDetail:
        code, raw = self._exchange("GET", _PATH + "/" + quote(self._binding.name, safe="") + "?with_meta=true")
        if code != 200:
            _zeroize_mutable(raw)
            raise LdapServerCandidateError(_UNAVAILABLE)
        return project_ldap_detail(raw, observation.schema, observation.defaults, self._binding,
                                   expected_serial=self._serial)

    def _lease_valid(self, binding: LdapServerCreateBinding, request: MaterialLeaseRequest) -> None:
        if (not self._execution_enabled or binding is not self._binding or type(request) is not MaterialLeaseRequest
            or request != self._request or request.action_id != ACTION_ID or request.action_version != ACTION_VERSION
            or not request.requested_at <= self._now() < request.expires_at):
            raise LdapServerCandidateError(_UNAVAILABLE)

    def _create_and_verify_with_material(self, binding: LdapServerCreateBinding,
            request: MaterialLeaseRequest, username: memoryview, password: memoryview) -> LdapServerCreateOutcome:
        body = bytearray()
        info = bytearray()
        claimed = False
        stage = _CreateStage.DIRECTORY_TEST
        http_status: int | None = None
        post_stage_entered = False
        try:
            self._lease_valid(binding, request)
            if (not _valid_material_view(username) or not _valid_material_view(password)
                or password.nbytes > 128 or not hmac.compare_digest(username, binding.username.encode())):
                raise ValueError
            current = self.inspect_create()
            if not hmac.compare_digest(current.state_digest, self._expected or ""):
                raise ValueError
            self._lease_valid(binding, request)
            claim = {"contract": CONTRACT, "parameters_digest": binding.parameters_digest,
                "request_digest": _digest(asdict(request)), "current_digest": current.state_digest,
                "claimed_at": self._now()}
            # Reserve before the material-bearing directory test as well as POST.
            self._write_once("create.claim.json", claim)
            claimed = True
            info = _info_body(binding, username, password)
            code, raw = self._exchange("GET", _INFO + "?json=" + quote_from_bytes(info, safe=""), limit=8 * 1048576,
                before_send=lambda: self._lease_valid(binding, request), deadline=request.expires_at)
            http_status = code if type(code) is int and 100 <= code <= 599 else None
            if code != 200:
                _zeroize_mutable(raw)
                raise ValueError
            if not project_ldap_info(raw, binding, expected_serial=self._serial):
                raise ValueError
            _zeroize_mutable(info)
            stage, http_status = _CreateStage.REFRESH, None
            self._lease_valid(binding, request)
            # Fresh source/default/CA drift and absence after the directory test.
            refreshed = self._components()
            self._absence()
            if refreshed.state_digest != current.state_digest:
                raise ValueError
            self._lease_valid(binding, request)
            stage, http_status = _CreateStage.POST, None
            post_stage_entered = True
            body = _create_body(binding, username, password)
            code, raw = self._exchange("POST", _PATH, body=body,
                before_send=lambda: self._lease_valid(binding, request), deadline=request.expires_at)
            http_status = code if type(code) is int and 100 <= code <= 599 else None
            if code != 200:
                _zeroize_mutable(raw)
                raise ValueError
            if not project_ldap_ack(raw, binding, expected_serial=self._serial, method="POST"):
                raise ValueError
            stage, http_status = _CreateStage.ACK_PERSIST, None
            self._write_once("create-ack.json", {"claim_digest": _digest(claim),
                "parameters_digest": binding.parameters_digest, "acknowledged_at": self._now()})
            stage, http_status = _CreateStage.READBACK, None
            detail = self._detail(refreshed)
            stage, http_status = _CreateStage.CREATED_PERSIST, None
            self._write_once("created.json", {"claim_digest": _digest(claim),
                "parameters_digest": binding.parameters_digest, "state_digest": detail.state_digest})
            return LdapServerCreateOutcome.VERIFIED_CREATED
        except Exception:
            # Only this invocation's consumed claim may produce a diagnostic.
            # Nested reads do not expose their status here; never retain an
            # earlier stage's code. Diagnostic failure cannot alter no-replay.
            if claimed:
                try:
                    self._write_once("create-diagnostic.json", {"stage": stage.value,
                        "http_status": http_status, "post_stage_entered": post_stage_entered})
                except Exception:
                    pass
            return LdapServerCreateOutcome.RECONCILIATION_REQUIRED
        finally:
            _zeroize_mutable(body)
            _zeroize_mutable(info)

    def inspect_owned(self) -> bool:
        """ACK-bound read-only reconciliation; never acquire or resend material."""
        try:
            claim = self._read_state("create.claim.json")
            ack = self._read_state("create-ack.json")
            if (claim["parameters_digest"] != self._binding.parameters_digest
                or ack["parameters_digest"] != self._binding.parameters_digest
                or ack["claim_digest"] != _digest(claim)):
                raise ValueError
            current = self._components()
            if current.state_digest != claim["current_digest"]:
                raise ValueError
            detail = self._detail(current)
            expected = {"claim_digest": _digest(claim), "parameters_digest": self._binding.parameters_digest,
                        "state_digest": detail.state_digest}
            if os.path.lexists(self._directory / "created.json"):
                if self._read_state("created.json") != expected:
                    raise ValueError
            else:
                self._write_once("created.json", expected)
            return True
        except Exception:
            raise LdapServerCandidateError(_UNAVAILABLE) from None

    def delete_owned(self) -> bool:
        """Separate default-closed recovery, current zero references and no drift."""
        try:
            if not self._recovery_enabled or not self.inspect_owned():
                raise ValueError
            owned = self._read_state("created.json")
            self._write_once("delete.claim.json", {"created_digest": _digest(owned), "claimed_at": self._now()})
            code, raw = self._exchange("DELETE", _PATH + "/" + quote(self._binding.name, safe=""))
            if code != 200:
                _zeroize_mutable(raw)
                raise ValueError
            if not project_ldap_ack(raw, self._binding, expected_serial=self._serial, method="DELETE"):
                raise ValueError
            self._absence()
            self._write_once("deleted.json", {"created_digest": _digest(owned), "verified_at": self._now()})
            return True
        except Exception:
            raise LdapServerCandidateError(_UNAVAILABLE) from None

    def inspect_deleted(self) -> bool:
        """Read-only reconciliation of an uncertain DELETE, never its retry."""
        try:
            marker = self._read_state("delete.claim.json")
            owned = self._read_state("created.json")
            if (marker["created_digest"] != _digest(owned)
                or owned["parameters_digest"] != self._binding.parameters_digest):
                raise ValueError
            self._absence()
            return True
        except Exception:
            raise LdapServerCandidateError(_UNAVAILABLE) from None


def _create_body(binding: LdapServerCreateBinding, username: memoryview, password: memoryview) -> bytearray:
    with _MutableJSONBuffer() as body:
        values = binding.desired_nonmaterial()
        del values["username"]
        body.extend(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()[:-1])
        body.extend(b',"username":')
        _append_material(body, username)
        body.extend(b',"password":')
        _append_material(body, password)
        body.extend(b"}")
        return body.finish()


def _info_body(binding: LdapServerCreateBinding, username: memoryview, password: memoryview) -> bytearray:
    with _MutableJSONBuffer() as body:
        ldap = {"server": binding.server, "port": 636, "cn_id": "sAMAccountName", "dn": binding.dn,
                "ca": binding.ca_name, "type": 2, "secure": 2, "server-identity-check": 1}
        body.extend(b'{"info_only":1,"mkey":null,"ldap":')
        body.extend(json.dumps(ldap, sort_keys=True, separators=(",", ":")).encode()[:-1])
        body.extend(b',"username":')
        _append_material(body, username)
        body.extend(b',"password":')
        _append_material(body, password)
        body.extend(b"}}")
        return body.finish()
