"""Default-closed fixed service Secret create and complete original readback.

One original active M4/C3 dispatch permits at most one POST followed by the
seven fixed full/material reads. Source/permission/Target preservation and
independent recovery still need the separately qualified native producer. A
callback or explicit enable flag grants none of that authority. No Tool or
normal-runtime action is registered here.
"""
from __future__ import annotations

from collections.abc import Callable
import http.client
import math
import os
import ssl
from threading import RLock
import time
from typing import Any
from urllib.parse import urlsplit

from v4_planning.material_provider import MaterialLeaseRequest, _OpaqueC3Object
from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome

from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context, _zeroize_mutable
from .windows_privileged_secret_birth import _SEND, _ACK, _FRAME, _BIRTH
from .windows_service_credential_birth import WindowsServiceCredentialBirthCustody
from .windows_service_credential_contract import WindowsServiceCredentialBinding
from .windows_service_credential_readback import WindowsServiceCredentialFullReader, _receive_fixed_json
from .windows_service_credential_owner_auth import WindowsServiceCredentialOwnerSession, check_owner_session_binding
from .windows_service_credential_authority import WindowsServiceCredentialLabAuthority

_ERROR = "The private Windows service credential create transport is unavailable."
_PATH = "/api/v2/cmdb/secret/database?vdom=root"


class WindowsServiceCredentialHttpError(RuntimeError):
    """Fixed refusal without source selectors, request or response content."""


class WindowsServiceCredentialHttpTransport(_OpaqueC3Object):
    def __init__(self, config: SecretMetadataHttpTransportConfig, custody: WindowsServiceCredentialBirthCustody, *,
            execution_enabled: bool = False, source_guard: Callable[[], bool] | None = None,
            owner_session: WindowsServiceCredentialOwnerSession | None = None,
            owner_authority: WindowsServiceCredentialLabAuthority | None = None,
            connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
            http_clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(config) is not SecretMetadataHttpTransportConfig
                    or type(custody) is not WindowsServiceCredentialBirthCustody or config != custody._config
                    or type(execution_enabled) is not bool or source_guard is not None and not callable(source_guard)
                    or not callable(connection_factory) or not callable(http_clock)):
                raise ValueError
            custody._validate()
            check_owner_session_binding(config, custody._owner_binding, owner_session, purpose="create")
            if owner_session is not None:
                if type(owner_authority) is not WindowsServiceCredentialLabAuthority:
                    raise ValueError
                owner_authority.validate_owner_creation(custody)
            elif owner_authority is not None:
                raise ValueError
            origin = urlsplit(config.base_url)
            if origin.hostname is None or origin.username is not None or origin.password is not None:
                raise ValueError
            context = _ssl_context(config)
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            self._config: SecretMetadataHttpTransportConfig = config
            self._custody: WindowsServiceCredentialBirthCustody = custody
            self._owner_session = owner_session
            self._owner_session_pin = owner_session
            self._owner_authority = self._owner_authority_pin = owner_authority
            self._tls: ssl.SSLContext = context
            self._enabled: bool = execution_enabled
            self._source_guard: Callable[[], bool] | None = source_guard
            self._source_pin: Callable[[], bool] | None = source_guard
            self._factory: Callable[..., Any] = connection_factory
            self._factory_pin: Callable[..., Any] = connection_factory
            self._clock: Callable[[], float] = http_clock
            self._clock_pin: Callable[[], float] = http_clock
            self._host: str = origin.hostname
            self._port: int = origin.port or 443
            self._attempted: bool = False
            self._failed_clock: bool = False
            self._last_time: float | None = None
            self._deadline: float | None = None
            self._lock: RLock = RLock()
        except Exception:
            raise WindowsServiceCredentialHttpError(_ERROR) from None

    def _now(self) -> float:
        try:
            value = self._clock()
            if (self._failed_clock or type(value) not in (int,float) or not math.isfinite(value) or value < 0
                    or self._last_time is not None and value < self._last_time):
                raise ValueError
            self._last_time = float(value)
            return float(value)
        except Exception:
            self._failed_clock = True
            raise WindowsServiceCredentialHttpError(_ERROR) from None

    def _remaining(self) -> float:
        if self._deadline is None: raise ValueError
        remaining = self._deadline - self._now()
        if remaining <= 0: raise ValueError
        return min(10.0, remaining)

    def _check_source(self) -> None:
        if (self._owner_session is not self._owner_session_pin
                or self._owner_authority is not self._owner_authority_pin):
            raise ValueError
        check_owner_session_binding(self._config, self._custody._owner_binding, self._owner_session, purpose="create")
        if self._owner_session is not None:
            if type(self._owner_authority) is not WindowsServiceCredentialLabAuthority:
                raise ValueError
            self._owner_authority.validate_owner_creation(self._custody)
            self._owner_session.require_current(self._custody, config=self._config, purpose="create")
        if (self._enabled is not True or self._config != self._custody._config
                or self._source_guard is None or self._source_guard is not self._source_pin
                or self._source_guard() is not True or self._factory is not self._factory_pin
                or self._clock is not self._clock_pin or not self._tls.check_hostname
                or self._tls.verify_mode != ssl.CERT_REQUIRED or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2):
            raise ValueError
        self._custody._validate()
        origin = urlsplit(self._config.base_url)
        if self._host != origin.hostname or self._port != (origin.port or 443): raise ValueError

    def _active_source(self) -> None:
        self._check_source()
        self._custody._writing_now()

    def _windows_service_credential_ready(self, binding: WindowsServiceCredentialBinding,
            request: MaterialLeaseRequest) -> bool:
        try:
            with self._lock:
                self._check_source()
                self._custody._guard.require()
                return (not self._attempted and not self._custody._closed
                    and type(binding) is WindowsServiceCredentialBinding and binding == self._custody._profile
                    and type(request) is MaterialLeaseRequest and request == self._custody._request
                    and not any(os.path.lexists(self._custody._directory/name)
                        for name in (_SEND,_ACK,_FRAME,_BIRTH,"full-read.original.attempt.json","full-read.original.result.json")))
        except Exception:
            return False

    def _post(self, body: memoryview) -> None:
        raw=bytearray()
        connection=response=None
        try:
            self._active_source(); self._remaining()
            connection=self._factory(self._host,self._port,timeout=self._remaining(),context=self._tls)
            connection.connect()
            self._active_source(); self._remaining()
            self._custody.begin_original_send(body)
            self._active_source(); self._remaining()
            headers = self._owner_session._headers("create", self._custody, config=self._config) if self._owner_session is not None else {
                "Authorization":"Bearer "+self._config.bearer_token,"Accept":"application/json",
                "Content-Type":"application/json","Accept-Encoding":"identity","Cache-Control":"no-store","Connection":"close",
                "User-Agent":"fortipam-mcp-service-credential/1"}
            connection.request("POST",_PATH,body=body,headers=headers)
            response=connection.getresponse()
            raw=_receive_fixed_json(response,16384,guard=self._active_source,remaining=self._remaining)
            self._active_source(); self._remaining()
            self._custody.capture_original_ack(raw,http_status=response.status,content_type=response.getheader("Content-Type"))
        finally:
            _zeroize_mutable(raw)
            try:
                if response is not None: response.close()
            finally:
                if connection is not None: connection.close()

    def _create_windows_service_credential(self, binding: WindowsServiceCredentialBinding,
            request: MaterialLeaseRequest, body: memoryview) -> SecretCreateAdapterOutcome:
        try:
            with self._lock:
                if self._attempted: raise ValueError
                self._attempted=True
                if (type(binding) is not WindowsServiceCredentialBinding or binding != self._custody._profile
                        or type(request) is not MaterialLeaseRequest or request != self._custody._request):
                    raise ValueError
                self._active_source()
                self._deadline=self._now()+min(30.0,float(self._config.timeout_seconds))
                self._post(body)
                self._active_source(); self._remaining()
                reader=WindowsServiceCredentialFullReader(self._custody,phase="original",read_enabled=True,
                    source_guard=self._source_guard,connection_factory=self._factory,http_clock=self._now,
                    owner_session=self._owner_session)
                result=reader.read_once(max_deadline=self._deadline)
                self._active_source(); self._remaining()
                if not result.original_material_seal_present or result.original.state_digest is None:
                    raise ValueError
                return SecretCreateAdapterOutcome.VERIFIED_CREATED
        except Exception:
            return SecretCreateAdapterOutcome.RECONCILIATION_REQUIRED
