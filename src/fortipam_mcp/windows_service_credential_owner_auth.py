"""Explicit private Owner authentication for the fixed service credential path.

The binding separates the metadata observer from the actual creator. Login and
identity checks grant no M4/C3, object permission, association or activity
authority. The existing fixed adapters retain their authorization and routes.
No cookie, CSRF or credential is returned through an MCP interface or persisted.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
from http.cookies import SimpleCookie
import math
import re
from threading import RLock
import time
from typing import Any, Literal, TYPE_CHECKING
from urllib.parse import quote, urlsplit

import httpx

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from . import secret_bulk_import_metadata as m
from .local_user_reset_fixture_preflight import _actor_context
from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig,
    _zeroize_mutable,
)
from .target_lifecycle_dependencies import _envelope, _one
from .target_api_dependency_reader import _private_http_logs
from .windows_target_owner_source import _ca_digest

if TYPE_CHECKING:
    from .windows_service_credential_birth import WindowsServiceCredentialBirthCustody

_ERROR = "The private Windows service credential Owner authentication is unavailable."
_CONTRACT = "fortipam-build29-service-credential-explicit-owner-auth-v1"
_ACTOR = "/api/v2/monitor/web-ui/state"
_DATABASE = "/api/v2/cmdb/secret/database"
_CLEAR = "/api/v2/internal/secret-clear-text"
_STATUS = "/api/v2/monitor/system/status"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_Operation = Literal["create", "full", "material", "delete", "absence"]


class WindowsServiceCredentialOwnerAuthError(ValueError):
    """Categorical refusal without identity, cookie or response content."""


@dataclass(frozen=True, slots=True, repr=False)
class WindowsServiceCredentialOwnerBinding(_OpaqueC3Object):
    """A declared principal/source binding, never evidence or permission."""
    owner_digest: str
    serial_digest: str
    folder_context_digest: str
    origin_digest: str
    ca_digest: str | None

    def __post_init__(self) -> None:
        for value in (self.owner_digest, self.serial_digest, self.folder_context_digest, self.origin_digest):
            require_digest(value, "service_owner_binding")
        if self.ca_digest is not None:
            require_digest(self.ca_digest, "service_owner_ca")

    @property
    def binding_digest(self) -> str:
        self.__post_init__()
        return canonical_digest(dict(contract=_CONTRACT, actual_authentication="owner-cookie",
            owner=self.owner_digest, serial=self.serial_digest, folder=self.folder_context_digest,
            origin=self.origin_digest, ca=self.ca_digest, identity_policy="enabled-local-super-admin"))


def service_credential_owner_binding(config: SecretMetadataHttpTransportConfig, *, owner_name: str,
        serial_digest: str, folder_context_digest: str) -> WindowsServiceCredentialOwnerBinding:
    """Bind configured metadata and Owner inputs without authenticating them."""
    try:
        if type(config) is not SecretMetadataHttpTransportConfig or type(owner_name) is not str or _NAME.fullmatch(owner_name) is None:
            raise ValueError
        config.__post_init__()
        return WindowsServiceCredentialOwnerBinding(hashlib.sha256(owner_name.encode()).hexdigest(),
            serial_digest, folder_context_digest, hashlib.sha256(config.base_url.encode()).hexdigest(), _ca_digest(config))
    except Exception:
        raise WindowsServiceCredentialOwnerAuthError(_ERROR) from None


def owner_auth_binding_digest(config: SecretMetadataHttpTransportConfig,
        binding: WindowsServiceCredentialOwnerBinding) -> str:
    """Validate stable declared source bindings, not a live session or grant."""
    if type(config) is not SecretMetadataHttpTransportConfig or type(binding) is not WindowsServiceCredentialOwnerBinding:
        raise ValueError
    config.__post_init__()
    if (binding.origin_digest != hashlib.sha256(config.base_url.encode()).hexdigest()
            or binding.ca_digest != _ca_digest(config)):
        raise ValueError
    return binding.binding_digest


class WindowsServiceCredentialOwnerSession(_OpaqueC3Object):
    """One default-closed login lifetime, exact Owner and one custody context.

    Fixed adapters call the private header selector after their original M4/C3
    and state checks. This class neither dispatches a Secret request nor exposes
    a general endpoint, connection factory or credential acquisition interface.
    Independent recovery requires a separate instance and authenticated session.
    """
    _config: SecretMetadataHttpTransportConfig
    _binding: WindowsServiceCredentialOwnerBinding
    _owner: str
    _binding_pin: str
    _purpose: Literal["create", "recovery"]
    _purpose_pin: Literal["create", "recovery"]
    _clock: Callable[[], float]
    _clock_pin: Callable[[], float]
    _enabled: bool
    _session: OwnerSessionMetadataTransport
    _session_pin: OwnerSessionMetadataTransport
    _client_factory_pin: Callable[..., Any]
    _credentials_pin: Callable[[], tuple[str, str]]
    _attempted: bool
    _active: bool
    _failed: bool
    _lock: RLock
    _request_count: int
    _main_request_count: int
    _logout_started: bool
    _logout_status_read: bool
    _request_hook: Callable[[httpx.Request], None]
    _response_hook: Callable[[httpx.Response], None]
    _landing_url: httpx.URL | None
    _landing_followed: bool
    def __init__(self, config: SecretMetadataHttpTransportConfig, *, owner_name: str,
            credentials: Callable[[], tuple[str, str]], binding: WindowsServiceCredentialOwnerBinding,
            purpose: Literal["create", "recovery"], enabled: bool = False,
            client_factory: Callable[..., Any] = httpx.Client,
            clock: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(purpose) is not str or purpose not in ("create", "recovery") or type(enabled) is not bool
                    or not callable(credentials) or not callable(client_factory) or not callable(clock)
                    or service_credential_owner_binding(config, owner_name=owner_name,
                        serial_digest=binding.serial_digest, folder_context_digest=binding.folder_context_digest) != binding):
                raise ValueError
            self._config, self._binding, self._owner = config, binding, owner_name
            self._binding_pin = owner_auth_binding_digest(config, binding)
            self._purpose = self._purpose_pin = purpose
            self._clock = self._clock_pin = clock
            self._enabled = enabled
            self._request_count = self._main_request_count = 0
            self._logout_started = self._logout_status_read = False
            self._request_hook = self._guard_request
            self._response_hook = self._capture_login_redirect
            self._landing_url, self._landing_followed = None, False
            def fixed_client_factory(**options: Any) -> Any:
                if "event_hooks" in options:
                    raise ValueError
                return client_factory(**options, event_hooks={"request": [self._request_hook], "response": [self._response_hook]})
            self._session = OwnerSessionMetadataTransport(config, owner_name=owner_name, credentials=credentials,
                folder_path="service-credential-auth", secret_name="service-credential-auth", target_name="service-credential-auth",
                witness=FortiPamSecretMetadataHttpTransport(config), client_factory=fixed_client_factory, clock=clock)
            self._session_pin = self._session
            self._client_pin: Any = None
            self._client_factory_pin = self._session._session_factory
            self._credentials_pin = self._session._credentials
            self._attempted = self._active = self._failed = False
            self._last_time: float | None = None
            self._deadline: float | None = None
            self._cookie_pin: str | None = None
            self._custody_context: str | None = None
            self._lock = RLock()
        except Exception:
            raise WindowsServiceCredentialOwnerAuthError(_ERROR) from None

    @property
    def binding(self) -> WindowsServiceCredentialOwnerBinding:
        if owner_auth_binding_digest(self._config, self._binding) != self._binding_pin:
            raise WindowsServiceCredentialOwnerAuthError(_ERROR)
        return self._binding

    @property
    def logout_verified(self) -> bool:
        return self._session.logout_verified

    def _now(self) -> float:
        try:
            value = self._clock()
            if (self._clock is not self._clock_pin or self._failed or type(value) not in (int, float)
                    or not math.isfinite(value) or value < 0 or self._last_time is not None and value < self._last_time):
                raise ValueError
            self._last_time = float(value)
            return float(value)
        except Exception:
            self._failed = True
            raise WindowsServiceCredentialOwnerAuthError(_ERROR) from None

    def _check_configuration(self) -> None:
        if (self._enabled is not True or self._session is not self._session_pin
                or self._session._config != self._config or self._session._owner_name != self._owner
                or self._session._session_factory is not self._client_factory_pin
                or self._session._credentials is not self._credentials_pin or self._session._clock is not self._clock_pin
                or self._purpose != self._purpose_pin or self._purpose not in ("create", "recovery")
                or self.binding.owner_digest != hashlib.sha256(self._owner.encode()).hexdigest()):
            raise ValueError
        self._now()

    def _guard_request(self, request: httpx.Request) -> None:
        """Keep the borrowed login helper inside this exact metadata boundary."""
        origin = httpx.URL(self._config.base_url)
        if ((request.url.scheme, request.url.host, request.url.port) != (origin.scheme, origin.host, origin.port)
                or request.url.username or request.url.password or request.url.fragment
                or "authorization" in request.headers):
            raise ValueError
        path, query = request.url.path, request.url.query
        if request.method == "GET" and path == "/logout" and not query:
            if self._logout_started:
                raise ValueError
            self._logout_started = True
        elif request.method == "GET" and path == _STATUS and not query and self._logout_started:
            if self._logout_status_read:
                raise ValueError
            self._logout_status_read = True
        else:
            allowed = {
                ("GET", "/remote/login", b"lang=en"), ("POST", "/XX/YY/ZZ/AUTH", b""),
                ("GET", _STATUS, b""), ("GET", _ACTOR, b""),
                ("GET", "/api/v2/cmdb/system/admin/" + self._owner,
                    b"format=name%7Caccprofile%7Cstatus%7Cremote-auth%7Cwildcard&with_meta=true&vdom=root"),
            }
            landing = (request.method == "GET" and self._landing_url is not None
                and request.url == self._landing_url and not self._landing_followed)
            if (self._logout_started or not landing and (request.method, path, query) not in allowed
                    or self._main_request_count >= 8):
                raise ValueError
            if landing:
                self._landing_followed = True
            self._main_request_count += 1
        self._request_count += 1

    def _capture_login_redirect(self, response: httpx.Response) -> None:
        """Accept only this AUTH's relative, same-origin non-API UI landing.

        This follows the existing fixed Owner login pattern. The landing never
        authenticates the actor and its URL remains private session memory.
        """
        if response.request.method != "POST" or response.request.url.path != "/XX/YY/ZZ/AUTH" or response.status_code != 303:
            return
        location = response.headers.get("location")
        if (not location or len(location) > 2048 or any(ord(c) < 33 or ord(c) > 126 for c in location)
                or self._landing_url is not None):
            raise ValueError
        redirect = urlsplit(location)
        origin = httpx.URL(self._config.base_url)
        destination = origin.join(location)
        if (redirect.scheme or redirect.netloc or redirect.fragment or not redirect.path.startswith("/")
                or redirect.path.startswith("//") or "%" in redirect.path
                or (destination.scheme, destination.host, destination.port) != (origin.scheme, origin.host, origin.port)
                or destination.username or destination.password
                or destination.path.casefold() == "/api" or destination.path.casefold().startswith("/api/")
                or destination.path in {"/XX/YY/ZZ/AUTH", "/logout"}):
            raise ValueError
        self._landing_url = destination

    def _cookies_digest(self) -> str:
        if self._session._client is None:
            raise ValueError
        values: list[dict[str, object]] = []
        for cookie in self._session._client.cookies.jar:
            if len(values) >= 32:
                raise ValueError
            values.append(dict(name=cookie.name, domain=cookie.domain, path=cookie.path, secure=cookie.secure,
                value=hashlib.sha256(cookie.value.encode()).hexdigest()))
        if not values:
            raise ValueError
        return canonical_digest(sorted(values, key=lambda item: (str(item["name"]), str(item["domain"]), str(item["path"]))))

    def _validated_cookie(self, method: str, path: str) -> tuple[str, str]:
        cookie = self._session._client.build_request(method, self._config.base_url + path).headers.get("cookie")
        if not cookie or len(cookie) > 16384 or any(ord(c) < 32 or ord(c) >= 127 for c in cookie):
            raise ValueError
        cookies: SimpleCookie = SimpleCookie()
        cookies.load(cookie)
        csrf = cookies.get("ccsrftoken")
        if csrf is None or not csrf.value or len(csrf.value) > 4096 or any(ord(c) < 33 or ord(c) >= 127 for c in csrf.value):
            raise ValueError
        return cookie, csrf.value

    def _identity(self) -> str:
        """Two fixed bounded Owner GETs, preserving the native build29 locus."""
        buffers: list[bytearray] = []
        try:
            self._check_configuration()
            if self._session._client is None:
                raise ValueError
            if self._active and (self._deadline is None or self._now() >= self._deadline):
                raise ValueError
            paths = (_ACTOR, "/api/v2/cmdb/system/admin/" + quote(self._owner, safe="") +
                "?format=name%7Caccprofile%7Cstatus%7Cremote-auth%7Cwildcard&with_meta=true&vdom=root")
            for path in paths:
                self._now()
                raw = bytearray(); buffers.append(raw)
                with self._session._client.stream("GET", self._config.base_url + path,
                        headers={"Accept": "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-store"}) as response:
                    if (response.status_code != 200 or response.headers.get("content-type", "").split(";")[0].lower() != "application/json"
                            or response.headers.get("content-encoding") not in (None, "", "identity")):
                        raise ValueError
                    lengths = response.headers.get_list("content-length")
                    if (len(lengths) > 1 or lengths and (re.fullmatch(r"[0-9]{1,7}", lengths[0]) is None
                            or not 0 < int(lengths[0]) <= 262144)):
                        raise ValueError
                    for chunk in response.iter_bytes():
                        self._now()
                        if (len(raw) + len(chunk) > 262144 or self._active
                                and (self._deadline is None or self._now() >= self._deadline)):
                            raise ValueError
                        raw.extend(chunk)
                    if lengths and len(raw) != int(lengths[0]):
                        raise ValueError
            span = _envelope(buffers[0], path="web-ui", name="state", serial_digest=self._binding.serial_digest, monitor=True)
            fields = m._object_spans(buffers[0], *span, frozenset({"admin", "vdom_mode", "maintenance_mode"}))
            admin = m._object_spans(buffers[0], *fields["admin"], frozenset({"name", "profile", "global_admin", "super_admin"}))
            profile = m._object_spans(buffers[0], *admin["profile"], frozenset({"name"}))
            maintenance = m._object_spans(buffers[0], *fields["maintenance_mode"], frozenset({"mode"}))
            if (m._scalar(buffers[0], admin["name"]) != self._owner or m._scalar(buffers[0], profile["name"]) != "super_admin"
                    or m._scalar(buffers[0], admin["super_admin"]) is not True or m._scalar(buffers[0], admin["global_admin"]) is not True
                    or m._scalar(buffers[0], fields["vdom_mode"]) != "" or m._scalar(buffers[0], maintenance["mode"]) != "disable"):
                raise ValueError
            actor = _actor_context(buffers[0], expected_name=self._owner)
            row = _one(buffers[1], _envelope(buffers[1], path="system", name="admin", serial_digest=self._binding.serial_digest))
            expected = {"name": self._owner, "accprofile": "super_admin", "status": "enable", "remote-auth": "disable", "wildcard": "disable"}
            actual = m._object_spans(buffers[1], *row, frozenset(expected))
            if {key: m._scalar(buffers[1], value) for key, value in actual.items()} != expected:
                raise ValueError
            return canonical_digest(dict(actor=actor, expected=expected, binding=self._binding_pin))
        finally:
            for raw in buffers:
                _zeroize_mutable(raw)

    @contextmanager
    def authenticated(self) -> Iterator[WindowsServiceCredentialOwnerSession]:
        try:
            with self._lock:
                if self._attempted:
                    raise ValueError
                self._attempted = True
                self._check_configuration()
            with _private_http_logs(), self._session.authenticated():
                identity = self._identity()
                # Validate the mutation/read-material authentication syntax
                # before an adapter can acquire its original C3 material.
                self._validated_cookie("POST", _DATABASE + "?vdom=root")
                with self._lock:
                    self._deadline = self._now() + 60.0
                    self._cookie_pin = self._cookies_digest()
                    self._client_pin = self._session._client
                    self._active = True
                yield self
                if (self._cookies_digest() != self._cookie_pin or self._identity() != identity
                        or self._cookies_digest() != self._cookie_pin):
                    raise ValueError
        except Exception:
            raise WindowsServiceCredentialOwnerAuthError(_ERROR) from None
        finally:
            with self._lock:
                self._active = False
                self._deadline = None
                self._cookie_pin = None
                self._client_pin = None
                self._landing_url = None

    def require_binding(self, binding: WindowsServiceCredentialOwnerBinding, *,
            config: SecretMetadataHttpTransportConfig, purpose: Literal["create", "recovery"]) -> None:
        """Check the live declared principal before a final profile exists."""
        try:
            with self._lock:
                self._check_configuration()
                if (type(binding) is not WindowsServiceCredentialOwnerBinding or binding != self.binding or config != self._config
                        or purpose != self._purpose or not self._active or self._deadline is None
                        or self._session._client is not self._client_pin
                        or self._session._client.event_hooks.get("request") != [self._request_hook]
                        or self._session._client.event_hooks.get("response") != [self._response_hook]
                        or self._now() >= min(self._deadline, self._session._expires_at)
                        or self._cookies_digest() != self._cookie_pin):
                    raise ValueError
        except Exception:
            raise WindowsServiceCredentialOwnerAuthError(_ERROR) from None

    def require_current(self, custody: WindowsServiceCredentialBirthCustody, *,
            config: SecretMetadataHttpTransportConfig, purpose: Literal["create", "recovery"]) -> None:
        try:
            with self._lock:
                from .windows_service_credential_birth import WindowsServiceCredentialBirthCustody
                self.require_binding(self.binding, config=config, purpose=purpose)
                if (type(custody) is not WindowsServiceCredentialBirthCustody or custody._owner_binding != self.binding
                        or custody._profile.serial_digest != self.binding.serial_digest
                        or custody._profile.folder_context_digest != self.binding.folder_context_digest):
                    raise ValueError
                custody._validate()
                if self._custody_context is None:
                    self._custody_context = custody._context
                if custody._context != self._custody_context:
                    raise ValueError
        except Exception:
            raise WindowsServiceCredentialOwnerAuthError(_ERROR) from None

    def _headers(self, operation: _Operation, custody: WindowsServiceCredentialBirthCustody, *,
            config: SecretMetadataHttpTransportConfig) -> dict[str, str]:
        """Fixed authenticated route families; adapters own every actual request."""
        try:
            with self._lock:
                self.require_current(custody, config=config, purpose=self._purpose)
                if operation not in ("create", "full", "material", "delete", "absence"):
                    raise ValueError
                if self._purpose == "create":
                    if operation in ("delete", "absence"):
                        raise ValueError
                    custody._writing_now()
                else:
                    if operation == "create" or custody.inspect_original_creation().original_outcome == "in_progress":
                        raise ValueError
                if operation == "create":
                    path = _DATABASE + "?vdom=root"
                else:
                    original = custody.inspect_original_creation()
                    if type(original.native_secret_id) is not int or original.native_secret_id <= 0:
                        raise ValueError
                    path = _DATABASE + "/" + str(original.native_secret_id)
                    path += "?format=id&vdom=root" if operation == "absence" else "?vdom=root" if operation == "delete" else "?with_meta=true&vdom=root"
                    if operation == "material":
                        if original.native_uuid is None:
                            raise ValueError
                        path = _CLEAR
                method = "POST" if operation in ("create", "material") else "DELETE" if operation == "delete" else "GET"
                cookie, csrf = self._validated_cookie(method, path)
                headers = {"Cookie": cookie, "Accept": "application/json", "Accept-Encoding": "identity",
                    "Connection": "close", "Cache-Control": "no-store", "User-Agent": "fortipam-mcp-service-credential/1"}
                if method in ("POST", "DELETE"):
                    headers["X-CSRFTOKEN"] = csrf
                    if method == "POST":
                        headers["Content-Type"] = "application/json"
                return headers
        except Exception:
            raise WindowsServiceCredentialOwnerAuthError(_ERROR) from None


def check_owner_session_binding(config: SecretMetadataHttpTransportConfig,
        binding: WindowsServiceCredentialOwnerBinding | None,
        session: WindowsServiceCredentialOwnerSession | None, *, purpose: Literal["create", "recovery"]) -> None:
    """Refuse implicit fallback or an unbound Cookie/Bearer principal change."""
    if binding is None:
        if session is not None:
            raise ValueError
    elif (type(session) is not WindowsServiceCredentialOwnerSession or session._config != config
            or session.binding != binding or session._purpose != purpose):
        raise ValueError
