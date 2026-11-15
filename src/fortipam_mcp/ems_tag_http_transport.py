"""Private fixed EMS login/read/logout channel; no Tag mutation or MCP Tool.

Protected composition loads central credentials directly. Physical routing,
hostname/CA verification and the original peer must all match. Only fixed
catalog IDs become detail routes; no caller REST method, query or JSON exists.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import http.client
import http.cookiejar
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import ssl
from threading import RLock
from typing import Any
from urllib.request import Request

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest

from .ems_tag_contract import DisabledLinuxProcessTag, _envelope, qualify_tag_catalog
from .ems_tag_custody import _pairs, _nonfinite
from .ems_tag_sources import CATALOG_PATH, METADATA_PATH, EmsTagSources
from .secret_metadata_http_transport import _zeroize_mutable

_ERROR = "The private EMS tag HTTP channel is unavailable."
_SIGNIN = "/api/v1/auth/signin"
_SIGNOUT = "/api/v1/auth/signout"
_CHECK = "/api/v1/session/check"
_DETAIL = re.compile(r"/api/v1/tags/zero_trust/([1-9][0-9]{0,9})/get\Z")


class EmsTagHttpError(RuntimeError):
    """No credentials, route values or native response in failures."""


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagHttpConfig(_OpaqueC3Object):
    hostname: str
    address: str
    local_address: str
    interface_index: int
    ca_file: Path
    ca_sha256: str
    peer_sha256: str
    port: int = 443

    def __post_init__(self) -> None:
        try:
            if (type(self.hostname) is not str or len(self.hostname) > 253
                    or re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", self.hostname) is None
                    or type(self.port) is not int or self.port != 443
                    or type(self.interface_index) is not int or not 0 < self.interface_index < 2**31
                    or not isinstance(self.ca_file, Path) or not self.ca_file.is_absolute()
                    or not self.ca_file.is_file()):
                raise ValueError
            for address in (self.address, self.local_address):
                if type(address) is not str or str(ipaddress.IPv4Address(address)) != address:
                    raise ValueError
            for digest in (self.ca_sha256, self.peer_sha256):
                require_digest(digest, "ems_http_peer")
            if hashlib.sha256(self.ca_file.read_bytes()).hexdigest() != self.ca_sha256:
                raise ValueError
        except Exception:
            raise EmsTagHttpError(_ERROR) from None

    @property
    def binding_digest(self) -> str:
        self.__post_init__()
        return canonical_digest({"contract": "ems-7.4.8.2245-protected-fixed-http-v1",
            "hostname": self.hostname, "address": self.address, "port": self.port,
            "local_address": self.local_address, "interface_index": self.interface_index,
            "ca_file": str(self.ca_file), "ca_sha256": self.ca_sha256, "peer_sha256": self.peer_sha256,
            "login_site_field": "omitted"})


@dataclass(frozen=True, slots=True, repr=False)
class EmsTagSessionClosure(_OpaqueC3Object):
    own_logout_verified: bool
    next_session_check_401: bool
    cookie_jar_cleared: bool
    owned_mutable_buffers_cleared: bool
    connections_closed: bool
    failure_stage: str | None = None
    logout_http_status: int | None = None


class NativeEmsTagHttpTransport(_OpaqueC3Object):
    """One protected session, bounded fixed reads and one ordinary own logout."""

    def __init__(self, config: EmsTagHttpConfig, *,
                 owner_credentials: Callable[[], tuple[str, str]]) -> None:
        try:
            if type(config) is not EmsTagHttpConfig or not callable(owner_credentials):
                raise ValueError
            config.__post_init__()
            self._config, self._binding, self._credentials = config, config.binding_digest, owner_credentials
            self._tls = ssl.create_default_context()
            self._tls.load_verify_locations(cafile=config.ca_file)
            self._tls.minimum_version = ssl.TLSVersion.TLSv1_2
            self._jar = http.cookiejar.CookieJar()
            self._live = self._closed = self._failed = False
            self._connections_closed = self._buffers_cleared = True
            self._owner: str | None = None
            self._counts: dict[str, int] = {}
            self._detail_ids: set[int] = set()
            self._rule_set_metadata_source: object | None = None
            self._request_stage = "not_started"
            self._response_status: int | None = None
            self._lock = RLock()
            self._closure: EmsTagSessionClosure | None = None
        except Exception:
            raise EmsTagHttpError(_ERROR) from None

    def _pins(self) -> None:
        self._config.__post_init__()
        if (self._config.binding_digest != self._binding or self._closed
                or self._tls.check_hostname is not True or self._tls.verify_mode != ssl.CERT_REQUIRED
                or self._tls.minimum_version < ssl.TLSVersion.TLSv1_2):
            raise ValueError

    def _connect(self, *, timeout_seconds: float = 10) -> http.client.HTTPSConnection:
        self._pins()
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= 10):
            raise ValueError
        c = self._config
        current = {item[4][0] for item in socket.getaddrinfo(c.hostname, c.port, socket.AF_INET, socket.SOCK_STREAM)}
        if current != {c.address}:
            raise ValueError
        channel = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection = http.client.HTTPSConnection(c.hostname, c.port, timeout=timeout_seconds, context=self._tls)
        try:
            channel.settimeout(timeout_seconds)
            channel.setsockopt(socket.IPPROTO_IP, 25, c.interface_index)
            channel.bind((c.local_address, 0))
            channel.connect((c.address, c.port))
            connection.sock = self._tls.wrap_socket(channel, server_hostname=c.hostname)
            certificate = connection.sock.getpeercert(binary_form=True)
            if (type(certificate) is not bytes
                    or not hmac.compare_digest(hashlib.sha256(certificate).hexdigest(), c.peer_sha256)):
                raise ValueError
            connection.debuglevel = 0
            return connection
        except BaseException:
            connection.close()
            channel.close()
            raise

    def _headers(self, method: str, path: str, body: bytearray | None) -> Request:
        origin = "https://" + self._config.hostname
        headers = {"Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close",
                   "Ems-Call-Type": "1", "Origin": origin, "Referer": origin + "/"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        tokens = []
        for cookie in self._jar:
            if cookie.domain.lstrip(".") != self._config.hostname:
                raise ValueError
            if cookie.name == "csrftoken":
                if type(cookie.value) is not str or not cookie.value:
                    raise ValueError
                tokens.append(cookie.value)
        if len(tokens) > 1 or len(list(self._jar)) > 16:
            raise ValueError
        if tokens:
            headers["X-CSRFToken"] = tokens[0]
        request = Request(origin + path, headers=headers, method=method)
        self._jar.add_cookie_header(request)
        return request

    def _reserve(self, method: str, path: str) -> tuple[str, int]:
        self._pins()
        if self._failed and path not in {_SIGNOUT, _CHECK}:
            raise ValueError
        key = path
        if method == "GET" and path == "/":
            maximum, ceiling = 2097152, 1
            if self._live or self._counts.get(_SIGNIN, 0):
                raise ValueError
        elif method == "POST" and path == _SIGNIN:
            maximum, ceiling = 2097152, 1
            if self._live or not self._counts.get("/", 0):
                raise ValueError
        elif method == "POST" and path == _SIGNOUT:
            maximum, ceiling = 65536, 1
            if not self._counts.get(_SIGNIN, 0):
                raise ValueError
        elif method == "GET" and path == _CHECK:
            maximum, ceiling = 65536, 1
            if not self._counts.get(_SIGNOUT, 0):
                raise ValueError
        elif method == "GET" and path in {METADATA_PATH, CATALOG_PATH}:
            if not self._live:
                raise ValueError
            maximum, ceiling = (2097152, 12) if path == METADATA_PATH else (262144, 18)
        else:
            match = _DETAIL.fullmatch(path) if type(path) is str else None
            if (method != "GET" or match is None or not self._live
                    or int(match[1]) not in self._detail_ids):
                raise ValueError
            maximum, ceiling = 262144, 12
        if self._counts.get(key, 0) >= ceiling:
            raise ValueError
        self._counts[key] = self._counts.get(key, 0) + 1
        return key, maximum

    @staticmethod
    def _consume(response: http.client.HTTPResponse, raw: bytearray, maximum: int) -> None:
        fields = response.getheaders()
        for name in ("content-length", "transfer-encoding", "content-type", "content-encoding"):
            if sum(key.lower() == name for key, _ in fields) > 1:
                raise ValueError
        length = response.getheader("Content-Length")
        transfer = response.getheader("Transfer-Encoding")
        if (response.getheader("Content-Encoding", "identity") not in {"", "identity"}
                or length is not None and (not length.isdecimal() or int(length) > maximum)
                or transfer is not None and (transfer.lower() != "chunked" or not response.chunked or length is not None)):
            raise ValueError
        while True:
            block = response.read(min(32768, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
            if len(raw) > maximum:
                raise ValueError
        if (length is not None and len(raw) != int(length)
                or response.chunked and response.chunk_left is not None):
            raise ValueError

    def _request(self, method: str, path: str, body: bytearray | None = None) -> tuple[int, Any]:
        raw = bytearray()
        connection = response = None
        try:
            self._request_stage, self._response_status = "route_guard", None
            _, maximum = self._reserve(method, path)
            if body is not None and path != _SIGNIN:
                raise ValueError
            request = self._headers(method, path, body)
            self._request_stage = "connect"
            connection = self._connect()
            self._request_stage = "request"
            connection.request(method, path, body=body, headers=dict(request.header_items()))
            self._request_stage = "response_headers"
            response = connection.getresponse()
            self._response_status = response.status
            self._jar.extract_cookies(response, request)
            foreign = [cookie for cookie in self._jar if cookie.domain.lstrip(".") != self._config.hostname]
            for cookie in foreign:
                self._jar.clear(cookie.domain, cookie.path, cookie.name)
            if foreign:
                raise ValueError
            if path == _CHECK and response.status == 401:
                self._request_stage = "done"
                return 401, None
            self._request_stage = "response_framing"
            self._consume(response, raw, maximum)
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != ("text/html" if path == "/" else "application/json"):
                raise ValueError
            self._request_stage = "json_decode"
            decoded = None if path == "/" else json.loads(raw, object_pairs_hook=_pairs, parse_constant=_nonfinite)
            self._request_stage = "done"
            return response.status, decoded
        except Exception:
            self._failed = True
            raise EmsTagHttpError(_ERROR) from None
        finally:
            _zeroize_mutable(raw)
            if body is not None:
                _zeroize_mutable(body)
            self._buffers_cleared = self._buffers_cleared and not raw and (body is None or not body)
            for resource in (response, connection):
                if resource is not None:
                    try:
                        resource.close()
                    except Exception:
                        self._connections_closed = False

    def authenticate(self) -> None:
        body = bytearray()
        credentials: tuple[str, str] | None = None
        try:
            with self._lock:
                if self._closed or self._failed or self._counts:
                    raise ValueError
                status, _ = self._request("GET", "/")
                if status != 200:
                    raise ValueError
                credentials = self._credentials()
                if (type(credentials) is not tuple or len(credentials) != 2
                        or any(type(item) is not str or not item or "\x00" in item for item in credentials)
                        or len(credentials[0]) > 256 or len(credentials[1]) > 4096):
                    raise ValueError
                owner = credentials[0].casefold()
                body = bytearray(json.dumps({"name": credentials[0], "password": credentials[1]},
                    separators=(",", ":")).encode())
                status, reply = self._request("POST", _SIGNIN, body)
                if status != 200:
                    raise ValueError
                _envelope(reply)
                self._owner, self._live = owner, True
        except Exception:
            self._failed = True
            raise EmsTagHttpError(_ERROR) from None
        finally:
            credentials = None
            _zeroize_mutable(body)

    def get_json(self, path: str) -> object:
        try:
            with self._lock:
                if self._failed or not self._live or path in {"/", _CHECK}:
                    raise ValueError
                status, reply = self._request("GET", path)
                if status != 200:
                    raise ValueError
                _envelope(reply)
                if path == CATALOG_PATH:
                    catalog = qualify_tag_catalog(reply)
                    if catalog.count > 17:
                        raise ValueError
                    self._detail_ids = set(catalog._ids)
                return reply
        except Exception:
            self._failed = True
            raise EmsTagHttpError(_ERROR) from None

    def make_sources(self, draft: DisabledLinuxProcessTag, *, source_key: bytes) -> EmsTagSources:
        try:
            with self._lock:
                self._pins()
                if not self._live or self._failed or self._owner is None:
                    raise ValueError
                return EmsTagSources(draft=draft, owner_name=self._owner,
                    instance_scope_digest=self._binding, source_key=source_key, get_json=self.get_json)
        except Exception:
            raise EmsTagHttpError(_ERROR) from None

    def session_binding_digest(self, witness_key: bytes) -> str:
        """Compare real owner sessions without exporting or storing a cookie."""
        raw = bytearray()
        try:
            with self._lock:
                self._pins()
                if (not self._live or self._failed or self._owner is None
                        or type(witness_key) is not bytes or not 32 <= len(witness_key) <= 4096):
                    raise ValueError
                cookies = [cookie for cookie in self._jar if cookie.name == "sessionid"
                    and cookie.domain.lstrip(".") == self._config.hostname]
                if (len(cookies) != 1 or type(cookies[0].value) is not str
                        or not 0 < len(cookies[0].value) <= 4096 or "\x00" in cookies[0].value):
                    raise ValueError
                digest = hmac.new(witness_key, b"ems-real-owner-session-binding/v1\x00", hashlib.sha256)
                digest.update(self._binding.encode());digest.update(b"\x00")
                digest.update(self._owner.encode());digest.update(b"\x00")
                raw = bytearray(cookies[0].value.encode())
                digest.update(raw)
                return digest.hexdigest()
        except Exception:
            raise EmsTagHttpError(_ERROR) from None
        finally:
            _zeroize_mutable(raw)

    def close(self) -> EmsTagSessionClosure:
        with self._lock:
            if self._closure is not None:
                return self._closure
            logout = denied = False
            stage: str | None = None
            logout_status: int | None = None
            try:
                if self._counts.get(_SIGNIN, 0) and not self._counts.get(_SIGNOUT, 0):
                    stage = "logout_request"
                    status, reply = self._request("POST", _SIGNOUT)
                    logout_status, stage = status, "logout_envelope"
                    if type(reply) is not dict or set(reply) != {"result"}:
                        raise ValueError
                    result = reply["result"]
                    if (type(result) is not dict or set(result) != {"retval", "message"}
                            or type(result["retval"]) is not int or result["retval"] != 1
                            or type(result["message"]) is not str or len(result["message"]) > 4096
                            or "\x00" in result["message"]):
                        raise ValueError
                    logout = status == 200
                    stage = None if logout else "logout_status"
            except Exception:
                if stage == "logout_request":
                    stage, logout_status = "logout_" + self._request_stage, self._response_status
            finally:
                self._live = False
            try:
                if logout:
                    stage = "post_logout_check"
                    status, _ = self._request("GET", _CHECK)
                    denied = status == 401
                    if denied:
                        stage = None
            except Exception:
                pass
            self._jar.clear()
            self._closed = True
            self._closure = EmsTagSessionClosure(logout, denied, not bool(list(self._jar)),
                self._buffers_cleared, self._connections_closed, stage, logout_status)
            return self._closure
