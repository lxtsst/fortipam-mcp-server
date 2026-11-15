"""Private, short-lived 7.0 Owner login for fixed collector metadata reads.

The host supplies the protected login provider and exact collector selectors.
The fixed CREATE bridge is separately opt-in; no tools are registered here.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from contextlib import contextmanager
import json
import http.client
from http.cookies import SimpleCookie
import time
import threading
from typing import Any, Iterator, Literal
from urllib.parse import quote, urlsplit

import httpx

from .secret_metadata_http_transport import (
    COLLECTION_PATH, MAX_RESPONSE_BYTES, SYSTEM_STATUS_PATH, TEMPLATE_COLLECTION_PATH,
    UTILITY_ID_PATH, FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig,
    SecretMetadataHttpTransportError, _folder_path, _path_for_url, _record,
    _redact_json_field_values, _segment, _ssl_context, _zeroize_mutable,
    _WINRM_COLLECTOR_DETAIL_QUERY, _DOMAIN_ACCOUNT_DETAIL_QUERY, _json_value_end, _skip_json_space,
)
from .folder_acl_live_workflow import _relations
from .local_user_reset_metadata_reader import _validate_value
from .local_user_reset_projection import _object_spans
from .target_contract import DOMAIN_TEMPLATE, DOMAIN_TEMPLATE_FIELD_TYPES

_UNAVAILABLE = "The private Owner metadata session is unavailable."
_DOMAIN_TEMPLATE_PATH = TEMPLATE_COLLECTION_PATH + "/" + quote(DOMAIN_TEMPLATE, safe="")


def _domain_template_metadata(content: bytearray) -> dict[str, object]:
    """Project fixed Template definitions without decoding response values."""
    start = _skip_json_space(content, 0)
    end = _json_value_end(content, start)
    if _skip_json_space(content, end) != len(content):
        raise ValueError
    _validate_value(content, start, end, depth=0)
    envelope = _object_spans(content, start, end)

    def exact(spans: dict[str, tuple[int, int]], key: str, choices: tuple[object, ...]) -> object:
        with memoryview(content)[slice(*spans[key])] as token:
            for value in choices:
                if token == json.dumps(value).encode("ascii"):
                    return value
        raise ValueError

    expected = {
        "version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
        "status": "success", "path": "secret", "name": "template", "vdom": "root",
    }
    projected = {key: exact(envelope, key, (value,)) for key, value in expected.items()}
    if "error" in envelope:
        projected["error"] = exact(envelope, "error", (None, 0))
    left, right = envelope["results"]
    if content[left] == 91:
        left = _skip_json_space(content, left + 1)
        row_end = _json_value_end(content, left)
        if _skip_json_space(content, row_end) != right - 1:
            raise ValueError
        right = row_end
    row = _object_spans(content, left, right)
    name = exact(row, "name", (DOMAIN_TEMPLATE,))
    left, right = row["field" if "field" in row else "fields"]
    if content[left] != 91 or content[right - 1] != 93:
        raise ValueError
    fields: list[dict[str, object]] = []
    cursor = _skip_json_space(content, left + 1)
    while cursor < right - 1:
        if len(fields) >= len(DOMAIN_TEMPLATE_FIELD_TYPES):
            raise ValueError
        field_end = _json_value_end(content, cursor)
        field = _object_spans(content, cursor, field_end)
        fields.append({
            "name": exact(field, "name", tuple(name for name, _ in DOMAIN_TEMPLATE_FIELD_TYPES)),
            "type": exact(field, "type", tuple(kind for _, kind in DOMAIN_TEMPLATE_FIELD_TYPES)),
        })
        cursor = _skip_json_space(content, field_end)
        if cursor == right - 1:
            break
        if content[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(content, cursor + 1)
    if len(fields) != len(DOMAIN_TEMPLATE_FIELD_TYPES):
        raise ValueError
    projected["results"] = [{"name": name, "field": fields}]
    return projected


class OwnerSessionMetadataTransport(FortiPamSecretMetadataHttpTransport):
    """Scoped reads under the Owner; a separately pinned API reader is witness."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, *, owner_name: str,
                 credentials: Callable[[], tuple[str, str]], folder_path: str,
                 secret_name: str, target_name: str,
                 witness: FortiPamSecretMetadataHttpTransport,
                 client_factory: Callable[..., Any] = httpx.Client,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
                 allow_secret_create: bool = False,
                 allow_collector_credential_repair: bool = False,
                 clock: Callable[[], float] = time.monotonic) -> None:
        parsed = urlsplit(config.base_url)
        if parsed.username is not None or parsed.password is not None:
            raise ValueError(_UNAVAILABLE)
        _segment(owner_name)
        _segment(secret_name)
        _segment(target_name)
        folder = _folder_path(folder_path)
        if type(allow_secret_create) is not bool or type(allow_collector_credential_repair) is not bool:
            raise ValueError(_UNAVAILABLE)
        super().__init__(config, bound_secret_name=secret_name,
                         collector_witness_transport=witness,
                         detail_connection_factory=self._metadata_connection)
        self._owner_name = owner_name
        self._credentials = credentials
        self._session_factory = client_factory
        self._raw_connection_factory = connection_factory
        self._allow_secret_create = allow_secret_create
        self._create_dispatched = False
        self._allow_collector_credential_repair = allow_collector_credential_repair
        self._collector_credential_repair_lock = threading.Lock()
        self._collector_credential_repair_reserved = False
        self._collector_credential_repair_dispatched = False
        self._clock = clock
        self._client: Any = None
        self._session_lock = threading.Lock()
        self._expires_at = 0.0
        self._folder_id: int | None = None
        self._secret_id: int | None = None
        self._allowed_paths = {
            SYSTEM_STATUS_PATH,
            TEMPLATE_COLLECTION_PATH + "/" + quote("Windows Machine", safe=""),
            _DOMAIN_TEMPLATE_PATH,
            "/api/v2/cmdb/secret/target/" + quote(target_name, safe=""),
            UTILITY_ID_PATH + "/" + _path_for_url(folder),
            UTILITY_ID_PATH + "/" + _path_for_url(folder + "/" + secret_name),
        }
        self._folder_lookup_path = UTILITY_ID_PATH + "/" + _path_for_url(folder)
        self._secret_lookup_path = UTILITY_ID_PATH + "/" + _path_for_url(folder + "/" + secret_name)
        self.logout_verified = False

    @contextmanager
    def authenticated(self) -> Iterator[OwnerSessionMetadataTransport]:
        """Reject concurrent use rather than mix cookies or bound read state."""
        if not self._session_lock.acquire(blocking=False):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        try:
            with self._authenticated_once():
                yield self
        finally:
            self._session_lock.release()

    @contextmanager
    def _authenticated_once(self) -> Iterator[OwnerSessionMetadataTransport]:
        """Login once, pin firmware, and revoke the session on every exit."""
        if self._client is not None:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        client = self._session_factory(base_url=self._config.base_url,
            verify=_ssl_context(self._config), timeout=self._config.timeout_seconds,
            follow_redirects=False, trust_env=False)
        self._client = client
        self.logout_verified = False
        login_attempted = False
        failed = False
        try:
            page = client.get("/remote/login?lang=en")
            if page.status_code != 200 or 'action="/XX/YY/ZZ/AUTH"' not in page.text:
                raise ValueError
            username, password = self._credentials()
            if username != self._owner_name or not isinstance(password, str) or not password:
                raise ValueError
            login_attempted = True
            response = client.post("/XX/YY/ZZ/AUTH", data={"username": username,
                "password": password, "magic": "0", "4Tredir": "/", "4Tmthd": "0"})
            del username, password
            if response.status_code != 303:
                raise ValueError
            location = response.headers.get("location")
            if not location:
                raise ValueError
            destination = httpx.URL(self._config.base_url).join(location)
            origin = httpx.URL(self._config.base_url)
            if (destination.scheme, destination.host, destination.port) != (origin.scheme, origin.host, origin.port):
                raise ValueError
            if destination.username or destination.password:
                raise ValueError
            client.get(str(destination))
            self._expires_at = self._clock() + 300
            if self.read_product_version_and_build() != ("7.0.0", 29):
                raise ValueError
            yield self
        except Exception:
            failed = True
            raise SecretMetadataHttpTransportError(_UNAVAILABLE) from None
        finally:
            try:
                if login_attempted:
                    logged_out = client.get("/logout")
                    denied = client.get(SYSTEM_STATUS_PATH)
                    self.logout_verified = logged_out.status_code == 200 and denied.status_code in {401, 403}
            except Exception:
                self.logout_verified = False
            finally:
                client.cookies.clear()
                client.close()
                self._client = None
                self._folder_id = None
                self._secret_id = None
                self._expires_at = 0.0
            if login_attempted and not self.logout_verified and not failed:
                raise SecretMetadataHttpTransportError(_UNAVAILABLE)

    def _request(self, method: Literal["GET", "POST", "DELETE"], path: str,
                 body: Mapping[str, object] | None, *, query: str | None = None) -> tuple[int, object | None]:
        folder_detail = self._folder_id is not None and path == f"/api/v2/cmdb/secret/folder/{self._folder_id}"
        create_defaults = self._allow_secret_create and path == COLLECTION_PATH and query == "action=default"
        if (self._client is None or self._clock() >= self._expires_at
            or method != "GET" or body is not None
            or path not in self._allowed_paths and not folder_detail and not create_defaults):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        content = bytearray()
        try:
            url = path + ("?" + query if query else "")
            with self._client.stream("GET", url, headers={"Accept": "application/json"}) as response:
                if "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    content.extend(chunk)
                if path == _DOMAIN_TEMPLATE_PATH:
                    payload = _domain_template_metadata(content)
                else:
                    _redact_json_field_values(content)
                    payload = json.loads(content)
                if path == self._folder_lookup_path and response.status_code == 200:
                    from .secret_metadata_http_transport import _response_id
                    self._folder_id = _response_id(payload)
                if path == self._secret_lookup_path:
                    from .secret_metadata_http_transport import _response_id
                    self._secret_id = _response_id(payload) if response.status_code == 200 else None
                return int(response.status_code), payload
        except Exception:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(content)

    def _verify_collector_folder_acl(self, folder_id: int, owner_name: str) -> bool:
        if folder_id != self._folder_id or owner_name != self._owner_name:
            return False
        status, payload = self._request("GET", f"/api/v2/cmdb/secret/folder/{folder_id}", None,
            query="format=id%7Cinherit-permission%7Cuser-permission%7Cgroup-permission")
        row = _record(payload)
        if (status != 200 or row is None or type(row.get("id")) is not int
            or row.get("id") != folder_id or row.get("inherit-permission") != "disable"
            or row.get("group-permission") != []):
            return False
        users = _relations(row, principal_key="user-name")
        return (len(users) == 1 and users[0].relation_id > 0
            and users[0].names == (owner_name,) and users[0].folder_permission == "owner"
            and users[0].secret_permission == "owner")

    def _request_projection_detail(
        self, secret_id: int, *, winrm_collector: bool = False, domain_account: bool = False,
    ) -> tuple[int, object | None, bool]:
        if (type(secret_id) is not int or secret_id != self._secret_id
            or type(winrm_collector) is not bool or type(domain_account) is not bool
            or winrm_collector == domain_account):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return super()._request_projection_detail(
            secret_id, winrm_collector=winrm_collector, domain_account=domain_account,
        )

    def _metadata_connection(self, *args: Any, **kwargs: Any) -> _OwnerConnection:
        return self._connection(False, *args, **kwargs)

    def secret_create_connection(self, *args: Any, **kwargs: Any) -> _OwnerConnection:
        """Only the protected CREATE bridge may use this opted-in fixed factory."""
        if not self._allow_secret_create or self._create_dispatched:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        return self._connection(True, *args, **kwargs)

    def collector_credential_repair_connection(
        self, *args: Any, secret_id: int, **kwargs: Any,
    ) -> _OwnerConnection:
        """Return one CSRF-bound PUT connection for the resolved collector only."""
        with self._collector_credential_repair_lock:
            if (
                not self._allow_collector_credential_repair
                or self._collector_credential_repair_reserved
                or self._collector_credential_repair_dispatched
                or type(secret_id) is not int
                or secret_id <= 0
                or secret_id != self._secret_id
            ):
                raise SecretMetadataHttpTransportError(_UNAVAILABLE)
            self._collector_credential_repair_reserved = True
            return self._connection(False, *args, repair_secret_id=secret_id, **kwargs)

    def _connection(
        self, create: bool, *args: Any, repair_secret_id: int | None = None, **kwargs: Any,
    ) -> _OwnerConnection:
        parsed = urlsplit(self._config.base_url)
        if args != (parsed.hostname, parsed.port or 443) or self._client is None or self._clock() >= self._expires_at:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        # Never accept another host or caller-selected TLS settings.
        connection = self._raw_connection_factory(parsed.hostname, parsed.port or 443,
            timeout=self._config.timeout_seconds, context=_ssl_context(self._config))
        return _OwnerConnection(self, connection, create, repair_secret_id)


class _OwnerConnection:
    """Preserve mutable-body and pre-decode redaction in the existing bridges."""
    def __init__(
        self, owner: OwnerSessionMetadataTransport, connection: Any, create: bool,
        repair_secret_id: int | None = None,
    ) -> None:
        self._owner, self._connection, self._create = owner, connection, create
        self._repair_secret_id = repair_secret_id

    def request(self, method: str, url: str, body: memoryview | None = None,
                headers: dict[str, str] | None = None) -> None:
        owner = self._owner
        if owner._client is None or owner._clock() >= owner._expires_at:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        repair = self._repair_secret_id is not None
        expected_urls = (
            (COLLECTION_PATH,) if self._create
            else (f"{COLLECTION_PATH}/{self._repair_secret_id}",) if repair
            else tuple(f"{COLLECTION_PATH}/{owner._secret_id}?{query}"
                       for query in (_WINRM_COLLECTOR_DETAIL_QUERY, _DOMAIN_ACCOUNT_DETAIL_QUERY))
        )
        if (url not in expected_urls or method != ("POST" if self._create else "PUT" if repair else "GET")
            or (self._create and (not isinstance(body, memoryview) or owner._create_dispatched))
            or (repair and (
                not owner._allow_collector_credential_repair
                or owner._collector_credential_repair_dispatched
                or not isinstance(body, memoryview)
                or self._repair_secret_id != owner._secret_id
            ))
            or (not self._create and not repair and (body is not None or owner._secret_id is None))):
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        cookie = owner._client.build_request("GET", owner._config.base_url + url).headers.get("cookie")
        if not cookie:
            raise SecretMetadataHttpTransportError(_UNAVAILABLE)
        safe_headers = {"Accept": "application/json", "Cookie": cookie,
            "Connection": "close", "Cache-Control": "no-cache, no-store",
            "User-Agent": owner._client.headers["User-Agent"]}
        if self._create or repair:
            cookies: SimpleCookie = SimpleCookie()
            cookies.load(cookie)
            token = cookies.get("ccsrftoken")
            if token is None or not token.value or len(token.value) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token.value):
                raise SecretMetadataHttpTransportError(_UNAVAILABLE)
            safe_headers.update({"Content-Type": "application/json", "X-CSRFTOKEN": token.value})
            if self._create:
                owner._create_dispatched = True
            else:
                with owner._collector_credential_repair_lock:
                    if (
                        not owner._collector_credential_repair_reserved
                        or owner._collector_credential_repair_dispatched
                    ):
                        raise SecretMetadataHttpTransportError(_UNAVAILABLE)
                    owner._collector_credential_repair_dispatched = True
        self._connection.request(method, url, body=body, headers=safe_headers)

    def getresponse(self) -> Any:
        return self._connection.getresponse()

    def close(self) -> None:
        self._connection.close()
