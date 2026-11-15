"""Private build-29 BP005 requester session for the fixed Request transport."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
import hmac
import json
from pathlib import Path
import re
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_owner_session import _LoginForm
from .local_user_reset_projection import _object_spans
from .secret_request_create_contract import (
    REQUEST_CREATE_PATH, REQUEST_DEFAULT_QUERY, SecretRequestDefaultEvidence,
    REQUEST_CREATE_POST_QUERY,
    validate_secret_request_default_response,
)
from .secret_request_collection_http_transport import (
    REQUEST_CREATOR_COLLECTION_QUERY, SecretRequestCreatorSnapshot,
    _REQUEST_BODY, _parse_snapshot,
)
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, _json_value_end, _skip_json_space,
    _ssl_context, _zeroize_mutable,
)
from .secret_request_create_invocation_witness import SecretRequestCreateInvocationWitnessSink
from .secret_request_create_http_transport import (
    FortiPamSecretRequestCreateHttpTransport,
    OwnerOnlySecretRequestCreateBindingResolver,
    OwnerOnlySecretRequestCreateDispatchClaim,
)
from .secret_request_http_transport import (
    FortiPamSecretRequestHttpTransport, SecretRequestObservation,
    SecretRequestHttpTransportError,
    _REQUEST_DETAIL_QUERY, _REQUEST_DETAIL_V70_QUERY,
    _extract_record_fields, _positive_id, _server_date,
)

_UNAVAILABLE = "The fixed Request requester session is unavailable."
_STATE = "/api/v2/monitor/web-ui/state"
_LIMIT = 1_048_576
_BP005_PREFIX = "FORTIPAM_MCP_V4_LOCAL_USER_CREATE_ACTION_BP005_"


class SecretRequestRequesterSessionError(RuntimeError):
    """Never include private identities, cookies or upstream response text."""


def build_bp005_requester_session(
    config: SecretMetadataHttpTransportConfig, environment: Mapping[str, str],
) -> FixedSecretRequestRequesterSession:
    """Reuse the active BP005 provider; defer material access until actor login."""
    try:
        from .local_user_reset_material_source import _directory_identity, _read_material
        requester = environment[_BP005_PREFIX + "USERNAME"]
        directory = Path(environment[_BP005_PREFIX + "MATERIAL_DIRECTORY"])
        identity = _directory_identity(directory)

        def credentials() -> tuple[str, str]:
            material = bytearray()
            try:
                material, count = _read_material(directory, identity, "initial-password")
                del material[count:]
                return requester, material.decode("ascii")
            except Exception:
                raise SecretRequestRequesterSessionError(_UNAVAILABLE) from None
            finally:
                _zeroize_mutable(material)

        return FixedSecretRequestRequesterSession(
            config, requester=requester, credentials=credentials,
        )
    except Exception:
        raise SecretRequestRequesterSessionError(_UNAVAILABLE) from None


class FixedSecretRequestRequesterSession:
    """One protected login; exact actor check; retained-cookie logout proof.

    This private composition dependency does not grant dispatch authority.
    The Request transport still owns intent resolution, claims and readback.
    """

    def __init__(self, config: SecretMetadataHttpTransportConfig, *, requester: str,
                 credentials: Callable[[], tuple[str, str]],
                 client_factory: Callable[..., Any] = httpx.Client) -> None:
        try:
            if type(config) is not SecretMetadataHttpTransportConfig:
                raise ValueError
            origin = urlsplit(config.base_url)
            if (origin.scheme != "https" or not origin.hostname or origin.username
                    or origin.password or origin.path not in {"", "/"}
                    or origin.query or origin.fragment or not 1 <= (origin.port or 443) <= 65535
                    or type(requester) is not str or re.fullmatch(
                        r"mcp-v4-user-bp005-standard-[0-9]{8}-[a-f0-9]{8}", requester) is None
                    or not callable(credentials) or not callable(client_factory)):
                raise ValueError
            self._tls = _ssl_context(config)
        except Exception:
            raise SecretRequestRequesterSessionError(_UNAVAILABLE) from None
        self._config, self._requester = config, requester
        self._credentials, self._factory = credentials, client_factory
        self._client: Any = None
        self._csrf: str | None = None
        self._started = self._authenticated = self._login_attempted = False
        self._closed = False
        self._cleanup_verified: bool | None = None
        self._stage = "not_started"
        self._post_attempted = False

    def compose_create_transport(
        self, *, binding_resolver: OwnerOnlySecretRequestCreateBindingResolver,
        dispatch_claim: OwnerOnlySecretRequestCreateDispatchClaim,
        authorized_environment_ref: str, authorized_scope_ref: str,
        invocation_witness_sink: SecretRequestCreateInvocationWitnessSink | None = None,
    ) -> FortiPamSecretRequestCreateHttpTransport:
        """Bind every dependency to this session; the transport owns the claim."""
        return FortiPamSecretRequestCreateHttpTransport(
            self._config, binding_resolver=binding_resolver,
            dispatch_claim=dispatch_claim,
            authorized_environment_ref=authorized_environment_ref,
            authorized_scope_ref=authorized_scope_ref,
            actor_inspector=self, default_inspector=_RequesterDefault(self),
            collection=self, detail_observer=self,
            request_dispatcher=self._dispatch_request_once,
            session_finalizer=self.finalize,
            invocation_witness_sink=invocation_witness_sink,
        )

    def _read(self, path: str) -> tuple[int, bytearray]:
        if path not in {"/remote/login?lang=en", _STATE, "/logout"}:
            raise ValueError
        content = bytearray()
        try:
            with self._client.stream("GET", path) as response:
                for chunk in response.iter_bytes():
                    if len(content) + len(chunk) > _LIMIT:
                        raise ValueError
                    content.extend(chunk)
                return response.status_code, content
        except Exception:
            _zeroize_mutable(content)
            raise

    def inspect(self, expected_requester: str) -> None:
        """Implement the exact-actor inspector without API-principal substitution."""
        if (self._started or self._closed or type(expected_requester) is not str
                or not hmac.compare_digest(expected_requester, self._requester)):
            raise SecretRequestRequesterSessionError(_UNAVAILABLE)
        self._started = True
        raw = bytearray()
        try:
            self._client = self._factory(
                base_url=self._config.base_url, verify=self._tls,
                timeout=self._config.timeout_seconds, follow_redirects=False, trust_env=False,
                headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache, no-store"},
            )
            self._stage = "login_page"
            status, raw = self._read("/remote/login?lang=en")
            form = _LoginForm()
            form.feed(raw.decode("utf-8"))
            if status != 200 or form.matches != 1:
                raise ValueError
            _zeroize_mutable(raw)
            self._stage = "credential_provider"
            username, password = self._credentials()
            if (username != self._requester or type(password) is not str
                    or not 1 <= len(password) <= 4096):
                raise ValueError
            self._stage = "login_redirect"
            self._login_attempted = True
            try:
                with self._client.stream("POST", "/XX/YY/ZZ/AUTH", data={
                    "username": username, "password": password, "magic": "0",
                    "4Tredir": "/", "4Tmthd": "0",
                }) as response:
                    location = response.headers.get("location", "")
                    parsed = urlsplit(location)
                    if (response.status_code != 303 or not location.startswith("/")
                            or location.startswith("//") or parsed.scheme or parsed.netloc
                            or parsed.path.startswith("/api/") or "\\" in location
                            or any(ord(c) < 32 for c in location) or len(location) > 2048):
                        raise ValueError
            finally:
                del username, password
            self._stage = "landing"
            with self._client.stream("GET", location) as response:
                if response.status_code != 200:
                    raise ValueError
            self._stage = "actor"
            status, raw = self._read(_STATE)
            if status != 200:
                raise ValueError
            _actor_context(raw, expected_name=self._requester)
            left = _skip_json_space(raw, 0)
            right = _json_value_end(raw, left)
            root = _object_spans(raw, left, right)
            fields = _object_spans(raw, *root["results"])
            self._stage = "csrf"
            cookie_name = json.loads(raw[slice(*fields["ccsrf_token_cookie_name"])])
            if type(cookie_name) is not str or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", cookie_name) is None:
                raise ValueError
            token = self._client.cookies.get(cookie_name)
            if type(token) is not str:
                raise ValueError
            token = token.strip('"')
            if re.fullmatch(r"[A-Za-z0-9._~-]{1,256}", token) is None:
                raise ValueError
            self._csrf, self._authenticated = token, True
        except Exception:
            self.finalize()
            raise SecretRequestRequesterSessionError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(raw)

    def _request_read(self, *, creator: bool) -> bytearray:
        """Two fixed reads only; the POST uses the native GET override."""
        raw = bytearray()
        try:
            if not self._authenticated or self._closed or self._csrf is None:
                raise ValueError
            headers = {"Accept": "application/json"}
            if creator:
                headers.update({"X-HTTP-Method-Override": "GET",
                                "X-Requested-With": "XMLHttpRequest",
                                "X-CSRFTOKEN": self._csrf,
                                "Content-Type": "application/json"})
            query = REQUEST_CREATOR_COLLECTION_QUERY if creator else REQUEST_DEFAULT_QUERY
            with self._client.stream(
                "POST" if creator else "GET", REQUEST_CREATE_PATH + "?" + query,
                headers=headers, content=_REQUEST_BODY if creator else None,
            ) as response:
                if (response.status_code != 200 or
                    response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                        != "application/json"):
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > _LIMIT:
                        raise ValueError
                    raw.extend(chunk)
            return raw
        except Exception:
            _zeroize_mutable(raw)
            raise SecretRequestRequesterSessionError(_UNAVAILABLE) from None

    def read_request_default(self) -> SecretRequestDefaultEvidence:
        raw = self._request_read(creator=False)
        try:
            result = validate_secret_request_default_response(json.loads(raw))
            if (result.fortipam_version, result.fortipam_build) != ("7.0.0", 29):
                raise ValueError
            return result
        except Exception:
            raise SecretRequestRequesterSessionError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(raw)

    def snapshot(self) -> SecretRequestCreatorSnapshot:
        raw = self._request_read(creator=True)
        try:
            result = _parse_snapshot(raw)
            if (result.fortipam_version, result.fortipam_build) != ("7.0.0", 29):
                raise ValueError
            return result
        except Exception:
            raise SecretRequestRequesterSessionError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(raw)

    def _dispatch_request_once(self, body: memoryview) -> int:
        """Private fixed POST; called only after the create transport's claim."""
        try:
            if (not self._authenticated or self._closed or self._csrf is None
                    or self._post_attempted or not isinstance(body, memoryview)
                    or not body.readonly or not 0 < len(body) <= _LIMIT):
                raise ValueError
            # Set before touching the network: failures cannot retry a POST.
            self._post_attempted = True
            with self._client.stream(
                "POST", REQUEST_CREATE_PATH + "?" + REQUEST_CREATE_POST_QUERY,
                headers={"Accept": "application/json", "Content-Type": "application/json",
                         "Content-Length": str(len(body)),
                         "X-Requested-With": "XMLHttpRequest", "X-CSRFTOKEN": self._csrf},
                content=iter((body,)),
            ) as response:
                # Never consume the POST response, including rejection bodies.
                return int(response.status_code)
        except Exception:
            raise SecretRequestRequesterSessionError(_UNAVAILABLE) from None

    def _request_detail_read(
        self, request_id: int, query: str,
    ) -> tuple[int, dict[str, object] | None, datetime | None]:
        raw = bytearray()
        try:
            identifier = _positive_id(request_id)
            if (not self._authenticated or self._closed or self._csrf is None
                    or query not in {_REQUEST_DETAIL_QUERY, _REQUEST_DETAIL_V70_QUERY}):
                raise ValueError
            with self._client.stream(
                "GET", f"{REQUEST_CREATE_PATH}/{identifier}?{query}",
                headers={"Accept": "application/json"},
            ) as response:
                status = int(response.status_code)
                if status != 200:
                    return status, None, None
                if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
                    raise ValueError
                date = _server_date(response.headers.get("date", ""))
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > _LIMIT:
                        raise ValueError
                    raw.extend(chunk)
            root_start = _skip_json_space(raw, 0)
            root_end = _json_value_end(raw, root_start)
            root = _object_spans(raw, root_start, root_end)
            for key, expected in {"version": "v7.0.0", "build": 29,
                                  "path": "secret", "name": "request",
                                  "vdom": "root", "http_method": "GET",
                                  "http_status": 200, "status": "success"}.items():
                actual = json.loads(raw[slice(*root[key])])
                if type(actual) is not type(expected) or actual != expected:
                    raise ValueError
            return status, _extract_record_fields(raw), date
        except Exception:
            raise SecretRequestRequesterSessionError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(raw)

    def observe(
        self, request_id: int, *, expected_secret_id: int,
        expected_request_type: str = "launcher",
    ) -> SecretRequestObservation:
        """Reuse the existing categorical observer under the same cookie actor."""
        if expected_request_type not in {"launcher", "job"}:
            raise SecretRequestRequesterSessionError(_UNAVAILABLE)
        return FortiPamSecretRequestHttpTransport(
            self._config, request_reader=self._request_detail_read,
        ).observe(request_id, expected_secret_id=expected_secret_id,
                  expected_request_type="launcher" if expected_request_type == "launcher" else "job")

    def finalize(self) -> bool:
        """Idempotent cleanup; require server rejection of the pre-logout cookie."""
        if self._cleanup_verified is not None:
            return self._cleanup_verified
        self._closed = True
        self._cleanup_verified = False
        cookies = None
        raw = bytearray()
        try:
            if not self._login_attempted:
                self._cleanup_verified = True
            else:
                cookies = httpx.Cookies(self._client.cookies)
                status, raw = self._read("/logout")
                _zeroize_mutable(raw)
                self._client.cookies.clear()
                self._client.cookies.update(cookies)
                denied, raw = self._read(_STATE)
                self._cleanup_verified = status in {200, 302, 303} and denied in {401, 403}
        except Exception:
            self._cleanup_verified = False
        finally:
            _zeroize_mutable(raw)
            self._csrf, self._authenticated = None, False
            if cookies is not None:
                cookies.clear()
            if self._client is not None:
                try:
                    self._client.cookies.clear()
                    self._client.close()
                except Exception:
                    self._cleanup_verified = False
        return self._cleanup_verified


class _RequesterDefault:
    def __init__(self, session: FixedSecretRequestRequesterSession) -> None:
        self._session = session

    def inspect(self) -> SecretRequestDefaultEvidence:
        return self._session.read_request_default()


class _RequesterObservationTransport(FortiPamSecretRequestHttpTransport):
    """Use a fresh exact-user session for each bound read and verify logout."""

    def __init__(self, prototype: FixedSecretRequestRequesterSession) -> None:
        super().__init__(prototype._config)
        self._prototype = prototype

    def observe(
        self, request_id: int, *, expected_secret_id: int,
        expected_request_type: Literal["launcher", "job"] = "launcher",
    ) -> SecretRequestObservation:
        # Validate selectors before opening a session. The protected observer
        # resolves its caller/opaque binding before reaching this transport.
        _positive_id(request_id)
        _positive_id(expected_secret_id)
        if expected_request_type not in {"launcher", "job"}:
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        prototype = self._prototype
        session = FixedSecretRequestRequesterSession(
            prototype._config, requester=prototype._requester,
            credentials=prototype._credentials, client_factory=prototype._factory,
        )
        try:
            session.inspect(prototype._requester)
            return session.observe(
                request_id, expected_secret_id=expected_secret_id,
                expected_request_type=expected_request_type,
            )
        except Exception:
            raise SecretRequestHttpTransportError(_UNAVAILABLE) from None
        finally:
            # Do not publish a state result if session revocation is unproven.
            if session.finalize() is not True:
                raise SecretRequestHttpTransportError(_UNAVAILABLE)


def build_bp005_requester_observation_transport(
    config: SecretMetadataHttpTransportConfig, environment: Mapping[str, str],
) -> FortiPamSecretRequestHttpTransport:
    """Pin the existing provider once; defer credentials to each bound read."""
    return _RequesterObservationTransport(
        build_bp005_requester_session(config, environment),
    )
