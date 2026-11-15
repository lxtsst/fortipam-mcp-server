"""Disabled-by-default HTTP transport for bounded FortiPAM Folder contracts.

The transport deliberately exposes only fixed collection, detail, child-create,
and ACL-update operations. It is not a generic REST client: every route and
request shape is compiled into this module, and each dedicated configuration
namespace requires an explicit opt-in flag.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import ssl
from typing import Any, Literal, Protocol, cast
from urllib.parse import urlsplit


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_FOLDER_"
FOLDER_ACL_ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_FOLDER_ACL_"
FOLDER_ARCHIVE_ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_FOLDER_ARCHIVE_"
COLLECTION_PATH = "/api/v2/cmdb/secret/folder"
MAX_REQUEST_BYTES = 16_384
MAX_RESPONSE_BYTES = 1_048_576
MAX_FOLDER_NAME_LENGTH = 64
MAX_FOLDER_ID = 2_147_483_647

_CHILD_FIELDS = frozenset(
    {
        "id",
        "name",
        "inherit-policy",
        "inherit-permission",
        "inherit-folder-ztna",
        "parent-folder",
        "user-permission",
        "group-permission",
    }
)

_UPDATE_FIELDS = frozenset(
    {
        "id",
        "name",
        "parent-folder",
        "folder-type",
        "secret-policy",
        "inherit-policy",
        "inherit-permission",
        "inherit-folder-ztna",
        "ztna-ems-tag",
        "ztna-tags-match-logic",
        "user-permission",
        "group-permission",
    }
)
_MAX_ACL_RELATIONS = 128
_MAX_PRINCIPAL_NAMES_PER_RELATION = 64
_MAX_PRINCIPAL_NAME_LENGTH = 128
_MAX_PERMISSION_LENGTH = 64


class FolderTransportConfigurationError(ValueError):
    """Raised when the dedicated transport configuration is unsafe."""


class FolderTransportError(RuntimeError):
    """Raised for a transport failure without disclosing response content."""


@dataclass(frozen=True, slots=True)
class FolderTransportConfig:
    """Dedicated non-secret configuration plus an in-memory bearer token."""

    base_url: str
    bearer_token: str
    timeout_seconds: float
    ca_file: str | None
    explicitly_enabled: bool = False

    def __post_init__(self) -> None:
        if self.explicitly_enabled is not True:
            raise FolderTransportConfigurationError(
                "The Folder HTTP transport is disabled by default."
            )
        normalized_base_url = _validate_base_url(self.base_url)
        object.__setattr__(self, "base_url", normalized_base_url)
        if (
            not isinstance(self.bearer_token, str)
            or not self.bearer_token
            or self.bearer_token != self.bearer_token.strip()
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.bearer_token
            )
        ):
            raise FolderTransportConfigurationError("A dedicated bearer token is required.")
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(
            self.timeout_seconds, bool
        ):
            raise FolderTransportConfigurationError("The timeout is invalid.")
        if not 1 <= float(self.timeout_seconds) <= 60:
            raise FolderTransportConfigurationError(
                "The timeout must be between 1 and 60 seconds."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise FolderTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class FolderHttpResponse:
    """Internal parsed response for a fixed folder operation."""

    status_code: int
    content_type: str
    data: Any


class ResponseStream(Protocol):
    """Minimal streamed response required by the transport."""

    status_code: int
    headers: Mapping[str, str]

    def iter_bytes(self) -> Iterator[bytes]: ...


class ResponseStreamContext(Protocol):
    """Minimal context manager for a streamed response."""

    def __enter__(self) -> ResponseStream: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...


class SyncHttpClient(Protocol):
    """Minimal synchronous HTTP client accepted by the transport."""

    def __enter__(self) -> SyncHttpClient: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None: ...

    def stream(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        content: bytes | None,
    ) -> ResponseStreamContext: ...


class SyncHttpClientFactory(Protocol):
    """Narrow injectable client factory for deterministic tests."""

    def __call__(
        self,
        *,
        verify: ssl.SSLContext,
        timeout: float,
        follow_redirects: Literal[False],
        trust_env: Literal[False],
    ) -> SyncHttpClient: ...


def load_folder_transport_config(
    environment: Mapping[str, str] | None = None,
) -> FolderTransportConfig:
    """Load the dedicated child-Folder environment namespace after opt-in."""

    return _load_folder_transport_config(environment, prefix=ENV_PREFIX)


def load_folder_acl_transport_config(
    environment: Mapping[str, str] | None = None,
) -> FolderTransportConfig:
    """Load the independent Folder ACL API namespace after exact opt-in."""

    return _load_folder_transport_config(environment, prefix=FOLDER_ACL_ENV_PREFIX)


def load_folder_archive_transport_config(
    environment: Mapping[str, str] | None = None,
) -> FolderTransportConfig:
    """Load the independent empty-Folder archive API namespace after opt-in."""

    return _load_folder_transport_config(environment, prefix=FOLDER_ARCHIVE_ENV_PREFIX)


def _load_folder_transport_config(
    environment: Mapping[str, str] | None,
    *,
    prefix: str,
) -> FolderTransportConfig:
    """Load one exact Folder transport namespace without credential fallback."""

    env = os.environ if environment is None else environment
    enabled = _env_value(env, "ENABLED", prefix=prefix)
    if enabled != "true":
        raise FolderTransportConfigurationError(
            f"{prefix}ENABLED must be exactly true before this transport can load."
        )
    supplied = _env_value(env, "BASE_URL", prefix=prefix) or _env_value(
        env, "HOST", prefix=prefix
    )
    if supplied is None:
        raise FolderTransportConfigurationError("A dedicated HTTPS target is required.")
    base_url = supplied if "://" in supplied else f"https://{supplied}"
    base_url = _validate_base_url(base_url)
    token = _env_value(env, "API_TOKEN", prefix=prefix)
    if token is None:
        raise FolderTransportConfigurationError("A dedicated bearer token is required.")
    timeout = _parse_timeout(
        _env_value(env, "TIMEOUT_SECONDS", prefix=prefix) or "15"
    )
    ca_file_value = _env_value(env, "CA_FILE", prefix=prefix)
    ca_file: str | None = None
    if ca_file_value is not None:
        path = Path(ca_file_value).expanduser()
        if not path.is_file():
            raise FolderTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )
        ca_file = str(path)
    return FolderTransportConfig(
        base_url=base_url,
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
        explicitly_enabled=True,
    )


def build_folder_ssl_context(config: FolderTransportConfig) -> ssl.SSLContext:
    """Build a certificate-verifying context; verification cannot be disabled."""

    if config.ca_file is not None:
        context = ssl.create_default_context(cafile=config.ca_file)
    else:
        try:
            import truststore
        except ImportError as exc:  # pragma: no cover - dependency guard.
            raise RuntimeError(
                "truststore is required for native system TLS verification."
            ) from exc
        context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


class FortiPamFolderHttpTransport:
    """Synchronous, fixed-route child-Public-Folder HTTP transport."""

    def __init__(
        self,
        config: FolderTransportConfig,
        *,
        client_factory: SyncHttpClientFactory | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory or _default_client_factory

    def read_collection(self) -> Mapping[str, object]:
        """GET the one fixed folder collection path."""

        return _mapping_payload(self._request("GET", COLLECTION_PATH, None))

    def read_folder(self, folder_id: int) -> Mapping[str, object]:
        """GET one fixed folder-detail path for a positive signed int32 id."""

        safe_id = _positive_folder_id(folder_id)
        return _mapping_payload(
            self._request("GET", f"{COLLECTION_PATH}/{safe_id}", None)
        )

    def verify_owner_only_folder(self, folder_id: int, owner_name: str) -> bool:
        """Verify a private collector Folder without returning principals or ACLs.

        This is a prerequisite only; it grants no Secret-create authority and
        does not prove effective access beyond the returned Folder ACL.
        """
        safe_id = _positive_folder_id(folder_id)
        owner = _non_empty_text(owner_name, maximum=_MAX_PRINCIPAL_NAME_LENGTH)
        payload = self.read_folder(safe_id)
        record = payload.get("results")
        if isinstance(record, list):
            record = record[0] if len(record) == 1 else None
        if not isinstance(record, Mapping):
            return False
        if (
            type(record.get("id")) is not int
            or record["id"] != safe_id
            or record.get("inherit-permission") != "disable"
            or record.get("group-permission") != []
        ):
            return False
        users = record.get("user-permission")
        if not isinstance(users, list) or len(users) != 1:
            return False
        # GET may return names as strings and include launcher metadata. The
        # strict write encoder is intentionally not a read-response parser.
        from .folder_acl_live_workflow import FolderAclLiveWorkflowError, _relations
        try:
            relation = _relations(record, principal_key="user-name")[0]
        except FolderAclLiveWorkflowError:
            return False
        return bool(
            relation.relation_id > 0
            and relation.names == (owner,)
            and relation.folder_permission == "owner"
            and relation.secret_permission == "owner"
        )

    def create_child(self, body: Mapping[str, object]) -> Mapping[str, object]:
        """POST one strictly validated inherited child-folder body."""

        encoded = _encode_child_body(body)
        return _mapping_payload(self._request("POST", COLLECTION_PATH, encoded))

    def create_isolated_child(
        self, *, name: str, parent_folder_id: int, owner_name: str,
        empty_inactive_policy: bool = False,
    ) -> Mapping[str, object]:
        """Candidate-only fixed CREATE; authorization belongs to its workflow.

        Existing inherited-child tools never call this separate operation.
        No caller-defined ACL or update of an existing Folder is accepted.
        """
        body = _isolated_child_body(name, parent_folder_id, owner_name, empty_inactive_policy=empty_inactive_policy)
        encoded = json.dumps(body, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if len(encoded) > MAX_REQUEST_BYTES:
            raise FolderTransportError("The child-folder request exceeded its safety limit.")
        return _mapping_payload(self._request("POST", COLLECTION_PATH, encoded))

    def update_folder(
        self,
        folder_id: int,
        body: Mapping[str, object],
    ) -> Mapping[str, object]:
        """PUT one validated Public child-Folder ACL projection by exact id."""

        safe_id = _positive_folder_id(folder_id)
        encoded = _encode_folder_update_body(body, folder_id=safe_id)
        response = self._request(
            "PUT", f"{COLLECTION_PATH}/{safe_id}", encoded
        )
        if (
            isinstance(response.data, Mapping)
            and response.data.get("status") == "error"
        ):
            # FortiPAM can return a product-level error envelope over HTTP 200.
            # Keep the reason categorical; response details may expose config.
            logging.getLogger(__name__).warning(
                "Fixed Folder request rejected: method=PUT product_status=error"
            )
            raise FolderTransportError(
                "FortiPAM reported an unsuccessful Folder update."
            )
        return _mapping_payload(response)

    def delete_empty_folder(self, folder_id: int) -> Mapping[str, object]:
        """DELETE one exact Public Folder; FortiPAM rejects a non-empty Folder."""

        safe_id = _positive_folder_id(folder_id)
        return _mapping_payload(
            self._request("DELETE", f"{COLLECTION_PATH}/{safe_id}", None)
        )

    def _request(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE"],
        path: str,
        body: bytes | None,
    ) -> FolderHttpResponse:
        fixed_collection_operation = (method, path) in {
            ("GET", COLLECTION_PATH),
            ("POST", COLLECTION_PATH),
        }
        fixed_detail_operation = False
        if method in {"GET", "PUT", "DELETE"} and path.startswith(
            f"{COLLECTION_PATH}/"
        ):
            detail_id = path.removeprefix(f"{COLLECTION_PATH}/")
            fixed_detail_operation = (
                detail_id.isascii()
                and detail_id.isdigit()
                and str(_positive_folder_id(int(detail_id))) == detail_id
            )
        if not fixed_collection_operation and not fixed_detail_operation:
            raise FolderTransportError("The folder operation is outside the fixed boundary.")
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self._config.bearer_token}",
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        try:
            with self._client_factory(
                verify=build_folder_ssl_context(self._config),
                timeout=float(self._config.timeout_seconds),
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    method,
                    f"{self._config.base_url}{path}",
                    headers=headers,
                    content=body,
                ) as response:
                    if not 200 <= response.status_code < 300:
                        # Do not log the URL, bearer header, body or raw response.
                        logging.getLogger(__name__).warning(
                            "Fixed Folder request rejected: method=%s http_status=%d",
                            method, response.status_code,
                        )
                        raise FolderTransportError(
                            f"FortiPAM returned HTTP {response.status_code}."
                        )
                    content_type = _header(response.headers, "content-type")
                    if content_type is None or "json" not in content_type.lower():
                        raise FolderTransportError(
                            "FortiPAM returned an unexpected response content type."
                        )
                    content = _bounded_response_content(response)
                    status_code = response.status_code
        except FolderTransportError:
            raise
        except Exception as exc:
            raise FolderTransportError(
                "Unable to complete the fixed FortiPAM folder request."
            ) from exc
        try:
            decoded = json.loads(content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise FolderTransportError("FortiPAM returned malformed JSON.") from exc
        return FolderHttpResponse(
            status_code=status_code,
            content_type=content_type,
            data=decoded,
        )


def _encode_child_body(body: Mapping[str, object]) -> bytes:
    if not isinstance(body, Mapping):
        raise FolderTransportError("The child-folder request must be an object.")
    if set(body) != _CHILD_FIELDS or not all(isinstance(key, str) for key in body):
        raise FolderTransportError("The child-folder request fields are invalid.")
    if type(body["id"]) is not int or body["id"] != 0:
        raise FolderTransportError("The child-folder id must be zero.")
    _positive_folder_id(body["parent-folder"])
    name = body["name"]
    if (
        not isinstance(name, str)
        or not name
        or len(name) > MAX_FOLDER_NAME_LENGTH
        or "/" in name
        or "\\" in name
        or any(ord(character) < 32 or ord(character) == 127 for character in name)
    ):
        raise FolderTransportError("The child-folder name is invalid.")
    for field in (
        "inherit-policy",
        "inherit-permission",
        "inherit-folder-ztna",
    ):
        if body[field] != "enable":
            raise FolderTransportError("Child-folder inheritance must remain enabled.")
    for field in ("user-permission", "group-permission"):
        if not isinstance(body[field], list) or body[field]:
            raise FolderTransportError(
                "Child-folder permission arrays must remain empty."
            )
    encoded = json.dumps(
        dict(body),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_REQUEST_BYTES:
        raise FolderTransportError("The child-folder request exceeded its safety limit.")
    return encoded


def _isolated_child_body(name: str, parent_folder_id: int, owner_name: str, *,
                         empty_inactive_policy: bool = False) -> dict[str, object]:
    """Fixed candidate body for a new child with one owner and no groups."""
    if type(empty_inactive_policy) is not bool:
        raise FolderTransportError("The isolated child-folder policy mode is invalid.")
    body: dict[str, object] = {
        "id": 0, "name": _valid_folder_name(name),
        "parent-folder": _positive_folder_id(parent_folder_id),
        "inherit-policy": "enable", "inherit-folder-ztna": "enable",
        "inherit-permission": "disable",
        "user-permission": [{
            "id": 0,
            "user-name": [{"name": _non_empty_text(owner_name, maximum=_MAX_PRINCIPAL_NAME_LENGTH)}],
            "folder-permission": "owner", "secret-permission": "owner",
        }],
        "group-permission": [],
    }
    if empty_inactive_policy:
        body["secret-policy"] = ""
    return body


def _encode_folder_update_body(
    body: Mapping[str, object],
    *,
    folder_id: int,
) -> bytes:
    """Encode the one documented Folder update projection without GUI-only data."""

    if not isinstance(body, Mapping):
        raise FolderTransportError("The Folder update request must be an object.")
    if set(body) != _UPDATE_FIELDS or not all(isinstance(key, str) for key in body):
        raise FolderTransportError("The Folder update request fields are invalid.")
    if type(body["id"]) is not int or body["id"] != folder_id:
        raise FolderTransportError("The Folder update id must match the fixed route.")
    _positive_folder_id(body["parent-folder"])
    _valid_folder_name(body["name"])
    if body["folder-type"] != "public":
        raise FolderTransportError("Only Public child Folders are within this boundary.")
    for field in ("secret-policy",):
        _non_empty_text(body[field], maximum=_MAX_PERMISSION_LENGTH)
    for field in ("inherit-policy", "inherit-folder-ztna"):
        if body[field] not in {"enable", "disable"}:
            raise FolderTransportError("The Folder inheritance value is invalid.")
    if not isinstance(body["ztna-ems-tag"], list) or body["ztna-ems-tag"]:
        raise FolderTransportError(
            "The non-empty Folder ZTNA tag projection is not established."
        )
    if body["ztna-tags-match-logic"] not in {"and", "or"}:
        raise FolderTransportError("The Folder ZTNA tag match logic is invalid.")
    if body["inherit-permission"] != "disable":
        raise FolderTransportError(
            "Folder ACL updates must preserve an independent permission projection."
        )
    _validate_acl_relations(body["user-permission"], principal_key="user-name")
    _validate_acl_relations(body["group-permission"], principal_key="group-name")
    encoded = json.dumps(
        dict(body),
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_REQUEST_BYTES:
        raise FolderTransportError("The Folder update request exceeded its safety limit.")
    return encoded


def _validate_acl_relations(value: object, *, principal_key: str) -> None:
    if not isinstance(value, list) or len(value) > _MAX_ACL_RELATIONS:
        raise FolderTransportError("The Folder ACL relation array is invalid.")
    expected_fields = {"id", principal_key, "folder-permission", "secret-permission"}
    for relation in value:
        if not isinstance(relation, Mapping) or set(relation) != expected_fields:
            raise FolderTransportError("The Folder ACL relation fields are invalid.")
        relation_id = relation["id"]
        if type(relation_id) is not int or relation_id < 0 or relation_id > MAX_FOLDER_ID:
            raise FolderTransportError("The Folder ACL relation id is invalid.")
        names = relation[principal_key]
        if (
            not isinstance(names, list)
            or not names
            or len(names) > _MAX_PRINCIPAL_NAMES_PER_RELATION
        ):
            raise FolderTransportError("The Folder ACL principal list is invalid.")
        for name in names:
            if not isinstance(name, Mapping) or set(name) != {"name"}:
                raise FolderTransportError("The Folder ACL principal fields are invalid.")
            _non_empty_text(name["name"], maximum=_MAX_PRINCIPAL_NAME_LENGTH)
        _non_empty_text(
            relation["folder-permission"], maximum=_MAX_PERMISSION_LENGTH
        )
        _non_empty_text(
            relation["secret-permission"], maximum=_MAX_PERMISSION_LENGTH
        )


def _valid_folder_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_FOLDER_NAME_LENGTH
        or "/" in value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise FolderTransportError("The Folder name is invalid.")
    return value


def _non_empty_text(value: object, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise FolderTransportError("The Folder update value is invalid.")
    return value


def _mapping_payload(response: FolderHttpResponse) -> Mapping[str, object]:
    if not isinstance(response.data, Mapping):
        raise FolderTransportError("FortiPAM returned an unexpected JSON shape.")
    payload = {str(key): value for key, value in response.data.items()}
    payload["http_status"] = response.status_code
    return payload


def _positive_folder_id(value: object) -> int:
    if type(value) is not int or value <= 0 or value > MAX_FOLDER_ID:
        raise FolderTransportError("The folder id must be a positive signed int32 value.")
    return value


def _bounded_response_content(response: ResponseStream) -> bytes:
    declared = _header(response.headers, "content-length")
    if declared is not None:
        try:
            declared_size = int(declared)
        except ValueError as exc:
            raise FolderTransportError("FortiPAM returned an invalid content length.") from exc
        if declared_size < 0:
            raise FolderTransportError("FortiPAM returned an invalid content length.")
        if declared_size > MAX_RESPONSE_BYTES:
            raise FolderTransportError(
                "FortiPAM response exceeded the 1 MiB safety limit."
            )
    chunks: list[bytes] = []
    received = 0
    for chunk in response.iter_bytes():
        received += len(chunk)
        if received > MAX_RESPONSE_BYTES:
            raise FolderTransportError(
                "FortiPAM response exceeded the 1 MiB safety limit."
            )
        chunks.append(chunk)
    return b"".join(chunks)


def _header(headers: Mapping[str, str], name: str) -> str | None:
    wanted = name.lower()
    for key, value in headers.items():
        if key.lower() == wanted:
            return value
    return None


def _env_value(
    environment: Mapping[str, str],
    suffix: str,
    *,
    prefix: str = ENV_PREFIX,
) -> str | None:
    value = environment.get(f"{prefix}{suffix}")
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _validate_base_url(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise FolderTransportConfigurationError("The dedicated HTTPS target is invalid.")
    candidate = value.rstrip("/")
    parsed = urlsplit(candidate)
    try:
        port = parsed.port
    except ValueError as exc:
        raise FolderTransportConfigurationError("The HTTPS target port is invalid.") from exc
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise FolderTransportConfigurationError(
            "The dedicated target must be an HTTPS origin without credentials, path, query, or fragment."
        )
    return candidate


def _parse_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise FolderTransportConfigurationError("The timeout is invalid.") from exc
    if not 1 <= timeout <= 60:
        raise FolderTransportConfigurationError(
            "The timeout must be between 1 and 60 seconds."
        )
    return timeout


def _default_client_factory(
    *,
    verify: ssl.SSLContext,
    timeout: float,
    follow_redirects: Literal[False],
    trust_env: Literal[False],
) -> SyncHttpClient:
    try:
        import httpx
    except ModuleNotFoundError as exc:  # pragma: no cover - dependency guard.
        raise RuntimeError("httpx is required for the fixed folder transport.") from exc
    return cast(
        SyncHttpClient,
        httpx.Client(
            verify=verify,
            timeout=timeout,
            follow_redirects=follow_redirects,
            trust_env=trust_env,
        ),
    )


__all__ = [
    "COLLECTION_PATH",
    "ENV_PREFIX",
    "FOLDER_ACL_ENV_PREFIX",
    "FOLDER_ARCHIVE_ENV_PREFIX",
    "FolderHttpResponse",
    "FolderTransportConfig",
    "FolderTransportConfigurationError",
    "FolderTransportError",
    "FortiPamFolderHttpTransport",
    "MAX_REQUEST_BYTES",
    "MAX_RESPONSE_BYTES",
    "SyncHttpClientFactory",
    "build_folder_ssl_context",
    "load_folder_acl_transport_config",
    "load_folder_archive_transport_config",
    "load_folder_transport_config",
]
