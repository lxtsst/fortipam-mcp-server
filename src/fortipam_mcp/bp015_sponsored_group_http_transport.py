"""Fixed, non-disclosing HTTP transport for one BP015 Sponsored Group.

This module intentionally owns only the routes needed to create and remove a
single, caller-supplied Sponsored Group candidate.  It is not a REST wrapper:
all collection filters, methods, headers, request bodies, and readback checks
are compiled here.  Responses are bounded, decoded only long enough to make a
categorical decision, and never returned to the caller.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import http.client
import json
from typing import Any, Final, Literal, cast
from urllib.parse import quote, urlsplit

from .mutable_json_buffer import _take_mutable_prefix
from .bp015_sponsored_group_create_contract import (
    CREATE_PATH,
    DEFAULT_QUERY,
    SponsoredGroupCreateContractError,
    SponsoredGroupCreateInput,
    SponsoredGroupDefaultEvidence,
    validate_sponsored_group_default_response,
)
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES,
    SecretMetadataHttpTransportConfig,
    SecretMetadataHttpTransportError,
    _ssl_context,
    _zeroize_mutable,
    load_secret_metadata_http_transport_config,
)


GROUP_DEFAULT_PATH: Final = f"{CREATE_PATH}?{DEFAULT_QUERY}"
GROUP_COLLECTION_PATH: Final = f"{CREATE_PATH}?with_meta=true"
OWNER_COLLECTION_PATH: Final = "/api/v2/cmdb/system/admin?with_meta=true"
MEMBER_COLLECTION_PATH: Final = OWNER_COLLECTION_PATH
_UNAVAILABLE: Final = "FortiPAM BP015 Sponsored Group transport is unavailable."
_MAX_COLLECTION_RECORDS: Final = 64
_ALLOWED_ENVELOPE_KEYS: Final = frozenset(
    {
        "action", "build", "http_method", "http_status", "matched_count", "name",
        "next_idx", "path", "results", "revision", "serial", "size", "status", "vdom",
        "version",
    }
)


class BP015SponsoredGroupHttpTransportError(RuntimeError):
    """Stable, non-disclosing failure for the fixed BP015 transport."""


@dataclass(frozen=True, slots=True, repr=False)
class SponsoredGroupCreateReadback:
    """Categorical result of one fixed create/reconciliation sequence."""

    default_validated: bool
    owner_binding_accepted: bool
    group_absent_before_create: bool
    create_response_category: Literal["accepted", "ambiguous"]
    group_exists: bool
    name_matches: bool
    group_type_matches: bool
    group_max_users_matches: bool
    access_matches: bool
    owner_matches: bool
    member_empty: bool
    readback_digest: str

    @property
    def verified(self) -> bool:
        return all(
            (
                self.default_validated,
                self.owner_binding_accepted,
                self.group_absent_before_create,
                self.group_exists,
                self.name_matches,
                self.group_type_matches,
                self.group_max_users_matches,
                self.access_matches,
                self.owner_matches,
                self.member_empty,
            )
        )

    def __repr__(self) -> str:
        return "<SponsoredGroupCreateReadback categorical>"


@dataclass(frozen=True, slots=True, repr=False)
class SponsoredGroupCleanupReadback:
    """Categorical result of one bound disposable Group cleanup sequence."""

    member_relation_zero: bool
    group_readback_verified: bool
    delete_response_category: Literal["accepted", "ambiguous"]
    group_absent_after_delete: bool
    cleanup_digest: str

    @property
    def verified(self) -> bool:
        return (
            self.member_relation_zero
            and self.group_readback_verified
            and self.group_absent_after_delete
        )

    def __repr__(self) -> str:
        return "<SponsoredGroupCleanupReadback categorical>"


def load_bp015_sponsored_group_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> SecretMetadataHttpTransportConfig:
    """Reuse the protected central API transport configuration without copying it."""

    return load_secret_metadata_http_transport_config(environment)


class FortiPamBP015SponsoredGroupHttpTransport:
    """Create once, reconcile by exact readback, then clean up only a bound name."""

    __slots__ = (
        "_bound_api_owner_name",
        "_bound_input",
        "_config",
        "_connection_factory",
        "_create_attempted",
        "_delete_attempted",
    )

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        bound_api_owner_name: str | None = None,
        connection_factory: Any | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
        self._config = config
        try:
            if bound_api_owner_name is not None:
                SponsoredGroupCreateInput(
                    "mcp-v4-bp015-owner-binding-check", bound_api_owner_name, 1
                )
        except SponsoredGroupCreateContractError as exc:
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE) from exc
        self._bound_api_owner_name = bound_api_owner_name
        self._connection_factory = connection_factory
        self._create_attempted = False
        self._delete_attempted = False
        self._bound_input: SponsoredGroupCreateInput | None = None

    def create_and_readback(
        self, request: SponsoredGroupCreateInput
    ) -> SponsoredGroupCreateReadback:
        """Validate defaults, preflight one owner/name, POST once, then reconcile."""

        if type(request) is not SponsoredGroupCreateInput or self._create_attempted:
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
        try:
            evidence = self._read_default()
            request.body(evidence)
            owner_binding_accepted = (
                self._bound_api_owner_name is not None
                and request.owner_name == self._bound_api_owner_name
            )
            if not owner_binding_accepted and not self._owner_is_unique(
                request.owner_name
            ):
                raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
            if not self._group_is_absent(request.group_name):
                raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
        except (
            SponsoredGroupCreateContractError,
            SecretMetadataHttpTransportError,
            ValueError,
        ) as exc:
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE) from exc

        self._create_attempted = True
        create_response_category = self._post_once(CREATE_PATH, request.body(evidence))
        readback = self._readback_group(request, create_response_category)
        if readback.verified and _is_disposable_name(request.group_name):
            self._bound_input = request
        return readback

    def cleanup_bound_disposable(self) -> SponsoredGroupCleanupReadback:
        """Delete exactly one same-process, verified disposable Group binding."""

        request = self._bound_input
        if request is None or self._delete_attempted:
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
        if not self._member_relation_is_zero(request.group_name):
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
        current = self._readback_group(request, "accepted")
        if not current.verified:
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)

        self._delete_attempted = True
        delete_response_category = self._delete_once(request.group_name)
        absent = self._group_is_absent(request.group_name)
        categorical: dict[str, object] = {
            "member_relation_zero": True,
            "group_readback_verified": True,
            "delete_response_category": delete_response_category,
            "group_absent_after_delete": absent,
        }
        result = SponsoredGroupCleanupReadback(
            member_relation_zero=True,
            group_readback_verified=True,
            delete_response_category=delete_response_category,
            group_absent_after_delete=absent,
            cleanup_digest=_digest(categorical),
        )
        if result.verified:
            self._bound_input = None
        return result

    def _read_default(self) -> SponsoredGroupDefaultEvidence:
        status, payload = self._read_json("GET", GROUP_DEFAULT_PATH, None)
        if status != 200 or not isinstance(payload, Mapping):
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
        try:
            return validate_sponsored_group_default_response(
                cast(Mapping[str, object], payload)
            )
        except SponsoredGroupCreateContractError as exc:
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE) from exc

    def _owner_is_unique(self, owner_name: str) -> bool:
        status, payload = self._read_json(
            "POST", OWNER_COLLECTION_PATH, _owner_filter_body(owner_name)
        )
        records = _collection_records(payload, status, path="system", name="admin")
        return len(records) == 1 and records[0].get("name") == owner_name

    def _group_is_absent(self, group_name: str) -> bool:
        status, payload = self._read_json(
            "POST", GROUP_COLLECTION_PATH, _group_filter_body(group_name)
        )
        records = _collection_records(payload, status, path="user", name="group")
        return records == []

    def _member_relation_is_zero(self, group_name: str) -> bool:
        status, payload = self._read_json(
            "POST", MEMBER_COLLECTION_PATH, _member_filter_body(group_name)
        )
        records = _collection_records(payload, status, path="system", name="admin")
        return records == []

    def _readback_group(
        self,
        request: SponsoredGroupCreateInput,
        create_response_category: Literal["accepted", "ambiguous"],
    ) -> SponsoredGroupCreateReadback:
        try:
            status, payload = self._read_json(
                "POST", GROUP_COLLECTION_PATH, _group_filter_body(request.group_name)
            )
            records = _collection_records(payload, status, path="user", name="group")
            if len(records) != 1:
                return _unverified_readback(create_response_category)
            record = records[0]
            name_matches = (
                type(record.get("name")) is str
                and record.get("name") == request.group_name
            )
            group_type_matches = (
                type(record.get("group-type")) is str
                and record.get("group-type") == "sponsor"
            )
            group_max_users_matches = (
                type(record.get("group-max-users")) is int
                and record.get("group-max-users") == request.maximum_members
            )
            access_matches = (
                type(record.get("access")) is str
                and record.get("access") == "customized"
            )
            owner_matches = _exact_owner(record.get("user-permission"), request.owner_name)
            member_empty = record.get("member") == []
            categorical: dict[str, object] = {
                "default_validated": True,
                "owner_binding_accepted": True,
                "group_absent_before_create": True,
                "create_response_category": create_response_category,
                "group_exists": True,
                "name_matches": name_matches,
                "group_type_matches": group_type_matches,
                "group_max_users_matches": group_max_users_matches,
                "access_matches": access_matches,
                "owner_matches": owner_matches,
                "member_empty": member_empty,
            }
            return SponsoredGroupCreateReadback(
                **categorical, readback_digest=_digest(categorical)  # type: ignore[arg-type]
            )
        except BP015SponsoredGroupHttpTransportError:
            return _unverified_readback(create_response_category)

    def _post_once(
        self, path: str, body: Mapping[str, object]
    ) -> Literal["accepted", "ambiguous"]:
        try:
            status, is_json = self._write_status("POST", path, body)
            return "accepted" if status == 200 and is_json else "ambiguous"
        except BP015SponsoredGroupHttpTransportError:
            return "ambiguous"

    def _delete_once(self, group_name: str) -> Literal["accepted", "ambiguous"]:
        try:
            status, is_json = self._write_status(
                "DELETE", f"{CREATE_PATH}/{quote(group_name, safe='')}", None
            )
            return "accepted" if status == 200 and is_json else "ambiguous"
        except BP015SponsoredGroupHttpTransportError:
            return "ambiguous"

    def _read_json(
        self,
        method: Literal["GET", "POST"],
        path: str,
        body: Mapping[str, object] | None,
    ) -> tuple[int, object]:
        connection: Any = None
        response: Any = None
        content = bytearray(MAX_RESPONSE_BYTES + 1)
        encoded: bytearray | None = None
        try:
            connection = self._connection()
            if body is not None:
                encoded = bytearray(_json_body(body))
            connection.request(
                method,
                path,
                body=encoded,
                headers=_headers(
                    self._config, method, override=method == "POST"
                ),
            )
            response = connection.getresponse()
            status = int(response.status)
            content_type = response.getheader("content-type", "")
            if not isinstance(content_type, str) or "json" not in content_type.lower():
                raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
            total = _read_bounded(response, content)
            content = _take_mutable_prefix(content, total)
            return status, json.loads(content)
        except BP015SponsoredGroupHttpTransportError:
            raise
        except Exception as exc:
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE) from exc
        finally:
            if encoded is not None:
                _zeroize_mutable(encoded)
            _zeroize_mutable(content)
            _close(response)
            _close(connection)

    def _write_status(
        self,
        method: Literal["POST", "DELETE"],
        path: str,
        body: Mapping[str, object] | None,
    ) -> tuple[int, bool]:
        connection: Any = None
        response: Any = None
        encoded: bytearray | None = None
        content = bytearray(MAX_RESPONSE_BYTES + 1)
        try:
            connection = self._connection()
            if body is not None:
                encoded = bytearray(_json_body(body))
            connection.request(
                method,
                path,
                body=encoded,
                headers=_headers(self._config, method, override=False),
            )
            response = connection.getresponse()
            status = int(response.status)
            content_type = response.getheader("content-type", "")
            is_json = isinstance(content_type, str) and "json" in content_type.lower()
            total = _read_bounded(response, content)
            content = _take_mutable_prefix(content, total)
            product_accepted = False
            if is_json:
                try:
                    payload = json.loads(content)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    payload = None
                product_accepted = _successful_write_envelope(payload, method)
            return status, product_accepted
        except Exception as exc:
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE) from exc
        finally:
            if encoded is not None:
                _zeroize_mutable(encoded)
            _zeroize_mutable(content)
            _close(response)
            _close(connection)

    def _connection(self) -> Any:
        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
        try:
            factory = self._connection_factory or http.client.HTTPSConnection
            return factory(
                parsed.hostname,
                parsed.port or 443,
                timeout=self._config.timeout_seconds,
                context=_ssl_context(self._config),
            )
        except Exception as exc:
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE) from exc


def _headers(
    config: SecretMetadataHttpTransportConfig, method: str, *, override: bool
) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {config.bearer_token}",
        "Connection": "close",
        "User-Agent": "fortipam-mcp-v4-bp015-sponsored-group/1",
    }
    if method == "POST":
        headers["Content-Type"] = "application/json"
    if override:
        headers["X-HTTP-Method-Override"] = "GET"
    return headers


def _json_body(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _successful_write_envelope(payload: object, method: str) -> bool:
    return (
        isinstance(payload, Mapping)
        and payload.get("status") in {"success", "OK"}
        and payload.get("http_status") == 200
        and payload.get("http_method") == method
        and payload.get("version") == "v7.0.0"
        and type(payload.get("build")) is int
        and payload.get("build") == 29
        and payload.get("path") == "user"
        and payload.get("name") == "group"
    )


def _read_bounded(response: Any, content: bytearray) -> int:
    total = 0
    while total < len(content):
        view = memoryview(content)[total:]
        try:
            count = response.readinto(view)
        finally:
            view.release()
        if not isinstance(count, int) or count < 0:
            raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
        if count == 0:
            break
        total += count
    if total > MAX_RESPONSE_BYTES:
        raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
    return total


def _close(value: Any) -> None:
    if value is not None:
        try:
            value.close()
        except Exception:
            pass


def _collection_records(
    payload: object, status: int, *, path: str, name: str
) -> list[Mapping[str, object]]:
    if status != 200 or not isinstance(payload, Mapping):
        raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
    envelope = cast(Mapping[str, object], payload)
    if (
        any(not isinstance(key, str) for key in envelope)
        or set(envelope) - _ALLOWED_ENVELOPE_KEYS
        or envelope.get("status") != (
            "OK" if (path, name) == ("user", "group") else "success"
        )
        or envelope.get("version") != "v7.0.0"
        or type(envelope.get("build")) is not int
        or envelope.get("build") != 29
        or envelope.get("http_method") != "POST"
        or envelope.get("http_status") != 200
        or envelope.get("path") != path
        or envelope.get("name") != name
        or not isinstance(envelope.get("results"), list)
    ):
        raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
    records = cast(list[object], envelope["results"])
    if (
        len(records) > _MAX_COLLECTION_RECORDS
        or not _collection_paging_is_valid(
            envelope, record_count=len(records), path=path, name=name
        )
        or not all(
        isinstance(record, Mapping) and all(isinstance(key, str) for key in record)
        for record in records
        )
    ):
        raise BP015SponsoredGroupHttpTransportError(_UNAVAILABLE)
    return [cast(Mapping[str, object], record) for record in records]


def _collection_paging_is_valid(
    envelope: Mapping[str, object], *, record_count: int, path: str, name: str
) -> bool:
    if (path, name) == ("user", "group"):
        return all(key not in envelope for key in ("matched_count", "next_idx", "size"))
    matched_count = envelope.get("matched_count")
    next_idx = envelope.get("next_idx")
    size = envelope.get("size")
    return (
        type(matched_count) is int
        and matched_count == record_count
        and type(next_idx) is int
        and 0 <= next_idx <= 100_000
        and type(size) is int
        and 0 <= size <= 100_000
    )


def _group_filter_body(group_name: str) -> dict[str, object]:
    return {
        "json_filter": [
            {
                "logic": "or",
                "filters": [
                    {
                        "key": "name", "type": "string", "operator": "exact",
                        "pattern": group_name, "negate": False,
                    }
                ],
            }
        ]
    }


def _owner_filter_body(owner_name: str) -> dict[str, object]:
    return {
        "json_filter": [
            {
                "logic": "or",
                "filters": [
                    {
                        "key": "name", "type": "string", "operator": "exact",
                        "pattern": owner_name, "negate": False,
                    }
                ],
            },
            {
                "logic": "or",
                "filters": [
                    {
                        "key": "name", "type": "string", "operator": "exact",
                        "pattern": "invitation_guests", "negate": True,
                    }
                ],
            },
        ]
    }


def _member_filter_body(group_name: str) -> dict[str, object]:
    return {
        "json_filter": [
            {
                "logic": "and",
                "filters": [
                    {
                        "key": "name", "type": "string", "operator": "exact",
                        "pattern": "invitation_guest", "negate": True,
                    }
                ],
            },
            {
                "logic": "or",
                "filters": [
                    {
                        "key": "sponsor-group", "type": "string", "operator": "exact",
                        "pattern": group_name, "negate": False,
                    }
                ],
            },
            {
                "logic": "or",
                "filters": [
                    {
                        "key": "name", "type": "string", "operator": "exact",
                        "pattern": "invitation_guests", "negate": True,
                    }
                ],
            },
        ]
    }


def _exact_owner(value: object, owner_name: str) -> bool:
    if not isinstance(value, list) or len(value) != 1:
        return False
    relation = value[0]
    if not isinstance(relation, Mapping) or not _only_known_origin_metadata(
        relation, {"id", "permission", "user-name"}
    ):
        return False
    users = relation.get("user-name")
    return (
        type(relation.get("id")) is int
        and relation.get("id") == 1
        and relation.get("permission") == "owner"
        and isinstance(users, list)
        and len(users) == 1
        and isinstance(users[0], Mapping)
        and _only_known_origin_metadata(users[0], {"name"})
        and users[0].get("name") == owner_name
    )


def _only_known_origin_metadata(
    value: Mapping[object, object], semantic_keys: set[str]
) -> bool:
    if any(not isinstance(key, str) for key in value):
        return False
    keys = set(cast(Mapping[str, object], value))
    if keys - semantic_keys not in (set(), {"q_origin_key"}):
        return False
    if "q_origin_key" in value:
        origin = value.get("q_origin_key")
        if not (
            isinstance(origin, str)
            or (type(origin) is int and 0 <= origin <= 2_147_483_647)
        ):
            return False
    return semantic_keys <= keys


def _is_disposable_name(value: str) -> bool:
    return value.startswith("mcp-v4-bp015-")


def _unverified_readback(
    create_response_category: Literal["accepted", "ambiguous"],
) -> SponsoredGroupCreateReadback:
    categorical: dict[str, object] = {
        "default_validated": True,
        "owner_binding_accepted": True,
        "group_absent_before_create": True,
        "create_response_category": create_response_category,
        "group_exists": False,
        "name_matches": False,
        "group_type_matches": False,
        "group_max_users_matches": False,
        "access_matches": False,
        "owner_matches": False,
        "member_empty": False,
    }
    return SponsoredGroupCreateReadback(
        **categorical, readback_digest=_digest(categorical)  # type: ignore[arg-type]
    )


def _digest(categorical: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(categorical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


__all__ = [
    "BP015SponsoredGroupHttpTransportError",
    "FortiPamBP015SponsoredGroupHttpTransport",
    "GROUP_COLLECTION_PATH",
    "GROUP_DEFAULT_PATH",
    "MEMBER_COLLECTION_PATH",
    "OWNER_COLLECTION_PATH",
    "SponsoredGroupCleanupReadback",
    "SponsoredGroupCreateReadback",
    "load_bp015_sponsored_group_http_transport_config",
]
