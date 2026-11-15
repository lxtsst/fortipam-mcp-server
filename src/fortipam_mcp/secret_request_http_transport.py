"""Fixed read-only FortiPAM Secret-request state observation.

The transport accepts one protected numeric request ID and one protected
numeric Secret ID. It returns only five categorical top-level fields. The
Secret ID is parsed as bounded ASCII digits solely for an exact relation check;
identity, comments, approver arrays, custom fields, and unknown members are
skipped as bytes. The observed 7.0 fallback decodes only bounded start/end
timestamps and timezone inside this transport to classify a time window; no
timestamp or raw value is returned.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import http.client
import json
import os
from pathlib import Path
import stat
from typing import Any, Literal, cast
from urllib.parse import urlsplit

from v4_planning.models import require_digest, require_ref

from .mutable_json_buffer import _take_mutable_prefix
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES,
    SecretMetadataHttpTransportConfig,
    _json_string_end,
    _json_value_end,
    _skip_json_space,
    _ssl_context,
    _zeroize_mutable,
)


REQUEST_COLLECTION_PATH = "/api/v2/cmdb/secret/request"
REQUEST_BINDING_CONTRACT = "fortipam-secret-request-observation-binding-v1"
REQUEST_BINDING_VERSION = "1.0.0"
_REQUEST_DETAIL_QUERY = (
    "format=secret-id%7Crequest-type%7Cfinal-status%7Cavailability-status%7C"
    "action-status%7Ccurrent-tier"
)
_REQUEST_DETAIL_V70_QUERY = "with_meta=true&vdom=root"
_DISPLAY_STATUS_FIELDS = frozenset(
    {"availability-status", "action-status", "current-tier"}
)
_V70_TIME_FIELDS = frozenset({"start-time", "expiration-time", "timezone"})
_ALLOWED_FIELDS = frozenset(
    {
        "secret-id",
        "request-type",
        "final-status",
        "availability-status",
        "action-status",
        "current-tier",
        "tier1-status",
        "start-time",
        "expiration-time",
        "timezone",
    }
)
_REQUEST_TYPES = frozenset({"launcher", "job"})
_FINAL_STATUSES = frozenset({"approved", "denied", "pending"})
_AVAILABILITY_STATUSES = frozenset(
    {"pending", "denied", "available", "unavailable", "expired"}
)
_ACTION_STATUSES = frozenset({"none", "needed", "complete", "unknown"})
_CURRENT_TIERS = {
    "first tier": "tier1",
    "second tier": "tier2",
    "third tier": "tier3",
    "complete": "complete",
    "unknown": "unknown",
    "tier1": "tier1",
    "tier2": "tier2",
    "tier3": "tier3",
}
_UNAVAILABLE = "FortiPAM Secret request observation is unavailable."
_MAX_BINDING_BYTES = 4_096


class SecretRequestHttpTransportError(RuntimeError):
    """Stable non-disclosing request-observation failure."""


@dataclass(frozen=True, slots=True)
class SecretRequestObservation:
    """Categorical request state without an ID, identity, Secret, or timing."""

    request_exists: bool
    request_type: str
    lifecycle_state: str
    approval_progress: str
    action_status: str
    raw_values_returned: bool = False
    deadline_state: Literal["unknown", "not_elapsed", "elapsed"] = "unknown"


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestObservationBinding:
    """Trusted opaque mapping; numeric Request and Secret IDs stay private."""

    request_ref: str
    request_id: int
    secret_id: int
    requester_digest: str
    environment_ref: str
    scope_ref: str
    request_type: Literal["launcher", "job"] = "launcher"

    def __post_init__(self) -> None:
        try:
            require_ref(self.request_ref, "request_ref")
            require_digest(self.requester_digest, "requester_digest")
            require_ref(self.environment_ref, "environment_ref")
            require_ref(self.scope_ref, "scope_ref")
            _positive_id(self.request_id)
            _positive_id(self.secret_id)
        except (TypeError, ValueError) as exc:
            raise SecretRequestHttpTransportError(_UNAVAILABLE) from exc
        if self.request_type not in _REQUEST_TYPES:
            raise SecretRequestHttpTransportError(_UNAVAILABLE)


class OwnerOnlySecretRequestObservationBindingResolver:
    """Load one exact protected request binding without exposing numeric IDs."""

    def __init__(self, path: Path) -> None:
        self._path = Path(path)
        if not self._path.is_absolute():
            raise SecretRequestHttpTransportError(_UNAVAILABLE)

    def resolve(
        self,
        request_ref: str,
        *,
        requester_digest: str,
        environment_ref: str,
        scope_ref: str,
    ) -> SecretRequestObservationBinding:
        payload = self._load()
        return self._resolve_payload(
            payload,
            request_ref=request_ref,
            requester_digest=requester_digest,
            environment_ref=environment_ref,
            scope_ref=scope_ref,
        )

    def _resolve_payload(
        self,
        payload: Mapping[str, object],
        *,
        request_ref: str,
        requester_digest: str,
        environment_ref: str,
        scope_ref: str,
    ) -> SecretRequestObservationBinding:
        expected = {
            "contract",
            "version",
            "request_ref",
            "request_id",
            "secret_id",
            "requester_digest",
            "environment_ref",
            "scope_ref",
            "request_type",
        }
        if (
            set(payload) != expected
            or payload.get("contract") != REQUEST_BINDING_CONTRACT
            or payload.get("version") != REQUEST_BINDING_VERSION
            or payload.get("request_ref") != request_ref
            or payload.get("requester_digest") != requester_digest
            or payload.get("environment_ref") != environment_ref
            or payload.get("scope_ref") != scope_ref
        ):
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        try:
            request_type = _string(payload, "request_type")
            if request_type not in _REQUEST_TYPES:
                raise ValueError
            return SecretRequestObservationBinding(
                request_ref=_string(payload, "request_ref"),
                request_id=_mapping_positive_id(payload, "request_id"),
                secret_id=_mapping_positive_id(payload, "secret_id"),
                requester_digest=_string(payload, "requester_digest"),
                environment_ref=_string(payload, "environment_ref"),
                scope_ref=_string(payload, "scope_ref"),
                request_type=cast(Literal["launcher", "job"], request_type),
            )
        except (TypeError, ValueError) as exc:
            raise SecretRequestHttpTransportError(_UNAVAILABLE) from exc

    def resolve_bound(
        self,
        request_ref: str,
        *,
        requester_digest: str,
    ) -> SecretRequestObservationBinding:
        """Resolve the file-bound environment and scope without caller input."""

        payload = self._load()
        try:
            environment_ref = _string(payload, "environment_ref")
            scope_ref = _string(payload, "scope_ref")
        except (TypeError, ValueError) as exc:
            raise SecretRequestHttpTransportError(_UNAVAILABLE) from exc
        return self._resolve_payload(
            payload,
            request_ref=request_ref,
            requester_digest=requester_digest,
            environment_ref=environment_ref,
            scope_ref=scope_ref,
        )

    def _load(self) -> Mapping[str, object]:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._path, flags)
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.getuid()
                    or stat.S_IMODE(metadata.st_mode) & 0o077
                    or not 0 < metadata.st_size <= _MAX_BINDING_BYTES
                ):
                    raise OSError
                content = os.read(descriptor, _MAX_BINDING_BYTES + 1)
            finally:
                os.close(descriptor)
            value = json.loads(content)
        except (OSError, UnicodeError, json.JSONDecodeError):
            raise SecretRequestHttpTransportError(_UNAVAILABLE) from None
        if not isinstance(value, Mapping):
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        return cast(Mapping[str, object], value)


class ProtectedSecretRequestObserver:
    """Expose state only through one exact requester- and scope-bound reference."""

    def __init__(
        self,
        transport: FortiPamSecretRequestHttpTransport,
        binding: SecretRequestObservationBinding,
        *,
        authorized_environment_ref: str,
        authorized_scope_ref: str,
    ) -> None:
        if not isinstance(transport, FortiPamSecretRequestHttpTransport):
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        try:
            self._environment_ref = require_ref(
                authorized_environment_ref,
                "authorized_environment_ref",
            )
            self._scope_ref = require_ref(
                authorized_scope_ref,
                "authorized_scope_ref",
            )
        except ValueError as exc:
            raise SecretRequestHttpTransportError(_UNAVAILABLE) from exc
        self._transport = transport
        self._binding = binding

    def observe(
        self,
        request_ref: str,
        *,
        requester_digest: str,
    ) -> SecretRequestObservation:
        try:
            require_ref(request_ref, "request_ref")
            require_digest(requester_digest, "requester_digest")
        except ValueError as exc:
            raise SecretRequestHttpTransportError(_UNAVAILABLE) from exc
        binding = self._binding
        if (
            request_ref != binding.request_ref
            or requester_digest != binding.requester_digest
            or binding.environment_ref != self._environment_ref
            or binding.scope_ref != self._scope_ref
        ):
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        return self._transport.observe(
            binding.request_id,
            expected_secret_id=binding.secret_id,
            expected_request_type=binding.request_type,
        )


class FortiPamSecretRequestHttpTransport:
    """Read one exact request detail and return only categorical state."""

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        connection_factory: Any | None = None,
        request_reader: Callable[[int, str], tuple[int, dict[str, object] | None, datetime | None]] | None = None,
    ) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        self._config = config
        self._connection_factory = connection_factory
        self._request_reader = request_reader

    def observe(
        self,
        request_id: int,
        *,
        expected_secret_id: int,
        expected_request_type: Literal["launcher", "job"] = "launcher",
    ) -> SecretRequestObservation:
        identifier = _positive_id(request_id)
        protected_secret_id = _positive_id(expected_secret_id)
        if expected_request_type not in _REQUEST_TYPES:
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        status, fields, server_time = self._request(identifier)
        if status == 404:
            return SecretRequestObservation(
                False,
                expected_request_type,
                "not_found",
                "unknown",
                "unknown",
            )
        if status != 200 or fields is None:
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        if not _DISPLAY_STATUS_FIELDS.issubset(fields):
            status, fields, server_time = self._request(
                identifier, query=_REQUEST_DETAIL_V70_QUERY
            )
            if status != 200 or fields is None:
                raise SecretRequestHttpTransportError(_UNAVAILABLE)
        if fields.get("secret-id") != protected_secret_id:
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        request_type = _enum(fields, "request-type", _REQUEST_TYPES)
        if request_type != expected_request_type:
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        final_status = _enum(fields, "final-status", _FINAL_STATUSES)
        deadline_state = _v70_job_deadline(fields, server_time) if request_type == "job" else "unknown"
        if not _DISPLAY_STATUS_FIELDS.issubset(fields):
            tier1_status = _enum(fields, "tier1-status", _FINAL_STATUSES)
            availability = _v70_launcher_availability(fields, server_time) if request_type == "launcher" else None
            if final_status == "approved":
                if tier1_status != "approved":
                    raise SecretRequestHttpTransportError(_UNAVAILABLE)
                lifecycle = (
                    "expired" if availability == "expired" else
                    "approved_available" if availability == "available" else
                    "approved_not_yet_available" if availability == "unavailable" else
                    "approved_availability_unknown"
                )
                progress = "complete"
            elif final_status == "denied":
                lifecycle = "denied"
                progress = "complete"
            else:
                lifecycle = "expired" if availability == "expired" else "pending"
                progress = "tier1" if tier1_status == "pending" else "unknown"
            return SecretRequestObservation(
                True,
                request_type,
                lifecycle,
                progress,
                "none" if availability == "expired" else "unknown",
                deadline_state=deadline_state,
            )
        availability = _enum(
            fields,
            "availability-status",
            _AVAILABILITY_STATUSES,
        )
        action_status = _enum(fields, "action-status", _ACTION_STATUSES)
        current_tier_raw = _text(fields, "current-tier")
        current_tier = _CURRENT_TIERS.get(current_tier_raw)
        if current_tier is None:
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        return SecretRequestObservation(
            True,
            request_type,
            _lifecycle(final_status, availability),
            current_tier,
            action_status,
            deadline_state=deadline_state,
        )

    def _request(
        self,
        request_id: int,
        *,
        query: str = _REQUEST_DETAIL_QUERY,
    ) -> tuple[int, dict[str, object] | None, datetime | None]:
        if self._request_reader is not None:
            try:
                return self._request_reader(request_id, query)
            except Exception:
                raise SecretRequestHttpTransportError(_UNAVAILABLE) from None
        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        connection: Any = None
        response: Any = None
        content = bytearray(MAX_RESPONSE_BYTES + 1)
        try:
            factory = self._connection_factory or http.client.HTTPSConnection
            connection = factory(
                parsed.hostname,
                parsed.port or 443,
                timeout=self._config.timeout_seconds,
                context=_ssl_context(self._config),
            )
            connection.request(
                "GET",
                f"{REQUEST_COLLECTION_PATH}/{request_id}?{query}",
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "User-Agent": "fortipam-mcp-v4-secret-request/1",
                },
            )
            response = connection.getresponse()
            status = int(response.status)
            if status != 200:
                return status, None, None
            server_time = _server_date(response.getheader("date", ""))
            content_type = response.getheader("content-type", "")
            if not isinstance(content_type, str) or "json" not in content_type.lower():
                raise SecretRequestHttpTransportError(_UNAVAILABLE)
            total = 0
            while total < len(content):
                view = memoryview(content)[total:]
                try:
                    count = response.readinto(view)
                finally:
                    view.release()
                if not isinstance(count, int) or count < 0:
                    raise SecretRequestHttpTransportError(_UNAVAILABLE)
                if count == 0:
                    break
                total += count
            if total > MAX_RESPONSE_BYTES:
                raise SecretRequestHttpTransportError(_UNAVAILABLE)
            content = _take_mutable_prefix(content, total)
            return status, _extract_record_fields(content), server_time
        except SecretRequestHttpTransportError:
            raise
        except Exception as exc:
            raise SecretRequestHttpTransportError(_UNAVAILABLE) from exc
        finally:
            _zeroize_mutable(content)
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


def _extract_record_fields(content: bytearray) -> dict[str, object]:
    root_start = _skip_json_space(content, 0)
    root_end = _json_value_end(content, root_start)
    if (
        root_start >= len(content)
        or content[root_start] != 123
        or _skip_json_space(content, root_end) != len(content)
    ):
        raise SecretRequestHttpTransportError(_UNAVAILABLE)
    wrapper = _object_members(content, root_start, root_end, {"results", "result"})
    record_value = wrapper.get("results", wrapper.get("result"))
    if record_value is None:
        raise SecretRequestHttpTransportError(_UNAVAILABLE)
    start, end = record_value
    start = _skip_json_space(content, start)
    if content[start] == 91:
        item_start = _skip_json_space(content, start + 1)
        item_end = _json_value_end(content, item_start)
        if (
            content[item_start] != 123
            or _skip_json_space(content, item_end) >= end
            or content[_skip_json_space(content, item_end)] != 93
        ):
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        start, end = item_start, item_end
    if content[start] != 123:
        raise SecretRequestHttpTransportError(_UNAVAILABLE)
    members = _object_members(content, start, end, _ALLOWED_FIELDS)
    result: dict[str, object] = {}
    for key in _ALLOWED_FIELDS:
        value_range = members.get(key)
        if value_range is None:
            if key in {"secret-id", "request-type", "final-status"}:
                raise SecretRequestHttpTransportError(_UNAVAILABLE)
            continue
        value_start, value_end = value_range
        if key == "secret-id":
            value = _json_positive_id(content, value_start, value_end)
        else:
            try:
                value = json.loads(content[value_start:value_end])
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SecretRequestHttpTransportError(_UNAVAILABLE) from exc
            if not isinstance(value, str):
                if key in _V70_TIME_FIELDS:
                    continue
                raise SecretRequestHttpTransportError(_UNAVAILABLE)
        result[key] = value
    return result


def _object_members(
    content: bytearray,
    start: int,
    end: int,
    selected: set[str] | frozenset[str],
) -> dict[str, tuple[int, int]]:
    if content[start] != 123 or end <= start or content[end - 1] != 125:
        raise SecretRequestHttpTransportError(_UNAVAILABLE)
    cursor = _skip_json_space(content, start + 1)
    result: dict[str, tuple[int, int]] = {}
    while cursor < end - 1:
        if content[cursor] != 34:
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        key_end = _json_string_end(content, cursor)
        try:
            key = json.loads(content[cursor : key_end + 1])
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecretRequestHttpTransportError(_UNAVAILABLE) from exc
        separator = _skip_json_space(content, key_end + 1)
        if not isinstance(key, str) or separator >= end or content[separator] != 58:
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        value_start = _skip_json_space(content, separator + 1)
        value_end = _json_value_end(content, value_start)
        if key in selected:
            if key in result:
                raise SecretRequestHttpTransportError(_UNAVAILABLE)
            result[key] = (value_start, value_end)
        cursor = _skip_json_space(content, value_end)
        if cursor == end - 1:
            break
        if content[cursor] != 44:
            raise SecretRequestHttpTransportError(_UNAVAILABLE)
        cursor = _skip_json_space(content, cursor + 1)
    return result


def _positive_id(value: int) -> int:
    if type(value) is not int or not 0 < value <= 2_147_483_647:
        raise SecretRequestHttpTransportError(_UNAVAILABLE)
    return value


def _string(mapping: Mapping[str, object], name: str) -> str:
    value = mapping.get(name)
    if not isinstance(value, str):
        raise SecretRequestHttpTransportError(_UNAVAILABLE)
    return value


def _mapping_positive_id(mapping: Mapping[str, object], name: str) -> int:
    value = mapping.get(name)
    if type(value) is not int:
        raise SecretRequestHttpTransportError(_UNAVAILABLE)
    return _positive_id(value)


def _json_positive_id(content: bytearray, start: int, end: int) -> int:
    raw = content[start:end]
    if not raw or len(raw) > 10 or any(value < 48 or value > 57 for value in raw):
        raise SecretRequestHttpTransportError(_UNAVAILABLE)
    value = int(raw)
    return _positive_id(value)


def _text(fields: dict[str, object], key: str) -> str:
    value = fields.get(key)
    if not isinstance(value, str):
        raise SecretRequestHttpTransportError(_UNAVAILABLE)
    return value


def _enum(fields: dict[str, object], key: str, values: frozenset[str]) -> str:
    value = _text(fields, key)
    if value not in values:
        raise SecretRequestHttpTransportError(_UNAVAILABLE)
    return value


def _server_date(value: object) -> datetime | None:
    if not isinstance(value, str) or not 0 < len(value) <= 80:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _v70_job_deadline(
    fields: dict[str, object], server_time: datetime | None,
) -> Literal["unknown", "not_elapsed", "elapsed"]:
    """Report elapsed time independently of product approval/availability state."""
    if (server_time is None or fields.get("timezone") != "Asia/Shanghai"
            or abs(datetime.now(timezone.utc) - server_time) > timedelta(minutes=5)):
        return "unknown"
    raw = fields.get("expiration-time")
    if not isinstance(raw, str) or len(raw) != 19:
        return "unknown"
    try:
        end = datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return "unknown"
    if end.strftime("%Y-%m-%d %H:%M:%S") != raw:
        return "unknown"
    end_at = end.replace(tzinfo=timezone(timedelta(hours=8)))
    return "elapsed" if server_time > end_at else "not_elapsed"


def _v70_launcher_availability(
    fields: dict[str, object], server_time: datetime | None,
) -> str | None:
    """Compute the observed build-29 Shanghai window from its server clock."""
    if (server_time is None or fields.get("timezone") != "Asia/Shanghai"
        or abs(datetime.now(timezone.utc) - server_time) > timedelta(minutes=5)):
        return None
    start_raw = fields.get("start-time")
    end_raw = fields.get("expiration-time")
    if (not isinstance(start_raw, str) or not isinstance(end_raw, str)
        or len(start_raw) != 19 or len(end_raw) != 19):
        return None
    try:
        start = datetime.strptime(start_raw, "%Y-%m-%d %H:%M:%S")
        end = datetime.strptime(end_raw, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    if (start.strftime("%Y-%m-%d %H:%M:%S") != start_raw
        or end.strftime("%Y-%m-%d %H:%M:%S") != end_raw or end <= start):
        return None
    shanghai = timezone(timedelta(hours=8))
    start_at = start.replace(tzinfo=shanghai)
    end_at = end.replace(tzinfo=shanghai)
    if server_time < start_at:
        return "unavailable"
    if server_time > end_at:
        return "expired"
    return "available"


def _lifecycle(final_status: str, availability: str) -> str:
    if availability == "expired":
        return "expired"
    if final_status == "denied" or availability == "denied":
        return "denied"
    if final_status == "approved" and availability == "available":
        return "approved_available"
    if final_status == "approved" and availability == "unavailable":
        return "approved_not_yet_available"
    if final_status == "pending" and availability in {"pending", "unavailable"}:
        return "pending"
    return "unrecognized"


__all__ = [
    "FortiPamSecretRequestHttpTransport",
    "OwnerOnlySecretRequestObservationBindingResolver",
    "ProtectedSecretRequestObserver",
    "REQUEST_BINDING_CONTRACT",
    "REQUEST_BINDING_VERSION",
    "REQUEST_COLLECTION_PATH",
    "SecretRequestHttpTransportError",
    "SecretRequestObservation",
    "SecretRequestObservationBinding",
]
