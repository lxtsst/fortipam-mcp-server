"""Fixed REST transport for one bounded FortiPAM Report Layout create action.

The transport reads the built-in ``default`` layout, accepts only its exact
bounded no-email daily shape, clones it under one MCP-controlled alphanumeric
name, and performs categorical readback. It is not a generic report API and it
never returns report body content or raw FortiPAM payloads through MCP.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
import hashlib
import json
import re
import ssl
from typing import Any, Literal
from urllib.parse import quote

from .character_set_http_transport import (
    CharacterSetHttpTransportConfig,
    load_character_set_http_transport_config,
)


COLLECTION_PATH = "/api/v2/cmdb/report/layout"
DEFAULT_DETAIL_PATH = f"{COLLECTION_PATH}/default"
REPORT_LAYOUT_NAME_PREFIX = "MCPV4Report"
REPORT_LAYOUT_DELETE_NAME = "MCPV4ReportB163Accept"
MAX_RESPONSE_BYTES = 1_048_576
_NAME = re.compile(r"MCPV4Report[A-Za-z0-9]{1,36}\Z")
_UNAVAILABLE = "FortiPAM V4 Report Layout action is unavailable."
_TOP_LEVEL_KEYS = frozenset(
    {
        "body-item",
        "cutoff-option",
        "cutoff-time",
        "day",
        "description",
        "email-recipients",
        "email-send",
        "format",
        "max-pdf-report",
        "name",
        "options",
        "page",
        "q_origin_key",
        "schedule-type",
        "style-theme",
        "subtitle",
        "time",
        "title",
    }
)
_BODY_ITEM_KEYS = frozenset(
    {
        "chart",
        "chart-options",
        "content",
        "description",
        "id",
        "img-src",
        "misc-component",
        "parameters",
        "q_origin_key",
        "style",
        "text-component",
        "title",
        "top-n",
        "type",
    }
)
_PAGE_KEYS = frozenset(
    {
        "column-break-before",
        "footer",
        "header",
        "options",
        "page-break-before",
        "paper",
    }
)
_PAGE_COMPONENT_KEYS = frozenset(
    {
        "content",
        "description",
        "id",
        "img-src",
        "q_origin_key",
        "style",
        "type",
    }
)
_FIXED_SCALARS: Mapping[str, object] = {
    "cutoff-option": "run-time",
    "cutoff-time": "00:00",
    "day": "sunday",
    "email-send": "disable",
    "format": "pdf",
    "max-pdf-report": 31,
    "options": "include-table-of-content view-chart-as-heading",
    "schedule-type": "daily",
    "style-theme": "default-report",
    "time": "00:00",
}


class ReportLayoutHttpTransportError(RuntimeError):
    """Raised for a bounded Report Layout API transport or schema failure."""


@dataclass(frozen=True, slots=True)
class ReportLayoutInspection:
    """Categorical current state plus the private eligible-default digest."""

    exists: bool
    default_eligible: bool
    default_digest: str


@dataclass(frozen=True, slots=True)
class ReportLayoutReadback:
    """Categorical post-write evidence without returning report content."""

    exists: bool
    name_matches: bool
    default_clone_matches: bool
    daily_schedule_matches: bool
    email_disabled: bool
    filters_absent: bool
    body_item_count_matches: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.exists,
                self.name_matches,
                self.default_clone_matches,
                self.daily_schedule_matches,
                self.email_disabled,
                self.filters_absent,
                self.body_item_count_matches,
            )
        )


@dataclass(frozen=True, slots=True)
class ReportLayoutDeleteInspection:
    """Categorical eligibility for the one accepted fixed-layout recovery."""

    exists: bool
    eligible_fixed_clone: bool
    target_digest: str


@dataclass(frozen=True, slots=True)
class ReportLayoutDeleteReadback:
    """Categorical absence evidence after one fixed DELETE."""

    absent: bool

    @property
    def verified(self) -> bool:
        return self.absent


class FortiPamReportLayoutHttpTransport:
    """Issue only fixed default/detail/create/readback report requests."""

    def __init__(
        self,
        config: CharacterSetHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect(self, name: str) -> ReportLayoutInspection:
        """Read the eligible default and target presence without report content."""

        safe_name = _name(name)
        default = self._read_eligible_default()
        target_status, target_payload = self._request(
            "GET", self._detail_path(safe_name), None
        )
        if target_status == 404:
            exists = False
        elif target_status == 200 and _record(target_payload) is not None:
            exists = True
        else:
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        return ReportLayoutInspection(
            exists=exists,
            default_eligible=True,
            default_digest=_template_digest(default),
        )

    def create_and_readback(
        self,
        name: str,
        expected_default_digest: str,
    ) -> ReportLayoutReadback:
        """Clone the unchanged eligible default and categorically verify it."""

        safe_name = _name(name)
        if not _digest(expected_default_digest):
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        default = self._read_eligible_default()
        if not _constant_time_equal(
            _template_digest(default), expected_default_digest
        ):
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        body = deepcopy(default)
        body["name"] = safe_name
        status, payload = self._request("POST", COLLECTION_PATH, body)
        if status != 200 or not _successful_response(payload):
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)

        detail_status, detail_payload = self._request(
            "GET", self._detail_path(safe_name), None
        )
        target_raw = _record(detail_payload)
        if detail_status != 200 or target_raw is None:
            return _failed_readback()
        try:
            target = _sanitize_layout(target_raw, expected_name=safe_name)
        except ReportLayoutHttpTransportError:
            return _failed_readback()
        body_items = target["body-item"]
        filters_absent = isinstance(body_items, list) and all(
            isinstance(item, Mapping) and item.get("parameters") == []
            for item in body_items
        )
        return ReportLayoutReadback(
            exists=True,
            name_matches=target.get("name") == safe_name,
            default_clone_matches=_constant_time_equal(
                _template_digest(target), expected_default_digest
            ),
            daily_schedule_matches=(
                target.get("schedule-type") == "daily"
                and target.get("time") == "00:00"
                and target.get("day") == "sunday"
            ),
            email_disabled=(
                target.get("email-send") == "disable"
                and target.get("email-recipients") == ""
            ),
            filters_absent=filters_absent,
            body_item_count_matches=isinstance(body_items, list)
            and len(body_items) == 36,
        )

    def inspect_delete_target(self) -> ReportLayoutDeleteInspection:
        """Inspect only the accepted b163 target and unchanged default clone."""

        default = self._read_eligible_default()
        status, payload = self._request(
            "GET",
            self._detail_path(REPORT_LAYOUT_DELETE_NAME),
            None,
        )
        if status == 404:
            return ReportLayoutDeleteInspection(False, False, "0" * 64)
        record = _record(payload)
        if status != 200 or record is None:
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        target = _sanitize_layout(record, expected_name=REPORT_LAYOUT_DELETE_NAME)
        eligible = _constant_time_equal(
            _template_digest(target),
            _template_digest(default),
        )
        return ReportLayoutDeleteInspection(
            exists=True,
            eligible_fixed_clone=eligible,
            target_digest=_layout_digest(target),
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> ReportLayoutDeleteReadback:
        """Delete only the unchanged accepted target and prove fixed absence."""

        if not _digest(expected_target_digest):
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_clone
            or not _constant_time_equal(
                inspection.target_digest,
                expected_target_digest,
            )
        ):
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        status, payload = self._request(
            "DELETE",
            self._detail_path(REPORT_LAYOUT_DELETE_NAME),
            None,
        )
        if status != 200 or not _successful_response(payload):
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        readback_status, _ = self._request(
            "GET",
            self._detail_path(REPORT_LAYOUT_DELETE_NAME),
            None,
        )
        return ReportLayoutDeleteReadback(absent=readback_status == 404)

    def _read_eligible_default(self) -> dict[str, object]:
        status, payload = self._request("GET", DEFAULT_DETAIL_PATH, None)
        record = _record(payload)
        if status != 200 or record is None:
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        return _sanitize_layout(record, expected_name="default")

    def _request(
        self,
        method: Literal["GET", "POST", "DELETE"],
        path: str,
        body: Mapping[str, object] | None,
    ) -> tuple[int, object | None]:
        try:
            import httpx

            factory = self._client_factory or httpx.Client
            with factory(
                verify=_ssl_context(self._config),
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                response = client.request(
                    method,
                    f"{self._config.base_url}{path}",
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                    },
                    json=body,
                )
        except Exception as exc:
            raise ReportLayoutHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ReportLayoutHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path(name: str) -> str:
        return f"{COLLECTION_PATH}/{quote(name, safe='')}"


def load_report_layout_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> CharacterSetHttpTransportConfig:
    """Reuse the established central REST identity; create no new account."""

    return load_character_set_http_transport_config(environment)


def _sanitize_layout(
    record: Mapping[str, object],
    *,
    expected_name: str,
) -> dict[str, object]:
    if set(record) != _TOP_LEVEL_KEYS or record.get("name") != expected_name:
        raise ReportLayoutHttpTransportError(_UNAVAILABLE)
    for key, value in _FIXED_SCALARS.items():
        if record.get(key) != value:
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
    if record.get("email-recipients") != "":
        raise ReportLayoutHttpTransportError(_UNAVAILABLE)
    for key in ("description", "subtitle", "title"):
        _bounded_string(record.get(key))

    page = record.get("page")
    if not isinstance(page, Mapping) or set(page) != _PAGE_KEYS:
        raise ReportLayoutHttpTransportError(_UNAVAILABLE)
    safe_page: dict[str, object] = {}
    for key, value in page.items():
        if key == "header":
            safe_page[key] = _sanitize_page_section(
                value,
                item_key="header-item",
                expected_count=1,
            )
        elif key == "footer":
            safe_page[key] = _sanitize_page_section(
                value,
                item_key="footer-item",
                expected_count=2,
            )
        else:
            safe_page[str(key)] = _bounded_string(value)

    body_items = record.get("body-item")
    if not isinstance(body_items, list) or len(body_items) != 36:
        raise ReportLayoutHttpTransportError(_UNAVAILABLE)
    safe_items: list[dict[str, object]] = []
    ids: set[int] = set()
    for item in body_items:
        if not isinstance(item, Mapping) or not set(item).issubset(_BODY_ITEM_KEYS):
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        item_id = item.get("id")
        if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id in ids:
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        ids.add(item_id)
        if item.get("parameters") != []:
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        safe_item: dict[str, object] = {}
        for key, value in item.items():
            if key == "q_origin_key":
                _bounded_integer(value)
            elif key in {"id", "top-n"}:
                safe_item[str(key)] = _bounded_integer(value)
            elif key == "parameters":
                safe_item[str(key)] = []
            else:
                safe_item[str(key)] = _bounded_string(value)
        safe_items.append(safe_item)

    safe: dict[str, object] = {}
    for key, value in record.items():
        if key == "q_origin_key":
            _bounded_string(value)
        elif key == "body-item":
            safe[key] = safe_items
        elif key == "page":
            safe[key] = safe_page
        elif key == "name":
            safe[key] = expected_name
        elif key in _FIXED_SCALARS:
            safe[key] = value
        else:
            safe[key] = _bounded_string(value)
    return safe


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _sanitize_page_section(
    value: object,
    *,
    item_key: str,
    expected_count: int,
) -> dict[str, object]:
    if not isinstance(value, Mapping) or set(value) != {item_key, "style"}:
        raise ReportLayoutHttpTransportError(_UNAVAILABLE)
    style = _bounded_string(value.get("style"))
    items = value.get(item_key)
    if not isinstance(items, list) or len(items) != expected_count:
        raise ReportLayoutHttpTransportError(_UNAVAILABLE)
    safe_items: list[dict[str, object]] = []
    ids: set[int] = set()
    for item in items:
        if not isinstance(item, Mapping) or set(item) != _PAGE_COMPONENT_KEYS:
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        item_id = _bounded_integer(item.get("id"))
        if item_id in ids:
            raise ReportLayoutHttpTransportError(_UNAVAILABLE)
        ids.add(item_id)
        _bounded_integer(item.get("q_origin_key"))
        safe_items.append(
            {
                str(key): (
                    item_id
                    if key == "id"
                    else _bounded_string(item_value)
                )
                for key, item_value in item.items()
                if key != "q_origin_key"
            }
        )
    return {item_key: safe_items, "style": style}


def _template_digest(layout: Mapping[str, object]) -> str:
    projection = deepcopy(dict(layout))
    projection.pop("name", None)
    return hashlib.sha256(
        json.dumps(
            projection,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _layout_digest(layout: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            layout,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _bounded_string(value: object) -> str:
    if not isinstance(value, str) or len(value) > 32_768:
        raise ReportLayoutHttpTransportError(_UNAVAILABLE)
    return value


def _bounded_integer(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or abs(value) > 9_223_372_036_854_775_807
    ):
        raise ReportLayoutHttpTransportError(_UNAVAILABLE)
    return value


def _name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise ReportLayoutHttpTransportError(_UNAVAILABLE)
    return value


def _digest(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _constant_time_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left, right)


def _successful_response(payload: object) -> bool:
    return isinstance(payload, Mapping) and payload.get("http_status") in {None, 200}


def _ssl_context(config: CharacterSetHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise ReportLayoutHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def _failed_readback() -> ReportLayoutReadback:
    return ReportLayoutReadback(False, False, False, False, False, False, False)


__all__ = [
    "COLLECTION_PATH",
    "DEFAULT_DETAIL_PATH",
    "REPORT_LAYOUT_DELETE_NAME",
    "REPORT_LAYOUT_NAME_PREFIX",
    "FortiPamReportLayoutHttpTransport",
    "ReportLayoutHttpTransportError",
    "ReportLayoutInspection",
    "ReportLayoutDeleteInspection",
    "ReportLayoutDeleteReadback",
    "ReportLayoutReadback",
    "load_report_layout_http_transport_config",
]
