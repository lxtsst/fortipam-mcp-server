"""One-use, exact-source Unix Account Discovery scan for FortiPAM 7.0.

This transport never enables a schedule, auto-onboarding, or Import. A POST
attempt consumes the object even when the response or readback is ambiguous.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
import threading
from typing import TYPE_CHECKING, Literal
from urllib.parse import quote

import httpx
from v4_planning.material_provider import _OpaqueC3Object

from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .discovery_entry_http_transport import inspect_discovery_entry_detail
from .discovery_review_http_transport import (
    DiscoveryReviewHttpTransportError,
    _nonfinite,
    _unique_pairs,
)
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
    _ssl_context,
    _zeroize_mutable,
)

if TYPE_CHECKING:
    from .discovery_account_run_custody import AccountDiscoveryRunCustody


_PATH = "/api/v2/internal/secret-discovery"
_UNAVAILABLE = "FortiPAM Unix Discovery scan is unavailable."
_MAX_RESPONSE_BYTES = 16_384
_MAX_FULL_SOURCE_BYTES = 262_144


class DiscoveryRunHttpTransportError(RuntimeError):
    """Stable error without source, credential, account, or response values."""


@dataclass(frozen=True, slots=True, repr=False)
class AccountDiscoveryAck(_OpaqueC3Object):
    """Parsed reply counts; no durable custody, target progress or idle claim."""

    ongoing_requests: int
    failed_requests: int

    def __post_init__(self) -> None:
        if (type(self.ongoing_requests) is not int or self.ongoing_requests < 0
                or type(self.failed_requests) is not int or self.failed_requests < 0):
            raise DiscoveryRunHttpTransportError(_UNAVAILABLE)

    @property
    def zero_requests(self) -> bool:
        return self.ongoing_requests == self.failed_requests == 0


def _account_count(value: object) -> int:
    # The pinned build29 client normalizes reply counts with Number(...).
    # Accept only its exact nonnegative integer subset, never loose coercion.
    if type(value) is int and value >= 0: return value
    if type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,15}", value):
        number = int(value)
        if number <= 9_007_199_254_740_991: return number
    raise DiscoveryRunHttpTransportError(_UNAVAILABLE)


REPLY_SHAPE_CONTRACT = "fortipam-build29-original-account-reply-shape-v1"
_WIRE_KINDS = frozenset({"unobserved", "missing", "integer", "decimal_text", "other_text", "boolean", "null", "floating", "array", "object"})


@dataclass(frozen=True, slots=True, repr=False)
class AccountDiscoveryReplyShape(_OpaqueC3Object):
    """Fixed nonmaterial original reply metadata; no counters or raw keys."""

    contract: str
    http_status: int | None
    json_content: bool
    response_complete: bool
    truncated: bool
    json_category: str
    ongoing_kind: str
    failed_kind: str
    results_kind: str
    results_ongoing_kind: str
    results_failed_kind: str
    status_category: str
    error_category: str
    root_empty: bool | None

    def __post_init__(self) -> None:
        if (self.contract != REPLY_SHAPE_CONTRACT or type(self.contract) is not str
                or self.http_status is not None and (type(self.http_status) is not int or not 100 <= self.http_status <= 599)
                or any(type(value) is not bool for value in (self.json_content, self.response_complete, self.truncated))
                or self.response_complete and self.truncated
                or any(type(value) is not str for value in (self.json_category, self.ongoing_kind, self.failed_kind))
                or self.json_category not in {"incomplete", "not_json", "empty", "invalid_json", "non_object", "object"}
                or self.ongoing_kind not in _WIRE_KINDS or self.failed_kind not in _WIRE_KINDS
                or any(type(value) is not str or value not in _WIRE_KINDS for value in (self.results_kind, self.results_ongoing_kind, self.results_failed_kind))
                or type(self.status_category) is not str or self.status_category not in {"unobserved", "missing", "success", "error", "other"}
                or type(self.error_category) is not str or self.error_category not in {"unobserved", "missing", "zero", "nonzero", "other"}
                or self.root_empty is not None and type(self.root_empty) is not bool):
            raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
        if (self.json_category == "object") != (self.ongoing_kind != "unobserved" and self.failed_kind != "unobserved"):
            raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
        if self.json_category != "object" and (self.ongoing_kind != "unobserved" or self.failed_kind != "unobserved"):
            raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
        if (not self.response_complete or self.truncated) != (self.json_category == "incomplete"):
            raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
        if self.response_complete and ((not self.json_content) != (self.json_category == "not_json")):
            raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
        if self.json_category == "object":
            if self.root_empty is None or self.results_kind == "unobserved" or self.status_category == "unobserved" or self.error_category == "unobserved":
                raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
        elif (self.root_empty is not None or any(value != "unobserved" for value in
                (self.results_kind, self.results_ongoing_kind, self.results_failed_kind, self.status_category, self.error_category))):
            raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
        if self.results_kind == "object":
            if "unobserved" in (self.results_ongoing_kind, self.results_failed_kind): raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
        elif (self.results_ongoing_kind, self.results_failed_kind) != ("unobserved", "unobserved"):
            raise DiscoveryRunHttpTransportError(_UNAVAILABLE)


def _reply_shape_record(value: object) -> AccountDiscoveryReplyShape:
    fields = {"contract", "http_status", "json_content", "response_complete", "truncated", "json_category", "ongoing_kind", "failed_kind",
        "results_kind", "results_ongoing_kind", "results_failed_kind", "status_category", "error_category", "root_empty"}
    if type(value) is not dict or set(value) != fields: raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
    return AccountDiscoveryReplyShape(**value)


def _account_reply_shape(raw: bytearray, http_status: int | None, content_type: str, *, complete: bool, truncated: bool) -> AccountDiscoveryReplyShape:
    """Project only fixed field kinds inside the protected producer."""
    if type(raw) is not bytearray or len(raw) > _MAX_RESPONSE_BYTES: raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
    category = "incomplete"; ongoing = failed = "unobserved"
    results = results_ongoing = results_failed = status = error = "unobserved"
    root_empty = None
    is_json = "json" in content_type.lower()
    if complete and not truncated:
        category = "not_json" if not is_json else "empty" if not raw else "invalid_json"
        if is_json and raw:
            try:
                value = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
                category = "object" if type(value) is dict else "non_object"
                if type(value) is dict:
                    def kind(container: dict[str, object], field: str) -> str:
                        if field not in container: return "missing"
                        item = container[field]
                        if type(item) is str:
                            try: _account_count(item)
                            except DiscoveryRunHttpTransportError: return "other_text"
                            return "decimal_text"
                        return {int: "integer", bool: "boolean", float: "floating", list: "array", dict: "object", type(None): "null"}[type(item)]
                    ongoing, failed, results = (kind(value, field) for field in ("ongoing_requests", "failed_requests", "results"))
                    if results == "object":
                        results_ongoing = kind(value["results"], "ongoing_requests")
                        results_failed = kind(value["results"], "failed_requests")
                    status = "missing" if "status" not in value else value["status"] if value["status"] in ("success", "error") else "other"
                    error = "missing" if "error" not in value else "zero" if type(value["error"]) is int and value["error"] == 0 else "nonzero" if type(value["error"]) is int else "other"
                    root_empty = not value
            except (ValueError, TypeError, KeyError, RecursionError, DiscoveryReviewHttpTransportError): category = "invalid_json"
    return AccountDiscoveryReplyShape(REPLY_SHAPE_CONTRACT, http_status, is_json, complete, truncated, category, ongoing, failed,
        results, results_ongoing, results_failed, status, error, root_empty)


def _account_reply(raw: bytearray, http_status: int | None, content_type: str, *, truncated: bool = False, complete: bool = True) -> AccountDiscoveryAck:
    if (type(raw) is not bytearray or not 0 < len(raw) <= _MAX_RESPONSE_BYTES or truncated is not False
            or complete is not True or type(http_status) is not int or http_status != 200 or type(content_type) is not str or "json" not in content_type.lower()):
        raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
    payload = json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
    if type(payload) is not dict: raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
    if payload.get("status") == "error" or type(payload.get("error")) is int and payload["error"] != 0:
        raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
    ongoing, failed = _account_count(payload.get("ongoing_requests")), _account_count(payload.get("failed_requests"))
    return AccountDiscoveryAck(ongoing, failed)


@dataclass(frozen=True, slots=True, repr=False)
class DiscoveryRunResult:
    dispatch: Literal["accepted", "ambiguous"]
    http_status: int | None
    source_scanned: bool
    auto_onboarding_disabled: bool
    import_dispatched: bool = False
    account_ack: AccountDiscoveryAck | None = None

    def __repr__(self) -> str:
        return "<DiscoveryRunResult categorical>"


class FortiPamDiscoveryRunHttpTransport:
    """Dispatch one scan only after exact disabled-source preflight."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, *, original_custody: AccountDiscoveryRunCustody | None = None) -> None:
        if not isinstance(config, SecretMetadataHttpTransportConfig):
            raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
        self._config = config
        if original_custody is not None:
            from .discovery_account_run_custody import AccountDiscoveryRunCustody
            if type(original_custody) is not AccountDiscoveryRunCustody or not original_custody.matches_transport(config):
                raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
        self._original_custody = original_custody
        self._attempted = False
        self._lock = threading.Lock()

    def inspect_unscanned(self, request: DisabledUnixDiscoveryCreateInput) -> bool:
        if type(request) is not DisabledUnixDiscoveryCreateInput:
            raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
        try:
            state = inspect_discovery_entry_detail(
                self._config,
                expected_name=request.source_name,
                expected_secret_id=request.discovery_secret_id,
                expected_source_type="Unix-like",
            )
        except Exception:
            raise DiscoveryRunHttpTransportError(_UNAVAILABLE) from None
        return bool(state and state.create_readback_verified)

    def run_once(self, request: DisabledUnixDiscoveryCreateInput) -> DiscoveryRunResult:
        with self._lock:
            if self._attempted or not self.inspect_unscanned(request):
                raise DiscoveryRunHttpTransportError(_UNAVAILABLE)
            self._attempted = True
        if self._original_custody is not None:
            try:
                self._original_custody.begin_original_send(request, self._config, self._read_full_source(request))
            except Exception:
                self._original_custody.close()
                raise DiscoveryRunHttpTransportError(_UNAVAILABLE) from None
        status: int | None = None
        response_body = bytearray()
        accepted = False
        account_ack: AccountDiscoveryAck | None = None
        content_type = ""
        truncated = False
        complete = read_complete = False
        try:
            with httpx.Client(
                base_url=self._config.base_url,
                verify=_ssl_context(self._config),
                timeout=self._config.timeout_seconds,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                with client.stream(
                    "POST", _PATH,
                    headers={
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                        "Cache-Control": "no-cache, no-store",
                    },
                    json={"discovery-name": request.source_name, "type": "discovery"},
                ) as response:
                    status = response.status_code
                    content_type = response.headers.get("content-type", "")
                    if self._original_custody is not None or status == 200 and "json" in content_type.lower():
                        for chunk in response.iter_bytes():
                            if len(response_body) + len(chunk) > _MAX_RESPONSE_BYTES:
                                truncated = True
                                break
                            response_body.extend(chunk)
                        read_complete = not truncated
            complete = read_complete
            account_ack = _account_reply(response_body, status, content_type, truncated=truncated, complete=complete)
            accepted = account_ack.failed_requests == 0
        except (httpx.HTTPError, OSError, ValueError, TypeError, RecursionError, DiscoveryReviewHttpTransportError, DiscoveryRunHttpTransportError):
            pass
        finally:
            if self._original_custody is not None:
                try:
                    self._original_custody.capture_original_ack(response_body, http_status=status, content_type=content_type, truncated=truncated, complete=complete)
                except ValueError:
                    pass
            _zeroize_mutable(response_body)

        try:
            state = inspect_discovery_entry_detail(
                self._config,
                expected_name=request.source_name,
                expected_secret_id=request.discovery_secret_id,
                expected_source_type="Unix-like",
            )
            scanned = bool(
                accepted and state and state.exact_name_found and state.source_type_matches_expected
                and state.periodic_scanning_disabled and state.auto_onboarding_disabled
                and state.discovery_secret_matches_expected is True
                and not state.no_scan_timestamp
                # A timestamp is not completion while the accepted reply still
                # reports in-flight work. Keep the consumed claim for separate
                # observation; never resend the Scan to obtain a newer reply.
                and account_ack is not None and account_ack.zero_requests
            )
            auto_onboarding_disabled = bool(state and state.auto_onboarding_disabled)
        except Exception:
            scanned = False
            auto_onboarding_disabled = False
        result = DiscoveryRunResult(
            "accepted" if accepted else "ambiguous", status, scanned,
            auto_onboarding_disabled, account_ack=account_ack,
        )
        if self._original_custody is not None and not self._original_custody._closed:
            try:
                self._original_custody.capture_original_state(request, self._read_full_source(request), result)
            except (ValueError, DiscoveryRunHttpTransportError):
                pass
        return result

    def _read_full_source(self, request: DisabledUnixDiscoveryCreateInput) -> object:
        raw = bytearray()
        try:
            with httpx.Client(base_url=self._config.base_url, verify=_ssl_context(self._config), timeout=self._config.timeout_seconds,
                    follow_redirects=False, trust_env=False) as client:
                with client.stream("GET", "/api/v2/cmdb/secret/discovery/" + quote(request.source_name, safe="") + "?vdom=root",
                        headers={"Accept": "application/json", "Accept-Encoding": "identity", "Authorization": "Bearer " + self._config.bearer_token,
                            "Cache-Control": "no-cache, no-store"}) as response:
                    if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower(): raise ValueError
                    for chunk in response.iter_bytes():
                        if len(raw) + len(chunk) > _MAX_FULL_SOURCE_BYTES: raise ValueError
                        raw.extend(chunk)
            return json.loads(raw, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
        except Exception:
            raise DiscoveryRunHttpTransportError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(raw)


__all__ = [
    "DiscoveryRunHttpTransportError", "DiscoveryRunResult",
    "AccountDiscoveryAck",
    "FortiPamDiscoveryRunHttpTransport",
]
