"""Exact-source, aggregate-only Unix Discovery result read for 7.0 build 29."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
import json
import math
import time
from typing import NoReturn
from urllib.parse import quote

import httpx

from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
    _ssl_context,
    _zeroize_mutable,
)
from .target_api_dependency_reader import _private_http_logs


CONTRACT = "fortipam_v4_unix_discovery_review_700_aggregate_v1"
SELECTION_CONTRACT = "fortipam_v4_unix_discovery_selection_700_v1"
_UNAVAILABLE = "FortiPAM Unix Discovery review is unavailable."
_MAX_BYTES = 262_144
_FIELDS = (
    "name|source-type|discovery-type|discovery-results|discovery-secret|"
    "discovery-method|last-discovery-time|auto-onboarding|schedule-status"
)
_ROW_FIELDS = frozenset(_FIELDS.split("|")) | {"q_origin_key"}
_ZERO_TIME = "0000-00-00 00:00:00"
_ACCOUNT_FIELDS = frozenset({"name", "managed-status", "last-scanned-time", "q_origin_key"})
_ENVELOPE_FIELDS = frozenset({"version", "build", "path", "name", "http_method", "http_status",
    "status", "vdom", "serial", "results", "error", "mkey", "revision", "limit_reached",
    "size", "matched_count", "next_idx"})
_READ_TTL = 30.0


class DiscoveryReviewHttpTransportError(RuntimeError):
    """Stable error without account, address, Secret, or raw response values."""


def _refuse() -> NoReturn:
    raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _refuse()
        result[key] = value
    return result


def _nonfinite(value: str) -> NoReturn:
    _refuse()


def _source_timestamp(value: object) -> None:
    # Calendar syntax only. Appliance timezone, age and a newer running scan
    # are not established by this completed retained-snapshot observation.
    if type(value) is not str or len(value) != 19 or value == _ZERO_TIME:
        _refuse()
    try:
        if datetime.strptime(value, "%Y-%m-%d %H:%M:%S").strftime("%Y-%m-%d %H:%M:%S") != value:
            _refuse()
    except (TypeError, ValueError):
        raise DiscoveryReviewHttpTransportError(_UNAVAILABLE) from None


def project_unix_discovery_review(
    response: object, request: DisabledUnixDiscoveryCreateInput,
) -> dict[str, object]:
    """Reduce one exact scanned source to counts and an onboarding-review signal."""

    if type(request) is not DisabledUnixDiscoveryCreateInput or not isinstance(response, Mapping):
        raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
    try:
        request.__post_init__()
    except ValueError:
        raise DiscoveryReviewHttpTransportError(_UNAVAILABLE) from None
    if not response.keys() <= _ENVELOPE_FIELDS:
        _refuse()
    for key, expected in dict(status="success", http_method="GET", http_status=200,
            path="secret", name="discovery", vdom="root", version="v7.0.0", build=29).items():
        value = response.get(key)
        if type(value) is not type(expected) or value != expected:
            _refuse()
    if "error" in response:
        error = response["error"]
        if error is not None and (type(error) is not int or error != 0):
            _refuse()
    if "limit_reached" in response and response["limit_reached"] is not False:
        _refuse()
    # These describe one named detail, never completeness of a global namespace.
    # Other count/continuation grammars require independent native qualification.
    for key, expected in (("size", 1), ("matched_count", 1), ("next_idx", 0)):
        if key in response and (type(response[key]) is not int or response[key] != expected):
            _refuse()
    rows = response.get("results")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping):
        raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
    row = rows[0]
    if (not _ROW_FIELDS.issuperset(row)
            or not frozenset(_FIELDS.split("|")).issubset(row)
            or row.get("name") != request.source_name
            or row.get("source-type") != "Unix-like"
            or row.get("discovery-type") != "account-discovery"
            or row.get("discovery-method") != "existing-secret"
            or type(row.get("discovery-secret")) is not int
            or row.get("discovery-secret") != request.discovery_secret_id
            or row.get("schedule-status") != "disable"
            or row.get("auto-onboarding") != "disable"
            or not isinstance(row.get("last-discovery-time"), str)
            or row.get("last-discovery-time") in {"", _ZERO_TIME}):
        raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
    _source_timestamp(row["last-discovery-time"])
    accounts = row.get("discovery-results")
    # An empty table has no qualified zero-result completion witness. It cannot
    # establish absence or authorize a "no unmanaged account" decision.
    if not isinstance(accounts, list) or not 1 <= len(accounts) <= 1000:
        raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
    statuses = []
    names: set[str] = set()
    for account in accounts:
        if not isinstance(account, Mapping) or set(account) != _ACCOUNT_FIELDS:
            raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
        name = account["name"]
        if (type(name) is not str or not 1 <= len(name) <= 255 or name in names
                or any(ord(char) < 32 or ord(char) == 127 for char in name)):
            _refuse()
        names.add(name)
        if any(type(account[key]) is not str for key in ("last-scanned-time", "q_origin_key")):
            _refuse()
        state = account.get("managed-status")
        if type(state) is not int or not 0 <= state <= 2_147_483_647:
            raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
        statuses.append(state)
    unmanaged = statuses.count(0)
    return {
        "contract": CONTRACT,
        "source_exact": True,
        "source_type": "Unix-like",
        "scan_state": "completed",
        "total_accounts": len(statuses),
        "managed_accounts": len(statuses) - unmanaged,
        "unmanaged_accounts": unmanaged,
        "onboarding_review": "needed" if unmanaged else "no_unmanaged_account",
        "periodic_scanning_disabled": True,
        "auto_onboarding_disabled": True,
        "import_executed": False,
        "device_write_executed": False,
        "account_names_returned": False,
        "credential_values_returned": False,
        "raw_api_response_returned": False,
    }


def project_unix_discovery_selection(
    response: object, request: DisabledUnixDiscoveryCreateInput,
    selected_account: str,
) -> dict[str, object]:
    """Classify one privately bound fixture account without returning its name."""

    if (not isinstance(selected_account, str)
            or not selected_account.startswith("fpam-bp014-discovery-r")
            or not selected_account.removeprefix("fpam-bp014-discovery-r").isdigit()):
        raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
    summary = project_unix_discovery_review(response, request)
    if not isinstance(response, Mapping):
        raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
    rows = response.get("results")
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], Mapping):
        raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
    accounts = rows[0].get("discovery-results")
    if not isinstance(accounts, list):
        raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
    selected = [account for account in accounts if isinstance(account, Mapping)
                and account.get("name") == selected_account]
    if len(selected) != 1 or set(selected[0]) != _ACCOUNT_FIELDS:
        raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
    unmanaged = selected[0].get("managed-status") == 0
    return {
        "contract": SELECTION_CONTRACT,
        "source_exact": True,
        "scan_state": "completed",
        "selected_account_exact": True,
        "selected_account_unmanaged": unmanaged,
        "onboarding_decision": (
            "prepare_existing_onboarding" if unmanaged else "already_managed"
        ),
        "total_accounts": summary["total_accounts"],
        "unmanaged_accounts": summary["unmanaged_accounts"],
        "selected_account_name_returned": False,
        "credential_values_returned": False,
        "raw_api_response_returned": False,
        "import_executed": False,
        "device_write_executed": False,
    }


class FortiPamDiscoveryReviewHttpTransport:
    """Read a private fixed source through strict TLS and discard full results."""

    def __init__(self, config: SecretMetadataHttpTransportConfig, *,
            clock: Callable[[], float] = time.monotonic,
            client_factory: Callable[..., httpx.Client] = httpx.Client) -> None:
        if (not isinstance(config, SecretMetadataHttpTransportConfig)
                or not callable(clock) or not callable(client_factory)):
            raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
        self._config = config
        self._clock, self._factory = clock, client_factory

    def review(self, request: DisabledUnixDiscoveryCreateInput) -> dict[str, object]:
        return project_unix_discovery_review(self._read_payload(request), request)

    def select(
        self, request: DisabledUnixDiscoveryCreateInput, selected_account: str,
    ) -> dict[str, object]:
        return project_unix_discovery_selection(
            self._read_payload(request), request, selected_account,
        )

    def _read_payload(self, request: DisabledUnixDiscoveryCreateInput) -> object:
        if type(request) is not DisabledUnixDiscoveryCreateInput:
            raise DiscoveryReviewHttpTransportError(_UNAVAILABLE)
        path = (
            "/api/v2/cmdb/secret/discovery/" + quote(request.source_name, safe="")
            + "?format=" + quote(_FIELDS, safe="") + "&vdom=root"
        )
        payload = bytearray()
        last = -1.0
        def now() -> float:
            nonlocal last
            value = self._clock()
            if type(value) not in (float, int) or not math.isfinite(value) or value < 0 or value < last:
                _refuse()
            last = float(value)
            return last
        deadline: float
        def remaining() -> float:
            value = deadline - now()
            if value <= 0:
                _refuse()
            return min(10.0, float(self._config.timeout_seconds), value)
        try:
            deadline = now() + _READ_TTL
            request.__post_init__()
            self._config.__post_init__()
            with _private_http_logs():
                client = self._factory(base_url=self._config.base_url, verify=_ssl_context(self._config),
                    timeout=remaining(), follow_redirects=False, trust_env=False)
                try:
                    with client:
                        with client.stream("GET", path, headers={
                            "Accept": "application/json", "Accept-Encoding": "identity",
                            "Authorization": f"Bearer {self._config.bearer_token}",
                            "Cache-Control": "no-cache, no-store",
                        }, timeout=remaining()) as response:
                            remaining()
                            if (response.status_code != 200 or response.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json"
                                    or response.headers.get("content-encoding", "identity").strip().lower() not in ("", "identity")):
                                _refuse()
                            iterator = response.iter_raw()
                            while True:
                                remaining()
                                try:
                                    chunk = next(iterator)
                                except StopIteration:
                                    remaining()
                                    break
                                remaining()
                                if len(payload) + len(chunk) > _MAX_BYTES:
                                    _refuse()
                                payload.extend(chunk)
                finally:
                    if not client.is_closed:
                        client.close()
            remaining()
            result = json.loads(payload, object_pairs_hook=_unique_pairs, parse_constant=_nonfinite)
            remaining()
            return result
        except Exception:
            raise DiscoveryReviewHttpTransportError(_UNAVAILABLE) from None
        finally:
            _zeroize_mutable(payload)


__all__ = [
    "CONTRACT", "SELECTION_CONTRACT", "DiscoveryReviewHttpTransportError",
    "FortiPamDiscoveryReviewHttpTransport", "project_unix_discovery_review",
    "project_unix_discovery_selection",
]
