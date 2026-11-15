"""Private full-row preservation across one Unix Source scan; no I/O or authority.

The owner-side producer must independently establish original creation custody,
the native fixture and authenticated scope. These content witnesses cannot
authorize deletion, establish latest-run freshness, or reconcile an UNKNOWN.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import hmac
import json
import re
from typing import NoReturn, cast

from .discovery_entry_create_contract import DisabledUnixDiscoveryCreateInput
from .discovery_entry_create_http_transport import DiscoveryEntryCreateResult
from .discovery_entry_projection import DiscoveryEntryReadback
from .discovery_review_http_transport import project_unix_discovery_selection
from .discovery_run_http_transport import AccountDiscoveryAck, DiscoveryRunResult


CONTRACT = "fortipam-unix-discovery-source-scan-preservation-v1"
_UNAVAILABLE = "Owned Unix Discovery source preservation is unavailable."
_ZERO_TIME = "0000-00-00 00:00:00"
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_SOURCE = re.compile(r"bp014-discovery-unix-disabled-[0-9]{8}-r[0-9]+\Z")
_ACCOUNT = re.compile(r"fpam-bp014-discovery-r[0-9]{9}\Z")
_REVIEW_FIELDS = frozenset({
    "name", "source-type", "discovery-type", "discovery-results", "discovery-secret",
    "discovery-method", "last-discovery-time", "auto-onboarding", "schedule-status",
})


class DiscoverySourcePreservationError(RuntimeError):
    """No record contents, selectors, credentials or source-key details."""


def _require(value: object) -> None:
    if not value:
        raise DiscoverySourcePreservationError(_UNAVAILABLE)


def _canonical(value: object) -> bytes:
    remaining = 16_384

    def validate(item: object, depth: int) -> None:
        nonlocal remaining
        remaining -= 1
        _require(depth <= 10 and remaining >= 0)
        if type(item) in (str, int, bool, type(None)):
            return
        if type(item) is list:
            _require(len(item) <= 4096)
            for child in item:
                validate(child, depth + 1)
            return
        if type(item) is dict:
            _require(len(item) <= 256 and all(type(key) is str for key in item))
            for child in item.values():
                validate(child, depth + 1)
            return
        raise DiscoverySourcePreservationError(_UNAVAILABLE)

    validate(value, 0)
    result = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    _require(len(result) <= 262_144)
    return result


class OwnedUnixDiscoveryScanPreservation:
    """Pin complete Source content, allowing only the scan timestamp/results delta."""

    __slots__ = ("_request", "_selected", "_scope", "_key", "_birth_pin", "_scan_pin")

    def __init__(
        self, request: DisabledUnixDiscoveryCreateInput, selected_account: str,
        *, actor_digest: str, device_digest: str, fixture_birth_digest: str,
        creation: DiscoveryEntryCreateResult, original_source: Mapping[str, object],
        key: bytearray,
    ) -> None:
        self._key = bytearray()
        try:
            _require(type(request) is DisabledUnixDiscoveryCreateInput)
            _require(_SOURCE.fullmatch(request.source_name))
            _require(type(selected_account) is str and _ACCOUNT.fullmatch(selected_account))
            scope = (actor_digest, device_digest, fixture_birth_digest)
            _require(all(type(value) is str and _DIGEST.fullmatch(value) for value in scope))
            _require(type(key) is bytearray and len(key) == 32)
            _require(type(creation) is DiscoveryEntryCreateResult)
            _require(type(creation.readback) is DiscoveryEntryReadback
                and all(type(value) is bool for value in asdict(creation.readback).values()))
            _require(creation.exact_get_404_before_create is True and creation.post_category == "http_200"
                and type(creation.post_http_status) is int and creation.post_http_status == 200 and creation.verified)
            self._request, self._selected, self._scope = request, selected_account, scope
            self._key = bytearray(key)
            self._scan_pin: str | None = None
            row = self._row(original_source)
            _require(row.get("last-discovery-time") == _ZERO_TIME and row.get("discovery-results") == [])
            self._birth_pin = self._pin(row)
        except Exception:
            self.close()
            raise DiscoverySourcePreservationError(_UNAVAILABLE) from None

    def __repr__(self) -> str:
        return "<OwnedUnixDiscoveryScanPreservation protected>"

    __str__ = __repr__

    def __copy__(self) -> NoReturn:
        raise DiscoverySourcePreservationError(_UNAVAILABLE)

    def __deepcopy__(self, memo: object) -> NoReturn:
        del memo
        raise DiscoverySourcePreservationError(_UNAVAILABLE)

    def __reduce_ex__(self, protocol: object) -> NoReturn:
        del protocol
        raise DiscoverySourcePreservationError(_UNAVAILABLE)

    def _row(self, response: Mapping[str, object]) -> dict[str, object]:
        _require(type(response) is dict)
        for field, expected in dict(status="success", http_method="GET", http_status=200,
                path="secret", name="discovery", vdom="root", version="v7.0.0", build=29).items():
            _require(type(response.get(field)) is type(expected) and response.get(field) == expected)
        serial = response.get("serial")
        _require(type(serial) is str and 1 <= len(serial) <= 96)
        _require(hashlib.sha256(cast(str, serial).encode()).hexdigest() == self._scope[1])
        _require(response.get("limit_reached", False) is False)
        rows = response.get("results")
        _require(type(rows) is list and len(rows) == 1 and type(rows[0]) is dict)
        row = cast(list[dict[str, object]], rows)[0]
        # The POST serializer contains disabled-feature placeholders that the
        # native GET normalizes. Require the accepted action's scope here, then
        # pin every returned field unchanged; never reconstruct a GET from POST.
        expected = {"name": self._request.source_name, "source-type": "Unix-like",
            "discovery-type": "account-discovery", "discovery-method": "existing-secret",
            "discovery-secret": self._request.discovery_secret_id,
            "schedule-status": "disable", "auto-onboarding": "disable"}
        for field, value in expected.items():
            _require(type(row.get(field)) is type(value) and row.get(field) == value)
        if "q_origin_key" in row:
            _require(row["q_origin_key"] == self._request.source_name)
        _require("last-discovery-time" in row and "discovery-results" in row)
        _canonical(row)
        return row

    def _pin(self, row: dict[str, object]) -> str:
        _require(len(self._key) == 32)
        return hmac.new(self._key, _canonical({"contract": CONTRACT,
            "scope": list(self._scope), "selected_account": self._selected, "row": row}), hashlib.sha256).hexdigest()

    def _check_scope(self, actor_digest: str, device_digest: str, fixture_birth_digest: str) -> None:
        _require(len(self._key) == 32)
        _require((actor_digest, device_digest, fixture_birth_digest) == self._scope)

    def accept_completed_scan(
        self, response: Mapping[str, object], run: DiscoveryRunResult,
        *, actor_digest: str, device_digest: str, fixture_birth_digest: str,
    ) -> dict[str, object]:
        try:
            self._check_scope(actor_digest, device_digest, fixture_birth_digest)
            _require(self._scan_pin is None)
            _require(type(run) is DiscoveryRunResult and run.dispatch == "accepted"
                and type(run.http_status) is int and run.http_status == 200
                and run.source_scanned is True and run.auto_onboarding_disabled is True
                and run.import_dispatched is False)
            _require(type(run.account_ack) is AccountDiscoveryAck)
            ack = cast(AccountDiscoveryAck, run.account_ack)
            ack.__post_init__()
            _require(ack.zero_requests)
            row = self._row(response)
            review = {field: value for field, value in response.items() if field != "results"}
            review["results"] = [{field: row[field] for field in _REVIEW_FIELDS}]
            selection = project_unix_discovery_selection(review, self._request, self._selected)
            _require(selection["selected_account_unmanaged"] is True
                and selection["onboarding_decision"] == "prepare_existing_onboarding")
            normalized = dict(row, **{"last-discovery-time": _ZERO_TIME, "discovery-results": []})
            _require(hmac.compare_digest(self._birth_pin, self._pin(normalized)))
            self._scan_pin = self._pin(row)
            return self._summary()
        except Exception:
            raise DiscoverySourcePreservationError(_UNAVAILABLE) from None

    def inspect_accepted_scan(
        self, response: Mapping[str, object], *, actor_digest: str,
        device_digest: str, fixture_birth_digest: str,
    ) -> dict[str, object]:
        try:
            self._check_scope(actor_digest, device_digest, fixture_birth_digest)
            _require(self._scan_pin is not None)
            _require(hmac.compare_digest(str(self._scan_pin), self._pin(self._row(response))))
            return self._summary()
        except Exception:
            raise DiscoverySourcePreservationError(_UNAVAILABLE) from None

    @staticmethod
    def _summary() -> dict[str, object]:
        return {"contract": CONTRACT, "original_configuration_preserved": True,
            "exact_unmanaged_scan_row_pinned": True, "credential_values_returned": False,
            "raw_source_returned": False, "latest_run_or_timezone_qualified": False,
            "source_recovery_authorized": False, "device_write_executed": False}

    def close(self) -> None:
        self._key[:] = b"\x00" * len(self._key)
        self._key.clear()
