"""Fixed build-29 Unix automatic-change schedule with an Owner session.

This unregistered transport implements only custom daily interval-one enable
and disable. A composition root must supply durable dispatch authorization.
Credential fields stay inside the final exchange and never enter readback.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.cookies import SimpleCookie
import http.client
import json
from threading import Lock
from typing import Any
from urllib.parse import quote, urlsplit

from .owner_session_metadata import OwnerSessionMetadataTransport
from .secret_metadata_http_transport import (
    COLLECTION_PATH, MAX_RESPONSE_BYTES, FortiPamSecretMetadataHttpTransport,
    SecretMetadataHttpTransportConfig, _record, _redact_json_field_values,
    _ssl_context, _zeroize_mutable,
)
from .secret_session_controls_http_transport import _successful_response

_UNAVAILABLE = "FortiPAM automatic-change schedule is unavailable."
_TEMPLATE = "Unix Account (SSH Password)"
_ZONE = timezone(timedelta(hours=8))


class PasswordChangeScheduleError(RuntimeError):
    """Stable error without device text or protected bindings."""


@dataclass(frozen=True, slots=True, repr=False)
class PasswordChangeScheduleBinding:
    folder_path: str
    owner_name: str
    secret_name: str
    policy_name: str
    target_name: str
    target_address: str
    account_name: str


@dataclass(frozen=True, slots=True, repr=False)
class PasswordChangeScheduleState:
    secret_id: int
    folder_id: int
    enabled: bool
    uses_policy_default: bool
    frequency: str
    interval: int
    start_epoch: int


@dataclass(frozen=True, slots=True)
class PasswordChangeScheduleReadback:
    accepted: bool
    verified: bool
    enabled: bool
    logout_verified: bool


class FortiPamPasswordChangeScheduleHttpTransport:
    """One fixed dispatch per instance, with fresh binding and Policy checks."""

    def __init__(self, config: SecretMetadataHttpTransportConfig,
                 binding: PasswordChangeScheduleBinding,
                 credentials: Callable[[], tuple[str, str]], *,
                 clock: Callable[[], datetime] | None = None) -> None:
        if not isinstance(binding, PasswordChangeScheduleBinding) or not all(
            isinstance(value, str) and value and not any(ord(c) < 32 for c in value)
            for value in (binding.folder_path, binding.owner_name, binding.secret_name,
                          binding.policy_name, binding.target_name,
                          binding.target_address, binding.account_name)
        ):
            raise PasswordChangeScheduleError(_UNAVAILABLE)
        self._config, self._binding, self._credentials = config, binding, credentials
        self._clock = clock or (lambda: datetime.now(_ZONE))
        self._witness = FortiPamSecretMetadataHttpTransport(
            config, bound_secret_name=binding.secret_name,
        )
        self._lock = Lock()
        self._dispatched = False

    def _session(self) -> OwnerSessionMetadataTransport:
        b = self._binding
        return OwnerSessionMetadataTransport(
            self._config, owner_name=b.owner_name, credentials=self._credentials,
            folder_path=b.folder_path, secret_name=b.secret_name,
            target_name=b.target_name, witness=self._witness,
        )

    def inspect(self) -> PasswordChangeScheduleState:
        try:
            owner = self._session()
            with owner.authenticated():
                result = self._inspect(owner)
            if not owner.logout_verified:
                raise ValueError
            return result
        except Exception:
            raise PasswordChangeScheduleError(_UNAVAILABLE) from None

    def _inspect(self, owner: OwnerSessionMetadataTransport) -> PasswordChangeScheduleState:
        b = self._binding
        folder_id = owner.resolve_folder_id(b.folder_path)
        if not owner._verify_collector_folder_acl(folder_id, b.owner_name):
            raise ValueError
        status, payload = owner._request(
            "GET", f"/api/v2/cmdb/secret/folder/{folder_id}", None,
            query="format=id%7Cinherit-policy%7Csecret-policy",
        )
        folder = _record(payload)
        if (status != 200 or folder is None or folder.get("id") != folder_id
                or folder.get("inherit-policy") != "disable"
                or folder.get("secret-policy") != b.policy_name):
            raise ValueError
        status, payload = self._witness._request(
            "GET", "/api/v2/cmdb/secret/policy/" + quote(b.policy_name, safe=""), None,
        )
        policy = _record(payload)
        if (status != 200 or policy is None or policy.get("name") != b.policy_name
                or policy.get("password-changer") != "not-set"):
            raise ValueError
        secret_id = owner._lookup_id("secret", b.folder_path + "/" + b.secret_name)
        if type(secret_id) is not int or secret_id <= 0:
            raise ValueError
        row = self._read(owner, secret_id)
        return self._state(row, secret_id, folder_id)

    def _state(self, row: Mapping[str, Any], secret_id: int, folder_id: int) -> PasswordChangeScheduleState:
        self._identity(row, secret_id, folder_id)
        changer, defaults = row.get("password-changer"), row.get("pwd-chg-use-policy-default")
        interval, start = row.get("pwd-chg-sch-interval"), row.get("pwd-chg-sch-start-date")
        if (changer not in {"enable", "disable"} or defaults not in {"enable", "disable"}
                or row.get("pwd-chg-sch-frequency") not in {"day", "week", "month"}
                or type(interval) is not int or not 1 <= interval <= 400
                or type(start) is not int or start < 0):
            raise ValueError
        return PasswordChangeScheduleState(secret_id, folder_id, changer == "enable",
            defaults == "enable", row["pwd-chg-sch-frequency"], interval, start)

    def enable_and_readback(self, expected: PasswordChangeScheduleState) -> PasswordChangeScheduleReadback:
        return self._mutate(expected, enabled=True)

    def disable_and_readback(self, expected: PasswordChangeScheduleState) -> PasswordChangeScheduleReadback:
        return self._mutate(expected, enabled=False)

    def _mutate(self, expected: PasswordChangeScheduleState, *, enabled: bool) -> PasswordChangeScheduleReadback:
        with self._lock:
            try:
                if (self._dispatched or not isinstance(expected, PasswordChangeScheduleState)
                        or expected.enabled == enabled
                        or (not enabled and (expected.uses_policy_default
                            or expected.frequency != "day" or expected.interval != 1
                            or expected.start_epoch <= 0))):
                    raise ValueError
                owner = self._session()
                with owner.authenticated():
                    if self._inspect(owner) != expected:
                        raise ValueError
                    start = (int((self._clock() + timedelta(minutes=5)).timestamp())
                             if enabled else expected.start_epoch)
                    row = self._read(owner, expected.secret_id, protected=True)
                    body: dict[str, object] = {}
                    fields: list[dict[str, Any]] = []
                    try:
                        if self._state(row, expected.secret_id, expected.folder_id) != expected:
                            raise ValueError
                        fields = self._retained_fields(row, self._binding)
                        # Host may be absent after a frontend-compatible PUT.
                        status, payload = self._witness._request(
                            "GET", "/api/v2/cmdb/secret/target/" + quote(self._binding.target_name, safe=""),
                            None, query="format=name%7Caddress",
                        )
                        target = _record(payload)
                        if (status != 200 or target is None
                                or target.get("name") != self._binding.target_name
                                or target.get("address") != self._binding.target_address):
                            raise ValueError
                        body = self._body(expected, fields, start, enabled)
                        self._dispatched = True  # No retry after any dispatch ambiguity.
                        accepted = self._put(owner, expected.secret_id, body)
                    finally:
                        _wipe_fields(row)
                        _wipe_fields(body)
                        for item in fields:
                            item.clear()
                        fields.clear()
                    after = self._inspect(owner)
                    verified = accepted and after.secret_id == expected.secret_id and after.folder_id == expected.folder_id
                    if enabled:
                        verified = verified and after.enabled and not after.uses_policy_default and after.frequency == "day" and after.interval == 1 and after.start_epoch == start
                    else:
                        # Disabled scheduler fields normalize; next-time can remain cached.
                        verified = verified and not after.enabled
                return PasswordChangeScheduleReadback(accepted, verified and owner.logout_verified,
                    after.enabled, owner.logout_verified)
            except Exception:
                raise PasswordChangeScheduleError(_UNAVAILABLE) from None

    def _identity(self, row: Mapping[str, Any], secret_id: int, folder_id: int) -> None:
        b = self._binding
        expected = {"id": secret_id, "folder": folder_id, "name": b.secret_name,
                    "template": _TEMPLATE, "target": b.target_name,
                    "inherit-permission": "enable", "ssh-service-status": "up",
                    "sftp-service-status": "up", "recording": "enable"}
        if any(row.get(key) != value for key, value in expected.items()):
            raise ValueError

    @staticmethod
    def _retained_fields(row: Mapping[str, Any], b: PasswordChangeScheduleBinding) -> list[dict[str, Any]]:
        fields = row.get("field")
        if not isinstance(fields, list) or len(fields) not in {2, 3} or not all(isinstance(item, dict) for item in fields):
            raise ValueError
        named = {item.get("name"): item for item in fields}
        if (len(named) != len(fields) or set(named) not in ({"Username", "Password"}, {"Host", "Username", "Password"})
                or named["Username"].get("value") != b.account_name
                or not isinstance(named["Password"].get("value"), str) or not named["Password"]["value"]
                or ("Host" in named and named["Host"].get("value") != b.target_address)):
            raise ValueError
        return [{key: item[key] for key in ("id", "name", "value", "keyinfo") if key in item}
                for item in fields if item["name"] != "Host"]

    def _body(self, state: PasswordChangeScheduleState, fields: list[dict[str, Any]], start: int, enabled: bool) -> dict[str, object]:
        b = self._binding
        return {"id": state.secret_id, "name": b.secret_name, "folder": state.folder_id,
                "template": _TEMPLATE, "target": b.target_name, "field": fields,
                "password-changer": "enable" if enabled else "disable",
                "pwd-chg-use-policy-default": "disable", "pwd-chg-sch-frequency": "day",
                "pwd-chg-sch-interval": 1, "pwd-chg-sch-month-type": "specific",
                "pwd-chg-sch-month-day": "1", "pwd-chg-sch-week-day": "",
                "pwd-chg-sch-start-date": datetime.fromtimestamp(start, _ZONE).strftime("%Y-%m-%d %H:%M:%S")}

    def _read(self, owner: OwnerSessionMetadataTransport, secret_id: int, *, protected: bool = False) -> dict[str, Any]:
        content = bytearray()
        try:
            if owner._client is None:
                raise ValueError
            with owner._client.stream("GET", f"{COLLECTION_PATH}/{secret_id}", headers={"Accept": "application/json"}) as response:
                if response.status_code != 200:
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    content.extend(chunk)
            if not protected:
                _redact_json_field_values(content)
            row = _record(json.loads(content))
            if row is None:
                raise ValueError
            return dict(row)
        finally:
            _zeroize_mutable(content)

    def _put(self, owner: OwnerSessionMetadataTransport, secret_id: int, body: Mapping[str, object]) -> bool:
        encoded = bytearray(json.dumps(body, separators=(",", ":")).encode("utf-8"))
        received = bytearray()
        connection = None
        try:
            if owner._client is None or len(encoded) > MAX_RESPONSE_BYTES:
                raise ValueError
            parsed = urlsplit(self._config.base_url)
            if parsed.hostname is None:
                raise ValueError
            cookie = owner._client.build_request("GET", self._config.base_url + COLLECTION_PATH).headers.get("cookie")
            if not cookie:
                raise ValueError
            jar = SimpleCookie()
            jar.load(cookie)
            csrf = jar.get("ccsrftoken")
            if csrf is None or not csrf.value:
                raise ValueError
            connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                timeout=self._config.timeout_seconds, context=_ssl_context(self._config))
            connection.request("PUT", f"{COLLECTION_PATH}/{secret_id}", body=memoryview(encoded),
                headers={"Accept": "application/json", "Content-Type": "application/json",
                         "Cookie": cookie, "X-CSRFTOKEN": csrf.value, "Connection": "close",
                         "User-Agent": owner._client.headers["User-Agent"]})
            response = connection.getresponse()
            try:
                received.extend(response.read(MAX_RESPONSE_BYTES + 1))
                if len(received) > MAX_RESPONSE_BYTES:
                    raise ValueError
                _redact_json_field_values(received)
                return response.status == 200 and _successful_response(json.loads(received))
            finally:
                response.close()
        finally:
            _zeroize_mutable(encoded)
            _zeroize_mutable(received)
            if connection is not None:
                connection.close()


def _wipe_fields(row: dict[str, Any]) -> None:
    fields = row.get("field")
    if isinstance(fields, list):
        for item in fields:
            if isinstance(item, dict):
                item.clear()
        fields.clear()
    row.clear()
