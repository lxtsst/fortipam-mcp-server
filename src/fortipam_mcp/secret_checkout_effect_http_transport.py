"""Unregistered build-29 same-owner Checkout effect qualification transport.

Response success requires the fixed build-29 five-member envelope and bound
Secret ID. Native message strings are validated bytewise and never decoded.
Even a matching state transition cannot constitute action acceptance here.
"""

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
import hashlib
import json
import os
import re
from pathlib import Path
import stat
import time
from typing import Any

from .secret_checkout_association_http_transport import (
    SecretCheckoutBinding, _CheckoutUnixFieldExchange,
)
from .secret_checkout_effect_contract import (
    Operation, SecretCheckoutEffectBinding, compile_fixed_checkout_effect,
    fixed_checkout_effect_state,
)
from .secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES, SecretMetadataHttpTransportConfig, _record,
    _json_string_end, _json_value_end, _skip_json_space, _zeroize_mutable,
)

_UNAVAILABLE = "The fixed Secret checkout effect transport is unavailable."


@dataclass(frozen=True, slots=True, repr=False)
class SecretCheckoutEffectInspection:
    binding: SecretCheckoutEffectBinding
    metadata_digest: str
    preserved_metadata_digest: str
    execution_account_digest: str


@dataclass(frozen=True, slots=True)
class SecretCheckoutEffectReadback:
    dispatch_consumed: bool
    http_ok_observed: bool
    same_owner_state_matches: bool
    other_metadata_preserved: bool
    execution_account_preserved: bool
    owner_logout_verified: bool
    native_response_qualified: bool = False

    @property
    def verified(self) -> bool:
        return all(asdict(self).values())


class SecretCheckoutEffectHttpTransport:
    """One fixed request and categorical evidence, default closed and no replay."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, binding: SecretCheckoutBinding,
        credentials: Callable[[], tuple[str, str]], *, operation: Operation,
        claim_path: Path, execution_enabled: bool = False,
        owner_factory: Callable[[], Any] | None = None,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if (not isinstance(binding, SecretCheckoutBinding)
                or binding.template_name != "Unix Account (SSH Password)"
                or binding.checkout_script != "" or binding.checkin_script != ""
                or type(binding.execution_secret_name) is not str
                or re.fullmatch(r"mcp-v4-bp008-(?:denial|checkout)-[0-9]{8}-r[1-9][0-9]*",
                                binding.execution_secret_name) is None
                or binding.execution_secret_name == binding.secret_name
                or operation not in {"checkout", "checkin"}
                or type(execution_enabled) is not bool or not callable(wall_clock)
                or type(binding.force_checkout_idle_time) is not int
                or not 0 <= binding.force_checkout_idle_time <= 30):
            raise RuntimeError(_UNAVAILABLE)
        # This reader cannot retain/load account fields or perform description PUT.
        self._reader = _CheckoutUnixFieldExchange(
            config, binding, credentials, description="", claim_path=claim_path,
            owner_factory=owner_factory,
        )
        if not self._reader._fixture_binding_matches(binding):
            raise RuntimeError(_UNAVAILABLE)
        self._binding, self._operation = binding, operation
        self._claim, self._enabled = claim_path, execution_enabled
        self._wall_clock = wall_clock

    def _companion(self, owner: Any, folder_id: int) -> tuple[int, str]:
        b = self._binding
        secret_id = owner._lookup_id("secret", b.folder_path + "/" + b.execution_secret_name)
        if type(secret_id) is not int or not 0 < secret_id <= 2_147_483_647:
            raise ValueError
        code, envelope, _ = self._reader._exchange(owner, "GET", secret_id)
        row = _record(envelope)
        if (code != 200 or not self._reader._qualified(envelope, "GET")
                or not isinstance(row, Mapping)
                or any(type(row.get(k)) is not type(v) or row.get(k) != v for k, v in {
                    "id": secret_id, "folder": folder_id, "name": b.execution_secret_name,
                    "template": b.template_name, "target": b.target_name,
                    "ssh-service-status": "up", "associated-secret": 0,
                    "target-privilege-account": "disable", "checkout": "disable",
                    "checkout-script": "", "checkin-script": "",
                }.items())):
            raise ValueError
        target, permissions = row.get("target-info"), row.get("permissions")
        if (not isinstance(target, Mapping) or type(target.get("priv_acct")) is not int
                or target["priv_acct"] != 0 or not isinstance(permissions, Mapping)
                or permissions.get("checkout_status") != "none"
                or permissions.get("passwd_change") != "allowed"):
            raise ValueError
        return secret_id, _digest({k: v for k, v in row.items() if k != "field"})

    def _current(self, owner: Any, *, operation: Operation) -> tuple[SecretCheckoutEffectInspection, Mapping[str, object]]:
        metadata, envelope, _ = self._reader._read(owner)
        row = _record(envelope)
        if (not isinstance(row, Mapping) or type(row.get("force-checkout-idle-time")) is not int
                or row["force-checkout-idle-time"] != self._binding.force_checkout_idle_time):
            raise ValueError
        companion_id, companion_digest = self._companion(owner, metadata.folder_id)
        binding = SecretCheckoutEffectBinding(metadata.secret_id, metadata.folder_id,
            self._binding.secret_name, self._binding.target_name, companion_id, self._binding.owner_name)
        compile_fixed_checkout_effect(envelope, binding, operation=operation)
        return SecretCheckoutEffectInspection(binding,
            _digest({k: v for k, v in row.items() if k != "field"}),
            _preserved_digest(row), companion_digest), envelope

    def inspect(self) -> SecretCheckoutEffectInspection:
        self._reader._unconsumed()
        try:
            owner = self._reader._owner()
            with owner.authenticated():
                current, _ = self._current(owner, operation=self._operation)
            if not owner.logout_verified:
                raise ValueError
            return current
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def execute_and_readback(self, expected: SecretCheckoutEffectInspection) -> SecretCheckoutEffectReadback:
        # Closed and consumed requests refuse before constructing/logging in Owner.
        if not self._enabled:
            raise RuntimeError(_UNAVAILABLE)
        with self._reader._lock:
            self._reader._unconsumed()
            consumed = False
            stage = "baseline_read"
            try:
                owner = self._reader._owner()
                with owner.authenticated():
                    current, envelope = self._current(owner, operation=self._operation)
                    if not isinstance(expected, SecretCheckoutEffectInspection) or current != expected:
                        raise ValueError
                    path, body = compile_fixed_checkout_effect(envelope, current.binding,
                                                              operation=self._operation)
                    token = owner._client.cookies.get("ccsrftoken")
                    if (not isinstance(token, str) or not token.strip('"')
                            or any(ord(c) < 33 or ord(c) > 126 for c in token.strip('"'))):
                        raise ValueError
                    # A second complete read binds dispatch to the inspected current state.
                    fresh, _ = self._current(owner, operation=self._operation)
                    if fresh != current:
                        raise ValueError
                    stage = "claim"
                    self._write(self._claim.name, {"state": "reserved",
                        "binding_digest": _digest(asdict(current.binding)),
                        "metadata_digest": current.metadata_digest,
                        "preserved_metadata_digest": current.preserved_metadata_digest,
                        "execution_account_digest": current.execution_account_digest})
                    consumed = True
                    stage = "post"
                    dispatch_started = int(self._wall_clock())
                    with owner._client.stream("POST", path, json=body,
                        headers={"Accept": "application/json", "X-CSRFTOKEN": token.strip('"')}) as response:
                        http_ok = type(response.status_code) is int and response.status_code == 200
                        diagnostics = _read_native_response_diagnostics(response, expected_secret_id=current.binding.secret_id)
                        self._write(self._claim.name + ".http.json", {
                            "http_ok_observed": http_ok, **diagnostics})
                    stage = "readback"
                    reverse: Operation = "checkin" if self._operation == "checkout" else "checkout"
                    after, after_envelope = self._current(owner, operation=reverse)
                    state_matches = fixed_checkout_effect_state(after_envelope, current.binding,
                                                                checked_out=self._operation == "checkout")
                    if self._operation == "checkout":
                        row = _record(after_envelope)
                        timestamp = row.get("checkout-time") if isinstance(row, Mapping) else None
                        state_matches = (state_matches and type(timestamp) is int
                            and dispatch_started - 2 <= timestamp <= int(self._wall_clock()) + 2)
                    preserved = after.preserved_metadata_digest == current.preserved_metadata_digest
                    companion = (after.binding == current.binding
                                 and after.execution_account_digest == current.execution_account_digest)
                result = SecretCheckoutEffectReadback(True, http_ok, state_matches, preserved,
                                                     companion, owner.logout_verified,
                                                     diagnostics.get("native_response_qualified") is True)
                self._write(self._claim.name + ".readback.json", asdict(result))
                return result
            except Exception:
                if consumed:
                    try:
                        self._write(self._claim.name + ".failure.json", {"failure_stage": stage})
                    except Exception:
                        pass
                raise RuntimeError(_UNAVAILABLE) from None

    def _write(self, name: str, evidence: Mapping[str, object]) -> None:
        if name not in {self._claim.name, self._claim.name + ".http.json",
                        self._claim.name + ".readback.json", self._claim.name + ".failure.json"}:
            raise ValueError
        self._reader._check_parent()
        directory = os.open(self._claim.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, "w") as file:
                json.dump({"contract": "secret-checkout-effect-qualification-v3",
                           "operation": self._operation, "replay_permitted": False, **evidence}, file)
                file.flush()
                os.fsync(file.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _preserved_digest(row: Mapping[str, Any]) -> str:
    # These three fields are separately qualified by the fixed lease contract.
    result = {k: v for k, v in row.items() if k not in {
        "field", "checkout-user", "checkout-admin", "checkout-time"}}
    permissions = row.get("permissions")
    if not isinstance(permissions, Mapping):
        raise ValueError
    result["permissions"] = {k: v for k, v in permissions.items()
                             if k not in {"checkout_status", "passwd_change"}}
    return _digest(result)


def _read_native_response_diagnostics(
    response: Any, *, expected_secret_id: int | None = None,
) -> dict[str, object]:
    """Decode no native message, field, selector or arbitrary result value."""
    raw = bytearray()
    try:
        if "json" not in response.headers.get("content-type", "").lower():
            raise ValueError
        for chunk in response.iter_bytes():
            if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                raise ValueError
            raw.extend(chunk)
        diagnostics = _project_native_response_diagnostics(raw)
        if expected_secret_id is not None:
            diagnostics["native_response_qualified"] = _qualify_fixed_native_response(raw, expected_secret_id)
        return diagnostics
    finally:
        _zeroize_mutable(raw)


def _project_native_response_diagnostics(raw: bytearray) -> dict[str, object]:
    """Record recognized scalar categories; skip every other value bytewise.

    This parser is a qualification observer, not native success authority.
    Unrecognized members, enum values and shapes cannot become acceptance.
    """
    expected = {"version": "v7.0.0", "build": 29, "http_status": 200,
                "http_method": "POST", "status": "OK", "script_status": "failed", "error": 0}
    result: dict[str, object] = {"root_object_scanned": True, "unrecognized_member_count": 0}
    unknown = 0
    cursor = _skip_json_space(raw, 0)
    if cursor >= len(raw) or raw[cursor] != 123:
        raise ValueError
    cursor = _skip_json_space(raw, cursor + 1)
    seen: set[str] = set()
    if cursor < len(raw) and raw[cursor] == 125:
        cursor += 1
    else:
        while True:
            key_end = _json_string_end(raw, cursor) + 1
            if key_end - cursor > 256:
                raise ValueError
            key = json.loads(raw[cursor:key_end])
            if key in seen:
                raise ValueError
            seen.add(key)
            cursor = _skip_json_space(raw, key_end)
            if cursor >= len(raw) or raw[cursor] != 58:
                raise ValueError
            cursor = _skip_json_space(raw, cursor + 1)
            end = _json_value_end(raw, cursor)
            if key in expected:
                value = expected[key]
                # Compare only fixed canonical bytes; decode no arbitrary value.
                encoded = json.dumps(value, separators=(",", ":")).encode()
                result[key + "_present"] = True
                result[key + "_expected_category"] = raw[cursor:end] == encoded
                if key in {"status", "script_status"}:
                    categories = ("OK", "success", "error") if key == "status" else ("failed", "success", "succeeded")
                    result[key + "_category"] = next((category for category in categories
                        if raw[cursor:end] == json.dumps(category).encode()), "unrecognized")
            elif key == "msg":
                result["msg_present"] = True
                result["msg_valid_string_shape"] = _valid_private_json_string(raw, cursor, end)
            elif key == "secret-id":
                result["secret_id_present"] = True
                result["secret_id_number_shape"] = raw[cursor] in b'-0123456789'
            elif key in {"path", "name"}:
                # Finite public route literals only; an unknown value stays private.
                route_categories = ("secret-checkout", "secret-checkin", "secret", "internal", "checkout", "checkin", "")
                result[key + "_present"] = True
                result[key + "_category"] = next((category for category in route_categories
                    if raw[cursor:end] == json.dumps(category).encode()), "unrecognized")
            elif key == "results":
                result["results_present"] = True
                result["results_shape_category"] = ("object" if raw[cursor] == 123 else
                    "array" if raw[cursor] == 91 else "null" if raw[cursor:end] == b"null" else "unrecognized")
            else:
                unknown += 1
            cursor = _skip_json_space(raw, end)
            if cursor >= len(raw):
                raise ValueError
            if raw[cursor] == 125:
                cursor += 1
                break
            if raw[cursor] != 44:
                raise ValueError
            cursor = _skip_json_space(raw, cursor + 1)
    if _skip_json_space(raw, cursor) != len(raw):
        raise ValueError
    result["unrecognized_member_count"] = unknown
    return result


def _qualify_fixed_native_response(raw: bytearray, secret_id: int) -> bool:
    """Accept only the observed five-member envelope; return no native value."""
    try:
        if type(secret_id) is not int or not 0 < secret_id <= 2_147_483_647:
            return False
        expected = {"http_method": b'"POST"', "http_status": b'200',
                    "status": b'"OK"', "secret-id": str(secret_id).encode("ascii")}
        cursor = _skip_json_space(raw, 0)
        if cursor >= len(raw) or raw[cursor] != 123:
            return False
        cursor = _skip_json_space(raw, cursor + 1)
        seen: set[str] = set()
        while cursor < len(raw) and raw[cursor] != 125:
            end = _json_string_end(raw, cursor) + 1
            if end - cursor > 256:
                return False
            key = json.loads(raw[cursor:end])
            if key in seen or key not in {*expected, "msg"}:
                return False
            seen.add(key)
            cursor = _skip_json_space(raw, end)
            if cursor >= len(raw) or raw[cursor] != 58:
                return False
            cursor = _skip_json_space(raw, cursor + 1)
            end = _json_value_end(raw, cursor)
            if key == "msg":
                if not _valid_private_json_string(raw, cursor, end):
                    return False
            elif raw[cursor:end] != expected[key]:
                return False
            cursor = _skip_json_space(raw, end)
            if cursor >= len(raw):
                return False
            if raw[cursor] == 125:
                break
            if raw[cursor] != 44:
                return False
            cursor = _skip_json_space(raw, cursor + 1)
            if cursor >= len(raw) or raw[cursor] == 125:
                return False
        return (seen == {*expected, "msg"} and cursor < len(raw) and raw[cursor] == 125
                and _skip_json_space(raw, cursor + 1) == len(raw))
    except Exception:
        return False


def _valid_private_json_string(raw: bytearray, start: int, end: int) -> bool:
    """Validate JSON escapes and UTF-8 without creating a message string."""
    if end - start > 4096 or end - start < 2 or raw[start] != 34 or raw[end - 1] != 34:
        return False
    cursor = start + 1
    while cursor < end - 1:
        value = raw[cursor]
        if value < 32 or value == 34:
            return False
        if value == 92:
            cursor += 1
            if cursor >= end - 1:
                return False
            if raw[cursor] in b'"\\/bfnrt':
                cursor += 1
                continue
            if raw[cursor] != 117 or cursor + 4 >= end - 1:
                return False
            digits = raw[cursor + 1:cursor + 5]
            if any(v not in b'0123456789abcdefABCDEF' for v in digits):
                return False
            code = int(digits, 16)
            cursor += 5
            if 0xD800 <= code <= 0xDBFF:
                if cursor + 6 > end - 1 or raw[cursor:cursor + 2] != b'\\u':
                    return False
                digits = raw[cursor + 2:cursor + 6]
                if (any(v not in b'0123456789abcdefABCDEF' for v in digits)
                        or not 0xDC00 <= int(digits, 16) <= 0xDFFF):
                    return False
                cursor += 6
            elif 0xDC00 <= code <= 0xDFFF:
                return False
        elif value < 128:
            cursor += 1
        else:
            width = 2 if 0xC2 <= value <= 0xDF else 3 if 0xE0 <= value <= 0xEF else 4 if 0xF0 <= value <= 0xF4 else 0
            if not width or cursor + width > end - 1:
                return False
            if any(not 0x80 <= raw[i] <= 0xBF for i in range(cursor + 1, cursor + width)):
                return False
            second = raw[cursor + 1]
            if ((value == 0xE0 and second < 0xA0) or (value == 0xED and second >= 0xA0)
                    or (value == 0xF0 and second < 0x90) or (value == 0xF4 and second >= 0x90)):
                return False
            cursor += width
    return cursor == end - 1
