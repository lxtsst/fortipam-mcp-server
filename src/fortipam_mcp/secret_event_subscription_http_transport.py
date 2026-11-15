"""Private build-29 Web/cfg-chg subscription cycle; no generic relay.

The enable and restore directions have separate, durable one-dispatch claims.
Restoration is bound to the enable claim and its original metadata baseline.
Secret field/history bytes are never decoded or persisted. Their equality is
witnessed only with a per-dispatch key that is destroyed after readback.
"""

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Any

import httpx

from .secret_event_subscription_contract import (
    Operation, SUBSCRIPTION_PATH, SecretEventSubscriptionBinding, _current,
    compile_fixed_subscription, project_subscription_detail,
    project_subscription_portal, subscription_readback_matches,
)
from .secret_metadata_http_transport import (
    COLLECTION_PATH, MAX_RESPONSE_BYTES, SecretMetadataHttpTransportConfig,
    _json_string_end, _json_value_end, _skip_json_space, _ssl_context,
    _zeroize_mutable,
)
from .secret_request_http_transport import _object_members

_UNAVAILABLE = "The fixed Secret event subscription transport is unavailable."
_CLAIM_CONTRACT = "secret-event-subscription-700-claim-v1"
_MATERIAL = frozenset({"field", "credentials-history", "totp-setting"})
_KEY = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
# Qualified current build-29 schema/record names, never values. A new field
# cannot silently enter the persistent nonmaterial-state witness.
_RECORD_KEYS = frozenset({
    'address-blacklist', 'address-whitelist', 'allow-viewer-launch-web', 'approval-profile',
    'associated-secret', 'auto-association', 'av-profile', 'av-scan', 'block-clipboard',
    'bypass-approval', 'bypass-ssh-filter-for-owner', 'checkin-pwd-change', 'checkin-script',
    'checkout', 'checkout-admin', 'checkout-duration', 'checkout-duration-renew',
    'checkout-renew-times', 'checkout-script', 'checkout-time', 'checkout-user',
    'creation-time', 'credential-expire-notification', 'credential-expiry-after',
    'credentials-history', 'dependency', 'description', 'display-num', 'dlp-sensor',
    'dlp-status', 'field', 'folder', 'folder-name', 'force-checkout-idle-time',
    'group-permission', 'heartbeat-interval', 'heartbeat-start-time',
    'heartbeat-use-policy-default', 'http-service-status', 'id', 'inherit-folder-ztna',
    'inherit-permission', 'instruction-profile', 'invitation', 'keyboard-layout',
    'last-approval-script-result', 'last-approval-script-time', 'last-approval-script-type',
    'last-credential-change-date', 'last-launch-time', 'last-password-change-status',
    'last-password-change-time', 'last-password-verification-status',
    'last-password-verification-time', 'last-success-password-change-time',
    'last-success-password-verification-time', 'launcher', 'ldaps-service-status', 'name',
    'need-approval', 'need-approval-job', 'next-credential-change-date',
    'next-password-change-time', 'next-password-verification-time', 'password-changer',
    'password-heartbeat', 'permissions', 'policy', 'proxy', 'pwd-chg-sch-frequency',
    'pwd-chg-sch-interval', 'pwd-chg-sch-month-day', 'pwd-chg-sch-month-type',
    'pwd-chg-sch-next-time', 'pwd-chg-sch-start-date', 'pwd-chg-sch-week-day',
    'pwd-chg-use-policy-default', 'q_origin_key', 'rdp-auto-totp', 'rdp-event-filter',
    'rdp-event-filter-profile', 'rdp-nla-kerberos', 'rdp-remote-app',
    'rdp-remote-app-owner-exempt', 'rdp-remote-app-profile', 'rdp-restricted-admin-mode',
    'rdp-security-level', 'rdp-service-status', 'rdp-tcp-forward', 'recording',
    'rsa-sign-algo', 'samba-service-status', 'secret-auth', 'secret-auth-duration',
    'server-info', 'sftp-service-status', 'ssh-algorithm', 'ssh-filter',
    'ssh-filter-profile', 'ssh-service-status', 'ssh-switch-account', 'subscriber', 'target',
    'target-info', 'target-privilege-account', 'telnet-service-status', 'template',
    'totp-setting', 'tunnel-encryption', 'user-permission', 'uuid', 'vnc-service-status',
    'web-proxy-port', 'web-proxy-server', 'winappfilter', 'winappfilter-profile',
    'ztna-ems-tag', 'ztna-tags-match-logic',
})


class SecretEventSubscriptionHttpTransportError(RuntimeError):
    """Keep all upstream values outside exception text."""

    def __init__(self, *, stage: str = "preflight") -> None:
        super().__init__(_UNAVAILABLE)
        self.stage = stage if stage in {
            "preflight", "gate", "current_read", "baseline_drift", "recovery_scope",
            "claim_reserve", "dispatch", "readback", "reconciliation",
        } else "preflight"


@dataclass(frozen=True, slots=True, repr=False)
class SecretEventSubscriptionInspection:
    current_digest: str
    metadata_digest: str
    other_subscribers_digest: str


@dataclass(frozen=True, slots=True)
class SecretEventSubscriptionReadback:
    dispatch_consumed: bool
    http_accepted: bool
    response_qualified: bool
    subscription_matches: bool
    other_metadata_preserved: bool
    returned_credential_bytes_preserved: bool
    current_identity_verified: bool
    email_guard_preserved: bool
    response_class: str

    @property
    def verified(self) -> bool:
        return all((self.dispatch_consumed, self.http_accepted, self.response_qualified,
                    self.subscription_matches, self.other_metadata_preserved,
                    self.returned_credential_bytes_preserved, self.current_identity_verified,
                    self.email_guard_preserved))


@dataclass(slots=True, repr=False)
class _Snapshot:
    inspection: SecretEventSubscriptionInspection
    payload: dict[str, object]
    portal: dict[str, object]
    credential_witness: bytes | None


class FortiPamSecretEventSubscriptionHttpTransport:
    """One privately bound direction, fixed GET/POST routes and closed Gate.

    The bound identity is reverified through its source-defined user portal.
    The restoration pair must share the protected key and exact binding.
    HTTP acceptance alone is not subscription or notification acceptance.
    """

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, binding: SecretEventSubscriptionBinding,
        *, operation: Operation, claim_path: Path, hmac_key_file: Path,
        subscribe_claim_path: Path | None = None,
        execution_enabled: Callable[[], bool] = lambda: False,
        expected_email: str = "",
        client_factory: Callable[..., Any] = httpx.Client,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if (type(config) is not SecretMetadataHttpTransportConfig
                or type(binding) is not SecretEventSubscriptionBinding
                or operation not in {"subscribe", "restore"} or not callable(execution_enabled)
                or (operation == "restore") != (subscribe_claim_path is not None)):
            raise SecretEventSubscriptionHttpTransportError()
        # Validate selectors using the fixed compiler, without any device access.
        synthetic = {"version": "v7.0.0", "build": 29, "http_status": 200,
            "http_method": "GET", "path": "secret", "name": "database", "status": "OK",
            "results": {"id": binding.secret_id, "folder": binding.folder_id,
                "name": binding.secret_name, "target": binding.target_name,
                "template": "Web Account", "subscriber": []}}
        try:
            compile_fixed_subscription(synthetic, {"name": binding.owner_name, "email": expected_email},
                                       binding, operation="subscribe", expected_email=expected_email)
            self._key = _private_key(Path(hmac_key_file))
            self._config, self._binding, self._operation = config, binding, operation
            self._expected_email = expected_email
            self._claim = Path(claim_path)
            self._subscribe_claim = Path(subscribe_claim_path) if subscribe_claim_path is not None else None
            self._check_parent(self._claim)
            if self._subscribe_claim is not None:
                self._check_parent(self._subscribe_claim)
                if self._claim == self._subscribe_claim:
                    raise ValueError
        except Exception:
            raise SecretEventSubscriptionHttpTransportError() from None
        self._gate, self._factory, self._sleep = execution_enabled, client_factory, sleep
        self._lock = threading.Lock()
        binding_scope: dict[str, object] = {
            "binding": asdict(binding), "api_origin": config.base_url.rstrip("/")}
        if expected_email:
            # Preserve the accepted unset-email MAC domain and old claims.
            # A recipient change invalidates the new profile's existing records.
            binding_scope["notification_recipient"] = expected_email
        self._binding_digest = self._mac("binding", binding_scope)

    def _mac(self, domain: str, value: object) -> str:
        return hmac.new(self._key, ("subscription-700:" + domain + ":").encode()
            + json.dumps(value, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()

    def _client(self) -> Any:
        return self._factory(base_url=self._config.base_url, verify=_ssl_context(self._config),
            timeout=self._config.timeout_seconds, follow_redirects=False, trust_env=False,
            headers={"Authorization": "Bearer " + self._config.bearer_token,
                     "Accept": "application/json", "Accept-Encoding": "identity",
                     "Cache-Control": "no-cache,no-store"})

    def inspect(self) -> SecretEventSubscriptionInspection:
        self._unconsumed()
        try:
            with self._client() as client:
                state = self._read(client)
                compile_fixed_subscription(state.payload, state.portal, self._binding,
                    operation=self._operation, expected_email=self._expected_email)
                self._recovery_scope(state)
                return state.inspection
        except Exception:
            raise SecretEventSubscriptionHttpTransportError(stage="current_read") from None

    def apply_and_readback(self, expected: SecretEventSubscriptionInspection) -> SecretEventSubscriptionReadback:
        with self._lock:
            self._unconsumed()
            if self._gate() is not True:
                raise SecretEventSubscriptionHttpTransportError(stage="gate")
            witness_key = bytearray(secrets.token_bytes(32))
            stage = "current_read"
            try:
                with self._client() as client:
                    before = self._read(client, witness_key)
                    stage = "baseline_drift"
                    if type(expected) is not SecretEventSubscriptionInspection or before.inspection != expected:
                        raise ValueError
                    body = compile_fixed_subscription(before.payload, before.portal, self._binding,
                        operation=self._operation, expected_email=self._expected_email)
                    stage = "recovery_scope"
                    self._recovery_scope(before)
                    stage = "gate"
                    if self._gate() is not True:
                        raise ValueError
                    stage = "claim_reserve"
                    self._reserve(before.inspection)
                    # All exceptions after this reservation are non-retry.
                    stage = "dispatch"
                    accepted = qualified = False
                    response_class = "unreadable"
                    try:
                        accepted, qualified, response_class = self._post(client, body)
                    except Exception:
                        pass
                    stage = "readback"
                    state_matches = metadata_matches = credential_matches = identity = email_guard = False
                    for delay in (0.0, 0.25, 1.0, 3.0):
                        if delay:
                            self._sleep(delay)
                        try:
                            after = self._read(client, witness_key)
                            state_matches = subscription_readback_matches(before.payload, after.payload,
                                self._binding, subscribed=self._operation == "subscribe")
                            metadata_matches = before.inspection.metadata_digest == after.inspection.metadata_digest
                            credential_matches = (before.credential_witness is not None
                                and after.credential_witness is not None
                                and hmac.compare_digest(before.credential_witness, after.credential_witness))
                            identity = True
                            email_guard = self._operation == "restore" or after.portal["email"] == self._expected_email
                        except Exception:
                            continue
                        if state_matches:
                            break
                    return SecretEventSubscriptionReadback(True, accepted, qualified, state_matches,
                        metadata_matches, credential_matches, identity, email_guard, response_class)
            except Exception:
                raise SecretEventSubscriptionHttpTransportError(stage=stage) from None
            finally:
                _zeroize_mutable(witness_key)

    def reconcile(self) -> dict[str, object]:
        """Fresh fixed read of a consumed claim; this never permits redispatch."""
        try:
            claim = self._read_claim(self._claim, self._operation)
            with self._client() as client:
                state = self._read(client)
            _, own = _current(state.payload, self._binding)
            return {"dispatch_remains_consumed": True,
                "subscription_matches": own == (["cfg-chg"] if self._operation == "subscribe" else []),
                "other_metadata_preserved": state.inspection.metadata_digest == claim["metadata_digest"],
                "other_subscribers_preserved": state.inspection.other_subscribers_digest == claim["other_subscribers_digest"],
                "current_identity_verified": True, "redispatch_permitted": False,
                "credential_values_returned": False, "stored_credential_preservation_proven": False}
        except Exception:
            raise SecretEventSubscriptionHttpTransportError(stage="reconciliation") from None

    def _read(self, client: Any, witness_key: bytearray | None = None) -> _Snapshot:
        raw = self._get(client, f"{COLLECTION_PATH}/{self._binding.secret_id}?with_meta=true&vdom=root")
        portal_raw = bytearray()
        try:
            payload = project_subscription_detail(raw)
            row, _ = _current(payload, self._binding)
            fields = _record_spans(raw)
            if (not set(fields) <= _RECORD_KEYS or not _MATERIAL <= set(fields)
                    or raw[fields["field"][0]] != 91
                    or any(raw[fields[k][0]] not in {91, 123} for k in _MATERIAL)):
                raise ValueError
            # Credential history and TOTP are source-defined structured
            # material, so only their ephemeral byte equality is witnessed.
            # Invitation/dependency content has no qualified private provider.
            for key in ("invitation", "dependency"):
                if key in fields:
                    a, b = fields[key]
                    if raw[a] != 91 or _skip_json_space(raw, a + 1) != b - 1:
                        raise ValueError
            # last-approval-script-result is a schema option, not script output.
            metadata = _span_mac(raw, fields, self._key, excluded=_MATERIAL | {"subscriber"}, domain=b"metadata")
            credential = (_span_mac(raw, fields, witness_key, excluded=set(fields) - _MATERIAL,
                                   domain=b"returned-credential-bytes").encode()
                          if witness_key is not None else None)
            subscribers = row["subscriber"]
            assert isinstance(subscribers, list)
            others = self._mac("other-subscribers", {r["name"]: r["event"] for r in subscribers
                                                     if r["name"] != self._binding.owner_name})
            portal_raw = self._get(client, "/api/v2/internal/user-portal")
            portal = project_subscription_portal(portal_raw)
            if (portal["name"] != self._binding.owner_name or type(portal["email"]) is not str
                    or len(portal["email"]) > 255):
                raise ValueError
            current = self._mac("current", {"payload": payload, "portal": portal,
                "metadata": metadata, "transport_binding": self._binding_digest})
            return _Snapshot(SecretEventSubscriptionInspection(current, metadata, others), payload, portal, credential)
        finally:
            _zeroize_mutable(raw)
            _zeroize_mutable(portal_raw)

    @staticmethod
    def _get(client: Any, path: str) -> bytearray:
        raw = bytearray()
        try:
            with client.stream("GET", path) as response:
                if response.status_code != 200 or "json" not in response.headers.get("content-type", "").lower():
                    raise ValueError
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
            return raw
        except Exception:
            _zeroize_mutable(raw)
            raise

    def _post(self, client: Any, body: Mapping[str, object]) -> tuple[bool, bool, str]:
        raw = bytearray()
        status: int | None = None
        content_type_json = False
        body_complete = False
        try:
            with client.stream("POST", SUBSCRIPTION_PATH, json=body) as response:
                status = response.status_code
                content_type_json = "json" in response.headers.get("content-type", "").lower()
                accepted = response.status_code == 200
                for chunk in response.iter_bytes():
                    if len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                        raise ValueError
                    raw.extend(chunk)
                body_complete = True
                if not accepted:
                    return False, False, "http_rejected"
                if not raw:
                    return True, False, "empty"
                if not content_type_json:
                    return True, False, "non_json"
                # Candidate grammar awaits native qualification and requires
                # independent state/identity/material-byte readback.
                start = _skip_json_space(raw, 0)
                end = _json_value_end(raw, start)
                if _skip_json_space(raw, end) != len(raw):
                    return True, False, "unqualified_json"
                fields = _bounded_response_members(raw, start, end)
                if set(fields) == {"http_method", "http_status", "status", "msg"}:
                    # Native build-29 subscription replies carry opaque text,
                    # not the CMDB version/path/results envelope. Never decode
                    # that text or use it as instructions or success evidence.
                    literals = {"http_method": (b'"POST"',), "http_status": (b"200",),
                                "status": (b'"success"', b'"OK"')}
                    a, b = fields["msg"]
                    qualified = (raw[a] == 34 and 2 < b - a <= 16_384
                        and all(any(raw[left:right] == bytearray(value) for value in literals[key])
                                for key, (left, right) in fields.items() if key != "msg"))
                    return True, qualified, "qualified_native_message_envelope" if qualified else "unqualified_json"
                wanted = {"version", "build", "http_status", "http_method", "status", "path", "name", "results"}
                if set(fields) != wanted:
                    return True, False, "unqualified_json"
                if any(b - a > 80 or raw[a] in {91, 123}
                       for k, (a, b) in fields.items() if k != "results"):
                    return True, False, "unqualified_json"
                values = {k: json.loads(raw[a:b]) for k, (a, b) in fields.items() if k != "results"}
                expected = {"version": "v7.0.0", "build": 29, "http_status": 200,
                            "http_method": "POST", "path": "internal", "name": "subscribe"}
                qualified = (set(fields) == wanted and all(type(values.get(k)) is type(v)
                             and values[k] == v for k, v in expected.items())
                             and values.get("status") in {"success", "OK"})
                if qualified:
                    a, b = fields["results"]
                    qualified = raw[a:b] == b"{}" or raw[a:b] == b"[]"
                return True, qualified, "qualified_envelope" if qualified else "unqualified_json"
        finally:
            try:
                self._record_response_shape(raw, status, content_type_json, body_complete)
            finally:
                _zeroize_mutable(raw)

    def _record_response_shape(
        self, raw: bytearray, status: int | None, json_content: bool, body_complete: bool,
    ) -> None:
        """Keep one minimized observation for reconciliation, never raw values.

        Known public member names and exact fixed-constant comparisons may be
        retained. Unknown names, messages, result values and identifiers cannot
        enter this owner-only record. Shape evidence does not qualify success.
        """
        known = {"http_method", "http_status", "status", "results", "error", "path", "name",
                 "version", "build", "vdom", "mkey", "revision", "message", "serial", "cli_error",
                 "msg"}
        record: dict[str, object] = {"contract": "subscription-700-response-shape-v1",
            "operation": self._operation, "binding_digest": self._binding_digest,
            "http_status": status if status in {200, 400, 401, 403, 404, 409, 500} else None,
            "json_content_type": json_content, "response_body_complete": body_complete,
            "body_class": "unclassified" if raw or not body_complete else "empty",
            "raw_values_retained": False, "response_success_proven": False}
        try:
            if raw and json_content and body_complete:
                start = _skip_json_space(raw, 0)
                end = _json_value_end(raw, start)
                if _skip_json_space(raw, end) != len(raw):
                    raise ValueError
                fields = _bounded_response_members(raw, start, end)
                record["body_class"] = "object"
                record["known_root_members"] = sorted(set(fields) & known)
                record["unknown_root_member_count"] = len(set(fields) - known)
                record["diagnostic_field_shapes"] = {
                    key: {"kind": _response_kind(raw, a, b),
                          "empty_or_zero": b - a <= 5 and any(raw[a:b] == bytearray(literal) for literal in
                                               (b'""', b"{}", b"[]", b"null", b"0", b"false"))}
                    for key, (a, b) in fields.items() if key == "msg"}
                # Aggregate unknown value types only; retain neither their
                # names nor values. These hints cannot qualify a response.
                kinds: dict[str, int] = {}
                for key, (a, b) in fields.items():
                    if key not in known:
                        kind = _response_kind(raw, a, b)
                        kinds[kind] = kinds.get(kind, 0) + 1
                record["unknown_member_kinds"] = kinds
                constants = {"http_method": (b'"POST"',), "http_status": (b"200",),
                    "status": (b'"OK"', b'"success"'), "path": (b'"internal"',),
                    "name": (b'"subscribe"',), "version": (b'"v7.0.0"',),
                    "build": (b"29",), "vdom": (b'"root"',), "error": (b"0",),
                    "cli_error": (b'""',)}
                record["fixed_constant_matches"] = {
                    key: any(raw[a:b] == value for value in values)
                    for key, values in constants.items() if key in fields
                    for a, b in [fields[key]]}
                if "results" in fields:
                    a, b = fields["results"]
                    record["results_kind"] = _response_kind(raw, a, b)
                    record["result_integer_matches_bound_secret"] = raw[a:b] == str(self._binding.secret_id).encode()
                    if raw[a] == 123:
                        results = _bounded_response_members(raw, a, b)
                        permitted = {"id", "secret-id", "name", "event", "subscriber", "status"}
                        record["known_result_members"] = sorted(set(results) & permitted)
                        record["unknown_result_member_count"] = len(set(results) - permitted)
                        record["result_id_matches_bound_secret"] = any(
                            raw[left:right] == str(self._binding.secret_id).encode()
                            for key, (left, right) in results.items() if key in {"id", "secret-id"})
        except Exception:
            record["body_class"] = "unclassified"
        record["record_mac"] = self._mac("response-shape", record)
        self._write_record(self._claim.with_name(self._claim.stem + ".response.json"), record)

    @staticmethod
    def _check_parent(path: Path) -> None:
        info = path.parent.lstat()
        if (not path.is_absolute() or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError

    def _unconsumed(self) -> None:
        try:
            self._check_parent(self._claim)
            if os.path.lexists(self._claim):
                raise ValueError
        except Exception:
            raise SecretEventSubscriptionHttpTransportError() from None

    def _recovery_scope(self, state: _Snapshot) -> None:
        if self._subscribe_claim is None:
            return
        claim = self._read_claim(self._subscribe_claim, "subscribe")
        if (claim["metadata_digest"] != state.inspection.metadata_digest
                or claim["other_subscribers_digest"] != state.inspection.other_subscribers_digest):
            raise ValueError

    def _reserve(self, state: SecretEventSubscriptionInspection) -> None:
        self._unconsumed()
        record: dict[str, object] = {"contract": _CLAIM_CONTRACT, "state": "reserved",
            "operation": self._operation, "replay_permitted": False,
            "binding_digest": self._binding_digest, **asdict(state)}
        record["record_mac"] = self._mac("claim", record)
        self._write_record(self._claim, record)

    def _write_record(self, path: Path, record: Mapping[str, object]) -> None:
        self._check_parent(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, "w") as file:
                json.dump(record, file, sort_keys=True)
                file.flush()
                os.fsync(file.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _read_claim(self, path: Path, operation: Operation) -> dict[str, object]:
        self._check_parent(path)
        record = json.loads(_private_bytes(path, limit=4096))
        keys = {"contract", "state", "operation", "replay_permitted", "binding_digest",
                "current_digest", "metadata_digest", "other_subscribers_digest", "record_mac"}
        if not isinstance(record, dict) or set(record) != keys:
            raise ValueError
        mac = record.pop("record_mac")
        if (record["contract"] != _CLAIM_CONTRACT or record["state"] != "reserved"
                or record["operation"] != operation or record["replay_permitted"] is not False
                or record["binding_digest"] != self._binding_digest
                or type(mac) is not str or not hmac.compare_digest(mac, self._mac("claim", record))):
            raise ValueError
        return record


def _record_spans(raw: bytearray) -> dict[str, tuple[int, int]]:
    start = _skip_json_space(raw, 0)
    root = _object_members(raw, start, _json_value_end(raw, start), {"results"})
    a, b = root["results"]
    if raw[a] == 91:
        a = _skip_json_space(raw, a + 1)
        b = _json_value_end(raw, a)
    if raw[a] != 123 or raw[b - 1] != 125:
        raise ValueError
    fields: dict[str, tuple[int, int]] = {}
    cursor = _skip_json_space(raw, a + 1)
    while cursor < b - 1:
        key_end = _json_string_end(raw, cursor)
        if key_end - cursor > 66:
            raise ValueError
        key = json.loads(raw[cursor:key_end + 1])
        if type(key) is not str or _KEY.fullmatch(key) is None or len(fields) >= 128:
            raise ValueError
        separator = _skip_json_space(raw, key_end + 1)
        if raw[separator] != 58:
            raise ValueError
        left = _skip_json_space(raw, separator + 1)
        right = _json_value_end(raw, left)
        if right >= b:
            raise ValueError
        if key in fields:
            # Current build 29 repeats one non-selected field identically.
            # Selected projection members still reject every duplicate.
            old_a, old_b = fields[key]
            with memoryview(raw)[old_a:old_b] as old, memoryview(raw)[left:right] as new:
                if not hmac.compare_digest(old, new):
                    raise ValueError
        fields[key] = left, right
        cursor = _skip_json_space(raw, right)
        if cursor == b - 1:
            break
        if raw[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(raw, cursor + 1)
        if cursor >= b - 1:
            raise ValueError
    return fields


def _bounded_response_members(raw: bytearray, start: int, end: int) -> dict[str, tuple[int, int]]:
    """Bound member names and reject duplicates without decoding any values."""
    if raw[start] != 123 or raw[end - 1] != 125:
        raise ValueError
    fields: dict[str, tuple[int, int]] = {}
    cursor = _skip_json_space(raw, start + 1)
    while cursor < end - 1:
        key_end = _json_string_end(raw, cursor)
        if key_end - cursor > 66:
            raise ValueError
        key = json.loads(raw[cursor:key_end + 1])
        if type(key) is not str or _KEY.fullmatch(key) is None or key in fields or len(fields) >= 32:
            raise ValueError
        separator = _skip_json_space(raw, key_end + 1)
        if raw[separator] != 58:
            raise ValueError
        a = _skip_json_space(raw, separator + 1)
        b = _json_value_end(raw, a)
        if b >= end:
            raise ValueError
        fields[key] = a, b
        cursor = _skip_json_space(raw, b)
        if cursor == end - 1:
            break
        if raw[cursor] != 44:
            raise ValueError
        cursor = _skip_json_space(raw, cursor + 1)
        if cursor >= end - 1:
            raise ValueError
    return fields


def _response_kind(raw: bytearray, start: int, end: int) -> str:
    first = raw[start]
    if first in {123, 91}:
        kind = "object" if first == 123 else "array"
        return "empty_" + kind if _skip_json_space(raw, start + 1) == end - 1 else kind
    if first == 34:
        return "string"
    if raw[start:end] == b"true" or raw[start:end] == b"false":
        return "boolean"
    if raw[start:end] == b"null":
        return "null"
    return "integer" if re.fullmatch(rb"-?(?:0|[1-9][0-9]*)", raw[start:end]) else "unclassified"


def _span_mac(raw: bytearray, fields: dict[str, tuple[int, int]], key: bytes | bytearray,
              *, excluded: set[str] | frozenset[str], domain: bytes) -> str:
    digest = hmac.new(key, b"subscription-700:" + domain + b":" , hashlib.sha256)
    for name in sorted(set(fields) - excluded):
        a, b = fields[name]
        digest.update(name.encode() + b"\0" + str(b - a).encode() + b"\0")
        with memoryview(raw)[a:b] as value:
            digest.update(value)
    return digest.hexdigest()


def _private_bytes(path: Path, *, limit: int) -> bytes:
    if not path.is_absolute():
        raise ValueError
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= limit):
            raise ValueError
        value = os.read(fd, limit + 1)
        if len(value) > limit:
            raise ValueError
        return value
    finally:
        os.close(fd)


def _private_key(path: Path) -> bytes:
    value = _private_bytes(path, limit=4096)
    if len(value) < 32:
        raise ValueError
    return value
