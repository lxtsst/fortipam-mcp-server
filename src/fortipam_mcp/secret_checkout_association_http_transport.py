"""Fixed private Owner-session checkout association using retained Unix fields."""

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Any

from .job_definition_http_transport import FortiPamDisabledJobHttpTransport
from .secret_checkout_association_contract import (
    CONTROLS, compile_fixed_secret_checkout_body, project_secret_checkout_metadata,
)
from .secret_description_update_http_transport import (
    FortiPamSecretDescriptionUpdateHttpTransport, SecretDescriptionBinding,
    SecretDescriptionInspection,
    _metadata_digest,
)
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, UTILITY_ID_PATH, _path_for_url, _record,
)

_UNAVAILABLE = "The fixed Secret checkout association transport is unavailable."


@dataclass(frozen=True, slots=True, repr=False, kw_only=True)
class SecretCheckoutBinding(SecretDescriptionBinding):
    execution_secret_name: str
    checkout_script: str
    checkin_script: str
    baseline_controls: tuple[tuple[str, str | int], ...]
    force_checkout_idle_time: int


@dataclass(frozen=True, slots=True, repr=False)
class SecretCheckoutInspection:
    metadata: SecretDescriptionInspection
    body_digest: str
    unchanged_metadata_digest: str
    script_definition_digest: str
    execution_account_digest: str


@dataclass(frozen=True, slots=True)
class SecretCheckoutReadback:
    dispatch_consumed: bool
    http_accepted: bool
    controls_match: bool
    other_metadata_preserved: bool
    retained_field_values_match: bool
    owner_logout_verified: bool

    @property
    def verified(self) -> bool:
        return all(asdict(self).values())


class _CheckoutUnixFieldExchange(FortiPamSecretDescriptionUpdateHttpTransport):
    @staticmethod
    def _fixture_binding_matches(binding: SecretDescriptionBinding) -> bool:
        return (isinstance(binding, SecretCheckoutBinding)
                and re.fullmatch(r"mcp-v4-bp008-(?:denial|checkout)-[0-9]{8}-r[1-9][0-9]*", binding.secret_name) is not None)

    def update_and_readback(self, expected: SecretDescriptionInspection) -> Any:
        raise RuntimeError(_UNAVAILABLE)

    def _owner(self) -> Any:
        owner = super()._owner()
        if self._owner_factory is None:
            binding = self._binding
            if not isinstance(binding, SecretCheckoutBinding):
                raise ValueError
            # Add exactly the privately bound companion's read-only lookup.
            # The primary Secret remains the sole create/repair identity.
            owner._allowed_paths.add(UTILITY_ID_PATH + "/" + _path_for_url(
                binding.folder_path + "/" + binding.execution_secret_name))
        return owner


class SecretCheckoutAssociationHttpTransport:
    """Specialize the accepted private field-retention path, never its text action."""

    def __init__(
        self, config: SecretMetadataHttpTransportConfig, binding: SecretCheckoutBinding,
        credentials: Callable[[], tuple[str, str]], *, retained_account: Callable[[], str],
        claim_path: Path, restore: bool = False, owner_factory: Callable[[], Any] | None = None,
        script_reader: Callable[[], object] | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if (not isinstance(binding, SecretCheckoutBinding) or type(restore) is not bool
                or type(binding.execution_secret_name) is not str
                or re.fullmatch(r"mcp-v4-bp008-(?:denial|checkout)-[0-9]{8}-r[1-9][0-9]*",
                                binding.execution_secret_name) is None
                or binding.execution_secret_name == binding.secret_name
                or type(binding.force_checkout_idle_time) is not int or not 0 <= binding.force_checkout_idle_time <= 30
                or len(binding.baseline_controls) != len(CONTROLS)
                or set(dict(binding.baseline_controls)) != CONTROLS):
            raise RuntimeError(_UNAVAILABLE)
        self._checkout_binding = binding
        self._restore = restore
        self._operation = ("restore_checkout_baseline" if restore else
                           "configure_basic_checkout" if binding.checkout_script == binding.checkin_script == ""
                           else "associate_checkout_scripts")
        self._private = _CheckoutUnixFieldExchange(config, binding, credentials, description="", claim_path=claim_path,
            owner_factory=owner_factory, retained_account=retained_account, sleep=sleep)
        self._config, self._claim, self._sleep = config, claim_path, sleep
        self._script_reader = script_reader or self._read_scripts

    def _read_scripts(self) -> object:
        t = FortiPamDisabledJobHttpTransport(self._config, target_name="fixed-script-read",
                                           target_requester="fixed-script-read", expected_secret_id=1)
        code, result = t._request("POST", "/api/v2/cmdb/secret/script", {"json_filter": []},
                                  query="with_meta=true&vdom=root", override="GET")
        if code != 200:
            raise ValueError
        return result

    def _inspection(self, owner: Any) -> tuple[SecretCheckoutInspection, dict[str, object]]:
        metadata, envelope, _ = self._private._read(owner)
        projected = project_secret_checkout_metadata(envelope)
        row = projected["results"]
        if not isinstance(row, Mapping):
            raise ValueError
        identity = {key: row[key] for key in ("id", "name", "folder", "template")}
        b = self._checkout_binding
        execution = self._execution_account(owner)
        scripts = None if b.checkout_script == b.checkin_script == "" else self._script_reader()
        body = compile_fixed_secret_checkout_body(projected, scripts, identity=identity,
            checkout_script=b.checkout_script, checkin_script=b.checkin_script,
            baseline_controls=dict(b.baseline_controls), force_idle_time=b.force_checkout_idle_time,
            execution_secret_id=execution.secret_id,
            restore=self._restore)
        full = _record(envelope)
        if (not isinstance(full, Mapping)
                or not _checkout_permission_state_matches(full, "enable" if self._restore else "disable")):
            raise ValueError
        if scripts is not None and (not isinstance(scripts, Mapping)
                                    or not isinstance(scripts.get("results"), list)):
            raise ValueError
        fields = ("name", "type", "comments", "script", "expect-type", "expect-string", "log-trigger")
        owned = [] if scripts is None else [
            {key: row[key] for key in fields} for row in scripts["results"]
            if row.get("name") in {b.checkout_script, b.checkin_script}]
        owned.sort(key=lambda row: str(row["name"]))
        return SecretCheckoutInspection(metadata, _digest(body), _stable_checkout_metadata_digest(full),
                                        _digest(owned), execution.preserved_metadata_digest), body

    def _execution_account(self, owner: Any) -> SecretDescriptionInspection:
        b = self._checkout_binding
        folder = owner.resolve_folder_id(b.folder_path)
        secret_id = owner._lookup_id("secret", b.folder_path + "/" + b.execution_secret_name)
        if type(secret_id) is not int or not 0 < secret_id <= 2_147_483_647:
            raise ValueError
        status, envelope, _ = self._private._exchange(owner, "GET", secret_id)
        row = _record(envelope)
        if not isinstance(row, Mapping):
            raise ValueError
        target_info = row.get("target-info")
        description = row.get("description")
        if (status != 200 or not self._private._qualified(envelope, "GET")
                or any(type(row.get(key)) is not type(value) or row.get(key) != value
                       for key, value in {"id": secret_id, "folder": folder,
                    "name": b.execution_secret_name, "template": b.template_name,
                    "target": b.target_name, "ssh-service-status": "up",
                    "target-privilege-account": "disable", "associated-secret": 0,
                    "checkout": "disable", "checkout-script": "", "checkin-script": ""}.items())
                or not isinstance(target_info, Mapping)
                or type(target_info.get("priv_acct")) is not int
                or target_info["priv_acct"] != 0
                or not isinstance(description, str)):
            raise ValueError
        return SecretDescriptionInspection(secret_id, folder, description, _metadata_digest(row))

    def inspect(self) -> SecretCheckoutInspection:
        self._private._unconsumed()
        try:
            owner = self._private._owner()
            with owner.authenticated():
                current, _ = self._inspection(owner)
            if not owner.logout_verified:
                raise ValueError
            return current
        except Exception:
            raise RuntimeError(_UNAVAILABLE) from None

    def associate_and_readback(self, expected: SecretCheckoutInspection) -> SecretCheckoutReadback:
        with self._private._lock:
            self._private._unconsumed()
            retained: list[dict[str, object]] = []
            body: dict[str, object] = {}
            consumed = False
            stage = "owner_baseline"
            try:
                owner = self._private._owner()
                with owner.authenticated():
                    current, body = self._inspection(owner)
                    if not isinstance(expected, SecretCheckoutInspection) or current != expected:
                        raise ValueError
                    stage = "field_retention"
                    retained = self._private._retained_fields(owner, current.metadata)
                    execution = self._execution_account(owner)
                    if execution.preserved_metadata_digest != current.execution_account_digest:
                        raise ValueError
                    execution_fields = self._private._retained_fields(owner, execution)
                    for item in execution_fields:
                        item.clear()
                    execution_fields.clear()
                    stage = "prewrite_drift"
                    fresh, _ = self._inspection(owner)
                    if fresh != current:
                        raise ValueError
                    body.update(target=self._checkout_binding.target_name, field=retained)
                    stage = "csrf"
                    csrf = owner._client.cookies.get("ccsrftoken")
                    if not isinstance(csrf, str) or not csrf.strip('"') or any(
                        ord(char) < 33 or ord(char) > 126 for char in csrf.strip('"')
                    ):
                        raise ValueError
                    stage = "claim"
                    self._reserve_checkout(current)
                    consumed = True
                    stage = "put"
                    status, response, _ = self._private._exchange(owner, "PUT", current.metadata.secret_id,
                        body, headers={"X-CSRFTOKEN": csrf.strip('"')},
                        response_status=lambda code: self._save_receipt(".http-status.json", {
                            "body_digest": current.body_digest, "http_status": code,
                        }))
                    accepted = status == 200 and self._private._qualified(response, "PUT")
                    self._save_receipt(".http-result.json", {
                        "body_digest": current.body_digest,
                        "http_status": status, "http_accepted": accepted,
                        **(_native_error_category(response) if not accepted else {}),
                    })
                    stage = "readback"
                    controls_match = preserved = retained_match = False
                    for delay in (0.0, 0.5, 1.0, 2.0, 4.0):
                        if delay:
                            self._sleep(delay)
                        after, envelope, _ = self._private._read(owner)
                        row = _record(envelope)
                        if not isinstance(row, Mapping):
                            raise ValueError
                        controls_match = all(type(row.get(k)) is type(body[k]) and row[k] == body[k] for k in CONTROLS)
                        preserved = (after.secret_id == current.metadata.secret_id
                            and after.folder_id == current.metadata.folder_id
                            and _checkout_permission_state_matches(row, body["checkout"])
                            and _stable_checkout_metadata_digest(row) == current.unchanged_metadata_digest
                            and self._execution_account(owner).preserved_metadata_digest
                            == current.execution_account_digest)
                        if controls_match and preserved:
                            check = self._private._retained_fields(owner, after)
                            retained_match = check == retained
                            for item in check:
                                item.clear()
                            check.clear()
                            break
                result = SecretCheckoutReadback(True, accepted, controls_match, preserved,
                                                 retained_match, owner.logout_verified)
                self._save_receipt(".readback-result.json", {
                    "body_digest": current.body_digest, **asdict(result),
                })
                return result
            except Exception:
                if consumed:
                    try:
                        self._save_receipt(".failure.json", {"failure_stage": stage})
                    except Exception:
                        pass
                raise RuntimeError(_UNAVAILABLE) from None
            finally:
                for item in retained:
                    item.clear()
                retained.clear()
                body.clear()

    def _save_receipt(self, suffix: str, evidence: Mapping[str, object]) -> None:
        """Persist only fixed categorical evidence; never overwrite consumed records."""
        if suffix not in {".http-status.json", ".http-result.json", ".readback-result.json", ".failure.json"}:
            raise ValueError
        directory = os.open(self._claim.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
                raise ValueError
            fd = os.open(self._claim.name + suffix,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, "w") as file:
                json.dump({"contract": "secret-checkout-association-evidence-v1",
                           "operation": self._operation,
                           "replay_permitted": False, **evidence}, file)
                file.flush()
                os.fsync(file.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    def _reserve_checkout(self, current: SecretCheckoutInspection) -> None:
        self._private._unconsumed()
        directory = os.open(self._claim.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700:
                raise ValueError
            fd = os.open(self._claim.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, "w") as file:
                json.dump({"contract": "secret-checkout-association-claim-v1", "state": "reserved",
                    "operation": self._operation,
                    "body_digest": current.body_digest, "metadata_digest": current.metadata.preserved_metadata_digest,
                    "script_definition_digest": current.script_definition_digest,
                    "execution_account_digest": current.execution_account_digest,
                    "unchanged_metadata_digest": current.unchanged_metadata_digest,
                    "binding_digest": _digest(asdict(self._checkout_binding)), "replay_permitted": False}, file)
                file.flush(); os.fsync(file.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _unchanged_digest(row: Mapping[str, Any]) -> str:
    return _digest({key: value for key, value in row.items() if key not in CONTROLS | {"field"}})


def _checkout_permission_state_matches(row: Mapping[str, Any], checkout: object) -> bool:
    """The fixed profile is never checked out during a configuration write."""
    expected = {"disable": ("none", "allowed"), "enable": ("required", "forbidden")}
    if type(checkout) is not str or checkout not in expected:
        return False
    permissions = row.get("permissions")
    if not isinstance(permissions, Mapping):
        return False
    return all(type(permissions.get(key)) is str and permissions[key] == value
               for key, value in zip(("checkout_status", "passwd_change"), expected[checkout]))


def _stable_checkout_metadata_digest(row: Mapping[str, Any]) -> str:
    """Preserve all metadata except controls and two separately checked derived enums."""
    permissions = row.get("permissions")
    if not isinstance(permissions, Mapping):
        raise ValueError
    stable = {key: value for key, value in row.items() if key not in CONTROLS | {"field"}}
    stable["permissions"] = {key: value for key, value in permissions.items()
                             if key not in {"checkout_status", "passwd_change"}}
    return _digest(stable)


def _native_error_category(payload: object) -> dict[str, object]:
    """Classify known native error keys without retaining any upstream text."""
    if not isinstance(payload, Mapping):
        return {}
    result: dict[str, object] = {}
    error = payload.get("error")
    if type(error) is int and -2_147_483_648 <= error < 0:
        result["native_error_code"] = error
    messages = [value.casefold() for key in ("error", "cli_error")
                if isinstance(value := payload.get(key), str) and len(value) <= 4096]
    result["native_error_text_present"] = bool(messages)
    for label, needle in (("permission_denied_hint", "permission denied"),
                          ("referenced_entry_missing_hint", "entry not found"),
                          ("invalid_value_hint", "invalid value")):
        result[label] = any(needle in text for text in messages)
    result["checkout_field_hints"] = sorted(
        field for field in CONTROLS if any(
            re.search(r"['\"]" + re.escape(field) + r"['\"]", text) for text in messages
        )
    )
    return result
