"""Fixed REST/SSH recovery for the accepted disabled b68 Automation Stitch."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import ssl
from typing import Any, Literal
from urllib.parse import quote

from .address_http_transport import AddressHttpTransportConfig
from .automation_stitch_ssh_transport import (
    AutomationStitchInspection,
    AutomationStitchReadback,
    FortiPamAutomationStitchSshTransport,
)


STITCH_COLLECTION_PATH = "/api/v2/cmdb/system/automation-stitch"
TRIGGER_COLLECTION_PATH = "/api/v2/cmdb/system/automation-trigger"
ACTION_COLLECTION_PATH = "/api/v2/cmdb/system/automation-action"
STITCH_DELETE_NAME = "mcp-v4-automation-stitch-b68"
TRIGGER_PRESERVE_NAME = "mcp-v4-automation-trigger-b40"
ACTION_PRESERVE_NAME = "mcp-v4-automation-action-b44"
STITCH_ACCEPTED_DIGEST = (
    "6151c136dd26e435afec147f7fdd918e515b0c3174bc5df75888a281e27c99f4"
)
TRIGGER_ACCEPTED_DIGEST = (
    "6dbad8bf12f3b4b3fc96b440b4b26668c8da832a831775699867deac221fb903"
)
ACTION_ACCEPTED_DIGEST = (
    "8c00fc37492bfdfc2a8be50ff037b7db97928dad1535370a9d422be0133ef654"
)
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 Automation Stitch recovery is unavailable."


class AutomationStitchDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the fixed Stitch recovery configuration is unsafe."""


class AutomationStitchDeleteHttpTransportError(RuntimeError):
    """Stable, non-disclosing fixed Stitch recovery failure."""


@dataclass(frozen=True, slots=True)
class AutomationStitchDeleteInspection:
    """Categorical eligibility for only the accepted disabled b68 Stitch."""

    exists: bool
    eligible_fixed_stitch: bool
    stitch_reference_count: int
    target_digest: str
    trigger_digest: str
    action_digest: str


@dataclass(frozen=True, slots=True)
class AutomationStitchDeleteReadback:
    """Stitch absence plus fixed Trigger/Action preservation after DELETE."""

    api_absent: bool
    ssh_absent: bool
    trigger_api_preserved: bool
    action_api_preserved: bool
    trigger_ssh_present: bool
    action_ssh_present: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.api_absent,
                self.ssh_absent,
                self.trigger_api_preserved,
                self.action_api_preserved,
                self.trigger_ssh_present,
                self.action_ssh_present,
            )
        )


class FortiPamAutomationStitchDeleteHttpTransport:
    """Delete only unchanged b68 and prove b40/b44 remain unchanged."""

    def __init__(
        self,
        config: AddressHttpTransportConfig,
        ssh_transport: FortiPamAutomationStitchSshTransport,
        *,
        client_factory: Callable[..., Any] | None = None,
        accepted_digest: str = STITCH_ACCEPTED_DIGEST,
        trigger_digest: str = TRIGGER_ACCEPTED_DIGEST,
        action_digest: str = ACTION_ACCEPTED_DIGEST,
    ) -> None:
        if not all(_digest(value) for value in (accepted_digest, trigger_digest, action_digest)):
            raise AutomationStitchDeleteHttpTransportConfigurationError(
                "The accepted Automation Stitch dependency digests are invalid."
            )
        self._config = config
        self._ssh_transport = ssh_transport
        self._client_factory = client_factory
        self._accepted_digest = accepted_digest
        self._trigger_digest = trigger_digest
        self._action_digest = action_digest

    def inspect_delete_target(self) -> AutomationStitchDeleteInspection:
        """Prove complete fixed Stitch, dependencies, and zero references."""

        status, payload = self._request("GET", self._stitch_path())
        if status == 404:
            return AutomationStitchDeleteInspection(
                exists=False,
                eligible_fixed_stitch=False,
                stitch_reference_count=0,
                target_digest="0" * 64,
                trigger_digest="0" * 64,
                action_digest="0" * 64,
            )
        record = _record(payload)
        if status != 200 or record is None:
            raise AutomationStitchDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _record_digest(record)
        trigger_record = self._required_record(self._trigger_path())
        action_record = self._required_record(self._action_path())
        trigger_digest = _record_digest(trigger_record)
        action_digest = _record_digest(action_record)
        if (
            not hmac.compare_digest(target_digest, self._accepted_digest)
            or not hmac.compare_digest(trigger_digest, self._trigger_digest)
            or not hmac.compare_digest(action_digest, self._action_digest)
            or not _fixed_stitch_projection(record)
            or not _fixed_trigger_projection(trigger_record)
            or not _fixed_action_projection(action_record)
        ):
            raise AutomationStitchDeleteHttpTransportError(_UNAVAILABLE)
        ssh_readback = self._ssh_transport.readback_existing(
            STITCH_DELETE_NAME,
            TRIGGER_PRESERVE_NAME,
            ACTION_PRESERVE_NAME,
        )
        reference_count = self._ssh_transport.reference_count(STITCH_DELETE_NAME)
        if not isinstance(ssh_readback, AutomationStitchReadback) or not ssh_readback.verified:
            raise AutomationStitchDeleteHttpTransportError(_UNAVAILABLE)
        return AutomationStitchDeleteInspection(
            exists=True,
            eligible_fixed_stitch=reference_count == 0,
            stitch_reference_count=reference_count,
            target_digest=target_digest,
            trigger_digest=trigger_digest,
            action_digest=action_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> AutomationStitchDeleteReadback:
        """Delete exactly once and prove Stitch absence plus dependency preservation."""

        if not _digest(expected_target_digest):
            raise AutomationStitchDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_stitch
            or inspection.stitch_reference_count != 0
            or not hmac.compare_digest(inspection.target_digest, expected_target_digest)
            or not hmac.compare_digest(inspection.target_digest, self._accepted_digest)
            or not hmac.compare_digest(inspection.trigger_digest, self._trigger_digest)
            or not hmac.compare_digest(inspection.action_digest, self._action_digest)
        ):
            raise AutomationStitchDeleteHttpTransportError(_UNAVAILABLE)

        status, payload = self._request("DELETE", self._stitch_path())
        if status != 200 or not _successful_response(payload):
            raise AutomationStitchDeleteHttpTransportError(_UNAVAILABLE)

        readback_status, _ = self._request("GET", self._stitch_path())
        trigger_status, trigger_payload = self._request("GET", self._trigger_path())
        action_status, action_payload = self._request("GET", self._action_path())
        trigger_record = _record(trigger_payload)
        action_record = _record(action_payload)
        ssh_inspection = self._ssh_transport.inspect(
            STITCH_DELETE_NAME,
            TRIGGER_PRESERVE_NAME,
            ACTION_PRESERVE_NAME,
        )
        if not isinstance(ssh_inspection, AutomationStitchInspection):
            raise AutomationStitchDeleteHttpTransportError(_UNAVAILABLE)
        return AutomationStitchDeleteReadback(
            api_absent=readback_status == 404,
            ssh_absent=not ssh_inspection.stitch_name_exists,
            trigger_api_preserved=(
                trigger_status == 200
                and trigger_record is not None
                and hmac.compare_digest(
                    _record_digest(trigger_record),
                    self._trigger_digest,
                )
                and _fixed_trigger_projection(trigger_record)
            ),
            action_api_preserved=(
                action_status == 200
                and action_record is not None
                and hmac.compare_digest(
                    _record_digest(action_record),
                    self._action_digest,
                )
                and _fixed_action_projection(action_record)
            ),
            trigger_ssh_present=ssh_inspection.trigger_name_exists,
            action_ssh_present=ssh_inspection.action_name_exists,
        )

    def _required_record(self, path: str) -> Mapping[str, object]:
        status, payload = self._request("GET", path)
        record = _record(payload)
        if status != 200 or record is None:
            raise AutomationStitchDeleteHttpTransportError(_UNAVAILABLE)
        return record

    def _request(
        self,
        method: Literal["GET", "DELETE"],
        path: str,
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
                )
        except Exception as exc:
            raise AutomationStitchDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise AutomationStitchDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AutomationStitchDeleteHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _stitch_path() -> str:
        return f"{STITCH_COLLECTION_PATH}/{quote(STITCH_DELETE_NAME, safe='')}"

    @staticmethod
    def _trigger_path() -> str:
        return f"{TRIGGER_COLLECTION_PATH}/{quote(TRIGGER_PRESERVE_NAME, safe='')}"

    @staticmethod
    def _action_path() -> str:
        return f"{ACTION_COLLECTION_PATH}/{quote(ACTION_PRESERVE_NAME, safe='')}"


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _fixed_stitch_projection(record: Mapping[str, object]) -> bool:
    actions = record.get("actions")
    action = actions[0] if isinstance(actions, list) and len(actions) == 1 else None
    return (
        set(record)
        == {"actions", "description", "destination", "name", "q_origin_key", "status", "trigger"}
        and record.get("name") == STITCH_DELETE_NAME
        and record.get("q_origin_key") == STITCH_DELETE_NAME
        and record.get("status") == "disable"
        and record.get("description") == "MCP V4 disabled single-action lab stitch"
        and record.get("trigger") == TRIGGER_PRESERVE_NAME
        and isinstance(action, Mapping)
        and set(action) == {"action", "delay", "id", "q_origin_key", "required"}
        and action.get("action") == ACTION_PRESERVE_NAME
        and action.get("delay") == 0
        and action.get("required") == "enable"
    )


def _fixed_trigger_projection(record: Mapping[str, object]) -> bool:
    logids = record.get("logid")
    logid = logids[0] if isinstance(logids, list) and len(logids) == 1 else None
    fields = record.get("fields")
    field = fields[0] if isinstance(fields, list) and len(fields) == 1 else None
    return (
        record.get("name") == TRIGGER_PRESERVE_NAME
        and record.get("q_origin_key") == TRIGGER_PRESERVE_NAME
        and record.get("event-type") == "event-log"
        and record.get("category") == 1
        and record.get("logic") == "and"
        and isinstance(logid, Mapping)
        and logid.get("id") == 44547
        and isinstance(field, Mapping)
        and field.get("match") == "regex"
        and field.get("name") == "msg"
        and field.get("value") == "mcp-v4-no-action"
    )


def _fixed_action_projection(record: Mapping[str, object]) -> bool:
    return (
        record.get("name") == ACTION_PRESERVE_NAME
        and record.get("q_origin_key") == ACTION_PRESERVE_NAME
        and record.get("action-type") == "email"
        and record.get("email-subject") == "FortiPAM V4 unbound action"
        and record.get("message") == "MCP V4 unbound action no stitch"
        and record.get("description") == "MCP V4 unbound automation action"
    )


def _record_digest(record: Mapping[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            record,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _digest(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _successful_response(payload: object) -> bool:
    return isinstance(payload, Mapping) and payload.get("http_status") in {None, 200}


def _ssl_context(config: AddressHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover
        raise AutomationStitchDeleteHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "ACTION_ACCEPTED_DIGEST",
    "ACTION_PRESERVE_NAME",
    "AutomationStitchDeleteHttpTransportConfigurationError",
    "AutomationStitchDeleteHttpTransportError",
    "AutomationStitchDeleteInspection",
    "AutomationStitchDeleteReadback",
    "FortiPamAutomationStitchDeleteHttpTransport",
    "STITCH_ACCEPTED_DIGEST",
    "STITCH_DELETE_NAME",
    "TRIGGER_ACCEPTED_DIGEST",
    "TRIGGER_PRESERVE_NAME",
]
