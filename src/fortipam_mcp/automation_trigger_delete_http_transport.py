"""Fixed REST/SSH recovery for the accepted unbound b40 Automation Trigger."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import ssl
from typing import Any, Literal, Protocol
from urllib.parse import quote

from .address_http_transport import AddressHttpTransportConfig
from .automation_action_ssh_transport import AutomationActionInspection
from .automation_trigger_ssh_transport import (
    AutomationTriggerInspection,
    AutomationTriggerReadback,
)


TRIGGER_COLLECTION_PATH = "/api/v2/cmdb/system/automation-trigger"
ACTION_COLLECTION_PATH = "/api/v2/cmdb/system/automation-action"
TRIGGER_DELETE_NAME = "mcp-v4-automation-trigger-b40"
ACTION_PRESERVE_NAME = "mcp-v4-automation-action-b44"
TRIGGER_ACCEPTED_DIGEST = (
    "6dbad8bf12f3b4b3fc96b440b4b26668c8da832a831775699867deac221fb903"
)
ACTION_ACCEPTED_DIGEST = (
    "8c00fc37492bfdfc2a8be50ff037b7db97928dad1535370a9d422be0133ef654"
)
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 Automation Trigger recovery is unavailable."


class AutomationTriggerDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the fixed Trigger recovery configuration is unsafe."""


class AutomationTriggerDeleteHttpTransportError(RuntimeError):
    """Stable, non-disclosing fixed Trigger recovery failure."""


class TriggerSshTransport(Protocol):
    def inspect(self, trigger_name: str) -> AutomationTriggerInspection: ...

    def readback_existing(self, trigger_name: str) -> AutomationTriggerReadback: ...

    def reference_count(self, trigger_name: str) -> int: ...


class ActionSshTransport(Protocol):
    def inspect(self, action_name: str) -> AutomationActionInspection: ...


@dataclass(frozen=True, slots=True)
class AutomationTriggerDeleteInspection:
    """Categorical eligibility for only the accepted unbound b40 Trigger."""

    exists: bool
    eligible_fixed_trigger: bool
    trigger_reference_count: int
    target_digest: str
    action_digest: str


@dataclass(frozen=True, slots=True)
class AutomationTriggerDeleteReadback:
    """Trigger absence plus fixed b44 Action preservation after DELETE."""

    api_absent: bool
    ssh_absent: bool
    action_api_preserved: bool
    action_ssh_present: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.api_absent,
                self.ssh_absent,
                self.action_api_preserved,
                self.action_ssh_present,
            )
        )


class FortiPamAutomationTriggerDeleteHttpTransport:
    """Delete only unchanged b40 and prove b44 remains unchanged."""

    def __init__(
        self,
        config: AddressHttpTransportConfig,
        trigger_ssh_transport: TriggerSshTransport,
        action_ssh_transport: ActionSshTransport,
        *,
        client_factory: Callable[..., Any] | None = None,
        accepted_digest: str = TRIGGER_ACCEPTED_DIGEST,
        action_digest: str = ACTION_ACCEPTED_DIGEST,
    ) -> None:
        if not all(_digest(value) for value in (accepted_digest, action_digest)):
            raise AutomationTriggerDeleteHttpTransportConfigurationError(
                "The accepted Automation Trigger dependency digests are invalid."
            )
        self._config = config
        self._trigger_ssh_transport = trigger_ssh_transport
        self._action_ssh_transport = action_ssh_transport
        self._client_factory = client_factory
        self._accepted_digest = accepted_digest
        self._action_digest = action_digest

    def inspect_delete_target(self) -> AutomationTriggerDeleteInspection:
        """Prove complete fixed Trigger, b44 preservation, and zero references."""

        status, payload = self._request("GET", self._trigger_path())
        if status == 404:
            return AutomationTriggerDeleteInspection(
                exists=False,
                eligible_fixed_trigger=False,
                trigger_reference_count=0,
                target_digest="0" * 64,
                action_digest="0" * 64,
            )
        record = _record(payload)
        if status != 200 or record is None:
            raise AutomationTriggerDeleteHttpTransportError(_UNAVAILABLE)
        action_record = self._required_record(self._action_path())
        target_digest = _record_digest(record)
        action_digest = _record_digest(action_record)
        if (
            not hmac.compare_digest(target_digest, self._accepted_digest)
            or not hmac.compare_digest(action_digest, self._action_digest)
            or not _fixed_trigger_projection(record)
            or not _fixed_action_projection(action_record)
        ):
            raise AutomationTriggerDeleteHttpTransportError(_UNAVAILABLE)
        trigger_readback = self._trigger_ssh_transport.readback_existing(
            TRIGGER_DELETE_NAME
        )
        action_inspection = self._action_ssh_transport.inspect(ACTION_PRESERVE_NAME)
        reference_count = self._trigger_ssh_transport.reference_count(
            TRIGGER_DELETE_NAME
        )
        if (
            not isinstance(trigger_readback, AutomationTriggerReadback)
            or not _fixed_trigger_ssh_projection(trigger_readback)
            or not isinstance(action_inspection, AutomationActionInspection)
            or not action_inspection.action_name_exists
        ):
            raise AutomationTriggerDeleteHttpTransportError(_UNAVAILABLE)
        return AutomationTriggerDeleteInspection(
            exists=True,
            eligible_fixed_trigger=reference_count == 0,
            trigger_reference_count=reference_count,
            target_digest=target_digest,
            action_digest=action_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> AutomationTriggerDeleteReadback:
        """Delete exactly once and prove Trigger absence plus b44 preservation."""

        if not _digest(expected_target_digest):
            raise AutomationTriggerDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_trigger
            or inspection.trigger_reference_count != 0
            or not hmac.compare_digest(inspection.target_digest, expected_target_digest)
            or not hmac.compare_digest(inspection.target_digest, self._accepted_digest)
            or not hmac.compare_digest(inspection.action_digest, self._action_digest)
        ):
            raise AutomationTriggerDeleteHttpTransportError(_UNAVAILABLE)

        status, payload = self._request("DELETE", self._trigger_path())
        if status != 200 or not _successful_response(payload):
            raise AutomationTriggerDeleteHttpTransportError(_UNAVAILABLE)

        readback_status, _ = self._request("GET", self._trigger_path())
        action_status, action_payload = self._request("GET", self._action_path())
        action_record = _record(action_payload)
        trigger_inspection = self._trigger_ssh_transport.inspect(TRIGGER_DELETE_NAME)
        action_inspection = self._action_ssh_transport.inspect(ACTION_PRESERVE_NAME)
        if (
            not isinstance(trigger_inspection, AutomationTriggerInspection)
            or not isinstance(action_inspection, AutomationActionInspection)
        ):
            raise AutomationTriggerDeleteHttpTransportError(_UNAVAILABLE)
        return AutomationTriggerDeleteReadback(
            api_absent=readback_status == 404,
            ssh_absent=not trigger_inspection.trigger_name_exists,
            action_api_preserved=(
                action_status == 200
                and action_record is not None
                and hmac.compare_digest(
                    _record_digest(action_record),
                    self._action_digest,
                )
                and _fixed_action_projection(action_record)
            ),
            action_ssh_present=action_inspection.action_name_exists,
        )

    def _required_record(self, path: str) -> Mapping[str, object]:
        status, payload = self._request("GET", path)
        record = _record(payload)
        if status != 200 or record is None:
            raise AutomationTriggerDeleteHttpTransportError(_UNAVAILABLE)
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
            raise AutomationTriggerDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise AutomationTriggerDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AutomationTriggerDeleteHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _trigger_path() -> str:
        return f"{TRIGGER_COLLECTION_PATH}/{quote(TRIGGER_DELETE_NAME, safe='')}"

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


def _fixed_trigger_projection(record: Mapping[str, object]) -> bool:
    logids = record.get("logid")
    logid = logids[0] if isinstance(logids, list) and len(logids) == 1 else None
    fields = record.get("fields")
    field = fields[0] if isinstance(fields, list) and len(fields) == 1 else None
    return (
        record.get("name") == TRIGGER_DELETE_NAME
        and record.get("q_origin_key") == TRIGGER_DELETE_NAME
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


def _fixed_trigger_ssh_projection(readback: AutomationTriggerReadback) -> bool:
    return all(
        (
            readback.trigger_name_exists,
            readback.event_log_type_enabled,
            readback.fixed_logid_present,
            readback.category_one_present,
            readback.logic_and_enabled,
        )
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
        raise AutomationTriggerDeleteHttpTransportConfigurationError(
            "System trust-store support is unavailable."
        ) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
