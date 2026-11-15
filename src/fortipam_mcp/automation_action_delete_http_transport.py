"""Fixed REST/SSH recovery for the accepted unbound b44 Automation Action."""

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
from .automation_action_ssh_transport import (
    AutomationActionInspection,
    AutomationActionReadback,
)


ACTION_COLLECTION_PATH = "/api/v2/cmdb/system/automation-action"
TRIGGER_COLLECTION_PATH = "/api/v2/cmdb/system/automation-trigger"
STITCH_COLLECTION_PATH = "/api/v2/cmdb/system/automation-stitch"
ACTION_DELETE_NAME = "mcp-v4-automation-action-b44"
TRIGGER_ABSENT_NAME = "mcp-v4-automation-trigger-b40"
STITCH_ABSENT_NAME = "mcp-v4-automation-stitch-b68"
ACTION_ACCEPTED_DIGEST = (
    "8c00fc37492bfdfc2a8be50ff037b7db97928dad1535370a9d422be0133ef654"
)
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 Automation Action recovery is unavailable."


class AutomationActionDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the fixed Action recovery configuration is unsafe."""


class AutomationActionDeleteHttpTransportError(RuntimeError):
    """Stable, non-disclosing fixed Action recovery failure."""


class ActionSshTransport(Protocol):
    def inspect(self, action_name: str) -> AutomationActionInspection: ...

    def readback_existing(self, action_name: str) -> AutomationActionReadback: ...

    def reference_count(self, action_name: str) -> int: ...


@dataclass(frozen=True, slots=True)
class AutomationActionDeleteInspection:
    """Categorical eligibility for only the accepted unbound b44 Action."""

    exists: bool
    eligible_fixed_action: bool
    action_reference_count: int
    target_digest: str
    accepted_trigger_absent: bool
    accepted_stitch_absent: bool


@dataclass(frozen=True, slots=True)
class AutomationActionDeleteReadback:
    """Action absence after the one fixed DELETE."""

    api_absent: bool
    ssh_absent: bool

    @property
    def verified(self) -> bool:
        return self.api_absent and self.ssh_absent


class FortiPamAutomationActionDeleteHttpTransport:
    """Delete only unchanged, unreferenced b44 and prove its absence."""

    def __init__(
        self,
        config: AddressHttpTransportConfig,
        action_ssh_transport: ActionSshTransport,
        *,
        client_factory: Callable[..., Any] | None = None,
        accepted_digest: str = ACTION_ACCEPTED_DIGEST,
    ) -> None:
        if not _digest(accepted_digest):
            raise AutomationActionDeleteHttpTransportConfigurationError(
                "The accepted Automation Action digest is invalid."
            )
        self._config = config
        self._action_ssh_transport = action_ssh_transport
        self._client_factory = client_factory
        self._accepted_digest = accepted_digest

    def inspect_delete_target(self) -> AutomationActionDeleteInspection:
        """Prove complete fixed Action, absent dependencies, and zero references."""

        status, payload = self._request("GET", self._action_path())
        if status == 404:
            return AutomationActionDeleteInspection(
                exists=False,
                eligible_fixed_action=False,
                action_reference_count=0,
                target_digest="0" * 64,
                accepted_trigger_absent=False,
                accepted_stitch_absent=False,
            )
        record = _record(payload)
        if status != 200 or record is None:
            raise AutomationActionDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _record_digest(record)
        if (
            not hmac.compare_digest(target_digest, self._accepted_digest)
            or not _fixed_action_projection(record)
        ):
            raise AutomationActionDeleteHttpTransportError(_UNAVAILABLE)
        trigger_status, _ = self._request("GET", self._trigger_path())
        stitch_status, _ = self._request("GET", self._stitch_path())
        action_readback = self._action_ssh_transport.readback_existing(
            ACTION_DELETE_NAME
        )
        reference_count = self._action_ssh_transport.reference_count(
            ACTION_DELETE_NAME
        )
        if (
            not isinstance(action_readback, AutomationActionReadback)
            or not action_readback.verified
        ):
            raise AutomationActionDeleteHttpTransportError(_UNAVAILABLE)
        trigger_absent = trigger_status == 404
        stitch_absent = stitch_status == 404
        return AutomationActionDeleteInspection(
            exists=True,
            eligible_fixed_action=(
                reference_count == 0 and trigger_absent and stitch_absent
            ),
            action_reference_count=reference_count,
            target_digest=target_digest,
            accepted_trigger_absent=trigger_absent,
            accepted_stitch_absent=stitch_absent,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> AutomationActionDeleteReadback:
        """Delete exactly once and prove Action absence."""

        if not _digest(expected_target_digest):
            raise AutomationActionDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_action
            or inspection.action_reference_count != 0
            or not inspection.accepted_trigger_absent
            or not inspection.accepted_stitch_absent
            or not hmac.compare_digest(inspection.target_digest, expected_target_digest)
            or not hmac.compare_digest(inspection.target_digest, self._accepted_digest)
        ):
            raise AutomationActionDeleteHttpTransportError(_UNAVAILABLE)

        status, payload = self._request("DELETE", self._action_path())
        if status != 200 or not _successful_response(payload):
            raise AutomationActionDeleteHttpTransportError(_UNAVAILABLE)

        readback_status, _ = self._request("GET", self._action_path())
        action_inspection = self._action_ssh_transport.inspect(ACTION_DELETE_NAME)
        if not isinstance(action_inspection, AutomationActionInspection):
            raise AutomationActionDeleteHttpTransportError(_UNAVAILABLE)
        return AutomationActionDeleteReadback(
            api_absent=readback_status == 404,
            ssh_absent=not action_inspection.action_name_exists,
        )

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
            raise AutomationActionDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise AutomationActionDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AutomationActionDeleteHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _action_path() -> str:
        return f"{ACTION_COLLECTION_PATH}/{quote(ACTION_DELETE_NAME, safe='')}"

    @staticmethod
    def _trigger_path() -> str:
        return f"{TRIGGER_COLLECTION_PATH}/{quote(TRIGGER_ABSENT_NAME, safe='')}"

    @staticmethod
    def _stitch_path() -> str:
        return f"{STITCH_COLLECTION_PATH}/{quote(STITCH_ABSENT_NAME, safe='')}"


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _fixed_action_projection(record: Mapping[str, object]) -> bool:
    return (
        record.get("name") == ACTION_DELETE_NAME
        and record.get("q_origin_key") == ACTION_DELETE_NAME
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
        raise AutomationActionDeleteHttpTransportConfigurationError(
            "System trust-store support is unavailable."
        ) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
