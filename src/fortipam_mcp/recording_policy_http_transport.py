"""Fixed REST transport for one FortiPAM Secret Policy recording transition.

Only one existing laboratory-prefixed Secret Policy can transition from a
supported non-recording baseline to ``recording=enable``. The transport uses
fixed detail GET and PUT routes and never exposes remote Policy, Folder,
Secret, session, or raw API data through the MCP boundary; the workflow may
echo its explicit non-secret selected Policy name in the C/P/E preview.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any, Literal
from urllib.parse import quote, urlsplit


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_RECORDING_POLICY_API_"
COLLECTION_PATH = "/api/v2/cmdb/secret/policy"
SECRET_POLICY_NAME_PREFIX = "mcp-v4-secret-policy-"
MAX_RESPONSE_BYTES = 1_048_576
RECORDING_ENABLED = "enable"
_RECORDING_NOT_ENABLED = frozenset({"disable", "not-set", "not_set", "unset"})
_NAME = re.compile(r"mcp-v4-secret-policy-[A-Za-z0-9][A-Za-z0-9._-]{0,42}\Z")
_UNAVAILABLE = "FortiPAM V4 Recording Policy action is unavailable."


class RecordingPolicyHttpTransportConfigurationError(ValueError):
    """Raised when dedicated Recording Policy API settings are unsafe."""


class RecordingPolicyHttpTransportError(RuntimeError):
    """Raised for a bounded Recording Policy API failure."""


@dataclass(frozen=True, slots=True)
class RecordingPolicyHttpTransportConfig:
    """Dedicated HTTPS and bearer settings held only in process memory."""

    base_url: str
    bearer_token: str
    timeout_seconds: float
    ca_file: str | None

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise RecordingPolicyHttpTransportConfigurationError(
                "A dedicated HTTPS Recording Policy API target is required."
            )
        if not self.bearer_token or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.bearer_token
        ):
            raise RecordingPolicyHttpTransportConfigurationError(
                "A dedicated Recording Policy API bearer token is required."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise RecordingPolicyHttpTransportConfigurationError(
                "The Recording Policy API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise RecordingPolicyHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class RecordingPolicyInspection:
    """Value-minimized current state for one existing Secret Policy."""

    policy_exists: bool
    recording_enabled: bool
    state_digest: str

    @property
    def ready_to_enable(self) -> bool:
        return self.policy_exists and not self.recording_enabled


@dataclass(frozen=True, slots=True)
class RecordingPolicyReadback:
    """Categorical post-write evidence without returning Policy data."""

    policy_exists: bool
    recording_enabled: bool

    @property
    def verified(self) -> bool:
        return self.policy_exists and self.recording_enabled


def load_recording_policy_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> RecordingPolicyHttpTransportConfig:
    """Load independently scoped API configuration after explicit opt-in."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise RecordingPolicyHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token is None:
        raise RecordingPolicyHttpTransportConfigurationError(
            "Dedicated Recording Policy API target and bearer token are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise RecordingPolicyHttpTransportConfigurationError(
            "The Recording Policy API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return RecordingPolicyHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamRecordingPolicyHttpTransport:
    """Issue only compiled Secret Policy recording enable requests."""

    def __init__(
        self,
        config: RecordingPolicyHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect(self, policy_name: str) -> RecordingPolicyInspection:
        """Read recording posture without returning a Policy configuration."""

        name = _name(policy_name)
        status, payload = self._request("GET", self._detail_path(name), None)
        if status == 404:
            return RecordingPolicyInspection(False, False, _state_digest(name, "absent"))
        detail = _record(payload)
        if status != 200 or detail is None:
            raise RecordingPolicyHttpTransportError(_UNAVAILABLE)
        return _inspection_from_detail(detail, name)

    def enable_and_readback(self, policy_name: str) -> RecordingPolicyReadback:
        """Enable only the documented recording field and read it back."""

        name = _name(policy_name)
        current = self.inspect(name)
        if not current.ready_to_enable:
            raise RecordingPolicyHttpTransportError(_UNAVAILABLE)
        status, payload = self._request(
            "PUT",
            self._detail_path(name),
            {"recording": RECORDING_ENABLED},
        )
        if status != 200 or not _successful_response(payload):
            raise RecordingPolicyHttpTransportError(_UNAVAILABLE)
        detail_status, detail_payload = self._request("GET", self._detail_path(name), None)
        detail = _record(detail_payload)
        if detail_status != 200 or detail is None:
            return RecordingPolicyReadback(False, False)
        try:
            inspected = _inspection_from_detail(detail, name)
        except RecordingPolicyHttpTransportError:
            return RecordingPolicyReadback(False, False)
        return RecordingPolicyReadback(
            policy_exists=inspected.policy_exists,
            recording_enabled=inspected.recording_enabled,
        )

    def _request(
        self,
        method: Literal["GET", "PUT"],
        path: str,
        body: Mapping[str, object] | None,
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
                    json=body,
                )
        except Exception as exc:
            raise RecordingPolicyHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise RecordingPolicyHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RecordingPolicyHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path(policy_name: str) -> str:
        return f"{COLLECTION_PATH}/{quote(policy_name, safe='')}"


def _inspection_from_detail(
    detail: Mapping[str, object], policy_name: str
) -> RecordingPolicyInspection:
    if detail.get("name") != policy_name:
        raise RecordingPolicyHttpTransportError(_UNAVAILABLE)
    recording = detail.get("recording")
    if recording == RECORDING_ENABLED:
        return RecordingPolicyInspection(True, True, _state_digest(policy_name, recording))
    if recording in _RECORDING_NOT_ENABLED:
        return RecordingPolicyInspection(True, False, _state_digest(policy_name, recording))
    raise RecordingPolicyHttpTransportError(_UNAVAILABLE)


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _state_digest(policy_name: str, recording: str) -> str:
    return hashlib.sha256(
        json.dumps(
            {"policy_name": policy_name, "recording": recording},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    ).hexdigest()


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise RecordingPolicyHttpTransportError(_UNAVAILABLE)
    return value


def _successful_response(payload: object) -> bool:
    return isinstance(payload, Mapping) and payload.get("http_status") in {None, 200}


def _ssl_context(config: RecordingPolicyHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - dependency guard.
        raise RecordingPolicyHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "COLLECTION_PATH",
    "ENV_PREFIX",
    "FortiPamRecordingPolicyHttpTransport",
    "RECORDING_ENABLED",
    "RecordingPolicyHttpTransportConfig",
    "RecordingPolicyHttpTransportConfigurationError",
    "RecordingPolicyHttpTransportError",
    "RecordingPolicyInspection",
    "RecordingPolicyReadback",
    "SECRET_POLICY_NAME_PREFIX",
    "load_recording_policy_http_transport_config",
]
