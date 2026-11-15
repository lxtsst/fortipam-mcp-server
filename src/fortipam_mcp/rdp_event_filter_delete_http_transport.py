"""Fixed REST/SSH recovery transport for the accepted b35 RDP event filter.

The transport compiles only one Profile detail/delete route plus bounded Secret
and Policy dependency reads.  It pins the complete API record by digest and
independently verifies the documented three-event SSH projection.  Raw records,
names, and protected content never cross the MCP boundary.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import ssl
from typing import Any, Literal
from urllib.parse import quote, urlsplit

from .rdp_event_filter_ssh_transport import (
    FortiPamRdpEventFilterSshTransport,
    RdpEventFilterInspection,
    RdpEventFilterReadback,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_RDP_EVENT_FILTER_API_"
COLLECTION_PATH = "/api/v2/cmdb/secret/event-filter-profile"
SECRET_COLLECTION_PATH = "/api/v2/cmdb/secret/database"
POLICY_COLLECTION_PATH = "/api/v2/cmdb/secret/policy"
RDP_EVENT_FILTER_DELETE_NAME = "mcp-v4-rdp-event-filter-b35"
RDP_EVENT_FILTER_ACCEPTED_DIGEST = (
    "ea59120cbb87feff7628ebcef140d021e559f22736bb9f79259cd093ab423a60"
)
DEPENDENCY_PAGE_SIZE = 100
MAX_DEPENDENCY_PAGES = 100
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 RDP event-filter recovery is unavailable."


class RdpEventFilterDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the dedicated RDP event-filter API route is unsafe."""


class RdpEventFilterDeleteHttpTransportError(RuntimeError):
    """Stable, non-disclosing fixed recovery failure."""


@dataclass(frozen=True, slots=True)
class RdpEventFilterDeleteHttpTransportConfig:
    """Dedicated verified-TLS API settings held only in process memory."""

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
            raise RdpEventFilterDeleteHttpTransportConfigurationError(
                "A dedicated HTTPS RDP event-filter API target is required."
            )
        if (
            not self.bearer_token
            or len(self.bearer_token) > 4096
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.bearer_token
            )
        ):
            raise RdpEventFilterDeleteHttpTransportConfigurationError(
                "The RDP event-filter API bearer token is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise RdpEventFilterDeleteHttpTransportConfigurationError(
                "The RDP event-filter API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise RdpEventFilterDeleteHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class RdpEventFilterDeleteInspection:
    """Categorical eligibility for the exact accepted b35 recovery target."""

    exists: bool
    eligible_fixed_profile: bool
    secret_reference_count: int
    policy_reference_count: int
    target_digest: str


@dataclass(frozen=True, slots=True)
class RdpEventFilterDeleteReadback:
    """Dual categorical absence after the fixed DELETE."""

    api_absent: bool
    ssh_absent: bool

    @property
    def verified(self) -> bool:
        return self.api_absent and self.ssh_absent


def load_rdp_event_filter_delete_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> RdpEventFilterDeleteHttpTransportConfig:
    """Load the independently scoped fixed recovery API configuration."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise RdpEventFilterDeleteHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token is None:
        raise RdpEventFilterDeleteHttpTransportConfigurationError(
            "Dedicated RDP event-filter API target and bearer token are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise RdpEventFilterDeleteHttpTransportConfigurationError(
            "The RDP event-filter API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return RdpEventFilterDeleteHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamRdpEventFilterDeleteHttpTransport:
    """Inspect and delete only the unchanged, unreferenced b35 Profile."""

    def __init__(
        self,
        config: RdpEventFilterDeleteHttpTransportConfig,
        ssh_transport: FortiPamRdpEventFilterSshTransport,
        *,
        client_factory: Callable[..., Any] | None = None,
        accepted_digest: str = RDP_EVENT_FILTER_ACCEPTED_DIGEST,
    ) -> None:
        if not _digest(accepted_digest):
            raise RdpEventFilterDeleteHttpTransportConfigurationError(
                "The accepted RDP event-filter digest is invalid."
            )
        self._config = config
        self._ssh_transport = ssh_transport
        self._client_factory = client_factory
        self._accepted_digest = accepted_digest

    def inspect_delete_target(self) -> RdpEventFilterDeleteInspection:
        """Prove the accepted record, fixed CLI projection, and no references."""

        status, payload = self._request("GET", self._detail_path(), None)
        if status == 404:
            return RdpEventFilterDeleteInspection(False, False, 0, 0, "0" * 64)
        record = _record(payload)
        if status != 200 or record is None:
            raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _profile_digest(record)
        if (
            not hmac.compare_digest(target_digest, self._accepted_digest)
            or not _fixed_api_projection(record)
        ):
            raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE)
        ssh_readback = self._ssh_transport.readback(RDP_EVENT_FILTER_DELETE_NAME)
        if not isinstance(ssh_readback, RdpEventFilterReadback) or not ssh_readback.verified:
            raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE)
        secret_references = self._dependency_reference_count(SECRET_COLLECTION_PATH)
        policy_references = self._dependency_reference_count(POLICY_COLLECTION_PATH)
        return RdpEventFilterDeleteInspection(
            exists=True,
            eligible_fixed_profile=secret_references == 0 and policy_references == 0,
            secret_reference_count=secret_references,
            policy_reference_count=policy_references,
            target_digest=target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> RdpEventFilterDeleteReadback:
        """Delete exactly once and prove absence over both API and SSH."""

        if not _digest(expected_target_digest):
            raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_profile
            or inspection.secret_reference_count != 0
            or inspection.policy_reference_count != 0
            or not hmac.compare_digest(inspection.target_digest, expected_target_digest)
            or not hmac.compare_digest(inspection.target_digest, self._accepted_digest)
        ):
            raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE)
        status, payload = self._request("DELETE", self._detail_path(), None)
        if status != 200 or not _successful_response(payload):
            raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE)
        readback_status, _ = self._request("GET", self._detail_path(), None)
        ssh_inspection = self._ssh_transport.inspect(RDP_EVENT_FILTER_DELETE_NAME)
        if not isinstance(ssh_inspection, RdpEventFilterInspection):
            raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE)
        return RdpEventFilterDeleteReadback(
            api_absent=readback_status == 404,
            ssh_absent=not ssh_inspection.profile_name_exists,
        )

    def _dependency_reference_count(self, path: str) -> int:
        reference_count = 0
        for page in range(MAX_DEPENDENCY_PAGES):
            status, payload = self._request(
                "GET",
                path,
                None,
                query=(
                    f"start={page * DEPENDENCY_PAGE_SIZE}&count={DEPENDENCY_PAGE_SIZE}"
                ),
            )
            records = _records(payload)
            if status != 200 or records is None:
                raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE)
            reference_count += sum(
                _count_exact_reference(record, RDP_EVENT_FILTER_DELETE_NAME)
                for record in records
            )
            if len(records) < DEPENDENCY_PAGE_SIZE:
                return reference_count
        raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE)

    def _request(
        self,
        method: Literal["GET", "DELETE"],
        path: str,
        body: Mapping[str, object] | None,
        *,
        query: str | None = None,
    ) -> tuple[int, object | None]:
        url = f"{self._config.base_url}{path}"
        if query is not None:
            url = f"{url}?{query}"
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
                    url,
                    headers={
                        "Accept": "application/json",
                        "Authorization": f"Bearer {self._config.bearer_token}",
                    },
                    json=body,
                )
        except Exception as exc:
            raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path() -> str:
        return f"{COLLECTION_PATH}/{quote(RDP_EVENT_FILTER_DELETE_NAME, safe='')}"


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _records(payload: object) -> list[Mapping[str, object]] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, list) and all(isinstance(item, Mapping) for item in result):
        return list(result)
    if isinstance(result, Mapping):
        return [result]
    return None


def _fixed_api_projection(record: Mapping[str, object]) -> bool:
    return (
        record.get("name") == RDP_EVENT_FILTER_DELETE_NAME
        and record.get("q_origin_key") == RDP_EVENT_FILTER_DELETE_NAME
        and record.get("process-log") in {"enable", "monitor"}
        and record.get("filesystem-log") in {"enable", "monitor"}
        and (
            record.get("user-management") in {"enable", "monitor"}
            or record.get("user-management-log") in {"enable", "monitor"}
        )
    )


def _count_exact_reference(value: object, target: str) -> int:
    if isinstance(value, str):
        return int(value == target)
    if isinstance(value, Mapping):
        return sum(_count_exact_reference(item, target) for item in value.values())
    if isinstance(value, list):
        return sum(_count_exact_reference(item, target) for item in value)
    return 0


def _profile_digest(record: Mapping[str, object]) -> str:
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


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _ssl_context(config: RdpEventFilterDeleteHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover
        raise RdpEventFilterDeleteHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "COLLECTION_PATH",
    "ENV_PREFIX",
    "FortiPamRdpEventFilterDeleteHttpTransport",
    "POLICY_COLLECTION_PATH",
    "RDP_EVENT_FILTER_ACCEPTED_DIGEST",
    "RDP_EVENT_FILTER_DELETE_NAME",
    "RdpEventFilterDeleteHttpTransportConfig",
    "RdpEventFilterDeleteHttpTransportConfigurationError",
    "RdpEventFilterDeleteHttpTransportError",
    "RdpEventFilterDeleteInspection",
    "RdpEventFilterDeleteReadback",
    "SECRET_COLLECTION_PATH",
    "load_rdp_event_filter_delete_http_transport_config",
]
