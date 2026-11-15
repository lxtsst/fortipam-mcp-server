"""Fixed REST/SSH recovery transport for the accepted b34 PDF DLP Sensor.

The transport compiles one Sensor detail/delete route plus bounded Secret and
Policy dependency reads. It pins the complete API record by digest,
independently verifies the fixed PDF Sensor over SSH, and proves that the
accepted File Pattern remains intact after deletion. Raw records, names, and
protected content never cross the MCP boundary.
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

from .dlp_sensor_ssh_transport import (
    DlpSensorInspection,
    DlpSensorReadback,
    FortiPamDlpSensorSshTransport,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_API_"
COLLECTION_PATH = "/api/v2/cmdb/dlp/sensor"
SECRET_COLLECTION_PATH = "/api/v2/cmdb/secret/database"
POLICY_COLLECTION_PATH = "/api/v2/cmdb/secret/policy"
DLP_SENSOR_DELETE_NAME = "mcp-v4-dlp-sensor-b34"
DLP_SENSOR_PATTERN_ID = 1000
DLP_SENSOR_PATTERN_NAME = "mcp-v4-dlp-pattern-b32"
DLP_SENSOR_ACCEPTED_DIGEST = (
    "aaf3e417cca503153a82e456db8a1b39ca9f3114822b262c528d230293a3ee00"
)
DEPENDENCY_PAGE_SIZE = 100
MAX_DEPENDENCY_PAGES = 100
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 DLP Sensor recovery is unavailable."


class DlpSensorDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the dedicated DLP Sensor API route is unsafe."""


class DlpSensorDeleteHttpTransportError(RuntimeError):
    """Stable, non-disclosing fixed recovery failure."""


@dataclass(frozen=True, slots=True)
class DlpSensorDeleteHttpTransportConfig:
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
            raise DlpSensorDeleteHttpTransportConfigurationError(
                "A dedicated HTTPS DLP Sensor API target is required."
            )
        if (
            not self.bearer_token
            or len(self.bearer_token) > 4096
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.bearer_token
            )
        ):
            raise DlpSensorDeleteHttpTransportConfigurationError(
                "The DLP Sensor API bearer token is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise DlpSensorDeleteHttpTransportConfigurationError(
                "The DLP Sensor API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise DlpSensorDeleteHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class DlpSensorDeleteInspection:
    """Categorical eligibility for the exact accepted b34 PDF Sensor."""

    exists: bool
    eligible_fixed_sensor: bool
    secret_reference_count: int
    policy_reference_count: int
    target_digest: str


@dataclass(frozen=True, slots=True)
class DlpSensorDeleteReadback:
    """Dual Sensor absence plus preserved File Pattern after DELETE."""

    api_absent: bool
    ssh_absent: bool
    file_pattern_preserved: bool

    @property
    def verified(self) -> bool:
        return self.api_absent and self.ssh_absent and self.file_pattern_preserved


def load_dlp_sensor_delete_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> DlpSensorDeleteHttpTransportConfig:
    """Load the independently scoped fixed recovery API configuration."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise DlpSensorDeleteHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token is None:
        raise DlpSensorDeleteHttpTransportConfigurationError(
            "Dedicated DLP Sensor API target and bearer token are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise DlpSensorDeleteHttpTransportConfigurationError(
            "The DLP Sensor API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return DlpSensorDeleteHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamDlpSensorDeleteHttpTransport:
    """Inspect and delete only the unchanged, unreferenced b34 PDF Sensor."""

    def __init__(
        self,
        config: DlpSensorDeleteHttpTransportConfig,
        ssh_transport: FortiPamDlpSensorSshTransport,
        *,
        client_factory: Callable[..., Any] | None = None,
        accepted_digest: str = DLP_SENSOR_ACCEPTED_DIGEST,
    ) -> None:
        if not _digest(accepted_digest):
            raise DlpSensorDeleteHttpTransportConfigurationError(
                "The accepted DLP Sensor digest is invalid."
            )
        self._config = config
        self._ssh_transport = ssh_transport
        self._client_factory = client_factory
        self._accepted_digest = accepted_digest

    def inspect_delete_target(self) -> DlpSensorDeleteInspection:
        """Prove the accepted record, fixed CLI projection, and no references."""

        status, payload = self._request("GET", self._detail_path(), None)
        if status == 404:
            return DlpSensorDeleteInspection(False, False, 0, 0, "0" * 64)
        record = _record(payload)
        if status != 200 or record is None:
            raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _profile_digest(record)
        if (
            not hmac.compare_digest(target_digest, self._accepted_digest)
            or not _fixed_api_projection(record)
        ):
            raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE)
        ssh_readback = self._ssh_transport.readback(
            DLP_SENSOR_DELETE_NAME,
            DLP_SENSOR_PATTERN_ID,
        )
        if not isinstance(ssh_readback, DlpSensorReadback) or not ssh_readback.verified:
            raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE)
        secret_references = self._dependency_reference_count(SECRET_COLLECTION_PATH)
        policy_references = self._dependency_reference_count(POLICY_COLLECTION_PATH)
        return DlpSensorDeleteInspection(
            exists=True,
            eligible_fixed_sensor=secret_references == 0 and policy_references == 0,
            secret_reference_count=secret_references,
            policy_reference_count=policy_references,
            target_digest=target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> DlpSensorDeleteReadback:
        """Delete exactly once and prove Sensor absence plus Pattern preservation."""

        if not _digest(expected_target_digest):
            raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_sensor
            or inspection.secret_reference_count != 0
            or inspection.policy_reference_count != 0
            or not hmac.compare_digest(inspection.target_digest, expected_target_digest)
            or not hmac.compare_digest(inspection.target_digest, self._accepted_digest)
        ):
            raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE)
        status, payload = self._request("DELETE", self._detail_path(), None)
        if status != 200 or not _successful_response(payload):
            raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE)
        readback_status, _ = self._request("GET", self._detail_path(), None)
        ssh_inspection = self._ssh_transport.inspect(
            DLP_SENSOR_DELETE_NAME,
            DLP_SENSOR_PATTERN_ID,
            DLP_SENSOR_PATTERN_NAME,
        )
        if not isinstance(ssh_inspection, DlpSensorInspection):
            raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE)
        pattern_preserved = (
            ssh_inspection.file_pattern_id_exists
            and ssh_inspection.file_pattern_name_exists
            and ssh_inspection.file_pattern_binding_matches
        )
        return DlpSensorDeleteReadback(
            api_absent=readback_status == 404,
            ssh_absent=not ssh_inspection.sensor_name_exists,
            file_pattern_preserved=pattern_preserved,
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
                raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE)
            reference_count += sum(
                _count_exact_reference(record, DLP_SENSOR_DELETE_NAME)
                for record in records
            )
            if len(records) < DEPENDENCY_PAGE_SIZE:
                return reference_count
        raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE)

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
            raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path() -> str:
        return f"{COLLECTION_PATH}/{quote(DLP_SENSOR_DELETE_NAME, safe='')}"


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
    filters = record.get("filter")
    item = filters[0] if isinstance(filters, list) and len(filters) == 1 else None
    return (
        record.get("name") == DLP_SENSOR_DELETE_NAME
        and record.get("q_origin_key") == DLP_SENSOR_DELETE_NAME
        and isinstance(item, Mapping)
        and item.get("id") == 1
        and item.get("name") == "mcp-v4-dlp-filter-pdf-block"
        and item.get("proto") == "http-get"
        and item.get("filter-by") == "file-type"
        and item.get("file-type") == DLP_SENSOR_PATTERN_ID
        and item.get("action") == "block"
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


def _ssl_context(config: DlpSensorDeleteHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover
        raise DlpSensorDeleteHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "COLLECTION_PATH",
    "DLP_SENSOR_ACCEPTED_DIGEST",
    "DLP_SENSOR_DELETE_NAME",
    "DLP_SENSOR_PATTERN_ID",
    "DLP_SENSOR_PATTERN_NAME",
    "DlpSensorDeleteHttpTransportConfig",
    "DlpSensorDeleteHttpTransportConfigurationError",
    "DlpSensorDeleteHttpTransportError",
    "DlpSensorDeleteInspection",
    "DlpSensorDeleteReadback",
    "ENV_PREFIX",
    "FortiPamDlpSensorDeleteHttpTransport",
    "POLICY_COLLECTION_PATH",
    "SECRET_COLLECTION_PATH",
    "load_dlp_sensor_delete_http_transport_config",
]
