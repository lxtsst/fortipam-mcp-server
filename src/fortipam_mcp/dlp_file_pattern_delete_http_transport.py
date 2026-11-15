"""Fixed REST/SSH recovery transport for the accepted b32 DLP File Pattern.

The transport compiles one integer-ID detail/delete route plus complete DLP
Sensor dependency reads. It pins the complete API record by digest,
independently verifies the exact PDF Pattern over SSH, and proves that the
accepted Regexp Sensor is preserved. Raw records, names, and protected content
never cross the MCP boundary.
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
from urllib.parse import urlsplit

from .dlp_file_pattern_ssh_transport import (
    DlpFilePatternReadback,
    FortiPamDlpFilePatternSshTransport,
)
from .dlp_sensor_ssh_transport import (
    DlpRegexpSensorReadback,
    FortiPamDlpSensorSshTransport,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_API_"
COLLECTION_PATH = "/api/v2/cmdb/dlp/filepattern"
SENSOR_COLLECTION_PATH = "/api/v2/cmdb/dlp/sensor"
DLP_FILE_PATTERN_DELETE_ID = 1000
DLP_FILE_PATTERN_DELETE_NAME = "mcp-v4-dlp-pattern-b32"
DLP_FILE_PATTERN_ACCEPTED_DIGEST = (
    "37c33b0e9831b92dadfbd9752dea119ed4f6a9e87ee78c8bc55910c450c46c97"
)
DLP_REGEXP_SENSOR_NAME = "mcp-v4-dlp-regexp-sensor-b34"
DEPENDENCY_PAGE_SIZE = 100
MAX_DEPENDENCY_PAGES = 100
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 DLP File Pattern recovery is unavailable."


class DlpFilePatternDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the dedicated DLP File Pattern API route is unsafe."""


class DlpFilePatternDeleteHttpTransportError(RuntimeError):
    """Stable, non-disclosing fixed recovery failure."""


@dataclass(frozen=True, slots=True)
class DlpFilePatternDeleteHttpTransportConfig:
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
            raise DlpFilePatternDeleteHttpTransportConfigurationError(
                "A dedicated HTTPS DLP File Pattern API target is required."
            )
        if (
            not self.bearer_token
            or len(self.bearer_token) > 4096
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.bearer_token
            )
        ):
            raise DlpFilePatternDeleteHttpTransportConfigurationError(
                "The DLP File Pattern API bearer token is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise DlpFilePatternDeleteHttpTransportConfigurationError(
                "The DLP File Pattern API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise DlpFilePatternDeleteHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class DlpFilePatternDeleteInspection:
    """Categorical eligibility for the exact accepted b32 File Pattern."""

    exists: bool
    eligible_fixed_pattern: bool
    sensor_reference_count_rest: int
    sensor_reference_count_ssh: int
    target_digest: str
    regexp_sensor_digest: str


@dataclass(frozen=True, slots=True)
class DlpFilePatternDeleteReadback:
    """Dual Pattern absence plus preserved fixed Regexp Sensor after DELETE."""

    api_absent: bool
    ssh_absent: bool
    regexp_sensor_preserved_api: bool
    regexp_sensor_preserved_ssh: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.api_absent,
                self.ssh_absent,
                self.regexp_sensor_preserved_api,
                self.regexp_sensor_preserved_ssh,
            )
        )


def load_dlp_file_pattern_delete_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> DlpFilePatternDeleteHttpTransportConfig:
    """Load the independently scoped fixed recovery API configuration."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise DlpFilePatternDeleteHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token is None:
        raise DlpFilePatternDeleteHttpTransportConfigurationError(
            "Dedicated DLP File Pattern API target and bearer token are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise DlpFilePatternDeleteHttpTransportConfigurationError(
            "The DLP File Pattern API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return DlpFilePatternDeleteHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamDlpFilePatternDeleteHttpTransport:
    """Inspect and delete only the unchanged, unreferenced b32 File Pattern."""

    def __init__(
        self,
        config: DlpFilePatternDeleteHttpTransportConfig,
        pattern_ssh_transport: FortiPamDlpFilePatternSshTransport,
        sensor_ssh_transport: FortiPamDlpSensorSshTransport,
        *,
        client_factory: Callable[..., Any] | None = None,
        accepted_digest: str = DLP_FILE_PATTERN_ACCEPTED_DIGEST,
    ) -> None:
        if not _digest(accepted_digest):
            raise DlpFilePatternDeleteHttpTransportConfigurationError(
                "The accepted DLP File Pattern digest is invalid."
            )
        self._config = config
        self._pattern_ssh_transport = pattern_ssh_transport
        self._sensor_ssh_transport = sensor_ssh_transport
        self._client_factory = client_factory
        self._accepted_digest = accepted_digest

    def inspect_delete_target(self) -> DlpFilePatternDeleteInspection:
        """Prove the accepted record, exact SSH projection, and no references."""

        status, payload = self._request("GET", self._detail_path(), None)
        if status == 404:
            return DlpFilePatternDeleteInspection(
                False,
                False,
                0,
                0,
                "0" * 64,
                "0" * 64,
            )
        record = _record(payload)
        if status != 200 or record is None:
            raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _record_digest(record)
        if (
            not hmac.compare_digest(target_digest, self._accepted_digest)
            or not _fixed_pattern_api_projection(record)
        ):
            raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE)
        pattern_readback = self._pattern_ssh_transport.readback(
            DLP_FILE_PATTERN_DELETE_ID,
            DLP_FILE_PATTERN_DELETE_NAME,
        )
        if (
            not isinstance(pattern_readback, DlpFilePatternReadback)
            or not pattern_readback.verified
        ):
            raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE)

        rest_references = self._sensor_reference_count()
        ssh_references = self._sensor_ssh_transport.file_pattern_reference_count(
            DLP_FILE_PATTERN_DELETE_ID
        )
        if type(ssh_references) is not int or ssh_references < 0:
            raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE)

        regexp_status, regexp_payload = self._request(
            "GET",
            self._regexp_sensor_detail_path(),
            None,
        )
        regexp_record = _record(regexp_payload)
        regexp_readback = self._sensor_ssh_transport.readback_regexp_sensor(
            DLP_REGEXP_SENSOR_NAME
        )
        if (
            regexp_status != 200
            or regexp_record is None
            or not _fixed_regexp_sensor_api_projection(regexp_record)
            or not isinstance(regexp_readback, DlpRegexpSensorReadback)
            or not regexp_readback.verified
        ):
            raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE)
        return DlpFilePatternDeleteInspection(
            exists=True,
            eligible_fixed_pattern=rest_references == 0 and ssh_references == 0,
            sensor_reference_count_rest=rest_references,
            sensor_reference_count_ssh=ssh_references,
            target_digest=target_digest,
            regexp_sensor_digest=_record_digest(regexp_record),
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
        expected_regexp_sensor_digest: str,
    ) -> DlpFilePatternDeleteReadback:
        """Delete exactly once and prove Pattern absence plus Sensor preservation."""

        if not _digest(expected_target_digest) or not _digest(
            expected_regexp_sensor_digest
        ):
            raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_pattern
            or inspection.sensor_reference_count_rest != 0
            or inspection.sensor_reference_count_ssh != 0
            or not hmac.compare_digest(inspection.target_digest, expected_target_digest)
            or not hmac.compare_digest(inspection.target_digest, self._accepted_digest)
            or not hmac.compare_digest(
                inspection.regexp_sensor_digest,
                expected_regexp_sensor_digest,
            )
        ):
            raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE)

        status, payload = self._request("DELETE", self._detail_path(), None)
        if status != 200 or not _successful_response(payload):
            raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE)

        readback_status, _ = self._request("GET", self._detail_path(), None)
        pattern_inspection = self._pattern_ssh_transport.inspect(
            DLP_FILE_PATTERN_DELETE_ID,
            DLP_FILE_PATTERN_DELETE_NAME,
        )
        regexp_status, regexp_payload = self._request(
            "GET",
            self._regexp_sensor_detail_path(),
            None,
        )
        regexp_record = _record(regexp_payload)
        regexp_readback = self._sensor_ssh_transport.readback_regexp_sensor(
            DLP_REGEXP_SENSOR_NAME
        )
        regexp_api_preserved = (
            regexp_status == 200
            and regexp_record is not None
            and _fixed_regexp_sensor_api_projection(regexp_record)
            and hmac.compare_digest(
                _record_digest(regexp_record),
                expected_regexp_sensor_digest,
            )
        )
        return DlpFilePatternDeleteReadback(
            api_absent=readback_status == 404,
            ssh_absent=(
                not pattern_inspection.pattern_id_exists
                and not pattern_inspection.pattern_name_exists
            ),
            regexp_sensor_preserved_api=regexp_api_preserved,
            regexp_sensor_preserved_ssh=(
                isinstance(regexp_readback, DlpRegexpSensorReadback)
                and regexp_readback.verified
            ),
        )

    def _sensor_reference_count(self) -> int:
        reference_count = 0
        for page in range(MAX_DEPENDENCY_PAGES):
            status, payload = self._request(
                "GET",
                SENSOR_COLLECTION_PATH,
                None,
                query=(
                    f"start={page * DEPENDENCY_PAGE_SIZE}&count={DEPENDENCY_PAGE_SIZE}"
                ),
            )
            records = _records(payload)
            if status != 200 or records is None:
                raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE)
            reference_count += sum(
                _count_pattern_references(record) for record in records
            )
            if len(records) < DEPENDENCY_PAGE_SIZE:
                return reference_count
        raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE)

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
            raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path() -> str:
        return f"{COLLECTION_PATH}/{DLP_FILE_PATTERN_DELETE_ID}"

    @staticmethod
    def _regexp_sensor_detail_path() -> str:
        return f"{SENSOR_COLLECTION_PATH}/{DLP_REGEXP_SENSOR_NAME}"


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


def _fixed_pattern_api_projection(record: Mapping[str, object]) -> bool:
    entries = record.get("entries")
    entry = entries[0] if isinstance(entries, list) and len(entries) == 1 else None
    return (
        record.get("id") == DLP_FILE_PATTERN_DELETE_ID
        and record.get("q_origin_key") == DLP_FILE_PATTERN_DELETE_ID
        and record.get("name") == DLP_FILE_PATTERN_DELETE_NAME
        and isinstance(entry, Mapping)
        and entry.get("filter-type") == "type"
        and entry.get("file-type") == "pdf"
    )


def _fixed_regexp_sensor_api_projection(record: Mapping[str, object]) -> bool:
    filters = record.get("filter")
    item = filters[0] if isinstance(filters, list) and len(filters) == 1 else None
    return (
        record.get("name") == DLP_REGEXP_SENSOR_NAME
        and record.get("q_origin_key") == DLP_REGEXP_SENSOR_NAME
        and isinstance(item, Mapping)
        and item.get("id") == 1
        and item.get("name") == "mcp-v4-dlp-filter-regexp-block"
        and item.get("type") == "file"
        and item.get("proto") == "http-get"
        and item.get("filter-by") == "regexp"
        and isinstance(item.get("regexp"), str)
        and bool(item.get("regexp"))
        and item.get("action") == "block"
    )


def _count_pattern_references(record: Mapping[str, object]) -> int:
    filters = record.get("filter")
    if not isinstance(filters, list):
        return 0
    return sum(
        1
        for item in filters
        if isinstance(item, Mapping)
        and item.get("filter-by") == "file-type"
        and item.get("file-type") == DLP_FILE_PATTERN_DELETE_ID
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


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _ssl_context(config: DlpFilePatternDeleteHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover
        raise DlpFilePatternDeleteHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "COLLECTION_PATH",
    "DLP_FILE_PATTERN_ACCEPTED_DIGEST",
    "DLP_FILE_PATTERN_DELETE_ID",
    "DLP_FILE_PATTERN_DELETE_NAME",
    "DLP_REGEXP_SENSOR_NAME",
    "DlpFilePatternDeleteHttpTransportConfig",
    "DlpFilePatternDeleteHttpTransportConfigurationError",
    "DlpFilePatternDeleteHttpTransportError",
    "DlpFilePatternDeleteInspection",
    "DlpFilePatternDeleteReadback",
    "ENV_PREFIX",
    "FortiPamDlpFilePatternDeleteHttpTransport",
    "SENSOR_COLLECTION_PATH",
    "load_dlp_file_pattern_delete_http_transport_config",
]
