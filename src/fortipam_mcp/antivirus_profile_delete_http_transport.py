"""Fixed REST/SSH recovery transport for the accepted b35 AntiVirus Profile.

Only the exact Profile detail/delete route and the paginated Secret dependency
read are compiled here.  The complete API record is pinned by a private digest,
while the existing bounded SSH adapter independently verifies the documented
HTTP/SSH ``av-scan block`` projection.  No Profile or Secret content is returned
through MCP.
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

from .antivirus_profile_ssh_transport import (
    AntivirusProfileInspection,
    AntivirusProfileReadback,
    FortiPamAntivirusProfileSshTransport,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_ANTIVIRUS_PROFILE_API_"
COLLECTION_PATH = "/api/v2/cmdb/antivirus/profile"
SECRET_COLLECTION_PATH = "/api/v2/cmdb/secret/database"
ANTIVIRUS_PROFILE_DELETE_NAME = "mcp-v4-av-profile-b35"
ANTIVIRUS_PROFILE_ACCEPTED_DIGEST = (
    "68bd0bc2f5c237c4546651efe88535673105d714028f0b3fc7a02979e22f242c"
)
SECRET_PAGE_SIZE = 100
MAX_SECRET_PAGES = 100
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 AntiVirus Profile recovery is unavailable."


class AntivirusProfileDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the dedicated AntiVirus Profile API route is unsafe."""


class AntivirusProfileDeleteHttpTransportError(RuntimeError):
    """Stable, non-disclosing fixed recovery failure."""


@dataclass(frozen=True, slots=True)
class AntivirusProfileDeleteHttpTransportConfig:
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
            raise AntivirusProfileDeleteHttpTransportConfigurationError(
                "A dedicated HTTPS AntiVirus Profile API target is required."
            )
        if (
            not self.bearer_token
            or len(self.bearer_token) > 4096
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in self.bearer_token
            )
        ):
            raise AntivirusProfileDeleteHttpTransportConfigurationError(
                "The AntiVirus Profile API bearer token is invalid."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise AntivirusProfileDeleteHttpTransportConfigurationError(
                "The AntiVirus Profile API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise AntivirusProfileDeleteHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


@dataclass(frozen=True, slots=True)
class AntivirusProfileDeleteInspection:
    """Categorical eligibility for the exact accepted b35 recovery target."""

    exists: bool
    eligible_fixed_profile: bool
    secret_reference_count: int
    target_digest: str


@dataclass(frozen=True, slots=True)
class AntivirusProfileDeleteReadback:
    """Dual categorical absence after the fixed DELETE."""

    api_absent: bool
    ssh_absent: bool

    @property
    def verified(self) -> bool:
        return self.api_absent and self.ssh_absent


def load_antivirus_profile_delete_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> AntivirusProfileDeleteHttpTransportConfig:
    """Load the independently scoped fixed recovery API configuration."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise AntivirusProfileDeleteHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token is None:
        raise AntivirusProfileDeleteHttpTransportConfigurationError(
            "Dedicated AntiVirus Profile API target and bearer token are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise AntivirusProfileDeleteHttpTransportConfigurationError(
            "The AntiVirus Profile API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return AntivirusProfileDeleteHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamAntivirusProfileDeleteHttpTransport:
    """Inspect and delete only the unchanged, unreferenced b35 Profile."""

    def __init__(
        self,
        config: AntivirusProfileDeleteHttpTransportConfig,
        ssh_transport: FortiPamAntivirusProfileSshTransport,
        *,
        client_factory: Callable[..., Any] | None = None,
        accepted_digest: str = ANTIVIRUS_PROFILE_ACCEPTED_DIGEST,
    ) -> None:
        if not _digest(accepted_digest):
            raise AntivirusProfileDeleteHttpTransportConfigurationError(
                "The accepted AntiVirus Profile digest is invalid."
            )
        self._config = config
        self._ssh_transport = ssh_transport
        self._client_factory = client_factory
        self._accepted_digest = accepted_digest

    def inspect_delete_target(self) -> AntivirusProfileDeleteInspection:
        """Prove the accepted full record, fixed CLI projection, and no refs."""

        status, payload = self._request("GET", self._detail_path(), None)
        if status == 404:
            return AntivirusProfileDeleteInspection(False, False, 0, "0" * 64)
        record = _record(payload)
        if status != 200 or record is None:
            raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _profile_digest(record)
        if (
            not hmac.compare_digest(target_digest, self._accepted_digest)
            or not _fixed_api_projection(record)
        ):
            raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE)
        ssh_readback = self._ssh_transport.readback(ANTIVIRUS_PROFILE_DELETE_NAME)
        if not isinstance(ssh_readback, AntivirusProfileReadback) or not ssh_readback.verified:
            raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE)
        reference_count = self._secret_reference_count()
        return AntivirusProfileDeleteInspection(
            exists=True,
            eligible_fixed_profile=reference_count == 0,
            secret_reference_count=reference_count,
            target_digest=target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> AntivirusProfileDeleteReadback:
        """Delete exactly once and prove absence over both API and SSH."""

        if not _digest(expected_target_digest):
            raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_profile
            or inspection.secret_reference_count != 0
            or not hmac.compare_digest(
                inspection.target_digest,
                expected_target_digest,
            )
            or not hmac.compare_digest(
                inspection.target_digest,
                self._accepted_digest,
            )
        ):
            raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE)
        status, payload = self._request("DELETE", self._detail_path(), None)
        if status != 200 or not _successful_response(payload):
            raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE)
        readback_status, _ = self._request("GET", self._detail_path(), None)
        ssh_inspection = self._ssh_transport.inspect(ANTIVIRUS_PROFILE_DELETE_NAME)
        if not isinstance(ssh_inspection, AntivirusProfileInspection):
            raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE)
        return AntivirusProfileDeleteReadback(
            api_absent=readback_status == 404,
            ssh_absent=not ssh_inspection.profile_name_exists,
        )

    def _secret_reference_count(self) -> int:
        reference_count = 0
        for page in range(MAX_SECRET_PAGES):
            status, payload = self._request(
                "GET",
                SECRET_COLLECTION_PATH,
                None,
                query=f"start={page * SECRET_PAGE_SIZE}&count={SECRET_PAGE_SIZE}",
            )
            records = _records(payload)
            if status != 200 or records is None:
                raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE)
            reference_count += sum(
                _count_exact_reference(record, ANTIVIRUS_PROFILE_DELETE_NAME)
                for record in records
            )
            if len(records) < SECRET_PAGE_SIZE:
                return reference_count
        raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE)

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
            raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path() -> str:
        return f"{COLLECTION_PATH}/{quote(ANTIVIRUS_PROFILE_DELETE_NAME, safe='')}"


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
    http = record.get("http")
    ssh = record.get("ssh")
    return (
        record.get("name") == ANTIVIRUS_PROFILE_DELETE_NAME
        and record.get("q_origin_key") == ANTIVIRUS_PROFILE_DELETE_NAME
        and isinstance(http, Mapping)
        and http.get("av-scan") == "block"
        and isinstance(ssh, Mapping)
        and ssh.get("av-scan") == "block"
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


def _ssl_context(config: AntivirusProfileDeleteHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover
        raise AntivirusProfileDeleteHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "ANTIVIRUS_PROFILE_ACCEPTED_DIGEST",
    "ANTIVIRUS_PROFILE_DELETE_NAME",
    "AntivirusProfileDeleteHttpTransportConfig",
    "AntivirusProfileDeleteHttpTransportConfigurationError",
    "AntivirusProfileDeleteHttpTransportError",
    "AntivirusProfileDeleteInspection",
    "AntivirusProfileDeleteReadback",
    "COLLECTION_PATH",
    "ENV_PREFIX",
    "FortiPamAntivirusProfileDeleteHttpTransport",
    "SECRET_COLLECTION_PATH",
    "load_antivirus_profile_delete_http_transport_config",
]
