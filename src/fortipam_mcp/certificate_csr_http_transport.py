"""Fixed FortiPAM 1.9.1 HTTP transport for one CSR generation profile.

Only the documented name-availability GET, exact local-certificate detail GET,
and UI API Preview-derived CSR POST are compiled into this adapter.  CSR,
certificate, and private-key values are never returned by the transport.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any, Literal
from urllib.parse import quote, urlencode, urlsplit

from .certificate_csr_contract import (
    CSR_KEY_SIZE,
    CSR_KEY_TYPE,
    CSR_SCOPE,
    CertificateCsrInspection,
    CertificateCsrReadback,
)


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_CERTIFICATE_CSR_API_"
_AVAILABILITY_PATH = "/api/v2/monitor/vpn-certificate/cert-name-available"
_CREATE_PATH = "/api/v2/monitor/vpn-certificate/csr/generate"
_DETAIL_ROOT = "/api/v2/cmdb/vpn.certificate/local"
_AVAILABLE_CERTIFICATES_PATH = "/api/v2/monitor/system/available-certificates"
_MAX_RESPONSE_BYTES = 1_048_576
_NAME = re.compile(r"mcp-v4-cert-[A-Za-z0-9][A-Za-z0-9._-]{0,50}\Z")
_DENIED_MESSAGE = "FortiPAM V4 certificate CSR transport is unavailable."


class CertificateCsrHttpTransportConfigurationError(ValueError):
    """Raised when the dedicated CSR transport is incomplete or unsafe."""


class CertificateCsrHttpTransportError(RuntimeError):
    """Stable, non-disclosing CSR transport failure."""


@dataclass(frozen=True, slots=True)
class CertificateCsrHttpTransportConfig:
    """Dedicated HTTPS API settings held only in process memory."""

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
            raise CertificateCsrHttpTransportConfigurationError(
                "A dedicated HTTPS FortiPAM API target is required."
            )
        if not self.bearer_token or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.bearer_token
        ):
            raise CertificateCsrHttpTransportConfigurationError(
                "A dedicated bearer token is required."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise CertificateCsrHttpTransportConfigurationError(
                "The certificate CSR API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise CertificateCsrHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


def load_certificate_csr_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> CertificateCsrHttpTransportConfig:
    """Load the independent, exact CSR transport configuration."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise CertificateCsrHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token = _value(env, "API_TOKEN")
    ca_file = _value(env, "CA_FILE")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    if base_url is None or token is None:
        raise CertificateCsrHttpTransportConfigurationError(
            "Dedicated FortiPAM API target and bearer token are required."
        )
    try:
        timeout_seconds = float(timeout_raw)
    except ValueError as exc:
        raise CertificateCsrHttpTransportConfigurationError(
            "The certificate CSR API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return CertificateCsrHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=token,
        timeout_seconds=timeout_seconds,
        ca_file=ca_file,
    )


class FortiPamCertificateCsrHttpTransport:
    """Issue only the exact CSR preflight, create, and readback requests."""

    def __init__(
        self,
        config: CertificateCsrHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory

    def inspect(self, certificate_name: str) -> CertificateCsrInspection:
        """Verify exact absence and vendor name availability without values."""

        name = _certificate_name(certificate_name)
        detail_status, _ = self._request("GET", self._detail_path(name), None)
        if detail_status not in {200, 404}:
            raise CertificateCsrHttpTransportError(_DENIED_MESSAGE)
        availability_query = urlencode({"mkey": name, "scope": CSR_SCOPE})
        status, payload = self._request(
            "GET",
            f"{_AVAILABILITY_PATH}?{availability_query}",
            None,
        )
        available = _name_available(payload)
        if status != 200 or available is None:
            raise CertificateCsrHttpTransportError(_DENIED_MESSAGE)
        return CertificateCsrInspection(
            exists=detail_status == 200,
            name_available=available,
        )

    def generate_and_readback(
        self,
        certificate_name: str,
        subject_ipv4: str,
    ) -> CertificateCsrReadback:
        """Generate one fixed RSA CSR and reduce detail readback to booleans."""

        name = _certificate_name(certificate_name)
        subject = _ipv4(subject_ipv4)
        body: dict[str, object] = {
            "keytype": CSR_KEY_TYPE,
            "keysize": CSR_KEY_SIZE,
            "orgunits": [],
            "scope": CSR_SCOPE,
            "certname": name,
            "subject": subject,
        }
        status, payload = self._request(
            "POST",
            f"{_CREATE_PATH}?{urlencode({'vdom': 'root'})}",
            body,
        )
        if status != 200 or not _successful_response(payload):
            raise CertificateCsrHttpTransportError(_DENIED_MESSAGE)
        return self.readback(name)

    def readback(self, certificate_name: str) -> CertificateCsrReadback:
        """Reduce one existing CSR state to fixed booleans without material."""

        name = _certificate_name(certificate_name)
        detail_status, detail_payload = self._request(
            "GET",
            self._detail_path(name),
            None,
        )
        detail = _record(detail_payload)
        if detail_status != 200 or detail is None:
            return CertificateCsrReadback(False, False, False, False)
        monitor_status, monitor_payload = self._request(
            "GET",
            _AVAILABLE_CERTIFICATES_PATH,
            None,
        )
        monitor_records = [
            record
            for record in _records(monitor_payload)
            if record.get("name") == name
        ]
        monitor = monitor_records[0] if len(monitor_records) == 1 else None
        fixed_profile = (
            monitor_status == 200
            and monitor is not None
            and monitor.get("type") == "local-csr"
            and monitor.get("status") == "pending"
            and isinstance(monitor.get("key_type"), str)
            and str(monitor.get("key_type")).strip().lower() == CSR_KEY_TYPE
            and monitor.get("range") == CSR_SCOPE
        )
        return CertificateCsrReadback(
            entry_exists=True,
            name_matches=detail.get("name") == name,
            csr_present=fixed_profile,
            private_key_present=(
                fixed_profile and monitor is not None
                and monitor.get("has_valid_cert_key") is True
            ),
        )

    def _request(
        self,
        method: Literal["GET", "POST"],
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
            raise CertificateCsrHttpTransportError(_DENIED_MESSAGE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > _MAX_RESPONSE_BYTES:
            raise CertificateCsrHttpTransportError(_DENIED_MESSAGE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CertificateCsrHttpTransportError(_DENIED_MESSAGE) from exc

    @staticmethod
    def _detail_path(certificate_name: str) -> str:
        return f"{_DETAIL_ROOT}/{quote(certificate_name, safe='')}"


def _ssl_context(config: CertificateCsrHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise CertificateCsrHttpTransportError(_DENIED_MESSAGE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _certificate_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise CertificateCsrHttpTransportError(_DENIED_MESSAGE)
    return value


def _ipv4(value: str) -> str:
    if not isinstance(value, str):
        raise CertificateCsrHttpTransportError(_DENIED_MESSAGE)
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise CertificateCsrHttpTransportError(_DENIED_MESSAGE) from exc


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _records(payload: object) -> list[Mapping[str, object]]:
    if not isinstance(payload, Mapping):
        return []
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return [result]
    if isinstance(result, list):
        return [item for item in result if isinstance(item, Mapping)]
    return []


def _name_available(payload: object) -> bool | None:
    record = _record(payload)
    value = record.get("is_valid") if record is not None else None
    return value if isinstance(value, bool) else None


def _successful_response(payload: object) -> bool:
    if not isinstance(payload, Mapping):
        return False
    reported_status = payload.get("http_status")
    return reported_status in {None, 200}


__all__ = [
    "ENV_PREFIX",
    "CertificateCsrHttpTransportConfig",
    "CertificateCsrHttpTransportConfigurationError",
    "CertificateCsrHttpTransportError",
    "FortiPamCertificateCsrHttpTransport",
    "load_certificate_csr_http_transport_config",
]
