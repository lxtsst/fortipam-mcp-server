"""Read and minimize only the latest FortiPAM 7.0 Secret Audit CSV."""

from __future__ import annotations

import http.client
from urllib.parse import urlsplit

from .secret_audit_inventory_http_transport import (
    FortiPamSecretAuditInventoryHttpTransport,
)
from .secret_audit_report_summary import summarize_secret_access_audit_csv
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
    _ssl_context,
)


_MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM Secret Access Audit summary is unavailable."


class SecretAuditSummaryHttpError(RuntimeError):
    """Stable failure without report content, name, or resource values."""


class FortiPamSecretAuditSummaryHttpTransport:
    """Select one existing report privately and return only aggregate counts."""

    def __init__(self, config: SecretMetadataHttpTransportConfig) -> None:
        self._config = config
        self._inventory = FortiPamSecretAuditInventoryHttpTransport(config)

    def summarize_latest(self) -> dict[str, object]:
        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise SecretAuditSummaryHttpError(_UNAVAILABLE)
        connection: http.client.HTTPSConnection | None = None
        response: http.client.HTTPResponse | None = None
        body = bytearray()
        try:
            names = self._inventory.snapshot().names
            if not names:
                raise SecretAuditSummaryHttpError(_UNAVAILABLE)
            connection = http.client.HTTPSConnection(
                parsed.hostname,
                parsed.port or 443,
                timeout=self._config.timeout_seconds,
                context=_ssl_context(self._config),
            )
            connection.request(
                "GET",
                "/audit_files/root/" + max(names),
                headers={
                    "Accept": "text/csv",
                    "Accept-Encoding": "identity",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "User-Agent": "fortipam-mcp-v4-secret-audit-summary/1",
                },
            )
            response = connection.getresponse()
            if (
                response.status != 200
                or response.getheader("content-type", "").split(";", 1)[0]
                .strip()
                .lower()
                != "text/csv"
                or response.getheader("content-encoding", "identity").lower()
                not in {"identity", ""}
            ):
                raise SecretAuditSummaryHttpError(_UNAVAILABLE)
            body.extend(response.read(_MAX_RESPONSE_BYTES + 1))
            if len(body) > _MAX_RESPONSE_BYTES:
                raise SecretAuditSummaryHttpError(_UNAVAILABLE)
            return summarize_secret_access_audit_csv(bytes(body))
        except SecretAuditSummaryHttpError:
            raise
        except Exception as exc:
            raise SecretAuditSummaryHttpError(_UNAVAILABLE) from exc
        finally:
            for index in range(len(body)):
                body[index] = 0
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()


__all__ = [
    "FortiPamSecretAuditSummaryHttpTransport",
    "SecretAuditSummaryHttpError",
]
