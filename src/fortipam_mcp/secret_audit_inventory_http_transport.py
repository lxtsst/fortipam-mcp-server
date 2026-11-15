"""Private, read-only FortiPAM 7.0 Secret Audit report inventory reader.

The inventory contains report names and timestamps. They stay inside the
transport and are used only to compare an exact before/after generation state.
No report file is opened or downloaded.
"""

from __future__ import annotations

from dataclasses import dataclass
import http.client
import json
import re
from urllib.parse import urlsplit

from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
    _ssl_context,
)


REPORT_LIST_PATH = "/api/v2/monitor/audit/local-report-list?vdom=root"
_MAX_RESPONSE_BYTES = 1_048_576
_MAX_REPORTS = 1000
_REPORT_NAME = re.compile(r"SecretAccessAuditReport-\d{4}-\d{2}-\d{2}-\d{6}\.csv\Z")
_UNAVAILABLE = "FortiPAM V4 Secret Audit report inventory is unavailable."


class SecretAuditInventoryError(RuntimeError):
    """Stable failure without raw API response or report metadata."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretAuditInventorySnapshot:
    """Private names for one bounded before/after comparison."""

    names: frozenset[str]

    def __repr__(self) -> str:
        return "<SecretAuditInventorySnapshot redacted>"


class FortiPamSecretAuditInventoryHttpTransport:
    """Read only the fixed 7.0 Secret Audit list through an existing API actor."""

    def __init__(self, config: SecretMetadataHttpTransportConfig) -> None:
        self._config = config

    def snapshot(self) -> SecretAuditInventorySnapshot:
        parsed = urlsplit(self._config.base_url)
        if parsed.hostname is None:
            raise SecretAuditInventoryError(_UNAVAILABLE)
        connection: http.client.HTTPSConnection | None = None
        response: http.client.HTTPResponse | None = None
        body = bytearray()
        try:
            connection = http.client.HTTPSConnection(
                parsed.hostname,
                parsed.port or 443,
                timeout=self._config.timeout_seconds,
                context=_ssl_context(self._config),
            )
            connection.request(
                "GET",
                REPORT_LIST_PATH,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Authorization": f"Bearer {self._config.bearer_token}",
                    "Connection": "close",
                    "User-Agent": "fortipam-mcp-v4-secret-audit-inventory/1",
                },
            )
            response = connection.getresponse()
            if (
                response.status != 200
                or response.getheader("content-type", "").split(";", 1)[0].strip().lower()
                != "application/json"
                or response.getheader("content-encoding", "identity").lower()
                not in {"identity", ""}
            ):
                raise SecretAuditInventoryError(_UNAVAILABLE)
            body.extend(response.read(_MAX_RESPONSE_BYTES + 1))
            if len(body) > _MAX_RESPONSE_BYTES:
                raise SecretAuditInventoryError(_UNAVAILABLE)
            payload = json.loads(body)
            if (
                not isinstance(payload, dict)
                or payload.get("build") != 29
                or payload.get("version") not in {"v7.0.0", "7.0.0"}
                or payload.get("http_method") != "GET"
            ):
                raise SecretAuditInventoryError(_UNAVAILABLE)
            records = payload.get("results")
            if not isinstance(records, list) or len(records) > _MAX_REPORTS:
                raise SecretAuditInventoryError(_UNAVAILABLE)
            names: set[str] = set()
            for record in records:
                if not isinstance(record, dict):
                    raise SecretAuditInventoryError(_UNAVAILABLE)
                name = record.get("name")
                if (
                    not isinstance(name, str)
                    or _REPORT_NAME.fullmatch(name) is None
                    or not isinstance(record.get("time"), str)
                    or not isinstance(record.get("filesize"), str)
                    or name in names
                ):
                    raise SecretAuditInventoryError(_UNAVAILABLE)
                names.add(name)
            return SecretAuditInventorySnapshot(frozenset(names))
        except SecretAuditInventoryError:
            raise
        except Exception as exc:
            raise SecretAuditInventoryError(_UNAVAILABLE) from exc
        finally:
            for index in range(len(body)):
                body[index] = 0
            if response is not None:
                response.close()
            if connection is not None:
                connection.close()


__all__ = [
    "FortiPamSecretAuditInventoryHttpTransport",
    "REPORT_LIST_PATH",
    "SecretAuditInventoryError",
    "SecretAuditInventorySnapshot",
]
