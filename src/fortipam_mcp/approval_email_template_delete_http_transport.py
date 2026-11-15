"""Fixed REST/SSH recovery for the accepted b37/b39 Approval Email Template."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import ssl
from typing import Any, Literal
from urllib.parse import quote

from .address_http_transport import AddressHttpTransportConfig
from .approval_email_template_ssh_transport import (
    APPROVAL_EMAIL_TEMPLATE_UPDATED_CONTENT,
    APPROVAL_EMAIL_TEMPLATE_UPDATED_SUBJECT,
    ApprovalEmailTemplateInspection,
    ApprovalEmailTemplateUpdateReadback,
    FortiPamApprovalEmailTemplateSshTransport,
)


COLLECTION_PATH = "/api/v2/cmdb/secret/approval-email-template"
TEMPLATE_DELETE_NAME = "mcp-v4-approval-email-template-b37"
TEMPLATE_ACCEPTED_DIGEST = (
    "a89601815bedebee41a34ef25342bb44898f9c3b06847cd2da431e77a160e387"
)
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 Approval Email Template recovery is unavailable."


class ApprovalEmailTemplateDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the fixed Template recovery configuration is unsafe."""


class ApprovalEmailTemplateDeleteHttpTransportError(RuntimeError):
    """Stable, non-disclosing fixed Template recovery failure."""


@dataclass(frozen=True, slots=True)
class ApprovalEmailTemplateDeleteInspection:
    """Categorical eligibility for only the accepted b37/b39 Template."""

    exists: bool
    eligible_fixed_template: bool
    template_reference_count: int
    target_digest: str


@dataclass(frozen=True, slots=True)
class ApprovalEmailTemplateDeleteReadback:
    """REST and SSH absence after the exact fixed Template DELETE."""

    api_absent: bool
    ssh_absent: bool

    @property
    def verified(self) -> bool:
        return self.api_absent and self.ssh_absent


class FortiPamApprovalEmailTemplateDeleteHttpTransport:
    """Inspect and delete only the unchanged, unreferenced b37/b39 Template."""

    def __init__(
        self,
        config: AddressHttpTransportConfig,
        ssh_transport: FortiPamApprovalEmailTemplateSshTransport,
        *,
        client_factory: Callable[..., Any] | None = None,
        accepted_digest: str = TEMPLATE_ACCEPTED_DIGEST,
    ) -> None:
        if not _digest(accepted_digest):
            raise ApprovalEmailTemplateDeleteHttpTransportConfigurationError(
                "The accepted Approval Email Template digest is invalid."
            )
        self._config = config
        self._ssh_transport = ssh_transport
        self._client_factory = client_factory
        self._accepted_digest = accepted_digest

    def inspect_delete_target(self) -> ApprovalEmailTemplateDeleteInspection:
        """Prove complete fixed record, updated projection, and zero references."""

        status, payload = self._request("GET", self._detail_path())
        if status == 404:
            return ApprovalEmailTemplateDeleteInspection(
                exists=False,
                eligible_fixed_template=False,
                template_reference_count=0,
                target_digest="0" * 64,
            )
        record = _record(payload)
        if status != 200 or record is None:
            raise ApprovalEmailTemplateDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _record_digest(record)
        if (
            not hmac.compare_digest(target_digest, self._accepted_digest)
            or not _fixed_template_projection(record)
        ):
            raise ApprovalEmailTemplateDeleteHttpTransportError(_UNAVAILABLE)
        ssh_readback = self._ssh_transport.readback_updated(TEMPLATE_DELETE_NAME)
        reference_count = self._ssh_transport.reference_count(TEMPLATE_DELETE_NAME)
        if (
            not isinstance(ssh_readback, ApprovalEmailTemplateUpdateReadback)
            or not ssh_readback.verified
        ):
            raise ApprovalEmailTemplateDeleteHttpTransportError(_UNAVAILABLE)
        return ApprovalEmailTemplateDeleteInspection(
            exists=True,
            eligible_fixed_template=reference_count == 0,
            template_reference_count=reference_count,
            target_digest=target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> ApprovalEmailTemplateDeleteReadback:
        """Delete exactly once and prove fixed Template absence."""

        if not _digest(expected_target_digest):
            raise ApprovalEmailTemplateDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_template
            or inspection.template_reference_count != 0
            or not hmac.compare_digest(
                inspection.target_digest,
                expected_target_digest,
            )
            or not hmac.compare_digest(
                inspection.target_digest,
                self._accepted_digest,
            )
        ):
            raise ApprovalEmailTemplateDeleteHttpTransportError(_UNAVAILABLE)

        status, payload = self._request("DELETE", self._detail_path())
        if status != 200 or not _successful_response(payload):
            raise ApprovalEmailTemplateDeleteHttpTransportError(_UNAVAILABLE)

        readback_status, _ = self._request("GET", self._detail_path())
        ssh_inspection = self._ssh_transport.inspect(TEMPLATE_DELETE_NAME)
        if not isinstance(ssh_inspection, ApprovalEmailTemplateInspection):
            raise ApprovalEmailTemplateDeleteHttpTransportError(_UNAVAILABLE)
        return ApprovalEmailTemplateDeleteReadback(
            api_absent=readback_status == 404,
            ssh_absent=not ssh_inspection.template_name_exists,
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
            raise ApprovalEmailTemplateDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise ApprovalEmailTemplateDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApprovalEmailTemplateDeleteHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path() -> str:
        return f"{COLLECTION_PATH}/{quote(TEMPLATE_DELETE_NAME, safe='')}"


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _fixed_template_projection(record: Mapping[str, object]) -> bool:
    return (
        set(record) == {"content", "name", "q_origin_key", "subject"}
        and record.get("name") == TEMPLATE_DELETE_NAME
        and record.get("q_origin_key") == TEMPLATE_DELETE_NAME
        and record.get("subject") == APPROVAL_EMAIL_TEMPLATE_UPDATED_SUBJECT
        and record.get("content") == APPROVAL_EMAIL_TEMPLATE_UPDATED_CONTENT
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
        raise ApprovalEmailTemplateDeleteHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "ApprovalEmailTemplateDeleteHttpTransportConfigurationError",
    "ApprovalEmailTemplateDeleteHttpTransportError",
    "ApprovalEmailTemplateDeleteInspection",
    "ApprovalEmailTemplateDeleteReadback",
    "COLLECTION_PATH",
    "FortiPamApprovalEmailTemplateDeleteHttpTransport",
    "TEMPLATE_ACCEPTED_DIGEST",
    "TEMPLATE_DELETE_NAME",
]
