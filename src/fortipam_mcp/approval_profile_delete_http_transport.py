"""Fixed REST/SSH recovery for the accepted b36/b38 Approval Profile."""

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
from .approval_profile_ssh_transport import (
    ApprovalProfileInspection,
    ApprovalProfileUpdateReadback,
    FortiPamApprovalProfileSshTransport,
)


COLLECTION_PATH = "/api/v2/cmdb/secret/approval-profile"
PROFILE_DELETE_NAME = "mcp-v4-approval-profile-b36"
PROFILE_ACCEPTED_DIGEST = (
    "affdc016e5226d8b6690adbfcadf85b0eeac32f3764c8d679c570ae236fd869d"
)
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 Approval Profile recovery is unavailable."


class ApprovalProfileDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the fixed Profile recovery configuration is unsafe."""


class ApprovalProfileDeleteHttpTransportError(RuntimeError):
    """Stable, non-disclosing fixed Profile recovery failure."""


@dataclass(frozen=True, slots=True)
class ApprovalProfileDeleteInspection:
    """Categorical eligibility for only the accepted b36/b38 Profile."""

    exists: bool
    eligible_fixed_profile: bool
    profile_reference_count: int
    target_digest: str


@dataclass(frozen=True, slots=True)
class ApprovalProfileDeleteReadback:
    """REST and SSH absence after the exact fixed Profile DELETE."""

    api_absent: bool
    ssh_absent: bool

    @property
    def verified(self) -> bool:
        return self.api_absent and self.ssh_absent


class FortiPamApprovalProfileDeleteHttpTransport:
    """Inspect and delete only the unchanged, unreferenced b36/b38 Profile."""

    def __init__(
        self,
        config: AddressHttpTransportConfig,
        ssh_transport: FortiPamApprovalProfileSshTransport,
        *,
        client_factory: Callable[..., Any] | None = None,
        accepted_digest: str = PROFILE_ACCEPTED_DIGEST,
    ) -> None:
        if not _digest(accepted_digest):
            raise ApprovalProfileDeleteHttpTransportConfigurationError(
                "The accepted Approval Profile digest is invalid."
            )
        self._config = config
        self._ssh_transport = ssh_transport
        self._client_factory = client_factory
        self._accepted_digest = accepted_digest

    def inspect_delete_target(self) -> ApprovalProfileDeleteInspection:
        """Prove complete fixed record, updated projection, and zero references."""

        status, payload = self._request("GET", self._detail_path())
        if status == 404:
            return ApprovalProfileDeleteInspection(
                exists=False,
                eligible_fixed_profile=False,
                profile_reference_count=0,
                target_digest="0" * 64,
            )
        record = _record(payload)
        if status != 200 or record is None:
            raise ApprovalProfileDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _record_digest(record)
        if (
            not hmac.compare_digest(target_digest, self._accepted_digest)
            or not _fixed_profile_projection(record)
        ):
            raise ApprovalProfileDeleteHttpTransportError(_UNAVAILABLE)
        ssh_readback = self._ssh_transport.readback_updated(PROFILE_DELETE_NAME)
        reference_count = self._ssh_transport.reference_count(PROFILE_DELETE_NAME)
        if (
            not isinstance(ssh_readback, ApprovalProfileUpdateReadback)
            or not ssh_readback.verified
        ):
            raise ApprovalProfileDeleteHttpTransportError(_UNAVAILABLE)
        return ApprovalProfileDeleteInspection(
            exists=True,
            eligible_fixed_profile=reference_count == 0,
            profile_reference_count=reference_count,
            target_digest=target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> ApprovalProfileDeleteReadback:
        """Delete exactly once and prove fixed Profile absence."""

        if not _digest(expected_target_digest):
            raise ApprovalProfileDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_profile
            or inspection.profile_reference_count != 0
            or not hmac.compare_digest(
                inspection.target_digest,
                expected_target_digest,
            )
            or not hmac.compare_digest(
                inspection.target_digest,
                self._accepted_digest,
            )
        ):
            raise ApprovalProfileDeleteHttpTransportError(_UNAVAILABLE)

        status, payload = self._request("DELETE", self._detail_path())
        if status != 200 or not _successful_response(payload):
            raise ApprovalProfileDeleteHttpTransportError(_UNAVAILABLE)

        readback_status, _ = self._request("GET", self._detail_path())
        ssh_inspection = self._ssh_transport.inspect(PROFILE_DELETE_NAME)
        if not isinstance(ssh_inspection, ApprovalProfileInspection):
            raise ApprovalProfileDeleteHttpTransportError(_UNAVAILABLE)
        return ApprovalProfileDeleteReadback(
            api_absent=readback_status == 404,
            ssh_absent=not ssh_inspection.profile_name_exists,
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
            raise ApprovalProfileDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise ApprovalProfileDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApprovalProfileDeleteHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _detail_path() -> str:
        return f"{COLLECTION_PATH}/{quote(PROFILE_DELETE_NAME, safe='')}"


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


def _fixed_profile_projection(record: Mapping[str, object]) -> bool:
    return (
        set(record)
        == {
            "approver-perm-req",
            "auto-approval-schedule",
            "description",
            "email-approval-link-expiry",
            "email-template",
            "field",
            "first-group",
            "first-num",
            "first-user",
            "max-allowed-duration",
            "name",
            "q_origin_key",
            "remote-group-email",
            "remote-trust-time",
            "second-group",
            "second-num",
            "second-user",
            "self-approval",
            "third-group",
            "third-num",
            "third-user",
            "type",
        }
        and record.get("name") == PROFILE_DELETE_NAME
        and record.get("q_origin_key") == PROFILE_DELETE_NAME
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
        raise ApprovalProfileDeleteHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "ApprovalProfileDeleteHttpTransportConfigurationError",
    "ApprovalProfileDeleteHttpTransportError",
    "ApprovalProfileDeleteInspection",
    "ApprovalProfileDeleteReadback",
    "COLLECTION_PATH",
    "FortiPamApprovalProfileDeleteHttpTransport",
    "PROFILE_ACCEPTED_DIGEST",
    "PROFILE_DELETE_NAME",
]
