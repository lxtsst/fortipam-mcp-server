"""Fixed REST/SSH recovery for the accepted b29 Classification Tag."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import ssl
from typing import Any, Literal, Protocol
from urllib.parse import quote

from .classification_tag_assign_contract import ClassificationTagAssignInspection
from .folder_http_transport import FolderTransportConfig


COLLECTION_PATH = "/api/v2/cmdb/secret/classification-tag"
_TAG_NAME = re.compile(r"mcp-v4-classification-tag-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
_TARGET_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 Classification Tag recovery is unavailable."


class ClassificationTagDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the fixed Tag recovery binding is incomplete or unsafe."""


class ClassificationTagDeleteHttpTransportError(RuntimeError):
    """Stable non-disclosing fixed Tag recovery failure."""


class TargetClassificationTransport(Protocol):
    def inspect_classification_tag_assignment(
        self,
        target_name: str,
        classification_tag_name: str,
    ) -> ClassificationTagAssignInspection: ...


class ClassificationTagReferenceTransport(Protocol):
    def reference_count(self, tag_name: str) -> int: ...


@dataclass(frozen=True, slots=True)
class ClassificationTagDeleteInspection:
    """Categorical eligibility for only the protected accepted Tag."""

    exists: bool
    eligible_fixed_tag: bool
    tag_reference_count: int
    target_is_default: bool
    target_non_class_state_digest: str
    target_digest: str


@dataclass(frozen=True, slots=True)
class ClassificationTagDeleteReadback:
    """Tag absence plus preserved default Target after the fixed DELETE."""

    api_absent: bool
    target_exists: bool
    target_class_is_other: bool
    target_non_class_state_preserved: bool
    reference_count_zero: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.api_absent,
                self.target_exists,
                self.target_class_is_other,
                self.target_non_class_state_preserved,
                self.reference_count_zero,
            )
        )


class FortiPamClassificationTagDeleteHttpTransport:
    """Delete only the unchanged, unreferenced protected b29 Tag."""

    def __init__(
        self,
        config: FolderTransportConfig,
        target_transport: TargetClassificationTransport,
        reference_transport: ClassificationTagReferenceTransport,
        *,
        tag_name: str,
        target_name: str,
        accepted_digest: str,
        client_factory: Callable[..., Any] | None = None,
    ) -> None:
        if (
            _TAG_NAME.fullmatch(tag_name) is None
            or _TARGET_NAME.fullmatch(target_name) is None
            or not _digest(accepted_digest)
        ):
            raise ClassificationTagDeleteHttpTransportConfigurationError(
                "The fixed Classification Tag recovery binding is invalid."
            )
        self._config = config
        self._target_transport = target_transport
        self._reference_transport = reference_transport
        self._tag_name = tag_name
        self._target_name = target_name
        self._accepted_digest = accepted_digest
        self._client_factory = client_factory

    def inspect_delete_target(self) -> ClassificationTagDeleteInspection:
        """Prove exact Tag state, default Target state, and zero references."""

        status, payload = self._request("GET", self._detail_path())
        if status == 404:
            return ClassificationTagDeleteInspection(
                exists=False,
                eligible_fixed_tag=False,
                tag_reference_count=0,
                target_is_default=False,
                target_non_class_state_digest="0" * 64,
                target_digest="0" * 64,
            )
        record = _record(payload)
        if status != 200 or record is None or not self._fixed_projection(record):
            raise ClassificationTagDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _record_digest(record)
        if not hmac.compare_digest(target_digest, self._accepted_digest):
            raise ClassificationTagDeleteHttpTransportError(_UNAVAILABLE)

        target = self._target_transport.inspect_classification_tag_assignment(
            self._target_name,
            self._tag_name,
        )
        references = self._reference_transport.reference_count(self._tag_name)
        if (
            not isinstance(target, ClassificationTagAssignInspection)
            or not target.target_exists
            or not target.classification_tag_exists
            or not hmac.compare_digest(
                target.classification_tag_state_digest,
                target_digest,
            )
        ):
            raise ClassificationTagDeleteHttpTransportError(_UNAVAILABLE)
        target_is_default = target.current_class_is_other and not target.current_class_matches_tag
        return ClassificationTagDeleteInspection(
            exists=True,
            eligible_fixed_tag=target_is_default and references == 0,
            tag_reference_count=references,
            target_is_default=target_is_default,
            target_non_class_state_digest=target.target_non_class_state_digest,
            target_digest=target_digest,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
        expected_target_non_class_state_digest: str,
    ) -> ClassificationTagDeleteReadback:
        """Delete exactly once and prove Tag absence plus Target preservation."""

        if not _digest(expected_target_digest) or not _digest(
            expected_target_non_class_state_digest
        ):
            raise ClassificationTagDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_tag
            or inspection.tag_reference_count != 0
            or not inspection.target_is_default
            or not hmac.compare_digest(inspection.target_digest, expected_target_digest)
            or not hmac.compare_digest(inspection.target_digest, self._accepted_digest)
            or not hmac.compare_digest(
                inspection.target_non_class_state_digest,
                expected_target_non_class_state_digest,
            )
        ):
            raise ClassificationTagDeleteHttpTransportError(_UNAVAILABLE)

        status, payload = self._request("DELETE", self._detail_path())
        if status != 200 or not _successful_response(payload):
            raise ClassificationTagDeleteHttpTransportError(_UNAVAILABLE)

        readback_status, _ = self._request("GET", self._detail_path())
        target = self._target_transport.inspect_classification_tag_assignment(
            self._target_name,
            self._tag_name,
        )
        references = self._reference_transport.reference_count(self._tag_name)
        if not isinstance(target, ClassificationTagAssignInspection):
            raise ClassificationTagDeleteHttpTransportError(_UNAVAILABLE)
        return ClassificationTagDeleteReadback(
            api_absent=readback_status == 404 and not target.classification_tag_exists,
            target_exists=target.target_exists,
            target_class_is_other=(
                target.current_class_is_other and not target.current_class_matches_tag
            ),
            target_non_class_state_preserved=hmac.compare_digest(
                target.target_non_class_state_digest,
                expected_target_non_class_state_digest,
            ),
            reference_count_zero=references == 0,
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
            raise ClassificationTagDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise ClassificationTagDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ClassificationTagDeleteHttpTransportError(_UNAVAILABLE) from exc

    def _detail_path(self) -> str:
        return f"{COLLECTION_PATH}/{quote(self._tag_name, safe='')}"

    def _fixed_projection(self, record: Mapping[str, object]) -> bool:
        origin = record.get("q_origin_key", self._tag_name)
        return record.get("name") == self._tag_name and origin == self._tag_name


def _record(payload: object) -> Mapping[str, object] | None:
    if not isinstance(payload, Mapping):
        return None
    result = payload.get("results", payload.get("result"))
    if isinstance(result, Mapping):
        return result
    if isinstance(result, list) and len(result) == 1 and isinstance(result[0], Mapping):
        return result[0]
    return None


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


def _ssl_context(config: FolderTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise ClassificationTagDeleteHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "ClassificationTagDeleteHttpTransportConfigurationError",
    "ClassificationTagDeleteHttpTransportError",
    "ClassificationTagDeleteInspection",
    "ClassificationTagDeleteReadback",
    "FortiPamClassificationTagDeleteHttpTransport",
]
