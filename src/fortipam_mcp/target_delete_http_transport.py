"""Fixed REST/SSH recovery for the accepted laboratory Target."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import ssl
import stat
from typing import Any, Literal, Protocol
from urllib.parse import quote

from .classification_tag_assign_contract import ClassificationTagAssignInspection
from .target_contract import TARGET_CLASS, TargetInspection
from .target_http_transport import TargetHttpTransportConfig, _SUPPORTED_TARGET_PROFILES


COLLECTION_PATH = "/api/v2/cmdb/secret/target"
_TARGET_NAME = re.compile(r"mcp-v4-target-[A-Za-z0-9][A-Za-z0-9._-]{0,49}\Z")
_TAG_NAME = re.compile(r"mcp-v4-classification-tag-[A-Za-z0-9][A-Za-z0-9._-]{0,39}\Z")
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 Target recovery is unavailable."


class TargetDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the fixed Target recovery binding is incomplete or unsafe."""


class TargetDeleteHttpTransportError(RuntimeError):
    """Stable non-disclosing fixed Target recovery failure."""


class TargetClassificationTransport(Protocol):
    def inspect_classification_tag_assignment(
        self,
        target_name: str,
        classification_tag_name: str,
    ) -> ClassificationTagAssignInspection: ...


class TargetSshReadTransport(Protocol):
    def inspect(self, target_name: str) -> TargetInspection: ...


class TargetReferenceTransport(Protocol):
    def reference_count(self, target_name: str) -> int: ...


class TargetDeleteSessionDispatcher(Protocol):
    def inspect(self) -> None: ...

    def dispatch(self) -> tuple[int, object]: ...


@dataclass(frozen=True, slots=True)
class TargetDeleteInspection:
    """Categorical eligibility for only the protected accepted Target."""

    exists: bool
    eligible_fixed_target: bool
    target_reference_count: int
    target_class_is_other: bool
    classification_tag_absent: bool
    ssh_target_exists: bool
    target_non_class_state_digest: str
    target_digest: str
    delete_authentication: Literal["api_bearer", "owner_session"] = "api_bearer"


@dataclass(frozen=True, slots=True)
class TargetDeleteReadback:
    """Target absence plus preserved Tag absence after the fixed DELETE."""

    api_absent: bool
    ssh_absent: bool
    classification_tag_absent: bool
    reference_count_zero: bool

    @property
    def verified(self) -> bool:
        return all(
            (
                self.api_absent,
                self.ssh_absent,
                self.classification_tag_absent,
                self.reference_count_zero,
            )
        )


class FortiPamTargetDeleteHttpTransport:
    """Delete only the unchanged, default-class, unreferenced accepted Target."""

    def __init__(
        self,
        config: TargetHttpTransportConfig,
        target_transport: TargetClassificationTransport,
        ssh_transport: TargetSshReadTransport,
        reference_transport: TargetReferenceTransport,
        *,
        target_name: str,
        classification_tag_name: str,
        accepted_digest: str,
        claim_path: Path | None = None,
        client_factory: Callable[..., Any] | None = None,
        session_dispatcher: TargetDeleteSessionDispatcher | None = None,
    ) -> None:
        if (
            _TARGET_NAME.fullmatch(target_name) is None
            or _TAG_NAME.fullmatch(classification_tag_name) is None
            or not _digest(accepted_digest)
            or (session_dispatcher is not None and claim_path is None)
        ):
            raise TargetDeleteHttpTransportConfigurationError(
                "The fixed Target recovery binding is invalid."
            )
        self._config = config
        self._target_transport = target_transport
        self._ssh_transport = ssh_transport
        self._reference_transport = reference_transport
        self._target_name = target_name
        self._classification_tag_name = classification_tag_name
        self._accepted_digest = accepted_digest
        self._claim_path = claim_path
        self._product_identity: tuple[str, int] | None = None
        self._client_factory = client_factory
        self._session_dispatcher = session_dispatcher
        if claim_path is not None:
            self._check_claim_parent()

    def inspect_delete_target(self) -> TargetDeleteInspection:
        """Prove the exact default Target, prior Tag absence, and zero references."""

        self._require_unconsumed()
        status, payload = self._request("GET", self._detail_path())
        if status == 404:
            return TargetDeleteInspection(
                exists=False,
                eligible_fixed_target=False,
                target_reference_count=0,
                target_class_is_other=False,
                classification_tag_absent=False,
                ssh_target_exists=False,
                target_non_class_state_digest="0" * 64,
                target_digest="0" * 64,
            )
        record = _record(payload)
        if status != 200 or record is None or not self._fixed_projection(record):
            raise TargetDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _record_digest(record)
        non_class_digest = _record_digest_without_key(record, "class")
        if not hmac.compare_digest(target_digest, self._accepted_digest):
            raise TargetDeleteHttpTransportError(_UNAVAILABLE)

        related = self._target_transport.inspect_classification_tag_assignment(
            self._target_name,
            self._classification_tag_name,
        )
        ssh_target = self._ssh_transport.inspect(self._target_name)
        references = self._reference_transport.reference_count(self._target_name)
        if (
            not isinstance(related, ClassificationTagAssignInspection)
            or not isinstance(ssh_target, TargetInspection)
            or not related.target_exists
            or related.classification_tag_exists
            or not related.current_class_is_other
            or related.current_class_matches_tag
            or not hmac.compare_digest(
                related.target_non_class_state_digest,
                non_class_digest,
            )
            or not ssh_target.exists
        ):
            raise TargetDeleteHttpTransportError(_UNAVAILABLE)
        if references == 0 and self._session_dispatcher is not None:
            self._session_dispatcher.inspect()
        return TargetDeleteInspection(
            exists=True,
            eligible_fixed_target=references == 0,
            target_reference_count=references,
            target_class_is_other=True,
            classification_tag_absent=True,
            ssh_target_exists=True,
            target_non_class_state_digest=non_class_digest,
            target_digest=target_digest,
            delete_authentication="owner_session" if self._session_dispatcher is not None else "api_bearer",
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
        expected_target_non_class_state_digest: str,
    ) -> TargetDeleteReadback:
        """Delete exactly once and prove Target absence through REST and SSH."""

        if not _digest(expected_target_digest) or not _digest(
            expected_target_non_class_state_digest
        ):
            raise TargetDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_target
            or inspection.target_reference_count != 0
            or not inspection.target_class_is_other
            or not inspection.classification_tag_absent
            or not inspection.ssh_target_exists
            or not hmac.compare_digest(
                inspection.target_digest,
                expected_target_digest,
            )
            or not hmac.compare_digest(
                inspection.target_digest,
                self._accepted_digest,
            )
            or not hmac.compare_digest(
                inspection.target_non_class_state_digest,
                expected_target_non_class_state_digest,
            )
        ):
            raise TargetDeleteHttpTransportError(_UNAVAILABLE)

        self._reserve_claim()
        status, payload = self._request("DELETE", self._detail_path())
        if status != 200 or not _successful_response(payload):
            raise TargetDeleteHttpTransportError(_UNAVAILABLE)

        readback_status, _ = self._request("GET", self._detail_path())
        related = self._target_transport.inspect_classification_tag_assignment(
            self._target_name,
            self._classification_tag_name,
        )
        ssh_target = self._ssh_transport.inspect(self._target_name)
        references = self._reference_transport.reference_count(self._target_name)
        if not isinstance(related, ClassificationTagAssignInspection) or not isinstance(
            ssh_target, TargetInspection
        ):
            raise TargetDeleteHttpTransportError(_UNAVAILABLE)
        return TargetDeleteReadback(
            api_absent=readback_status == 404 and not related.target_exists,
            ssh_absent=not ssh_target.exists,
            classification_tag_absent=not related.classification_tag_exists,
            reference_count_zero=references == 0,
        )

    def _request(
        self,
        method: Literal["GET", "DELETE"],
        path: str,
    ) -> tuple[int, object | None]:
        if method == "DELETE" and self._session_dispatcher is not None:
            if path != self._detail_path():
                raise TargetDeleteHttpTransportError(_UNAVAILABLE)
            status, payload = self._session_dispatcher.dispatch()
            self._qualify_response(payload, status, method)
            return status, payload
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
            raise TargetDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise TargetDeleteHttpTransportError(_UNAVAILABLE)
        try:
            status = int(response.status_code)
            payload = json.loads(response.content)
            if self._claim_path is not None:
                self._qualify_response(payload, status, method)
            return status, payload
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TargetDeleteHttpTransportError(_UNAVAILABLE) from exc

    def _detail_path(self) -> str:
        return f"{COLLECTION_PATH}/{quote(self._target_name, safe='')}"

    def _qualify_response(self, payload: object, status: int, method: str) -> None:
        if not isinstance(payload, Mapping):
            raise TargetDeleteHttpTransportError(_UNAVAILABLE)
        version, build = payload.get("version"), payload.get("build")
        if not isinstance(version, str) or type(build) is not int:
            raise TargetDeleteHttpTransportError(_UNAVAILABLE)
        identity = (version.removeprefix("v"), build)
        missing_status = (
            identity == ("7.0.0", 29) and status == 404 and method == "GET"
            and payload.get("status") == "Not Found"
            and payload.get("results") in (None, [], {})
        )
        if identity not in _SUPPORTED_TARGET_PROFILES or any(
            payload.get(key) != value for key, value in {
                "http_status": status, "http_method": method,
                "path": "secret", "name": "target",
            }.items()
        ) or status not in {200, 404} or (
            payload.get("status") != ("success" if status == 200 else "error")
            and not missing_status
        ):
            raise TargetDeleteHttpTransportError(_UNAVAILABLE)
        if self._product_identity is not None and identity != self._product_identity:
            raise TargetDeleteHttpTransportError(_UNAVAILABLE)
        self._product_identity = identity

    def _check_claim_parent(self) -> None:
        if self._claim_path is None:
            return
        try:
            info = self._claim_path.parent.lstat()
            if (not self._claim_path.is_absolute() or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
        except Exception:
            raise TargetDeleteHttpTransportError(_UNAVAILABLE) from None

    def _require_unconsumed(self) -> None:
        if self._claim_path is not None:
            self._check_claim_parent()
            if os.path.lexists(self._claim_path):
                raise TargetDeleteHttpTransportError(_UNAVAILABLE)

    def _reserve_claim(self) -> None:
        if self._claim_path is None:
            return
        self._require_unconsumed()
        try:
            directory = os.open(self._claim_path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(directory)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                    raise ValueError
                descriptor = os.open(self._claim_path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=directory)
                with os.fdopen(descriptor, "w") as stream:
                    json.dump({"contract": "fortipam-target-delete-claim-v1", "state": "delete_attempt_reserved",
                               "accepted_digest": self._accepted_digest,
                               "binding_digest": _record_digest({"target": self._target_name, "tag": self._classification_tag_name}),
                               "product_identity": self._product_identity}, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception:
            raise TargetDeleteHttpTransportError(_UNAVAILABLE) from None

    def _fixed_projection(self, record: Mapping[str, object]) -> bool:
        origin = record.get("q_origin_key", self._target_name)
        return (
            record.get("name") == self._target_name
            and origin == self._target_name
            and record.get("class") == TARGET_CLASS
        )


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
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _record_digest_without_key(record: Mapping[str, object], key: str) -> str:
    return _record_digest({name: value for name, value in record.items() if name != key})


def _digest(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _successful_response(payload: object) -> bool:
    return isinstance(payload, Mapping) and payload.get("http_status") in {None, 200}


def _ssl_context(config: TargetHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise TargetDeleteHttpTransportError(_UNAVAILABLE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "FortiPamTargetDeleteHttpTransport",
    "TargetDeleteHttpTransportConfigurationError",
    "TargetDeleteHttpTransportError",
    "TargetDeleteInspection",
    "TargetDeleteReadback",
]
