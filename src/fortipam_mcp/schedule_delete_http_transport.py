"""Fixed REST/SSH recovery for the accepted unreferenced b66 Schedule."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import json
import ssl
from typing import Any, Literal, Protocol
from urllib.parse import quote

from .schedule_assign_http_transport import (
    FIXED_DETACH_ROLE,
    FIXED_DETACH_SCHEDULE,
    FIXED_DETACH_USER,
    FIXED_SCHEDULE_RECORD_DIGEST,
    FIXED_USER_NON_SCHEDULE_DIGEST,
    ScheduleAssignHttpTransportConfig,
)
from .schedule_ssh_transport import ScheduleInspection, ScheduleReadback


SCHEDULE_COLLECTION_PATH = "/api/v2/cmdb/firewall.schedule/recurring"
USER_COLLECTION_PATH = "/api/v2/cmdb/system/admin"
SCHEDULE_DELETE_NAME = FIXED_DETACH_SCHEDULE
SCHEDULE_ACCEPTED_DIGEST = FIXED_SCHEDULE_RECORD_DIGEST
MAX_RESPONSE_BYTES = 1_048_576
_UNAVAILABLE = "FortiPAM V4 Schedule recovery is unavailable."


class ScheduleDeleteHttpTransportConfigurationError(ValueError):
    """Raised when the fixed Schedule recovery configuration is unsafe."""


class ScheduleDeleteHttpTransportError(RuntimeError):
    """Stable, non-disclosing fixed Schedule recovery failure."""


class ScheduleSshTransport(Protocol):
    def inspect(self, schedule_name: str) -> ScheduleInspection: ...

    def readback_existing(self, schedule_name: str) -> ScheduleReadback: ...

    def reference_count(self, schedule_name: str) -> int: ...


@dataclass(frozen=True, slots=True)
class ScheduleDeleteInspection:
    """Categorical eligibility for only the accepted unreferenced b66 Schedule."""

    exists: bool
    eligible_fixed_schedule: bool
    user_reference_count: int
    cmdb_reference_count: int
    target_digest: str
    fixed_user_unassigned: bool


@dataclass(frozen=True, slots=True)
class ScheduleDeleteReadback:
    """Schedule absence and fixed-User preservation after the one DELETE."""

    api_absent: bool
    ssh_absent: bool
    fixed_user_unassigned: bool

    @property
    def verified(self) -> bool:
        return self.api_absent and self.ssh_absent and self.fixed_user_unassigned


class FortiPamScheduleDeleteHttpTransport:
    """Delete only unchanged, unreferenced b66 and prove its absence."""

    def __init__(
        self,
        config: ScheduleAssignHttpTransportConfig,
        schedule_ssh_transport: ScheduleSshTransport,
        *,
        client_factory: Callable[..., Any] | None = None,
        accepted_digest: str = SCHEDULE_ACCEPTED_DIGEST,
    ) -> None:
        if not _digest(accepted_digest):
            raise ScheduleDeleteHttpTransportConfigurationError(
                "The accepted Schedule digest is invalid."
            )
        self._config = config
        self._schedule_ssh_transport = schedule_ssh_transport
        self._client_factory = client_factory
        self._accepted_digest = accepted_digest

    def inspect_delete_target(self) -> ScheduleDeleteInspection:
        """Prove exact Schedule shape, fixed User state, and zero references."""

        status, payload = self._request("GET", self._schedule_path())
        if status == 404:
            return ScheduleDeleteInspection(
                exists=False,
                eligible_fixed_schedule=False,
                user_reference_count=0,
                cmdb_reference_count=0,
                target_digest="0" * 64,
                fixed_user_unassigned=False,
            )
        record = _record(payload)
        if status != 200 or record is None:
            raise ScheduleDeleteHttpTransportError(_UNAVAILABLE)
        target_digest = _mapping_digest(record)
        if (
            not hmac.compare_digest(target_digest, self._accepted_digest)
            or not _fixed_schedule_projection(record)
        ):
            raise ScheduleDeleteHttpTransportError(_UNAVAILABLE)

        schedule_readback = self._schedule_ssh_transport.readback_existing(
            SCHEDULE_DELETE_NAME
        )
        if not isinstance(schedule_readback, ScheduleReadback) or not schedule_readback.verified:
            raise ScheduleDeleteHttpTransportError(_UNAVAILABLE)
        user_reference_count = self._user_reference_count()
        fixed_user_unassigned = self._fixed_user_unassigned()
        cmdb_reference_count = self._schedule_ssh_transport.reference_count(
            SCHEDULE_DELETE_NAME
        )
        if (
            not isinstance(cmdb_reference_count, int)
            or isinstance(cmdb_reference_count, bool)
            or cmdb_reference_count < 0
        ):
            raise ScheduleDeleteHttpTransportError(_UNAVAILABLE)
        return ScheduleDeleteInspection(
            exists=True,
            eligible_fixed_schedule=(
                fixed_user_unassigned
                and user_reference_count == 0
                and cmdb_reference_count == 0
            ),
            user_reference_count=user_reference_count,
            cmdb_reference_count=cmdb_reference_count,
            target_digest=target_digest,
            fixed_user_unassigned=fixed_user_unassigned,
        )

    def delete_and_readback(
        self,
        expected_target_digest: str,
    ) -> ScheduleDeleteReadback:
        """Delete exactly once and prove Schedule absence and User preservation."""

        if not _digest(expected_target_digest):
            raise ScheduleDeleteHttpTransportError(_UNAVAILABLE)
        inspection = self.inspect_delete_target()
        if (
            not inspection.exists
            or not inspection.eligible_fixed_schedule
            or inspection.user_reference_count != 0
            or inspection.cmdb_reference_count != 0
            or not inspection.fixed_user_unassigned
            or not hmac.compare_digest(inspection.target_digest, expected_target_digest)
            or not hmac.compare_digest(inspection.target_digest, self._accepted_digest)
        ):
            raise ScheduleDeleteHttpTransportError(_UNAVAILABLE)

        status, payload = self._request("DELETE", self._schedule_path())
        if status != 200 or not _successful_response(payload):
            raise ScheduleDeleteHttpTransportError(_UNAVAILABLE)

        readback_status, _ = self._request("GET", self._schedule_path())
        schedule_inspection = self._schedule_ssh_transport.inspect(
            SCHEDULE_DELETE_NAME
        )
        if not isinstance(schedule_inspection, ScheduleInspection):
            raise ScheduleDeleteHttpTransportError(_UNAVAILABLE)
        return ScheduleDeleteReadback(
            api_absent=readback_status == 404,
            ssh_absent=not schedule_inspection.schedule_name_exists,
            fixed_user_unassigned=self._fixed_user_unassigned(),
        )

    def _user_reference_count(self) -> int:
        status, payload = self._request("GET", USER_COLLECTION_PATH)
        if status != 200:
            raise ScheduleDeleteHttpTransportError(_UNAVAILABLE)
        return sum(
            record.get("schedule") == SCHEDULE_DELETE_NAME
            for record in _records(payload)
        )

    def _fixed_user_unassigned(self) -> bool:
        status, payload = self._request("GET", self._user_path())
        record = _record(payload)
        return bool(
            status == 200
            and record is not None
            and record.get("name") == FIXED_DETACH_USER
            and record.get("status") == "disable"
            and record.get("remote-auth") == "disable"
            and record.get("wildcard") == "disable"
            and record.get("accprofile") == FIXED_DETACH_ROLE
            and record.get("schedule") in {None, ""}
            and hmac.compare_digest(
                _mapping_digest_without_key(record, "schedule"),
                FIXED_USER_NON_SCHEDULE_DIGEST,
            )
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
            raise ScheduleDeleteHttpTransportError(_UNAVAILABLE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > MAX_RESPONSE_BYTES:
            raise ScheduleDeleteHttpTransportError(_UNAVAILABLE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScheduleDeleteHttpTransportError(_UNAVAILABLE) from exc

    @staticmethod
    def _schedule_path() -> str:
        return f"{SCHEDULE_COLLECTION_PATH}/{quote(SCHEDULE_DELETE_NAME, safe='')}"

    @staticmethod
    def _user_path() -> str:
        return f"{USER_COLLECTION_PATH}/{quote(FIXED_DETACH_USER, safe='')}"


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


def _fixed_schedule_projection(record: Mapping[str, object]) -> bool:
    day = record.get("day")
    return (
        record.get("name") == SCHEDULE_DELETE_NAME
        and record.get("start") == "01:00"
        and record.get("end") == "01:30"
        and (day == "monday" or day == ["monday"])
        and record.get("color") in {None, 0}
    )


def _mapping_digest(record: Mapping[str, object]) -> str:
    return _canonical_digest(record)


def _mapping_digest_without_key(record: Mapping[str, object], key: str) -> str:
    return _canonical_digest({name: value for name, value in record.items() if name != key})


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
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


def _ssl_context(config: ScheduleAssignHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover
        raise ScheduleDeleteHttpTransportConfigurationError(
            "System trust-store support is unavailable."
        ) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


__all__ = [
    "FortiPamScheduleDeleteHttpTransport",
    "SCHEDULE_ACCEPTED_DIGEST",
    "SCHEDULE_DELETE_NAME",
    "ScheduleDeleteHttpTransportConfigurationError",
    "ScheduleDeleteHttpTransportError",
    "ScheduleDeleteInspection",
    "ScheduleDeleteReadback",
]
