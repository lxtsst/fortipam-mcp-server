"""API-first transport for one bounded FortiPAM login-Schedule assignment.

FortiPAM 1.9.1's versioned frontend maps a selected login Schedule to the
existing Local User's ``schedule`` field and saves the existing-user CMDB
projection through ``system/admin/{name}``.  This adapter compiles only that
one transition and never exposes a generic REST client or a User payload.
"""

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
from urllib.parse import quote, urlsplit

from .schedule_assign_contract import (
    ScheduleAssignInspection,
    ScheduleAssignReadback,
    ScheduleDetachInspection,
    ScheduleDetachReadback,
)
from .schedule_ssh_transport import ScheduleReadback


ENV_PREFIX = "FPA_HOME_LAB_FPA1_V4_SCHEDULE_ASSIGN_"
LAB_USER_NAME_PREFIX = "mcp-v4-user-"
SCHEDULE_NAME_PREFIX = "mcp-v4-schedule-"
_USER_COLLECTION_PATH = "/api/v2/cmdb/system/admin"
_SCHEDULE_COLLECTION_PATH = "/api/v2/cmdb/firewall.schedule/recurring"
_MAX_RESPONSE_BYTES = 1_048_576
_USER_NAME = re.compile(r"mcp-v4-user-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_SCHEDULE_NAME = re.compile(r"mcp-v4-schedule-[A-Za-z0-9][A-Za-z0-9._-]{0,47}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_DENIED_MESSAGE = "FortiPAM V4 Schedule assignment transport is unavailable."
FIXED_DETACH_USER = "mcp-v4-user-b57"
FIXED_DETACH_SCHEDULE = "mcp-v4-schedule-b66"
FIXED_DETACH_ROLE = "mcp-v4-role-b76a"
FIXED_USER_RECORD_DIGEST = (
    "b21c4c223310bb66bca5b6dcbe7349f2eea698335ec2b6fbf8fe5826803ef5ae"
)
FIXED_USER_NON_SCHEDULE_DIGEST = (
    "4fc25c762c47f3199f6f53561b9ee5a672b17a371eb2a79af530b3501b6f08ee"
)
FIXED_SCHEDULE_RECORD_DIGEST = (
    "7eb6afcb040f1b48e6756f81af7be61c584037b2a78d5e3581eacc51cf2f6a1d"
)

# Exact existing-local-user field allowlist from the FortiPAM 1.9.1 frontend
# User CMDB model.  Existing users omit password material before serialization.
_EXISTING_USER_WRITE_FIELDS = frozenset(
    {
        "id",
        "name",
        "display-name",
        "wildcard",
        "remote-auth",
        "remote-server",
        "remote-group",
        "force-saml-login",
        "peer-auth",
        "peer-group",
        *(f"trusthost{index}" for index in range(1, 11)),
        "accprofile",
        "allow-remove-admin-session",
        "comments",
        "schedule",
        "accprofile-override",
        "radius-vdom-override",
        "password-expire",
        "force-password-change",
        "two-factor",
        "two-factor-notification",
        "fortitoken",
        "email-to",
        "sms-server",
        "sms-custom-server",
        "sms-phone",
        "guest-auth",
        "guest-lang",
        "status",
        "vdom",
        "sponsor-group",
        "auto-created-user",
        "secret-launch-limitation",
        "secret-launch-limitation-override",
    }
)


class ScheduleAssignHttpTransportConfigurationError(ValueError):
    """Raised when the dedicated Schedule-assignment API route is unsafe."""


class ScheduleAssignHttpTransportError(RuntimeError):
    """Stable non-disclosing failure for the fixed API adapter."""


class ScheduleSshReadTransport(Protocol):
    """Complete fixed Schedule readback required by detach recovery."""

    def readback_existing(self, schedule_name: str) -> ScheduleReadback: ...


@dataclass(frozen=True, slots=True)
class ScheduleAssignHttpTransportConfig:
    """Dedicated HTTPS and bearer-token settings kept only in memory."""

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
            raise ScheduleAssignHttpTransportConfigurationError(
                "A dedicated HTTPS Schedule assignment API target is required."
            )
        if not self.bearer_token or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.bearer_token
        ):
            raise ScheduleAssignHttpTransportConfigurationError(
                "A dedicated Schedule assignment bearer token is required."
            )
        if not 1 <= self.timeout_seconds <= 60:
            raise ScheduleAssignHttpTransportConfigurationError(
                "The Schedule assignment API timeout is invalid."
            )
        if self.ca_file is not None and not Path(self.ca_file).is_file():
            raise ScheduleAssignHttpTransportConfigurationError(
                "The configured certificate authority file is unavailable."
            )


def load_schedule_assign_http_transport_config(
    environment: Mapping[str, str] | None = None,
) -> ScheduleAssignHttpTransportConfig:
    """Load only independently scoped Schedule-assignment API settings."""

    env = os.environ if environment is None else environment
    if _value(env, "ENABLED") != "true":
        raise ScheduleAssignHttpTransportConfigurationError(
            f"{ENV_PREFIX}ENABLED must be exactly true."
        )
    base_url = _value(env, "BASE_URL") or _value(env, "HOST")
    token_file = _value(env, "API_TOKEN_FILE")
    timeout_raw = _value(env, "TIMEOUT_SECONDS") or "15"
    ca_file = _value(env, "CA_FILE")
    if base_url is None or token_file is None:
        raise ScheduleAssignHttpTransportConfigurationError(
            "Dedicated Schedule assignment API target and token file are required."
        )
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ScheduleAssignHttpTransportConfigurationError(
            "The Schedule assignment API timeout is invalid."
        ) from exc
    normalized_url = base_url if "://" in base_url else f"https://{base_url}"
    return ScheduleAssignHttpTransportConfig(
        base_url=normalized_url.rstrip("/"),
        bearer_token=_read_owner_only_token(Path(token_file)),
        timeout_seconds=timeout,
        ca_file=ca_file,
    )


class FortiPamScheduleAssignHttpTransport:
    """Issue only fixed User/Schedule inspection, assignment, and readback calls."""

    def __init__(
        self,
        config: ScheduleAssignHttpTransportConfig,
        *,
        client_factory: Callable[..., Any] | None = None,
        schedule_ssh_transport: ScheduleSshReadTransport | None = None,
    ) -> None:
        self._config = config
        self._client_factory = client_factory
        self._schedule_ssh_transport = schedule_ssh_transport

    def inspect_assignment(
        self,
        username: str,
        schedule_name: str,
    ) -> ScheduleAssignInspection:
        """Read one exact pair and return only categorical evidence and digests."""

        user = _user_name(username)
        schedule = _schedule_name(schedule_name)
        user_record, schedule_record = self._read_pair(user, schedule)
        user_exists = user_record is not None
        schedule_exists = schedule_record is not None
        user_disabled = user_record is not None and user_record.get("status") == "disable"
        user_local = user_record is not None and _user_is_local(user_record)
        schedule_unassigned = user_record is not None and user_record.get("schedule") in {
            None,
            "",
        }
        user_digest = _mapping_digest_without_key(user_record, "schedule")
        schedule_digest = _mapping_digest(schedule_record)
        return ScheduleAssignInspection(
            user_exists=user_exists,
            schedule_exists=schedule_exists,
            user_disabled=user_disabled,
            user_local=user_local,
            schedule_unassigned=schedule_unassigned,
            user_non_schedule_state_digest=user_digest,
            schedule_state_digest=schedule_digest,
            state_digest=_assignment_state_digest(
                user,
                schedule,
                user_exists=user_exists,
                schedule_exists=schedule_exists,
                user_disabled=user_disabled,
                user_local=user_local,
                current_schedule=(
                    user_record.get("schedule") if user_record is not None else None
                ),
                user_non_schedule_state_digest=user_digest,
                schedule_state_digest=schedule_digest,
            ),
        )

    def assign_and_readback(
        self,
        username: str,
        schedule_name: str,
        *,
        user_non_schedule_state_digest: str,
        schedule_state_digest: str,
    ) -> ScheduleAssignReadback:
        """Save the exact UI projection and verify all unrelated state is preserved."""

        user = _user_name(username)
        schedule = _schedule_name(schedule_name)
        expected_user_digest = _digest_value(user_non_schedule_state_digest)
        expected_schedule_digest = _digest_value(schedule_state_digest)
        current_user, current_schedule = self._read_pair(user, schedule)
        if (
            current_user is None
            or current_schedule is None
            or current_user.get("status") != "disable"
            or not _user_is_local(current_user)
            or current_user.get("schedule") not in {None, ""}
            or not hmac.compare_digest(
                _mapping_digest_without_key(current_user, "schedule"),
                expected_user_digest,
            )
            or not hmac.compare_digest(
                _mapping_digest(current_schedule),
                expected_schedule_digest,
            )
        ):
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
        body = _existing_user_projection(current_user)
        body["schedule"] = schedule
        status, payload = self._request("PUT", self._user_path(user), body)
        if status != 200 or not _successful_write_response(payload):
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)

        updated_user, updated_schedule = self._read_pair(user, schedule)
        user_exists = updated_user is not None
        schedule_exists = updated_schedule is not None
        return ScheduleAssignReadback(
            user_exists=user_exists,
            schedule_exists=schedule_exists,
            user_disabled=(
                updated_user is not None and updated_user.get("status") == "disable"
            ),
            user_local=updated_user is not None and _user_is_local(updated_user),
            schedule_matches=(
                updated_user is not None and updated_user.get("schedule") == schedule
            ),
            user_non_schedule_state_preserved=(
                updated_user is not None
                and hmac.compare_digest(
                    _mapping_digest_without_key(updated_user, "schedule"),
                    expected_user_digest,
                )
            ),
            schedule_state_preserved=(
                updated_schedule is not None
                and hmac.compare_digest(
                    _mapping_digest(updated_schedule),
                    expected_schedule_digest,
                )
            ),
        )

    def inspect_fixed_detach(self) -> ScheduleDetachInspection:
        """Prove only the accepted b57/b66 assignment is recovery-eligible."""

        user_record, schedule_record = self._read_pair(
            FIXED_DETACH_USER,
            FIXED_DETACH_SCHEDULE,
        )
        if user_record is None or schedule_record is None:
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
        user_digest = _mapping_digest(user_record)
        user_non_schedule_digest = _mapping_digest_without_key(
            user_record, "schedule"
        )
        schedule_digest = _mapping_digest(schedule_record)
        if not all(
            (
                hmac.compare_digest(user_digest, FIXED_USER_RECORD_DIGEST),
                hmac.compare_digest(
                    user_non_schedule_digest,
                    FIXED_USER_NON_SCHEDULE_DIGEST,
                ),
                hmac.compare_digest(
                    schedule_digest,
                    FIXED_SCHEDULE_RECORD_DIGEST,
                ),
            )
        ):
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
        projection = _existing_user_projection(user_record)
        reference_count, only_fixed_user = self._fixed_schedule_references()
        schedule_ssh = self._schedule_ssh_readback()
        return ScheduleDetachInspection(
            user_exists=True,
            schedule_exists=True,
            user_disabled=projection.get("status") == "disable",
            user_local=(
                projection.get("remote-auth") == "disable"
                and projection.get("wildcard") == "disable"
            ),
            role_matches=projection.get("accprofile") == FIXED_DETACH_ROLE,
            schedule_matches=(
                projection.get("schedule") == FIXED_DETACH_SCHEDULE
            ),
            schedule_rest_projection_matches=_fixed_schedule_projection(
                schedule_record
            ),
            schedule_ssh_projection_matches=schedule_ssh.verified,
            schedule_reference_count=reference_count,
            only_fixed_user_references_schedule=only_fixed_user,
            user_record_digest=user_digest,
            user_non_schedule_state_digest=user_non_schedule_digest,
            schedule_state_digest=schedule_digest,
        )

    def detach_fixed_and_readback(
        self,
        *,
        expected_user_record_digest: str,
        expected_user_non_schedule_state_digest: str,
        expected_schedule_state_digest: str,
    ) -> ScheduleDetachReadback:
        """Clear only b57's b66 assignment and prove full preservation."""

        expected_user = _digest_value(expected_user_record_digest)
        expected_non_schedule = _digest_value(
            expected_user_non_schedule_state_digest
        )
        expected_schedule = _digest_value(expected_schedule_state_digest)
        inspection = self.inspect_fixed_detach()
        if (
            not inspection.eligible
            or not hmac.compare_digest(inspection.user_record_digest, expected_user)
            or not hmac.compare_digest(
                inspection.user_non_schedule_state_digest,
                expected_non_schedule,
            )
            or not hmac.compare_digest(
                inspection.schedule_state_digest,
                expected_schedule,
            )
        ):
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
        current_user, _ = self._read_pair(
            FIXED_DETACH_USER,
            FIXED_DETACH_SCHEDULE,
        )
        if current_user is None or not hmac.compare_digest(
            _mapping_digest(current_user), expected_user
        ):
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
        body = _existing_user_projection(current_user)
        body["schedule"] = ""
        status, payload = self._request(
            "PUT",
            self._user_path(FIXED_DETACH_USER),
            body,
        )
        if status != 200 or not _successful_write_response(payload):
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)

        updated_user, updated_schedule = self._read_pair(
            FIXED_DETACH_USER,
            FIXED_DETACH_SCHEDULE,
        )
        reference_count, _ = self._fixed_schedule_references()
        schedule_ssh = self._schedule_ssh_readback()
        return ScheduleDetachReadback(
            user_exists=updated_user is not None,
            schedule_exists=updated_schedule is not None,
            user_disabled=(
                updated_user is not None and updated_user.get("status") == "disable"
            ),
            user_local=updated_user is not None and _user_is_local(updated_user),
            role_preserved=(
                updated_user is not None
                and updated_user.get("accprofile") == FIXED_DETACH_ROLE
            ),
            schedule_unassigned=(
                updated_user is not None
                and updated_user.get("schedule") in {None, ""}
            ),
            user_non_schedule_state_preserved=(
                updated_user is not None
                and hmac.compare_digest(
                    _mapping_digest_without_key(updated_user, "schedule"),
                    expected_non_schedule,
                )
            ),
            schedule_state_preserved=(
                updated_schedule is not None
                and hmac.compare_digest(
                    _mapping_digest(updated_schedule),
                    expected_schedule,
                )
            ),
            schedule_rest_projection_preserved=(
                updated_schedule is not None
                and _fixed_schedule_projection(updated_schedule)
            ),
            schedule_ssh_projection_preserved=schedule_ssh.verified,
            schedule_reference_count=reference_count,
        )

    def _fixed_schedule_references(self) -> tuple[int, bool]:
        status, payload = self._request("GET", _USER_COLLECTION_PATH, None)
        if status != 200:
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
        references = [
            record
            for record in _records(payload)
            if record.get("schedule") == FIXED_DETACH_SCHEDULE
        ]
        return len(references), (
            len(references) == 1
            and references[0].get("name") == FIXED_DETACH_USER
        )

    def _schedule_ssh_readback(self) -> ScheduleReadback:
        if self._schedule_ssh_transport is None:
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
        try:
            readback = self._schedule_ssh_transport.readback_existing(
                FIXED_DETACH_SCHEDULE
            )
        except Exception as exc:
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE) from exc
        if not isinstance(readback, ScheduleReadback):
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
        return readback

    def _read_pair(
        self,
        username: str,
        schedule_name: str,
    ) -> tuple[Mapping[str, object] | None, Mapping[str, object] | None]:
        user_status, user_payload = self._request(
            "GET", self._user_path(username), None
        )
        schedule_status, schedule_payload = self._request(
            "GET", self._schedule_path(schedule_name), None
        )
        if user_status not in {200, 404} or schedule_status not in {200, 404}:
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
        user_record = _record(user_payload) if user_status == 200 else None
        schedule_record = _record(schedule_payload) if schedule_status == 200 else None
        if user_status == 200 and (
            user_record is None or user_record.get("name") != username
        ):
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
        if schedule_status == 200 and (
            schedule_record is None or schedule_record.get("name") != schedule_name
        ):
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
        return user_record, schedule_record

    def _request(
        self,
        method: Literal["GET", "PUT"],
        path: str,
        body: Mapping[str, object] | None,
    ) -> tuple[int, object]:
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
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE) from exc
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type.lower() or len(response.content) > _MAX_RESPONSE_BYTES:
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
        try:
            return int(response.status_code), json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE) from exc

    @staticmethod
    def _user_path(username: str) -> str:
        return f"{_USER_COLLECTION_PATH}/{quote(username, safe='')}"

    @staticmethod
    def _schedule_path(schedule_name: str) -> str:
        return f"{_SCHEDULE_COLLECTION_PATH}/{quote(schedule_name, safe='')}"


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
        record.get("name") == FIXED_DETACH_SCHEDULE
        and record.get("start") == "01:00"
        and record.get("end") == "01:30"
        and (day == "monday" or day == ["monday"])
        and record.get("color") in {None, 0}
    )


def _existing_user_projection(record: Mapping[str, object]) -> dict[str, object]:
    identifier = record.get("id")
    name = record.get("name")
    if (
        not isinstance(identifier, int)
        or isinstance(identifier, bool)
        or identifier <= 0
        or not isinstance(name, str)
        or _USER_NAME.fullmatch(name) is None
    ):
        raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
    projection = {
        key: value
        for key, value in record.items()
        if not key.startswith("history") and key in _EXISTING_USER_WRITE_FIELDS
    }
    projection["$originalName"] = name
    projection.pop("password", None)
    if projection.get("name") != name or projection.get("id") != identifier:
        raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
    return projection


def _user_is_local(record: Mapping[str, object]) -> bool:
    return record.get("remote-auth") == "disable" and record.get("wildcard") == "disable"


def _successful_write_response(payload: object) -> bool:
    return isinstance(payload, Mapping) and payload.get("http_status") in {None, 200}


def _mapping_digest(record: Mapping[str, object] | None) -> str:
    return _canonical_digest(record if record is not None else {"absent": True})


def _mapping_digest_without_key(
    record: Mapping[str, object] | None,
    key: str,
) -> str:
    if record is None:
        return _canonical_digest({"absent": True})
    return _canonical_digest({name: value for name, value in record.items() if name != key})


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _assignment_state_digest(
    username: str,
    schedule_name: str,
    *,
    user_exists: bool,
    schedule_exists: bool,
    user_disabled: bool,
    user_local: bool,
    current_schedule: object,
    user_non_schedule_state_digest: str,
    schedule_state_digest: str,
) -> str:
    return _canonical_digest(
        {
            "username": username,
            "schedule_name": schedule_name,
            "user_exists": user_exists,
            "schedule_exists": schedule_exists,
            "user_disabled": user_disabled,
            "user_local": user_local,
            "current_schedule": current_schedule,
            "user_non_schedule_state_digest": user_non_schedule_state_digest,
            "schedule_state_digest": schedule_state_digest,
        }
    )


def _digest_value(value: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
    return value


def _ssl_context(config: ScheduleAssignHttpTransportConfig) -> ssl.SSLContext:
    if config.ca_file is not None:
        return ssl.create_default_context(cafile=config.ca_file)
    try:
        import truststore
    except ImportError as exc:  # pragma: no cover - deployment dependency guard.
        raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE) from exc
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def _value(environment: Mapping[str, str], suffix: str) -> str | None:
    value = environment.get(f"{ENV_PREFIX}{suffix}")
    if value is None:
        return None
    normalized = value.strip()
    return normalized or None


def _read_owner_only_token(path: Path) -> str:
    try:
        metadata = path.lstat()
        if (
            not path.is_file()
            or stat.S_ISLNK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ScheduleAssignHttpTransportConfigurationError(
                "The Schedule assignment token file must be owner-only."
            )
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ScheduleAssignHttpTransportConfigurationError(
            "The Schedule assignment token file is unavailable."
        ) from exc
    if not token:
        raise ScheduleAssignHttpTransportConfigurationError(
            "The Schedule assignment token file is empty."
        )
    return token


def _user_name(value: str) -> str:
    if not isinstance(value, str) or _USER_NAME.fullmatch(value) is None:
        raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
    return value


def _schedule_name(value: str) -> str:
    if not isinstance(value, str) or _SCHEDULE_NAME.fullmatch(value) is None:
        raise ScheduleAssignHttpTransportError(_DENIED_MESSAGE)
    return value


__all__ = [
    "ENV_PREFIX",
    "FortiPamScheduleAssignHttpTransport",
    "LAB_USER_NAME_PREFIX",
    "SCHEDULE_NAME_PREFIX",
    "ScheduleAssignHttpTransportConfig",
    "ScheduleAssignHttpTransportConfigurationError",
    "ScheduleAssignHttpTransportError",
    "load_schedule_assign_http_transport_config",
]
