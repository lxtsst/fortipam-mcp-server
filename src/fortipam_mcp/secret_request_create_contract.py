"""Pure, source-pinned FortiPAM Secret-request create contract.

The contract is pinned to a target-version ``action=default`` response and the
matching frontend CMDB serializer.  It validates the complete default object
before compiling one request body.  It has no HTTP client, credential access,
MCP registration, execution gate, or write capability.

Requester names, Secret identifiers, comments, timezones, and custom-field
values belong only in a protected runtime.  The request inputs therefore hide
their representation and must never be placed in Schemes, Plans, logs, or MCP
results.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import re
from typing import Final, Literal, cast


REQUEST_CREATE_METHOD: Final[Literal["POST"]] = "POST"
REQUEST_CREATE_PATH = "/api/v2/cmdb/secret/request"
REQUEST_CREATE_POST_QUERY = "with_meta=true&vdom=root"
REQUEST_DEFAULT_METHOD = "GET"
REQUEST_DEFAULT_QUERY = "action=default&with_meta=true&vdom=root"
REQUEST_SCHEMA_REF = "fortipam-1.9.1-build1758-secret-request-create-v1"
FORTIPAM_VERSION: Final[Literal["1.9.1"]] = "1.9.1"
FORTIPAM_BUILD: Final[Literal[1758]] = 1758
FORTIPAM_700_SCHEMA_REF = "fortipam-7.0.0-build29-secret-request-create-v1"
FORTIPAM_700_VERSION: Final[Literal["7.0.0"]] = "7.0.0"
FORTIPAM_700_BUILD: Final[Literal[29]] = 29
_SUPPORTED_DEFAULTS = {
    (FORTIPAM_VERSION, FORTIPAM_BUILD): REQUEST_SCHEMA_REF,
    (FORTIPAM_700_VERSION, FORTIPAM_700_BUILD): FORTIPAM_700_SCHEMA_REF,
}

_TOP_LEVEL_FIELDS = frozenset(
    {
        "http_method",
        "revision",
        "results",
        "vdom",
        "path",
        "name",
        "action",
        "status",
        "http_status",
        "serial",
        "version",
        "build",
    }
)
_DEFAULT_RESULTS: dict[str, object] = {
    "id": 0,
    "user": "",
    "secret-id": 0,
    "display-name": "",
    "approval-profile": "",
    "request-type": "launcher",
    "request-ownership-type": "self",
    "request-invitation-user": "",
    "creation-time": "0000-00-00 00:00:00",
    "start-after-approve": "disable",
    "expiration-time": "0000-00-00 00:00:00",
    "start-time": "0000-00-00 00:00:00",
    "duration": 30,
    "final-status": "pending",
    "tier1-status": "pending",
    "tier2-status": "pending",
    "tier3-status": "pending",
    "comments": "",
    "job-name": "",
    "timezone": "",
    "tier-last-sent": 0,
    "emails-sent": [],
    "tier1": [],
    "tier2": [],
    "tier3": [],
    "field": [],
}
_CMDB_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\Z")
_MAX_INT32 = 2_147_483_647
_MAX_CUSTOM_FIELDS = 64


class SecretRequestCreateContractError(ValueError):
    """Raised when target-version evidence or protected input is incomplete."""


@dataclass(frozen=True, slots=True)
class SecretRequestDefaultEvidence:
    """Value-minimized proof that the exact default response was validated."""

    request_schema_ref: str = REQUEST_SCHEMA_REF
    fortipam_version: Literal["1.9.1", "7.0.0"] = FORTIPAM_VERSION
    fortipam_build: Literal[1758, 29] = FORTIPAM_BUILD
    create_method: Literal["POST"] = REQUEST_CREATE_METHOD
    create_path: str = REQUEST_CREATE_PATH
    complete_default_projection: Literal[True] = True
    raw_values_returned: Literal[False] = False

    def __post_init__(self) -> None:
        if (
            _SUPPORTED_DEFAULTS.get(
                (self.fortipam_version, self.fortipam_build)
            )
            != self.request_schema_ref
            or self.create_method != REQUEST_CREATE_METHOD
            or self.create_path != REQUEST_CREATE_PATH
            or self.complete_default_projection is not True
            or self.raw_values_returned is not False
        ):
            raise SecretRequestCreateContractError(
                "Secret request default evidence is unsupported."
            )


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestCustomField:
    """One protected Approval Profile field value for the request body."""

    name: str
    value: str
    required: bool

    def __post_init__(self) -> None:
        _bounded_text(self.name, "custom field name", 128, allow_empty=False)
        _bounded_text(self.value, "custom field value", 4_096, allow_empty=True)
        if type(self.required) is not bool:
            raise SecretRequestCreateContractError(
                "custom field required must be a boolean."
            )
        if self.required and not self.value:
            raise SecretRequestCreateContractError(
                "A required custom field must have a value."
            )

    def body(self, position: int) -> dict[str, object]:
        if type(position) is not int or not 1 <= position <= _MAX_CUSTOM_FIELDS:
            raise SecretRequestCreateContractError(
                "custom field position is outside the fixed bound."
            )
        return {
            "id": position,
            "q_origin_key": position,
            "name": self.name,
            "value": self.value,
        }


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestCreateInput:
    """Protected inputs for one frontend-equivalent request create body."""

    requester: str
    secret_id: int
    request_type: Literal["launcher", "job"]
    start_after_approve: Literal["enable", "disable"]
    start_time: str
    expiration_time: str
    duration: int
    comments: str
    timezone: str
    job_name: str | None = None
    custom_fields: tuple[SecretRequestCustomField, ...] = ()

    def __post_init__(self) -> None:
        _bounded_text(self.requester, "requester", 128, allow_empty=False)
        _positive_int32(self.secret_id, "secret_id")
        if self.request_type not in {"launcher", "job"}:
            raise SecretRequestCreateContractError(
                "request_type must be launcher or job."
            )
        if self.start_after_approve not in {"enable", "disable"}:
            raise SecretRequestCreateContractError(
                "start_after_approve must be enable or disable."
            )
        _bounded_text(self.comments, "comments", 255, allow_empty=True)
        _bounded_text(self.timezone, "timezone", 128, allow_empty=False)
        if self.request_type == "launcher":
            if self.job_name is not None:
                raise SecretRequestCreateContractError(
                    "A launcher request must not declare a job_name."
                )
        else:
            _bounded_text(self.job_name, "job_name", 128, allow_empty=False)
            if self.start_after_approve != "disable":
                raise SecretRequestCreateContractError(
                    "A job request must use its Job schedule, not start upon approval."
                )
        if self.start_after_approve == "enable":
            if self.start_time or self.expiration_time:
                raise SecretRequestCreateContractError(
                    "Start and expiration time must be empty when starting upon approval."
                )
            _positive_int32(self.duration, "duration")
        else:
            if self.duration != 0:
                raise SecretRequestCreateContractError(
                    "A scheduled request must compile duration as zero."
                )
            _timestamp(self.expiration_time, "expiration_time")
            if self.request_type == "job":
                if self.start_time:
                    raise SecretRequestCreateContractError(
                        "A job request derives its start time from the Job schedule."
                    )
            else:
                _timestamp(self.start_time, "start_time")
                if self.expiration_time <= self.start_time:
                    raise SecretRequestCreateContractError(
                        "expiration_time must be later than start_time."
                    )
        if not isinstance(self.custom_fields, tuple):
            raise SecretRequestCreateContractError(
                "custom_fields must be an immutable tuple."
            )
        if len(self.custom_fields) > _MAX_CUSTOM_FIELDS:
            raise SecretRequestCreateContractError(
                "custom_fields exceeds the fixed implementation bound."
            )
        names: set[str] = set()
        for item in self.custom_fields:
            if not isinstance(item, SecretRequestCustomField) or item.name in names:
                raise SecretRequestCreateContractError(
                    "custom_fields contains an invalid or duplicate entry."
                )
            names.add(item.name)

    def body(
        self,
        evidence: SecretRequestDefaultEvidence,
    ) -> dict[str, object]:
        """Compile only the target-version frontend CMDB request projection."""

        if not isinstance(evidence, SecretRequestDefaultEvidence):
            raise SecretRequestCreateContractError(
                "Exact FortiPAM request-default evidence is required."
            )
        body: dict[str, object] = {
            "id": 0,
            "user": self.requester,
            "secret-id": self.secret_id,
            "request-type": self.request_type,
            "start-after-approve": self.start_after_approve,
            "start-time": self.start_time,
            "expiration-time": self.expiration_time,
            "duration": self.duration,
            "comments": self.comments,
            "timezone": self.timezone,
            "field": [
                item.body(position)
                for position, item in enumerate(self.custom_fields, start=1)
            ],
        }
        # Both accepted frontends produce ``undefined`` for this member on a
        # Launcher request, so JSON serialization omits it.  Job requests bind
        # the aligned job name explicitly.
        if self.job_name is not None:
            body["job-name"] = self.job_name
        return body


def validate_secret_request_default_response(
    response: Mapping[str, object],
) -> SecretRequestDefaultEvidence:
    """Validate the complete build-1758 default without retaining identifiers."""

    if not isinstance(response, Mapping) or set(response) != _TOP_LEVEL_FIELDS:
        raise SecretRequestCreateContractError(
            "Secret request default response does not match the exact contract."
        )
    if (
        response.get("http_method") != REQUEST_DEFAULT_METHOD
        or response.get("vdom") != "root"
        or response.get("path") != "secret"
        or response.get("name") != "request"
        or response.get("action") != "default"
        or response.get("status") != "success"
        or response.get("http_status") != 200
    ):
        raise SecretRequestCreateContractError(
            "Secret request default response is not the accepted target version."
        )
    _bounded_text(response.get("revision"), "revision", 128, allow_empty=False)
    _bounded_text(response.get("serial"), "serial", 128, allow_empty=False)
    results = response.get("results")
    if not isinstance(results, Mapping) or not _exact_value_equal(
        dict(results), _DEFAULT_RESULTS
    ):
        raise SecretRequestCreateContractError(
            "Secret request defaults do not match the complete accepted projection."
        )
    version = response.get("version")
    build = response.get("build")
    if (
        not isinstance(version, str)
        or not version.startswith("v")
        or type(build) is not int
    ):
        raise SecretRequestCreateContractError(
            "Secret request default response is not the accepted target version."
        )
    pair = (version[1:], build)
    schema_ref = _SUPPORTED_DEFAULTS.get(pair)
    if schema_ref is None:
        raise SecretRequestCreateContractError(
            "Secret request default response is not the accepted target version."
        )
    return SecretRequestDefaultEvidence(
        request_schema_ref=schema_ref,
        fortipam_version=cast(Literal["1.9.1", "7.0.0"], pair[0]),
        fortipam_build=cast(Literal[1758, 29], pair[1]),
    )


def _exact_value_equal(observed: object, expected: object) -> bool:
    """Compare a JSON value without Python's bool/int equality coercion."""

    if type(observed) is not type(expected):
        return False
    if isinstance(expected, dict):
        observed_dict = cast(dict[object, object], observed)
        expected_dict = cast(dict[object, object], expected)
        return set(observed_dict) == set(expected_dict) and all(
            _exact_value_equal(observed_dict[key], expected_dict[key])
            for key in expected_dict
        )
    if isinstance(expected, list):
        observed_list = cast(list[object], observed)
        expected_list = cast(list[object], expected)
        return len(observed_list) == len(expected_list) and all(
            _exact_value_equal(item, expected_list[index])
            for index, item in enumerate(observed_list)
        )
    return observed == expected


def _bounded_text(
    value: object,
    field: str,
    maximum: int,
    *,
    allow_empty: bool,
) -> str:
    if not isinstance(value, str) or len(value) > maximum or (not value and not allow_empty):
        raise SecretRequestCreateContractError(f"{field} is not a bounded string.")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise SecretRequestCreateContractError(f"{field} contains a control character.")
    return value


def _positive_int32(value: object, field: str) -> int:
    if type(value) is not int or not 0 < value <= _MAX_INT32:
        raise SecretRequestCreateContractError(
            f"{field} must be a positive signed int32 value."
        )
    return value


def _timestamp(value: object, field: str) -> str:
    text = _bounded_text(value, field, 19, allow_empty=False)
    if _CMDB_TIMESTAMP.fullmatch(text) is None:
        raise SecretRequestCreateContractError(
            f"{field} must use the fixed CMDB timestamp shape."
        )
    try:
        datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise SecretRequestCreateContractError(
            f"{field} must be a valid CMDB timestamp."
        ) from exc
    return text


__all__ = [
    "FORTIPAM_BUILD",
    "FORTIPAM_VERSION",
    "FORTIPAM_700_BUILD",
    "FORTIPAM_700_SCHEMA_REF",
    "FORTIPAM_700_VERSION",
    "REQUEST_CREATE_METHOD",
    "REQUEST_CREATE_PATH",
    "REQUEST_CREATE_POST_QUERY",
    "REQUEST_DEFAULT_METHOD",
    "REQUEST_DEFAULT_QUERY",
    "REQUEST_SCHEMA_REF",
    "SecretRequestCreateContractError",
    "SecretRequestCreateInput",
    "SecretRequestCustomField",
    "SecretRequestDefaultEvidence",
    "validate_secret_request_default_response",
]
