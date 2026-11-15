"""Fixed FortiPAM 7.0 disabled-Job body compiler for a protected lab source.

The compiled body contains private Job/Secret selectors and script text. Keep
it inside the protected transport; never expose it through MCP or logs. This
module does not dispatch a request or grant Job creation authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import re

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest


_JOB_NAME = re.compile(r"mcp-v4-bp008-job-[0-9]{8}-r[1-9][0-9]*\Z")
_REQUESTER = re.compile(r"[A-Za-z][A-Za-z0-9._-]{0,63}\Z")
_SCRIPT = "echo BP008_JOB_OK"
_BODY_FIELDS = (
    "associated-secret", "job-sch-frequency", "job-sch-interval",
    "job-sch-month-day", "job-sch-month-type", "job-sch-start-date",
    "job-sch-week-day", "new-line-mode", "schedule", "scheduled-time",
    "script", "script-name", "script-type", "secret", "ssh-procedure",
    "status", "type", "user", "web-api-procedure", "web-proxy-port",
    "web-proxy-server",
)
_UNAVAILABLE = "The fixed disabled Job definition is unavailable."


class JobDefinitionCreateContractError(ValueError):
    """The protected source cannot compile one exact disabled Job body."""


def compile_disabled_job_create_body(
    source_detail: object,
    *,
    source_name: str,
    target_name: str,
    target_requester: str,
    expected_secret_id: int,
) -> dict[str, object]:
    """Clone only the observed 23-field GUI POST shape under fixed constraints.

    The caller must bind the target requester to its authenticated API identity,
    independently verify target absence, own a durable one-use dispatch claim,
    and reconcile the result. No network request occurs here.
    """

    try:
        if (
            not isinstance(source_detail, Mapping)
            or source_detail.get("status") != "success"
            or source_detail.get("version") not in {"v7.0.0", "7.0.0"}
            or type(source_detail.get("build")) is not int
            or source_detail.get("build") != 29
            or not isinstance(source_name, str)
            or not isinstance(target_name, str)
            or _JOB_NAME.fullmatch(source_name) is None
            or _JOB_NAME.fullmatch(target_name) is None
            or source_name == target_name
            or not isinstance(target_requester, str)
            or _REQUESTER.fullmatch(target_requester) is None
            or type(expected_secret_id) is not int
            or expected_secret_id <= 0
        ):
            raise ValueError
        results = source_detail.get("results")
        if isinstance(results, list):
            if len(results) != 1 or not isinstance(results[0], Mapping):
                raise ValueError
            source = results[0]
        elif isinstance(results, Mapping):
            source = results
        else:
            raise ValueError
        if (
            source.get("name") != source_name
            or source.get("user") != "admin"
            or type(source.get("secret")) is not int
            or source.get("secret") != expected_secret_id
            or source.get("associated-secret") != 0
            or source.get("status") != "disable"
            or source.get("type") != "ssh-script"
            or source.get("schedule") != "one-shot"
            or source.get("script-type") != "custom-script"
            or source.get("script-name") != ""
            or source.get("script") != _SCRIPT
            or source.get("approval-status") != "approved"
            or source.get("ssh-procedure") != []
            or source.get("web-api-procedure") != []
            or any(key not in source for key in _BODY_FIELDS)
            or not isinstance(source.get("scheduled-time"), str)
            or not isinstance(source.get("job-sch-start-date"), str)
        ):
            raise ValueError
        body = {key: source[key] for key in _BODY_FIELDS}
        body["name"] = target_name
        body["user"] = target_requester
        body["$originalName"] = ""
        return body
    except Exception:
        raise JobDefinitionCreateContractError(_UNAVAILABLE) from None


@dataclass(frozen=True, slots=True, repr=False)
class DisabledJobCreateAckPins(_OpaqueC3Object):
    """Private original-dispatch context; never provenance or authorization."""

    job_name: str
    serial_digest: str
    requester_digest: str
    body_digest: str
    plan_digest: str
    authorization_digest: str
    private_nonce: str

    def __post_init__(self) -> None:
        try:
            if type(self.job_name) is not str or _JOB_NAME.fullmatch(self.job_name) is None:
                raise ValueError
            for value in (self.serial_digest, self.requester_digest, self.body_digest,
                          self.plan_digest, self.authorization_digest, self.private_nonce):
                require_digest(value, "job_ack_context")
        except Exception:
            raise JobDefinitionCreateContractError(_UNAVAILABLE) from None

    @property
    def context_digest(self) -> str:
        self.__post_init__()
        return canonical_digest({"contract": "disabled-job-create-ack-build29/v1",
            "job_name": self.job_name, "serial_digest": self.serial_digest,
            "requester_digest": self.requester_digest, "body_digest": self.body_digest,
            "plan_digest": self.plan_digest, "authorization_digest": self.authorization_digest,
            "private_nonce": self.private_nonce})


@dataclass(frozen=True, slots=True, repr=False)
class DisabledJobCreateAcknowledgement(_OpaqueC3Object):
    """A private keyed response witness, not durable original-ACK custody."""

    context_digest: str
    acknowledgement_digest: str


def consume_disabled_job_create_ack(
    raw: bytearray, *, pins: DisabledJobCreateAckPins, http_status: int,
    content_type: str, witness_key: bytes | bytearray,
) -> DisabledJobCreateAcknowledgement:
    """Consume a strict POST-success candidate without decoding Job content.

    Reuse the existing bounded byte parser and erase the response on every path.
    Only fixed envelope scalars are decoded. The prospective trusted producer
    must bind these pins to the actual original request and M4 claim, persist
    the witness before post-read, and qualify this exact envelope on the device.
    This pure consumer performs no I/O and enables neither create nor recovery.
    A native success alone never proves disabled/pristine full-state readback.
    """
    from . import secret_bulk_import_metadata as metadata
    from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

    fields = frozenset({"version", "build", "http_method", "http_status", "status", "path",
        "name", "vdom", "serial", "mkey", "error", "action", "schema_errors", "results"})
    required = fields - {"error", "action", "schema_errors", "results"}
    try:
        if (type(raw) is not bytearray or not 0 < len(raw) <= 16_384
                or type(pins) is not DisabledJobCreateAckPins
                or type(http_status) is not int or http_status != 200
                or type(content_type) is not str or len(content_type) > 128
                or content_type.split(";", 1)[0].strip().lower() != "application/json"
                or type(witness_key) not in (bytes, bytearray) or witness_key is raw
                or not 32 <= len(witness_key) <= 128):
            raise ValueError
        context = pins.context_digest
        left = _skip_json_space(raw, 0)
        right = _json_value_end(raw, left)
        if _skip_json_space(raw, right) != len(raw):
            raise ValueError
        metadata._validate_json(raw, left, right, depth=0, budget=[50_000])
        spans = metadata._object_spans(raw, left, right, fields)
        if not required <= spans.keys() or {"action", "schema_errors", "results"} & spans.keys():
            raise ValueError
        expected: dict[str, str | int] = {"version": "v7.0.0", "build": 29, "http_method": "POST",
            "http_status": 200, "status": "success", "path": "secret", "name": "job",
            "vdom": "root", "mkey": pins.job_name}
        for key, wanted in expected.items():
            actual = metadata._scalar(raw, spans[key])
            if type(actual) is not type(wanted) or actual != wanted:
                raise ValueError
        serial = metadata._text(metadata._scalar(raw, spans["serial"]), maximum=128)
        if not hmac.compare_digest(hashlib.sha256(serial.encode()).hexdigest(), pins.serial_digest):
            raise ValueError
        if "error" in spans:
            error = metadata._scalar(raw, spans["error"])
            if type(error) is not int or error != 0:
                raise ValueError
        witness = hmac.new(witness_key, b"disabled-job-create-ack-build29/v1\x00"
            + context.encode("ascii") + b"\x00", hashlib.sha256)
        witness.update(raw)
        return DisabledJobCreateAcknowledgement(context, witness.hexdigest())
    except Exception:
        raise JobDefinitionCreateContractError(_UNAVAILABLE) from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)


def _observe_disabled_job_ack_shape(raw: bytearray, job_name: str) -> dict[str, str | int | bool]:
    """Minimize the original bounded response without decoding error text/Job data."""
    from . import secret_bulk_import_metadata as m
    from .secret_metadata_http_transport import _json_value_end, _skip_json_space
    observation: dict[str, str | int | bool] = {"response_digest": hashlib.sha256(raw).hexdigest(),
        "body_shape": "unqualified"}
    try:
        if type(raw) is not bytearray or not 0 < len(raw) <= 16384 or _JOB_NAME.fullmatch(job_name) is None:
            raise ValueError
        left = _skip_json_space(raw, 0); right = _json_value_end(raw, left)
        if _skip_json_space(raw, right) != len(raw):
            raise ValueError
        m._validate_json(raw, left, right, depth=0, budget=[50000])
        fields = m._object_spans(raw, left, right, frozenset({"status", "error", "mkey", "results", "action", "schema_errors"}))
        observation["body_shape"] = "json_object"
        observation["status_category"] = "unqualified"
        if "status" in fields:
            token = raw[slice(*fields["status"])]
            for label in ("success", "OK", "error", "forbidden"):
                if token == ('"' + label + '"').encode(): observation["status_category"] = label
        observation["error_code"] = "absent"
        if "error" in fields:
            token = raw[slice(*fields["error"])]
            if re.fullmatch(rb"-?(?:0|[1-9][0-9]{0,4})", token):
                observation["error_code"] = int(token)
            else:
                observation["error_code"] = "unqualified"
        import json
        observation["mkey_matches"] = "mkey" in fields and raw[slice(*fields["mkey"])] == json.dumps(job_name).encode()
        for key in ("results", "action", "schema_errors"):
            observation[key + "_present"] = key in fields
    except Exception:
        pass
    return observation
