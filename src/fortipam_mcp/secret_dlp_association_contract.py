"""Private build-29 fixed log-only DLP delta; no dispatch authority.

The final private reader must redact field values before this projection and
provide fresh opaque-field witnesses and non-material field descriptors. The
returned delta is not a complete native save body or an MCP result. A future
adapter must retain the separately qualified native body and opaque carrier.
"""

from collections.abc import Mapping
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re
from typing import Literal, TypedDict


REGEXP_SENTINEL = "MCP_V4_DLP_REGEX_SENTINEL"
FILTER_NAME = "mcp-v4-dlp-file-audit"
_IDENTITY = frozenset({"id", "name", "folder", "template"})
_DLP = frozenset({"dlp-status", "dlp-sensor"})
_PRESERVED = frozenset({"target", "description", "proxy", "recording",
                        "ssh-service-status", "sftp-service-status",
                        "ssh-filter", "ssh-filter-profile"})
_ENVELOPE = {"version": "v7.0.0", "build": 29, "http_method": "GET",
             "http_status": 200, "path": "secret", "name": "database"}
_SENSOR_NAME = re.compile(r"mcp-v4-dlp-sftp-audit-[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_SECRET_NAME = re.compile(r"mcp-v4-bp005-dlp-audit-[A-Za-z0-9][A-Za-z0-9._-]*\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_UNAVAILABLE = "The fixed Secret DLP association is unavailable."


FixedLogOnlyDlpFilter = TypedDict("FixedLogOnlyDlpFilter", {
    "id": int, "name": str, "type": str, "proto": str, "filter-by": str,
    "regexp": str, "file-size": int, "file-type": int,
    "sensitivity": list[dict[str, str]], "action": str, "archive": str,
    "severity": str, "direction": str, "company-identifier": str,
    "match-percentage": int, "expiry": str,
})
FixedLogOnlySensorProfile = TypedDict("FixedLogOnlySensorProfile", {
    "name": str, "comment": str, "dlp-log": str, "extended-log": str,
    "nac-quar-log": str, "full-archive-proto": str, "summary-proto": str, "replacemsg-group": str,
    "filter": list[FixedLogOnlyDlpFilter],
})


class SecretDlpAssociationContractError(ValueError):
    """Non-disclosing rejection of unqualified state or preservation evidence."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretDlpAssociationIdentity:
    id: int
    name: str
    folder: int
    template: str
    target: str


@dataclass(frozen=True, slots=True, repr=False)
class SecretDlpAssociationInspection:
    """Immutable private snapshots, without field values or keyinfo."""

    identity: SecretDlpAssociationIdentity
    sensor_name: str
    phase: Literal["baseline", "associated"]
    actor_digest: str
    preservation_digest: str
    opaque_field_digest: str
    redacted_metadata_witness_digest: str
    sensor_digest: str
    state_digest: str
    projected_secret_json: str
    native_sensor_json: str


@dataclass(frozen=True, slots=True, repr=False)
class SecretDlpAssociationReadback:
    acknowledged: bool
    logout_verified: bool
    opaque_fields_match: bool
    after: SecretDlpAssociationInspection | None


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    allow_nan=False).encode()).hexdigest()


def _valid_digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _valid_id(value: object) -> bool:
    return type(value) is int and 0 < value <= 2_147_483_647


def _qualified(payload: object, *, path: str, name: str) -> Mapping[str, object]:
    expected = {**_ENVELOPE, "path": path, "name": name}
    if (not isinstance(payload, Mapping) or any(
            type(payload.get(key)) is not type(value) or payload.get(key) != value
            for key, value in expected.items()) or payload.get("status") not in {"OK", "success"}):
        raise ValueError
    row = payload.get("results")
    if isinstance(row, list) and len(row) == 1:
        row = row[0]
    if not isinstance(row, Mapping):
        raise ValueError
    return row


def _credential_shape(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) not in {2, 3}:
        raise ValueError
    expected = {"Username": "username", "Password": "password", "Host": "target-address"}
    descriptors = []
    for item in value:
        if (not isinstance(item, Mapping) or set(item) != {"id", "name", "type"}
                or type(item["id"]) is not int or not 0 < item["id"] <= 2_147_483_647
                or type(item["name"]) is not str or item["name"] not in expected
                or type(item["type"]) is not str or item["type"] != expected[item["name"]]):
            raise ValueError
        descriptors.append(dict(item))
    names = {item["name"] for item in descriptors}
    if (names not in ({"Username", "Password"}, {"Host", "Username", "Password"})
            or len(names) != len(descriptors)
            or len({item["id"] for item in descriptors}) != len(descriptors)):
        raise ValueError
    return sorted(descriptors, key=lambda item: str(item["name"]))


def project_secret_dlp_metadata(
    payload: object, *, credential_shape: object, opaque_field_digest: str,
) -> dict[str, object]:
    """Minimize a freshly qualified redacted read and witness all other metadata.

    The field digest is a private reader's opaque witness, not a claim that a
    stored password was recovered. Neither values nor keyinfo enter here.
    """
    try:
        if not isinstance(payload, Mapping):
            raise ValueError
        row = _qualified(payload, path="secret", name="database")
        if (row.get("field", object()) is not None
                or not (_IDENTITY | _DLP | _PRESERVED).issubset(row)
                or not _valid_digest(opaque_field_digest)):
            raise ValueError
        preserved = {key: value for key, value in row.items() if key not in _DLP | {"field"}}
        projected = {key: row[key] for key in _IDENTITY | _DLP | _PRESERVED}
        metadata_digest = _digest(preserved)
        return {**_ENVELOPE, "status": payload["status"],
                "results": projected, "metadata_digest": metadata_digest,
                "preservation_digest": _preservation_digest(projected, metadata_digest),
                "credential_shape": _credential_shape(credential_shape),
                "opaque_field_digest": opaque_field_digest}
    except Exception:
        raise SecretDlpAssociationContractError(_UNAVAILABLE) from None


def _preservation_digest(row: Mapping[str, object], metadata_digest: str) -> str:
    return _digest({"metadata_digest": metadata_digest,
                    "projection": {key: value for key, value in row.items() if key not in _DLP}})


def fixed_log_only_sensor_profile(*, sensor_name: str) -> FixedLogOnlySensorProfile:
    """Return the one canonical profile, including every qualified safe default.

    Native build-29 schema/default r3 establishes the full defaults. The public
    DLP serializer joins selected protocols with one space and lowercases them.
    Constructing this profile does not prove that a Sensor exists or was saved.
    """
    if (type(sensor_name) is not str or len(sensor_name) > 35
            or _SENSOR_NAME.fullmatch(sensor_name) is None):
        raise SecretDlpAssociationContractError(_UNAVAILABLE)
    return {"name": sensor_name, "comment": "", "dlp-log": "enable",
            "extended-log": "disable", "nac-quar-log": "disable",
            "full-archive-proto": "", "summary-proto": "",
            "replacemsg-group": "", "filter": [{
                "id": 1, "name": FILTER_NAME, "type": "file", "proto": "http-get http-post",
                "filter-by": "regexp", "regexp": REGEXP_SENTINEL, "file-size": 10,
                "file-type": 0, "sensitivity": [], "action": "log-only", "archive": "disable",
                "severity": "medium", "direction": "uplink", "company-identifier": "",
                "match-percentage": 10, "expiry": "5m"}]}


def fixed_log_only_sensor_digest(sensor: object, *, expected_sensor_name: str) -> str:
    """Qualify an existing native Sensor snapshot, never a default or attestation.

    Routing origins are required and type-checked independently. Native regexp
    reads may omit only the inactive file-size and match-percentage defaults;
    their exact defaults are restored for the canonical digest. Every other
    configuration member remains mandatory and unknown members are rejected.
    """
    try:
        row = _qualified(sensor, path="dlp", name="sensor")
        expected = fixed_log_only_sensor_profile(sensor_name=expected_sensor_name)
        if (set(row) != set(expected) | {"q_origin_key"}
                or type(row["q_origin_key"]) is not str or row["q_origin_key"] != expected_sensor_name):
            raise ValueError
        filters = row["filter"]
        if not isinstance(filters, list) or len(filters) != 1 or not isinstance(filters[0], Mapping):
            raise ValueError
        native_filter = filters[0]
        expected_filter = expected["filter"][0]
        inactive_defaults = {"file-size": expected_filter["file-size"],
                             "match-percentage": expected_filter["match-percentage"]}
        inactive = set(inactive_defaults)
        if (not (set(expected_filter) - inactive | {"q_origin_key"}).issubset(native_filter)
                or not set(native_filter).issubset(set(expected_filter) | {"q_origin_key"})
                or type(native_filter["q_origin_key"]) is not int
                or native_filter["q_origin_key"] != expected_filter["id"]):
            raise ValueError
        normalized_filter = {key: value for key, value in native_filter.items() if key != "q_origin_key"}
        for key, value in inactive_defaults.items():
            if key not in normalized_filter:
                normalized_filter[key] = value
        normalized = {key: value for key, value in row.items() if key != "q_origin_key"}
        normalized["filter"] = [normalized_filter]
        # JSON equality alone accepts bool as integer; bind canonical types too.
        if _digest(normalized) != _digest(expected):
            raise ValueError
        return _digest(expected)
    except Exception:
        raise SecretDlpAssociationContractError(_UNAVAILABLE) from None


def compile_fixed_secret_dlp_body(
    before: object, sensor: object, *, identity: Mapping[str, object],
    expected_sensor_name: str, expected_sensor_digest: str,
    expected_preservation_digest: str, expected_credential_shape: object,
    expected_opaque_field_digest: str, restore: bool = False,
) -> dict[str, object]:
    """Enable one qualified Sensor, or restore disable plus its empty reference."""
    try:
        if (not isinstance(before, Mapping) or type(restore) is not bool or not isinstance(identity, Mapping)
                or set(identity) != _IDENTITY
                or any(not _valid_id(identity[key]) for key in ("id", "folder"))
                or identity["template"] != "Unix Account (SSH Password)"
                or type(identity["name"]) is not str or len(identity["name"].encode()) > 255
                or _SECRET_NAME.fullmatch(identity["name"]) is None):
            raise ValueError
        if any(not _valid_digest(value) for value in (
                expected_sensor_digest, expected_preservation_digest, expected_opaque_field_digest)):
            raise ValueError
        sensor_digest = fixed_log_only_sensor_digest(sensor, expected_sensor_name=expected_sensor_name)
        row = _qualified(before, path="secret", name="database")
        if (set(before) != set(_ENVELOPE) | {"status", "results", "metadata_digest", "preservation_digest",
                                          "credential_shape", "opaque_field_digest"}
                or set(row) != _IDENTITY | _DLP | _PRESERVED
                or any(type(row[key]) is not type(value) or row[key] != value
                       for key, value in identity.items())
                or any(type(row[key]) is not str or row[key] != "enable" for key in ("proxy", "recording"))
                or any(type(row[key]) is not str or row[key] != "up" for key in (
                    "ssh-service-status", "sftp-service-status"))
                or row["ssh-filter"] != "disable" or row["ssh-filter-profile"] != ""
                or type(row["target"]) is not str or not row["target"]
                or type(row["description"]) is not str
                or not hmac.compare_digest(sensor_digest, expected_sensor_digest)
                or not _valid_digest(before["metadata_digest"])
                or _preservation_digest(row, before["metadata_digest"]) != expected_preservation_digest
                or before["preservation_digest"] != expected_preservation_digest
                or before["opaque_field_digest"] != expected_opaque_field_digest
                or _credential_shape(before["credential_shape"]) != _credential_shape(expected_credential_shape)):
            raise ValueError
        current = {"dlp-status": "enable", "dlp-sensor": expected_sensor_name} if restore else {
            "dlp-status": "disable", "dlp-sensor": ""}
        if any(type(row[key]) is not str or row[key] != value for key, value in current.items()):
            raise ValueError
        proposed = {"dlp-status": "disable", "dlp-sensor": ""} if restore else {
            "dlp-status": "enable", "dlp-sensor": expected_sensor_name}
        return {**identity, **proposed}
    except Exception:
        raise SecretDlpAssociationContractError(_UNAVAILABLE) from None


def qualify_secret_dlp_association_inspection(
    projected_secret: object, native_sensor: object, *, identity: SecretDlpAssociationIdentity,
    sensor_name: str, actor_digest: str, redacted_metadata_witness_digest: str,
) -> SecretDlpAssociationInspection:
    """Qualify fresh private source snapshots; constructing a profile is insufficient."""
    try:
        if (type(identity) is not SecretDlpAssociationIdentity or not isinstance(projected_secret, Mapping)
                or not isinstance(native_sensor, Mapping) or not _valid_digest(actor_digest)
                or not _valid_digest(redacted_metadata_witness_digest)):
            raise ValueError
        row = _qualified(projected_secret, path="secret", name="database")
        if type(identity.target) is not str or not identity.target or row.get("target") != identity.target:
            raise ValueError
        phase: Literal["baseline", "associated"] = "associated" if row.get("dlp-status") == "enable" else "baseline"
        sensor_digest = fixed_log_only_sensor_digest(native_sensor, expected_sensor_name=sensor_name)
        selectors = {key: value for key, value in asdict(identity).items() if key != "target"}
        compile_fixed_secret_dlp_body(
            projected_secret, native_sensor, identity=selectors, expected_sensor_name=sensor_name,
            expected_sensor_digest=sensor_digest,
            expected_preservation_digest=projected_secret["preservation_digest"],
            expected_credential_shape=projected_secret["credential_shape"],
            expected_opaque_field_digest=projected_secret["opaque_field_digest"], restore=phase == "associated",
        )
        sensor_snapshot = {**_ENVELOPE, "path": "dlp", "name": "sensor", "status": native_sensor["status"],
                           "results": _qualified(native_sensor, path="dlp", name="sensor")}
        projection_json = json.dumps(projected_secret, sort_keys=True, separators=(",", ":"), allow_nan=False)
        sensor_json = json.dumps(sensor_snapshot, sort_keys=True, separators=(",", ":"), allow_nan=False)
        state_digest = _digest({"identity": asdict(identity), "sensor_name": sensor_name, "phase": phase,
                                "actor_digest": actor_digest, "projection": projected_secret,
                                "redacted_metadata_witness_digest": redacted_metadata_witness_digest,
                                "sensor_digest": sensor_digest, "native_sensor_snapshot": sensor_snapshot})
        return SecretDlpAssociationInspection(
            identity, sensor_name, phase, actor_digest, projected_secret["preservation_digest"],
            projected_secret["opaque_field_digest"], redacted_metadata_witness_digest, sensor_digest,
            state_digest, projection_json, sensor_json,
        )
    except Exception:
        raise SecretDlpAssociationContractError(_UNAVAILABLE) from None


def validate_secret_dlp_association_inspection(value: object) -> SecretDlpAssociationInspection:
    """Requalify immutable snapshots and their witnesses, never a boolean attestation."""
    try:
        if type(value) is not SecretDlpAssociationInspection:
            raise ValueError
        qualified = qualify_secret_dlp_association_inspection(
            json.loads(value.projected_secret_json), json.loads(value.native_sensor_json), identity=value.identity,
            sensor_name=value.sensor_name, actor_digest=value.actor_digest,
            redacted_metadata_witness_digest=value.redacted_metadata_witness_digest,
        )
        if qualified != value:
            raise ValueError
        return qualified
    except Exception:
        raise SecretDlpAssociationContractError(_UNAVAILABLE) from None
