"""Private build29 Web fixture creation join; no dispatch or cleanup authority.

Join the original in-process POST observation, its existing durable M4 terminal
record, and a separate byte-only metadata response. This is an inactive evidence
component. A fixed read producer, signed fixture admission and action-specific
recovery remain required; this module cannot create, attach or delete a Secret.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import uuid
from typing import cast

from v4_planning import M4ClaimState, M4Compensation, M4Outcome, M4Verification, canonical_digest
from v4_planning.material_provider import MaterialProviderClass, MaterialPurpose
from v4_planning.secret_create_adapter import SECRET_CREATE_ACTION_ID, SECRET_CREATE_ACTION_VERSION

from . import secret_bulk_import_metadata as metadata
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_191_http_transport import FortiPam191SecretCreateHttpTransport, WebSecretCreateDispatchObservation
from .secret_create_191_private_adapter import SecretCreate191WebBinding
from .secret_create_m4_runtime import SecretCreateM4ExecutionBinding
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

_ERROR = "The private Web fixture creation evidence is unavailable."
_ROW = frozenset({"id", "name", "folder", "template", "target", "inherit-permission",
                  "recording", "http-service-status", "uuid", "instruction-profile"})
_ENVELOPE = frozenset({"version", "build", "path", "name", "http_method", "status", "http_status",
                       "serial", "vdom", "results", "action", "error", "size", "matched_count",
                       "filtered_count", "limit_reached", "next_idx"})
_MAX_BYTES = 524_288
_DEFAULT_UUID = "00000000-0000-0000-0000-000000000000"


class WebSecretFixtureCreationError(ValueError):
    """Categorical refusal without selectors, native data or partial evidence."""


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretFixtureCreationEvidence:
    """Private minimized evidence. Its construction grants no operation rights."""

    native_secret_id: int
    serial_digest: str
    baseline_json: str
    baseline_digest: str
    execution_digest: str
    creation_digest: str

    def __repr__(self) -> str:
        return "<WebSecretFixtureCreationEvidence redacted>"

    __str__ = __repr__


def _project(raw: bytearray, *, serial_digest: str, binding: SecretCreate191WebBinding,
             folder_id: int, create_uuid: str) -> dict[str, object]:
    if (not 0 < len(raw) <= _MAX_BYTES or re.fullmatch(r"[a-f0-9]{64}", serial_digest) is None
            or create_uuid != _DEFAULT_UUID):
        raise ValueError
    start = _skip_json_space(raw, 0)
    end = _json_value_end(raw, start)
    if _skip_json_space(raw, end) != len(raw):
        raise ValueError
    metadata._validate_json(raw, start, end, depth=0, budget=[50_000])
    envelope = metadata._object_spans(raw, start, end, _ENVELOPE)
    for key, expected in {"version": "v7.0.0", "build": 29, "path": "secret", "name": "database",
                          "http_method": "GET", "status": "OK", "http_status": 200, "vdom": "root"}.items():
        value = metadata._scalar(raw, envelope[key])
        if type(value) is not type(expected) or value != expected:
            raise ValueError
    serial = metadata._text(metadata._scalar(raw, envelope["serial"]), maximum=128)
    if hashlib.sha256(serial.encode()).hexdigest() != serial_digest or "action" in envelope:
        raise ValueError
    if "error" in envelope:
        error = metadata._scalar(raw, envelope["error"])
        if type(error) is not int or error != 0:
            raise ValueError
    for key in ("size", "matched_count", "filtered_count", "next_idx"):
        if key in envelope:
            value = metadata._integer(metadata._scalar(raw, envelope[key]), zero=True)
            if key == "next_idx" and value != 0:
                raise ValueError
    if "limit_reached" in envelope and metadata._scalar(raw, envelope["limit_reached"]) is not False:
        raise ValueError
    matches: list[dict[str, object]] = []
    ids: set[int] = set()
    for span in metadata._array(raw, envelope["results"], 256):
        selected = metadata._object_spans(raw, *span, _ROW | {"q_origin_key"})
        identity = metadata._integer(metadata._scalar(raw, selected["id"]))
        name = metadata._text(metadata._scalar(raw, selected["name"]))
        if identity in ids:
            raise ValueError
        ids.add(identity)
        if name != binding.secret_name:
            continue
        if not _ROW <= set(selected):
            raise ValueError
        row = {key: metadata._scalar(raw, selected[key]) for key in _ROW}
        if "q_origin_key" in selected:
            origin = metadata._scalar(raw, selected["q_origin_key"])
            if not ((type(origin) is int and origin == identity)
                    or (type(origin) is str and origin == str(identity))):
                raise ValueError
        expected_row = {"name": binding.secret_name, "folder": folder_id, "template": "Web Account",
                        "target": "", "inherit-permission": "enable", "recording": "enable",
                        "http-service-status": "up", "instruction-profile": ""}
        if any(type(row[key]) is not type(value) or row[key] != value for key, value in expected_row.items()):
            raise ValueError
        # Build29 defaults use a zero placeholder; configured native UUIDs are
        # canonical and nonzero. This snapshot is a later drift anchor, never
        # proof that the request UUID was preserved or an ownership grant.
        native_uuid = row["uuid"]
        if (type(native_uuid) is not str or str(uuid.UUID(native_uuid)) != native_uuid
                or native_uuid == _DEFAULT_UUID):
            raise ValueError
        matches.append(row)
    if len(matches) != 1:
        raise ValueError
    return matches[0]


def _qualify_web_creation_execution(*, create_binding: SecretCreate191WebBinding,
        execution_binding: SecretCreateM4ExecutionBinding,
        execution_store: PersistentM4ExecutionStateStore,
        expected_store_digest: str) -> str:
    """Verify only original signed execution; no native observation is imported."""
    try:
        if (type(create_binding) is not SecretCreate191WebBinding
                or type(execution_binding) is not SecretCreateM4ExecutionBinding
                or type(execution_store) is not PersistentM4ExecutionStateStore):
            raise ValueError
        create_binding.__post_init__()
        if (create_binding.contract_ref != "fortipam-700-build29-web-secret-create-candidate-v1"
                or create_binding.target_product_version != "7.0.0" or create_binding.target_product_build != 29):
            raise ValueError
        store_digest = canonical_digest({"database": str(execution_store._path),
            "key_file": str(execution_store._key_path), "key_digest": hashlib.sha256(execution_store._key).hexdigest()})
        if store_digest != expected_store_digest:
            raise ValueError
        plan, authorization, request = (execution_binding.plan, execution_binding.authorization,
                                        execution_binding.lease_request)
        plan.__post_init__()
        authorization.__post_init__()
        request.__post_init__()
        if (plan.action_id != SECRET_CREATE_ACTION_ID or plan.action_version != SECRET_CREATE_ACTION_VERSION
                or authorization.plan_ref != plan.plan_ref or authorization.plan_digest != plan.plan_digest
                or authorization.requester_digest != plan.requester_digest
                or authorization.confirmation_digest != plan.confirmation_digest
                or authorization.approval_digest != plan.approval_digest
                or request.action_id != plan.action_id or request.action_version != plan.action_version
                or request.plan_digest != plan.plan_digest or create_binding.plan_digest != plan.plan_digest
                or request.authorization_digest != authorization.authorization_digest
                or request.policy_decision_digest != execution_binding.policy_decision_digest
                or request.scope_digest != execution_binding.scope_digest
                or request.audience_digest != execution_binding.audience_digest
                or request.purpose is not MaterialPurpose.INITIAL_ONBOARDING
                or request.provider_class is not MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE
                or request.requested_at < authorization.issued_at
                or request.expires_at > min(authorization.expires_at, plan.expires_at)):
            raise ValueError
        context = canonical_digest({"authorization_digest": authorization.authorization_digest,
                                    "plan_digest": plan.plan_digest, "revision": plan.revision})
        claim = execution_store.inspect_claim(plan_ref=plan.plan_ref,
            requester_digest=plan.requester_digest, idempotency_digest=plan.idempotency_digest,
            context_digest=context, authorization_digest=authorization.authorization_digest)
        if (claim.state is not M4ClaimState.REPLAY or claim.result is None
                or claim.result.outcome is not M4Outcome.SUCCEEDED
                or claim.result.verification is not M4Verification.VERIFIED
                or claim.result.compensation is not M4Compensation.NOT_REQUESTED
                or claim.result.idempotent_replay is not False):
            raise ValueError
        execution_digest = canonical_digest({"store": store_digest,
            "plan": plan.plan_digest, "plan_ref": plan.plan_ref, "requester": plan.requester_digest,
            "idempotency": plan.idempotency_digest, "authorization": authorization.authorization_digest,
            "context": context})
        return execution_digest
    except Exception:
        raise WebSecretFixtureCreationError(_ERROR) from None


def _qualify_original_web_creation(*, transport: FortiPam191SecretCreateHttpTransport,
        create_binding: SecretCreate191WebBinding, execution_binding: SecretCreateM4ExecutionBinding,
        execution_store: PersistentM4ExecutionStateStore,
        expected_store_digest: str) -> tuple[WebSecretCreateDispatchObservation, str]:
    """Read original evidence before any device I/O; never acquire or execute."""
    try:
        if type(transport) is not FortiPam191SecretCreateHttpTransport:
            raise ValueError
        execution_digest = _qualify_web_creation_execution(create_binding=create_binding,
            execution_binding=execution_binding, execution_store=execution_store,
            expected_store_digest=expected_store_digest)
        observation = transport.read_web_create_dispatch_observation(create_binding, execution_binding.lease_request)
        if observation is None or observation.create_uuid != _DEFAULT_UUID:
            raise ValueError
        return observation, execution_digest
    except Exception:
        raise WebSecretFixtureCreationError(_ERROR) from None


def join_web_secret_fixture_creation(*, transport: FortiPam191SecretCreateHttpTransport,
        create_binding: SecretCreate191WebBinding, execution_binding: SecretCreateM4ExecutionBinding,
        execution_store: PersistentM4ExecutionStateStore, response: bytearray,
        serial_digest: str, expected_store_digest: str) -> WebSecretFixtureCreationEvidence:
    """Consume a private metadata buffer; never recreate or dispatch an M4 claim.

    Expiry does not erase historical success. Original plan/authorization/request
    and keyed ledger namespace are checked without acquiring C3 or executing M4.
    expected_store_digest is a protected startup binding fixed before the POST.
    Caller-provided success booleans and imported observations are not accepted.
    """
    try:
        if type(response) is not bytearray:
            raise ValueError
        observation, execution_digest = _qualify_original_web_creation(
            transport=transport, create_binding=create_binding, execution_binding=execution_binding,
            execution_store=execution_store, expected_store_digest=expected_store_digest)
        request = execution_binding.lease_request
        row = _project(response, serial_digest=serial_digest, binding=create_binding,
                       folder_id=observation.native_folder_id, create_uuid=observation.create_uuid)
        if observation.native_ack is not None:
            if (observation.native_ack.native_secret_id != row["id"]
                    or observation.native_ack.serial_digest != serial_digest):
                raise ValueError
        baseline = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
        # Native metadata legitimately includes empty strings. Preserve its
        # exact qualified values instead of passing it through M2 normalization.
        baseline_digest = hashlib.sha256(b"private-web-fixture-baseline/v1\0" + baseline.encode("ascii")).hexdigest()
        creation_digest = canonical_digest({"execution": execution_digest, "baseline": baseline_digest,
            "origin": observation.origin, "serial": serial_digest, "scope": request.scope_digest,
            "audience": request.audience_digest, "policy": request.policy_decision_digest})
        return WebSecretFixtureCreationEvidence(cast(int, row["id"]), serial_digest, baseline,
                                                baseline_digest, execution_digest, creation_digest)
    except Exception:
        raise WebSecretFixtureCreationError(_ERROR) from None
    finally:
        if type(response) is bytearray:
            _zeroize_mutable(response)
