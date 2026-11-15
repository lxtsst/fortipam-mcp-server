"""Inactive fixed original-row UDS channel; ledger/signing keys stay owner-side."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
import hashlib
import hmac
from pathlib import Path
import secrets
import threading
import time
from typing import Callable, TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan, M4Verification, canonical_digest
from v4_planning.execution_kernel import (
    M4Claim, M4ClaimState, M4Outcome, M4Compensation, _ACTIVE_DISPATCH, _M4DispatchScope, _require_m4_dispatch_ownership,
    _reserve_m4_material_acquisition,
)
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.import_parent import FileImportParentRecord
from .target_create_lifecycle import TargetCreateLifecycle
from .target_coordinate_lifecycle import TargetCoordinateLifecycle
from .secret_bulk_import_parent_graph import _OriginalImportTargetReuse
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_runtime import MaterialRuntimeOutcome, MaterialUseClaim, MaterialUseClaimState
from v4_planning.models import require_digest
from v4_planning.persistence import PersistentProtectedPlanningStore
from v4_planning.store import OriginalImportBindingRecord, OriginalImportRowAckRecord

from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_bulk_import_file import _read_owned, _SourceIdentity, _wipe
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR
from .secret_bulk_import_row_authority import (
    PinnedOriginalRowAcquisitionAuthority, _OriginalRowPermissionPins, _original_material_request_digest,
)
from .secret_bulk_import_row_loader import _PreboundOriginalImportRowLoader
from .secret_bulk_import_row_namespace import OriginalImportOperation, OriginalImportRow, PinnedOriginalImportRows
from .secret_bulk_import_session import _OwnerFileSourceSession
from .secret_bulk_import_token_channel import (
    IntakeTokenChannelBinding, _ChannelLifetime, _PinnedKey, _body, _canonical,
    _envelope, _socket_identity, _NONCE, _MAX_FRAME,
)
from .web_secret_create_ack import WebSecretCreateAckCapture, WebSecretCreateAcknowledgement, _ack_digest

if TYPE_CHECKING:
    from .secret_bulk_import_row_adapter import _OriginalRowSecretCreateAdapter, _OriginalRowUseContext

CONTRACT = "fortipam-owner-file-original-row-channel-v1"
_PREFIX = "/v1/owner-file-original-row/"
_REQUEST_DOMAIN = (CONTRACT + "/request\0").encode()
_RESPONSE_DOMAIN = (CONTRACT + "/response\0").encode()


@dataclass(frozen=True, slots=True, repr=False)
class _OriginalRowAckPins(_OpaqueC3Object):
    """Trusted composition pins, not a grant or native-response proof."""

    row: OriginalImportRow
    defaults_digest: str
    capture: WebSecretCreateAckCapture

    def __post_init__(self) -> None:
        if (type(self.row) is not OriginalImportRow or type(self.capture) is not WebSecretCreateAckCapture
                or self.capture.observe_source or type(self.row.index) is not int or not 0 <= self.row.index < 256):
            raise BulkImportIntakeError(_ERROR)
        self.capture.__post_init__()
        require_digest(self.defaults_digest, "original default")

    def digest(self) -> str:
        self.__post_init__()
        return canonical_digest({"row": asdict(self.row), "defaults": self.defaults_digest,
                                 "ack_source": self.capture.source_digest})


def _original_ack_record(binding: OriginalRowChannelBinding, pins: _OriginalRowAckPins,
                         parent: OriginalImportBindingRecord,
                         ack: WebSecretCreateAcknowledgement) -> OriginalImportRowAckRecord:
    pins.__post_init__()
    pins.row.verify_m4_plan(binding.plan)
    if (binding.ack_pins_digest != pins.digest() or type(ack) is not WebSecretCreateAcknowledgement
            or ack.serial_digest != pins.capture.serial_digest or ack.observed_status is not None
            or type(ack.native_secret_id) is not int or not 1 <= ack.native_secret_id < 2**31
            or ack.acknowledgement_digest != _ack_digest(ack.native_secret_id, pins.capture)
            or parent.plan_ref != binding.plan.plan_ref or parent.plan_digest != binding.parent_digest
            or parent.requester_digest != binding.plan.requester_digest
            or parent.namespace_key_digest != binding.namespace_key_digest or pins.row.index >= parent.row_count):
        raise BulkImportIntakeError(_ERROR)
    plan, auth, row = binding.plan, binding.authorization, pins.row
    return OriginalImportRowAckRecord(plan_ref=plan.plan_ref,
        parent_binding_digest=canonical_digest(parent.as_dict()), requester_digest=plan.requester_digest,
        row_index=row.index, idempotency_digest=row.idempotency_digest, parameters_digest=row.parameters_digest,
        child_plan_digest=plan.plan_digest, child_revision=plan.revision, authorization_digest=auth.authorization_digest,
        context_digest=canonical_digest({"authorization_digest": auth.authorization_digest,
                                        "plan_digest": plan.plan_digest, "revision": plan.revision}),
        serial_digest=ack.serial_digest, defaults_digest=pins.defaults_digest,
        ack_source_digest=pins.capture.source_digest, acknowledgement_digest=ack.acknowledgement_digest,
        native_secret_id=ack.native_secret_id)


@dataclass(frozen=True, slots=True, repr=False)
class OriginalRowChannelBinding(_OpaqueC3Object):
    source: OwnerFileIntakeBinding
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    parent_digest: str
    namespace_key_digest: str
    permission: _OriginalRowPermissionPins
    material_requested_at: int | None = None
    material_expires_at: int | None = None
    ack_pins_digest: str | None = None

    def __post_init__(self) -> None:
        if (type(self.source) is not OwnerFileIntakeBinding or type(self.plan) is not M4ExecutionPlan
                or type(self.authorization) is not M4ExecutionAuthorization
                or type(self.permission) is not _OriginalRowPermissionPins):
            raise BulkImportIntakeError(_ERROR)
        if (self.material_requested_at is None) != (self.material_expires_at is None):
            raise BulkImportIntakeError(_ERROR)
        if self.material_requested_at is not None:
            if self.material_expires_at is None:
                raise BulkImportIntakeError(_ERROR)
            _original_material_request_digest(self.permission, self.material_requested_at, self.material_expires_at)
            if self.material_expires_at > self.source.expires_at:
                raise BulkImportIntakeError(_ERROR)
        self.source.__post_init__()
        self.plan.__post_init__()
        self.authorization.__post_init__()
        self.permission.__post_init__()
        if self.ack_pins_digest is not None:
            require_digest(self.ack_pins_digest, "original ACK pins")
            if self.material_requested_at is None:
                raise BulkImportIntakeError(_ERROR)
        require_digest(self.parent_digest, "original parent")
        require_digest(self.namespace_key_digest, "original key")
        if (self.authorization.plan_ref != self.plan.plan_ref
                or self.authorization.plan_digest != self.plan.plan_digest
                or self.authorization.requester_digest != self.plan.requester_digest
                or self.permission.plan != self.plan or self.permission.authorization != self.authorization
                or self.permission.scope_digest != self.source.scope_digest):
            raise BulkImportIntakeError(_ERROR)

    def context_digest(self) -> str:
        # Raw paths/file hashes and source material never cross this channel.
        content = {"contract": CONTRACT, "plan": self.plan.plan_digest,
            "authorization": self.authorization.authorization_digest, "parent": self.parent_digest,
            "namespace_key": self.namespace_key_digest, "deployment": self.source.deployment_digest,
            "workload": self.source.workload_digest, "batch": self.source.batch_digest,
            "permission": asdict(self.permission), "material_requested_at": self.material_requested_at,
            "material_expires_at": self.material_expires_at}
        if self.ack_pins_digest is not None:
            content["ack_pins"] = self.ack_pins_digest
        return canonical_digest(content)

    def lifetime_binding(self) -> IntakeTokenChannelBinding:
        return IntakeTokenChannelBinding(self.source.issuer, self.source.planning_resource,
            self.source.intake_resource, self.source.deployment_digest, self.source.workload_digest,
            max(self.source.issued_at, self.authorization.issued_at),
            min(self.source.expires_at, self.authorization.expires_at, self.plan.expires_at,
                self.material_expires_at or self.source.expires_at))


class OriginalRowChannelOwner(_OpaqueC3Object):
    """Owner-side original records and one transient NEW dispatch, no new journal."""

    def __init__(self, binding: OriginalRowChannelBinding, parent: PersistentProtectedPlanningStore,
                 execution: PersistentM4ExecutionStateStore, permission: PinnedOriginalRowAcquisitionAuthority,
                 *, material_store: PersistentMaterialUseStateStore | None = None,
                 ack_pins: _OriginalRowAckPins | None = None,
                 dependency_owners: tuple[OriginalRowChannelOwner, ...] = (),
                 target_owners: tuple[TargetCreateLifecycle | TargetCoordinateLifecycle | _OriginalImportTargetReuse, ...] = (),
                 clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(binding) is not OriginalRowChannelBinding
                    or type(parent) is not PersistentProtectedPlanningStore
                    or type(execution) is not PersistentM4ExecutionStateStore
                    or not execution.monotonic_checkpoint_protocol_bound
                    or type(permission) is not PinnedOriginalRowAcquisitionAuthority
                    or permission._source != binding.source or permission._pins.plan != binding.plan
                    or permission._pins.authorization != binding.authorization
                    or permission._pins != binding.permission):
                raise ValueError
            binding.__post_init__()
            if ack_pins is not None:
                if type(ack_pins) is not _OriginalRowAckPins or binding.ack_pins_digest != ack_pins.digest():
                    raise ValueError
                ack_pins.row.verify_m4_plan(binding.plan)
            elif binding.ack_pins_digest is not None:
                raise ValueError
            if (binding.material_requested_at is None) != (material_store is None):
                raise ValueError
            if material_store is not None:
                if (type(material_store) is not PersistentMaterialUseStateStore
                        or not material_store.monotonic_checkpoint_protocol_bound
                        or material_store._path in {parent._path, execution._path}
                        or material_store._key_path in {parent._key_path, execution._key_path}
                        or hashlib.sha256(material_store._key).hexdigest() == binding.namespace_key_digest
                        or any(hmac.compare_digest(material_store._key, key) for key in (parent._key, execution._key))):
                    raise ValueError
            self._binding, self._parent, self._execution, self._permission = binding, parent, execution, permission
            self._create_check_attempted = False
            if (type(dependency_owners) is not tuple or len(dependency_owners) > 1
                    or any(type(owner) is not OriginalRowChannelOwner or owner is self
                           or owner._parent is not parent or owner._execution is not execution
                           for owner in dependency_owners)):
                raise ValueError
            self._dependency_owners = dependency_owners
            if (type(target_owners) is not tuple or len(target_owners) > 1
                    or any(not (
                        type(owner) is TargetCreateLifecycle and owner._store is execution
                        and owner._authority._original_import is not None
                        and owner._authority._original_import._parent_store is parent
                        or type(owner) is TargetCoordinateLifecycle and owner._phase == 'update'
                        and owner._store is execution and owner._import is not None
                        and owner._import._parent_store is parent
                        or type(owner) is _OriginalImportTargetReuse and owner._parent_store is parent)
                        for owner in target_owners)):
                raise ValueError
            self._target_owners = target_owners
            self._parent_prepared = False
            self._clock = clock
            self._scope: _M4DispatchScope | None = None
            self._load_nonce: str | None = None
            self._material_store = material_store
            self._material_key_identity: _SourceIdentity | None = None
            self._material_nonce: str | None = None
            self._material_claim: MaterialUseClaim | None = None
            self._material_finished = False
            self._ack_pins, self._ack_attempted = ack_pins, False
            self._readback_lifetime = (None if ack_pins is None else
                _ChannelLifetime(binding.lifetime_binding(), clock, time.monotonic))
            self._lock = threading.RLock()
            if material_store is not None:
                self._verify_material_key()
            self._record()
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _record(self) -> OriginalImportBindingRecord:
        b = self._binding
        record = self._parent.get_original_import_binding(b.plan.plan_ref,
            expected_plan_digest=b.parent_digest, requester_digest=b.plan.requester_digest,
            namespace_key_digest=b.namespace_key_digest)
        parent = self._parent.get_import_parent(b.plan.plan_ref)
        if type(parent) is FileImportParentRecord:
            lines = [line for line in parent.lines if line.kind == 'secret'
                     and line.idempotency_digest == b.plan.idempotency_digest]
            if (len(lines) != 1 or lines[0].parameters_digest != b.plan.parameters_digest
                    or b.plan.summary_digest != parent.plan_digest
                    or b.plan.confirmation_digest != parent.intent_policy_digest
                    or b.plan.expires_at > parent.expires_at
                    or parent.environment_digest != b.source.deployment_digest
                    or parent.scope_digest != b.source.scope_digest):
                raise BulkImportIntakeError(_ERROR)
        return record

    def prepare_original_dispatch(self) -> None:
        """Independent admission; the native kernel performs the fresh device read."""
        with self._lock:
            self._parent_prepared = False
            try:
                if self._scope is not None or _ACTIVE_DISPATCH.get() is not None:
                    raise ValueError
                now = self._clock()
                b = self._binding
                from .secret_bulk_import_row_current import _OriginalRowNativeCurrent
                reader: object = self._permission._reader
                if type(reader) is _OriginalRowNativeCurrent:
                    checker = self._permission._checker
                    checker(b.source, canonical_digest(checker._reference), now)
                    reader._check_plan(b.plan)
                    reader._check_original()
                else:
                    self._permission.verify_row_acquisition(b.plan, b.authorization, b.source, now_epoch=now)
                self._verify_parent_forward(now, claimed=False)
                if type(reader) is _OriginalRowNativeCurrent:
                    checker(b.source, canonical_digest(checker._reference), self._clock())
                self._parent_prepared = True
            except Exception:
                raise BulkImportIntakeError(_ERROR) from None

    def _verify_parent_forward(self, now: int, *, claimed: bool = True) -> dict[str, str | int]:
        """Stop before acquisition on parent drift, occupied siblings or unknowns.

        Existing Target lifecycle ownership must be joined before Target-dependent
        rows can use this path. A verified M4 status alone is never that proof.
        """
        b = self._binding
        self._record()
        parent = self._parent.get_import_parent(b.plan.plan_ref)
        if type(parent) is not FileImportParentRecord:
            if self._dependency_owners or self._target_owners:
                raise BulkImportIntakeError(_ERROR)
            return {}
        if type(now) is not int or not parent.created_at <= now < parent.expires_at:
            raise BulkImportIntakeError(_ERROR)
        if claimed and not self._parent_prepared:
            raise BulkImportIntakeError(_ERROR)
        mutations = tuple(line for line in parent.lines if line.idempotency_digest is not None)
        ids = tuple(line.idempotency_digest for line in mutations if line.idempotency_digest is not None)
        claims = self._execution._inspect_original_claims(plan_ref=parent.plan_ref,
            requester_digest=parent.requester_digest, idempotency_digests=ids)
        selected = next(line for line in mutations if line.idempotency_digest == b.plan.idempotency_digest)
        for line, claim in zip(mutations, claims, strict=True):
            if line == selected:
                if claim.state is not (M4ClaimState.IN_PROGRESS if claimed else M4ClaimState.NEW):
                    raise BulkImportIntakeError(_ERROR)
            elif claim.state is not M4ClaimState.NEW:
                result = claim.result
                if (claim.state is not M4ClaimState.REPLAY or result is None
                        or result.outcome is not M4Outcome.SUCCEEDED
                        or result.verification is not M4Verification.VERIFIED
                        or result.compensation is not M4Compensation.NOT_REQUESTED):
                    raise BulkImportIntakeError(_ERROR)
        dependencies = {line.line_ref: line for line in parent.lines if line.line_ref in selected.depends_on}
        if len(dependencies) != len(self._dependency_owners) + len(self._target_owners):
            raise BulkImportIntakeError(_ERROR)
        verified = set()
        selectors: dict[str, str | int] = {}
        for owner in self._dependency_owners:
            ack = owner._inspect_verified_ack()
            matched = [line for line in dependencies.values() if line.kind == 'secret'
                       and line.idempotency_digest == ack.idempotency_digest
                       and line.parameters_digest == ack.parameters_digest and line.index == ack.row_index]
            if (len(matched) != 1 or ack.plan_ref != parent.plan_ref
                    or ack.requester_digest != parent.requester_digest or matched[0].line_ref in verified):
                raise BulkImportIntakeError(_ERROR)
            verified.add(matched[0].line_ref)
            selectors[matched[0].line_ref] = ack.native_secret_id
        for target_owner in self._target_owners:
            target_binding = (target_owner if isinstance(target_owner, _OriginalImportTargetReuse)
                              else target_owner._authority._original_import)
            if (target_binding is None or target_binding.parent != parent
                    or dependencies.get(target_binding.line.line_ref) != target_binding.line
                    or target_binding.line.line_ref in verified):
                raise BulkImportIntakeError(_ERROR)
            current = target_owner._inspect_verified_import_target()
            verified.add(target_binding.line.line_ref)
            selectors[target_binding.line.line_ref] = current.name
        after = self._clock()
        if (type(after) is not int or not now <= after < parent.expires_at
                or self._parent.get_import_parent(parent.plan_ref) != parent):
            raise BulkImportIntakeError(_ERROR)
        return selectors

    def _verify_material_key(self) -> None:
        store = self._material_store
        if store is None:
            raise ValueError
        raw, identity = _read_owned(store._key_path, self._material_key_identity)
        try:
            if not 32 <= len(raw) <= 128 or not hmac.compare_digest(raw, store._key):
                raise ValueError
            if self._material_key_identity is None:
                self._material_key_identity = identity
        finally:
            _wipe(raw)

    def arm_original_dispatch(self) -> None:
        """Called only by the original owner's kernel adapter before contacting intake."""
        b = self._binding
        _require_m4_dispatch_ownership(b.plan, b.authorization, self._execution)
        with self._lock:
            if self._scope is not None:
                raise BulkImportIntakeError(_ERROR)
            self._record()
            self._verify_parent_forward(self._clock())
            _reserve_m4_material_acquisition(b.plan, b.authorization, self._execution)
            self._scope = _ACTIVE_DISPATCH.get()

    def _observe(self, purpose: str, nonce: str, claim_digest: object, now: int,
                 ack_payload: object = None) -> dict[str, object]:
        with self._lock:
            b = self._binding
            scope = self._scope
            if purpose != "resolve" and (
                    scope is None or not scope.active or scope.store is not self._execution
                    or scope.plan != b.plan or scope.authorization != b.authorization or not scope.material_reserved):
                raise ValueError
            if purpose.startswith("material-"):
                return self._observe_material(purpose, nonce, claim_digest, now)
            if purpose == "retain-ack":
                return self._observe_ack(claim_digest, ack_payload, now)
            if purpose == "verify-before-create":
                if (self._create_check_attempted or self._load_nonce is None
                        or claim_digest != canonical_digest(self._load_nonce) or self._material_finished
                        or self._material_claim is None or self._material_claim.state is not MaterialUseClaimState.NEW):
                    raise ValueError
                self._create_check_attempted = True
                store = self._material_store
                if store is None or b.material_requested_at is None or b.material_expires_at is None:
                    raise ValueError
                self._verify_material_key()
                material = store._inspect_claim(request_digest=_original_material_request_digest(
                    b.permission, b.material_requested_at, b.material_expires_at),
                    authorization_digest=b.authorization.authorization_digest)
                if material.state is not MaterialUseClaimState.IN_PROGRESS:
                    raise ValueError
                self._permission._verify_before_create(b.plan, b.authorization, b.source, now_epoch=now)
                self._verify_parent_forward(now)
            elif purpose == "verify-completion":
                if self._load_nonce is None or claim_digest != canonical_digest(self._load_nonce):
                    raise ValueError
                self._permission.verify_row_completion(b.plan, b.authorization, b.source, now_epoch=now)
            else:
                self._permission.verify_row_acquisition(b.plan, b.authorization, b.source, now_epoch=now)
                if purpose != 'resolve':
                    self._verify_parent_forward(now)
            record = self._record()
            if purpose == "resolve":
                if claim_digest is not None:
                    raise ValueError
                return {"record": record.as_dict(), "expires_at": self._permission.acquisition_expires_at()}
            context = canonical_digest({"authorization_digest": b.authorization.authorization_digest,
                "plan_digest": b.plan.plan_digest, "revision": b.plan.revision})
            reservation = self._execution.inspect_claim(plan_ref=b.plan.plan_ref,
                requester_digest=b.plan.requester_digest, idempotency_digest=b.plan.idempotency_digest,
                context_digest=context, authorization_digest=b.authorization.authorization_digest)
            if reservation.state is not M4ClaimState.IN_PROGRESS:
                raise ValueError
            if purpose == "claim":
                expected = None
                if self._material_store is not None:
                    if self._material_claim is None or self._material_claim.state is not MaterialUseClaimState.NEW:
                        raise ValueError
                    expected = canonical_digest(self._material_nonce)
                if self._load_nonce is not None or claim_digest != expected:
                    raise ValueError
                self._load_nonce = nonce
            elif purpose in {"verify", "verify-completion", "verify-before-create"}:
                expected = None if self._load_nonce is None else canonical_digest(self._load_nonce)
                if self._load_nonce is None and self._material_claim is not None and self._material_claim.state is MaterialUseClaimState.NEW:
                    expected = canonical_digest(self._material_nonce)
                if claim_digest != expected:
                    raise ValueError
            else:
                raise ValueError
            return {"record": None, "expires_at": self._permission.acquisition_expires_at()}

    def _observe_ack(self, proof: object, payload: object, now: int) -> dict[str, object]:
        b, pins, store = self._binding, self._ack_pins, self._material_store
        if (pins is None or store is None or self._ack_attempted or self._load_nonce is None
                or proof != canonical_digest(self._load_nonce) or self._material_finished
                or self._material_claim is None or self._material_claim.state is not MaterialUseClaimState.NEW
                or b.material_requested_at is None or b.material_expires_at is None
                or not b.material_requested_at <= now < min(b.material_expires_at, self._permission.acquisition_expires_at())):
            raise ValueError
        # Original evidence only: do not re-read the pre-state after POST.
        self._ack_attempted = True
        from .secret_bulk_import_row_current import _OriginalRowNativeCurrent
        reader: object = self._permission._reader
        if type(reader) is _OriginalRowNativeCurrent:
            reader._discard_current_scope()
        self._verify_material_key()
        context = canonical_digest({"authorization_digest": b.authorization.authorization_digest,
            "plan_digest": b.plan.plan_digest, "revision": b.plan.revision})
        original = self._execution.inspect_claim(plan_ref=b.plan.plan_ref, requester_digest=b.plan.requester_digest,
            idempotency_digest=b.plan.idempotency_digest, context_digest=context,
            authorization_digest=b.authorization.authorization_digest)
        material = store._inspect_claim(request_digest=_original_material_request_digest(
            b.permission, b.material_requested_at, b.material_expires_at),
            authorization_digest=b.authorization.authorization_digest)
        if original.state is not M4ClaimState.IN_PROGRESS or material.state is not MaterialUseClaimState.IN_PROGRESS:
            raise ValueError
        if (type(payload) is not dict or set(payload) != {"native_secret_id", "serial_digest", "defaults_digest",
                                                        "ack_source_digest", "acknowledgement_digest"}
                or payload["defaults_digest"] != pins.defaults_digest
                or payload["ack_source_digest"] != pins.capture.source_digest):
            raise ValueError
        ack = WebSecretCreateAcknowledgement(payload["native_secret_id"], payload["serial_digest"],
                                             payload["acknowledgement_digest"])
        record = _original_ack_record(b, pins, self._record(), ack)
        self._parent._put_original_import_row_ack(record)
        retained = self._parent._get_original_import_row_ack(record.plan_ref,
            idempotency_digest=record.idempotency_digest, requester_digest=record.requester_digest,
            parent_binding_digest=record.parent_binding_digest, parameters_digest=record.parameters_digest)
        if record != retained:
            raise ValueError
        self._verify_material_key()
        return {"record": {"retained_digest": canonical_digest(retained.as_dict())},
                "expires_at": min(b.material_expires_at, self._permission.acquisition_expires_at())}

    def _inspect_ack_claims(self) -> tuple[OriginalImportRowAckRecord, M4Claim, MaterialUseClaim]:
        """Join original ACK identity and exact claims without asserting success."""
        b, pins, store = self._binding, self._ack_pins, self._material_store
        if pins is None or store is None or b.material_requested_at is None or b.material_expires_at is None:
            raise BulkImportIntakeError(_ERROR)
        parent = self._record()
        record = self._parent._get_original_import_row_ack(b.plan.plan_ref,
            idempotency_digest=b.plan.idempotency_digest, requester_digest=b.plan.requester_digest,
            parent_binding_digest=canonical_digest(parent.as_dict()), parameters_digest=b.plan.parameters_digest)
        expected = _original_ack_record(b, pins, parent, WebSecretCreateAcknowledgement(
            record.native_secret_id, record.serial_digest, record.acknowledgement_digest))
        if record != expected:
            raise BulkImportIntakeError(_ERROR)
        self._verify_material_key()
        original = self._execution.inspect_claim(plan_ref=b.plan.plan_ref, requester_digest=b.plan.requester_digest,
            idempotency_digest=b.plan.idempotency_digest, context_digest=record.context_digest,
            authorization_digest=b.authorization.authorization_digest)
        material = store._inspect_claim(request_digest=_original_material_request_digest(
            b.permission, b.material_requested_at, b.material_expires_at),
            authorization_digest=b.authorization.authorization_digest)
        self._verify_material_key()
        return record, original, material

    def _inspect_ack_for_readback(self) -> OriginalImportRowAckRecord:
        """Select the original ACK for a fixed fresh GET, not C2 success or dispatch."""
        try:
            with self._lock:
                b, lifetime = self._binding, self._readback_lifetime
                b.__post_init__()
                if (lifetime is None or lifetime.binding != b.lifetime_binding()
                        or b.material_requested_at is None
                        or self._permission._source != b.source or self._permission._pins != b.permission):
                    raise ValueError
                now = lifetime.check()
                if now < b.material_requested_at:
                    raise ValueError
                checker = self._permission._checker
                # Verify only the live source/child permission. Calling the
                # projection reader here would recurse through this readback.
                checker(b.source, canonical_digest(checker._reference), now)
                self._verify_parent_forward(now)
                checker(b.source, canonical_digest(checker._reference), lifetime.check())
                record, original, material = self._inspect_ack_claims()
                if original.state is not M4ClaimState.IN_PROGRESS:
                    raise ValueError
                if material.state is MaterialUseClaimState.IN_PROGRESS:
                    scope = self._scope
                    if (self._material_finished or scope is None or not scope.active or scope.store is not self._execution
                            or scope.plan != b.plan or scope.authorization != b.authorization
                            or not scope.material_reserved):
                        raise ValueError
                elif (material.state is not MaterialUseClaimState.REPLAY
                        or material.outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED):
                    raise ValueError
                if lifetime.check() >= self._permission.acquisition_expires_at():
                    raise ValueError
                return record
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _inspect_verified_ack(self) -> OriginalImportRowAckRecord:
        """Read original ACK joined to both exact terminals, never grants a write."""
        record, original, material = self._inspect_ack_claims()
        if (original.state is not M4ClaimState.REPLAY or original.result is None
                or original.result.outcome is not M4Outcome.SUCCEEDED
                or original.result.verification is not M4Verification.VERIFIED
                or original.result.compensation is not M4Compensation.NOT_REQUESTED
                or material.state is not MaterialUseClaimState.REPLAY
                or material.outcome is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED):
            raise BulkImportIntakeError(_ERROR)
        return record

    def _observe_material(self, purpose: str, nonce: str, proof: object, now: int) -> dict[str, object]:
        b, store = self._binding, self._material_store
        if store is None or b.material_requested_at is None or b.material_expires_at is None:
            raise ValueError
        if not b.material_requested_at <= now < b.material_expires_at:
            raise ValueError
        self._verify_material_key()
        context = canonical_digest({"authorization_digest": b.authorization.authorization_digest,
            "plan_digest": b.plan.plan_digest, "revision": b.plan.revision})
        original = self._execution.inspect_claim(plan_ref=b.plan.plan_ref, requester_digest=b.plan.requester_digest,
            idempotency_digest=b.plan.idempotency_digest, context_digest=context,
            authorization_digest=b.authorization.authorization_digest)
        if original.state is not M4ClaimState.IN_PROGRESS:
            raise ValueError
        request_digest = _original_material_request_digest(b.permission, b.material_requested_at, b.material_expires_at)
        record: dict[str, object] | None = None
        if purpose in {"material-ready", "material-claim"}:
            if proof is not None or self._material_nonce is not None:
                raise ValueError
            self._permission.verify_row_acquisition(b.plan, b.authorization, b.source, now_epoch=now)
            self._verify_parent_forward(now)
            self._record()
            store.verify_ready()
            if purpose == "material-ready":
                record = {"ready": True}
            else:
                # Consume before the store operation: unknown delivery cannot
                # be adopted by a fresh request/client/nonce in this scope.
                self._material_nonce = nonce
                self._material_claim = store.claim(request_digest=request_digest,
                    authorization_digest=b.authorization.authorization_digest)
                record = {"state": self._material_claim.state.value,
                          "outcome": None if self._material_claim.outcome is None else self._material_claim.outcome.value}
            expires = min(b.material_expires_at, self._permission.acquisition_expires_at())
        elif purpose in {"material-release", "material-revoke"}:
            if (self._material_finished or self._material_claim is None
                    or self._material_claim.state is not MaterialUseClaimState.NEW):
                raise ValueError
            if purpose == "material-release":
                if self._load_nonce is None or proof != canonical_digest(self._load_nonce):
                    raise ValueError
                self._permission.verify_row_completion(b.plan, b.authorization, b.source, now_epoch=now)
                self._record()
                outcome = MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
            else:
                if self._material_nonce is None or proof != canonical_digest(self._material_nonce):
                    raise ValueError
                # Cleanup of this original consumed claim needs no fresh grant
                # or active parent and never reads/decrypts source material.
                outcome = MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
            self._material_finished = True
            store.finalize(request_digest=request_digest, authorization_digest=b.authorization.authorization_digest,
                           outcome=outcome)
            expires = min(b.material_expires_at, now + 60, b.authorization.expires_at, b.plan.expires_at)
        else:
            raise ValueError
        self._verify_material_key()
        return {"record": record, "expires_at": expires}


def create_original_row_channel_app(
    owner: OriginalRowChannelOwner, *, request_key_path: Path, request_key_sha256: str,
    signing_key_path: Path, signing_key_sha256: str,
    clock: Callable[[], int] = lambda: int(time.time()), monotonic: Callable[[], float] = time.monotonic,
) -> Starlette:
    """Private fixed server; no caller-selected plan, store, source, action or grant."""
    try:
        ledger_digests = {hashlib.sha256(owner._parent._key).hexdigest(),
                          hashlib.sha256(owner._execution._key).hexdigest()}
        if owner._material_store is not None:
            ledger_digests.add(hashlib.sha256(owner._material_store._key).hexdigest())
        if (type(owner) is not OriginalRowChannelOwner or request_key_sha256 == signing_key_sha256
                or signing_key_sha256 == owner._binding.namespace_key_digest
                or request_key_sha256 == owner._binding.namespace_key_digest
                or bool(ledger_digests & {request_key_sha256, signing_key_sha256})
                or any(path.parts[1:] == owner._binding.source.path.parts[1:]
                       for path in (request_key_path, signing_key_path))):
            raise ValueError
        lifetime = _ChannelLifetime(owner._binding.lifetime_binding(), clock, monotonic)
        credential, signer = _PinnedKey(request_key_path, request_key_sha256), _PinnedKey(signing_key_path, signing_key_sha256)
        context = owner._binding.context_digest()
    except Exception:
        raise BulkImportIntakeError(_ERROR) from None

    async def handle(request: Request) -> Response:
        raw = key = signing = None
        verified_request = False
        try:
            raw = await _body(request)
            payload, seal = _envelope(raw)
            purpose = request.path_params["purpose"]
            now = lifetime.check()
            fields = {"contract", "context", "nonce", "issued_at", "claim_digest"}
            if purpose == "retain-ack":
                fields.add("ack")
            if (purpose not in {"resolve", "claim", "verify", "verify-completion", "verify-before-create", "material-ready",
                                "material-claim", "material-release", "material-revoke", "retain-ack"}
                    or set(payload) != fields
                    or payload["contract"] != CONTRACT or payload["context"] != context
                    or type(payload["nonce"]) is not str or _NONCE.fullmatch(payload["nonce"]) is None
                    or type(payload["issued_at"]) is not int or not 0 <= now - payload["issued_at"] <= 10):
                raise ValueError
            key = credential.load()
            domain = _REQUEST_DOMAIN + purpose.encode() + b"\0"
            if not hmac.compare_digest(seal, hmac.new(key, domain + _canonical(payload), hashlib.sha256).hexdigest()):
                raise ValueError
            verified_request = True
            observation = await asyncio.to_thread(
                owner._observe, purpose, payload["nonce"], payload["claim_digest"], now, payload.get("ack"))
            after = lifetime.check()
            expires = observation["expires_at"]
            if type(expires) is not int or not now <= after < expires:
                raise ValueError
            renewed = credential.load()
            _wipe(renewed)
            signing = signer.load()
            if owner._material_store is not None and any(hmac.compare_digest(value, owner._material_store._key)
                                                         for value in (key, signing)):
                raise ValueError
            result = dict(contract=CONTRACT, context=context, purpose=purpose, nonce=payload["nonce"],
                          request_seal=seal, observed_at=after, **observation)
            signature = Ed25519PrivateKey.from_private_bytes(bytes(signing)).sign(_RESPONSE_DOMAIN + _canonical(result)).hex()
            return JSONResponse({"payload": result, "seal": signature}, headers={"Cache-Control": "no-store"})
        except BaseException as error:
            if verified_request:
                from .secret_bulk_import_row_current import _OriginalRowNativeCurrent
                reader: object = owner._permission._reader
                if type(reader) is _OriginalRowNativeCurrent:
                    reader._discard_current_scope()
            if not isinstance(error, Exception):
                raise
            return JSONResponse({"status": "unavailable"}, status_code=409, headers={"Cache-Control": "no-store"})
        finally:
            for value in (raw, key, signing):
                if value is not None:
                    _wipe(value)

    return Starlette(routes=[Route(_PREFIX + "{purpose}", handle, methods=["POST"])])


class UnixOriginalRowChannelClient(_OpaqueC3Object):
    """Intake-side pinned request credential/public key; no protected ledger inputs."""

    def __init__(self, binding: OriginalRowChannelBinding, *, socket_path: Path,
                 request_key_path: Path, request_key_sha256: str,
                 public_key_path: Path, public_key_sha256: str,
                 clock: Callable[[], int] = lambda: int(time.time()), monotonic: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(binding) is not OriginalRowChannelBinding or not socket_path.is_absolute()
                    or request_key_path.parent != socket_path.parent or public_key_path.parent != socket_path.parent
                    or request_key_sha256 == public_key_sha256
                    or any(path.parts[1:] == binding.source.path.parts[1:]
                           for path in (request_key_path, public_key_path))):
                raise ValueError
            binding.__post_init__()
            self._binding, self._socket = binding, socket_path
            self._material_digest: str | None = None
            self._lifetime = _ChannelLifetime(binding.lifetime_binding(), clock, monotonic)
            self._request, self._public = _PinnedKey(request_key_path, request_key_sha256), _PinnedKey(public_key_path, public_key_sha256)
            self._socket_pin = _socket_identity(socket_path)
            self._claim_digest: str | None = None
            self._verified_until = 0
            self._original_binding: OriginalImportBindingRecord | None = None
            self._ack_attempted = False
            self._ack_active_payload: dict[str, object] | None = None
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _post(self, purpose: str, raw: bytearray) -> bytearray:
        with httpx.Client(transport=httpx.HTTPTransport(uds=str(self._socket), retries=0), timeout=2.0,
                          follow_redirects=False, trust_env=False) as client:
            with client.stream("POST", "http://localhost" + _PREFIX + purpose,
                               content=bytes(raw), headers={"Content-Type": "application/json"}) as response:
                if response.status_code != 200:
                    raise ValueError
                result = bytearray()
                try:
                    for chunk in response.iter_bytes():
                        if len(result) + len(chunk) > _MAX_FRAME:
                            raise ValueError
                        result.extend(chunk)
                    return result
                except BaseException:
                    _wipe(result)
                    raise

    def _call(self, purpose: str, *, ack: dict[str, object] | None = None) -> dict[str, object]:
        key = public = raw = response = None
        try:
            now = self._lifetime.check()
            if _socket_identity(self._socket) != self._socket_pin:
                raise ValueError
            nonce = secrets.token_hex(16)
            proof = self._claim_digest or self._material_digest
            if purpose in {"resolve", "material-ready", "material-claim"}:
                proof = None
            elif purpose == "material-revoke":
                proof = self._material_digest
            payload = dict(contract=CONTRACT, context=self._binding.context_digest(), nonce=nonce,
                           issued_at=now, claim_digest=proof)
            if purpose == "retain-ack":
                if ack is None or ack is not self._ack_active_payload:
                    raise ValueError
                payload["ack"] = ack
            elif ack is not None:
                raise ValueError
            key = self._request.load()
            seal = hmac.new(key, _REQUEST_DOMAIN + purpose.encode() + b"\0" + _canonical(payload), hashlib.sha256).hexdigest()
            raw = bytearray(_canonical({"payload": payload, "seal": seal}))
            response = self._post(purpose, raw)
            result, signature = _envelope(response)
            public = self._public.load()
            Ed25519PublicKey.from_public_bytes(bytes(public)).verify(bytes.fromhex(signature), _RESPONSE_DOMAIN + _canonical(result))
            after = self._lifetime.check()
            if (set(result) != {"contract", "context", "purpose", "nonce", "request_seal", "observed_at", "record", "expires_at"}
                    or result["contract"] != CONTRACT or result["context"] != payload["context"]
                    or result["purpose"] != purpose or result["nonce"] != nonce or result["request_seal"] != seal
                    or type(result["observed_at"]) is not int or not now <= result["observed_at"] <= after
                    or type(result["expires_at"]) is not int or not after < result["expires_at"]
                    or result["expires_at"] > min(after + 60, self._binding.authorization.expires_at, self._binding.plan.expires_at)
                    or _socket_identity(self._socket) != self._socket_pin):
                raise ValueError
            if purpose == "material-ready":
                record = result["record"]
                if type(record) is not dict or set(record) != {"ready"} or record["ready"] is not True:
                    raise ValueError
            elif purpose == "material-claim":
                _material_claim_record(result["record"])
            elif purpose == "retain-ack":
                record = result["record"]
                if type(record) is not dict or set(record) != {"retained_digest"}:
                    raise ValueError
                require_digest(record["retained_digest"], "retained ACK")
            elif purpose != "resolve" and result["record"] is not None:
                raise ValueError
            renewed = self._request.load()
            _wipe(renewed)
            self._verified_until = result["expires_at"]
            if purpose == "claim":
                self._claim_digest = canonical_digest(nonce)
            elif purpose == "material-claim" and _material_claim_record(result["record"]).state is MaterialUseClaimState.NEW:
                self._material_digest = canonical_digest(nonce)
            return result
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None
        finally:
            for value in (key, public, raw, response):
                if value is not None:
                    _wipe(value)

    def _retain_ack_from_transport(self, transport: object) -> str:
        from .secret_bulk_import_row_http_transport import _Build29OriginalRowHttpTransport
        if type(transport) is not _Build29OriginalRowHttpTransport:
            raise BulkImportIntakeError(_ERROR)
        bridge = transport._encoder._converter._bridge
        if (self._ack_attempted or self._claim_digest is None or self._material_digest is None
                or not transport._reading_original_ack or not transport._ack_retention_attempted
                or not transport._post_attempted or transport._dispatch_body is None
                or transport._encoder._active_thread != threading.get_ident()
                or transport._encoder._active_metadata is None
                or bridge._loader._authority is not self or type(transport._ack) is not WebSecretCreateAcknowledgement
                or self._original_binding is None):
            raise BulkImportIntakeError(_ERROR)
        self._ack_attempted = True
        try:
            pins = _OriginalRowAckPins(bridge._context.row, transport._encoder._digest, transport._capture)
            record = _original_ack_record(self._binding, pins, self._original_binding, transport._ack)
            ack_payload = {name: getattr(record, name) for name in (
                "native_secret_id", "serial_digest", "defaults_digest", "ack_source_digest", "acknowledgement_digest")}
            self._ack_active_payload = ack_payload
            result = self._call("retain-ack", ack=ack_payload)["record"]
            expected = canonical_digest(record.as_dict())
            if type(result) is not dict or result["retained_digest"] != expected:
                raise ValueError
            return expected
        except BaseException:
            bridge._loader._session.close()
            raise
        finally:
            self._ack_active_payload = None

    def resolve_rows(self, session: _OwnerFileSourceSession, *, key_path: Path, key_sha256: str) -> PinnedOriginalImportRows:
        try:
            if key_sha256 != self._binding.namespace_key_digest or session._transaction._binding != self._binding.source:
                raise ValueError
            record = self._call("resolve")["record"]
            if type(record) is not dict:
                raise ValueError
            original = OriginalImportBindingRecord(**record)
            b = self._binding
            if (original.plan_ref != b.plan.plan_ref or original.plan_digest != b.parent_digest
                    or original.requester_digest != b.plan.requester_digest or original.namespace_key_digest != key_sha256):
                raise ValueError
            fields = asdict(original)
            fields.pop("plan_digest")
            fields.pop("namespace_key_digest")
            rows = PinnedOriginalImportRows(OriginalImportOperation(**fields), key_path=key_path, key_sha256=key_sha256)
            rows.verify_source_session(session, authenticated_requester_digest=b.plan.requester_digest)
            self._original_binding = original
            return rows
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def verify_row_acquisition(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                               source: OwnerFileIntakeBinding, *, now_epoch: int) -> None:
        now = self._lifetime.check()
        if (plan != self._binding.plan or authorization != self._binding.authorization
                or source != self._binding.source or type(now_epoch) is not int
                or not 0 <= now - now_epoch <= 10):
            raise BulkImportIntakeError(_ERROR)
        self._call("verify")

    def acquisition_expires_at(self) -> int:
        return self._verified_until

    def verify_row_completion(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                              source: OwnerFileIntakeBinding, *, now_epoch: int) -> None:
        now = self._lifetime.check()
        if (plan != self._binding.plan or authorization != self._binding.authorization
                or source != self._binding.source or type(now_epoch) is not int
                or not 0 <= now - now_epoch <= 10 or self._claim_digest is None):
            raise BulkImportIntakeError(_ERROR)
        self._call("verify-completion")


class _RemoteOriginalImportRowLoader(_PreboundOriginalImportRowLoader):
    """Reuse the decoder/lifecycle with owner-side metadata/NEW dispatch checks."""

    def __init__(self, session: _OwnerFileSourceSession, client: UnixOriginalRowChannelClient,
                 *, index: int, key_path: Path, key_sha256: str) -> None:
        try:
            if type(session) is not _OwnerFileSourceSession or type(client) is not UnixOriginalRowChannelClient:
                raise ValueError
            self._session, self._authority = session, client
            self._plan, self._authorization = client._binding.plan, client._binding.authorization
            self._rows = client.resolve_rows(session, key_path=key_path, key_sha256=key_sha256)
            self._row = self._rows.row(index)
            self._row.verify_m4_plan(self._plan)
            self._used, self._lock = False, threading.Lock()
            self._acquisition_deadline = None
            self._lifetime = None
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def _verify(self, *, completed: bool = False) -> None:
        self._verify_source_authority(completed=completed)

    def _reserve(self) -> None:
        assert type(self._authority) is UnixOriginalRowChannelClient
        self._authority._call("claim")


def _material_claim_record(value: object) -> MaterialUseClaim:
    if type(value) is not dict or set(value) != {"state", "outcome"}:
        raise BulkImportIntakeError(_ERROR)
    if type(value["state"]) is not str or (value["outcome"] is not None and type(value["outcome"]) is not str):
        raise BulkImportIntakeError(_ERROR)
    return MaterialUseClaim(MaterialUseClaimState(value["state"]),
        None if value["outcome"] is None else MaterialRuntimeOutcome(value["outcome"]))


class _OriginalRowMaterialStateClient(_OpaqueC3Object):
    """Fixed original material store operations over the existing signed socket."""

    def __init__(self, client: UnixOriginalRowChannelClient, context: _OriginalRowUseContext,
                 session: _OwnerFileSourceSession) -> None:
        from .secret_bulk_import_row_adapter import _OriginalRowUseContext
        if (type(client) is not UnixOriginalRowChannelClient or type(context) is not _OriginalRowUseContext
                or type(session) is not _OwnerFileSourceSession
                or client._binding.source != session._transaction._binding
                or client._binding.permission != context.permission
                or client._binding.material_requested_at != context.requested_at
                or client._binding.material_expires_at != context.expires_at):
            raise BulkImportIntakeError(_ERROR)
        context.__post_init__()
        self._client, self._context, self._session = client, context, session
        self._request = _original_material_request_digest(context.permission, context.requested_at, context.expires_at)
        self._authorization = context.permission.authorization.authorization_digest
        self._claim_attempted = self._finalize_attempted = False
        self._claimed: MaterialUseClaim | None = None

    @property
    def monotonic_checkpoint_protocol_bound(self) -> bool:
        # The signed readiness response proves the fixed server-side store;
        # the owner constructor rejects an uncheckpointed material store.
        return True

    def _verify_bridge(self, bridge: _OriginalRowSecretCreateAdapter) -> None:
        if (bridge._context != self._context or bridge._loader._authority is not self._client
                or bridge._loader._session is not self._session):
            raise BulkImportIntakeError(_ERROR)

    def verify_ready(self) -> None:
        self._client._call("material-ready")

    def _verify_inputs(self, request_digest: str, authorization_digest: str) -> None:
        if request_digest != self._request or authorization_digest != self._authorization:
            raise BulkImportIntakeError(_ERROR)

    def claim(self, *, request_digest: str, authorization_digest: str) -> MaterialUseClaim:
        self._verify_inputs(request_digest, authorization_digest)
        if self._claim_attempted:
            raise BulkImportIntakeError(_ERROR)
        self._claim_attempted = True
        try:
            self._claimed = _material_claim_record(self._client._call("material-claim")["record"])
            return self._claimed
        except BaseException:
            self._session.close()
            raise

    def finalize(self, *, request_digest: str, authorization_digest: str, outcome: MaterialRuntimeOutcome) -> None:
        self._verify_inputs(request_digest, authorization_digest)
        if (self._finalize_attempted or self._claimed is None or self._claimed.state is not MaterialUseClaimState.NEW
                or type(outcome) is not MaterialRuntimeOutcome):
            raise BulkImportIntakeError(_ERROR)
        self._finalize_attempted = True
        purpose = "material-release" if outcome is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED else "material-revoke"
        try:
            self._client._call(purpose)
        except BaseException:
            self._session.close()
            raise
