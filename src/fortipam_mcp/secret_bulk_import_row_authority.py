"""Inactive original-child lab issuance and independent remote permission.

Trusted lab composition can issue only an original retained file-parent row.
The separate acquisition verifier requires a revocable remote permission and
fresh fixed dependencies. No public Tool or production provider is registered.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
from pathlib import Path
from threading import RLock
import time
from typing import Any, Callable

from v4_planning import M4AuthorizationDenied, M4ExecutionAuthorization, M4ExecutionPlan, canonical_digest
from v4_planning.execution_kernel import M4ClaimState
from v4_planning.import_parent import FileImportParentRecord
from v4_planning.persistence import PersistentProtectedPlanningStore
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from v4_planning.secret_create_adapter import SECRET_CREATE_ACTION_ID, SECRET_CREATE_ACTION_VERSION

from .reference_authority_sidecar import UnixReferenceAuthorityClient
from .secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding, _ERROR
from .secret_bulk_import_intake_authority import _intent_digest
from .secret_bulk_import_reference_eligibility import ReferenceOwnerFileEligibility
from .secret_bulk_import_token_channel import _canonical
from .secret_create_m4_runtime import SecretCreateProjectionReader
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_bulk_import_dependencies import ImportDependencyCatalog, ResolvedImportDependencies
from .secret_bulk_import_row_namespace import PinnedOriginalImportRows
from .secret_bulk_import_parent_graph import _compile_original_import_graph

REFERENCE_KIND = "owner_file_original_row_acquisition"


@dataclass(frozen=True, slots=True, repr=False)
class _OriginalRowPermissionPins(_OpaqueC3Object):
    plan: M4ExecutionPlan
    authorization: M4ExecutionAuthorization
    policy_decision_digest: str
    scope_digest: str
    audience_digest: str

    def __post_init__(self) -> None:
        if type(self.plan) is not M4ExecutionPlan or type(self.authorization) is not M4ExecutionAuthorization:
            raise ValueError
        self.plan.__post_init__()
        self.authorization.__post_init__()
        if (self.plan.action_id != SECRET_CREATE_ACTION_ID
                or self.plan.action_version != SECRET_CREATE_ACTION_VERSION
                or self.authorization.plan_ref != self.plan.plan_ref
                or self.authorization.plan_digest != self.plan.plan_digest
                or self.authorization.requester_digest != self.plan.requester_digest
                or self.authorization.confirmation_digest != self.plan.confirmation_digest
                or self.authorization.approval_digest != self.plan.approval_digest):
            raise ValueError
        for name in ("policy_decision_digest", "scope_digest", "audience_digest"):
            require_digest(getattr(self, name), name)


class _OriginalRowM4Authority(_OpaqueC3Object):
    """Fixed standing-lab issuer; original identity survives new instances.

    Projection readers must be independently source-qualified by trusted
    composition. Issuance itself grants neither Reference nor material access.
    """

    def __init__(self, original: PinnedOriginalImportRows, source: OwnerFileIntakeBinding,
                 projected: ResolvedImportDependencies, catalog: ImportDependencyCatalog,
                 parent_store: PersistentProtectedPlanningStore, execution: PersistentM4ExecutionStateStore,
                 projection_reader: SecretCreateProjectionReader, *, index: int, expected_parent_digest: str,
                 authority_key: bytes, authenticated_requester_digest: str, transport_digest: str,
                 execution_enabled: bool = False, clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(original) is not PinnedOriginalImportRows or type(index) is not int
                    or type(execution) is not PersistentM4ExecutionStateStore
                    or not execution.monotonic_checkpoint_protocol_bound
                    or type(authority_key) is not bytes or not 32 <= len(authority_key) <= 4096
                    or type(execution_enabled) is not bool or not callable(clock)
                    or not callable(getattr(projection_reader, 'read_current', None))
                    or not callable(getattr(projection_reader, 'read_postcondition', None))):
                raise ValueError
            require_digest(transport_digest, 'transport')
            self._original, self._source, self._projected, self._catalog = original, source, projected, catalog
            self._parent_store, self._execution, self._reader = parent_store, execution, projection_reader
            self._key, self._enabled, self._clock = authority_key, execution_enabled, clock
            self._requester, self._transport, self._parent_digest = (
                authenticated_requester_digest, transport_digest, expected_parent_digest)
            self._row = original.row(index)
            self._lock, self._last_now = RLock(), -1
            self._issued: _OriginalRowPermissionPins | None = None
            self._parent = self._read_parent(self._now())
            if (hashlib.sha256(authority_key).hexdigest() == self._parent.namespace_key_digest
                    or any(hmac.compare_digest(authority_key, key) for key in (parent_store._key, execution._key))):
                raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def _now(self) -> int:
        now = self._clock()
        if type(now) is not int or now < 0 or now < self._last_now:
            self._enabled = False
            raise ValueError
        self._last_now = now
        return now

    def _read_parent(self, now: int) -> FileImportParentRecord:
        _compile_original_import_graph(self._original, self._source, self._projected, self._catalog,
            self._parent_store, expected_parent_digest=self._parent_digest,
            authenticated_requester_digest=self._requester, clock=lambda: now)
        parent = self._parent_store.get_import_parent(self._row.plan_ref)
        if (type(parent) is not FileImportParentRecord or parent.requester_digest != self._requester
                or not any(line.kind == 'secret' and line.index == self._row.index
                    and line.idempotency_digest == self._row.idempotency_digest
                    and line.parameters_digest == self._row.parameters_digest for line in parent.lines)):
            raise ValueError
        return parent

    def _mac(self, purpose: bytes, value: object) -> str:
        return hmac.new(self._key, b'fortipam-original-row-lab-authority/v1\0' + purpose + b'\0'
                        + _canonical(value), hashlib.sha256).hexdigest()

    def _derive(self) -> _OriginalRowPermissionPins:
        parent, row = self._parent, self._row
        line = next(line for line in parent.lines if line.kind == 'secret' and line.index == row.index)
        context = dict(parent_digest=parent.plan_digest, line_ref=line.line_ref,
                       transport_digest=self._transport, source_commitment=parent.source_commitment)
        approval = self._mac(b'approval', context)
        fields: dict[str, Any] = dict(plan_ref=parent.plan_ref, revision=1,
            action_id=SECRET_CREATE_ACTION_ID, action_version=SECRET_CREATE_ACTION_VERSION,
            adapter_ref='fortipam-build29-original-row-create-v1', target_ref=line.line_ref,
            requester_digest=parent.requester_digest, summary_digest=parent.plan_digest,
            confirmation_digest=parent.intent_policy_digest, approval_digest=approval,
            parameters_digest=row.parameters_digest, expected_current_digest=line.current_digest,
            expected_state_digest=line.expected_digest, idempotency_digest=row.idempotency_digest,
            expires_at=parent.expires_at, compensation_ref=None)
        plan = M4ExecutionPlan(**fields, plan_digest=canonical_digest(fields))
        signed = dict(context, plan_digest=plan.plan_digest)
        auth_fields: dict[str, Any] = dict(authorization_ref='original-row-auth-' + self._mac(b'authorization', signed),
            plan_ref=plan.plan_ref, plan_digest=plan.plan_digest, requester_digest=parent.requester_digest,
            confirmation_ref='original-row-intent-' + self._mac(b'intent', context),
            confirmation_digest=parent.intent_policy_digest,
            approval_ref='original-row-approval-' + self._mac(b'approval-ref', signed), approval_digest=approval,
            approver_digest=self._mac(b'lab-owner-policy', context), issued_at=parent.created_at,
            expires_at=parent.expires_at, one_time=True, execution_authorized=True)
        authorization = M4ExecutionAuthorization(**auth_fields, authorization_digest=canonical_digest(auth_fields))
        return _OriginalRowPermissionPins(plan, authorization, self._mac(b'policy', context),
                                          parent.scope_digest, parent.audience_digest)

    def issue(self) -> _OriginalRowPermissionPins:
        try:
            with self._lock:
                now = self._now()
                if not self._enabled or self._issued is not None or self._read_parent(now) != self._parent:
                    raise ValueError
                claim = self._execution._inspect_original_claims(plan_ref=self._parent.plan_ref,
                    requester_digest=self._requester, idempotency_digests=(self._row.idempotency_digest,))[0]
                if claim.state is not M4ClaimState.NEW:
                    raise ValueError
                pins = self._derive()
                if self._reader.read_current(pins.plan) != pins.plan.expected_current_digest:
                    raise ValueError
                if self._read_parent(self._now()) != self._parent:
                    raise ValueError
                final_claim = self._execution._inspect_original_claims(plan_ref=self._parent.plan_ref,
                    requester_digest=self._requester, idempotency_digests=(self._row.idempotency_digest,))[0]
                if final_claim.state is not M4ClaimState.NEW:
                    raise ValueError
                self._issued = pins
                return pins
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def verify(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization, *, now_epoch: int) -> None:
        try:
            with self._lock:
                now = self._now()
                if (not self._enabled or self._issued is None or type(now_epoch) is not int
                        or not self._parent.created_at <= now_epoch <= now < self._parent.expires_at
                        or self._read_parent(now) != self._parent
                        or self._derive() != self._issued
                        or plan != self._issued.plan or authorization != self._issued.authorization):
                    raise ValueError
        except Exception:
            raise M4AuthorizationDenied(_ERROR) from None

    def close(self) -> None:
        with self._lock:
            self._enabled, self._issued = False, None


def _original_material_request_digest(p: _OriginalRowPermissionPins, requested_at: int, expires_at: int) -> str:
    p.__post_init__()
    if (type(requested_at) is not int or type(expires_at) is not int
            or not p.authorization.issued_at <= requested_at < expires_at
            or expires_at > min(requested_at + 60, p.plan.expires_at, p.authorization.expires_at)):
        raise BulkImportIntakeError(_ERROR)
    return canonical_digest({"contract": "owner-file-original-row-use-v1",
        "provider_class": "owner_file_intake", "purpose": "initial_onboarding",
        "action_id": p.plan.action_id, "action_version": p.plan.action_version,
        "plan_ref": p.plan.plan_ref, "idempotency_digest": p.plan.idempotency_digest,
        "parameters_digest": p.plan.parameters_digest, "plan_digest": p.plan.plan_digest,
        "requester_digest": p.plan.requester_digest,
        "authorization_digest": p.authorization.authorization_digest,
        "policy_decision_digest": p.policy_decision_digest, "scope_digest": p.scope_digest,
        "audience_digest": p.audience_digest, "requested_at": requested_at, "expires_at": expires_at})


class _ReferenceOriginalRowPermission(ReferenceOwnerFileEligibility):
    _reference_kind = REFERENCE_KIND

    def __init__(self, source: OwnerFileIntakeBinding, pins: _OriginalRowPermissionPins,
                 *, authority: UnixReferenceAuthorityClient, authority_ref: str, reference: str,
                 scope_key_path: Path, scope_key_sha256: str, clock: Callable[[], int]) -> None:
        if type(authority) is not UnixReferenceAuthorityClient:
            raise BulkImportIntakeError(_ERROR)
        self._pins = pins
        super().__init__(source, authority=authority, authority_ref=authority_ref,
            reference=reference, requester_digest=pins.plan.requester_digest,
            scope_key_path=scope_key_path, scope_key_sha256=scope_key_sha256, clock=clock)

    def _scope_ref(self, binding: OwnerFileIntakeBinding, key: bytearray) -> str:
        self._pins.__post_init__()
        value = {"source": _intent_digest(binding, key), "child": asdict(self._pins),
                 "purpose": "initial_onboarding", "reference_kind": REFERENCE_KIND}
        return "owner-file-row-" + hmac.new(key,
            b"fortipam-owner-file-original-row-permission/v1\0" + _canonical(value), hashlib.sha256).hexdigest()


class PinnedOriginalRowAcquisitionAuthority(_OpaqueC3Object):
    """Remote exact child/source permission plus a prebound fixed dependency read."""

    def __init__(
        self, source: OwnerFileIntakeBinding, plan: M4ExecutionPlan,
        authorization: M4ExecutionAuthorization, *, policy_decision_digest: str,
        scope_digest: str, audience_digest: str, authority: UnixReferenceAuthorityClient,
        authority_ref: str, reference: str, scope_key_path: Path, scope_key_sha256: str,
        projection_reader: SecretCreateProjectionReader,
        clock: Callable[[], int] = lambda: int(time.time()),
    ) -> None:
        try:
            if type(source) is not OwnerFileIntakeBinding or scope_digest != source.scope_digest:
                raise ValueError
            self._source = source
            self._pins = _OriginalRowPermissionPins(plan, authorization,
                policy_decision_digest, scope_digest, audience_digest)
            self._pins.__post_init__()
            self._checker = _ReferenceOriginalRowPermission(source, self._pins,
                authority=authority, authority_ref=authority_ref, reference=reference,
                scope_key_path=scope_key_path, scope_key_sha256=scope_key_sha256, clock=clock)
            if (not callable(getattr(projection_reader, "read_current", None))
                    or not callable(getattr(projection_reader, "read_postcondition", None))):
                raise ValueError
            self._reader = projection_reader
        except Exception:
            raise BulkImportIntakeError(_ERROR) from None

    def verify_row_acquisition(
        self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
        source: OwnerFileIntakeBinding, *, now_epoch: int,
    ) -> None:
        self._verify_observation(plan, authorization, source, now_epoch=now_epoch, completed=False)

    def verify_row_completion(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                              source: OwnerFileIntakeBinding, *, now_epoch: int) -> None:
        self._verify_observation(plan, authorization, source, now_epoch=now_epoch, completed=True)

    def _verify_before_create(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                              source: OwnerFileIntakeBinding, *, now_epoch: int) -> None:
        self._verify_observation(plan, authorization, source, now_epoch=now_epoch,
                                 completed=False, before_create=True)

    def _verify_observation(self, plan: M4ExecutionPlan, authorization: M4ExecutionAuthorization,
                            source: OwnerFileIntakeBinding, *, now_epoch: int, completed: bool,
                            before_create: bool = False) -> None:
        try:
            if (plan != self._pins.plan or authorization != self._pins.authorization
                    or source != self._source or type(now_epoch) is not int
                    or not authorization.issued_at <= now_epoch < min(authorization.expires_at, plan.expires_at)):
                raise ValueError
            self._checker(source, canonical_digest(self._checker._reference), now_epoch)
            from .secret_bulk_import_row_current import _OriginalRowNativeCurrent
            reader: object = self._reader
            if before_create and type(reader) is _OriginalRowNativeCurrent:
                observed = reader._read_before_create(plan)
            else:
                observed = self._reader.read_postcondition(plan) if completed else self._reader.read_current(plan)
            expected = plan.expected_state_digest if completed else plan.expected_current_digest
            if observed != expected:
                raise ValueError
            # Revalidate after the bounded product dependency observation.
            self._checker(source, canonical_digest(self._checker._reference), now_epoch)
        except BaseException as error:
            from .secret_bulk_import_row_current import _OriginalRowNativeCurrent
            failed_reader: object = self._reader
            if type(failed_reader) is _OriginalRowNativeCurrent:
                failed_reader._discard_current_scope()
            if not isinstance(error, Exception):
                raise
            raise BulkImportIntakeError(_ERROR) from None

    def acquisition_expires_at(self) -> int:
        """Actual decision horizon only; never infer the full grant's expiry."""
        return min(self._checker._verified_until, self._pins.plan.expires_at,
                   self._pins.authorization.expires_at, self._source.expires_at)
