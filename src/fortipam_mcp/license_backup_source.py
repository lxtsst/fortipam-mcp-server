"""Fresh, default-denied local custody evidence from one original backup export.

No export/login, password getter, restore, license installation or recovery
qualification is supplied. The original live export authorization is not reused.
"""
from __future__ import annotations

from collections.abc import Callable
from threading import RLock
import hashlib
import hmac
import math
import time

from v4_planning import canonical_digest
from v4_planning.material_provider import MaterialAccessDenied, _OpaqueC3Object
from v4_planning.models import require_digest

from .backup_artifact_custody import BackupArtifactCustody, BackupCustodyBinding
from .backup_export_transport import BackupExportTransport, CONTRACT as EXPORT_CONTRACT
from .backup_export_workflow import BackupExportWorkflow, _BackupExportAdapter
from .license_upload_material import LicenseUploadMaterialBinding
from .m4_execution_store import PersistentM4ExecutionStateStore
from .crl_import_transport import digest as export_digest
from .ldap_server_runtime import _private_file, _read
from .mutable_json_buffer import _erase_transfer_storage

CONTRACT = "fortipam-license-original-backup-custody-local/v1"
_ERROR = "The private retained-backup evidence is unavailable."


class LicenseBackupCustodySource(_OpaqueC3Object):
    def __init__(self, workflow: BackupExportWorkflow, license_binding: LicenseUploadMaterialBinding, *,
            allowed_transport_digest: str, source_guard: Callable[[], bool] | None = None,
            clock: Callable[[], int] = lambda: int(time.time())) -> None:
        try:
            if (type(workflow) is not BackupExportWorkflow or type(license_binding) is not LicenseUploadMaterialBinding
                    or not callable(clock) or source_guard is not None and not callable(source_guard)): raise ValueError
            require_digest(allowed_transport_digest, "backup evidence transport")
            self._workflow, self._license = workflow, license_binding
            self._transport, self._store = workflow._transport, workflow._store
            self._plan, self._authorization = workflow._issued["create"]
            self._adapter = workflow._adapters["create"]
            custody = self._transport._custody
            if (type(self._transport) is not BackupExportTransport or type(self._store) is not PersistentM4ExecutionStateStore
                    or type(self._adapter) is not _BackupExportAdapter or type(custody) is not BackupArtifactCustody
                    or type(custody._binding) is not BackupCustodyBinding): raise ValueError
            self._custody = custody
            self._binding = self._custody._binding
            self._request = custody._request
            self._namespace = dict(workflow._namespace)
            self._pins = (workflow, license_binding, self._transport, self._store, self._plan, self._authorization,
                self._adapter, custody, self._binding, self._request)
            self._store_paths = (self._store._path, self._store._key_path)
            self._requester, self._client = license_binding._requester, allowed_transport_digest
            self._guard = self._guard_pin = source_guard
            self._clock, self._last_now = clock, -1
            self._closed = self._attempted = False
            self._lock = RLock()
            self._checkpoint = self._store._monotonic_checkpoint
            self._checkpoint_ref = self._store._checkpoint_store_ref
            self._parameters = self._transport.parameters_digest
            # Private integrity pins are compared only inside this boundary.
            # Password/configuration-derived digests never enter public hashes.
            self._artifact_pins = (self._custody._receipt, self._custody._password_digest,
                self._custody._record_digest, self._binding._retain_until)
            self._files = self._file_metadata()
            self._identity = canonical_digest(self._control_content())
            self._metadata()
        except Exception: raise MaterialAccessDenied(_ERROR) from None

    def _file_metadata(self) -> tuple[tuple[int, ...], ...]:
        self._binding._check()
        records = []
        for name in ("lease.claim", "backup.conf", "backup.password", "integrity.json"):
            path = self._binding._directory / name
            _private_file(path); info = path.stat()
            records.append((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
        return tuple(records)

    def _control_content(self) -> dict[str, object]:
        store = self._store
        return dict(contract=CONTRACT, license_binding=self._license._digest,
            backup_parameters=self._parameters, plan=self._plan.plan_digest,
            authorization=self._authorization.authorization_digest, requester=self._requester, client=self._client,
            database=hashlib.sha256(str(store._path.resolve()).encode()).hexdigest(),
            key_file=hashlib.sha256(str(store._key_path.resolve()).encode()).hexdigest(),
            key=hashlib.sha256(store._key).hexdigest(), checkpoint=store._checkpoint_store_ref)

    def _metadata(self) -> None:
        if (self._closed or any(current is not expected for current, expected in zip(
                (self._workflow, self._license, self._transport, self._store, self._plan, self._authorization,
                    self._adapter, self._custody, self._binding, self._request), self._pins, strict=True))
                or self._store._path is not self._store_paths[0] or self._store._key_path is not self._store_paths[1]):
            raise ValueError
        workflow, transport, custody, binding = self._workflow, self._transport, self._custody, self._binding
        p, a = self._plan, self._authorization
        issued = workflow._issued.get("create")
        self._license._metadata(); binding._check(); p.__post_init__(); a.__post_init__()
        if (self._closed or workflow._transport is not transport or workflow._store is not self._store
                or issued is None or issued[0] is not p or issued[1] is not a or workflow._namespace != self._namespace
                or workflow._adapters.get("create") is not self._adapter
                or self._adapter._workflow is not workflow or self._adapter._plan is not p or self._adapter._authorization is not a
                or self._adapter._acknowledged is not True or transport._custody is not custody
                or custody._binding is not binding or transport._binding is not binding
                or custody._request is not self._request or self._request.plan_digest != p.plan_digest
                or self._request.policy_digest != p.approval_digest or self._request.authorization_digest != a.authorization_digest
                or self._request.scope_digest != binding._scope or self._request.audience_digest != binding._audience
                or binding._scope != transport._scope or transport._scope != export_digest(dict(contract=EXPORT_CONTRACT,
                    serial=transport._serial, scope="global", owner=hashlib.sha256(transport._owner.encode()).hexdigest()))
                or not transport._attempted or not transport._export_requested or not custody._released
                or custody._lease is not None or custody._password is not None
                or self._artifact_pins != (custody._receipt, custody._password_digest, custody._record_digest, binding._retain_until)
                or any(value is None for value in self._artifact_pins)
                or self._store._monotonic_checkpoint is not self._checkpoint or self._store._checkpoint_store_ref != self._checkpoint_ref
                or not hmac.compare_digest(self._store._key, self._store._load_key())
                or transport.parameters_digest != self._parameters or p.parameters_digest != self._parameters
                or p.action_id != "backup-export-native-create" or p.action_version != "1.0.0" or p.adapter_ref != EXPORT_CONTRACT
                or p.target_ref != "fixed-encrypted-global-backup" or p.compensation_ref is not None
                or p.expected_current_digest != transport._initial or p.expected_state_digest != transport._expected
                or p.requester_digest != self._requester or workflow._namespace["requester_digest"] != self._requester
                or workflow._namespace["transport_digest"] != self._client
                or canonical_digest(dict(serial=transport._serial)) != self._license._serial
                or binding._audience != self._license._source._audience
                or self._file_metadata() != self._files
                or canonical_digest(self._control_content()) != self._identity): raise ValueError

    def _terminal(self) -> None:
        self._metadata()
        if not self._store.monotonic_checkpoint_protocol_bound or self._store.claim_count != 1: raise ValueError
        p, a = self._plan, self._authorization
        claim = self._store.inspect_claim(plan_ref=p.plan_ref, requester_digest=p.requester_digest,
            idempotency_digest=p.idempotency_digest, authorization_digest=a.authorization_digest,
            context_digest=canonical_digest(dict(plan_digest=p.plan_digest, authorization_digest=a.authorization_digest, revision=p.revision)))
        if (claim.result is None or claim.result.outcome != "succeeded" or claim.result.verification != "verified"
                or claim.result.compensation != "not_requested"): raise ValueError
        self._metadata()

    def _claim_file(self, before_read: Callable[[], None]) -> None:
        before_read()
        raw = _read(self._binding._directory / "lease.claim", 64)
        try:
            before_read()
            if not hmac.compare_digest(raw, self._request.authorization_digest.encode("ascii")): raise ValueError
        finally: _erase_transfer_storage(raw)

    def _now(self) -> int:
        now = self._clock()
        if type(now) is not int or now < 0 or now < self._last_now:
            self._closed = True
            raise ValueError
        self._last_now = now
        return now

    def observe(self, *, requester_digest: str, transport_digest: str,
            monotonic_deadline: float | None = None) -> dict[str, object]:
        # Foreign readers do not acquire a lifecycle or consume this source.
        if (requester_digest, transport_digest) != (self._requester, self._client): raise MaterialAccessDenied(_ERROR)
        try:
            with self._lock:
                if self._attempted: raise ValueError
                self._attempted = True
                if monotonic_deadline is not None and (type(monotonic_deadline) not in (int, float)
                        or not math.isfinite(monotonic_deadline) or time.monotonic() >= monotonic_deadline): raise ValueError
                self._terminal()
                started = time.monotonic(); now = self._now()
                deadline: float = min(now+10, self._binding._retain_until)
                if monotonic_deadline is not None:
                    deadline = min(deadline, now+monotonic_deadline-started)
                self._ready()
                if not now < deadline or time.monotonic()-started >= deadline-now: raise ValueError
                guard = self._guard_pin
                def before_read() -> None:
                    # Local-only checks; never reopen the old export grant or
                    # invoke a fresh guard/clock/checkpoint between files.
                    if (self._closed or guard is None or self._guard is not guard or self._guard_pin is not guard
                            or time.monotonic()-started >= deadline-now): raise ValueError
                    self._metadata()
                    if time.monotonic()-started >= deadline-now: raise ValueError
                with self._custody._lock:
                    self._claim_file(before_read)
                    self._custody._verify_stored_files(before_read=before_read)
                    self._custody._verify_record(before_read=before_read)
                self._terminal()
                observed = self._now()
                self._ready()
                if not now <= observed < deadline or time.monotonic()-started >= deadline-now: raise ValueError
                return dict(contract=CONTRACT, source_digest=self._identity, observed_at=observed, expires_at=deadline,
                    expires_monotonic_at=started+deadline-now,
                    original_backup_execution_verified=True, retained_files_intact_locally=True,
                    retention_not_expired=True, native_encryption_requested=True,
                    native_encryption_verified=False, backup_matches_current_configuration_verified=False,
                    restore_tested=False, license_rollback_ready=False,
                    license_install_authorized=False, device_contacted=False, new_export_requested=False)
        except Exception: raise MaterialAccessDenied(_ERROR) from None

    def _ready(self) -> None:
        guard = self._guard
        if self._closed or guard is None or guard is not self._guard_pin or guard() is not True: raise ValueError
        if self._guard is not guard or self._guard_pin is not guard: raise ValueError
        self._metadata()

    def close(self) -> None:
        self._closed = True
