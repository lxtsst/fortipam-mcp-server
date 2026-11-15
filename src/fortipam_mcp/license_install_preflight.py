"""Join original license inputs for a bounded, non-executable preflight.

Artifact metadata is borrowed, never consumed. Only the two read sources are
owned/disposed here. Independent snapshots cannot establish atomic license
state, artifact validity, backup recovery or installation authority.
"""
from __future__ import annotations

from threading import RLock
from time import monotonic as _monotonic

from v4_planning import canonical_digest
from v4_planning.material_provider import MaterialAccessDenied, MaterialBindingStatus, _OpaqueC3Object
from v4_planning.models import require_digest

from .license_backup_source import LicenseBackupCustodySource
from .license_upload_material import LicenseUploadMaterialBinding
from .license_vm_source import LicenseVmSource

CONTRACT = "fortipam-license-install-bound-prerequisites-local/v1"
_ERROR = "The private license preflight is unavailable."
_MISSING = (
    "complete_native_license_state", "native_status_symbols_and_semantics", "deployment_and_ha",
    "entitlement_and_registration", "license_artifact_format_and_integrity",
    "backup_decryption_and_current_configuration_match", "independent_restore",
    "maintenance_and_reboot_window", "console_recovery_access", "strict_native_upload_ack",
    "post_boot_license_and_capacity",
)


class LicenseInstallPreflight(_OpaqueC3Object):
    def __init__(self, vm_source: LicenseVmSource, license_binding: LicenseUploadMaterialBinding,
            backup_source: LicenseBackupCustodySource, *, requester_digest: str, transport_digest: str) -> None:
        try:
            if (type(vm_source) is not LicenseVmSource or type(license_binding) is not LicenseUploadMaterialBinding
                    or type(backup_source) is not LicenseBackupCustodySource
                    or vm_source._attempted or backup_source._attempted): raise ValueError
            for value in (requester_digest, transport_digest): require_digest(value, "license preflight identity")
            self._vm, self._license, self._backup = vm_source, license_binding, backup_source
            self._pins = (vm_source, license_binding, backup_source)
            self._identity = self._identity_pin = (requester_digest, transport_digest)
            self._guard_pins = (vm_source._guard_pin, license_binding._guard_pin, backup_source._guard_pin)
            self._lock = RLock()
            self._closed = self._attempted = False
            self._valid_until: float | None = None
            self._metadata()
        except Exception: raise MaterialAccessDenied(_ERROR) from None

    def _metadata(self) -> None:
        vm, binding, backup = self._pins
        if (self._closed or self._vm is not vm or self._license is not binding or self._backup is not backup
                or self._identity != self._identity_pin or backup._closed
                or backup._license is not binding or binding._source._used
                or backup._requester != self._identity_pin[0] or backup._client != self._identity_pin[1]
                or binding._requester != self._identity_pin[0]
                or canonical_digest(dict(serial=vm._serial)) != binding._serial
                or vm._actor != backup._transport._owner
                or vm._guard is not self._guard_pins[0] or vm._guard_pin is not self._guard_pins[0]
                or binding._guard_pin is not self._guard_pins[1]
                or backup._guard is not self._guard_pins[2] or backup._guard_pin is not self._guard_pins[2]): raise ValueError
        binding._metadata()
        backup._metadata()
        vm._pinned_window()
        if vm._cookie_state() != vm._cookie_pin: raise ValueError

    def _check_identity(self, requester_digest: str, transport_digest: str) -> None:
        if (self._identity != self._identity_pin
                or (requester_digest, transport_digest) != self._identity_pin): raise MaterialAccessDenied(_ERROR)

    def preview(self, *, requester_digest: str, transport_digest: str) -> dict[str, object]:
        self._check_identity(requester_digest, transport_digest)
        try:
            try:
                with self._lock:
                    self._check_identity(requester_digest, transport_digest)
                    if self._attempted: raise ValueError
                    self._attempted = True
                    deadline = _monotonic() + min(10, self._pins[0]._config.timeout_seconds)
                    self._metadata()
                    artifact = self._pins[1]._source
                    if artifact.validate_prebound() is not MaterialBindingStatus.AVAILABLE: raise ValueError
                    self._metadata()
                    if _monotonic() >= deadline: raise ValueError
                    vm = self._pins[0].read(monotonic_deadline=deadline)
                    vm_deadline = self._pins[0]._monotonic_deadline
                    if vm_deadline is None: raise ValueError
                    backup = self._pins[2].observe(requester_digest=requester_digest, transport_digest=transport_digest,
                        monotonic_deadline=deadline)
                    self._pins[0]._current()
                    observed, expires = backup["observed_at"], backup["expires_at"]
                    backup_deadline = backup["expires_monotonic_at"]
                    if (type(observed) is not int or isinstance(expires, bool) or not isinstance(expires, (int, float))
                            or isinstance(backup_deadline, bool) or not isinstance(backup_deadline, (int, float))): raise ValueError
                    self._valid_until = min(deadline, backup_deadline, vm_deadline)
                    if artifact.validate_prebound() is not MaterialBindingStatus.AVAILABLE: raise ValueError
                    now = self._pins[2]._now()
                    if not observed <= now < expires: raise ValueError
                    self._metadata()
                    self._check_handoff()
                    vm.pop("closed", None)
                    public = dict(contract=CONTRACT, action_family="license.install",
                        vm_observation=vm, artifact_metadata_available=True, license_material_loaded=False,
                        original_backup_execution_verified=backup["original_backup_execution_verified"],
                        retained_backup_files_intact=backup["retained_files_intact_locally"],
                        native_backup_encryption_verified=False, backup_matches_current_configuration_verified=False,
                        backup_restore_tested=False, sources_bound_to_original_target_requester_client=True,
                        observations_are_atomic=False, planning_status="incomplete_evidence", missing_requirements=list(_MISSING),
                        request_body_compiled=False, authorization_or_operation_created=False,
                        authoritative_license_state_observed=False, license_execution_ready=False,
                        execution_authorized=False, independent_restore_authorized=False, configuration_written=False)
            finally:
                self.close()
            self._check_handoff()
            public["private_read_sources_disposed"] = True
            return public
        except Exception: raise MaterialAccessDenied(_ERROR) from None

    def _check_handoff(self) -> None:
        # Pure trusted clock check after all callbacks and owned cleanup. The
        # original producer deadlines are retained, never restarted at handoff.
        if self._valid_until is None or _monotonic() >= self._valid_until: raise MaterialAccessDenied(_ERROR)

    def _revoke(self) -> None:
        self._closed = True
        self._pins[0]._closed = self._pins[2]._closed = True

    def close(self) -> None:
        self._closed = True
        try: self._pins[0].close()
        finally: self._pins[2].close()
