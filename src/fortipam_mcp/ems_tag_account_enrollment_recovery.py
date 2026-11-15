"""Recover only a complete, original-owned, unused append without an ACK."""
from __future__ import annotations

import os

from v4_planning import canonical_digest
from v4_planning.material_provider import MaterialBindingStatus

from .ems_tag_account_enrollment import EmsAccountCentralEnrollment
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = "ems-7.4.8.2245-complete-unused-account-registration-recovery-v1"
_ERROR = "The unverified EMS account registration recovery is unavailable."


def retire_complete_unused_registration_once(enrollment: EmsAccountCentralEnrollment, *, execution_enabled: bool = False) -> None:
    """No partial-tail deletion, late registration ACK, replay or material use."""
    raw = bytearray();writer = None
    try:
        if (type(enrollment) is not EmsAccountCentralEnrollment or type(execution_enabled) is not bool
                or not execution_enabled or not enrollment._enabled):raise ValueError
        with enrollment._lock:
            enrollment._now();enrollment._role_current()
            if {p.name for p in enrollment._directory.iterdir()} != {"prepare.json", "append.claim.json"}:raise ValueError
            prepare = enrollment._prepare(live=False);claim = enrollment._record("append.claim.json")
            writer = enrollment._take_writer(prepare["reference"])
            enrollment._role_current()
            if {p.name for p in enrollment._directory.iterdir()} != {"prepare.json", "append.claim.json"}:raise ValueError
            raw, info = enrollment._read_env();enrollment._owned_tail(raw, info, prepare, claim)
            if enrollment._loader.validate_prebound() is not MaterialBindingStatus.AVAILABLE:raise ValueError
            enrollment._write("retire.claim.json", dict(contract=CONTRACT, reference=prepare["reference"],
                original_length=prepare["original_length"], original_append_claim=canonical_digest(claim),
                expected_original_prefix=prepare["original_mac"], parent_scope=enrollment._owned.created_scope_digest,
                original_registration_unverified=True, unused=True))
            fd = os.open(enrollment._env, os.O_WRONLY | os.O_NOFOLLOW)
            try:
                if enrollment._version(os.fstat(fd)) != info:raise ValueError
                enrollment._now();enrollment._role_current()
                os.ftruncate(fd, prepare["original_length"]);os.fsync(fd)
            finally:os.close(fd)
            check, after = enrollment._read_env()
            try:
                if (list(after[:2]) != prepare["original_identity"] or len(check) != prepare["original_length"]
                        or enrollment._mac("original-env", check) != prepare["original_mac"]):raise ValueError
            finally:_zeroize_mutable(check)
            if enrollment._loader.validate_prebound() is not MaterialBindingStatus.UNAVAILABLE:raise ValueError
            enrollment._write("retire.ack.json", dict(contract=CONTRACT, reference=prepare["reference"],
                original_prefix_restored=True, original_registration_unverified=True))
    except Exception:
        if type(enrollment) is EmsAccountCentralEnrollment:enrollment._closed = True
        raise ValueError(_ERROR) from None
    finally:
        _zeroize_mutable(raw)
        if type(enrollment) is EmsAccountCentralEnrollment:enrollment._release_writer(writer)
