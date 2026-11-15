"""Retire only an exact central append after readonly verified Account recovery."""
from __future__ import annotations

import os

from v4_planning import canonical_digest
from v4_planning.material_provider import MaterialBindingStatus

from .ems_tag_account_custody import EmsAccountCustody
from .ems_tag_account_enrollment import EmsAccountCentralEnrollment
from .secret_metadata_http_transport import _zeroize_mutable

_ERROR = "The restored EMS account material retirement is unavailable."


def retire_recovered_account_material_once(enrollment: EmsAccountCentralEnrollment, recovery: EmsAccountCustody, *,
                                           execution_enabled: bool = False) -> None:
    """No material resolution, arbitrary deletion, retry or uncertain recovery."""
    raw = bytearray();writer = None
    try:
        if (type(enrollment) is not EmsAccountCentralEnrollment or type(recovery) is not EmsAccountCustody
                or type(execution_enabled) is not bool or not execution_enabled or not enrollment._enabled
                or recovery._store._read_only is not True or recovery._original is None):raise ValueError
        with enrollment._lock:
            enrollment._now();enrollment._role_current()
            owned = recovery.inspect_restoration();original = recovery._original
            if (original._store._read_only is not True or original._draft != enrollment._draft
                    or owned.parent_digest != enrollment._owned.custody_digest
                    or original._issued.plan.requester_digest != enrollment._requester
                    or recovery._issued.plan.requester_digest != enrollment._requester
                    or enrollment._sources._binding != recovery._binding["instance"]
                    or recovery._mac("owner", enrollment._sources._owner) != recovery._binding["owner"]
                    or enrollment._key in (recovery._key, recovery._store._key, original._key, original._store._key)):
                raise ValueError
            prepare = enrollment._prepare(live=False);reference = prepare["reference"]
            if reference != owned.material_reference or original._reference != reference:raise ValueError
            if (enrollment._directory / "retire.claim.json").exists():raise ValueError
            append = enrollment._record("append.claim.json");ack = enrollment._record("append.ack.json")
            if (set(ack) != {"reference", "claim_digest", "registered_at"} or ack["reference"] != reference
                    or ack["claim_digest"] != canonical_digest(append) or type(ack["registered_at"]) is not int
                    or not prepare["created_at"] <= ack["registered_at"] < prepare["expires_at"]):raise ValueError
            def used_digest() -> str:
                used = enrollment._record("material.used.json")
                if (set(used) != {"reference", "plan_digest", "authorization_digest", "claimed_at"}
                        or used["reference"] != reference or used["plan_digest"] != original._issued.plan.plan_digest
                        or used["authorization_digest"] != original._issued.authorization.authorization_digest
                        or type(used["claimed_at"]) is not int or not original._issued.authorization.issued_at
                        <= used["claimed_at"] < original._issued.authorization.expires_at):raise ValueError
                return canonical_digest(used)
            used = used_digest();recovery_effect = canonical_digest(recovery.inspect_effect())
            writer = enrollment._take_writer(reference)
            enrollment._role_current()
            if recovery.inspect_restoration() != owned or used_digest() != used:raise ValueError
            raw, info = enrollment._read_env();enrollment._owned_tail(raw, info, prepare, append)
            enrollment._write("retire.claim.json", dict(reference=reference, original_length=prepare["original_length"],
                unused=False, original_context=owned.context_digest, recovery_context=recovery._context,
                recovery_effect=recovery_effect, used_digest=used))
            fd = os.open(enrollment._env, os.O_WRONLY | os.O_NOFOLLOW)
            try:
                if enrollment._version(os.fstat(fd)) != info:raise ValueError
                enrollment._now();enrollment._role_current()
                if recovery.inspect_restoration() != owned:raise ValueError
                os.ftruncate(fd, prepare["original_length"]);os.fsync(fd)
            finally:os.close(fd)
            check, after = enrollment._read_env()
            try:
                if (list(after[:2]) != prepare["original_identity"] or len(check) != prepare["original_length"]
                        or enrollment._mac("original-env", check) != prepare["original_mac"]):raise ValueError
            finally:_zeroize_mutable(check)
            if enrollment._loader.validate_prebound() is not MaterialBindingStatus.UNAVAILABLE:raise ValueError
            enrollment._write("retire.ack.json", dict(reference=reference, original_prefix_restored=True,
                recovery_context=recovery._context, recovery_effect=recovery_effect))
    except Exception:
        if type(enrollment) is EmsAccountCentralEnrollment:enrollment._closed = True
        raise ValueError(_ERROR) from None
    finally:
        _zeroize_mutable(raw)
        if type(enrollment) is EmsAccountCentralEnrollment:enrollment._release_writer(writer)
