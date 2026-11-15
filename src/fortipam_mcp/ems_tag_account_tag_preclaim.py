"""Fixed fresh material lease after an interrupted, undispatched Tag recovery.

The old authentication purpose remains consumed. This admits one new protected
authentication preparation, never a replay, writer, new ownership or M4 issue.
Original Tag recovery reservation and all UNKNOWN prohibitions remain binding.
"""
from __future__ import annotations

import hashlib
import hmac
from threading import RLock

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object

from .ems_tag_account_custody import EmsAccountCustody
from .ems_tag_account_enrollment import EmsAccountCentralEnrollment
from .ems_tag_contract import _canonical
from .ems_tag_custody import EmsTagOriginalCustody, _decode
from .ldap_server_runtime import _read
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = "ems-7.4.8.2245-original-account-tag-preclaim-recovery-v1"
_ERROR = "The private EMS preclaim recovery preparation is unavailable."


class EmsTagPreclaimRecoveryPreparation(_OpaqueC3Object):
    """Server-held original inputs only; no detached proof or caller nonce."""

    def __init__(self, enrollment: EmsAccountCentralEnrollment, account: EmsAccountCustody,
                 tag: EmsTagOriginalCustody, abandoned: PersistentM4ExecutionStateStore, *,
                 source_key: bytes) -> None:
        try:
            if (type(enrollment) is not EmsAccountCentralEnrollment or type(account) is not EmsAccountCustody
                    or type(tag) is not EmsTagOriginalCustody or type(abandoned) is not PersistentM4ExecutionStateStore
                    or account._store._read_only is not True or tag._store._read_only is not True
                    or abandoned._read_only is not True or not abandoned.monotonic_checkpoint_protocol_bound
                    or type(source_key) is not bytes or not 32 <= len(source_key) <= 4096
                    or abandoned._path in (account._store._path, tag._store._path)):
                raise ValueError
            self._enrollment, self._account, self._tag, self._abandoned = enrollment, account, tag, abandoned
            self._owned = account.require_recovery_source(enrollment._sources, enrollment._requester)
            self._birth = tag.inspect_created_scope()
            self._key_hash = hashlib.sha256(source_key).hexdigest()
            self._purpose = (account._store._path.parent / (account._store._path.name
                + ".ems-account-tag-recover." + self._owned.context_digest + ".json"))
            self.reservation_name = self._purpose.name + ".preclaim-resume.json"
            self._raw = self._purpose_bytes()
            self._claim = self._purpose_claim()
            self._old_directory = abandoned._path.parent / "custody"
            self._send = tag._store._path.parent / (tag._store._path.name + ".ems-recover." + tag._plan.plan_digest + ".json")
            now = enrollment._now()
            self._created, self._expires = now, now + 300
            self._last, self._closed, self._lock = now, False, RLock()
            self.context_digest = canonical_digest(dict(contract=CONTRACT, original_account=self._owned.custody_digest,
                original_tag=self._birth.custody_digest, old_purpose=canonical_digest(self._claim),
                abandoned_store=str(abandoned._path), abandoned_key=hashlib.sha256(abandoned._key).hexdigest(),
                abandoned_checkpoint=abandoned._checkpoint_store_ref, source_key=self._key_hash,
                created_at=self._created, expires_at=self._expires))
            self.require_unused()
        except Exception:
            raise ValueError(_ERROR) from None

    def _purpose_bytes(self) -> bytes:
        raw = _read(self._purpose, 65536)
        try:
            return bytes(raw)
        finally:
            _zeroize_mutable(raw)

    def _purpose_claim(self) -> dict[str, object]:
        packet = _decode(bytearray(self._raw))
        if type(packet) is not dict or set(packet) != {"value", "signature"}:
            raise ValueError
        claim = packet["value"]
        expected = {"contract", "original", "reference", "parent", "account_scope", "phase", "parameters",
            "source_key_sha256", "tag_original", "owner_tag_scope", "requester"}
        if (type(claim) is not dict or set(claim) != expected or type(packet["signature"]) is not str
                or not hmac.compare_digest(packet["signature"], self._account._mac("account-tag-session-claim", claim))
                or claim["contract"] != "ems-7.4.8.2245-original-account-tag-session-v1"
                or claim["phase"] != "recover" or claim["original"] != self._owned.custody_digest
                or claim["parent"] != self._owned.parent_digest or claim["account_scope"] != self._owned.created_scope_digest
                or claim["reference"] != self._owned.material_reference or claim["source_key_sha256"] != self._key_hash
                or claim["requester"] != self._enrollment._requester or claim["tag_original"] != self._birth.custody_digest
                or claim["parameters"] != self._tag._draft.parameters_digest
                or claim["owner_tag_scope"] != self._birth.created_scope_digest):
            raise ValueError
        return claim

    def check(self, enrollment: EmsAccountCentralEnrollment, account: EmsAccountCustody) -> None:
        try:
            with self._lock:
                now = self._enrollment._now()
                if (self._closed or enrollment is not self._enrollment or account is not self._account
                        or not self._last <= now < self._expires or now < self._created
                        or self._abandoned._read_only is not True or self._abandoned.claim_count != 0
                        or self._account.require_recovery_source(enrollment._sources, enrollment._requester) != self._owned
                        or self._tag.inspect_created_scope() != self._birth
                        or self._tag._plan.requester_digest != enrollment._requester
                        or enrollment._draft != account._draft
                        or self._purpose_bytes() != self._raw or self._purpose_claim() != self._claim
                        or not self._old_directory.is_dir() or any(self._old_directory.iterdir())
                        or any((self._abandoned._path.parent / name).exists() for name in
                            ("cpe.private.json", "recovery-binding.private.json"))):
                    raise ValueError
                self._last = now
                # The authentication guard validates the exact registered
                # material after this check, before every protected boundary.
                # Repeating its SMB read here spends the same M4 freshness
                # window without adding an independent material observation.
        except Exception:
            self._closed = True
            raise ValueError(_ERROR) from None

    def require_unused(self) -> None:
        self.check(self._enrollment, self._account)
        if self._send.exists() or (self._purpose.parent / self.reservation_name).exists():
            raise ValueError(_ERROR)

    def claim_fields(self) -> dict[str, object]:
        self.check(self._enrollment, self._account)
        return dict(contract=CONTRACT, context=self.context_digest, original_purpose=canonical_digest(self._claim),
            abandoned_store=str(self._abandoned._path), abandoned_checkpoint=self._abandoned._checkpoint_store_ref,
            created_at=self._created, expires_at=self._expires)
