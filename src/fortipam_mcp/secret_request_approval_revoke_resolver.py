"""Protected original creation resolver; no device I/O or execution authority."""
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import stat

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .secret_metadata_http_transport import MAX_RESPONSE_BYTES, _zeroize_mutable
from .secret_request_approval_revoke_continuity import (
    SecretRequestApprovalRevokeContinuityExpected,
    SecretRequestApprovalRevokeContinuityWitness,
    _canonical, _decode,
    qualify_secret_request_approval_revoke_with_invocation,
)
from .secret_request_approval_revoke_detail_contract import SecretRequestApprovalRevokeDetailBinding
from .secret_request_create_invocation_witness import OwnerOnlySecretRequestCreateInvocationWitnessStore

_UNAVAILABLE = "Protected withdrawal creation binding is unavailable."


class SecretRequestApprovalRevokeResolverError(ValueError):
    """Stable failure without private paths, records or selectors."""


@dataclass(frozen=True, slots=True, repr=False)
class SecretRequestApprovalRevokeResolvedCreation:
    binding: SecretRequestApprovalRevokeDetailBinding
    continuity: SecretRequestApprovalRevokeContinuityWitness
    private_creation_digest: str


def _read(path: Path, limit: int) -> bytearray:
    raw = bytearray()
    try:
        parent = descriptor = None
        raw = bytearray(limit + 1)
        try:
            if not path.is_absolute() or ".." in path.parts:
                raise ValueError
            parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
            for part in path.parent.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(parent)
                parent = child
            info = os.fstat(parent)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 0 < before.st_size <= limit):
                raise ValueError
            count = os.readv(descriptor, [raw])
            after = os.fstat(descriptor)
            if (count != before.st_size or os.read(descriptor, 1)
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                raise ValueError
            raw = _take_mutable_prefix(raw, count)
            return raw
        except Exception:
            _zeroize_mutable(raw)
            raise SecretRequestApprovalRevokeResolverError(_UNAVAILABLE) from None
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if parent is not None:
                os.close(parent)
    except BaseException:
        _erase_transfer_storage(raw)
        raise


class OwnerOnlySecretRequestApprovalRevokeResolver:
    """Resolve three independently protected original records on every call.

    Startup composition supplies exact paths, separate signing keys and original
    expectations. No MCP arguments can choose records, keys or target identities.
    Resolution is historical provenance only; a workflow must still authenticate
    current reviewer intent, inspect fresh state and reserve one durable dispatch.
    """

    def __init__(self, *, continuity_path: Path, invocation_path: Path, create_claim_path: Path,
                 continuity_key: bytes, invocation_key: bytes,
                 expected: SecretRequestApprovalRevokeContinuityExpected, intent_ref: str) -> None:
        try:
            from v4_planning.models import require_ref
            require_ref(intent_ref, "original intent")
            if (type(expected) is not SecretRequestApprovalRevokeContinuityExpected
                    or type(continuity_key) is not bytes or len(continuity_key) != 32
                    or type(invocation_key) is not bytes or len(invocation_key) != 32
                    or hmac.compare_digest(continuity_key, invocation_key)
                    or len({continuity_path, invocation_path, create_claim_path}) != 3
                    or any(not isinstance(p, Path) or not p.is_absolute() or ".." in p.parts
                           for p in (continuity_path, invocation_path, create_claim_path))):
                raise ValueError
            self._continuity_path, self._claim_path = continuity_path, create_claim_path
            self._store = OwnerOnlySecretRequestCreateInvocationWitnessStore(invocation_path, invocation_key)
            self._key, self._expected, self._intent_ref = continuity_key, expected, intent_ref
        except Exception:
            raise SecretRequestApprovalRevokeResolverError(_UNAVAILABLE) from None

    def resolve(self) -> SecretRequestApprovalRevokeResolvedCreation:
        continuity_raw = claim_raw = None
        try:
            invocation = self._store.load()
            if invocation.intent_ref != self._intent_ref:
                raise ValueError
            claim_raw = _read(self._claim_path, 4096)
            claim = _decode(bytes(claim_raw))
            exact = {"contract": "fortipam-v4-secret-request-create-claim-v1",
                     "dispatch_attempted": True, "retry_allowed": False,
                     "terminal_outcome": "bound", "failure_stage": "none",
                     "http_status_class": "none", "post_http_status": 200}
            if (set(claim) != set(exact) | {"intent_binding_hmac"}
                    or any(type(claim[k]) is not type(v) or claim[k] != v for k, v in exact.items())
                    or type(claim["intent_binding_hmac"]) is not str
                    or len(claim["intent_binding_hmac"]) != 64
                    or any(c not in "0123456789abcdef" for c in claim["intent_binding_hmac"])):
                raise ValueError
            claim_digest = hashlib.sha256(_canonical(claim)).hexdigest()
            if not hmac.compare_digest(claim_digest, invocation.create_claim_digest):
                raise ValueError
            continuity_raw = _read(self._continuity_path, MAX_RESPONSE_BYTES)
            qualified = qualify_secret_request_approval_revoke_with_invocation(
                bytes(continuity_raw), verification_key=self._key,
                expected=self._expected, invocation=invocation,
            )
            digest = hashlib.sha256(_canonical({"continuity": qualified.private_continuity_digest,
                "claim": claim_digest, "intent": invocation.intent_ref,
                "requester": invocation.requester_digest, "transport": invocation.transport_digest})).hexdigest()
            return SecretRequestApprovalRevokeResolvedCreation(self._expected.binding, qualified, digest)
        except Exception:
            raise SecretRequestApprovalRevokeResolverError(_UNAVAILABLE) from None
        finally:
            for raw in (continuity_raw, claim_raw):
                if raw is not None:
                    _zeroize_mutable(raw)
