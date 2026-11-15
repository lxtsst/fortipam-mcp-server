"""Pinned issuer receipt for one synthetic Terraform plan; no signing or apply.

The independent producer signs domain-separated SHA256 of the exact metadata
payload bytes with Ed25519. This consumer holds only a pinned public key. The
receipt attests the fixed synthetic producer profile, not OS isolation, vendor
signature verification, a complete security review or runtime caller authority.
All paths, hashes, bindings and receipt bytes remain private server inputs.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import hmac
import math
from pathlib import Path
import re
from threading import Lock
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from .secret_bulk_import_file import _read_owned
from .secret_bulk_import_token_channel import _PinnedKey, _canonical
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .terraform_plan_projection import (
    TerraformPlanProjection, _equals, _object, project_private_terraform_plan,
)

CONTRACT = "fortipam-synthetic-terraform-plan-receipt/v1"
_DOMAIN = CONTRACT.encode("ascii") + b"\x00"
_ERROR = "The private signed Terraform artifact is unavailable."
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_FIELDS = frozenset({"contract", "purpose", "profile_digest", "run_nonce", "requester_digest", "transport_digest",
    "issued_at", "completed_at", "expires_at", "artifact_sha256", "artifact_bytes", "commands", "exit_codes",
    "endpoint_connection_attempts", "device_material_loaded", "device_contacted", "apply_invoked"})
_MAX_RECEIPT = 32768


class TerraformPlanReceiptError(ValueError):
    """Fixed non-disclosing denial without a partial projection."""


def _require_digest(value: str) -> None:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ValueError


@dataclass(frozen=True, slots=True, repr=False)
class TerraformPlanProducerPins(_OpaqueC3Object):
    producer_source_sha256: str
    terraform_binary_sha256: str
    provider_binary_sha256: str
    configuration_sha256: str
    provider_lock_sha256: str

    def digest(self) -> str:
        values = {key: getattr(self, key) for key in self.__dataclass_fields__}
        for value in values.values():
            _require_digest(value)
        return hashlib.sha256(_canonical(dict(contract=CONTRACT, terraform_version="1.9.8",
            provider_version="1.0.0", scope="loopback-synthetic-no-apply", **values))).hexdigest()


def _integer(content: bytearray, span: tuple[int, int]) -> int:
    with memoryview(content)[slice(*span)] as token:
        if not 1 <= len(token) <= 12 or any(byte not in b"0123456789" for byte in token):
            raise ValueError
        return int(token)


def _hex_token(content: bytearray, span: tuple[int, int], size: int) -> str:
    left, right = span
    if right - left != size + 2 or content[left] != 34 or content[right - 1] != 34:
        raise ValueError
    with memoryview(content)[left + 1:right - 1] as token:
        if any(byte not in b"0123456789abcdef" for byte in token):
            raise ValueError
        return token.tobytes().decode("ascii")


@dataclass(frozen=True, slots=True, repr=False)
class SignedTerraformPlanProjection(_OpaqueC3Object):
    projection: TerraformPlanProjection

    def summary(self) -> dict[str, object]:
        result = self.projection.summary()
        result.update(producer_receipt_contract=CONTRACT, producer_receipt_signature_verified=True, producer_profile_pinned=True,
            artifact_integrity_verified=True, receipt_valid_at_read=True, private_binding_matches=True,
            provenance_scope="fixed_synthetic_local_producer", runtime_caller_authenticated=False)
        return result


class PinnedSignedTerraformPlanArtifact(_OpaqueC3Object):
    """One authenticated receipt plus exact artifact, under original time/binding.

    Independent trusted composition selects the issuer, profile, subject and
    original run window; none can come from an MCP/planner argument or receipt.
    Read-only consumption needs no new ledger, signer service or action authority.
    """

    def __init__(self, *, artifact_path: Path, receipt_path: Path, public_key_path: Path,
            public_key_sha256: str, pins: TerraformPlanProducerPins, run_nonce: str,
            requester_digest: str, transport_digest: str, issued_at: int, expires_at: int,
            clock: Callable[[], int] = lambda: int(time.time()),
            monotonic: Callable[[], float] = time.monotonic) -> None:
        try:
            paths = (artifact_path, receipt_path, public_key_path)
            if (any(not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts for path in paths)
                    or len(set(paths)) != 3 or type(pins) is not TerraformPlanProducerPins
                    or type(issued_at) is not int or type(expires_at) is not int
                    or not 0 <= issued_at < expires_at <= issued_at + 900
                    or not callable(clock) or not callable(monotonic)):
                raise ValueError
            for value in (public_key_sha256, run_nonce, requester_digest, transport_digest):
                _require_digest(value)
            self._artifact, self._receipt = artifact_path, receipt_path
            self._profile = pins.digest()
            self._bindings = dict(profile_digest=self._profile, run_nonce=run_nonce,
                requester_digest=requester_digest, transport_digest=transport_digest)
            self._issued, self._expires = issued_at, expires_at
            self._clock, self._monotonic = clock, monotonic
            self._last_wall = -1
            self._last_mono = -1.0
            self._deadline: float | None = None
            self._attempted = self._closed = False
            self._lock = Lock()
            self._check()
            self._public = _PinnedKey(public_key_path, public_key_sha256)
            self._check()
        except Exception:
            raise TerraformPlanReceiptError(_ERROR) from None

    def _check(self) -> int:
        wall, mono = self._clock(), self._monotonic()
        if (self._closed or type(wall) is not int or not self._issued <= wall < self._expires
                or wall < self._last_wall or type(mono) not in (int, float) or not math.isfinite(mono)
                or mono < 0 or mono < self._last_mono or self._deadline is not None and mono >= self._deadline):
            raise ValueError
        if self._deadline is None:
            self._deadline = float(mono) + self._expires - wall
        self._last_wall, self._last_mono = wall, float(mono)
        return wall

    def _authenticate(self, receipt: bytearray, public: bytearray) -> tuple[str, int]:
        left = _skip_json_space(receipt, 0)
        right = _json_value_end(receipt, left)
        if not 0 < len(receipt) <= _MAX_RECEIPT or _skip_json_space(receipt, right) != len(receipt):
            raise ValueError
        metadata._validate_json(receipt, left, right, depth=0, budget=[5000])
        envelope = _object(receipt, (left, right), frozenset({"payload", "signature"}))
        if set(envelope) != {"payload", "signature"}:
            raise ValueError
        signature = bytes.fromhex(_hex_token(receipt, envelope["signature"], 128))
        with memoryview(receipt)[slice(*envelope["payload"])] as payload:
            message = _DOMAIN + hashlib.sha256(payload).digest()
        Ed25519PublicKey.from_public_bytes(bytes(public)).verify(signature, message)
        fields = _object(receipt, envelope["payload"], _FIELDS)
        if set(fields) != _FIELDS:
            raise ValueError
        expected = {
            "contract": _canonical(CONTRACT), "purpose": b'"synthetic-plan-review-only"',
            "commands": b'["version","init","plan","show"]', "exit_codes": b"[0,0,0,0]",
            "endpoint_connection_attempts": b"0", "device_material_loaded": b"false",
            "device_contacted": b"false", "apply_invoked": b"false",
            **{key: _canonical(value) for key, value in self._bindings.items()},
        }
        if any(not _equals(receipt, fields[key], value) for key, value in expected.items()):
            raise ValueError
        issued, completed, expires = (_integer(receipt, fields[key]) for key in ("issued_at", "completed_at", "expires_at"))
        now = self._check()
        if issued != self._issued or expires != self._expires or not issued <= completed <= now < expires:
            raise ValueError
        size = _integer(receipt, fields["artifact_bytes"])
        if not 0 < size <= 2 * 1024 * 1024:
            raise ValueError
        return _hex_token(receipt, fields["artifact_sha256"], 64), size

    def read_once(self) -> SignedTerraformPlanProjection:
        receipt = public = artifact = bytearray()
        try:
            with self._lock:
                if self._attempted or self._closed:
                    raise ValueError
                self._attempted = True
            self._check()
            public = self._public.load()
            receipt, _ = _read_owned(self._receipt)
            digest, size = self._authenticate(receipt, public)
            self._check()
            artifact, _ = _read_owned(self._artifact)
            if len(artifact) != size or not hmac.compare_digest(hashlib.sha256(artifact).hexdigest(), digest):
                raise ValueError
            projection = project_private_terraform_plan(artifact)
            fresh_public = self._public.load()
            _zeroize_mutable(fresh_public)
            self._check()
            return SignedTerraformPlanProjection(projection)
        except Exception:
            raise TerraformPlanReceiptError(_ERROR) from None
        finally:
            for raw in (receipt, public, artifact):
                _zeroize_mutable(raw)

    def close(self) -> None:
        with self._lock:
            self._closed = True
