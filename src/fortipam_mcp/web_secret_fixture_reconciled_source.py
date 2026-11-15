"""Authenticate independent retained-fixture evidence; never issue a grant.

Only a completed, original-key sealed reconciliation can supply the baseline
for the separate cleanup contract. Fresh full-state/material reads remain
mandatory. Ordinary recovery and original source attempts are not adopted.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object
from .secret_approval_build29_projection_source import _reject_constant, _unique_members
from .secret_approval_build29_runtime_provider import _read_private_buffer
from .secret_metadata_http_transport import _zeroize_mutable
from .web_secret_fixture_api_preservation_reader import WebSecretFixtureApiPreservationReader
from .web_secret_fixture_creation_record import WebSecretFixtureCreationRecord

CONTRACT = "retained-owned-web-reconciled-source/v1"
_DOMAIN = b"fortipam-owned-web-reconciled-source/v1\0"
_ERROR = "The private reconciled Web fixture source is unavailable."
_VALUE_FIELDS = frozenset({"contract", "namespace", "creation_digest", "observed_at", "completed_at",
    "preservation_digest", "credential", "totp", "original_claim_count", "original_files",
    "observer_attempt_digest", "execution_authority"})
_REQUIRED_FILES = frozenset({"creation/creation.record", "creation/creation.ack", "creation/creation.attempt",
    "creation/api-preservation.source.attempt"})
_NORMAL_REQUIRED_FILES = (_REQUIRED_FILES - {"creation/api-preservation.source.attempt"}) | {
    "creation/api-preservation.baseline.attempt", "creation/instruction.attach.attempt"}
_CREATION_FILES = _REQUIRED_FILES | _NORMAL_REQUIRED_FILES | {"creation/recovery.delete.attempt",
    "creation/api-preservation.recovery-dispatch.attempt"}


class WebSecretFixtureReconciledSourceError(ValueError):
    """Categorical refusal without private source fields or paths."""


class WebSecretFixtureReconciledSource(_OpaqueC3Object):
    """Original owned custody plus one fixed independent signed observation.

    The protected source file, reconciliation marker and original byte records
    remain pinned. Original M4 custody is verified on every use; a later cleanup
    may append its own claim but cannot replace the original creation claim.
    """
    _display_name = "WebSecretFixtureReconciledSource"

    def __init__(self, record: WebSecretFixtureCreationRecord, path: Path) -> None:
        try:
            if type(record) is not WebSecretFixtureCreationRecord or not isinstance(path, Path):
                raise ValueError
            self._record, self._path = record, path
            self._original = record.read_acknowledged_creation()
            if record._ack_capture is None:
                raise ValueError
            data = self._read(path)
            self._identity = self._file_identity(path)
            self._digest = hashlib.sha256(data).hexdigest()
            payload = json.loads(data, object_pairs_hook=_unique_members, parse_constant=_reject_constant)
            if type(payload) is not dict or set(payload) != {"value", "seal"}:
                raise ValueError
            value, seal = payload["value"], payload["seal"]
            if type(value) is not dict or set(value) != _VALUE_FIELDS or not self._is_digest(seal):
                raise ValueError
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
            expected = hmac.new(record._key, _DOMAIN + record._namespace.encode("ascii") + b"\0" + encoded,
                hashlib.sha256).hexdigest()
            if not hmac.compare_digest(seal, expected):
                raise ValueError
            if (value["contract"] != CONTRACT or value["namespace"] != record._namespace
                    or value["creation_digest"] != self._original.creation.creation_digest
                    or value["execution_authority"] is not False
                    or type(value["observed_at"]) is not int or type(value["completed_at"]) is not int
                    or not 0 <= value["observed_at"] <= value["completed_at"]
                    or type(value["original_claim_count"]) is not int
                    or not 1 <= value["original_claim_count"] == record._execution_store.claim_count
                    or not self._is_digest(value["preservation_digest"])
                    or not self._is_digest(value["observer_attempt_digest"])):
                raise ValueError
            for key, credential in (("credential", True), ("totp", False)):
                if type(value[key]) is not dict or WebSecretFixtureApiPreservationReader._envelope(
                        value[key], self._original.creation, credential=credential) != value[key]:
                    raise ValueError
            files = value["original_files"]
            required = _REQUIRED_FILES if record._ack_capture.observe_source else _NORMAL_REQUIRED_FILES
            if (type(files) is not dict or not required <= files.keys() or not 4 <= len(files) <= 32
                    or any(type(name) is not str or len(name) > 128 or ".." in name
                        or re.fullmatch(r"[A-Za-z0-9_./-]+", name) is None or name.startswith("/")
                        or not self._is_digest(digest) for name, digest in files.items())
                    or any(name.startswith("creation/") and name not in _CREATION_FILES for name in files)):
                raise ValueError
            self._value: dict[str, Any] = value
            self._value_digest = hashlib.sha256(encoded).hexdigest()
            self._guard()
        except Exception:
            raise WebSecretFixtureReconciledSourceError(_ERROR) from None

    @staticmethod
    def _is_digest(value: object) -> bool:
        return type(value) is str and re.fullmatch(r"[a-f0-9]{64}", value) is not None

    @staticmethod
    def _file_identity(path: Path) -> tuple[int, int]:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise ValueError
        return info.st_dev, info.st_ino

    @classmethod
    def _read(cls, path: Path) -> bytes:
        identity = cls._file_identity(path)
        raw = _read_private_buffer(path, 16384)
        try:
            if cls._file_identity(path) != identity:
                raise ValueError
            return bytes(raw)
        finally:
            _zeroize_mutable(raw)

    def _guard(self) -> None:
        try:
            record = self._record
            if (record.read_acknowledged_creation() != self._original
                    or self._file_identity(self._path) != self._identity
                    or hashlib.sha256(self._read(self._path)).hexdigest() != self._digest
                    or hashlib.sha256(json.dumps(self._value, sort_keys=True, separators=(",", ":"),
                        allow_nan=False).encode("ascii")).hexdigest() != self._value_digest):
                raise ValueError
            marker = record._directory / "api-preservation.reconciliation.attempt"
            expected = hmac.new(record._key, b"web-fixture-api-attempt/v1\0"
                + record._namespace.encode("ascii") + b"\0reconciliation\0\0[{},{}]",
                hashlib.sha256).hexdigest().encode("ascii") + b"\n"
            actual = self._read(marker)
            if (not hmac.compare_digest(actual, expected)
                    or hashlib.sha256(actual).hexdigest() != self._value["observer_attempt_digest"]):
                raise ValueError
            for name, digest in self._value["original_files"].items():
                if name in _CREATION_FILES and hashlib.sha256(self._read(
                        record._directory / name.split("/", 1)[1])).hexdigest() != digest:
                    raise ValueError
        except Exception:
            raise WebSecretFixtureReconciledSourceError(_ERROR) from None
