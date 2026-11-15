"""Inactive one-percentage-point file-to-Instruction reallocation candidate.

Both fields belong to secret/setting, so the candidate uses one two-field body.
It never changes video/software allocations, performs I/O, grants execution, or
proves recovery ownership. A writer must separately bind the original ACK and
authorization, reject drift immediately before dispatch, and perform readback.
"""
from __future__ import annotations

import json
from typing import Literal, NoReturn, cast

from v4_planning.material_provider import _OpaqueC3Object
from . import secret_bulk_import_metadata as m
from . import target_lifecycle_dependencies as d
from .instruction_feature_contract import (
    _METADATA, _digest, _fields, _fingerprint, _schema_binding,
)
from .instruction_resource_usage import InstructionResourceUsage
from .secret_metadata_http_transport import _zeroize_mutable

CONTRACT = "fortipam-700-build29-instruction-quota-file-transfer-private-v1"
_FILE = "file-storage-quota"
_SOFTWARE = "software-storage-quota"
_INSTRUCTION = "secret-instruction-quota"
_VIDEO = "pam-video-storage-limit"
_ERROR = "The private Instruction quota reallocation contract is unavailable."


class InstructionQuotaContractError(ValueError):
    """Stable refusal without configuration, capacity, or partial plans."""


def _fail() -> NoReturn:
    raise InstructionQuotaContractError(_ERROR) from None


class _Private(_OpaqueC3Object):
    __slots__ = ()

    def __setattr__(self, name: str, value: object) -> None:
        _fail()

    def __delattr__(self, name: str) -> None:
        _fail()


class InstructionQuotaState(_Private):
    """Full secret-setting preservation plus the unchanged video allocation."""
    __slots__ = ("_serial", "_schema", "_preserved", "_quotas", "_state", "field_count")
    _serial: str
    _schema: str
    _preserved: str
    _quotas: tuple[int, int, int, int]
    _state: str
    field_count: int

    def __init__(self) -> None:
        _fail()


def _quotas_valid(quotas: tuple[int, int, int, int]) -> None:
    if (len(quotas) != 4 or any(type(value) is not int or not low <= value <= high
            for value, (low, high) in zip(quotas, ((10, 90), (1, 30), (0, 30), (0, 5))))
            or sum(quotas) > 95):
        _fail()


def _state_digest(state: InstructionQuotaState, quotas: tuple[int, int, int, int]) -> str:
    return _digest([CONTRACT, state._serial, state._schema, state._preserved, quotas])


def _quota_schema_binding(schema: bytearray, serial_digest: str) -> tuple[frozenset[str], str]:
    children, schema_digest = _schema_binding(schema, serial_digest)
    span = d._one(schema, d._envelope(schema, path="secret", name="setting",
                                    serial_digest=serial_digest, action="schema"))
    definitions = _fields(schema, _fields(schema, span)["children"])
    for key in (_FILE, _SOFTWARE, _INSTRUCTION):
        if m._scalar(schema, _fields(schema, definitions[key])["type"]) != "integer":
            raise ValueError
    return children, schema_digest


def read_instruction_quota_state(schema: bytearray, current: bytearray, video: bytearray, *,
                                  serial_digest: str) -> InstructionQuotaState:
    """Consume full secret schema/current and one exact video projection.

    Only quota scalars are decoded. The feature reader's qualified normalization
    of two unstable schema string defaults is reused; current values and all
    other schema metadata remain bound without decoding their contents.
    """
    try:
        if any(type(raw) is not bytearray for raw in (schema, current, video)):
            raise ValueError
        if len({id(schema), id(current), id(video)}) != 3:
            raise ValueError
        children, schema_digest = _quota_schema_binding(schema, serial_digest)
        span = d._one(current, d._envelope(current, path="secret", name="setting",
                                           serial_digest=serial_digest))
        fields = _fields(current, span)
        if (set(fields) - _METADATA != children or "q_no_edit" in fields
                and m._scalar(current, fields["q_no_edit"]) is not False):
            raise ValueError
        video_span = d._one(video, d._envelope(video, path="system", name="global",
                                             serial_digest=serial_digest))
        video_fields = _fields(video, video_span)
        if set(video_fields) - _METADATA != {_VIDEO}:
            raise ValueError
        quotas = cast(tuple[int, int, int, int], (
            m._scalar(video, video_fields[_VIDEO]),
            *(m._scalar(current, fields[key]) for key in (_FILE, _SOFTWARE, _INSTRUCTION))))
        _quotas_valid(quotas)
        preserved = _digest([(key, _fingerprint(current, fields[key]))
            for key in sorted(fields) if key not in {_FILE, _INSTRUCTION}])
        state = object.__new__(InstructionQuotaState)
        for key, value in {"_serial": serial_digest, "_schema": schema_digest,
                "_preserved": preserved, "_quotas": quotas, "field_count": len(children)}.items():
            object.__setattr__(state, key, value)
        object.__setattr__(state, "_state", _state_digest(state, quotas))
        return state
    except Exception:
        _fail()
    finally:
        for raw in (schema, current, video):
            if type(raw) is bytearray:
                _zeroize_mutable(raw)


def _usage_fits(state: InstructionQuotaState, usage: InstructionResourceUsage,
                quotas: tuple[int, int, int, int]) -> None:
    if type(usage) is not InstructionResourceUsage or usage._serial != state._serial:
        _fail()
    _quotas_valid(quotas)
    total, *used = usage._bytes
    # Integer cross multiplication keeps byte-boundary checks exact above 2**53/100.
    if any(amount * 100 > total * allocation for amount, allocation in zip(used, quotas)):
        _fail()


class InstructionQuotaTransition(_Private):
    """Explicit fixed reallocation or restoration, never an original-ACK claim."""
    __slots__ = ("_current", "_expected", "_phase", "_target", "_usage", "digest")
    _current: str
    _expected: str
    _phase: Literal["allocate", "restore"]
    _target: tuple[int, int, int, int]
    _usage: str
    digest: str

    def __init__(self, baseline: InstructionQuotaState, current: InstructionQuotaState,
                 usage: InstructionResourceUsage, *, phase: Literal["allocate", "restore"],
                 operation_nonce: str) -> None:
        try:
            if (type(baseline) is not InstructionQuotaState or type(current) is not InstructionQuotaState
                    or type(phase) is not str or phase not in {"allocate", "restore"}
                    or type(operation_nonce) is not str or m._DIGEST.fullmatch(operation_nonce) is None
                    or baseline._quotas[3] != 0 or baseline._quotas[1] < 2):
                raise ValueError
            video, file, software, _ = baseline._quotas
            allocated = (video, file - 1, software, 1)
            expected_current = baseline._state if phase == "allocate" else _state_digest(baseline, allocated)
            if current._state != expected_current:
                raise ValueError
            target = allocated if phase == "allocate" else baseline._quotas
            _usage_fits(current, usage, current._quotas)
            _usage_fits(current, usage, target)
            expected = _state_digest(baseline, target)
            for key, value in {"_current": current._state, "_expected": expected,
                    "_phase": phase, "_target": target, "_usage": usage._state,
                    "digest": _digest([CONTRACT, phase, operation_nonce, baseline._state,
                        current._state, usage._state, expected])}.items():
                object.__setattr__(self, key, value)
        except Exception:
            _fail()


def build_instruction_quota_body(plan: InstructionQuotaTransition, current: InstructionQuotaState,
                                 usage: InstructionResourceUsage) -> bytearray:
    """Reject config and usage drift; emit exactly the two reallocated fields."""
    if (type(plan) is not InstructionQuotaTransition or type(current) is not InstructionQuotaState
            or type(usage) is not InstructionResourceUsage or plan._current != current._state
            or plan._usage != usage._state):
        _fail()
    _usage_fits(current, usage, plan._target)
    fields = ({_FILE: plan._target[1], _INSTRUCTION: plan._target[3]} if plan._phase == "allocate"
              else {_INSTRUCTION: plan._target[3], _FILE: plan._target[1]})
    return bytearray(json.dumps(fields, separators=(",", ":")).encode("ascii"))


def verify_instruction_quota_readback(plan: InstructionQuotaTransition, current: InstructionQuotaState,
                                      usage: InstructionResourceUsage) -> None:
    """Check exact configuration restoration; quota zero also requires zero usage."""
    if (type(plan) is not InstructionQuotaTransition or type(current) is not InstructionQuotaState
            or plan._expected != current._state):
        _fail()
    _usage_fits(current, usage, current._quotas)
