"""Private consuming Target creation evidence; no ownership authority or I/O.

A future fixed creator must supply its actual route-bound absence, original POST
ACK, complete readback and durable claim digest. These hashes cannot authorize
adoption, writes or cleanup by themselves; seal their provenance in the owning
runtime before use. Generated id/uuid/creation-time remain opaque and are bound
in the complete created-state fingerprint rather than copied from the proposal.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Literal

from . import secret_bulk_import_metadata as m
from . import target_preservation_contract as c
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from v4_planning.material_provider import _OpaqueC3Object

_ERROR = 'Protected Target creation evidence unavailable.'
_GENERATED = frozenset({'id', 'uuid', 'creation-time'})
_LIMIT = 2 * 1048576


class TargetCreationEvidenceError(ValueError):
    """No selectors or native values in failures."""


@dataclass(frozen=True, slots=True, repr=False)
class TargetCreationEvidence(_OpaqueC3Object):
    proposal_digest: str
    claim_digest: str
    absence_digest: str
    acknowledgement_digest: str
    created: c.TargetState
    evidence_digest: str


def _require_digest(value: object) -> None:
    if type(value) is not str or c._DIGEST.fullmatch(value) is None:
        raise ValueError


def _envelope(content: bytearray, proposal: c.TargetState, *, absent: bool,
              method: Literal['POST', 'DELETE'] = 'POST') -> str:
    if type(method) is not str or method not in ('POST', 'DELETE'):
        raise ValueError
    if type(content) is not bytearray or not 0 < len(content) <= _LIMIT:
        raise ValueError
    start = _skip_json_space(content, 0)
    end = _json_value_end(content, start)
    if _skip_json_space(content, end) != len(content):
        raise ValueError
    m._validate_json(content, start, end, depth=0, budget=[50000])
    fields = m._object_spans(content, start, end, c._ENVELOPE)
    for key, expected in {'version':'v7.0.0', 'build':29, 'path':'secret', 'name':'target',
            'vdom':'root', 'http_method':'GET' if absent else method,
            'status':'Not Found' if absent else 'success', 'http_status':404 if absent else 200}.items():
        actual = m._scalar(content, fields[key])
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError
    serial = m._text(m._scalar(content, fields['serial']), maximum=128)
    if hashlib.sha256(serial.encode()).hexdigest() != proposal.serial_digest:
        raise ValueError
    if not absent or 'mkey' in fields:
        if m._scalar(content, fields['mkey']) != proposal.name:
            raise ValueError
    if absent:
        error = fields.get('error')
        if error is None or content[error[0]:error[1]] != b'2': raise ValueError
        span = fields.get('results')
        if span is not None:
            if content[span[0]] == 91:
                if m._array(content, span, 1): raise ValueError
            elif content[span[0]] == 123:
                if c._member_count(content, span): raise ValueError
            elif content[span[0]:span[1]] != b'null':
                raise ValueError
    elif 'error' in fields:
        error = m._scalar(content, fields['error'])
        if error is not None and (type(error) is not int or error != 0):
            raise ValueError
    return hashlib.sha256(content).hexdigest()


def _fingerprint(proposal: str, claim: str, absence: str, ack: str, created: c.TargetState) -> str:
    return c._digest(('target-creation-evidence-v1', proposal, claim, absence, ack, created.state_digest))


def verify_target_creation_evidence(absence: bytearray, acknowledgement: bytearray,
                                    detail: bytearray, *, proposal: c.TargetState,
                                    claim_digest: str) -> TargetCreationEvidence:
    """Consume three actual source responses; bind every non-generated proposed field."""
    try:
        c._checked_state(proposal)
        _require_digest(claim_digest)
        absent_digest = _envelope(absence, proposal, absent=True)
        ack_digest = _envelope(acknowledgement, proposal, absent=False)
        created = c.capture_target_state(detail, expected_name=proposal.name,
                                         expected_serial_digest=proposal.serial_digest)
        wanted, observed = dict(proposal.field_digests), dict(created.field_digests)
        if any(wanted[key] != observed[key] for key in c.TARGET_STATE_FIELDS - _GENERATED):
            raise ValueError
        digest = _fingerprint(proposal.state_digest, claim_digest, absent_digest, ack_digest, created)
        return TargetCreationEvidence(proposal.state_digest, claim_digest, absent_digest, ack_digest, created, digest)
    except Exception:
        raise TargetCreationEvidenceError(_ERROR) from None
    finally:
        for content in (absence, acknowledgement, detail):
            if isinstance(content, bytearray): _zeroize_mutable(content)


def verify_original_target_state(content: bytearray, *, evidence: TargetCreationEvidence,
                                 expected_claim_digest: str) -> c.TargetState:
    """Check a sealed caller-selected evidence anchor; no self-issued ownership claim."""
    try:
        if type(evidence) is not TargetCreationEvidence:
            raise ValueError
        for value in (evidence.proposal_digest, evidence.claim_digest, evidence.absence_digest,
                      evidence.acknowledgement_digest, evidence.evidence_digest, expected_claim_digest):
            _require_digest(value)
        c._checked_state(evidence.created)
        if (evidence.claim_digest != expected_claim_digest or evidence.evidence_digest != _fingerprint(
                evidence.proposal_digest, evidence.claim_digest, evidence.absence_digest,
                evidence.acknowledgement_digest, evidence.created)):
            raise ValueError
        current = c.capture_target_state(content, expected_name=evidence.created.name,
                                         expected_serial_digest=evidence.created.serial_digest)
        if current.state_digest != evidence.created.state_digest:
            raise ValueError
        return current
    except Exception:
        raise TargetCreationEvidenceError(_ERROR) from None
    finally:
        if isinstance(content, bytearray): _zeroize_mutable(content)
