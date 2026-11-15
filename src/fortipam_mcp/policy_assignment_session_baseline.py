"""Private build29 empty Secret-session source; no transport or authority.

The qualified frontend GET /api/v2/monitor/user/proxy-session/select explicitly
handles an empty results array. Only that native empty shape is qualified here.
Missing, malformed or nonempty results never become an empty baseline. Source
actor, visibility and freshness remain the trusted producer's responsibility.
"""
from __future__ import annotations

from dataclasses import dataclass
import re

from v4_planning.material_provider import _OpaqueC3Object

from . import secret_bulk_import_metadata as metadata
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable
from .target_lifecycle_dependencies import _envelope, _spans
from .target_preservation_contract import _digest

CONTRACT = "fortipam-build29-policy-assignment-empty-session-source-v1"
_ERROR = "The private empty Secret-session source is unavailable."
_PAGING = frozenset({"next_idx", "next_index", "total", "total_count", "has_more", "offset",
    "start", "limit", "count", "limit_reached"})


class PolicyAssignmentSessionBaselineError(ValueError):
    """Fixed refusal, including nonempty or unqualified native results."""


@dataclass(frozen=True, slots=True, repr=False)
class PolicyAssignmentSessionBaseline(_OpaqueC3Object):
    serial_digest: str
    observation_digest: str

    def summary(self) -> dict[str, object]:
        return dict(contract=CONTRACT, observed_native_secret_session_result_empty=True,
            session_values_or_locators_returned=False, global_session_absence_qualified=False,
            actor_visibility_qualified=False, source_provenance_qualified=False,
            request_absence_qualified=False, assignment_authorized=False)


def consume_policy_assignment_empty_session_source(content: bytearray, *,
        serial_digest: str) -> PolicyAssignmentSessionBaseline:
    """Consume one exact empty native result, without decoding session values.

    Nonempty results are conservatively refused; the other frontend display
    shapes and fields are not promoted without their own native qualification.
    This observation alone never authorizes an assignment or proves global
    visibility. The owned buffer clears on success, refusal and interruption.
    """
    try:
        if type(serial_digest) is not str or re.fullmatch(r"[a-f0-9]{64}", serial_digest) is None:
            raise ValueError
        fields = _spans(content)
        span = _envelope(content, path="user", name="proxy-session", serial_digest=serial_digest,
            monitor=True, action="select")
        if "action" not in fields or metadata._scalar(content, fields["action"]) != "select":
            raise ValueError
        if metadata._array(content, span, 0):
            raise ValueError
        # A cursor or partial-result hint never becomes an empty observation.
        start = _skip_json_space(content, 0)
        paging = metadata._object_spans(content, start, _json_value_end(content, start), _PAGING)
        if paging:
            raise ValueError
        for name in ("size", "matched_count", "filtered_count"):
            if name in fields:
                value = metadata._scalar(content, fields[name])
                if type(value) is not int or value != 0:
                    raise ValueError
        return PolicyAssignmentSessionBaseline(serial_digest, _digest((CONTRACT, serial_digest, "native-empty-result")))
    except Exception:
        raise PolicyAssignmentSessionBaselineError(_ERROR) from None
    finally:
        if type(content) is bytearray:
            _zeroize_mutable(content)
