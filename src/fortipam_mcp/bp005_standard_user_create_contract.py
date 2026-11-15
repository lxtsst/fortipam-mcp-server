"""Fixed FortiPAM 7.0 Standard User creation body and semantic readback.

This is a private contract component only: it has no transport, dispatch,
authorization, credential persistence, or MCP registration. It reuses the
already source-qualified User default projection while pinning the BP005
audience to ``pam_standard_user`` and ``status=enable``.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json

from v4_planning.material_provider import C3MaterialBinding

from .local_user_reset_fixture_create import (
    LocalUserResetFixtureCreateDraft,
    LocalUserResetFixtureCreateError,
    _FIELDS,
    BP005_STANDARD_USERNAME_PATTERN,
    _fixture_envelope,
    prepare_bp005_standard_user_base_create,
    verify_bp005_standard_user_base_detail,
)
from .local_user_reset_projection import _object_spans
from .local_user_reset_http_transport import _valid_password
from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _append_material
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

_PROFILE = "pam_standard_user"
_STATUS = "enable"
_UNAVAILABLE = "The BP005 Standard User create contract is unavailable."


class Bp005StandardUserCreateError(RuntimeError):
    """Stable failure that never includes source, response, or C3 material."""


@dataclass(frozen=True, slots=True, repr=False)
class Bp005StandardUserCreateDraft(C3MaterialBinding):
    """Private, non-dispatchable body skeleton with no password field."""

    username: str
    source_defaults_digest: str
    nonmaterial_request_digest: str
    _wire: bytes
    _response_vdom: str
    _verification_draft: LocalUserResetFixtureCreateDraft

    def _encode(self, initial_password: memoryview) -> bytearray:
        with _MutableJSONBuffer() as body:
            try:
                if not _valid_password(initial_password):
                    raise ValueError
                if hashlib.sha256(self._wire).hexdigest() != self.nonmaterial_request_digest:
                    raise ValueError
                body.extend(self._wire[:-1])
                body.extend(b',"password":')
                _append_material(body, initial_password)
                body.append(125)
                return body.finish()
            except Exception:
                raise Bp005StandardUserCreateError(_UNAVAILABLE) from None


@dataclass(frozen=True, slots=True, repr=False)
class Bp005StandardUserCreatedReadback(C3MaterialBinding):
    """Private categorical identity and exact request/readback digests."""

    username: str
    user_id: int
    request_digest: str
    readback_digest: str


def prepare_bp005_standard_user_create(
    content: bytearray,
    schema: object,
    *,
    username: str,
) -> Bp005StandardUserCreateDraft:
    """Compile the qualified User defaults into one enabled Standard User.

    The underlying default projector deliberately emits only the existing
    disabled Guest fixture contract. This BP005 wrapper derives a separate,
    immutable body and binds the exact Standard User profile/status pair.
    The selected access-profile identity must still be read-qualified by the
    action's own live preflight before any dispatch.
    """

    base: LocalUserResetFixtureCreateDraft | None = None
    wire: bytearray | None = None
    try:
        base = prepare_bp005_standard_user_base_create(content, schema, username=username)
        if base.username != username or base.access_profile != "Guest":
            raise ValueError
        selected = json.loads(base._wire)
        if (
            type(selected) is not dict
            or set(selected) != _FIELDS | {"webauthn"}
            or selected.get("status") != "disable"
            or selected.get("accprofile") != "Guest"
            or selected.get("name") != username
            or selected.get("id") != 0
        ):
            raise ValueError
        selected["accprofile"] = _PROFILE
        selected["status"] = _STATUS
        wire = bytearray(json.dumps(
            selected, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("utf-8"))
        digest = hashlib.sha256(wire).hexdigest()
        return Bp005StandardUserCreateDraft(
            username, base.source_defaults_digest, digest, bytes(wire),
            base._response_vdom, base,
        )
    except Exception:
        raise Bp005StandardUserCreateError(_UNAVAILABLE) from None
    finally:
        if wire is not None:
            _zeroize_mutable(wire)


def verify_bp005_standard_user_created_detail(
    content: bytearray,
    draft: Bp005StandardUserCreateDraft,
) -> Bp005StandardUserCreatedReadback:
    """Require exact enabled-Standard state, then compare every other field.

    The private verifier normalizes the exact profile/status tokens and the
    derived reference count in a cleared temporary buffer. It validates and
    binds the observed reference count separately, then delegates all submitted
    fields, identity, and scope checks to the already-qualified create readback.
    """

    normalized: bytearray | None = None
    try:
        if (
            type(draft) is not Bp005StandardUserCreateDraft
            or type(draft._verification_draft) is not LocalUserResetFixtureCreateDraft
            or draft._verification_draft.username != draft.username
            or draft._verification_draft.access_profile != "Guest"
            or hashlib.sha256(draft._wire).hexdigest() != draft.nonmaterial_request_digest
        ):
            raise ValueError
        expected = json.loads(draft._wire)
        if (
            set(expected) != _FIELDS | {"webauthn"}
            or expected.get("name") != draft.username
            or expected.get("id") != 0
            or expected.get("accprofile") != _PROFILE
            or expected.get("status") != _STATUS
            or expected.get("vdom") != []
        ):
            raise ValueError

        root = _fixture_envelope(
            content, method="GET", expected_name=draft.username,
            expected_vdom=draft._response_vdom,
            username_pattern=BP005_STANDARD_USERNAME_PATTERN,
        )
        left, right = root["results"]
        if content[left] == 91:
            left = _skip_json_space(content, left + 1)
            end = _json_value_end(content, left)
            if _skip_json_space(content, end) != right - 1:
                raise ValueError
            right = end
        row = _object_spans(content, left, right)
        profile_span, status_span, ref_span = (
            row["accprofile"], row["status"], row["q_ref"]
        )
        with memoryview(content)[slice(*profile_span)] as value:
            if not hmac.compare_digest(value, b'"pam_standard_user"'):
                raise ValueError
        with memoryview(content)[slice(*status_span)] as value:
            if not hmac.compare_digest(value, b'"enable"'):
                raise ValueError
        observed_reference_count = json.loads(content[slice(*ref_span)])
        if type(observed_reference_count) is not int or observed_reference_count < 0:
            raise ValueError

        replacements = sorted((
            (*profile_span, b'"Guest"'),
            (*status_span, b'"disable"'),
            (*ref_span, b'0'),
        ))
        if any(first[1] > second[0] for first, second in zip(replacements, replacements[1:])):
            raise ValueError
        normalized = bytearray()
        cursor = 0
        for start, end, replacement in replacements:
            with memoryview(content)[cursor:start] as part:
                normalized.extend(part)
            normalized.extend(replacement)
            cursor = end
        with memoryview(content)[cursor:] as part:
            normalized.extend(part)

        observed = verify_bp005_standard_user_base_detail(normalized, draft._verification_draft)
        normalized = None  # delegated verifier zeroizes its input on all paths
        final_digest = hashlib.sha256(json.dumps({
            "contract": "bp005-standard-user-created-readback-v1",
            "request_digest": draft.nonmaterial_request_digest,
            "normalized_readback_digest": observed.readback_digest,
            "access_profile": _PROFILE,
            "status": _STATUS,
            "observed_reference_count": observed_reference_count,
        }, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")).hexdigest()
        return Bp005StandardUserCreatedReadback(
            observed.username, observed.user_id, draft.nonmaterial_request_digest, final_digest,
        )
    except Exception:
        raise Bp005StandardUserCreateError(_UNAVAILABLE) from None
    finally:
        _zeroize_mutable(content)
        if normalized is not None:
            _zeroize_mutable(normalized)


__all__ = [
    "Bp005StandardUserCreateDraft",
    "Bp005StandardUserCreateError",
    "Bp005StandardUserCreatedReadback",
    "prepare_bp005_standard_user_create",
    "verify_bp005_standard_user_created_detail",
]
