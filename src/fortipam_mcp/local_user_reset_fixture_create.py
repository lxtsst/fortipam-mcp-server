"""Private build-29 create-body preparation, with no transport or authority.

The fixed field set follows retained frontend modules 39797 and 390, not the
entire CMDB default object. This does not attest that creation occurred, verify
an access profile/actor, prove absence, or authorize a POST. The live candidate
still needs those checks, a durable claim and an actual post-create readback.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re

from v4_planning.material_provider import C3MaterialBinding

from .local_user_reset_http_transport import _NAME, _members, _valid_password
from .local_user_reset_projection import _object_spans, _sanitize_value, _schema_fields, _string_or_empty
from .local_user_reset_metadata_reader import _validate_value
from .local_user_reset_name_reader import _ROW
from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _append_material
from .secret_metadata_http_transport import _json_value_end, _skip_json_space, _zeroize_mutable

_UNAVAILABLE = "The private Local User fixture-create draft is unavailable."
_MAX_BYTES = 1_048_576
BP005_STANDARD_USERNAME_PATTERN = re.compile(
    r"mcp-v4-user-bp005-standard-[A-Za-z0-9][A-Za-z0-9._-]{0,36}\Z"
)
# Intersection of the User whitelist and the concrete unparse return keys.
# UI-only $originalName is absent for a new default. Password is added only by
# the private encoder; history, q_* and non-submitted schema fields stay out.
_FIELDS = frozenset({
    "id", "name", "display-name", "wildcard", "remote-auth", "remote-group", "remote-server",
    "guest-auth", "cert-auth", *(f"trusthost{index}" for index in range(1, 11)),
    "accprofile", "comments", "vdom", "schedule", "guest-lang", "two-factor",
    "two-factor-notification", "fortitoken", "email-to", "status", "sponsor-group",
    "auto-created-user", "secret-launch-limitation-override", "secret-launch-limitation",
})


class LocalUserResetFixtureCreateError(RuntimeError):
    """Fixed non-disclosing failure; no source or initial material is returned."""

    def __init__(self, stage: str) -> None:
        super().__init__(_UNAVAILABLE)
        self.stage = stage


@dataclass(frozen=True, slots=True, repr=False)
class LocalUserResetFixtureCreateDraft(C3MaterialBinding):
    """Immutable private wire skeleton; not a planning Scheme or create proof."""

    username: str
    access_profile: str
    source_defaults_digest: str
    nonmaterial_request_digest: str
    _wire: bytes
    _response_vdom: str

    def _encode(self, initial_password: memoryview) -> bytearray:
        """Private caller owns the returned buffer and must clear it on exit."""
        with _MutableJSONBuffer() as body:
            try:
                if not _valid_password(initial_password):
                    raise ValueError
                body.extend(self._wire[:-1])
                body.extend(b',"password":')
                _append_material(body, initial_password)
                body.append(125)
                return body.finish()
            except Exception:
                raise LocalUserResetFixtureCreateError("material_encoding") from None


@dataclass(frozen=True, slots=True, repr=False)
class LocalUserResetFixtureCreatedReadback(C3MaterialBinding):
    """Private postcondition observation; alone not creation or reset authority."""

    username: str
    user_id: int
    request_digest: str
    readback_digest: str


def verify_fixture_created_detail(
    content: bytearray, draft: LocalUserResetFixtureCreateDraft,
) -> LocalUserResetFixtureCreatedReadback:
    return _verify_fixture_created_detail(content, draft, username_pattern=_NAME)


def verify_bp005_standard_user_base_detail(
    content: bytearray, draft: LocalUserResetFixtureCreateDraft,
) -> LocalUserResetFixtureCreatedReadback:
    """Verify the disabled Guest-equivalent base using the BP005 name scope."""
    return _verify_fixture_created_detail(
        content, draft, username_pattern=BP005_STANDARD_USERNAME_PATTERN,
    )


def _verify_fixture_created_detail(
    content: bytearray, draft: LocalUserResetFixtureCreateDraft, *,
    username_pattern: re.Pattern[str],
) -> LocalUserResetFixtureCreatedReadback:
    """Compare the complete submitted non-material field set after creation.

    Id may change from its new-object sentinel to a positive assigned id.
    An empty submitted VDOM may read back as the one source-response scope;
    its actual representation remains bound into the readback digest.
    WebAuthn compares the submitted status only; this is not the complete User
    state needed by reset. A successful create response is independently needed
    to attribute this observation to our dispatch.
    """
    selected = bytearray()
    try:
        if type(draft) is not LocalUserResetFixtureCreateDraft:
            raise ValueError
        expected = json.loads(draft._wire)
        if (set(expected) != _FIELDS | {"webauthn"} or expected["id"] != 0
            or expected["name"] != draft.username or expected["accprofile"] != "Guest"
            or expected["status"] not in {"enable", "disable"} or expected["vdom"] != []
            or hashlib.sha256(draft._wire).hexdigest() != draft.nonmaterial_request_digest):
            raise ValueError
        root = _fixture_envelope(content, method="GET", expected_name=draft.username,
                                 expected_vdom=draft._response_vdom,
                                 username_pattern=username_pattern)
        left, right = root["results"]
        if content[left] == 91:
            left = _skip_json_space(content, left + 1)
            end = _json_value_end(content, left)
            if _skip_json_space(content, end) != right - 1:
                raise ValueError
            right = end
        row = _object_spans(content, left, right)
        if not set(expected) | {"q_ref"} <= row.keys() or not row.keys() <= set(expected) | _ROW:
            raise ValueError
        for key in ("name", "q_origin_key"):
            if key in row and content[slice(*row[key])] != json.dumps(draft.username).encode("ascii"):
                raise ValueError
        for left, right in row.values():
            _validate_value(content, left, right, depth=0)
        if content[slice(*row["q_ref"])] != b"0":
            raise ValueError
        selected.append(123)
        for index, key in enumerate(sorted(expected)):
            if index:
                selected.append(44)
            selected.extend(json.dumps(key).encode("ascii")); selected.append(58)
            if key == "webauthn":
                children = _object_spans(content, *row[key])
                if content[slice(*children["status"])] != b'"disable"':
                    raise ValueError
                selected.extend(b'{"status":"disable"}')
            else:
                selected.extend(memoryview(content)[slice(*row[key])])
        selected.append(125)
        observed = json.loads(selected)
        user_id = observed["id"]
        if type(user_id) is not int or user_id <= 0:
            raise ValueError
        observed["id"] = 0
        observed_vdom = observed["vdom"]
        if observed_vdom != []:
            if observed_vdom != [{"name": draft._response_vdom, "q_origin_key": draft._response_vdom}]:
                raise ValueError
            observed["vdom"] = []
        canonical = json.dumps(observed, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                               allow_nan=False).encode("utf-8")
        if not hmac.compare_digest(canonical, draft._wire):
            raise ValueError
        digest = hashlib.sha256(json.dumps({"user_id": user_id, "request": draft.nonmaterial_request_digest,
            "reported_reference_count": 0, "response_vdom": draft._response_vdom,
            "observed_vdom": observed_vdom}, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
        return LocalUserResetFixtureCreatedReadback(draft.username, user_id, draft.nonmaterial_request_digest, digest)
    except Exception:
        raise LocalUserResetFixtureCreateError("created_readback") from None
    finally:
        _zeroize_mutable(selected)
        _zeroize_mutable(content)


def verify_fixture_create_response(content: bytearray, *, expected_name: str, expected_vdom: str) -> None:
    """Require an exact successful POST identity; never infer it from readback."""
    try:
        _fixture_envelope(content, method="POST", expected_name=expected_name, expected_vdom=expected_vdom)
    except Exception:
        raise LocalUserResetFixtureCreateError("create_response") from None
    finally:
        _zeroize_mutable(content)


def verify_bp005_standard_user_create_response(
    content: bytearray, *, expected_name: str, expected_vdom: str,
) -> None:
    """Verify create attribution only for the closed BP005 username scope."""
    try:
        _fixture_envelope(
            content, method="POST", expected_name=expected_name,
            expected_vdom=expected_vdom,
            username_pattern=BP005_STANDARD_USERNAME_PATTERN,
        )
    except Exception:
        raise LocalUserResetFixtureCreateError("create_response") from None
    finally:
        _zeroize_mutable(content)


def _fixture_envelope(content: bytearray, *, method: str, expected_name: str,
                      expected_vdom: str,
                      username_pattern: re.Pattern[str] = _NAME) -> dict[str, tuple[int, int]]:
    if (type(content) is not bytearray or not 0 < len(content) <= _MAX_BYTES
        or method not in {"GET", "POST"} or not isinstance(expected_name, str)
        or len(expected_name) > 64 or username_pattern.fullmatch(expected_name) is None):
        raise ValueError
    left = _skip_json_space(content, 0); right = _json_value_end(content, left)
    if _skip_json_space(content, right) != len(content):
        raise ValueError
    root = _object_spans(content, left, right)
    _validate_scope(expected_vdom)
    allowed = {"http_method", "http_status", "status", "version", "build", "path", "name", "mkey",
               "results", "revision", "revision_changed", "serial", "vdom", "action"}
    if method == "POST":
        allowed.add("old_revision")
    if not root.keys() <= allowed:
        raise ValueError
    for key, value in {"http_method": method, "http_status": 200, "status": "success", "version": "v7.0.0",
                       "build": 29, "path": "system", "name": "admin", "mkey": expected_name,
                       "vdom": expected_vdom}.items():
        if content[slice(*root[key])] != json.dumps(value).encode("ascii"):
            raise ValueError
    for start, end in root.values():
        _validate_value(content, start, end, depth=0)
    for key in ("old_revision", "revision", "serial"):
        if key in root:
            with memoryview(content)[slice(*root[key])] as token:
                _string_or_empty(token)
    if "action" in root and content[slice(*root["action"])] != b'""':
        raise ValueError
    if "revision_changed" in root and content[slice(*root["revision_changed"])] != b"true":
        raise ValueError
    return root


def _validate_scope(value: object) -> None:
    if (not isinstance(value, str) or not 0 < len(value) <= 255
        or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError


def prepare_local_user_reset_fixture_create(
    content: bytearray, schema: object, *, username: str, access_profile: str,
) -> LocalUserResetFixtureCreateDraft:
    return _prepare_local_user_create(
        content, schema, username=username, access_profile=access_profile,
        username_pattern=_NAME, target_status="enable",
    )


def prepare_bp005_standard_user_base_create(
    content: bytearray, schema: object, *, username: str,
) -> LocalUserResetFixtureCreateDraft:
    """Compile qualified defaults for BP005 without using the BP002 name scope."""
    return _prepare_local_user_create(
        content, schema, username=username, access_profile="Guest",
        username_pattern=BP005_STANDARD_USERNAME_PATTERN, target_status="disable",
    )


def _prepare_local_user_create(
    content: bytearray, schema: object, *, username: str, access_profile: str,
    username_pattern: re.Pattern[str], target_status: str,
) -> LocalUserResetFixtureCreateDraft:
    """Consume fresh full default data; exclude material before any value decode.

The requested profile must independently be read-qualified by the future
acceptance client. Neither a valid name nor this private draft grants it.
    """
    sanitized = bytearray()
    stage = "input_binding"
    try:
        if (
            type(content) is not bytearray or not 0 < len(content) <= _MAX_BYTES
            or type(username) is not str or len(username) > 64 or username_pattern.fullmatch(username) is None
            or type(access_profile) is not str or not 0 < len(access_profile) <= 64
            or access_profile.casefold() == "super_admin"
            or any(ord(character) < 32 or ord(character) == 127 for character in access_profile)
            or target_status not in {"enable", "disable"}
        ):
            raise ValueError
        stage = "source_schema"
        fields = _schema_fields(schema)
        stage = "source_envelope"
        start = _skip_json_space(content, 0)
        end = _json_value_end(content, start)
        if _skip_json_space(content, end) != len(content):
            raise ValueError
        envelope = _members(content, start, end, {
            b'"action"', b'"build"', b'"http_method"', b'"http_status"', b'"name"', b'"path"',
            b'"results"', b'"revision"', b'"serial"', b'"status"', b'"vdom"', b'"version"',
        })
        for key, value in {
            b'"action"': b'"default"', b'"build"': b'29', b'"http_method"': b'"GET"',
            b'"http_status"': b'200', b'"name"': b'"admin"', b'"path"': b'"system"',
            b'"status"': b'"success"', b'"version"': b'"v7.0.0"',
        }.items():
            with memoryview(content)[slice(*envelope[key])] as token:
                if token != value:
                    raise ValueError
        for key in (b'"revision"', b'"serial"', b'"vdom"'):
            if key in envelope:
                with memoryview(content)[slice(*envelope[key])] as token:
                    _string_or_empty(token)
        response_vdom = json.loads(content[slice(*envelope[b'"vdom"'])])
        _validate_scope(response_vdom)
        stage = "default_projection"
        spans = _object_spans(content, *envelope[b'"results"'])
        if not (_FIELDS - {"vdom"}) <= spans.keys() or not {"password", "webauthn"} <= spans.keys():
            raise ValueError
        # The default response contains fields absent from schema, including
        # shared-key/history and GUI state. Validate syntax without decoding any
        # unselected value. This is a create projection, NOT full User readback.
        for left, right in spans.values():
            _validate_value(content, left, right, depth=0)
        for field in ("password", *(f"history{index}" for index in range(20))):
            if field in spans:
                with memoryview(content)[slice(*spans[field])] as token:
                    _string_or_empty(token)
        # New User UI replaces accprofile by its chosen Role and guest-lang by
        # English. Do not decode/copy their reference-object defaults. User.parse
        # supplies vdom=[]; User.unparse retains only webauthn.status.
        selected = _FIELDS - {"accprofile", "guest-lang", "vdom"}
        sanitized.append(123)
        for index, field in enumerate(sorted(selected)):
            if index:
                sanitized.append(44)
            sanitized.extend(json.dumps(field).encode("ascii"))
            sanitized.append(58)
            _sanitize_value(content, *spans[field], fields.get(field), sanitized, depth=1)
        sanitized.append(125)
        defaults = json.loads(sanitized)
        stage = "new_identity_and_fields"
        if (defaults.get("name") != "" or type(defaults.get("id")) is not int or defaults["id"] != 0
            or defaults.get("status") not in {"enable", "disable"}):
            raise ValueError
        # Do not silently inherit external identity, MFA or an existing group.
        stage = "identity_defaults"
        for field in ("remote-auth", "wildcard", "guest-auth", "cert-auth", "two-factor"):
            if defaults.get(field) != "disable":
                raise ValueError
        if defaults.get("auto-created-user") != "no":
            raise ValueError
        stage = "relation_defaults"
        for field in ("sponsor-group", "schedule", "remote-group", "remote-server", "fortitoken", "email-to"):
            if defaults.get(field) != "":
                raise ValueError
        # Require an explicit source status; never use the GUI's
        # missing-status fallback as evidence of a safe default.
        stage = "webauthn_defaults"
        webauthn = _object_spans(content, *spans["webauthn"])
        with memoryview(content)[slice(*webauthn["status"])] as token:
            if not hmac.compare_digest(token, b'"disable"'):
                raise ValueError
        stage = "wire_encoding"
        body = {field: defaults[field] for field in _FIELDS if field in defaults}
        body.update(name=username, accprofile=access_profile, status=target_status, vdom=[])
        body["guest-lang"] = "en"
        body["webauthn"] = {"status": "disable"}
        wire = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("utf-8")
        # Only selected source defaults are represented, not a complete user
        # state or all unsubmitted GUI/material fields in this response.
        defaults["webauthn"] = {"status": "disable"}
        defaults["response_vdom"] = response_vdom
        source = json.dumps(defaults, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                            allow_nan=False).encode("utf-8")
        return LocalUserResetFixtureCreateDraft(
            username, access_profile, hashlib.sha256(source).hexdigest(),
            hashlib.sha256(wire).hexdigest(), wire, response_vdom,
        )
    except Exception:
        raise LocalUserResetFixtureCreateError(stage) from None
    finally:
        _zeroize_mutable(sanitized)
        if isinstance(content, bytearray):
            _zeroize_mutable(content)
