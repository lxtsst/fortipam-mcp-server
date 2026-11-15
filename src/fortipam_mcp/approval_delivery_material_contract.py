"""Private full Approval Email SDK codec, with no material source or writer.

All three protected slots must be explicitly borrowed, including inactive slots.
Forwarding supplied bytes proves neither backend masking/preservation semantics
nor original custody, lease validity, recovery rights or execution authority.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import hmac
import re
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from . import approval_delivery_contract as source
from .mutable_json_buffer import _MutableJSONBuffer
from .secret_create_191_http_transport import _append_material, _valid_utf8

CONTRACT = "fortipam-build29-approval-email-full-material-sdk-codec/v1"
_ROLES = ("username", "credential", "client-secret")
_LOCAL_MATERIAL_BYTES = 4096
_ERROR = "The private approval-delivery material request is unavailable."


def _pins() -> tuple[str, str, str]:
    return (source.REQUEST_SOURCE_SHA256, source.SCHEMA_METADATA_SHA256,
            source.NORMALIZER_SOURCE_SHA256)


def _bindings(values: Mapping[str, str]) -> tuple[str, ...]:
    if not isinstance(values, Mapping):
        raise ValueError
    selected = dict(values)
    if (set(selected) != set(_ROLES)
            or any(type(selected[role]) is not str or re.fullmatch(r"[0-9a-f]{64}", selected[role]) is None
                   for role in _ROLES)):
        raise ValueError
    return tuple(selected[role] for role in _ROLES)


@dataclass(frozen=True, slots=True, repr=False, init=False)
class ApprovalDeliveryMaterialDraft(_OpaqueC3Object):
    """Factory-created typed input; never a source seal, plan or permission."""

    enabled: bool
    protocol: str
    input_nonmaterial_digest: str
    request_nonmaterial_digest: str
    _source_pins: tuple[str, str, str]
    _binding_digests: tuple[str, ...]
    _tokens: tuple[bytes | None, ...]

    def __new__(cls, *args: object, **kwargs: object) -> ApprovalDeliveryMaterialDraft:
        del args, kwargs
        raise ValueError(_ERROR)


def prepare_material_approval_delivery(values: Mapping[str, Any], *, enabled: bool,
        material_binding_digests: Mapping[str, str]) -> ApprovalDeliveryMaterialDraft:
    """Compile nonmaterial SDK fields and bind each supplied protected role.

    No C3 value is accepted here. Enable requires the known required nonmaterial
    fields, but complete frontend domain validation and backend material-size
    units remain unqualified. Disable clears both servers and forwards every
    other slot. Supplied binding digests are private input facts, not provenance.
    """
    try:
        if type(enabled) is not bool:
            raise ValueError
        selected = source._checked_nonmaterial(values)
        bindings = _bindings(material_binding_digests)
        protocol = selected["approval-email-protocol"]
        if enabled and (not selected["server"] or (
                not selected["email-pulling-server"] if protocol == "imaps"
                else not selected["tenant-id"] or not selected["app-id"])):
            raise ValueError
        proposed = dict(selected)
        if not enabled:
            proposed.update(server="", **{"email-pulling-server": ""})
        if proposed["server-cert"] in source._EMPTY_CERTIFICATE_KEYS:
            proposed["server-cert"] = ""
        pins = _pins()
        context = {"contract": CONTRACT, "sources": pins, "enabled": enabled,
                   "material_bindings": dict(zip(_ROLES, bindings, strict=True))}
        input_digest = hashlib.sha256(source._wire({**context, "nonmaterial": selected})).hexdigest()
        request_digest = hashlib.sha256(source._wire({**context, "nonmaterial": proposed})).hexdigest()
        tokens = tuple(None if key in source._MATERIAL else source._wire(proposed[key])
                       for key in source._FIELDS)
        draft = object.__new__(ApprovalDeliveryMaterialDraft)
        attributes = dict(enabled=enabled, protocol=protocol, input_nonmaterial_digest=input_digest,
            request_nonmaterial_digest=request_digest, _source_pins=pins,
            _binding_digests=bindings, _tokens=tokens)
        for name, value in attributes.items():
            object.__setattr__(draft, name, value)
        return draft
    except Exception:
        raise ValueError(_ERROR) from None


def build_approval_delivery_material_body(draft: ApprovalDeliveryMaterialDraft, *,
        username: memoryview, credential: memoryview, client_secret: memoryview,
        material_binding_digests: Mapping[str, str]) -> bytearray:
    """Borrow three readonly, mutable-backed UTF-8 views; caller erases result.

    The4096-octet cap is a local allocation bound, not interpretation of native
    password75/128 limits. Empty inactive slots must still be explicit. Active
    username and protocol credential are required when enabling. No material is
    decoded, hashed, retained in the draft, resolved or consumed as a dispatch.
    The upstream private consumer must independently enforce actual lease,
    original-state, permission, freshness and one-time operation requirements.
    """
    with _MutableJSONBuffer() as body:
        try:
            if type(draft) is not ApprovalDeliveryMaterialDraft or draft._source_pins != _pins():
                raise ValueError
            supplied = _bindings(material_binding_digests)
            if not all(hmac.compare_digest(left, right)
                       for left, right in zip(draft._binding_digests, supplied, strict=True)):
                raise ValueError
            views = dict(zip(_ROLES, (username, credential, client_secret), strict=True))
            for view in views.values():
                if (type(view) is not memoryview or type(view.obj) is not bytearray
                        or not view.readonly or view.ndim != 1 or view.format != "B"
                        or not view.c_contiguous or view.nbytes > _LOCAL_MATERIAL_BYTES
                        or not _valid_utf8(view)):
                    raise ValueError
            active = "credential" if draft.protocol == "imaps" else "client-secret"
            if draft.enabled and (not username or not views[active]):
                raise ValueError
            body.extend(b'{"approval-email-setting":{')
            for index, (key, token) in enumerate(zip(source._FIELDS, draft._tokens, strict=True)):
                if index:
                    body.append(44)
                body.extend(source._wire(key))
                body.append(58)
                if token is None:
                    _append_material(body, views[key])
                else:
                    body.extend(token)
            body.extend(b"}}")
            return body.finish()
        except Exception:
            raise ValueError(_ERROR) from None


def approval_delivery_material_boundary() -> dict[str, object]:
    """Fixed facts only; no input, material binding, endpoint or draft digest."""
    return dict(contract=CONTRACT, sdk_field_count=14, explicit_protected_slots=3,
        protocols=["imaps", "ms-graph"], disabled_clears_both_servers=True,
        factory_only_typed_draft=True,
        inactive_material_slots_forwarded=True, local_material_utf8_byte_cap=_LOCAL_MATERIAL_BYTES,
        material_values_decoded_or_hashed=False, native_material_size_units_qualified=False,
        complete_frontend_validation_qualified=False, material_source_or_lease_qualified=False,
        backend_material_masking_or_preservation_qualified=False,
        complete_current_baseline_qualified=False, singleton_partial_put_merge_qualified=False,
        independent_restore_qualified=False, polling_or_approval_effect_qualified=False,
        source_or_request_grants_authority=False, material_provider_registered=False,
        http_transport_registered=False, mcp_tool_registered=False, execution_authorized=False,
        device_contacted=False)
