"""Private build29 singleton EmailServer SDK payload; no dispatch authority.

Pinned module99290 saves the module2367 twelve-field unparse using singleton
PUT. The full fifteen-field source remains the readback boundary. This codec
only supports unchanged empty, disabled authentication; it accepts no credential
value, recipient, endpoint selector or operation. A future actual M4 must bind
its private input and emptiness facts to fresh source, intent and permission.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib
import ipaddress
import json
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

CONTRACT="fortipam-build29-email-server-empty-auth-sdk-payload/v1"
_WIRE_FIELDS=("type","sender","reply-to","server","port","source-ip","source-ip6","authenticate",
    "validate-server","username","password","security")
_OMITTED=("interface","interface-select-method","ssl-min-proto-version")
_NONMATERIAL=set(_WIRE_FIELDS)-{"username","password"}|set(_OMITTED)
_ERROR="The private empty-auth system-email payload is unavailable."


def _wire(value: object) -> bytes:
    return json.dumps(value,separators=(",",":"),ensure_ascii=True,allow_nan=False).encode("ascii")


@dataclass(frozen=True,slots=True,repr=False)
class SystemEmailEmptyAuthDraft(_OpaqueC3Object):
    """Private data only; neither a plan, full rollback seal nor authorization."""
    request_digest: str
    unforwarded_state_digest: str
    _wire: bytes

    def _encode(self) -> bytearray:return bytearray(self._wire)


def prepare_empty_auth_system_email(values: Mapping[str,Any],*,username_empty: bool=False,
        password_empty: bool=False) -> SystemEmailEmptyAuthDraft:
    """Mirror parse/unparse with the native service type preserved, not UI toggles.

    Direct UI form boolean-type conversion and nonempty credential preservation
    remain outside this contract. All unforwarded fields need unchanged full
    post-readback; their absence in the SDK body is not permission to reset them.
    """
    try:
        if (type(username_empty) is not bool or username_empty is not True
                or type(password_empty) is not bool or password_empty is not True
                or not isinstance(values,Mapping) or set(values)!=_NONMATERIAL):raise ValueError
        selected=dict(values)
        for key,value in selected.items():
            if key=="port":
                if type(value) is not int or not 1<=value<=65535:raise ValueError
            elif (type(value) is not str or len(value.encode("utf-8"))>4096
                    or any(ord(c)<32 or ord(c)==127 for c in value)):raise ValueError
        if (selected["type"] not in ("default","custom") or selected["security"] not in ("none","smtps","starttls")
                or selected["authenticate"]!="disable" or selected["validate-server"] not in ("enable","disable")
                or not selected["server"] or len(selected["server"])>253):raise ValueError
        for key,family in (("source-ip",4),("source-ip6",6)):
            if selected[key] and ipaddress.ip_address(selected[key]).version!=family:raise ValueError
        payload={key:"" if key in ("username","password")else selected[key]for key in _WIRE_FIELDS}
        body=_wire(payload)
        request=hashlib.sha256(CONTRACT.encode()+b"\x00"+body).hexdigest()
        unforwarded=hashlib.sha256(CONTRACT.encode()+b"\x00unforwarded\x00"+
            _wire({key:selected[key]for key in _OMITTED})).hexdigest()
        return SystemEmailEmptyAuthDraft(request,unforwarded,body)
    except Exception:raise ValueError(_ERROR) from None
