"""Consume one owned-user native key initialization; never decode its material."""
from __future__ import annotations

import hashlib
import hmac
import json

from .jwt_manual_key_contract import _digest, _require_digest
from .jwt_manual_key_preflight import _top
from .jwt_manual_rotation_contract import JwtManualRotationBinding
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _zeroize_mutable

_ERROR = "The owned JWT user initialization response is unavailable."


def consume_jwt_user_initialization(raw: bytearray, *, binding: JwtManualRotationBinding,
        claim_digest: str, witness_key: bytes) -> str:
    """Return a keyed original-response witness and erase the unused API key."""
    try:
        if type(raw) is not bytearray or type(binding) is not JwtManualRotationBinding or type(witness_key) is not bytes or len(witness_key) != 32:
            raise ValueError
        _require_digest(claim_digest)
        top = _top(raw)
        expected = {"version":"v7.0.0","build":29,"http_method":"POST","status":"success",
            "path":"system","name":"api-user","action":"generate-key"}
        allowed = set(expected)|{"results","serial","vdom","http_status","mkey","error","revision","revision_changed","old_revision"}
        if not set(expected)|{"serial","results"} <= top.keys() or not top.keys() <= allowed:
            raise ValueError
        for name,value in {**expected,**({"http_status":200}if "http_status" in top else{}),
                **({"vdom":"root"}if "vdom" in top else{}),**({"mkey":binding._user_name}if "mkey" in top else{}),
                **({"error":0}if "error" in top else{})}.items():
            actual = json.loads(raw[slice(*top[name])])
            if type(actual) is not type(value) or actual != value:
                raise ValueError
        serial = json.loads(raw[slice(*top["serial"])])
        if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != binding.serial_digest:
            raise ValueError
        fields = _object_spans(raw,*top["results"])
        # The native dialog consumes access_token from a credential result object.
        # Build29 also returns one supplementary field. Treat that entire field
        # as opaque C3: no value decoding, retention, or success inference.
        if "access_token" not in fields or len(fields) > 2:
            raise ValueError
        start,end = fields["access_token"]
        if raw[start] != 34 or raw[end-1] != 34 or not 16 <= end-start-2 <= 4096:
            raise ValueError
        # Validate the native opaque credential as bytes; do not create a string.
        with memoryview(raw)[start+1:end-1] as token:
            if any(value<33 or value>126 or value in (34,92)for value in token):
                raise ValueError
        context = _digest({"contract":"fortipam-jwt-owned-user-initialization-v1","binding":binding.digest,"claim":claim_digest})
        mac = hmac.new(witness_key,context.encode()+b"\x00",hashlib.sha256); mac.update(raw)
        return mac.hexdigest()
    except Exception:
        raise ValueError(_ERROR) from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)
