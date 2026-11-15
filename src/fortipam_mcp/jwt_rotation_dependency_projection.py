"""Fixed minimized JWT rotation relationship and original-owned User witnesses.

These pure consumers cannot obtain a configured User body or establish its
ownership. The runtime must verify original native ACK and ledger before reads.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json

from v4_planning.material_provider import _OpaqueC3Object

from .jwt_manual_key_contract import _digest, _require_digest
from .jwt_manual_key_preflight import _collection, _top
from .jwt_manual_key_owned_state import _META
from .jwt_manual_rotation_contract import JwtManualRotationBinding, USER_FIELDS
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _zeroize_mutable
from .target_lifecycle_dependencies import _envelope, _one
from .secret_bulk_import_metadata import _array

CONTRACT = "fortipam-build29-jwt-rotation-dependency-projection-v1"
_ERROR = "The fixed JWT rotation relationship is unavailable."


class JwtRotationDependencyError(RuntimeError):
    """No raw identities, user claims, material or private replies."""


@dataclass(frozen=True, slots=True, repr=False)
class JwtRotationDependencyState(_OpaqueC3Object):
    binding_digest: str
    jwt_user_present: bool
    other_users_digest: str
    complete_namespace_digest: str


def consume_jwt_rotation_dependencies(keys: bytearray, users: bytearray, *, binding: JwtManualRotationBinding,
        user_present: bool, expected_other_users_digest: str | None = None) -> JwtRotationDependencyState:
    """Only the one owned key and optional one exact JWT User may be present."""
    try:
        if type(binding) is not JwtManualRotationBinding or type(user_present) is not bool:
            raise ValueError
        key_rows,key_meta = _collection(keys,"jwt-key",binding.serial_digest)
        user_rows,user_meta = _collection(users,"api-user",binding.serial_digest)
        if key_rows != [{"name":binding._key_name,"type":"manually"}]:
            raise ValueError
        selected = [row for row in user_rows if row["name"] == binding._user_name]
        expected = [{"name":binding._user_name,"type":"jwt","jwt-key":binding._key_name}] if user_present else []
        if selected != expected:
            raise ValueError
        others = [row for row in user_rows if row["name"] != binding._user_name]
        if any(row["type"] == "jwt" or row["jwt-key"] for row in others):
            raise ValueError
        other_digest = _digest({"contract":CONTRACT,"other_users":others})
        if expected_other_users_digest is not None:
            _require_digest(expected_other_users_digest)
            if not hmac.compare_digest(other_digest,expected_other_users_digest):
                raise ValueError
        return JwtRotationDependencyState(binding.digest,user_present,other_digest,
            _digest({"contract":CONTRACT,"keys":key_rows,"key_metadata":key_meta,"users":user_rows,"user_metadata":user_meta}))
    except Exception:
        raise JwtRotationDependencyError(_ERROR) from None
    finally:
        for raw in (keys,users):
            if type(raw) is bytearray:
                _zeroize_mutable(raw)


@dataclass(frozen=True, slots=True, repr=False)
class JwtRotationUserState(_OpaqueC3Object):
    binding_digest: str
    complete_projection_hmac: str


def consume_jwt_rotation_owned_user(before: bytearray, after: bytearray, *, binding: JwtManualRotationBinding,
        witness_key: bytes, expected_projection_hmac: str | None = None) -> JwtRotationUserState:
    """Ten-field no-material native projection, preserving all returned metadata."""
    try:
        if type(binding) is not JwtManualRotationBinding or type(witness_key) is not bytes or len(witness_key) != 32:
            raise ValueError
        if expected_projection_hmac is not None:
            _require_digest(expected_projection_hmac)
        rows = []
        for raw in (before,after):
            if type(raw) is not bytearray:
                raise ValueError
            span = _envelope(raw,path="system",name="api-user",serial_digest=binding.serial_digest)
            top = _top(raw)
            if "schema_errors" in top or json.loads(raw[slice(*top["mkey"])]) != binding._user_name:
                raise ValueError
            fields = _object_spans(raw,*_one(raw,span))
            # Refuse any extra/material field before decoding the selected body.
            if set(fields) != USER_FIELDS | _META:
                raise ValueError
            claims = _array(raw,fields["claims"],3)
            if len(claims) != 3 or any(set(_object_spans(raw,*span)) != {"name","value","type","q_origin_key"} for span in claims):
                raise ValueError
            row = {k:json.loads(raw[slice(*v)])for k,v in fields.items()}
            config = binding.user_config()
            wanted_claims = config["claims"]
            if type(wanted_claims) is not list:
                raise ValueError
            config["claims"] = [{**claim,"q_origin_key":claim["name"]} for claim in wanted_claims]
            expected = {**config,"q_origin_key":binding._user_name,
                "q_path":"system","q_name":"api-user","q_mkey_type":"string","q_ref":0,
                "q_static":False,"q_no_edit":False,"q_no_rename":True,"q_global_entry":False}
            if any(type(row[k]) is not type(v) or row[k] != v for k,v in expected.items()):
                raise ValueError
            if type(row["q_type"]) is not int or not 0 <= row["q_type"] < 2**31:
                raise ValueError
            rows.append(row)
        if rows[0] != rows[1]:
            raise ValueError
        mac = hmac.new(witness_key,(CONTRACT + "\x00" + binding.digest + "\x00" + _digest(rows[0])).encode(),hashlib.sha256).hexdigest()
        if expected_projection_hmac is not None and not hmac.compare_digest(mac,expected_projection_hmac):
            raise ValueError
        return JwtRotationUserState(binding.digest,mac)
    except Exception:
        raise JwtRotationDependencyError(_ERROR) from None
    finally:
        for raw in (before,after):
            if type(raw) is bytearray:
                _zeroize_mutable(raw)


def consume_jwt_rotation_user_absence(raw: bytearray, *, binding: JwtManualRotationBinding) -> str:
    """Exact projected404, without inferring a credential or namespace absence."""
    try:
        if type(binding) is not JwtManualRotationBinding or type(raw) is not bytearray:
            raise ValueError
        top = _top(raw)
        expected = {"version":"v7.0.0","build":29,"http_method":"GET","http_status":404,
            "status":"error","path":"system","name":"api-user","vdom":"root","mkey":binding._user_name}
        for key,value in expected.items():
            actual = json.loads(raw[slice(*top[key])])
            if type(actual) is not type(value) or actual != value:
                raise ValueError
        serial = json.loads(raw[slice(*top["serial"])])
        if type(serial) is not str or hashlib.sha256(serial.encode()).hexdigest() != binding.serial_digest or "schema_errors" in top:
            raise ValueError
        for key,allowed in (("error",(None,)),("action",("",)),("results",(None,[]))):
            if key in top and json.loads(raw[slice(*top[key])]) not in allowed:
                raise ValueError
        return _digest({"contract":CONTRACT,"binding":binding.digest,"user_absent":True})
    except Exception:
        raise JwtRotationDependencyError(_ERROR) from None
    finally:
        if type(raw) is bytearray:
            _zeroize_mutable(raw)
