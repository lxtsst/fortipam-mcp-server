"""I/O-free build29 manual JWT overlap/cutover and JWT User wire contracts.

Private bodies and state witnesses convey no source, ownership or execution
authority. Original creation/ACK, live Owner qualification and independent M4s
remain required at the runtime boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from urllib.parse import quote

from v4_planning.material_provider import _OpaqueC3Object

from .jwt_manual_key_contract import DEFAULT_FIELDS, JwtManualPublicKey, _Private, _NAME, _digest, _require_digest
from .jwt_manual_key_owned_state import _META
from .jwt_manual_key_preflight import _top
from .local_user_reset_projection import _object_spans
from .secret_metadata_http_transport import _zeroize_mutable
from .target_lifecycle_dependencies import _envelope, _one

CONTRACT = "fortipam-build29-manual-jwt-rotation-private-v3"
USER_FIELDS = frozenset({"name", "comments", "accprofile", "schedule", "trusthost", "vdom", "type", "claims", "jwt-key", "lease-duration"})
USER_NAME = re.compile(r"mcp-v4-jwt-u-[a-f0-9]{18}\Z")
PHASES = frozenset({"original", "overlap", "cutover", "restore"})
_ERROR = "The private manual JWT rotation contract is unavailable."


class JwtManualRotationContractError(RuntimeError):
    """No identities, material, claims or native content in refusals."""


def _fail() -> None:
    raise JwtManualRotationContractError(_ERROR)


class JwtManualRotationBinding(_Private):
    __slots__ = ("_key_name", "_user_name", "_nonce", "_issuer", "_audience", "_subject", "serial_digest", "digest")
    _key_name: str
    _user_name: str
    _nonce: str
    _issuer: str
    _audience: str
    _subject: str
    serial_digest: str
    digest: str

    def __init__(self, key_name: str, user_name: str, nonce: str, *, serial_digest: str) -> None:
        try:
            if (type(key_name) is not str or _NAME.fullmatch(key_name) is None or len(key_name) > 35
                    or type(user_name) is not str or USER_NAME.fullmatch(user_name) is None):
                raise ValueError
            _require_digest(nonce); _require_digest(serial_digest)
            data = {"_key_name":key_name,"_user_name":user_name,"_nonce":nonce,
                "_issuer":"https://issuer.invalid/" + nonce[:24],
                "_audience":"urn:fortipam:rotation:" + nonce[:24],
                "_subject":"jwt-rotation-" + nonce[24:48],"serial_digest":serial_digest}
            for k, v in {**data,"digest":_digest({"contract":CONTRACT,**data})}.items():
                object.__setattr__(self,k,v)
        except Exception:
            raise JwtManualRotationContractError(_ERROR) from None

    def user_config(self) -> dict[str, object]:
        """Protected native ten-field configuration, never a public preview."""
        return {"name":self._user_name,"comments":"Bound manual JWT rotation fixture.",
            "accprofile":"pam_standard_user","schedule":"","trusthost":[],"vdom":[{"name":"root","q_origin_key":"root"}],
            "type":"jwt","claims":[{"name":name,"value":value,"type":"default"}for name,value in
                (("iss",self._issuer),("aud",self._audience),("sub",self._subject))],
            "jwt-key":self._key_name,"lease-duration":10}


class JwtManualRotationKeys(_Private):
    __slots__ = ("_old", "_new", "digest")
    _old: JwtManualPublicKey
    _new: JwtManualPublicKey
    digest: str

    def __init__(self, old: JwtManualPublicKey, new: JwtManualPublicKey) -> None:
        if type(old) is not JwtManualPublicKey or type(new) is not JwtManualPublicKey or old.digest == new.digest:
            _fail()
        object.__setattr__(self,"_old",old); object.__setattr__(self,"_new",new)
        object.__setattr__(self,"digest",_digest({"contract":CONTRACT,"old":old.digest,"new":new.digest}))

    def members(self, phase: str) -> list[dict[str, str]]:
        if type(phase) is not str or phase not in PHASES:
            _fail()
        keys = (self._new,self._old) if phase == "overlap" else (self._new,) if phase == "cutover" else (self._old,)
        return [{"key-name":key._pem.decode("ascii")}for key in keys]


class JwtManualRotationRequest(_Private):
    """One native User POST or key PUT; raw bytes close independently of metadata."""
    __slots__ = ("_body", "_closed", "phase", "binding_digest", "keys_digest", "method", "path", "query", "body_digest", "digest")
    _body: bytearray
    _closed: bool
    phase: str
    binding_digest: str
    keys_digest: str
    method: str
    path: str
    query: str
    body_digest: str
    digest: str

    def __init__(self, binding: JwtManualRotationBinding, keys: JwtManualRotationKeys, *, phase: str) -> None:
        body = bytearray()
        try:
            if type(binding) is not JwtManualRotationBinding or type(keys) is not JwtManualRotationKeys:
                raise ValueError
            if phase == "user-create":
                config = binding.user_config()
                # Match the native API User unparse order, including empty origin.
                value = {"name":config["name"],"$originalName":"",**{k:config[k]for k in
                    ("comments","accprofile","schedule","trusthost","vdom","type","claims","jwt-key","lease-duration")}}
                method,path = "POST","/api/v2/cmdb/system/api-user"
            elif phase == "user-initialize":
                value = {"api-user":binding._user_name}
                method,path = "POST","/api/v2/monitor/system/api-user/generate-key"
            elif phase in {"overlap", "cutover", "restore"}:
                value = {"q_origin_key":binding._key_name,"name":binding._key_name,"type":"manually",
                    "key":keys.members(phase),"jwks-url":"","check-interval":24,"ca":"","claim":[]}
                method,path = "PUT","/api/v2/cmdb/secret/jwt-key/" + quote(binding._key_name,safe="")
            else:
                raise ValueError
            body.extend(json.dumps(value,ensure_ascii=True,separators=(",",":"),allow_nan=False).encode())
            data = {"phase":phase,"binding_digest":binding.digest,"keys_digest":keys.digest,
                "method":method,"path":path,"query":""if phase == "user-initialize"else"with_meta=true","body_digest":hashlib.sha256(body).hexdigest()}
            for k, v in {**data,"_body":body,"_closed":False,"digest":_digest({"contract":CONTRACT,**data})}.items():
                object.__setattr__(self,k,v)
        except Exception:
            _zeroize_mutable(body)
            raise JwtManualRotationContractError(_ERROR) from None

    def _metadata_digest(self) -> str:
        return _digest({"contract":CONTRACT,**{k:getattr(self,k)for k in
            ("phase","binding_digest","keys_digest","method","path","query","body_digest")}})

    def borrow_body(self) -> memoryview:
        if self._closed or hashlib.sha256(self._body).hexdigest() != self.body_digest or self._metadata_digest() != self.digest:
            self.close(); _fail()
        return memoryview(self._body).toreadonly()

    def close(self) -> None:
        _zeroize_mutable(self._body); object.__setattr__(self,"_closed",True)


@dataclass(frozen=True, slots=True, repr=False)
class JwtRotationKeyState(_OpaqueC3Object):
    binding_digest: str
    keys_digest: str
    phase: str
    reference_count: int
    complete_row_hmac: str
    invariant_hmac: str


def consume_jwt_rotation_key_state(before: bytearray, after: bytearray, *,
        binding: JwtManualRotationBinding, keys: JwtManualRotationKeys, phase: str,
        reference_count: int, witness_key: bytes, expected_invariant_hmac: str | None = None) -> JwtRotationKeyState:
    """Full native row and exact keyed-member set, without adoption authority."""
    try:
        if (type(binding) is not JwtManualRotationBinding or type(keys) is not JwtManualRotationKeys
                or phase not in PHASES or type(reference_count) is not int or reference_count not in {0,1}
                or type(witness_key) is not bytes or len(witness_key) != 32):
            raise ValueError
        if expected_invariant_hmac is not None:
            _require_digest(expected_invariant_hmac)
        rows = []
        for raw in (before,after):
            if type(raw) is not bytearray:
                raise ValueError
            span = _envelope(raw,path="secret",name="jwt-key",serial_digest=binding.serial_digest)
            top = _top(raw)
            if "schema_errors" in top or json.loads(raw[slice(*top["mkey"])]) != binding._key_name:
                raise ValueError
            fields = _object_spans(raw,*_one(raw,span))
            if set(fields) != DEFAULT_FIELDS | _META:
                raise ValueError
            row = {k:json.loads(raw[slice(*v)])for k,v in fields.items()}
            expected = {"q_origin_key":binding._key_name,"name":binding._key_name,"type":"manually",
                "jwks-url":"","oidc-discovery-url":"","check-interval":24,"ca":"","claim":[],
                "q_path":"secret","q_name":"jwt-key","q_mkey_type":"string","q_ref":reference_count,
                "q_static":False,"q_no_edit":False,"q_no_rename":False,"q_global_entry":False}
            if any(type(row[k]) is not type(v) or row[k] != v for k,v in expected.items()):
                raise ValueError
            if type(row["q_type"]) is not int or not 0 <= row["q_type"] < 2**31:
                raise ValueError
            for k in ("last-check-time","last-update-time"):
                if type(row[k]) is not str or len(row[k])>128 or re.search(r"[\x00-\x1f\x7f]",row[k]):
                    raise ValueError
            members = row["key"]; wanted = keys.members(phase)
            if type(members) is not list or len(members) != len(wanted):
                raise ValueError
            wanted_names = {entry["key-name"] for entry in wanted}
            observed_names = set()
            for entry in members:
                if (type(entry) is not dict or not {"key-name"} <= set(entry) <= {"key-name","q_origin_key"}
                        or type(entry["key-name"]) is not str or entry["key-name"] not in wanted_names
                        or entry["key-name"] in observed_names
                        or "q_origin_key" in entry and entry["q_origin_key"] != entry["key-name"]):
                    raise ValueError
                observed_names.add(entry["key-name"])
            if observed_names != wanted_names:
                raise ValueError
            rows.append(row)
        if rows[0] != rows[1]:
            raise ValueError
        def mac(value: object) -> str:
            return hmac.new(witness_key,(CONTRACT + "\x00" + binding.digest + "\x00" + _digest(value)).encode(),hashlib.sha256).hexdigest()
        invariant = mac({k:v for k,v in rows[0].items() if k not in {"key","q_ref"}})
        if expected_invariant_hmac is not None and not hmac.compare_digest(invariant,expected_invariant_hmac):
            raise ValueError
        return JwtRotationKeyState(binding.digest,keys.digest,phase,reference_count,mac(rows[0]),invariant)
    except Exception:
        raise JwtManualRotationContractError(_ERROR) from None
    finally:
        for raw in (before,after):
            if type(raw) is bytearray:
                _zeroize_mutable(raw)
