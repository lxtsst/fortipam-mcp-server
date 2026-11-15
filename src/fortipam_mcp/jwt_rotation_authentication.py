"""Protected fixed JWT authentication/identity probe, without public tools.

The runtime must qualify its original owned User/key relationship before enabling
this fixture channel. A successful login alone is never a rotation or revocation
proof. Local close erases leases but makes no product-revocation claim.
"""
from __future__ import annotations

import base64
from collections.abc import Callable, Iterator
from contextlib import contextmanager
import hashlib
import json
import secrets
import ssl
import time
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .jwt_manual_key_contract import _Private
from .jwt_manual_key_owner_http import JwtManualKeyOwnerHttpConfig
from .jwt_manual_rotation_contract import JwtManualRotationBinding, JwtManualRotationKeys
from .local_user_reset_metadata_reader import _monitor_results
from .local_user_reset_projection import _object_spans
from .secret_approval_build29_http_transport import _validate_ack_json
from .secret_metadata_http_transport import MAX_RESPONSE_BYTES, _json_value_end, _skip_json_space, _zeroize_mutable
from .secret_request_approval_revoke_detail_contract import _reject_raw_duplicates
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "fortipam-build29-jwt-authentication-probe-v1"
_ERROR = "The protected JWT authentication probe is unavailable."
_LOGIN = "/auth/jwt/login"
_STATE = "/api/v2/monitor/web-ui/state"
_CASES = frozenset({"valid", "wrong-issuer", "wrong-audience", "wrong-subject", "expired"})


class JwtRotationAuthenticationError(RuntimeError):
    """Categorical refusal; assertions, tokens and native content never escape."""


class JwtRotationLease(_Private):
    __slots__ = ("_token", "_closed", "binding_digest", "key_digest", "issued_at")
    _token: bytearray
    _closed: bool
    binding_digest: str
    key_digest: str
    issued_at: int

    def __init__(self, token: str, binding: str, key: str, now: int) -> None:
        if type(token) is not str or not 1 <= len(token) <= 8192 or any(ord(c)<33 or ord(c)>126 for c in token):
            raise JwtRotationAuthenticationError(_ERROR)
        for name,value in {"_token":bytearray(token.encode("ascii")),"_closed":False,
                "binding_digest":binding,"key_digest":key,"issued_at":now}.items():
            object.__setattr__(self,name,value)

    def close(self) -> None:
        _zeroize_mutable(self._token); object.__setattr__(self,"_closed",True)


class JwtRotationAuthenticationProbe:
    """One TLS-verified, cookie-isolated, budgeted assertion and lease channel."""

    def __init__(self, config: JwtManualKeyOwnerHttpConfig, binding: JwtManualRotationBinding,
            keys: JwtManualRotationKeys, old_signer: rsa.RSAPrivateKey, new_signer: rsa.RSAPrivateKey, *,
            probe_enabled: bool = False, source_guard: Callable[[], bool] | None = None,
            client_factory: Callable[..., Any] = httpx.Client,
            clock: Callable[[], int] = lambda:int(time.time()),
            fresh_assertion_clients: bool = False, runtime_sampling: bool = False) -> None:
        try:
            if (type(config) is not JwtManualKeyOwnerHttpConfig or type(binding) is not JwtManualRotationBinding
                    or type(keys) is not JwtManualRotationKeys or not isinstance(old_signer,rsa.RSAPrivateKey)
                    or not isinstance(new_signer,rsa.RSAPrivateKey) or type(probe_enabled) is not bool
                    or type(fresh_assertion_clients) is not bool or type(runtime_sampling) is not bool
                    or source_guard is not None and not callable(source_guard) or not callable(client_factory) or not callable(clock)):
                raise ValueError
            config.__post_init__()
            for signer,expected in ((old_signer,keys._old),(new_signer,keys._new)):
                public = signer.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
                if hashlib.sha256(public).hexdigest() != expected.digest:
                    raise ValueError
            self._config,self._binding,self._keys = config,binding,keys
            self._old: rsa.RSAPrivateKey | None = old_signer
            self._new: rsa.RSAPrivateKey | None = new_signer
            self._enabled,self._guard,self._guard_pin = probe_enabled,source_guard,source_guard
            self._factory,self._factory_pin,self._clock = client_factory,client_factory,clock
            self._fresh_assertion_clients = self._fresh_assertion_pin = fresh_assertion_clients
            self._runtime_sampling = self._sampling_pin = runtime_sampling
            self._client: Any = None; self._client_pin: Any = None; self._logs: Any = None
            self._closed = self._entered = False
            self._positive_login_qualified = False
            self._last_clock: int | None = None
            self._auth_count = self._check_count = 0
            self._leases: list[JwtRotationLease] = []
            self.observations: list[dict[str,Any]] = []
        except Exception:
            raise JwtRotationAuthenticationError(_ERROR) from None

    def _live(self) -> int:
        now = self._clock()
        if (self._closed or not self._enabled or self._guard is None or self._guard is not self._guard_pin
                or self._guard() is not True or self._factory is not self._factory_pin
                or self._fresh_assertion_clients is not self._fresh_assertion_pin
                or self._runtime_sampling is not self._sampling_pin
                or self._client is not self._client_pin or type(now) is not int or now < 0
                or self._last_clock is not None and now < self._last_clock):
            raise JwtRotationAuthenticationError(_ERROR)
        self._last_clock = now
        return now

    def __enter__(self) -> JwtRotationAuthenticationProbe:
        try:
            self._live()
            if self._entered:
                raise ValueError
            self._entered = True
            self._logs = _private_http_logs(); self._logs.__enter__()
            tls = ssl.create_default_context(cafile=self._config.ca_file)
            tls.minimum_version = ssl.TLSVersion.TLSv1_2
            self._client = self._factory(base_url=self._config.base_url,verify=tls,
                timeout=self._config.timeout_seconds,follow_redirects=False,trust_env=False)
            self._client_pin = self._client
            self._client.__enter__()
            return self
        except Exception:
            self.close()
            raise JwtRotationAuthenticationError(_ERROR) from None
        except BaseException:
            self.close()
            raise

    @contextmanager
    def _assertion_client(self) -> Iterator[Any]:
        self._live()
        if not self._fresh_assertion_clients:
            yield self._client
            return
        tls = ssl.create_default_context(cafile=self._config.ca_file)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        with self._factory(base_url=self._config.base_url,verify=tls,
                timeout=self._config.timeout_seconds,follow_redirects=False,trust_env=False) as client:
            try:
                self._live(); client.cookies.clear()
                yield client
            finally:
                client.cookies.clear()

    def _assertion(self, which: str, case: str) -> bytearray:
        now = self._live()
        if which not in {"old","new"} or case not in _CASES:
            raise JwtRotationAuthenticationError(_ERROR)
        signer = self._old if which == "old" else self._new
        if signer is None:
            raise JwtRotationAuthenticationError(_ERROR)
        b = self._binding
        payload = {"iss":b._issuer,"aud":b._audience,"sub":b._subject,
            "iat":now,"nbf":now-2,"exp":now+120,"jti":secrets.token_hex(16)}
        field = {"wrong-issuer":"iss","wrong-audience":"aud","wrong-subject":"sub"}.get(case)
        if field is not None:
            payload[field] = str(payload[field]) + "-mismatch"
        if case == "expired":
            payload.update(iat=now-180,nbf=now-180,exp=now-60)
        def encode(value: object) -> bytes:
            return base64.urlsafe_b64encode(json.dumps(value,sort_keys=True,separators=(",",":")).encode()).rstrip(b"=")
        protected = bytearray(encode({"alg":"RS256","typ":"JWT"}) + b"." + encode(payload))
        try:
            signature = signer.sign(bytes(protected),padding.PKCS1v15(),hashes.SHA256())
            protected.extend(b"." + base64.urlsafe_b64encode(signature).rstrip(b"="))
            return protected
        except BaseException:
            _zeroize_mutable(protected)
            raise

    @staticmethod
    def _raw(response: Any, *, maximum: int = 32768) -> bytearray:
        raw = bytearray()
        try:
            if response.headers.get("content-type","").split(";",1)[0].strip().lower() != "application/json":
                raise ValueError
            for chunk in response.iter_bytes():
                if len(raw)+len(chunk)>maximum:
                    raise ValueError
                raw.extend(chunk)
            start = _skip_json_space(raw,0); end = _json_value_end(raw,start)
            if _skip_json_space(raw,end) != len(raw):
                raise ValueError
            _validate_ack_json(raw,start,end); _reject_raw_duplicates(raw,start,end)
            return raw
        except BaseException:
            _zeroize_mutable(raw)
            raise

    def authenticate(self, which: str, *, case: str = "valid") -> JwtRotationLease | None:
        assertion = body = raw = bytearray()
        try:
            now = self._live()
            if self._client is None or self._auth_count>=(32 if self._runtime_sampling else 16):
                raise ValueError
            self._auth_count += 1
            assertion = self._assertion(which,case)
            diagnostic: dict[str,Any] = {"operation":"assertion","key":which,"case":case,"stage":"request"}
            self.observations.append(diagnostic)
            body = bytearray(b'{"jwt":"' + assertion + b'"}')
            self._client.cookies.clear()
            with self._assertion_client() as channel, channel.stream("POST",_LOGIN,content=bytes(body),
                    headers={"Content-Type":"application/json","Accept":"application/json"}) as response:
                status = response.status_code
                media = response.headers.get("content-type","").split(";",1)[0].strip().lower()
                diagnostic.update(stage="response",http_status=status,json_content=media == "application/json")
                if status == 401 and media == "text/html":
                    complete = True
                    for chunk in response.iter_bytes():
                        remaining = 4096-len(raw); raw.extend(chunk[:remaining])
                        if len(chunk)>remaining:
                            complete = False; break
                    bounded = complete and len(raw)<=512
                    diagnostic.update(stage="html_rejection",bounded_body_complete=bounded,
                        gui_login_script=bounded and b"<script" in raw.lower() and b"/remote/login" in raw.lower())
                    if not bounded:
                        lowered = bytes(raw).lower()
                        diagnostic["html_observation"] = {"captured_complete":complete,"captured_bytes":len(raw),
                            "lockout_language":b"too many" in lowered and (b"login" in lowered or b"attempt" in lowered),
                            "rate_limit_language":b"rate limit" in lowered or "retry-after" in response.headers,
                            "login_form":b"<form" in lowered and b"password" in lowered,
                            "padding_comments":b"padding" in lowered and b"msie" in lowered,
                            "redirect_script":b"<script" in lowered and b"/remote/login" in lowered}
                    if diagnostic["gui_login_script"]:
                        diagnostic["stage"] = "gui_login_guard"
                        # Build29 uses this response for a rejected assertion.
                        # First qualify this fixed verified-origin handler
                        # through a successful assertion and exact identity.
                        self._live()
                        if self._positive_login_qualified:
                            diagnostic["stage"] = "denied"
                            diagnostic["prior_login_identity_qualified"] = True
                            return None
                    raise ValueError
                raw = self._raw(response)
            self._client.cookies.clear(); self._live()
            fields = _object_spans(raw,_skip_json_space(raw,0),_json_value_end(raw,_skip_json_space(raw,0)))
            diagnostic.update(stage="grammar",access_token_field_present="access-token" in fields,
                known_response_fields={name:name in fields for name in ("access-token","access_token","status","error","token")})
            if status in {401,403} and "access-token" not in fields:
                diagnostic["stage"] = "denied"
                return None
            if status != 200 or "access-token" not in fields:
                raise ValueError
            token = json.loads(raw[slice(*fields["access-token"])])
            key_digest = self._keys._old.digest if which == "old" else self._keys._new.digest
            lease = JwtRotationLease(token,self._binding.digest,key_digest,now); del token
            self._leases.append(lease)
            if not self.check(lease):
                raise ValueError
            diagnostic["stage"] = "identity_verified"
            self._positive_login_qualified = True
            return lease
        except Exception:
            raise JwtRotationAuthenticationError(_ERROR) from None
        finally:
            for buffer in (assertion,body,raw):
                _zeroize_mutable(buffer)
            if self._client is not None:
                self._client.cookies.clear()

    def check(self, lease: JwtRotationLease) -> bool:
        raw = bytearray()
        try:
            self._live()
            if (self._client is None or self._check_count>=(64 if self._runtime_sampling else 32) or type(lease) is not JwtRotationLease
                    or not any(lease is owned for owned in self._leases) or lease._closed
                    or lease.binding_digest != self._binding.digest):
                raise ValueError
            self._check_count += 1; self._client.cookies.clear()
            diagnostic: dict[str,Any] = {"operation":"lease","stage":"request"}
            self.observations.append(diagnostic)
            with self._client.stream("GET",_STATE,headers={"Authorization":"Bearer " + lease._token.decode("ascii"),
                    "Accept":"application/json","Cache-Control":"no-cache, no-store"}) as response:
                status = response.status_code
                diagnostic.update(stage="response",http_status=status)
                if status in {401,403}:
                    self._live()
                    diagnostic["stage"] = "denied"
                    return False
                if status != 200:
                    raise ValueError
                raw = self._raw(response,maximum=MAX_RESPONSE_BYTES)
            self._live()
            left,right = _monitor_results(raw,expected_route="web-ui/state")
            fields = _object_spans(raw,left,right)
            diagnostic["stage"] = "identity_fields"
            admin = _object_spans(raw,*fields["admin"])
            profile = _object_spans(raw,*admin["profile"])
            diagnostic.update(user_matches=json.loads(raw[slice(*admin["name"])]) == self._binding._user_name,
                role_matches=json.loads(raw[slice(*profile["name"])]) == "pam_standard_user",
                standard_privilege=json.loads(raw[slice(*admin["super_admin"])]) is False)
            if (json.loads(raw[slice(*admin["name"])]) != self._binding._user_name
                    or json.loads(raw[slice(*profile["name"])]) != "pam_standard_user"
                    or json.loads(raw[slice(*admin["super_admin"])]) is not False):
                raise ValueError
            top = _object_spans(raw,_skip_json_space(raw,0),_json_value_end(raw,_skip_json_space(raw,0)))
            if (json.loads(raw[slice(*top["version"])]) != "v7.0.0"
                    or type(json.loads(raw[slice(*top["build"])])) is not int
                    or json.loads(raw[slice(*top["build"])]) != 29
                    or hashlib.sha256(json.loads(raw[slice(*top["serial"])]).encode()).hexdigest() != self._binding.serial_digest):
                raise ValueError
            diagnostic["stage"] = "identity_verified"
            return True
        except Exception:
            raise JwtRotationAuthenticationError(_ERROR) from None
        finally:
            _zeroize_mutable(raw)
            if self._client is not None:
                self._client.cookies.clear()

    def close(self) -> None:
        self._enabled = False; self._closed = True
        self._positive_login_qualified = False
        try:
            for lease in self._leases:
                lease.close()
            if self._client is not None:
                self._client.cookies.clear(); self._client.close()
        finally:
            self._old = self._new = None
            self._client = self._client_pin = None
            if self._logs is not None:
                self._logs.__exit__(None,None,None); self._logs = None

    def __exit__(self, *_: object) -> None:
        self.close()
