"""Inactive fixed private token verification; no file route or Owner authority.

Issuer alone owns the OAuth store and response signing key. Intake has only a
dedicated request credential and pinned response public key. Process separation
does not by itself prove OS/container isolation or authorize file material.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
import httpx
from mcp.server.auth.provider import AccessToken, ProviderTokenVerifier, TokenVerifier
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from v4_planning.material_provider import _OpaqueC3Object

from .secret_bulk_import_file import _read_owned, _wipe
from .secret_bulk_import_intake import _clock_sample, _https, _text, _INTAKE_SCOPE
from .secret_bulk_import_oauth import OwnerFileIntakeOAuthCandidate, OwnerFileIntakeTokenVerifier

CONTRACT = "fortipam-owner-file-token-verification-v1"
_ERROR = "Private intake token verification unavailable."
_HEX = re.compile(r"[a-f0-9]{64}\Z")
_NONCE = re.compile(r"[a-f0-9]{32}\Z")
_MAX_FRAME = 32768
_PREFIX = "/v1/owner-file-token/"
_REQUEST_DOMAIN = (CONTRACT + "/request\0").encode()
_RESPONSE_DOMAIN = (CONTRACT + "/response\0").encode()


class IntakeTokenChannelError(ValueError):
    """Fixed error; never reflect token, locator or verification metadata."""


@dataclass(frozen=True, slots=True, repr=False)
class IntakeTokenChannelBinding(_OpaqueC3Object):
    issuer: str
    planning_resource: str
    intake_resource: str
    deployment_digest: str
    workload_digest: str
    issued_at: int
    expires_at: int

    def __post_init__(self) -> None:
        try:
            if (any(not _https(value) for value in (self.issuer, self.planning_resource, self.intake_resource))
                    or self.planning_resource == self.intake_resource
                    or any(type(value) is not str or _HEX.fullmatch(value) is None
                           for value in (self.deployment_digest, self.workload_digest))
                    or type(self.issued_at) is not int or type(self.expires_at) is not int
                    or not 0 <= self.issued_at < self.expires_at <= self.issued_at + 900):
                raise ValueError
        except Exception:
            raise IntakeTokenChannelError(_ERROR) from None


class _PinnedKey(_OpaqueC3Object):
    def __init__(self, path: Path, digest: str) -> None:
        if not isinstance(path, Path) or type(digest) is not str or _HEX.fullmatch(digest) is None:
            raise IntakeTokenChannelError(_ERROR)
        self.path, self.digest = path, digest
        self._identity: tuple[int, ...] | None = None
        raw = self.load()
        _wipe(raw)

    def load(self) -> bytearray:
        raw = None
        try:
            raw, identity = _read_owned(self.path, self._identity)
            if len(raw) != 32 or hashlib.sha256(raw).hexdigest() != self.digest:
                raise ValueError
            if self._identity is None:
                self._identity = identity
            return raw
        except Exception:
            if raw is not None:
                _wipe(raw)
            raise IntakeTokenChannelError(_ERROR) from None


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _members(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in items:
        if name in result:
            raise ValueError
        result[name] = value
    return result


def _envelope(raw: bytearray) -> tuple[dict[str, Any], str]:
    value = json.loads(raw, object_pairs_hook=_members)
    if (type(value) is not dict or set(value) != {"payload", "seal"}
            or type(value["payload"]) is not dict or type(value["seal"]) is not str):
        raise ValueError
    return value["payload"], value["seal"]


def _now(binding: IntakeTokenChannelBinding, clock: Callable[[], int]) -> int:
    now = clock()
    if type(now) is not int or not binding.issued_at <= now < binding.expires_at:
        raise ValueError
    return now


class _ChannelLifetime:
    def __init__(self, binding: IntakeTokenChannelBinding, clock: Callable[[], int],
                 monotonic: Callable[[], float]) -> None:
        self.binding, self.clock, self.monotonic = binding, clock, monotonic
        self.wall, self.mono = _now(binding, clock), _clock_sample(monotonic)
        self.deadline = self.mono + binding.expires_at - self.wall
        self.closed = False

    def check(self) -> int:
        try:
            wall, mono = _now(self.binding, self.clock), _clock_sample(self.monotonic)
            if self.closed or wall < self.wall or mono < self.mono or mono >= self.deadline:
                raise ValueError
            self.wall, self.mono = wall, mono
            return wall
        except Exception:
            self.closed = True
            raise


def _identity(token: AccessToken, binding: IntakeTokenChannelBinding, planning: bool, now: int) -> dict[str, Any]:
    resource = binding.planning_resource if planning else binding.intake_resource
    required = "fortipam:plan" if planning else _INTAKE_SCOPE
    allowed = {"fortipam:read", "fortipam:plan", "fortipam:operate"} if planning else {_INTAKE_SCOPE}
    if (not isinstance(token, AccessToken) or token.resource != resource
            or type(token.expires_at) is not int or token.expires_at <= now
            or not _text(token.client_id) or not _text(token.subject)
            or type(token.claims) is not dict or token.claims.get("iss") != binding.issuer
            or token.claims.get("sub") != token.subject or token.claims.get("client_id") != token.client_id
            or type(token.scopes) is not list or not token.scopes or len(token.scopes) > 3
            or any(type(scope) is not str for scope in token.scopes)
            or len(set(token.scopes)) != len(token.scopes)
            or required not in token.scopes or not set(token.scopes) <= allowed):
        raise ValueError
    return dict(iss=binding.issuer, sub=token.subject, client_id=token.client_id,
                resource=resource, scopes=token.scopes, expires_at=token.expires_at)


async def _body(request: Request) -> bytearray:
    raw = bytearray()
    try:
        lengths = request.headers.getlist("content-length")
        if (len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()
                or len(lengths[0]) > 5 or not 0 < int(lengths[0]) <= _MAX_FRAME
                or request.headers.get("content-type") != "application/json"):
            raise ValueError
        count = 0
        async with asyncio.timeout(2):
            async for chunk in request.stream():
                count += 1
                if count > 256 or len(raw) + len(chunk) > int(lengths[0]):
                    raise ValueError
                raw.extend(chunk)
        if len(raw) != int(lengths[0]):
            raise ValueError
        return raw
    except BaseException:
        _wipe(raw)
        raise


def create_intake_token_verification_app(
    issuer: OwnerFileIntakeOAuthCandidate, binding: IntakeTokenChannelBinding, *,
    request_key_path: Path, request_key_sha256: str,
    signing_key_path: Path, signing_key_sha256: str,
    clock: Callable[[], int] = lambda: int(time.time()),
    monotonic: Callable[[], float] = time.monotonic,
) -> Starlette:
    """Issuer-side only: fixed private verification, not a public HTTP route."""
    try:
        if (type(issuer) is not OwnerFileIntakeOAuthCandidate or type(binding) is not IntakeTokenChannelBinding
                or binding.issuer != issuer.settings.issuer
                or binding.planning_resource != issuer.settings.resource
                or binding.intake_resource != issuer._intake.settings.resource
                or request_key_sha256 == signing_key_sha256):
            raise ValueError
        binding.__post_init__()
        lifetime = _ChannelLifetime(binding, clock, monotonic)
        credential = _PinnedKey(request_key_path, request_key_sha256)
        signer = _PinnedKey(signing_key_path, signing_key_sha256)
    except Exception:
        raise IntakeTokenChannelError(_ERROR) from None
    verifiers = (OwnerFileIntakeTokenVerifier(issuer), ProviderTokenVerifier(issuer))

    async def verify(request: Request, planning: bool) -> Response:
        raw = secret = signing = None
        try:
            raw = await _body(request)
            payload, seal = _envelope(raw)
            purpose = "planning" if planning else "intake"
            now = lifetime.check()
            if (set(payload) != {"contract", "purpose", "deployment_digest", "workload_digest", "nonce", "issued_at", "token"}
                    or payload["contract"] != CONTRACT or payload["purpose"] != purpose
                    or payload["deployment_digest"] != binding.deployment_digest
                    or payload["workload_digest"] != binding.workload_digest
                    or type(payload["nonce"]) is not str or _NONCE.fullmatch(payload["nonce"]) is None
                    or type(payload["issued_at"]) is not int or not 0 <= now - payload["issued_at"] <= 10
                    or type(payload["token"]) is not str or not 0 < len(payload["token"].encode()) <= 16384):
                raise ValueError
            secret = credential.load()
            if not hmac.compare_digest(seal, hmac.new(secret, _REQUEST_DOMAIN + _canonical(payload), hashlib.sha256).hexdigest()):
                raise ValueError
            async with asyncio.timeout(2):
                token = await verifiers[int(planning)].verify_token(payload["token"])
            now = lifetime.check()
            if not 0 <= now - payload["issued_at"] <= 10:
                raise ValueError
            identity = None if token is None else _identity(token, binding, planning, now)
            renewed = credential.load()
            _wipe(renewed)
            signing = signer.load()
            result = dict(contract=CONTRACT, purpose=purpose, deployment_digest=binding.deployment_digest,
                          workload_digest=binding.workload_digest, nonce=payload["nonce"],
                          request_seal=seal, observed_at=now, identity=identity)
            signature = Ed25519PrivateKey.from_private_bytes(bytes(signing)).sign(_RESPONSE_DOMAIN + _canonical(result)).hex()
            return JSONResponse({"payload": result, "seal": signature}, headers={"Cache-Control": "no-store"})
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=409, headers={"Cache-Control": "no-store"})
        finally:
            for buffer in (raw, secret, signing):
                if buffer is not None:
                    _wipe(buffer)

    async def planning(request: Request) -> Response:
        return await verify(request, True)

    async def intake(request: Request) -> Response:
        return await verify(request, False)

    return Starlette(routes=[Route(_PREFIX + "planning", planning, methods=["POST"]),
                             Route(_PREFIX + "intake", intake, methods=["POST"])])


def _socket_identity(path: Path) -> tuple[int, ...]:
    parent, info = path.parent.lstat(), path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or stat.S_IMODE(parent.st_mode) != 0o700
            or parent.st_uid != os.getuid() or not stat.S_ISSOCK(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != os.getuid()):
        raise ValueError
    return parent.st_dev, parent.st_ino, info.st_dev, info.st_ino, info.st_ctime_ns


class UnixIntakeTokenVerifier(_OpaqueC3Object, TokenVerifier):
    """Private workload client; has no OAuth-store or issuer-private-key input."""

    def __init__(self, binding: IntakeTokenChannelBinding, *, socket_path: Path,
                 request_key_path: Path, request_key_sha256: str,
                 public_key_path: Path, public_key_sha256: str, planning: bool,
                 clock: Callable[[], int] = lambda: int(time.time()),
                 monotonic: Callable[[], float] = time.monotonic) -> None:
        try:
            if (type(binding) is not IntakeTokenChannelBinding or type(planning) is not bool
                    or not isinstance(socket_path, Path) or not socket_path.is_absolute()
                    or request_key_path.parent != socket_path.parent
                    or public_key_path.parent != socket_path.parent
                    or request_key_sha256 == public_key_sha256):
                raise ValueError
            binding.__post_init__()
            self._binding, self._socket, self._planning = binding, socket_path, planning
            self._lifetime = _ChannelLifetime(binding, clock, monotonic)
            self._request = _PinnedKey(request_key_path, request_key_sha256)
            self._public = _PinnedKey(public_key_path, public_key_sha256)
            self._socket_pin = _socket_identity(socket_path)
        except Exception:
            raise IntakeTokenChannelError(_ERROR) from None

    def _check(self) -> int:
        now = self._lifetime.check()
        if _socket_identity(self._socket) != self._socket_pin:
            raise ValueError
        return now

    async def verify_token(self, token: str) -> AccessToken | None:
        secret = public = sent = received = None
        try:
            if type(token) is not str or not 0 < len(token.encode()) <= 16384:
                raise ValueError
            now, binding = self._check(), self._binding
            started = now
            secret = self._request.load()
            public = self._public.load()
            purpose = "planning" if self._planning else "intake"
            payload = dict(contract=CONTRACT, purpose=purpose, deployment_digest=binding.deployment_digest,
                           workload_digest=binding.workload_digest, nonce=secrets.token_hex(16), issued_at=now, token=token)
            seal = hmac.new(secret, _REQUEST_DOMAIN + _canonical(payload), hashlib.sha256).hexdigest()
            sent = bytearray(_canonical({"payload": payload, "seal": seal}))
            received = bytearray()
            async with asyncio.timeout(2):
                async with httpx.AsyncClient(transport=httpx.AsyncHTTPTransport(uds=str(self._socket)),
                                             base_url="http://private-intake-token-auth", timeout=2,
                                             follow_redirects=False, trust_env=False) as client:
                    async with client.stream("POST", _PREFIX + purpose, content=bytes(sent),
                                             headers={"Content-Type": "application/json"}) as response:
                        if (response.status_code != 200 or response.headers.get("content-type") != "application/json"
                                or response.headers.get("content-encoding") not in (None, "identity")):
                            raise ValueError
                        async for chunk in response.aiter_bytes(chunk_size=4096):
                            if len(received) + len(chunk) > _MAX_FRAME:
                                raise ValueError
                            received.extend(chunk)
            value, signature = _envelope(received)
            Ed25519PublicKey.from_public_bytes(bytes(public)).verify(bytes.fromhex(signature), _RESPONSE_DOMAIN + _canonical(value))
            now = self._check()
            for pin in (self._request, self._public):
                fresh = pin.load()
                _wipe(fresh)
            if (set(value) != {"contract", "purpose", "deployment_digest", "workload_digest", "nonce", "request_seal", "observed_at", "identity"}
                    or any(value[name] != payload[name] for name in ("contract", "purpose", "deployment_digest", "workload_digest", "nonce"))
                    or value["request_seal"] != seal or type(value["observed_at"]) is not int
                    or not started <= value["observed_at"] <= now <= started + 10):
                raise ValueError
            identity = value["identity"]
            if identity is None:
                return None
            if type(identity) is not dict or set(identity) != {"iss", "sub", "client_id", "resource", "scopes", "expires_at"}:
                raise ValueError
            if (any(not _text(identity[name]) for name in ("iss", "sub", "client_id", "resource"))
                    or type(identity["expires_at"]) is not int or type(identity["scopes"]) is not list):
                raise ValueError
            verified = AccessToken(token=token, subject=identity["sub"], client_id=identity["client_id"],
                                   resource=identity["resource"], scopes=identity["scopes"], expires_at=identity["expires_at"],
                                   claims={name: identity[name] for name in ("iss", "sub", "client_id")})
            if _identity(verified, binding, self._planning, now) != identity:
                raise ValueError
            return verified
        except Exception:
            raise IntakeTokenChannelError(_ERROR) from None
        finally:
            for buffer in (secret, public, sent, received):
                if buffer is not None:
                    _wipe(buffer)
