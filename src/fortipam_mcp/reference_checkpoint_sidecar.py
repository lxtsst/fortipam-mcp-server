"""Process-separated Unix-socket service for V4 Reference checkpoints."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import socket
import stat
from typing import Mapping, cast

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from v4_planning import (
    PersistentReferenceCheckpointAuthority,
    ReferenceAuthorityCheckpointError,
    ReferenceAuthorityStoreTail,
)
from v4_planning.models import PlanningContractError, require_ref


REFERENCE_CHECKPOINT_DATABASE_ENV = "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_DATABASE"
REFERENCE_CHECKPOINT_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_HMAC_KEY_FILE"
)
REFERENCE_CHECKPOINT_AUTHORITY_REF_ENV = (
    "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_AUTHORITY_REF"
)
REFERENCE_CHECKPOINT_SOCKET_ENV = "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_SOCKET"
_MAX_BODY_BYTES = 3072


class ReferenceCheckpointSidecarError(ReferenceAuthorityCheckpointError):
    """Stable failure for the process-separated Reference checkpoint boundary."""


@dataclass(frozen=True, slots=True)
class ReferenceCheckpointSidecarSettings:
    database_path: Path
    hmac_key_path: Path
    authority_ref: str
    socket_path: Path

    def __post_init__(self) -> None:
        try:
            require_ref(self.authority_ref, "Reference checkpoint sidecar authority_ref")
        except PlanningContractError as exc:
            raise ReferenceCheckpointSidecarError(
                "Reference checkpoint sidecar configuration is invalid."
            ) from exc
        paths = (self.database_path, self.hmac_key_path, self.socket_path)
        if (
            any(not isinstance(path, Path) or not path.is_absolute() for path in paths)
            or len(set(paths)) != len(paths)
        ):
            raise ReferenceCheckpointSidecarError(
                "Reference checkpoint sidecar configuration is invalid."
            )


@dataclass(frozen=True, slots=True)
class UnixReferenceCheckpointClientSettings:
    socket_path: Path
    authority_ref: str
    timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        try:
            require_ref(self.authority_ref, "Reference checkpoint client authority_ref")
        except PlanningContractError as exc:
            raise ReferenceCheckpointSidecarError(
                "Reference checkpoint client configuration is invalid."
            ) from exc
        if (
            not isinstance(self.socket_path, Path)
            or not self.socket_path.is_absolute()
            or type(self.timeout_seconds) is not float
            or not 0.1 <= self.timeout_seconds <= 10.0
        ):
            raise ReferenceCheckpointSidecarError(
                "Reference checkpoint client configuration is invalid."
            )


class UnixReferenceCheckpointClient:
    """Implement the Reference checkpoint Protocol over one owner-only UDS."""

    def __init__(self, settings: UnixReferenceCheckpointClientSettings) -> None:
        if not isinstance(settings, UnixReferenceCheckpointClientSettings):
            raise ReferenceCheckpointSidecarError(
                "Reference checkpoint client configuration is invalid."
            )
        self._settings = settings
        self.authority_ref = settings.authority_ref

    def verify(self, tail: ReferenceAuthorityStoreTail) -> None:
        self._request(
            "/v1/reference-checkpoints/verify",
            {"authority_ref": self.authority_ref, "tail": _tail_payload(tail)},
        )

    def advance(
        self,
        previous: ReferenceAuthorityStoreTail,
        current: ReferenceAuthorityStoreTail,
    ) -> None:
        self._request(
            "/v1/reference-checkpoints/advance",
            {
                "authority_ref": self.authority_ref,
                "current": _tail_payload(current),
                "previous": _tail_payload(previous),
            },
        )

    def verify_ready(self) -> None:
        _assert_owner_only_socket(self._settings.socket_path)

    def uses_key_material(self, candidate: bytes) -> bool:
        del candidate
        return False

    def shares_key_material_with(self, candidate: object) -> bool:
        del candidate
        return False

    def _request(self, path: str, payload: dict[str, object]) -> None:
        self.verify_ready()
        transport = httpx.HTTPTransport(uds=str(self._settings.socket_path))
        try:
            with httpx.Client(
                transport=transport,
                base_url="http://reference-checkpoint-sidecar",
                timeout=self._settings.timeout_seconds,
                trust_env=False,
            ) as client:
                response = client.post(path, json=payload)
        except (httpx.HTTPError, OSError):
            raise ReferenceCheckpointSidecarError(
                "Reference checkpoint sidecar is unavailable."
            ) from None
        if response.status_code != 204 or response.content:
            raise ReferenceCheckpointSidecarError(
                "Reference checkpoint sidecar rejected the transition."
            )


def create_reference_checkpoint_sidecar_app(
    authority: PersistentReferenceCheckpointAuthority,
) -> Starlette:
    """Create the exact two-operation Reference checkpoint ASGI app."""

    if not isinstance(authority, PersistentReferenceCheckpointAuthority):
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint sidecar Authority is invalid."
        )

    async def verify(request: Request) -> Response:
        try:
            payload = await _payload(request)
            if set(payload) != {"authority_ref", "tail"} or (
                payload["authority_ref"] != authority.authority_ref
            ):
                raise ReferenceCheckpointSidecarError(
                    "Reference checkpoint request is invalid."
                )
            authority.verify(_tail(payload["tail"]))
        except ReferenceAuthorityCheckpointError:
            return JSONResponse({"status": "rejected"}, status_code=409)
        return Response(status_code=204)

    async def advance(request: Request) -> Response:
        try:
            payload = await _payload(request)
            if set(payload) != {"authority_ref", "current", "previous"} or (
                payload["authority_ref"] != authority.authority_ref
            ):
                raise ReferenceCheckpointSidecarError(
                    "Reference checkpoint request is invalid."
                )
            authority.advance(
                _tail(payload["previous"]),
                _tail(payload["current"]),
            )
        except ReferenceAuthorityCheckpointError:
            return JSONResponse({"status": "rejected"}, status_code=409)
        return Response(status_code=204)

    return Starlette(
        routes=(
            Route("/v1/reference-checkpoints/verify", verify, methods=["POST"]),
            Route("/v1/reference-checkpoints/advance", advance, methods=["POST"]),
        )
    )


def reference_checkpoint_settings_from_environment(
    environment: Mapping[str, str],
) -> ReferenceCheckpointSidecarSettings:
    """Load one complete sidecar configuration without reading key content."""

    values = {
        name: _value(environment, name)
        for name in (
            REFERENCE_CHECKPOINT_DATABASE_ENV,
            REFERENCE_CHECKPOINT_HMAC_KEY_FILE_ENV,
            REFERENCE_CHECKPOINT_AUTHORITY_REF_ENV,
            REFERENCE_CHECKPOINT_SOCKET_ENV,
        )
    }
    if any(value is None for value in values.values()):
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint sidecar configuration is incomplete."
        )
    return ReferenceCheckpointSidecarSettings(
        database_path=Path(
            cast(str, values[REFERENCE_CHECKPOINT_DATABASE_ENV])
        ).expanduser(),
        hmac_key_path=Path(
            cast(str, values[REFERENCE_CHECKPOINT_HMAC_KEY_FILE_ENV])
        ).expanduser(),
        authority_ref=cast(str, values[REFERENCE_CHECKPOINT_AUTHORITY_REF_ENV]),
        socket_path=Path(
            cast(str, values[REFERENCE_CHECKPOINT_SOCKET_ENV])
        ).expanduser(),
    )


async def _payload(request: Request) -> dict[str, object]:
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint request is invalid."
        )
    body = await request.body()
    if not body or len(body) > _MAX_BODY_BYTES:
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint request is invalid."
        )
    try:
        value = await request.json()
    except Exception:
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint request is invalid."
        ) from None
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint request is invalid."
        )
    return cast(dict[str, object], value)


def _tail(value: object) -> ReferenceAuthorityStoreTail:
    if type(value) is not dict or set(value) != {
        "chain_mac",
        "last_seen_at",
        "sequence",
        "store_ref",
    }:
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint request is invalid."
        )
    mapping = cast(dict[str, object], value)
    try:
        return ReferenceAuthorityStoreTail(
            store_ref=cast(str, mapping["store_ref"]),
            sequence=cast(int, mapping["sequence"]),
            chain_mac=cast(str, mapping["chain_mac"]),
            last_seen_at=cast(int, mapping["last_seen_at"]),
        )
    except (TypeError, ValueError, PlanningContractError):
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint request is invalid."
        ) from None


def _tail_payload(tail: ReferenceAuthorityStoreTail) -> dict[str, object]:
    if not isinstance(tail, ReferenceAuthorityStoreTail):
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint position is invalid."
        )
    return {
        "chain_mac": tail.chain_mac,
        "last_seen_at": tail.last_seen_at,
        "sequence": tail.sequence,
        "store_ref": tail.store_ref,
    }


def _assert_owner_only_socket(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint sidecar is unavailable."
        ) from None
    if (
        path.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint sidecar boundary is invalid."
        )


def _assert_owner_only_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint sidecar directory is unavailable."
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint sidecar directory must be owner-only."
        )


def _value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if type(raw) is not str:
        return None
    value = raw.strip()
    return value or None


def main() -> None:
    """Run the Reference checkpoint sidecar on one owner-only Unix socket."""

    import uvicorn

    settings = reference_checkpoint_settings_from_environment(os.environ)
    _assert_owner_only_directory(settings.socket_path.parent)
    if settings.socket_path.exists() or settings.socket_path.is_symlink():
        raise ReferenceCheckpointSidecarError(
            "Reference checkpoint sidecar socket already exists."
        )
    authority = PersistentReferenceCheckpointAuthority(
        settings.database_path,
        settings.hmac_key_path,
        authority_ref=settings.authority_ref,
    )
    os.umask(0o177)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(settings.socket_path))
        settings.socket_path.chmod(0o600)
        listener.listen(128)
        config = uvicorn.Config(
            create_reference_checkpoint_sidecar_app(authority),
            access_log=False,
            log_level="warning",
        )
        uvicorn.Server(config).run(sockets=[listener])
    finally:
        listener.close()
        if settings.socket_path.exists() and not settings.socket_path.is_symlink():
            settings.socket_path.unlink()


if __name__ == "__main__":
    main()


__all__ = [
    "ReferenceCheckpointSidecarError",
    "ReferenceCheckpointSidecarSettings",
    "UnixReferenceCheckpointClient",
    "UnixReferenceCheckpointClientSettings",
    "create_reference_checkpoint_sidecar_app",
    "reference_checkpoint_settings_from_environment",
]
