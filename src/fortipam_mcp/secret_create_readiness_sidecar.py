"""Readiness-only Unix boundary for the private Secret-create runtime."""

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

from .secret_create_runtime_sidecar import (
    SECRET_CREATE_RUNTIME_REF,
    SecretCreateRuntimeSidecarError,
    UnixSecretCreateRuntimeClientSettings,
    UnixSecretCreateRuntimeReadinessProbe,
)


SECRET_CREATE_READINESS_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_SECRET_CREATE_READINESS_SOCKET"
)
SECRET_CREATE_PRIVATE_RUNTIME_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_SECRET_CREATE_PRIVATE_RUNTIME_SOCKET"
)
SECRET_CREATE_READINESS_PROXY_REF = "v4-secret-create-readiness-proxy"
_MAX_BODY_BYTES = 512


class SecretCreateReadinessSidecarError(RuntimeError):
    """Stable failure for the readiness-only Unix boundary."""


@dataclass(frozen=True, slots=True)
class SecretCreateReadinessSidecarSettings:
    socket_path: Path
    private_runtime_socket_path: Path

    def __post_init__(self) -> None:
        paths = (self.socket_path, self.private_runtime_socket_path)
        if (
            any(not isinstance(path, Path) or not path.is_absolute() for path in paths)
            or len(set(paths)) != len(paths)
        ):
            raise SecretCreateReadinessSidecarError(
                "Secret create readiness sidecar configuration is invalid."
            )


@dataclass(frozen=True, slots=True)
class UnixSecretCreateReadinessProxyClientSettings:
    socket_path: Path
    timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.socket_path, Path)
            or not self.socket_path.is_absolute()
            or type(self.timeout_seconds) is not float
            or not 0.1 <= self.timeout_seconds <= 10.0
        ):
            raise SecretCreateReadinessSidecarError(
                "Secret create readiness client configuration is invalid."
            )


class UnixSecretCreateReadinessProxyClient:
    """Query only the readiness proxy; this type has no execution method."""

    def __init__(
        self,
        settings: UnixSecretCreateReadinessProxyClientSettings,
    ) -> None:
        if not isinstance(settings, UnixSecretCreateReadinessProxyClientSettings):
            raise SecretCreateReadinessSidecarError(
                "Secret create readiness client configuration is invalid."
            )
        self._settings = settings

    def verify_ready(self) -> None:
        _assert_owner_only_socket(self._settings.socket_path)
        transport = httpx.HTTPTransport(uds=str(self._settings.socket_path))
        try:
            with httpx.Client(
                transport=transport,
                base_url="http://secret-create-readiness-sidecar",
                timeout=self._settings.timeout_seconds,
                trust_env=False,
            ) as client:
                response = client.post(
                    "/v1/secret-create-readiness/ready",
                    json={"readiness_proxy_ref": SECRET_CREATE_READINESS_PROXY_REF},
                )
        except (httpx.HTTPError, OSError) as exc:
            raise SecretCreateReadinessSidecarError(
                "Secret create readiness sidecar is unavailable."
            ) from exc
        if response.status_code != 204 or response.content:
            raise SecretCreateReadinessSidecarError(
                "Secret create readiness sidecar rejected readiness."
            )

    def is_available(self) -> bool:
        try:
            self.verify_ready()
        except SecretCreateReadinessSidecarError:
            return False
        return True


def create_secret_create_readiness_sidecar_app(
    probe: UnixSecretCreateRuntimeReadinessProbe,
) -> Starlette:
    """Expose only the exact readiness request, never execution."""

    if not isinstance(probe, UnixSecretCreateRuntimeReadinessProbe):
        raise SecretCreateReadinessSidecarError(
            "Secret create readiness probe binding is invalid."
        )

    async def ready(request: Request) -> Response:
        try:
            if await _payload(request) != {
                "readiness_proxy_ref": SECRET_CREATE_READINESS_PROXY_REF
            }:
                raise SecretCreateReadinessSidecarError(
                    "Secret create readiness request is invalid."
                )
            probe.verify_ready()
        except SecretCreateReadinessSidecarError:
            return JSONResponse({"status": "rejected"}, status_code=409)
        except SecretCreateRuntimeSidecarError:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return Response(status_code=204)

    return Starlette(
        routes=(Route("/v1/secret-create-readiness/ready", ready, methods=["POST"]),)
    )


def secret_create_readiness_sidecar_settings_from_environment(
    environment: Mapping[str, str],
) -> SecretCreateReadinessSidecarSettings:
    """Load the two distinct owner-only Unix socket paths."""

    values = {
        name: _value(environment, name)
        for name in (
            SECRET_CREATE_READINESS_SOCKET_ENV,
            SECRET_CREATE_PRIVATE_RUNTIME_SOCKET_ENV,
        )
    }
    if any(value is None for value in values.values()):
        raise SecretCreateReadinessSidecarError(
            "Secret create readiness sidecar configuration is incomplete."
        )
    return SecretCreateReadinessSidecarSettings(
        socket_path=Path(
            cast(str, values[SECRET_CREATE_READINESS_SOCKET_ENV])
        ).expanduser(),
        private_runtime_socket_path=Path(
            cast(str, values[SECRET_CREATE_PRIVATE_RUNTIME_SOCKET_ENV])
        ).expanduser(),
    )


async def _payload(request: Request) -> dict[str, object]:
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise SecretCreateReadinessSidecarError(
            "Secret create readiness request is invalid."
        )
    body = await request.body()
    if not body or len(body) > _MAX_BODY_BYTES:
        raise SecretCreateReadinessSidecarError(
            "Secret create readiness request is invalid."
        )
    try:
        value = await request.json()
    except Exception:
        raise SecretCreateReadinessSidecarError(
            "Secret create readiness request is invalid."
        ) from None
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise SecretCreateReadinessSidecarError(
            "Secret create readiness request is invalid."
        )
    return cast(dict[str, object], value)


def _assert_owner_only_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SecretCreateReadinessSidecarError(
            "Secret create readiness sidecar directory is unavailable."
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SecretCreateReadinessSidecarError(
            "Secret create readiness sidecar directory must be owner-only."
        )


def _assert_owner_only_socket(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise SecretCreateReadinessSidecarError(
            "Secret create readiness sidecar is unavailable."
        ) from None
    if (
        path.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SecretCreateReadinessSidecarError(
            "Secret create readiness sidecar boundary is invalid."
        )


def _value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if type(raw) is not str:
        return None
    value = raw.strip()
    return value or None


def main() -> None:
    """Run the readiness-only proxy on one owner-only Unix socket."""

    import uvicorn

    settings = secret_create_readiness_sidecar_settings_from_environment(os.environ)
    _assert_owner_only_directory(settings.socket_path.parent)
    if settings.socket_path.exists() or settings.socket_path.is_symlink():
        raise SecretCreateReadinessSidecarError(
            "Secret create readiness sidecar socket already exists."
        )
    probe = UnixSecretCreateRuntimeReadinessProbe(
        UnixSecretCreateRuntimeClientSettings(settings.private_runtime_socket_path)
    )
    probe.verify_ready()
    os.umask(0o177)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(settings.socket_path))
        settings.socket_path.chmod(0o600)
        listener.listen(128)
        config = uvicorn.Config(
            create_secret_create_readiness_sidecar_app(probe),
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
    "SECRET_CREATE_PRIVATE_RUNTIME_SOCKET_ENV",
    "SECRET_CREATE_READINESS_SOCKET_ENV",
    "SECRET_CREATE_READINESS_PROXY_REF",
    "SecretCreateReadinessSidecarError",
    "SecretCreateReadinessSidecarSettings",
    "UnixSecretCreateReadinessProxyClient",
    "UnixSecretCreateReadinessProxyClientSettings",
    "create_secret_create_readiness_sidecar_app",
    "main",
    "secret_create_readiness_sidecar_settings_from_environment",
]
