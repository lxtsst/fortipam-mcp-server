"""Process-separated Unix service for value-free V4 reference authorization."""

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
    PersistentReferenceAuthority,
    PlanningContractError,
    ReferenceAuthorityError,
    VerifiedReferenceDecision,
)
from v4_planning.models import require_ref

from .reference_checkpoint_sidecar import (
    UnixReferenceCheckpointClient,
    UnixReferenceCheckpointClientSettings,
)


REFERENCE_AUTHORITY_DATABASE_ENV = "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_DATABASE"
REFERENCE_AUTHORITY_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_HMAC_KEY_FILE"
)
REFERENCE_AUTHORITY_REF_ENV = "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_REF"
REFERENCE_AUTHORITY_SOCKET_ENV = "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_SOCKET"
REFERENCE_AUTHORITY_CHECKPOINT_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_CHECKPOINT_SOCKET"
)
REFERENCE_AUTHORITY_CHECKPOINT_REF_ENV = (
    "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_CHECKPOINT_REF"
)
REFERENCE_AUTHORITY_CHECKPOINT_STORE_REF_ENV = (
    "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_CHECKPOINT_STORE_REF"
)
_MAX_BODY_BYTES = 8192


class ReferenceAuthoritySidecarError(ReferenceAuthorityError):
    """Stable failure for the process-separated Reference Authority boundary."""


@dataclass(frozen=True, slots=True)
class ReferenceAuthoritySidecarSettings:
    database_path: Path
    hmac_key_path: Path
    authority_ref: str
    socket_path: Path
    checkpoint_socket_path: Path
    checkpoint_authority_ref: str
    checkpoint_store_ref: str

    def __post_init__(self) -> None:
        paths = (
            self.database_path,
            self.hmac_key_path,
            self.socket_path,
            self.checkpoint_socket_path,
        )
        try:
            require_ref(self.authority_ref, "Reference sidecar authority_ref")
            require_ref(
                self.checkpoint_authority_ref,
                "Reference sidecar checkpoint authority_ref",
            )
            require_ref(
                self.checkpoint_store_ref,
                "Reference sidecar checkpoint store_ref",
            )
            if self.authority_ref == self.checkpoint_authority_ref:
                raise PlanningContractError(
                    "Reference and checkpoint authorities must be distinct."
                )
        except PlanningContractError as exc:
            raise ReferenceAuthoritySidecarError(
                "Reference sidecar configuration is invalid."
            ) from exc
        if (
            any(not isinstance(path, Path) or not path.is_absolute() for path in paths)
            or len(set(paths)) != len(paths)
        ):
            raise ReferenceAuthoritySidecarError(
                "Reference sidecar configuration is invalid."
            )


@dataclass(frozen=True, slots=True)
class UnixReferenceAuthorityClientSettings:
    socket_path: Path
    authority_ref: str
    timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        try:
            require_ref(self.authority_ref, "Reference client authority_ref")
        except PlanningContractError as exc:
            raise ReferenceAuthoritySidecarError(
                "Reference client configuration is invalid."
            ) from exc
        if (
            not isinstance(self.socket_path, Path)
            or not self.socket_path.is_absolute()
            or type(self.timeout_seconds) is not float
            or not 0.1 <= self.timeout_seconds <= 10.0
        ):
            raise ReferenceAuthoritySidecarError(
                "Reference client configuration is invalid."
            )


class UnixReferenceAuthorityClient:
    """Authorize exact reference contexts through one owner-only UDS."""

    def __init__(self, settings: UnixReferenceAuthorityClientSettings) -> None:
        if not isinstance(settings, UnixReferenceAuthorityClientSettings):
            raise ReferenceAuthoritySidecarError(
                "Reference client configuration is invalid."
            )
        self._settings = settings
        self.authority_ref = settings.authority_ref

    @property
    def monotonic_checkpoint_protocol_bound(self) -> bool:
        """The sidecar service requires its separate checkpoint binding."""

        return True

    def verify_ready(self) -> None:
        """Require the remote Authority to revalidate protected state."""

        response = self._post(
            "/v1/reference-authority/ready",
            {"authority_ref": self.authority_ref},
        )
        if response.status_code != 204 or response.content:
            raise ReferenceAuthoritySidecarError(
                "Reference sidecar rejected readiness."
            )

    def authorize(
        self,
        reference: str,
        *,
        reference_kind: str,
        requester_digest: str,
        environment_ref: str,
        scope_ref: str,
        now_epoch: int,
    ) -> VerifiedReferenceDecision:
        """Return one exact value-free decision from the remote Authority."""

        response = self._post(
            "/v1/reference-authority/authorize",
            {
                "authority_ref": self.authority_ref,
                "environment_ref": environment_ref,
                "now_epoch": now_epoch,
                "reference": reference,
                "reference_kind": reference_kind,
                "requester_digest": requester_digest,
                "scope_ref": scope_ref,
            },
        )
        if response.status_code != 200:
            raise ReferenceAuthoritySidecarError(
                "Reference sidecar rejected authorization."
            )
        try:
            payload = _mapping(response.json(), {"authority_ref", "decision"})
            if payload["authority_ref"] != self.authority_ref:
                raise ReferenceAuthoritySidecarError(
                    "Reference sidecar response is invalid."
                )
            return _decision_from_payload(payload["decision"])
        except (TypeError, ValueError, PlanningContractError):
            raise ReferenceAuthoritySidecarError(
                "Reference sidecar response is invalid."
            ) from None

    def uses_key_material(self, candidate: bytes) -> bool:
        """The client owns no Reference Authority HMAC key material."""

        del candidate
        return False

    def shares_key_material_with(self, candidate: object) -> bool:
        """The client owns no Authority key material to share."""

        del candidate
        return False

    def _post(self, path: str, payload: dict[str, object]) -> httpx.Response:
        _assert_owner_only_socket(self._settings.socket_path)
        transport = httpx.HTTPTransport(uds=str(self._settings.socket_path))
        try:
            with httpx.Client(
                transport=transport,
                base_url="http://reference-authority-sidecar",
                timeout=self._settings.timeout_seconds,
                trust_env=False,
            ) as client:
                return client.post(path, json=payload)
        except (httpx.HTTPError, OSError):
            raise ReferenceAuthoritySidecarError(
                "Reference sidecar is unavailable."
            ) from None


def create_reference_authority_sidecar_app(
    authority: PersistentReferenceAuthority,
) -> Starlette:
    """Create readiness and exact value-free authorization routes only."""

    if not isinstance(authority, PersistentReferenceAuthority):
        raise ReferenceAuthoritySidecarError(
            "Reference sidecar Authority is invalid."
        )

    async def ready(request: Request) -> Response:
        try:
            payload = await _payload(request)
            if payload != {"authority_ref": authority.authority_ref}:
                raise ReferenceAuthoritySidecarError(
                    "Reference request is invalid."
                )
            authority.verify_ready()
        except ReferenceAuthorityError:
            return JSONResponse({"status": "rejected"}, status_code=409)
        return Response(status_code=204)

    async def authorize(request: Request) -> Response:
        try:
            payload = await _payload(request)
            expected = {
                "authority_ref",
                "environment_ref",
                "now_epoch",
                "reference",
                "reference_kind",
                "requester_digest",
                "scope_ref",
            }
            if set(payload) != expected or payload["authority_ref"] != authority.authority_ref:
                raise ReferenceAuthoritySidecarError(
                    "Reference request is invalid."
                )
            decision = authority.authorize(
                _string(payload, "reference"),
                reference_kind=_string(payload, "reference_kind"),
                requester_digest=_string(payload, "requester_digest"),
                environment_ref=_string(payload, "environment_ref"),
                scope_ref=_string(payload, "scope_ref"),
                now_epoch=_integer(payload, "now_epoch"),
            )
        except (ReferenceAuthorityError, TypeError, ValueError):
            return JSONResponse({"status": "rejected"}, status_code=409)
        return JSONResponse(
            {
                "authority_ref": authority.authority_ref,
                "decision": decision.as_dict(),
            }
        )

    return Starlette(
        routes=(
            Route("/v1/reference-authority/ready", ready, methods=["POST"]),
            Route(
                "/v1/reference-authority/authorize",
                authorize,
                methods=["POST"],
            ),
        )
    )


def reference_sidecar_settings_from_environment(
    environment: Mapping[str, str],
) -> ReferenceAuthoritySidecarSettings:
    """Load one complete service configuration without reading key content."""

    names = (
        REFERENCE_AUTHORITY_DATABASE_ENV,
        REFERENCE_AUTHORITY_HMAC_KEY_FILE_ENV,
        REFERENCE_AUTHORITY_REF_ENV,
        REFERENCE_AUTHORITY_SOCKET_ENV,
        REFERENCE_AUTHORITY_CHECKPOINT_SOCKET_ENV,
        REFERENCE_AUTHORITY_CHECKPOINT_REF_ENV,
        REFERENCE_AUTHORITY_CHECKPOINT_STORE_REF_ENV,
    )
    values = {name: _value(environment, name) for name in names}
    if any(value is None for value in values.values()):
        raise ReferenceAuthoritySidecarError(
            "Reference sidecar configuration is incomplete."
        )
    return ReferenceAuthoritySidecarSettings(
        database_path=Path(
            cast(str, values[REFERENCE_AUTHORITY_DATABASE_ENV])
        ).expanduser(),
        hmac_key_path=Path(
            cast(str, values[REFERENCE_AUTHORITY_HMAC_KEY_FILE_ENV])
        ).expanduser(),
        authority_ref=cast(str, values[REFERENCE_AUTHORITY_REF_ENV]),
        socket_path=Path(
            cast(str, values[REFERENCE_AUTHORITY_SOCKET_ENV])
        ).expanduser(),
        checkpoint_socket_path=Path(
            cast(str, values[REFERENCE_AUTHORITY_CHECKPOINT_SOCKET_ENV])
        ).expanduser(),
        checkpoint_authority_ref=cast(
            str,
            values[REFERENCE_AUTHORITY_CHECKPOINT_REF_ENV],
        ),
        checkpoint_store_ref=cast(
            str,
            values[REFERENCE_AUTHORITY_CHECKPOINT_STORE_REF_ENV],
        ),
    )


def _decision_from_payload(value: object) -> VerifiedReferenceDecision:
    item = _mapping(
        value,
        {
            "authority_ref",
            "authorized",
            "checked_at",
            "environment_digest",
            "expires_at",
            "reference_digest",
            "reference_kind",
            "requester_digest",
            "scope_digest",
        },
    )
    return VerifiedReferenceDecision(
        reference_digest=_string(item, "reference_digest"),
        reference_kind=_string(item, "reference_kind"),
        authority_ref=_string(item, "authority_ref"),
        requester_digest=_string(item, "requester_digest"),
        environment_digest=_string(item, "environment_digest"),
        scope_digest=_string(item, "scope_digest"),
        authorized=_boolean(item, "authorized"),
        checked_at=_integer(item, "checked_at"),
        expires_at=_integer(item, "expires_at"),
    )


async def _payload(request: Request) -> dict[str, object]:
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise ReferenceAuthoritySidecarError("Reference request is invalid.")
    body = await request.body()
    if not body or len(body) > _MAX_BODY_BYTES:
        raise ReferenceAuthoritySidecarError("Reference request is invalid.")
    try:
        return _mapping(await request.json())
    except Exception:
        raise ReferenceAuthoritySidecarError(
            "Reference request is invalid."
        ) from None


def _mapping(
    value: object,
    keys: set[str] | None = None,
) -> dict[str, object]:
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise ReferenceAuthoritySidecarError("Reference value is invalid.")
    item = cast(dict[str, object], value)
    if keys is not None and set(item) != keys:
        raise ReferenceAuthoritySidecarError("Reference value is invalid.")
    return item


def _string(value: Mapping[str, object], name: str) -> str:
    item = value.get(name)
    if type(item) is not str:
        raise ReferenceAuthoritySidecarError("Reference value is invalid.")
    return item


def _integer(value: Mapping[str, object], name: str) -> int:
    item = value.get(name)
    if type(item) is not int:
        raise ReferenceAuthoritySidecarError("Reference value is invalid.")
    return item


def _boolean(value: Mapping[str, object], name: str) -> bool:
    item = value.get(name)
    if type(item) is not bool:
        raise ReferenceAuthoritySidecarError("Reference value is invalid.")
    return item


def _assert_owner_only_socket(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise ReferenceAuthoritySidecarError(
            "Reference sidecar is unavailable."
        ) from None
    if (
        path.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ReferenceAuthoritySidecarError(
            "Reference sidecar boundary is invalid."
        )


def _assert_owner_only_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ReferenceAuthoritySidecarError(
            "Reference sidecar directory is unavailable."
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ReferenceAuthoritySidecarError(
            "Reference sidecar directory must be owner-only."
        )


def _value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if type(raw) is not str:
        return None
    value = raw.strip()
    return value or None


def main() -> None:
    """Run the value-free Reference Authority on one owner-only Unix socket."""

    import uvicorn

    settings = reference_sidecar_settings_from_environment(os.environ)
    _assert_owner_only_directory(settings.socket_path.parent)
    if settings.socket_path.exists() or settings.socket_path.is_symlink():
        raise ReferenceAuthoritySidecarError(
            "Reference sidecar socket already exists."
        )
    checkpoint = UnixReferenceCheckpointClient(
        UnixReferenceCheckpointClientSettings(
            settings.checkpoint_socket_path,
            settings.checkpoint_authority_ref,
        )
    )
    checkpoint.verify_ready()
    authority = PersistentReferenceAuthority(
        settings.database_path,
        settings.hmac_key_path,
        authority_ref=settings.authority_ref,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=settings.checkpoint_store_ref,
    )
    os.umask(0o177)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(settings.socket_path))
        settings.socket_path.chmod(0o600)
        listener.listen(128)
        config = uvicorn.Config(
            create_reference_authority_sidecar_app(authority),
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
    "ReferenceAuthoritySidecarError",
    "ReferenceAuthoritySidecarSettings",
    "UnixReferenceAuthorityClient",
    "UnixReferenceAuthorityClientSettings",
    "create_reference_authority_sidecar_app",
    "main",
    "reference_sidecar_settings_from_environment",
]
