"""Process-separated Unix service for resolving V4 Scheme Draft references."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import os
from pathlib import Path
import socket
import stat
import time
from typing import Mapping, cast

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from v4_planning import (
    AuthenticatedRequester,
    PersistentSchemeDraftAuthority,
    PlanningContractError,
    SchemeDraft,
    SchemeDraftAuthorityError,
    scheme_draft_as_mapping,
    scheme_draft_from_mapping,
)
from v4_planning.models import require_ref

from .scheme_draft_checkpoint_sidecar import (
    UnixSchemeDraftCheckpointClient,
    UnixSchemeDraftCheckpointClientSettings,
)


SCHEME_DRAFT_AUTHORITY_DATABASE_ENV = (
    "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_DATABASE"
)
SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE"
)
SCHEME_DRAFT_AUTHORITY_REF_ENV = "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_REF"
SCHEME_DRAFT_AUTHORITY_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_SOCKET"
)
SCHEME_DRAFT_AUTHORITY_CHECKPOINT_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_CHECKPOINT_SOCKET"
)
SCHEME_DRAFT_AUTHORITY_CHECKPOINT_REF_ENV = (
    "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_CHECKPOINT_REF"
)
SCHEME_DRAFT_AUTHORITY_CHECKPOINT_STORE_REF_ENV = (
    "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_CHECKPOINT_STORE_REF"
)
_MAX_BODY_BYTES = 65_536


class SchemeDraftAuthoritySidecarError(SchemeDraftAuthorityError):
    """Stable failure for the process-separated Scheme Draft boundary."""


@dataclass(frozen=True, slots=True)
class SchemeDraftAuthoritySidecarSettings:
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
            require_ref(self.authority_ref, "Scheme Draft sidecar authority_ref")
            require_ref(
                self.checkpoint_authority_ref,
                "Scheme Draft sidecar checkpoint authority_ref",
            )
            require_ref(
                self.checkpoint_store_ref,
                "Scheme Draft sidecar checkpoint store_ref",
            )
            if self.authority_ref == self.checkpoint_authority_ref:
                raise PlanningContractError(
                    "Scheme Draft and checkpoint authorities must be distinct."
                )
        except PlanningContractError as exc:
            raise SchemeDraftAuthoritySidecarError(
                "Scheme Draft sidecar configuration is invalid."
            ) from exc
        if (
            any(not isinstance(path, Path) or not path.is_absolute() for path in paths)
            or len(set(paths)) != len(paths)
        ):
            raise SchemeDraftAuthoritySidecarError(
                "Scheme Draft sidecar configuration is invalid."
            )


@dataclass(frozen=True, slots=True)
class UnixSchemeDraftAuthorityClientSettings:
    socket_path: Path
    authority_ref: str
    timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        try:
            require_ref(self.authority_ref, "Scheme Draft client authority_ref")
        except PlanningContractError as exc:
            raise SchemeDraftAuthoritySidecarError(
                "Scheme Draft client configuration is invalid."
            ) from exc
        if (
            not isinstance(self.socket_path, Path)
            or not self.socket_path.is_absolute()
            or type(self.timeout_seconds) is not float
            or not 0.1 <= self.timeout_seconds <= 10.0
        ):
            raise SchemeDraftAuthoritySidecarError(
                "Scheme Draft client configuration is invalid."
            )


class UnixSchemeDraftAuthorityClient:
    """Resolve exact requester-bound drafts through one owner-only UDS."""

    def __init__(
        self,
        settings: UnixSchemeDraftAuthorityClientSettings,
        *,
        clock: Callable[[], int] | None = None,
    ) -> None:
        if not isinstance(settings, UnixSchemeDraftAuthorityClientSettings):
            raise SchemeDraftAuthoritySidecarError(
                "Scheme Draft client configuration is invalid."
            )
        self._settings = settings
        self._clock = clock or (lambda: int(time.time()))
        self.authority_ref = settings.authority_ref

    @property
    def monotonic_checkpoint_protocol_bound(self) -> bool:
        """The sidecar service requires its separate checkpoint binding."""

        return True

    def verify_ready(self) -> None:
        """Require the remote Authority to revalidate protected state."""

        response = self._post(
            "/v1/scheme-draft/ready",
            {"authority_ref": self.authority_ref},
        )
        if response.status_code != 204 or response.content:
            raise SchemeDraftAuthoritySidecarError(
                "Scheme Draft sidecar rejected readiness."
            )

    def resolve(
        self,
        scheme_draft_ref: str,
        requester: AuthenticatedRequester,
    ) -> SchemeDraft:
        """Resolve one exact opaque reference without local state/key access."""

        try:
            require_ref(scheme_draft_ref, "scheme_draft_ref")
        except PlanningContractError as exc:
            raise SchemeDraftAuthoritySidecarError(
                "Scheme Draft is unavailable."
            ) from exc
        if not isinstance(requester, AuthenticatedRequester):
            raise SchemeDraftAuthoritySidecarError("Scheme Draft is unavailable.")
        now_epoch = self._clock()
        if type(now_epoch) is not int or now_epoch < 0:
            raise SchemeDraftAuthoritySidecarError(
                "Scheme Draft client time is invalid."
            )
        response = self._post(
            "/v1/scheme-draft/resolve",
            {
                "authority_ref": self.authority_ref,
                "now_epoch": now_epoch,
                "requester": _requester_payload(requester),
                "scheme_draft_ref": scheme_draft_ref,
            },
        )
        if response.status_code != 200:
            raise SchemeDraftAuthoritySidecarError("Scheme Draft is unavailable.")
        try:
            payload = _mapping(response.json(), {"authority_ref", "draft"})
            if payload["authority_ref"] != self.authority_ref:
                raise SchemeDraftAuthoritySidecarError(
                    "Scheme Draft sidecar response is invalid."
                )
            return scheme_draft_from_mapping(_mapping(payload["draft"]))
        except (TypeError, ValueError, PlanningContractError):
            raise SchemeDraftAuthoritySidecarError(
                "Scheme Draft sidecar response is invalid."
            ) from None

    def uses_key_material(self, candidate: bytes) -> bool:
        """The client owns no Scheme Draft HMAC key material to compare."""

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
                base_url="http://scheme-draft-sidecar",
                timeout=self._settings.timeout_seconds,
                trust_env=False,
            ) as client:
                return client.post(path, json=payload)
        except (httpx.HTTPError, OSError):
            raise SchemeDraftAuthoritySidecarError(
                "Scheme Draft sidecar is unavailable."
            ) from None


def create_scheme_draft_authority_sidecar_app(
    authority: PersistentSchemeDraftAuthority,
) -> Starlette:
    """Create readiness and exact requester-bound resolve routes only."""

    if not isinstance(authority, PersistentSchemeDraftAuthority):
        raise SchemeDraftAuthoritySidecarError(
            "Scheme Draft sidecar Authority is invalid."
        )

    async def ready(request: Request) -> Response:
        try:
            payload = await _payload(request)
            if payload != {"authority_ref": authority.authority_ref}:
                raise SchemeDraftAuthoritySidecarError(
                    "Scheme Draft request is invalid."
                )
            authority.verify_ready()
        except SchemeDraftAuthorityError:
            return JSONResponse({"status": "rejected"}, status_code=409)
        return Response(status_code=204)

    async def resolve(request: Request) -> Response:
        try:
            payload = await _payload(request)
            if (
                set(payload)
                != {
                    "authority_ref",
                    "now_epoch",
                    "requester",
                    "scheme_draft_ref",
                }
                or payload["authority_ref"] != authority.authority_ref
            ):
                raise SchemeDraftAuthoritySidecarError(
                    "Scheme Draft request is invalid."
                )
            draft = authority.resolve(
                _string(payload, "scheme_draft_ref"),
                _requester_from_payload(payload["requester"]),
                now_epoch=_integer(payload, "now_epoch"),
            )
        except (SchemeDraftAuthorityError, TypeError, ValueError):
            return JSONResponse({"status": "rejected"}, status_code=409)
        return JSONResponse(
            {
                "authority_ref": authority.authority_ref,
                "draft": scheme_draft_as_mapping(draft),
            }
        )

    return Starlette(
        routes=(
            Route("/v1/scheme-draft/ready", ready, methods=["POST"]),
            Route("/v1/scheme-draft/resolve", resolve, methods=["POST"]),
        )
    )


def scheme_draft_sidecar_settings_from_environment(
    environment: Mapping[str, str],
) -> SchemeDraftAuthoritySidecarSettings:
    """Load one complete service configuration without reading key content."""

    names = (
        SCHEME_DRAFT_AUTHORITY_DATABASE_ENV,
        SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE_ENV,
        SCHEME_DRAFT_AUTHORITY_REF_ENV,
        SCHEME_DRAFT_AUTHORITY_SOCKET_ENV,
        SCHEME_DRAFT_AUTHORITY_CHECKPOINT_SOCKET_ENV,
        SCHEME_DRAFT_AUTHORITY_CHECKPOINT_REF_ENV,
        SCHEME_DRAFT_AUTHORITY_CHECKPOINT_STORE_REF_ENV,
    )
    values = {name: _value(environment, name) for name in names}
    if any(value is None for value in values.values()):
        raise SchemeDraftAuthoritySidecarError(
            "Scheme Draft sidecar configuration is incomplete."
        )
    return SchemeDraftAuthoritySidecarSettings(
        database_path=Path(
            cast(str, values[SCHEME_DRAFT_AUTHORITY_DATABASE_ENV])
        ).expanduser(),
        hmac_key_path=Path(
            cast(str, values[SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE_ENV])
        ).expanduser(),
        authority_ref=cast(str, values[SCHEME_DRAFT_AUTHORITY_REF_ENV]),
        socket_path=Path(
            cast(str, values[SCHEME_DRAFT_AUTHORITY_SOCKET_ENV])
        ).expanduser(),
        checkpoint_socket_path=Path(
            cast(str, values[SCHEME_DRAFT_AUTHORITY_CHECKPOINT_SOCKET_ENV])
        ).expanduser(),
        checkpoint_authority_ref=cast(
            str,
            values[SCHEME_DRAFT_AUTHORITY_CHECKPOINT_REF_ENV],
        ),
        checkpoint_store_ref=cast(
            str,
            values[SCHEME_DRAFT_AUTHORITY_CHECKPOINT_STORE_REF_ENV],
        ),
    )


def _requester_payload(requester: AuthenticatedRequester) -> dict[str, object]:
    return {
        "identity_authority_ref": requester.identity_authority_ref,
        "principal_class": requester.principal_class,
        "subject_namespace": requester.subject_namespace,
        "subject_ref": requester.subject_ref,
    }


def _requester_from_payload(value: object) -> AuthenticatedRequester:
    item = _mapping(
        value,
        {
            "identity_authority_ref",
            "principal_class",
            "subject_namespace",
            "subject_ref",
        },
    )
    return AuthenticatedRequester(
        subject_ref=_string(item, "subject_ref"),
        principal_class=_string(item, "principal_class"),
        identity_authority_ref=_optional_string(item, "identity_authority_ref"),
        subject_namespace=_optional_string(item, "subject_namespace"),
    )


async def _payload(request: Request) -> dict[str, object]:
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise SchemeDraftAuthoritySidecarError("Scheme Draft request is invalid.")
    body = await request.body()
    if not body or len(body) > _MAX_BODY_BYTES:
        raise SchemeDraftAuthoritySidecarError("Scheme Draft request is invalid.")
    try:
        return _mapping(await request.json())
    except Exception:
        raise SchemeDraftAuthoritySidecarError(
            "Scheme Draft request is invalid."
        ) from None


def _mapping(
    value: object,
    keys: set[str] | None = None,
) -> dict[str, object]:
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise SchemeDraftAuthoritySidecarError("Scheme Draft value is invalid.")
    item = cast(dict[str, object], value)
    if keys is not None and set(item) != keys:
        raise SchemeDraftAuthoritySidecarError("Scheme Draft value is invalid.")
    return item


def _string(value: Mapping[str, object], name: str) -> str:
    item = value.get(name)
    if type(item) is not str:
        raise SchemeDraftAuthoritySidecarError("Scheme Draft value is invalid.")
    return item


def _optional_string(value: Mapping[str, object], name: str) -> str | None:
    item = value.get(name)
    if item is not None and type(item) is not str:
        raise SchemeDraftAuthoritySidecarError("Scheme Draft value is invalid.")
    return cast(str | None, item)


def _integer(value: Mapping[str, object], name: str) -> int:
    item = value.get(name)
    if type(item) is not int:
        raise SchemeDraftAuthoritySidecarError("Scheme Draft value is invalid.")
    return item


def _assert_owner_only_socket(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise SchemeDraftAuthoritySidecarError(
            "Scheme Draft sidecar is unavailable."
        ) from None
    if (
        path.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SchemeDraftAuthoritySidecarError(
            "Scheme Draft sidecar boundary is invalid."
        )


def _assert_owner_only_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SchemeDraftAuthoritySidecarError(
            "Scheme Draft sidecar directory is unavailable."
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SchemeDraftAuthoritySidecarError(
            "Scheme Draft sidecar directory must be owner-only."
        )


def _value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if type(raw) is not str:
        return None
    value = raw.strip()
    return value or None


def main() -> None:
    """Run the Scheme Draft resolver on one owner-only Unix socket."""

    import uvicorn

    settings = scheme_draft_sidecar_settings_from_environment(os.environ)
    _assert_owner_only_directory(settings.socket_path.parent)
    if settings.socket_path.exists() or settings.socket_path.is_symlink():
        raise SchemeDraftAuthoritySidecarError(
            "Scheme Draft sidecar socket already exists."
        )
    checkpoint = UnixSchemeDraftCheckpointClient(
        UnixSchemeDraftCheckpointClientSettings(
            settings.checkpoint_socket_path,
            settings.checkpoint_authority_ref,
        )
    )
    checkpoint.verify_ready()
    authority = PersistentSchemeDraftAuthority(
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
            create_scheme_draft_authority_sidecar_app(authority),
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
    "SchemeDraftAuthoritySidecarError",
    "SchemeDraftAuthoritySidecarSettings",
    "UnixSchemeDraftAuthorityClient",
    "UnixSchemeDraftAuthorityClientSettings",
    "create_scheme_draft_authority_sidecar_app",
    "main",
    "scheme_draft_sidecar_settings_from_environment",
]
