"""Process-separated private runtime boundary for V4 Secret creation.

The Host sends only value-free lease control metadata. The sidecar owns the
opaque material binding, provider, lease, and action adapter and returns only a
closed categorical outcome. The packaged command remains deny-all.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import socket
import stat
from typing import Mapping, Protocol, cast

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from v4_planning import (
    C3MaterialBinding,
    DenyAllMaterialProvider,
    DenyAllSecretCreatePrivateAdapter,
    MaterialContractError,
    MaterialLeaseRequest,
    MaterialProviderClass,
    MaterialPurpose,
    MaterialRuntimeError,
    MaterialRuntimeOutcome,
    PersistentMaterialUseStateStore,
    SecretCreateMaterialRuntime,
)
from v4_planning.models import PlanningContractError, require_ref
from fortipam_mcp.material_checkpoint_sidecar import (
    UnixMaterialCheckpointClient,
    UnixMaterialCheckpointClientSettings,
)
from v4_planning.secret_create_adapter import (
    SecretCreateAdapterDenied,
    require_secret_create_lease_request,
)


SECRET_CREATE_RUNTIME_SOCKET_ENV = "FORTIPAM_MCP_V4_SECRET_CREATE_RUNTIME_SOCKET"
SECRET_CREATE_MATERIAL_DATABASE_ENV = (
    "FORTIPAM_MCP_V4_SECRET_CREATE_MATERIAL_DATABASE"
)
SECRET_CREATE_MATERIAL_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_SECRET_CREATE_MATERIAL_HMAC_KEY_FILE"
)
SECRET_CREATE_MATERIAL_CHECKPOINT_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_SECRET_CREATE_MATERIAL_CHECKPOINT_SOCKET"
)
SECRET_CREATE_MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV = (
    "FORTIPAM_MCP_V4_SECRET_CREATE_MATERIAL_CHECKPOINT_AUTHORITY_REF"
)
SECRET_CREATE_MATERIAL_CHECKPOINT_STORE_REF_ENV = (
    "FORTIPAM_MCP_V4_SECRET_CREATE_MATERIAL_CHECKPOINT_STORE_REF"
)
SECRET_CREATE_RUNTIME_REF = "v4-secret-create-private-runtime"
_MAX_BODY_BYTES = 4096


class SecretCreateRuntimeSidecarError(RuntimeError):
    """Stable failure for the process-separated private runtime boundary."""


class SecretCreateRuntimeExecutor(Protocol):
    """Exact private executor shape accepted by trusted sidecar composition."""

    def execute_once(
        self,
        binding: C3MaterialBinding,
        request: MaterialLeaseRequest,
        *,
        now_epoch: int,
    ) -> MaterialRuntimeOutcome: ...

    def verify_ready(self) -> None: ...


@dataclass(frozen=True, slots=True)
class SecretCreateRuntimeSidecarSettings:
    socket_path: Path
    material_database_path: Path
    material_hmac_key_path: Path
    material_checkpoint_socket_path: Path
    material_checkpoint_authority_ref: str
    material_checkpoint_store_ref: str

    def __post_init__(self) -> None:
        paths = (
            self.socket_path,
            self.material_database_path,
            self.material_hmac_key_path,
            self.material_checkpoint_socket_path,
        )
        try:
            require_ref(
                self.material_checkpoint_authority_ref,
                "Secret create material checkpoint authority_ref",
            )
            require_ref(
                self.material_checkpoint_store_ref,
                "Secret create material checkpoint store_ref",
            )
        except PlanningContractError as exc:
            raise SecretCreateRuntimeSidecarError(
                "Secret create runtime sidecar configuration is invalid."
            ) from exc
        if (
            any(not isinstance(path, Path) or not path.is_absolute() for path in paths)
            or len(set(paths)) != len(paths)
        ):
            raise SecretCreateRuntimeSidecarError(
                "Secret create runtime sidecar configuration is invalid."
            )


@dataclass(frozen=True, slots=True)
class UnixSecretCreateRuntimeClientSettings:
    socket_path: Path
    timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.socket_path, Path)
            or not self.socket_path.is_absolute()
            or type(self.timeout_seconds) is not float
            or not 0.1 <= self.timeout_seconds <= 10.0
        ):
            raise SecretCreateRuntimeSidecarError(
                "Secret create runtime client configuration is invalid."
            )


class UnixSecretCreateRuntimeReadinessProbe:
    """Retain only current readiness capability, never execution capability."""

    runtime_ref = SECRET_CREATE_RUNTIME_REF

    def __init__(self, settings: UnixSecretCreateRuntimeClientSettings) -> None:
        if not isinstance(settings, UnixSecretCreateRuntimeClientSettings):
            raise SecretCreateRuntimeSidecarError(
                "Secret create runtime readiness configuration is invalid."
            )
        self._settings = settings

    def verify_ready(self) -> None:
        response = _post_to_runtime(
            self._settings,
            "/v1/secret-create-runtime/ready",
            {"runtime_ref": self.runtime_ref},
        )
        if response.status_code != 204 or response.content:
            raise SecretCreateRuntimeSidecarError(
                "Secret create runtime sidecar rejected readiness."
            )

    def is_available(self) -> bool:
        try:
            self.verify_ready()
        except SecretCreateRuntimeSidecarError:
            return False
        return True


class UnixSecretCreateRuntimeClient:
    """Invoke the private action runtime without receiving C3 objects."""

    runtime_ref = SECRET_CREATE_RUNTIME_REF

    def __init__(self, settings: UnixSecretCreateRuntimeClientSettings) -> None:
        if not isinstance(settings, UnixSecretCreateRuntimeClientSettings):
            raise SecretCreateRuntimeSidecarError(
                "Secret create runtime client configuration is invalid."
            )
        self._settings = settings

    def verify_ready(self) -> None:
        response = _post_to_runtime(
            self._settings,
            "/v1/secret-create-runtime/ready",
            {"runtime_ref": self.runtime_ref},
        )
        if response.status_code != 204 or response.content:
            raise SecretCreateRuntimeSidecarError(
                "Secret create runtime sidecar rejected readiness."
            )

    def execute_once(
        self,
        request: MaterialLeaseRequest,
        *,
        now_epoch: int,
    ) -> MaterialRuntimeOutcome:
        try:
            exact_request = require_secret_create_lease_request(request)
        except (AttributeError, SecretCreateAdapterDenied) as exc:
            raise SecretCreateRuntimeSidecarError(
                "Secret create private runtime is unavailable."
            ) from exc
        if type(now_epoch) is not int or now_epoch < 0:
            raise SecretCreateRuntimeSidecarError(
                "Secret create private runtime is unavailable."
            )
        response = _post_to_runtime(
            self._settings,
            "/v1/secret-create-runtime/execute",
            {
                "lease_request": _lease_request_payload(exact_request),
                "now_epoch": now_epoch,
                "runtime_ref": self.runtime_ref,
            },
        )
        if response.status_code != 200:
            raise SecretCreateRuntimeSidecarError(
                "Secret create private runtime is unavailable."
            )
        try:
            payload = _mapping(response.json(), {"outcome", "runtime_ref"})
            if payload["runtime_ref"] != self.runtime_ref:
                raise SecretCreateRuntimeSidecarError(
                    "Secret create runtime sidecar response is invalid."
                )
            return MaterialRuntimeOutcome(_string(payload, "outcome"))
        except (TypeError, ValueError, SecretCreateRuntimeSidecarError):
            raise SecretCreateRuntimeSidecarError(
                "Secret create runtime sidecar response is invalid."
            ) from None



def _post_to_runtime(
    settings: UnixSecretCreateRuntimeClientSettings,
    path: str,
    payload: dict[str, object],
) -> httpx.Response:
    _assert_owner_only_socket(settings.socket_path)
    transport = httpx.HTTPTransport(uds=str(settings.socket_path))
    try:
        with httpx.Client(
            transport=transport,
            base_url="http://secret-create-runtime-sidecar",
            timeout=settings.timeout_seconds,
            trust_env=False,
        ) as client:
            return client.post(path, json=payload)
    except (httpx.HTTPError, OSError):
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime sidecar is unavailable."
        ) from None


def create_secret_create_runtime_sidecar_app(
    runtime: SecretCreateRuntimeExecutor,
    binding: C3MaterialBinding,
) -> Starlette:
    """Create readiness and exact value-free execution routes only."""

    if (
        not isinstance(binding, C3MaterialBinding)
        or not callable(getattr(runtime, "execute_once", None))
        or not callable(getattr(runtime, "verify_ready", None))
    ):
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime sidecar binding is invalid."
        )

    async def ready(request: Request) -> Response:
        try:
            payload = await _payload(request)
            if payload != {"runtime_ref": SECRET_CREATE_RUNTIME_REF}:
                raise SecretCreateRuntimeSidecarError(
                    "Secret create runtime request is invalid."
                )
            runtime.verify_ready()
        except SecretCreateRuntimeSidecarError:
            return JSONResponse({"status": "rejected"}, status_code=409)
        except (MaterialRuntimeError, SecretCreateAdapterDenied):
            return JSONResponse({"status": "unavailable"}, status_code=503)
        except Exception:
            return JSONResponse({"status": "unavailable"}, status_code=503)
        return Response(status_code=204)

    async def execute(request: Request) -> Response:
        try:
            payload = await _payload(request)
            if (
                set(payload) != {"lease_request", "now_epoch", "runtime_ref"}
                or payload["runtime_ref"] != SECRET_CREATE_RUNTIME_REF
            ):
                raise SecretCreateRuntimeSidecarError(
                    "Secret create runtime request is invalid."
                )
            outcome = runtime.execute_once(
                binding,
                _lease_request(payload["lease_request"]),
                now_epoch=_integer(payload, "now_epoch"),
            )
            if not isinstance(outcome, MaterialRuntimeOutcome):
                raise SecretCreateRuntimeSidecarError(
                    "Secret create runtime outcome is invalid."
                )
        except SecretCreateRuntimeSidecarError:
            return JSONResponse({"status": "rejected"}, status_code=409)
        except (MaterialRuntimeError, SecretCreateAdapterDenied):
            return JSONResponse({"status": "unavailable"}, status_code=503)
        except Exception:
            return JSONResponse(
                {"status": "reconciliation_required"},
                status_code=503,
            )
        return JSONResponse(
            {
                "outcome": outcome.value,
                "runtime_ref": SECRET_CREATE_RUNTIME_REF,
            }
        )

    return Starlette(
        routes=(
            Route("/v1/secret-create-runtime/ready", ready, methods=["POST"]),
            Route("/v1/secret-create-runtime/execute", execute, methods=["POST"]),
        )
    )


def secret_create_runtime_sidecar_settings_from_environment(
    environment: Mapping[str, str],
) -> SecretCreateRuntimeSidecarSettings:
    """Load the complete persistent replay/checkpoint composition."""

    values = {
        name: _value(environment, name)
        for name in (
            SECRET_CREATE_RUNTIME_SOCKET_ENV,
            SECRET_CREATE_MATERIAL_DATABASE_ENV,
            SECRET_CREATE_MATERIAL_HMAC_KEY_FILE_ENV,
            SECRET_CREATE_MATERIAL_CHECKPOINT_SOCKET_ENV,
            SECRET_CREATE_MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV,
            SECRET_CREATE_MATERIAL_CHECKPOINT_STORE_REF_ENV,
        )
    }
    if any(value is None for value in values.values()):
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime sidecar configuration is incomplete."
        )
    return SecretCreateRuntimeSidecarSettings(
        socket_path=Path(
            cast(str, values[SECRET_CREATE_RUNTIME_SOCKET_ENV])
        ).expanduser(),
        material_database_path=Path(
            cast(str, values[SECRET_CREATE_MATERIAL_DATABASE_ENV])
        ).expanduser(),
        material_hmac_key_path=Path(
            cast(str, values[SECRET_CREATE_MATERIAL_HMAC_KEY_FILE_ENV])
        ).expanduser(),
        material_checkpoint_socket_path=Path(
            cast(str, values[SECRET_CREATE_MATERIAL_CHECKPOINT_SOCKET_ENV])
        ).expanduser(),
        material_checkpoint_authority_ref=cast(
            str,
            values[SECRET_CREATE_MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV],
        ),
        material_checkpoint_store_ref=cast(
            str,
            values[SECRET_CREATE_MATERIAL_CHECKPOINT_STORE_REF_ENV],
        ),
    )


def _lease_request_payload(request: MaterialLeaseRequest) -> dict[str, object]:
    return {
        "action_id": request.action_id,
        "action_version": request.action_version,
        "audience_digest": request.audience_digest,
        "authorization_digest": request.authorization_digest,
        "expires_at": request.expires_at,
        "plan_digest": request.plan_digest,
        "policy_decision_digest": request.policy_decision_digest,
        "provider_class": request.provider_class.value,
        "purpose": request.purpose.value,
        "requested_at": request.requested_at,
        "scope_digest": request.scope_digest,
    }


def _lease_request(value: object) -> MaterialLeaseRequest:
    payload = _mapping(
        value,
        {
            "action_id",
            "action_version",
            "audience_digest",
            "authorization_digest",
            "expires_at",
            "plan_digest",
            "policy_decision_digest",
            "provider_class",
            "purpose",
            "requested_at",
            "scope_digest",
        },
    )
    try:
        return require_secret_create_lease_request(
            MaterialLeaseRequest(
                action_id=_string(payload, "action_id"),
                action_version=_string(payload, "action_version"),
                plan_digest=_string(payload, "plan_digest"),
                policy_decision_digest=_string(payload, "policy_decision_digest"),
                authorization_digest=_string(payload, "authorization_digest"),
                scope_digest=_string(payload, "scope_digest"),
                audience_digest=_string(payload, "audience_digest"),
                provider_class=MaterialProviderClass(
                    _string(payload, "provider_class")
                ),
                purpose=MaterialPurpose(_string(payload, "purpose")),
                requested_at=_integer(payload, "requested_at"),
                expires_at=_integer(payload, "expires_at"),
            )
        )
    except (MaterialContractError, SecretCreateAdapterDenied, ValueError):
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime request is invalid."
        ) from None


async def _payload(request: Request) -> dict[str, object]:
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime request is invalid."
        )
    body = await request.body()
    if not body or len(body) > _MAX_BODY_BYTES:
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime request is invalid."
        )
    try:
        return _mapping(await request.json())
    except Exception:
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime request is invalid."
        ) from None


def _mapping(value: object, keys: set[str] | None = None) -> dict[str, object]:
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime value is invalid."
        )
    item = cast(dict[str, object], value)
    if keys is not None and set(item) != keys:
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime value is invalid."
        )
    return item


def _string(value: Mapping[str, object], name: str) -> str:
    item = value.get(name)
    if type(item) is not str:
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime value is invalid."
        )
    return item


def _integer(value: Mapping[str, object], name: str) -> int:
    item = value.get(name)
    if type(item) is not int:
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime value is invalid."
        )
    return item


def _assert_owner_only_socket(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime sidecar is unavailable."
        ) from None
    if (
        path.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime sidecar boundary is invalid."
        )


def _assert_owner_only_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime sidecar directory is unavailable."
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime sidecar directory must be owner-only."
        )


def _value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if type(raw) is not str:
        return None
    value = raw.strip()
    return value or None


def main() -> None:
    """Run the persistent, checkpoint-bound deny-all private runtime."""

    import uvicorn

    settings = secret_create_runtime_sidecar_settings_from_environment(os.environ)
    _assert_owner_only_directory(settings.socket_path.parent)
    if settings.socket_path.exists() or settings.socket_path.is_symlink():
        raise SecretCreateRuntimeSidecarError(
            "Secret create runtime sidecar socket already exists."
        )
    checkpoint = UnixMaterialCheckpointClient(
        UnixMaterialCheckpointClientSettings(
            settings.material_checkpoint_socket_path,
            settings.material_checkpoint_authority_ref,
        )
    )
    state_store = PersistentMaterialUseStateStore(
        settings.material_database_path,
        settings.material_hmac_key_path,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=settings.material_checkpoint_store_ref,
    )
    runtime = SecretCreateMaterialRuntime(
        DenyAllMaterialProvider(),
        state_store,
        DenyAllSecretCreatePrivateAdapter(),
    )
    runtime.verify_ready()
    binding = C3MaterialBinding()
    os.umask(0o177)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(settings.socket_path))
        settings.socket_path.chmod(0o600)
        listener.listen(128)
        config = uvicorn.Config(
            create_secret_create_runtime_sidecar_app(runtime, binding),
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
    "SECRET_CREATE_MATERIAL_CHECKPOINT_AUTHORITY_REF_ENV",
    "SECRET_CREATE_MATERIAL_CHECKPOINT_SOCKET_ENV",
    "SECRET_CREATE_MATERIAL_CHECKPOINT_STORE_REF_ENV",
    "SECRET_CREATE_MATERIAL_DATABASE_ENV",
    "SECRET_CREATE_MATERIAL_HMAC_KEY_FILE_ENV",
    "SECRET_CREATE_RUNTIME_REF",
    "SECRET_CREATE_RUNTIME_SOCKET_ENV",
    "SecretCreateRuntimeSidecarError",
    "SecretCreateRuntimeSidecarSettings",
    "UnixSecretCreateRuntimeClient",
    "UnixSecretCreateRuntimeClientSettings",
    "UnixSecretCreateRuntimeReadinessProbe",
    "create_secret_create_runtime_sidecar_app",
    "main",
    "secret_create_runtime_sidecar_settings_from_environment",
]
