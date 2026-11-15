"""Process-separated Unix-socket service for approval-receipt authentication."""

from __future__ import annotations

from dataclasses import dataclass
import hmac
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
    ApprovalReceipt,
    ApprovalReceiptAuthenticator,
    PlanningContractError,
)
from v4_planning.approval import (
    MAX_APPROVAL_RECEIPT_KEY_BYTES,
    MIN_APPROVAL_RECEIPT_KEY_BYTES,
)
from v4_planning.models import require_digest


APPROVAL_RECEIPT_SIDECAR_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_APPROVAL_RECEIPT_SIDECAR_HMAC_KEY_FILE"
)
APPROVAL_RECEIPT_SIDECAR_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_APPROVAL_RECEIPT_SIDECAR_SOCKET"
)
_MAX_BODY_BYTES = 4096


class ApprovalReceiptSidecarError(PlanningContractError):
    """Stable failure for the process-separated receipt boundary."""


@dataclass(frozen=True, slots=True)
class ApprovalReceiptSidecarSettings:
    hmac_key_path: Path
    socket_path: Path

    def __post_init__(self) -> None:
        if (
            not isinstance(self.hmac_key_path, Path)
            or not isinstance(self.socket_path, Path)
            or not self.hmac_key_path.is_absolute()
            or not self.socket_path.is_absolute()
            or self.hmac_key_path == self.socket_path
        ):
            raise ApprovalReceiptSidecarError(
                "Approval receipt sidecar configuration is invalid."
            )


@dataclass(frozen=True, slots=True)
class UnixApprovalReceiptAuthenticatorSettings:
    socket_path: Path
    timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        if (
            not isinstance(self.socket_path, Path)
            or not self.socket_path.is_absolute()
            or type(self.timeout_seconds) is not float
            or not 0.1 <= self.timeout_seconds <= 10.0
        ):
            raise ApprovalReceiptSidecarError(
                "Approval receipt client configuration is invalid."
            )


class UnixApprovalReceiptAuthenticator:
    """Authenticate receipt digests through one owner-only Unix socket."""

    authority_ref = ApprovalReceiptAuthenticator.authority_ref

    def __init__(self, settings: UnixApprovalReceiptAuthenticatorSettings) -> None:
        if not isinstance(settings, UnixApprovalReceiptAuthenticatorSettings):
            raise ApprovalReceiptSidecarError(
                "Approval receipt client configuration is invalid."
            )
        self._settings = settings

    def verify_ready(self) -> None:
        """Require the remote authenticator to answer under the fixed identity."""

        response = self._post(
            "/v1/approval-receipt/ready",
            {"authenticator_ref": self.authority_ref},
        )
        if response.status_code != 204 or response.content:
            raise ApprovalReceiptSidecarError(
                "Approval receipt sidecar rejected readiness."
            )

    def mac(self, receipt_digest: str) -> str:
        """Return one MAC for an exact validated receipt digest."""

        try:
            require_digest(receipt_digest, "receipt_digest")
        except PlanningContractError as exc:
            raise ApprovalReceiptSidecarError(
                "Approval receipt digest is invalid."
            ) from exc
        response = self._post(
            "/v1/approval-receipt/mac",
            {
                "authenticator_ref": self.authority_ref,
                "receipt_digest": receipt_digest,
            },
        )
        if response.status_code != 200:
            raise ApprovalReceiptSidecarError(
                "Approval receipt sidecar rejected authentication."
            )
        try:
            payload = _mapping(response.json(), {"authenticator_ref", "receipt_mac"})
            if payload["authenticator_ref"] != self.authority_ref:
                raise ApprovalReceiptSidecarError(
                    "Approval receipt sidecar response is invalid."
                )
            receipt_mac = _string(payload, "receipt_mac")
            require_digest(receipt_mac, "receipt_mac")
            return receipt_mac
        except (TypeError, ValueError, PlanningContractError):
            raise ApprovalReceiptSidecarError(
                "Approval receipt sidecar response is invalid."
            ) from None

    def verify(self, receipt: ApprovalReceipt) -> bool:
        """Verify a typed receipt without bringing key material into the Host."""

        if (
            not isinstance(receipt, ApprovalReceipt)
            or receipt.authenticator_ref != self.authority_ref
            or receipt.receipt_mac is None
        ):
            return False
        try:
            expected = self.mac(receipt.receipt_digest)
        except ApprovalReceiptSidecarError:
            return False
        return hmac.compare_digest(expected, receipt.receipt_mac)

    def uses_key_material(self, candidate: bytes) -> bool:
        """The client owns no receipt HMAC key material to compare."""

        del candidate
        return False

    def _post(self, path: str, payload: dict[str, object]) -> httpx.Response:
        _assert_owner_only_socket(self._settings.socket_path)
        transport = httpx.HTTPTransport(uds=str(self._settings.socket_path))
        try:
            with httpx.Client(
                transport=transport,
                base_url="http://approval-receipt-sidecar",
                timeout=self._settings.timeout_seconds,
                trust_env=False,
            ) as client:
                return client.post(path, json=payload)
        except (httpx.HTTPError, OSError):
            raise ApprovalReceiptSidecarError(
                "Approval receipt sidecar is unavailable."
            ) from None


def create_approval_receipt_sidecar_app(
    authenticator: ApprovalReceiptAuthenticator,
) -> Starlette:
    """Create readiness and exact receipt-MAC routes only."""

    if not isinstance(authenticator, ApprovalReceiptAuthenticator):
        raise ApprovalReceiptSidecarError(
            "Approval receipt sidecar authenticator is invalid."
        )

    async def ready(request: Request) -> Response:
        try:
            payload = await _payload(request)
            if payload != {"authenticator_ref": authenticator.authority_ref}:
                raise ApprovalReceiptSidecarError(
                    "Approval receipt request is invalid."
                )
        except ApprovalReceiptSidecarError:
            return JSONResponse({"status": "rejected"}, status_code=409)
        return Response(status_code=204)

    async def mac(request: Request) -> Response:
        try:
            payload = await _payload(request)
            if (
                set(payload) != {"authenticator_ref", "receipt_digest"}
                or payload["authenticator_ref"] != authenticator.authority_ref
            ):
                raise ApprovalReceiptSidecarError(
                    "Approval receipt request is invalid."
                )
            receipt_mac = authenticator.mac(_string(payload, "receipt_digest"))
        except (ApprovalReceiptSidecarError, PlanningContractError):
            return JSONResponse({"status": "rejected"}, status_code=409)
        return JSONResponse(
            {
                "authenticator_ref": authenticator.authority_ref,
                "receipt_mac": receipt_mac,
            }
        )

    return Starlette(
        routes=(
            Route("/v1/approval-receipt/ready", ready, methods=["POST"]),
            Route("/v1/approval-receipt/mac", mac, methods=["POST"]),
        )
    )


def approval_receipt_sidecar_settings_from_environment(
    environment: Mapping[str, str],
) -> ApprovalReceiptSidecarSettings:
    """Load one complete service configuration without reading key content."""

    key_path = _value(environment, APPROVAL_RECEIPT_SIDECAR_HMAC_KEY_FILE_ENV)
    socket_path = _value(environment, APPROVAL_RECEIPT_SIDECAR_SOCKET_ENV)
    if key_path is None or socket_path is None:
        raise ApprovalReceiptSidecarError(
            "Approval receipt sidecar configuration is incomplete."
        )
    return ApprovalReceiptSidecarSettings(
        Path(key_path).expanduser(),
        Path(socket_path).expanduser(),
    )


async def _payload(request: Request) -> dict[str, object]:
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise ApprovalReceiptSidecarError("Approval receipt request is invalid.")
    body = await request.body()
    if not body or len(body) > _MAX_BODY_BYTES:
        raise ApprovalReceiptSidecarError("Approval receipt request is invalid.")
    try:
        return _mapping(await request.json())
    except Exception:
        raise ApprovalReceiptSidecarError(
            "Approval receipt request is invalid."
        ) from None


def _mapping(value: object, keys: set[str] | None = None) -> dict[str, object]:
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise ApprovalReceiptSidecarError("Approval receipt value is invalid.")
    item = cast(dict[str, object], value)
    if keys is not None and set(item) != keys:
        raise ApprovalReceiptSidecarError("Approval receipt value is invalid.")
    return item


def _string(value: Mapping[str, object], name: str) -> str:
    item = value.get(name)
    if type(item) is not str:
        raise ApprovalReceiptSidecarError("Approval receipt value is invalid.")
    return item


def _assert_owner_only_socket(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise ApprovalReceiptSidecarError(
            "Approval receipt sidecar is unavailable."
        ) from None
    if (
        path.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ApprovalReceiptSidecarError(
            "Approval receipt sidecar boundary is invalid."
        )


def _assert_owner_only_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ApprovalReceiptSidecarError(
            "Approval receipt sidecar directory is unavailable."
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ApprovalReceiptSidecarError(
            "Approval receipt sidecar directory must be owner-only."
        )


def _load_key(path: Path) -> bytes:
    _assert_owner_only_directory(path.parent)
    try:
        metadata = path.lstat()
        key = path.read_bytes()
    except OSError as exc:
        raise ApprovalReceiptSidecarError(
            "Approval receipt HMAC key is unavailable."
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not MIN_APPROVAL_RECEIPT_KEY_BYTES
        <= len(key)
        <= MAX_APPROVAL_RECEIPT_KEY_BYTES
    ):
        raise ApprovalReceiptSidecarError(
            "Approval receipt HMAC key boundary is invalid."
        )
    return key


def _value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if type(raw) is not str:
        return None
    value = raw.strip()
    return value or None


def main() -> None:
    """Run the receipt authenticator on one owner-only Unix-domain socket."""

    import uvicorn

    settings = approval_receipt_sidecar_settings_from_environment(os.environ)
    _assert_owner_only_directory(settings.socket_path.parent)
    if settings.socket_path.exists() or settings.socket_path.is_symlink():
        raise ApprovalReceiptSidecarError(
            "Approval receipt sidecar socket already exists."
        )
    authenticator = ApprovalReceiptAuthenticator(_load_key(settings.hmac_key_path))
    os.umask(0o177)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(settings.socket_path))
        settings.socket_path.chmod(0o600)
        listener.listen(128)
        config = uvicorn.Config(
            create_approval_receipt_sidecar_app(authenticator),
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
    "ApprovalReceiptSidecarError",
    "ApprovalReceiptSidecarSettings",
    "UnixApprovalReceiptAuthenticator",
    "UnixApprovalReceiptAuthenticatorSettings",
    "approval_receipt_sidecar_settings_from_environment",
    "create_approval_receipt_sidecar_app",
    "main",
]
