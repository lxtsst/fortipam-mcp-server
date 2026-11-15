"""One fixed FortiPAM 7.0 Local User create with owner-only initial material."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import secrets
import stat
import threading
from typing import Any
from urllib.parse import quote, urlencode

from .mutable_json_buffer import _take_mutable_prefix, _erase_transfer_storage
from .bp005_standard_user_create_contract import (
    Bp005StandardUserCreatedReadback,
    Bp005StandardUserCreateError,
    verify_bp005_standard_user_created_detail,
)
from .bp005_standard_user_preflight import (
    Bp005StandardUserPreflight,
    FortiPamBp005StandardUserPreflightReader,
)
from .local_user_create_ssh_transport import LocalUserCreateInspection, LocalUserCreateReadback
from .local_user_reset_fixture_create import (
    _FIELDS,
    verify_bp005_standard_user_create_response,
)
from .local_user_reset_http_transport import _NAME
from .secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
    _ssl_context,
    _zeroize_mutable,
)

_CREATE = "/api/v2/cmdb/system/admin?sponsor-group=&with_meta=true"
_MAX_BYTES = 1_048_576
_UNAVAILABLE = "The BP005 Standard User create transport is unavailable."
_MATERIAL_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


class Bp005StandardUserTransportError(RuntimeError):
    """Stable, non-disclosing create/readback transport failure."""


class FortiPamBp005StandardUserTransport:
    """Fixed Standard User POST/GET pair; no CLI, route, or body selector."""

    requires_durable_execution = True
    workflow_contract_id = "bp005_standard_user_create_v1"

    def __init__(
        self,
        config: SecretMetadataHttpTransportConfig,
        *,
        username: str,
        api_principal: str,
        material_directory: Path,
        enabled: bool = False,
        connection_factory: Callable[..., Any] = http.client.HTTPSConnection,
    ) -> None:
        try:
            if type(enabled) is not bool or not callable(connection_factory):
                raise ValueError
            self._preflight = FortiPamBp005StandardUserPreflightReader(
                config,
                username=username,
                api_principal=api_principal,
                connection_factory=connection_factory,
            )
            self._username = username
            self._detail = "/api/v2/cmdb/system/admin/" + quote(username, safe="") + "?" + urlencode({
                "format": "|".join(sorted(_FIELDS | {"webauthn"})),
                "with_meta": "true",
            })
            self._directory = Path(material_directory)
            self._directory_identity = self._check_directory()
            self._host, self._port = self._preflight._host, self._preflight._port
            self._config = config
            self._context = _ssl_context(config)
        except Exception:
            raise Bp005StandardUserTransportError(_UNAVAILABLE) from None
        self._enabled = enabled
        self._factory = connection_factory
        self._expected: Bp005StandardUserPreflight | None = None
        self._created: Bp005StandardUserCreatedReadback | None = None
        self._attempted = False
        self._post_attempted = False
        self._lock = threading.Lock()

    def _check_directory(self) -> tuple[int, int]:
        details = self._directory.lstat()
        if (
            not self._directory.is_absolute()
            or self._directory.is_symlink()
            or not stat.S_ISDIR(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o700
            or details.st_uid != os.getuid()
        ):
            raise ValueError
        return details.st_dev, details.st_ino

    def inspect(self, username: str) -> LocalUserCreateInspection:
        try:
            if username != self._username:
                raise ValueError
            current = self._preflight.read_preflight()
            if self._expected is None:
                self._expected = current
            return LocalUserCreateInspection(False, state_digest=current.state_digest)
        except Exception:
            raise Bp005StandardUserTransportError(_UNAVAILABLE) from None

    def create_and_readback(self, username: str) -> LocalUserCreateReadback:
        """Reject the legacy non-durable workflow entry unconditionally."""
        raise Bp005StandardUserTransportError(_UNAVAILABLE)

    def _create_with_dispatch_guard(
        self, username: str, guard: Callable[[], None],
    ) -> LocalUserCreateReadback:
        """Use the existing workflow's consumed M4 claim at final dispatch."""
        if not self._lock.acquire(blocking=False):
            raise Bp005StandardUserTransportError(_UNAVAILABLE)
        material = body = None
        try:
            if (
                not self._enabled
                or self._attempted
                or username != self._username
                or self._expected is None
                or not callable(guard)
            ):
                raise ValueError
            guard()
            current = self._preflight.read_preflight()
            if not hmac.compare_digest(current.state_digest, self._expected.state_digest):
                raise ValueError
            guard()
            self._attempted = True

            material = bytearray(b"Aa7!")
            material.extend(
                _MATERIAL_ALPHABET[secrets.randbelow(len(_MATERIAL_ALPHABET))]
                for _ in range(28)
            )
            self._write_once("initial-password", material)
            with memoryview(material) as view:
                body = current.draft._encode(view)

            acknowledgement_verified = False
            try:
                acknowledgement = self._exchange("POST", body=body, guard=guard)
                verify_bp005_standard_user_create_response(
                    acknowledgement,
                    expected_name=self._username,
                    expected_vdom=current.draft._response_vdom,
                )
                acknowledgement_verified = True
            except Exception:
                # Always reconcile after one POST, including timeout or an
                # unrecognized envelope. This branch never redispatches.
                pass
            finally:
                _zeroize_mutable(body)
                body = None
                _zeroize_mutable(material)
                material = None

            detail = self._exchange("GET")
            observed = verify_bp005_standard_user_created_detail(detail, current.draft)
            if not acknowledgement_verified:
                raise ValueError
            evidence = bytearray(json.dumps({
                "contract": "bp005-standard-user-created/v1",
                "username": self._username,
                "user_id": observed.user_id,
                "preflight_digest": current.state_digest,
                "request_digest": observed.request_digest,
                "readback_digest": observed.readback_digest,
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii"))
            try:
                self._write_once("created-readback.json", evidence)
            finally:
                _zeroize_mutable(evidence)
            self._created = observed
            return LocalUserCreateReadback(
                True,
                True,
                False,
                evidence_digest=observed.readback_digest,
                status_enabled=True,
            )
        except Exception:
            raise Bp005StandardUserTransportError(_UNAVAILABLE) from None
        finally:
            for value in (body, material):
                if value is not None:
                    _zeroize_mutable(value)
            self._lock.release()

    def _write_once(self, name: str, content: bytearray) -> None:
        if name not in {"initial-password", "created-readback.json"} or self._check_directory() != self._directory_identity:
            raise ValueError
        directory = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptor = None
        try:
            details = os.fstat(directory)
            if (
                (details.st_dev, details.st_ino) != self._directory_identity
                or stat.S_IMODE(details.st_mode) != 0o700
                or details.st_uid != os.getuid()
            ):
                raise ValueError
            descriptor = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=directory,
            )
            os.fchmod(descriptor, 0o600)
            total = 0
            while total < len(content):
                with memoryview(content)[total:] as view:
                    count = os.write(descriptor, view)
                if count <= 0:
                    raise ValueError
                total += count
            os.fsync(descriptor)
            os.fsync(directory)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(directory)

    def _exchange(
        self, method: str, *, body: bytearray | None = None,
        guard: Callable[[], None] | None = None,
    ) -> bytearray:
        content = bytearray()
        try:
            content = bytearray(_MAX_BYTES + 1)
            response = connection = None
            transfer = False
            try:
                if method == "POST" and body is not None and guard is not None:
                    path = _CREATE
                elif method == "GET" and body is None and guard is None:
                    path = self._detail
                else:
                    raise ValueError
                connection = self._factory(
                    self._host,
                    self._port,
                    timeout=self._config.timeout_seconds,
                    context=self._context,
                )
                headers = {
                    "Authorization": "Bearer " + self._config.bearer_token,
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "Cache-Control": "no-cache, no-store",
                    "User-Agent": "fortipam-bp005-standard-user-create/1",
                }
                if body is not None:
                    if guard is None:
                        raise ValueError
                    headers["Content-Type"] = "application/json"
                    guard()
                    if self._check_directory() != self._directory_identity or not self._enabled:
                        raise ValueError
                    self._post_attempted = True
                    with memoryview(body) as view:
                        connection.request(method, path, body=view, headers=headers)
                else:
                    connection.request(method, path, headers=headers)
                response = connection.getresponse()
                if (
                    type(response.status) is not int
                    or response.status != 200
                    or response.getheader("content-type", "").split(";", 1)[0].strip().lower() != "application/json"
                    or response.getheader("content-encoding", "identity").strip().lower() != "identity"
                ):
                    raise ValueError
                total = 0
                while total < len(content):
                    with memoryview(content)[total:] as view:
                        count = response.readinto(view)
                    if type(count) is not int or not 0 <= count <= len(content) - total:
                        raise ValueError
                    if count == 0:
                        break
                    total += count
                if total > _MAX_BYTES:
                    raise ValueError
                content = _take_mutable_prefix(content, total)
                transfer = True
                return content
            except Exception:
                raise Bp005StandardUserTransportError(_UNAVAILABLE) from None
            finally:
                if not transfer:
                    _zeroize_mutable(content)
                for resource in (response, connection):
                    if resource is not None:
                        try:
                            resource.close()
                        except Exception:
                            pass
        except BaseException:
            _erase_transfer_storage(content)
            raise


__all__ = ["Bp005StandardUserTransportError", "FortiPamBp005StandardUserTransport"]
