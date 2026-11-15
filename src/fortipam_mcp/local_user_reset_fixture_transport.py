"""Private build-29 fixture transport for the existing authenticated create flow.

No MCP registration or alternate authorization issuer. The existing create
workflow must consume its real intent record in the persistent M4 store before
calling the guarded entry. Generated initial material and readback evidence stay
in one pre-existing owner-only directory, never in the public workflow result.
An uncertain dispatch is retained and is never automatically repeated/deleted.
"""

from __future__ import annotations

from collections.abc import Callable
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
from .local_user_create_ssh_transport import LocalUserCreateInspection, LocalUserCreateReadback
from .local_user_create_live_workflow import BP002_ENABLED_GUEST_WORKFLOW_CONTRACT
from .local_user_reset_fixture_create import (
    LocalUserResetFixtureCreatedReadback, _FIELDS, verify_fixture_created_detail, verify_fixture_create_response,
)
from .local_user_reset_fixture_preflight import (
    FortiPamLocalUserResetFixturePreflightReader, LocalUserResetFixturePreflight,
)
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _zeroize_mutable

_CREATE = "/api/v2/cmdb/system/admin?sponsor-group=&with_meta=true"
_MAX_BYTES = 1_048_576
_UNAVAILABLE = "The private Local User reset fixture transport is unavailable."


class LocalUserResetFixtureTransportError(RuntimeError):
    """No credential, identity, body, endpoint or device error detail."""


class FortiPamLocalUserResetFixtureTransport:
    requires_durable_execution = True
    workflow_contract_id = BP002_ENABLED_GUEST_WORKFLOW_CONTRACT

    def __init__(self, config: SecretMetadataHttpTransportConfig, *, username: str, api_principal: str,
                 material_directory: Path, enabled: bool = False,
                 connection_factory: Callable[..., Any] = http.client.HTTPSConnection) -> None:
        try:
            if type(enabled) is not bool:
                raise ValueError
            self._preflight = FortiPamLocalUserResetFixturePreflightReader(
                config, username=username, api_principal=api_principal, connection_factory=connection_factory,
            )
            self._directory = Path(material_directory)
            self._directory_identity = self._check_directory()
            self._detail = "/api/v2/cmdb/system/admin/" + quote(username, safe="") + "?" + urlencode({
                "format": "|".join(sorted(_FIELDS | {"webauthn"})), "with_meta": "true",
            })
        except Exception:
            raise LocalUserResetFixtureTransportError(_UNAVAILABLE) from None
        self._username, self._enabled = username, enabled
        self._expected: LocalUserResetFixturePreflight | None = None
        self._created: LocalUserResetFixtureCreatedReadback | None = None
        self._attempted = False
        self._post_attempted = False
        self._lock = threading.Lock()

    def _check_directory(self) -> tuple[int, int]:
        path = self._directory
        details = path.lstat()
        if (not path.is_absolute() or path.is_symlink() or not stat.S_ISDIR(details.st_mode)
            or stat.S_IMODE(details.st_mode) != 0o700 or details.st_uid != os.getuid()):
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
            raise LocalUserResetFixtureTransportError(_UNAVAILABLE) from None

    def create_and_readback(self, username: str) -> LocalUserCreateReadback:
        # Prevent the legacy unguarded transport entry from authorizing this
        # candidate. Only the durable existing workflow calls the private entry.
        raise LocalUserResetFixtureTransportError(_UNAVAILABLE)

    def _create_with_dispatch_guard(self, username: str, guard: Callable[[], None]) -> LocalUserCreateReadback:
        if not self._lock.acquire(blocking=False):
            raise LocalUserResetFixtureTransportError(_UNAVAILABLE)
        material = body = None
        try:
            if (not self._enabled or self._attempted or username != self._username
                or self._expected is None or not callable(guard)):
                raise ValueError
            guard()
            current = self._preflight.read_preflight()
            if not hmac.compare_digest(current.state_digest, self._expected.state_digest):
                raise ValueError
            guard()
            self._attempted = True
            # Reserve the dedicated fixture material file before any POST.
            # O_EXCL also prevents a new process/new intent from reusing an
            # unresolved fixture directory, independent of volatile state.
            material = bytearray(b"Aa7!")
            alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            material.extend(alphabet[secrets.randbelow(len(alphabet))] for _ in range(28))
            self._write_once("initial-password", material)
            with memoryview(material) as view:
                body = current.draft._encode(view)
            accepted = False
            try:
                response = self._exchange("POST", body=body, guard=guard)
                verify_fixture_create_response(response, expected_name=self._username,
                                               expected_vdom=current.draft._response_vdom)
                accepted = True
            except Exception:
                # Reconcile even after a timeout or malformed acknowledgement;
                # readback alone cannot retroactively prove who created it.
                pass
            finally:
                _zeroize_mutable(body)
                _zeroize_mutable(material)
            response = self._exchange("GET")
            observed = verify_fixture_created_detail(response, current.draft)
            if not accepted:
                raise ValueError
            evidence = bytearray(json.dumps({
                "contract": "bp002-build29-created-fixture-readback/v1", "username": observed.username,
                "user_id": observed.user_id, "preflight_digest": current.state_digest,
                "request_digest": observed.request_digest, "readback_digest": observed.readback_digest,
            }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii"))
            try:
                self._write_once("created-readback.json", evidence)
            finally:
                _zeroize_mutable(evidence)
            self._created = observed
            return LocalUserCreateReadback(True, True, False, evidence_digest=observed.readback_digest,
                                          status_enabled=True)
        except Exception:
            raise LocalUserResetFixtureTransportError(_UNAVAILABLE) from None
        finally:
            for value in (material, body):
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
            if ((details.st_dev, details.st_ino) != self._directory_identity
                or stat.S_IMODE(details.st_mode) != 0o700 or details.st_uid != os.getuid()):
                raise ValueError
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
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

    def _exchange(self, method: str, *, body: bytearray | None = None,
                  guard: Callable[[], None] | None = None) -> bytearray:
        content = bytearray()
        try:
            content = bytearray(_MAX_BYTES + 1)
            response = connection = None
            transfer = False
            try:
                if method == "POST":
                    if body is None or guard is None:
                        raise ValueError
                    path = _CREATE
                elif method == "GET" and body is None and guard is None:
                    path = self._detail
                else:
                    raise ValueError
                reader = self._preflight
                connection = reader._factory(reader._host, reader._port, timeout=reader._config.timeout_seconds,
                                             context=reader._context)
                headers = {"Authorization": "Bearer " + reader._config.bearer_token,
                           "Accept": "application/json", "Accept-Encoding": "identity", "Connection": "close",
                           "Cache-Control": "no-cache, no-store", "User-Agent": "fortipam-bp002-fixture-create/1"}
                if body is not None:
                    headers["Content-Type"] = "application/json"
                    assert guard is not None
                    guard()
                    if not self._enabled or self._check_directory() != self._directory_identity:
                        raise ValueError
                    self._post_attempted = True
                    with memoryview(body) as view:
                        connection.request(method, path, body=view, headers=headers)
                else:
                    connection.request(method, path, headers=headers)
                response = connection.getresponse()
                if (type(response.status) is not int or response.status != 200
                    or response.getheader("content-type", "").split(";", 1)[0].strip().lower() != "application/json"
                    or response.getheader("content-encoding", "identity").strip().lower() != "identity"):
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
