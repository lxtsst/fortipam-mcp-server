"""Fixed build29 native encrypted global-file export to private local custody."""
from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
import hashlib
from pathlib import Path
import re
import time
from typing import Any
from urllib.parse import urlencode

from v4_planning import M4ExecutionAuthorization, M4ExecutionPlan
from v4_planning.execution_kernel import _require_m4_dispatch_ownership, _reserve_m4_material_acquisition
from v4_planning.material_provider import MaterialLeaseCompletion, MaterialRevocationReason
from .backup_artifact_custody import BackupArtifactCustody, BackupCustodyBinding, BackupLeaseRequest, MAX_BACKUP_BYTES
from .crl_import_transport import _frame, digest
from .local_user_reset_fixture_preflight import _actor_context
from .m4_execution_store import PersistentM4ExecutionStateStore
from .owner_session_metadata import OwnerSessionMetadataTransport
from .target_api_dependency_reader import _private_http_logs

CONTRACT = "fortipam-build29-native-encrypted-backup-v1"
EXPORT = "/api/v2/monitor/system/config/backup"
_ERROR = "The fixed encrypted backup export is unavailable."


class BackupExportTransport:
    def __init__(self, *, owner_factory: Callable[[], OwnerSessionMetadataTransport], owner_name: str,
                 serial: str, nonce: str, custody_directory: Path, retain_until: int,
                 audience_digest: str, clock: Callable[[], int] = lambda: int(time.time())) -> None:
        if (not callable(owner_factory) or not callable(clock)
                or any(type(v) is not str or not v for v in (owner_name, serial))
                or type(nonce) is not str or re.fullmatch(r"[a-f0-9]{16}", nonce) is None):
            raise ValueError(_ERROR)
        self._factory, self._owner, self._serial, self._clock = owner_factory, owner_name, serial, clock
        self._scope = digest({"contract": CONTRACT, "serial": serial, "scope": "global",
            "owner": hashlib.sha256(owner_name.encode()).hexdigest()})
        self._binding = BackupCustodyBinding(custody_directory, scope_digest=self._scope,
            audience_digest=audience_digest, retain_until=retain_until)
        self.parameters_digest = digest({"contract": CONTRACT, "scope": self._scope, "nonce": nonce,
            "directory": str(custody_directory), "inode": self._binding._inode,
            "retain_until": retain_until, "audience": audience_digest})
        self._initial = digest({"binding": self.parameters_digest, "artifact": "absent"})
        self._expected = digest({"binding": self.parameters_digest, "artifact": "retained_verified"})
        self._attempted = False
        self._export_requested = False
        self._custody: BackupArtifactCustody | None = None

    @contextmanager
    def _session(self) -> Iterator[Any]:
        owner = self._factory()
        raw = bytearray()
        try:
            with _private_http_logs(), owner.authenticated():
                with owner._client.stream("GET", "/api/v2/monitor/web-ui/state",
                        headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache, no-store"}) as response:
                    if response.status_code != 200:
                        raise ValueError
                    for chunk in response.iter_bytes():
                        if len(raw) + len(chunk) > 1048576:
                            raise ValueError
                        raw.extend(chunk)
                frame = _frame(raw, self._serial, method="GET", path="web-ui", name="state")
                _actor_context(raw, expected_name=self._owner)
                if frame["results"]["admin"].get("global_admin") is not True:
                    raise ValueError
                frame.clear()
                raw[:] = bytes(len(raw))
                yield owner._client
            if not owner.logout_verified:
                raise ValueError
        except Exception:
            raise ValueError(_ERROR) from None
        finally:
            raw[:] = bytes(len(raw))

    def inspect(self, phase: str) -> tuple[str, str]:
        if phase != "create" or self._attempted or self._binding._retain_until < self._clock() + 2 * 86400:
            raise ValueError(_ERROR)
        self._binding._empty()
        with self._session():
            pass
        return self._initial, self._expected

    def dispatch(self, phase: str, *, current_digest: str, plan: M4ExecutionPlan,
                 authorization: M4ExecutionAuthorization, store: PersistentM4ExecutionStateStore,
                 guard: Callable[[], None]) -> None:
        if (phase != "create" or self._attempted or plan.action_id != "backup-export-native-create"
                or plan.adapter_ref != CONTRACT or plan.parameters_digest != self.parameters_digest
                or current_digest != self._initial or plan.expected_current_digest != current_digest):
            raise ValueError(_ERROR)
        def final_guard() -> None:
            guard()
            _require_m4_dispatch_ownership(plan, authorization, store)
        final_guard()
        self._binding._empty()
        with self._session() as client:
            final_guard()
            self._attempted = True
            request = BackupLeaseRequest(plan.plan_digest, plan.approval_digest, authorization.authorization_digest,
                self._scope, self._binding._audience, self._clock(), plan.expires_at)
            custody = BackupArtifactCustody(self._binding, request, guard=guard, dispatch_guard=final_guard, clock=self._clock)
            self._custody = custody
            _reserve_m4_material_acquisition(plan, authorization, store)
            lease = custody.acquire_lease(self._binding, request)
            released = False
            try:
                def download(password: memoryview) -> Iterator[bytes]:
                    # Native controller semantics; the query never crosses a logging/MCP boundary.
                    params = {"destination": "file", "scope": "global", "password": bytes(password).decode("ascii"),
                        "confirmPassword": bytes(password).decode("ascii")}
                    path = EXPORT + "?" + urlencode(params)
                    params.clear()
                    final_guard()
                    count = 0
                    self._export_requested = True
                    with client.stream("GET", path, headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache, no-store"}) as response:
                        path = ""
                        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                        if (response.status_code != 200 or response.headers.get("content-encoding", "identity") != "identity"
                                or response.headers.get("content-disposition", "").split(";", 1)[0].strip().lower() != "attachment"
                                or not content_type or content_type in {"text/html", "application/json"}):
                            raise ValueError(_ERROR)
                        expected = response.headers.get("content-length")
                        if expected is not None and (not expected.isdecimal() or not 64 <= int(expected) <= MAX_BACKUP_BYTES):
                            raise ValueError(_ERROR)
                        for chunk in response.iter_bytes():
                            final_guard()
                            count += len(chunk)
                            if count > MAX_BACKUP_BYTES:
                                raise ValueError(_ERROR)
                            yield chunk
                        if count < 64 or expected is not None and count != int(expected):
                            raise ValueError(_ERROR)
                custody._consume(lease, download)
                if custody.release_lease(lease) is not MaterialLeaseCompletion.RELEASED:
                    raise ValueError(_ERROR)
                released = True
            finally:
                if not released:
                    custody.revoke_lease(lease, reason=MaterialRevocationReason.RECONCILIATION_REQUIRED)

    def postcondition(self, phase: str) -> str:
        if phase != "create" or not self._attempted or self._custody is None:
            raise ValueError(_ERROR)
        with self._session():
            pass
        self._custody.verify_retained()
        return self._expected
