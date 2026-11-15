"""One confirmation-gated FortiPAM Web VNC Template port update."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time
from typing import Protocol

from .template_ssh_transport import (
    TEMPLATE_DEFAULT_PORT,
    TEMPLATE_UPDATED_PORT,
    TEMPLATE_UPDATE_CONFIGURATION,
    TemplateUpdateBaselineReadback,
    TemplateUpdateReadback,
)


WORKFLOW_CONTRACT = "fortipam_v4_template_web_vnc_port_update_cli_workflow_v1"
WORKFLOW_UNAVAILABLE = "FortiPAM V4 Template update action is unavailable."
_TTL_SECONDS = 600
_NAME = re.compile(r"mcp-v4-template-[A-Za-z0-9][A-Za-z0-9._-]{0,46}\Z")


class TemplateUpdateLiveWorkflowError(RuntimeError):
    """Stable, non-disclosing failure for the bounded Template update."""


class TemplateUpdateLiveWorkflowTransport(Protocol):
    """Exact Template baseline inspection and Web VNC port update contract."""

    def update_baseline_readback(
        self,
        template_name: str,
    ) -> TemplateUpdateBaselineReadback | TemplateUpdateReadback: ...

    def update_web_vnc_port_and_readback(
        self,
        template_name: str,
    ) -> TemplateUpdateReadback | TemplateUpdateBaselineReadback: ...


@dataclass(frozen=True, slots=True)
class _TemplateUpdateRecord:
    preview_ref: str
    authorization_ref: str | None
    requester_digest: str
    template_name: str
    current_digest: str
    configuration_digest: str
    state: str
    expires_at: int


class TemplateWebVncPortUpdateLiveWorkflow:
    """One-confirmation update of one known Web VNC Template create baseline."""

    def __init__(
        self,
        transport: TemplateUpdateLiveWorkflowTransport,
        *,
        clock: Callable[[], int] | None = None,
        claim_path: Path | None = None,
        write_transport: str = "ssh_cli_fallback",
        restore_default_port: bool = False,
    ) -> None:
        if (write_transport not in {"ssh_cli_fallback", "rest_api"}
                or type(restore_default_port) is not bool
                or (restore_default_port and write_transport != "rest_api")):
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._transport = transport
        self._write_transport = write_transport
        self._restore_default_port = restore_default_port
        self._clock = clock or _now
        self._claim_path = claim_path
        if claim_path is not None:
            self._check_claim_parent()
        self._records: dict[str, _TemplateUpdateRecord] = {}
        self._authorization_index: dict[str, str] = {}
        self._lock = threading.RLock()

    def preview(self, *, template_name: str, requester_digest: str) -> dict[str, object]:
        """Read the exact create baseline and render C/P/E without a device write."""

        safe_name = _template_name(template_name)
        _require_requester(requester_digest)
        self._require_unconsumed()
        current = self._baseline_readback(safe_name)
        if not current.verified:
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        record = _TemplateUpdateRecord(
            preview_ref="template-update-preview-" + secrets.token_urlsafe(24),
            authorization_ref=None,
            requester_digest=requester_digest,
            template_name=safe_name,
            current_digest=_readback_digest(current),
            configuration_digest=current.configuration_digest,
            state="previewed",
            expires_at=self._clock() + _TTL_SECONDS,
        )
        with self._lock:
            self._purge_expired_locked()
            self._records[record.preview_ref] = record
        return self._preview_projection(record, current)

    def confirm(self, preview_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Confirm the exact baseline remains unchanged and issue one execution ref."""

        with self._lock:
            record = self._record_for_preview_locked(preview_ref)
            self._validate_record(record, requester_digest, "previewed")
            self._require_unconsumed()
            current = self._baseline_readback(record.template_name)
            if not current.verified or _readback_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            authorization_ref = "template-update-authorized-" + secrets.token_urlsafe(24)
            updated = replace(
                record,
                authorization_ref=authorization_ref,
                state="authorized",
            )
            self._records[record.preview_ref] = updated
            self._authorization_index[authorization_ref] = record.preview_ref
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": updated.preview_ref,
            "authorization_ref": authorization_ref,
            "confirmation": "recorded",
            "execution": "authorized_once",
            "expires_at": updated.expires_at,
            "device_write_executed": False,
        }

    def execute(self, authorization_ref: str, *, requester_digest: str) -> dict[str, object]:
        """Change only the confirmed Web VNC port and return categorical readback."""

        with self._lock:
            record = self._record_for_authorization_locked(authorization_ref)
            if record.state == "completed":
                self._validate_requester(record, requester_digest)
                return self._result(record, idempotent_replay=True)
            self._validate_record(record, requester_digest, "authorized")
            self._require_unconsumed(require_path=True)
            current = self._baseline_readback(record.template_name)
            if not current.verified or _readback_digest(current) != record.current_digest:
                self._records[record.preview_ref] = replace(record, state="invalidated")
                raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            self._reserve_claim(record)
            self._records[record.preview_ref] = replace(record, state="executing")
        try:
            readback = self._transport.update_web_vnc_port_and_readback(record.template_name)
        except Exception:
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        expected_type = TemplateUpdateBaselineReadback if self._restore_default_port else TemplateUpdateReadback
        if not isinstance(readback, expected_type):
            with self._lock:
                self._set_state_locked(record.preview_ref, "reconciliation_required")
            return self._result(record, idempotent_replay=False)
        with self._lock:
            self._set_state_locked(
                record.preview_ref,
                "completed" if readback.verified and hmac.compare_digest(
                    readback.configuration_digest, record.configuration_digest,
                ) else "reconciliation_required",
            )
        return self._result(record, idempotent_replay=False)

    def _check_claim_parent(self) -> None:
        try:
            path = self._claim_path
            if not isinstance(path, Path) or not path.is_absolute():
                raise ValueError
            info = path.parent.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
        except Exception:
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE) from None

    def _require_unconsumed(self, *, require_path: bool = False) -> None:
        if self._claim_path is None:
            if require_path:
                raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
            return
        self._check_claim_parent()
        if os.path.lexists(self._claim_path):
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _reserve_claim(self, record: _TemplateUpdateRecord) -> None:
        self._require_unconsumed(require_path=True)
        path = self._claim_path
        assert path is not None
        try:
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                info = os.fstat(parent)
                if (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                    raise ValueError
                descriptor = os.open(
                    path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600, dir_fd=parent,
                )
                with os.fdopen(descriptor, "w") as stream:
                    json.dump({
                        "contract": "fortipam_v4_template_update_intent_claim_v1",
                        "state": "execution_reserved",
                        "requester_digest": record.requester_digest,
                        "current_digest": record.current_digest,
                        "configuration_digest": record.configuration_digest,
                        "resource_binding_digest": hashlib.sha256(record.template_name.encode()).hexdigest(),
                        "authorization_digest": hashlib.sha256(str(record.authorization_ref).encode()).hexdigest(),
                        "direction": "restore_default_port" if self._restore_default_port else "update_port",
                    }, stream, sort_keys=True)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.fsync(parent)
            finally:
                os.close(parent)
        except Exception:
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE) from None

    def _baseline_readback(self, template_name: str) -> TemplateUpdateBaselineReadback | TemplateUpdateReadback:
        try:
            result = self._transport.update_baseline_readback(template_name)
        except Exception as exc:
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE) from exc
        expected_type = TemplateUpdateReadback if self._restore_default_port else TemplateUpdateBaselineReadback
        if not isinstance(result, expected_type):
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return result

    def _record_for_preview_locked(self, preview_ref: str) -> _TemplateUpdateRecord:
        if not _valid_ref(preview_ref, "template-update-preview-"):
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        record = self._records.get(preview_ref)
        if record is None:
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _record_for_authorization_locked(
        self,
        authorization_ref: str,
    ) -> _TemplateUpdateRecord:
        if not _valid_ref(authorization_ref, "template-update-authorized-"):
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._purge_expired_locked()
        preview_ref = self._authorization_index.get(authorization_ref)
        record = self._records.get(preview_ref) if preview_ref else None
        if record is None or record.authorization_ref != authorization_ref:
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        return record

    def _validate_record(
        self,
        record: _TemplateUpdateRecord,
        requester_digest: str,
        expected_state: str,
    ) -> None:
        self._validate_requester(record, requester_digest)
        if record.state != expected_state or self._clock() >= record.expires_at:
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    @staticmethod
    def _validate_requester(
        record: _TemplateUpdateRecord,
        requester_digest: str,
    ) -> None:
        _require_requester(requester_digest)
        if not hmac.compare_digest(record.requester_digest, requester_digest):
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)

    def _set_state_locked(self, preview_ref: str, state: str) -> None:
        record = self._records.get(preview_ref)
        if record is None:
            raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
        self._records[preview_ref] = replace(record, state=state)

    def _purge_expired_locked(self) -> None:
        now_epoch = self._clock()
        expired = [
            ref
            for ref, record in self._records.items()
            if record.expires_at <= now_epoch and record.state != "completed"
        ]
        for preview_ref in expired:
            record = self._records.pop(preview_ref)
            if record.authorization_ref is not None:
                self._authorization_index.pop(record.authorization_ref, None)

    def _preview_projection(
        self,
        record: _TemplateUpdateRecord,
        current: TemplateUpdateBaselineReadback | TemplateUpdateReadback,
    ) -> dict[str, object]:
        source_port = TEMPLATE_UPDATED_PORT if self._restore_default_port else TEMPLATE_DEFAULT_PORT
        destination_port = TEMPLATE_DEFAULT_PORT if self._restore_default_port else TEMPLATE_UPDATED_PORT
        return {
            "contract": WORKFLOW_CONTRACT,
            "preview_ref": record.preview_ref,
            "expires_at": record.expires_at,
            "Current State": {
                "requested_template_name": record.template_name,
                "template_name_exists": current.template_name_exists,
                ("known_web_vnc_updated_baseline_verified" if self._restore_default_port
                 else "known_web_vnc_create_baseline_verified"): current.verified,
                "web_vnc_launcher_port": source_port,
                "write_transport": self._write_transport,
            },
            "Proposed Changes": {
                "operation": (
                    "restore_web_vnc_template_default_port_via_rest_api" if self._restore_default_port else
                    "update_web_vnc_template_launcher_port_via_rest_api"
                    if self._write_transport == "rest_api"
                    else "update_web_vnc_template_launcher_port_via_cli_fallback"
                ),
                "template_name": record.template_name,
                "configuration_profile": ("web-vnc-launcher-port-5901-to-5900-v1" if self._restore_default_port
                                          else TEMPLATE_UPDATE_CONFIGURATION),
                "web_vnc_launcher_port": {
                    "from": source_port,
                    "to": destination_port,
                },
                "template_field_or_access_changes": False,
                "secret_or_target_association_changes": False,
                "session_or_target_changes": False,
                "rest_write_attempted": False,
            },
            "Expected State": {
                "template_name_matches": True,
                "template_name_exists": True,
                "web_vnc_create_baseline_preserved": True,
                "web_vnc_launcher_port": destination_port,
                "template_field_or_access_changes": False,
                "secret_or_target_association_changes": False,
                "session_or_target_changes": False,
                "readback_transport": "ssh_cli_fallback",
            },
            "device_write_executed": False,
        }

    def _result(
        self,
        record: _TemplateUpdateRecord,
        *,
        idempotent_replay: bool,
    ) -> dict[str, object]:
        with self._lock:
            latest = self._records.get(record.preview_ref)
        succeeded = latest is not None and latest.state == "completed"
        return {
            "contract": "fortipam_v4_template_web_vnc_port_update_cli_execution_v1",
            "outcome": "succeeded" if succeeded else "reconciliation_required",
            "verification": "verified" if succeeded else "unknown",
            "idempotent_replay": idempotent_replay,
            "compensation": ("default_port_restored" if self._restore_default_port and succeeded
                             else "separate_template_web_vnc_port_restore_action_required"),
            "template_name_returned": False,
            "template_field_or_access_changes": False,
            "secret_or_target_association_changes": False,
            "session_or_target_changes": False,
            "device_write_executed": True,
            "write_transport": self._write_transport,
        }


def _template_name(value: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)
    return value


def _require_requester(value: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise TemplateUpdateLiveWorkflowError(WORKFLOW_UNAVAILABLE)


def _valid_ref(value: str, prefix: str) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and 24 <= len(value) <= 160
        and re.fullmatch(r"[A-Za-z0-9_-]+", value[len(prefix) :]) is not None
    )


def _readback_digest(readback: TemplateUpdateBaselineReadback | TemplateUpdateReadback) -> str:
    encoded = json.dumps(
        {
            "template_name_exists": readback.template_name_exists,
            "access_everyone": readback.access_everyone,
            "username_field_present": readback.username_field_present,
            "username_field_mandatory": readback.username_field_mandatory,
            "password_field_present": readback.password_field_present,
            "password_field_mandatory": readback.password_field_mandatory,
            "web_vnc_launcher_present": readback.web_vnc_launcher_present,
            "web_vnc_port_is_default": (readback.web_vnc_port_is_default
                                        if isinstance(readback, TemplateUpdateBaselineReadback) else False),
            "web_vnc_port_is_updated": (readback.web_vnc_port_is_updated
                                        if isinstance(readback, TemplateUpdateReadback) else False),
            "configuration_digest": readback.configuration_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _now() -> int:
    return int(time.time())


__all__ = [
    "TemplateUpdateLiveWorkflowError",
    "TemplateUpdateLiveWorkflowTransport",
    "TemplateWebVncPortUpdateLiveWorkflow",
]
