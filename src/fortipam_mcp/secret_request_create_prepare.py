"""Write one protected Request Create intent without preparing a policy Scheme."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import time

from .secret_request_create_contract import SecretRequestCreateInput
from .secret_request_create_http_transport import (
    REQUEST_CREATE_INTENT_CONTRACT,
    REQUEST_CREATE_INTENT_VERSION,
    SecretRequestCreateBinding,
)


class SecretRequestCreatePrepareError(RuntimeError):
    """Stable non-disclosing error for protected intent preparation."""


def prepare_secret_request_create_intent(
    path: Path,
    *,
    binding: SecretRequestCreateBinding,
    request: SecretRequestCreateInput,
) -> None:
    """Write the exact owner-only binding accepted by the existing resolver."""

    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or not isinstance(binding, SecretRequestCreateBinding)
        or not isinstance(request, SecretRequestCreateInput)
        or request.requester != binding.fortipam_requester
        or binding.expires_at <= int(time.time())
    ):
        raise SecretRequestCreatePrepareError("Request intent preparation is unavailable.")
    try:
        parent = path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or stat.S_ISLNK(parent.st_mode)
            or parent.st_uid != os.getuid()
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise OSError
        payload = {
            "contract": REQUEST_CREATE_INTENT_CONTRACT,
            "version": REQUEST_CREATE_INTENT_VERSION,
            "intent_ref": binding.intent_ref,
            "fortipam_requester": binding.fortipam_requester,
            "requester_digest": binding.requester_digest,
            "environment_ref": binding.environment_ref,
            "scope_ref": binding.scope_ref,
            "expires_at": binding.expires_at,
            "submission_mode": binding.submission_mode,
            "secret_id": request.secret_id,
            "request_type": request.request_type,
            "start_after_approve": request.start_after_approve,
            "start_time": request.start_time,
            "expiration_time": request.expiration_time,
            "duration": request.duration,
            "comments": request.comments,
            "timezone": request.timezone,
            "job_name": request.job_name,
            "custom_fields": [
                {"name": field.name, "value": field.value, "required": field.required}
                for field in request.custom_fields
            ],
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(encoded)
                stream.write(b"\n")
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise
    except (OSError, TypeError, ValueError) as exc:
        raise SecretRequestCreatePrepareError(
            "Request intent preparation is unavailable."
        ) from exc


__all__ = ["SecretRequestCreatePrepareError", "prepare_secret_request_create_intent"]
