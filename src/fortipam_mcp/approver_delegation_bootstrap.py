"""Private owner-only bootstrap for exact V4 Approver delegations."""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
import sys
import time
from typing import Mapping, cast

from v4_planning import (
    AuthenticatedApprover,
    PersistentApproverAuthorizationAuthority,
)
from v4_planning.canonical import canonical_json
from v4_planning.models import PlanningContractError, require_ref

from .approver_checkpoint_sidecar import (
    ApproverCheckpointSidecarError,
    UnixApproverCheckpointClient,
    UnixApproverCheckpointClientSettings,
)


APPROVER_BOOTSTRAP_DATABASE_ENV = "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_DATABASE"
APPROVER_BOOTSTRAP_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_HMAC_KEY_FILE"
)
APPROVER_BOOTSTRAP_AUTHORITY_REF_ENV = (
    "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_AUTHORITY_REF"
)
APPROVER_BOOTSTRAP_CHECKPOINT_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_CHECKPOINT_SOCKET"
)
APPROVER_BOOTSTRAP_CHECKPOINT_AUTHORITY_REF_ENV = (
    "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_CHECKPOINT_AUTHORITY_REF"
)
APPROVER_BOOTSTRAP_CHECKPOINT_STORE_REF_ENV = (
    "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_CHECKPOINT_STORE_REF"
)
APPROVER_BOOTSTRAP_INPUT_ENV = "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_INPUT"
APPROVER_BOOTSTRAP_OUTPUT_ENV = "FORTIPAM_MCP_V4_APPROVER_BOOTSTRAP_OUTPUT"
_MAX_INPUT_BYTES = 65_536


class ApproverDelegationBootstrapError(RuntimeError):
    """Stable failure for the private Approver delegation bootstrap."""


@dataclass(frozen=True, slots=True)
class ApproverDelegationBootstrapSettings:
    database_path: Path
    hmac_key_path: Path
    authority_ref: str
    checkpoint_socket_path: Path
    checkpoint_authority_ref: str
    checkpoint_store_ref: str
    input_path: Path
    output_path: Path

    def __post_init__(self) -> None:
        paths = (
            self.database_path,
            self.hmac_key_path,
            self.checkpoint_socket_path,
            self.input_path,
            self.output_path,
        )
        try:
            require_ref(self.authority_ref, "Approver bootstrap authority_ref")
            require_ref(
                self.checkpoint_authority_ref,
                "Approver bootstrap checkpoint authority_ref",
            )
            require_ref(
                self.checkpoint_store_ref,
                "Approver bootstrap checkpoint store_ref",
            )
        except PlanningContractError as exc:
            raise ApproverDelegationBootstrapError(
                "Approver bootstrap configuration is invalid."
            ) from exc
        if (
            self.authority_ref == self.checkpoint_authority_ref
            or any(not isinstance(path, Path) or not path.is_absolute() for path in paths)
            or len(set(paths)) != len(paths)
        ):
            raise ApproverDelegationBootstrapError(
                "Approver bootstrap configuration is invalid."
            )


def bootstrap_settings_from_environment(
    environment: Mapping[str, str],
) -> ApproverDelegationBootstrapSettings:
    """Load one complete protected path and Authority configuration."""

    names = (
        APPROVER_BOOTSTRAP_DATABASE_ENV,
        APPROVER_BOOTSTRAP_HMAC_KEY_FILE_ENV,
        APPROVER_BOOTSTRAP_AUTHORITY_REF_ENV,
        APPROVER_BOOTSTRAP_CHECKPOINT_SOCKET_ENV,
        APPROVER_BOOTSTRAP_CHECKPOINT_AUTHORITY_REF_ENV,
        APPROVER_BOOTSTRAP_CHECKPOINT_STORE_REF_ENV,
        APPROVER_BOOTSTRAP_INPUT_ENV,
        APPROVER_BOOTSTRAP_OUTPUT_ENV,
    )
    values = {name: _value(environment, name) for name in names}
    if any(value is None for value in values.values()):
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap configuration is incomplete."
        )
    return ApproverDelegationBootstrapSettings(
        database_path=Path(
            cast(str, values[APPROVER_BOOTSTRAP_DATABASE_ENV])
        ).expanduser(),
        hmac_key_path=Path(
            cast(str, values[APPROVER_BOOTSTRAP_HMAC_KEY_FILE_ENV])
        ).expanduser(),
        authority_ref=cast(str, values[APPROVER_BOOTSTRAP_AUTHORITY_REF_ENV]),
        checkpoint_socket_path=Path(
            cast(str, values[APPROVER_BOOTSTRAP_CHECKPOINT_SOCKET_ENV])
        ).expanduser(),
        checkpoint_authority_ref=cast(
            str,
            values[APPROVER_BOOTSTRAP_CHECKPOINT_AUTHORITY_REF_ENV],
        ),
        checkpoint_store_ref=cast(
            str,
            values[APPROVER_BOOTSTRAP_CHECKPOINT_STORE_REF_ENV],
        ),
        input_path=Path(cast(str, values[APPROVER_BOOTSTRAP_INPUT_ENV])).expanduser(),
        output_path=Path(
            cast(str, values[APPROVER_BOOTSTRAP_OUTPUT_ENV])
        ).expanduser(),
    )


def bootstrap_approver_delegation(
    settings: ApproverDelegationBootstrapSettings,
    *,
    now_epoch: int | None = None,
) -> None:
    """Issue one exact delegation and write its handle only to a new file."""

    if not isinstance(settings, ApproverDelegationBootstrapSettings):
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap configuration is invalid."
        )
    now = int(time.time()) if now_epoch is None else now_epoch
    if type(now) is not int or now < 0:
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap time is invalid."
        )
    _assert_owner_only(settings.input_path.parent, directory=True)
    _assert_owner_only(settings.input_path, directory=False)
    _assert_owner_only(settings.output_path.parent, directory=True)
    if settings.output_path.exists() or settings.output_path.is_symlink():
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap output is unavailable."
        )
    payload = _read_payload(settings.input_path)
    if set(payload) != {
        "action_bindings",
        "approver",
        "environment_ref",
        "expires_at",
        "policy_version",
        "scope_ref",
    }:
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap input is invalid."
        )
    approver_value = payload["approver"]
    action_values = payload["action_bindings"]
    if (
        type(approver_value) is not dict
        or set(approver_value) != {
            "identity_authority_ref",
            "subject_namespace",
            "subject_ref",
        }
        or type(action_values) is not list
        or not 1 <= len(action_values) <= 64
    ):
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap input is invalid."
        )
    approver_mapping = cast(dict[str, object], approver_value)
    if not all(type(value) is str for value in approver_mapping.values()):
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap input is invalid."
        )
    action_bindings: list[tuple[str, str]] = []
    for value in action_values:
        if type(value) is not dict or set(value) != {"action_id", "action_version"}:
            raise ApproverDelegationBootstrapError(
                "Approver bootstrap input is invalid."
            )
        item = cast(dict[str, object], value)
        if type(item["action_id"]) is not str or type(item["action_version"]) is not str:
            raise ApproverDelegationBootstrapError(
                "Approver bootstrap input is invalid."
            )
        action_bindings.append(
            (cast(str, item["action_id"]), cast(str, item["action_version"]))
        )
    expires_at = payload["expires_at"]
    if type(expires_at) is not int:
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap input is invalid."
        )
    try:
        checkpoint = UnixApproverCheckpointClient(
            UnixApproverCheckpointClientSettings(
                settings.checkpoint_socket_path,
                settings.checkpoint_authority_ref,
            )
        )
        authority = PersistentApproverAuthorizationAuthority(
            settings.database_path,
            settings.hmac_key_path,
            authority_ref=settings.authority_ref,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=settings.checkpoint_store_ref,
            clock=lambda: now,
        )
        delegation_ref = authority.issue(
            AuthenticatedApprover(
                subject_ref=cast(str, approver_mapping["subject_ref"]),
                identity_authority_ref=cast(
                    str,
                    approver_mapping["identity_authority_ref"],
                ),
                subject_namespace=cast(
                    str,
                    approver_mapping["subject_namespace"],
                ),
            ),
            environment_ref=cast(str, payload["environment_ref"]),
            scope_ref=cast(str, payload["scope_ref"]),
            action_bindings=tuple(action_bindings),
            policy_version=cast(str, payload["policy_version"]),
            expires_at=expires_at,
            now_epoch=now,
        )
    except (ApproverCheckpointSidecarError, PlanningContractError, TypeError, ValueError):
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap input was rejected."
        ) from None
    _write_output(settings.output_path, delegation_ref)


def _read_payload(path: Path) -> dict[str, object]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or metadata.st_size > _MAX_INPUT_BYTES
            ):
                raise ApproverDelegationBootstrapError(
                    "Approver bootstrap input is unavailable."
                )
            content = os.read(descriptor, _MAX_INPUT_BYTES + 1)
        finally:
            os.close(descriptor)
        if not content or len(content) > _MAX_INPUT_BYTES:
            raise ApproverDelegationBootstrapError(
                "Approver bootstrap input is unavailable."
            )
        value = json.loads(content)
    except ApproverDelegationBootstrapError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap input is unavailable."
        ) from None
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap input is invalid."
        )
    return cast(dict[str, object], value)


def _write_output(path: Path, delegation_ref: str) -> None:
    content = canonical_json({"delegation_ref": delegation_ref}).encode("utf-8") + b"\n"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        try:
            offset = 0
            while offset < len(content):
                offset += os.write(descriptor, content[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(path, 0o600)
    except OSError:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap output is unavailable."
        ) from None


def _assert_owner_only(path: Path, *, directory: bool) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap protected path is unavailable."
        ) from None
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        path.is_symlink()
        or not expected_type(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ApproverDelegationBootstrapError(
            "Approver bootstrap protected path must be owner-only."
        )


def _value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if type(raw) is not str:
        return None
    value = raw.strip()
    return value or None


def main() -> None:
    """Run one private issuance without printing identity or delegation data."""

    try:
        bootstrap_approver_delegation(
            bootstrap_settings_from_environment(os.environ)
        )
    except ApproverDelegationBootstrapError:
        print('{"status":"failed"}', file=sys.stderr)
        raise SystemExit(1) from None
    print('{"status":"issued"}')


if __name__ == "__main__":
    main()


__all__ = [
    "ApproverDelegationBootstrapError",
    "ApproverDelegationBootstrapSettings",
    "bootstrap_approver_delegation",
    "bootstrap_settings_from_environment",
]
