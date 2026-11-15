"""Private owner-only bootstrap for requester-bound V4 Scheme Draft refs."""

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
    PersistentSchemeDraftAuthority,
    scheme_draft_from_mapping,
)
from v4_planning.canonical import canonical_json
from v4_planning.models import PlanningContractError, require_ref

from .scheme_draft_checkpoint_sidecar import (
    SchemeDraftCheckpointSidecarError,
    UnixSchemeDraftCheckpointClient,
    UnixSchemeDraftCheckpointClientSettings,
)


DRAFT_BOOTSTRAP_DATABASE_ENV = "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_DATABASE"
DRAFT_BOOTSTRAP_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_HMAC_KEY_FILE"
)
DRAFT_BOOTSTRAP_AUTHORITY_REF_ENV = "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_AUTHORITY_REF"
DRAFT_BOOTSTRAP_CHECKPOINT_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_CHECKPOINT_SOCKET"
)
DRAFT_BOOTSTRAP_CHECKPOINT_AUTHORITY_REF_ENV = (
    "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_CHECKPOINT_AUTHORITY_REF"
)
DRAFT_BOOTSTRAP_CHECKPOINT_STORE_REF_ENV = (
    "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_CHECKPOINT_STORE_REF"
)
DRAFT_BOOTSTRAP_INPUT_ENV = "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_INPUT"
DRAFT_BOOTSTRAP_OUTPUT_ENV = "FORTIPAM_MCP_V4_DRAFT_BOOTSTRAP_OUTPUT"
_MAX_INPUT_BYTES = 65_536


class SchemeDraftBootstrapError(RuntimeError):
    """Stable failure for the private Scheme Draft bootstrap boundary."""


@dataclass(frozen=True, slots=True)
class SchemeDraftBootstrapSettings:
    database_path: Path
    hmac_key_path: Path
    authority_ref: str
    input_path: Path
    output_path: Path
    checkpoint_socket_path: Path | None = None
    checkpoint_authority_ref: str | None = None
    checkpoint_store_ref: str | None = None

    def __post_init__(self) -> None:
        required_paths = (
            self.database_path,
            self.hmac_key_path,
            self.input_path,
            self.output_path,
        )
        checkpoint_values = (
            self.checkpoint_socket_path,
            self.checkpoint_authority_ref,
            self.checkpoint_store_ref,
        )
        try:
            require_ref(self.authority_ref, "Scheme Draft bootstrap authority_ref")
            if all(value is not None for value in checkpoint_values):
                require_ref(
                    cast(str, self.checkpoint_authority_ref),
                    "Scheme Draft bootstrap checkpoint authority_ref",
                )
                require_ref(
                    cast(str, self.checkpoint_store_ref),
                    "Scheme Draft bootstrap checkpoint store_ref",
                )
        except PlanningContractError as exc:
            raise SchemeDraftBootstrapError(
                "Scheme Draft bootstrap configuration is invalid."
            ) from exc
        if (
            any(
                not isinstance(path, Path) or not path.is_absolute()
                for path in required_paths
            )
            or len(set(required_paths)) != len(required_paths)
            or (any(value is not None for value in checkpoint_values) and not all(
                value is not None for value in checkpoint_values
            ))
            or (
                self.checkpoint_socket_path is not None
                and (
                    not isinstance(self.checkpoint_socket_path, Path)
                    or not self.checkpoint_socket_path.is_absolute()
                    or self.checkpoint_socket_path in required_paths
                    or self.checkpoint_authority_ref == self.authority_ref
                )
            )
        ):
            raise SchemeDraftBootstrapError(
                "Scheme Draft bootstrap configuration is invalid."
            )


def bootstrap_settings_from_environment(
    environment: Mapping[str, str],
) -> SchemeDraftBootstrapSettings:
    """Load one complete value-free path/Authority configuration."""

    required_names = (
        DRAFT_BOOTSTRAP_DATABASE_ENV,
        DRAFT_BOOTSTRAP_HMAC_KEY_FILE_ENV,
        DRAFT_BOOTSTRAP_AUTHORITY_REF_ENV,
        DRAFT_BOOTSTRAP_INPUT_ENV,
        DRAFT_BOOTSTRAP_OUTPUT_ENV,
    )
    checkpoint_names = (
        DRAFT_BOOTSTRAP_CHECKPOINT_SOCKET_ENV,
        DRAFT_BOOTSTRAP_CHECKPOINT_AUTHORITY_REF_ENV,
        DRAFT_BOOTSTRAP_CHECKPOINT_STORE_REF_ENV,
    )
    values = {
        name: _value(environment, name)
        for name in (*required_names, *checkpoint_names)
    }
    if any(values[name] is None for name in required_names) or (
        any(values[name] is not None for name in checkpoint_names)
        and not all(values[name] is not None for name in checkpoint_names)
    ):
        raise SchemeDraftBootstrapError(
            "Scheme Draft bootstrap configuration is incomplete."
        )
    return SchemeDraftBootstrapSettings(
        database_path=Path(cast(str, values[DRAFT_BOOTSTRAP_DATABASE_ENV])).expanduser(),
        hmac_key_path=Path(
            cast(str, values[DRAFT_BOOTSTRAP_HMAC_KEY_FILE_ENV])
        ).expanduser(),
        authority_ref=cast(str, values[DRAFT_BOOTSTRAP_AUTHORITY_REF_ENV]),
        input_path=Path(cast(str, values[DRAFT_BOOTSTRAP_INPUT_ENV])).expanduser(),
        output_path=Path(cast(str, values[DRAFT_BOOTSTRAP_OUTPUT_ENV])).expanduser(),
        checkpoint_socket_path=(
            Path(cast(str, values[DRAFT_BOOTSTRAP_CHECKPOINT_SOCKET_ENV])).expanduser()
            if values[DRAFT_BOOTSTRAP_CHECKPOINT_SOCKET_ENV] is not None
            else None
        ),
        checkpoint_authority_ref=values[DRAFT_BOOTSTRAP_CHECKPOINT_AUTHORITY_REF_ENV],
        checkpoint_store_ref=values[DRAFT_BOOTSTRAP_CHECKPOINT_STORE_REF_ENV],
    )


def bootstrap_scheme_draft(
    settings: SchemeDraftBootstrapSettings,
    *,
    now_epoch: int | None = None,
) -> None:
    """Issue one Draft ref and place it only in a new owner-only output file."""

    if not isinstance(settings, SchemeDraftBootstrapSettings):
        raise SchemeDraftBootstrapError(
            "Scheme Draft bootstrap configuration is invalid."
        )
    now = int(time.time()) if now_epoch is None else now_epoch
    if type(now) is not int or now < 0:
        raise SchemeDraftBootstrapError("Scheme Draft bootstrap time is invalid.")
    _assert_owner_only(settings.input_path.parent, directory=True)
    _assert_owner_only(settings.input_path, directory=False)
    _assert_owner_only(settings.output_path.parent, directory=True)
    if settings.output_path.exists() or settings.output_path.is_symlink():
        raise SchemeDraftBootstrapError(
            "Scheme Draft bootstrap output is unavailable."
        )
    payload = _read_payload(settings.input_path)
    if set(payload) != {"draft", "expires_at", "requester_digest"}:
        raise SchemeDraftBootstrapError("Scheme Draft bootstrap input is invalid.")
    draft_value = payload["draft"]
    if type(draft_value) is not dict:
        raise SchemeDraftBootstrapError("Scheme Draft bootstrap input is invalid.")
    try:
        draft = scheme_draft_from_mapping(cast(dict[str, object], draft_value))
        requester_digest = cast(str, payload["requester_digest"])
        expires_at = payload["expires_at"]
        if type(expires_at) is not int:
            raise SchemeDraftBootstrapError(
                "Scheme Draft bootstrap input is invalid."
            )
        checkpoint = None
        if settings.checkpoint_socket_path is not None:
            checkpoint = UnixSchemeDraftCheckpointClient(
                UnixSchemeDraftCheckpointClientSettings(
                    settings.checkpoint_socket_path,
                    cast(str, settings.checkpoint_authority_ref),
                )
            )
            checkpoint.verify_ready()
        authority = PersistentSchemeDraftAuthority(
            settings.database_path,
            settings.hmac_key_path,
            authority_ref=settings.authority_ref,
            monotonic_checkpoint=checkpoint,
            checkpoint_store_ref=settings.checkpoint_store_ref,
            clock=lambda: now,
        )
        draft_ref = authority.issue_for_requester_digest(
            draft,
            requester_digest,
            expires_at=expires_at,
            now_epoch=now,
        )
    except (
        SchemeDraftCheckpointSidecarError,
        PlanningContractError,
        TypeError,
        ValueError,
    ):
        raise SchemeDraftBootstrapError(
            "Scheme Draft bootstrap input was rejected."
        ) from None
    _write_output(settings.output_path, draft_ref)


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
                raise SchemeDraftBootstrapError(
                    "Scheme Draft bootstrap input is unavailable."
                )
            content = os.read(descriptor, _MAX_INPUT_BYTES + 1)
        finally:
            os.close(descriptor)
        if not content or len(content) > _MAX_INPUT_BYTES:
            raise SchemeDraftBootstrapError(
                "Scheme Draft bootstrap input is unavailable."
            )
        value = json.loads(content)
    except SchemeDraftBootstrapError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise SchemeDraftBootstrapError(
            "Scheme Draft bootstrap input is unavailable."
        ) from None
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise SchemeDraftBootstrapError("Scheme Draft bootstrap input is invalid.")
    return cast(dict[str, object], value)


def _write_output(path: Path, draft_ref: str) -> None:
    content = canonical_json({"scheme_draft_ref": draft_ref}).encode("utf-8") + b"\n"
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
        raise SchemeDraftBootstrapError(
            "Scheme Draft bootstrap output is unavailable."
        ) from None


def _assert_owner_only(path: Path, *, directory: bool) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise SchemeDraftBootstrapError(
            "Scheme Draft bootstrap protected path is unavailable."
        ) from None
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        path.is_symlink()
        or not expected_type(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise SchemeDraftBootstrapError(
            "Scheme Draft bootstrap protected path must be owner-only."
        )


def _value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if type(raw) is not str:
        return None
    value = raw.strip()
    return value or None


def main() -> None:
    """Run one private issuance without printing input or the issued ref."""

    try:
        bootstrap_scheme_draft(bootstrap_settings_from_environment(os.environ))
    except SchemeDraftBootstrapError:
        print('{"status":"failed"}', file=sys.stderr)
        raise SystemExit(1) from None
    print('{"status":"issued"}')


if __name__ == "__main__":
    main()


__all__ = [
    "SchemeDraftBootstrapError",
    "SchemeDraftBootstrapSettings",
    "bootstrap_scheme_draft",
    "bootstrap_settings_from_environment",
]
