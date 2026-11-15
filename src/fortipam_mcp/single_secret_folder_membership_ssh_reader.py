"""Private fixed global membership columns; no caller command or write path."""

from __future__ import annotations

import asyncio
import hmac
import re

from .folder_archive_reference_ssh_transport import _PARENT_PROJECTION
from .folder_namespace_ssh_reader import (
    _NAME_PROJECTION as _FOLDER_NAMES, _SERIAL_COMMAND, _VERSION_COMMAND,
    _folder_names, _frame_lines, _qualified_version_metadata,
)
from .secret_namespace_ssh_reader import _FOLDER_PROJECTION, _NAME_PROJECTION as _SECRET_NAMES, _secret_names
from .single_secret_folder_membership_source import SingleSecretFolderMembershipColumns
from .target_reference_ssh_transport import FortiPamTargetReferenceSshTransport
from .target_ssh_transport import (
    TargetSshTransportConfig, _close_cli, _require_root_prompt,
    _send_and_read, _send_and_read_dynamic_prompt,
)

_UNAVAILABLE = "The fixed single-Secret Folder native columns are unavailable."


class SingleSecretFolderMembershipSshReader:
    """One pinned same-Owner SSH capture with names bracketing each numeric column.

    Full row grammar, numeric membership and two-capture stability are verified
    by the bound source. Identity is checked before any namespace is read.
    """

    def __init__(self, config: TargetSshTransportConfig, *, expected_serial: str) -> None:
        if (type(config) is not TargetSshTransportConfig or type(expected_serial) is not str
            or re.fullmatch(r"[A-Za-z0-9_-]{1,128}", expected_serial) is None):
            raise ValueError(_UNAVAILABLE)
        self._ssh, self._serial = FortiPamTargetReferenceSshTransport(config), expected_serial

    def read_columns(self) -> SingleSecretFolderMembershipColumns:
        try:
            return asyncio.run(self._read_columns())
        except Exception:
            raise ValueError(_UNAVAILABLE) from None

    async def _read_columns(self) -> SingleSecretFolderMembershipColumns:
        async with self._ssh._connection() as connection:
            process, root, deadline = await self._ssh._open_cli(connection)
            try:
                if re.fullmatch(rb"[A-Za-z0-9._-]{1,63} #", root) is None:
                    raise ValueError
                serial = await _send_and_read(process, _SERIAL_COMMAND, root, deadline)
                lines = tuple(line for line in _frame_lines(serial, _SERIAL_COMMAND, root) if line.strip(b" \t"))
                if (len(lines) != 1 or not hmac.compare_digest(
                        lines[0], b"Serial-Number: " + self._serial.encode("ascii"))):
                    raise ValueError
                version = await _send_and_read(process, _VERSION_COMMAND, root, deadline)
                lines = tuple(line for line in _frame_lines(version, _VERSION_COMMAND, root) if line.strip(b" \t"))
                if not _qualified_version_metadata(lines):
                    raise ValueError
                folder = await _send_and_read_dynamic_prompt(process, "config secret folder", root, deadline)
                if folder != root[:-2] + b" (folder) #":
                    raise ValueError
                folder_names = await _send_and_read(process, _FOLDER_NAMES, folder, deadline)
                _folder_names(folder_names, folder)
                parents = await _send_and_read(process, _PARENT_PROJECTION, folder, deadline)
                folder_names_after = await _send_and_read(process, _FOLDER_NAMES, folder, deadline)
                _folder_names(folder_names_after, folder)
                if not hmac.compare_digest(folder_names, folder_names_after):
                    raise ValueError
                returned = await _send_and_read_dynamic_prompt(process, "end", root, deadline)
                _require_root_prompt(root, returned)
                if returned != root:
                    raise ValueError
                database = await _send_and_read_dynamic_prompt(process, "config secret database", root, deadline)
                if database != root[:-2] + b" (database) #":
                    raise ValueError
                secret_names = await _send_and_read(process, _SECRET_NAMES, database, deadline)
                _secret_names(secret_names, database)
                folders = await _send_and_read(process, _FOLDER_PROJECTION, database, deadline)
                secret_names_after = await _send_and_read(process, _SECRET_NAMES, database, deadline)
                _secret_names(secret_names_after, database)
                if not hmac.compare_digest(secret_names, secret_names_after):
                    raise ValueError
                returned = await _send_and_read_dynamic_prompt(process, "end", root, deadline)
                _require_root_prompt(root, returned)
                if returned != root:
                    raise ValueError
                return SingleSecretFolderMembershipColumns(
                    root, serial, version, folder_names, parents, secret_names, folders, returned,
                )
            finally:
                await _close_cli(process)
