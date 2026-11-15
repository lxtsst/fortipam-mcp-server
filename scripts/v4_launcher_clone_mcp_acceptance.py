"""One shared SDK session for the existing fixed RDP clone and owned cleanup."""
import json
import os
import re
import time
from pathlib import Path
from typing import Any

from fortipam_mcp.launcher_clone_live_workflow import CONTRACT
from scripts.v4_ldap_server_mcp_oauth_acceptance import _body, _new_dispatch_path


def _reference(value: object, prefix: str) -> None:
    if type(value) is not str or re.fullmatch(re.escape(prefix) + r'[A-Za-z0-9_-]{32}', value) is None:
        raise ValueError('Fixed Launcher reference is unavailable.')


def _fresh(expires: object) -> None:
    now = time.time()
    if type(expires) is not int or not now < expires <= now + 600:
        raise ValueError('Fixed Launcher preview expired.')


def _reserve(path: Path, recovery: bool) -> None:
    _new_dispatch_path(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(path.name, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'w') as stream:
            json.dump({'contract': CONTRACT, 'recovery': recovery, 'dispatch_reserved': True, 'retry_allowed': False}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


async def run_launcher_clone_mcp_acceptance(session: Any, dispatch_directory: Path) -> dict[str, object]:
    markers = {False: dispatch_directory / 'clone.dispatch.json', True: dispatch_directory / 'recover.dispatch.json'}
    for path in markers.values():
        _new_dispatch_path(path)
    await session.initialize()
    names = {tool.name for tool in (await session.list_tools()).tools}
    required = {verb + '_v4_launcher_clone' + ('_recovery' if recovery else '') + '_700'
                for recovery in markers for verb in ('preview', 'confirm', 'execute_confirmed')}
    if not required <= names:
        raise ValueError('Fixed Launcher tools are unavailable.')
    for recovery in (False, True):
        suffix = '_v4_launcher_clone' + ('_recovery' if recovery else '') + '_700'
        preview = _body(await session.call_tool('preview' + suffix, {}))
        _reference(preview.get('preview_ref'), 'launcher-clone-preview-')
        _fresh(preview.get('expires_at'))
        if preview != {'contract': CONTRACT, 'preview_ref': preview['preview_ref'], 'expires_at': preview['expires_at'],
            'Current State': {'source_preserved': True, 'destination_present': recovery, 'zero_references': True,
                              'verified_creation_required': recovery},
            'Proposed Changes': {'operation': 'remove_owned_clone' if recovery else 'clone_fixed_rdp_launcher',
                                 'source_changes': False, 'associations_or_launches': False},
            'Expected State': {'source_preserved': True, 'destination_present': not recovery,
                               'full_configuration_preserved': True, 'unrelated_launcher_metadata_preserved': True},
            'device_write_executed': False}:
            raise ValueError('Fixed Launcher preview is unavailable.')
        auth = _body(await session.call_tool('confirm' + suffix, {'preview_ref': preview['preview_ref']}))
        _reference(auth.get('authorization_ref'), 'launcher-clone-authorized-')
        if auth != {'contract': CONTRACT, 'authorization_ref': auth['authorization_ref'], 'confirmation': 'recorded',
                    'execution': 'authorized_once', 'device_write_executed': False}:
            raise ValueError('Fixed Launcher authorization is unavailable.')
        _fresh(preview['expires_at'])
        _reserve(markers[recovery], recovery)
        result = _body(await session.call_tool('execute_confirmed' + suffix, {'authorization_ref': auth['authorization_ref']}))
        if result != {'contract': CONTRACT, 'outcome': 'succeeded', 'verification': 'verified', 'intent_consumed': True,
                      'recovery': recovery, 'raw_response_returned': False, 'parameter_values_returned': False}:
            raise ValueError('Fixed Launcher result needs reconciliation; retry is forbidden.')
    return {'completed': True, 'clone_verified': True, 'owned_cleanup_verified': True,
            'source_and_collection_preserved': True, 'mcp_dispatches': 2, 'retry_allowed': False}
