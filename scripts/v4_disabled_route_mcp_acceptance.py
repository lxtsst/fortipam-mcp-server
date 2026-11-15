"""One SDK session for fixed disabled-route creation and independent recovery.

The caller owns OAuth/TLS and must revoke its token in finally. All shared
transport/auth controls use the existing acceptance helpers. This client sends
no device selector or body and never retries a consumed phase.
"""
from pathlib import Path
import json
import os
from typing import Any

from fortipam_mcp.disabled_route_contract import CONTRACT
from scripts.v4_ldap_server_mcp_oauth_acceptance import _body, _fresh, _new_dispatch_path, _reference


def _reserve(path: Path, phase: str) -> None:
    _new_dispatch_path(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(path.name, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600, dir_fd=parent)
        with os.fdopen(fd, 'w') as stream:
            json.dump({'contract': CONTRACT, 'phase': phase, 'dispatch_reserved': True, 'retry_allowed': False}, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(parent)
    finally:
        os.close(parent)


async def run_disabled_route_mcp_acceptance(session: Any, dispatch_directory: Path) -> dict[str, object]:
    markers = {phase: dispatch_directory / (phase + '.dispatch.json') for phase in ('create', 'recover')}
    for path in markers.values():
        _new_dispatch_path(path)
    await session.initialize()
    names = {tool.name for tool in (await session.list_tools()).tools}
    required = {f'{verb}_v4_disabled_route_{phase}_700' for phase in markers for verb in ('preview', 'authorize', 'execute')}
    if not required <= names:
        raise ValueError('Fixed route tools are unavailable.')
    for phase in ('create', 'recover'):
        preview = _body(await session.call_tool(f'preview_v4_disabled_route_{phase}_700', {}))
        _reference(preview.get('preview_ref'), 'route-preview-')
        _fresh(preview.get('expires_at'))
        expected = {'contract': CONTRACT, 'phase': phase, 'policy_mode': 'lab_auto',
            'preview_ref': preview['preview_ref'], 'expires_at': preview['expires_at'],
            'Current State': {'complete_route_table_verified': True, 'original_creation_verified': phase == 'recover'},
            'Proposed Changes': {'operation': phase + '_disabled_route', 'route_remains_disabled': True},
            'Expected State': {'other_routes_preserved': True, 'original_table_restored': phase == 'recover'},
            'device_write_executed': False}
        if preview != expected:
            raise ValueError('Fixed route preview is unavailable.')
        auth = _body(await session.call_tool(f'authorize_v4_disabled_route_{phase}_700', {'preview_ref': preview['preview_ref']}))
        _reference(auth.get('authorization_ref'), 'route-auth-')
        _fresh(auth.get('expires_at'))
        if auth != {'contract': CONTRACT, 'phase': phase, 'policy_mode': 'lab_auto',
                    'authorization_ref': auth['authorization_ref'], 'expires_at': preview['expires_at']}:
            raise ValueError('Fixed route authorization is unavailable.')
        _reserve(markers[phase], phase)
        _fresh(auth['expires_at'])
        result = _body(await session.call_tool(f'execute_v4_disabled_route_{phase}_700', {'authorization_ref': auth['authorization_ref']}))
        if result != {'contract': CONTRACT, 'phase': phase, 'outcome': 'succeeded', 'verification': 'verified',
                      'compensation': 'not_requested', 'idempotent_replay': False}:
            raise ValueError('Fixed route result needs reconciliation; retry is forbidden.')
    return {'contract': CONTRACT, 'completed': True, 'create_verified': True, 'recovery_verified': True,
            'original_routes_preserved': True, 'route_never_enabled': True, 'mcp_dispatches': 2, 'retry_allowed': False}
