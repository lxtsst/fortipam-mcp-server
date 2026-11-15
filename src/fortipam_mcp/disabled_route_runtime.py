"""Owner-only default-closed route startup; no device I/O or credential copying."""
from collections.abc import Mapping
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any

from .disabled_route_contract import DisabledRouteBinding
from .disabled_route_live_workflow import DisabledRouteLiveWorkflow
from .disabled_route_mcp_action import DisabledRouteMcpAction
from .ldap_server_runtime import _key, _path, _read
from .disabled_route_m4_adapter import _pairs
from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_metadata_http_transport import load_secret_metadata_http_transport_config

PREFIX = 'FORTIPAM_MCP_V4_DISABLED_ROUTE_700_'
CONTRACT = 'fortipam-disabled-route-startup-v1'
_ERROR = 'FortiPAM disabled route startup is unavailable.'


def _flag(environment: Mapping[str, str], name: str) -> bool:
    value = environment.get(PREFIX + name, 'false')
    if value not in {'true', 'false'}:
        raise ValueError
    return value == 'true'


def build_disabled_route_candidate(environment: Mapping[str, str]) -> DisabledRouteMcpAction | None:
    try:
        enabled = _flag(environment, 'ENABLED')
        create, recover = _flag(environment, 'CREATE_ENABLED'), _flag(environment, 'RECOVERY_ENABLED')
        if not enabled:
            if create or recover:
                raise ValueError
            return None
        manifest_path = _path(environment[PREFIX + 'STARTUP_MANIFEST_FILE'])
        raw = _read(manifest_path, 16384)
        try:
            manifest = json.loads(raw, object_pairs_hook=_pairs)
        finally:
            raw[:] = b'\0' * len(raw)
        if set(manifest) != {'contract', 'binding', 'identity', 'paths'} or manifest['contract'] != CONTRACT:
            raise ValueError
        if (set(manifest['binding']) not in ({'sequence', 'nonce'}, {'sequence', 'nonce', 'benchmark_host'})
                or set(manifest['identity']) != {'serial_digest', 'schema_digest', 'environment_ref',
                    'scope_ref', 'audience_ref', 'allowed_requester_digest', 'allowed_transport_digest'}
                or set(manifest['paths']) != {'execution_database_file', 'execution_hmac_key_file', 'authority_hmac_key_file'}):
            raise ValueError
        binding = DisabledRouteBinding(**manifest['binding'])
        paths = {k: _path(v) for k, v in manifest['paths'].items()}
        if len({manifest_path, *paths.values()}) != 4:
            raise ValueError
        authority, execution = _key(paths['authority_hmac_key_file']), _key(paths['execution_hmac_key_file'])
        if hmac.compare_digest(authority, execution):
            raise ValueError
        config = load_secret_metadata_http_transport_config(environment)
        namespace = {'manifest': manifest, 'api_origin': config.base_url, 'api_ca_file': config.ca_file,
                     'authority_key_digest': hashlib.sha256(authority).hexdigest(),
                     'execution_key_digest': hashlib.sha256(execution).hexdigest()}
        digest = hmac.new(execution, b'fortipam-disabled-route-runtime-v1\0' + json.dumps(namespace,
            sort_keys=True, separators=(',', ':'), allow_nan=False).encode(), hashlib.sha256).hexdigest()
        marker = Path(str(paths['execution_database_file']) + '.namespace')
        family = [Path(str(paths['execution_database_file']) + suffix) for suffix in ('', '-wal', '-shm', '-journal')]
        if marker in {manifest_path, *paths.values()} or set(family[1:]) & {manifest_path, *paths.values()}:
            raise ValueError
        if os.path.lexists(marker):
            if not paths['execution_database_file'].is_file():
                raise ValueError
            pinned = _read(marker, 128)
            try:
                if not hmac.compare_digest(bytes(pinned), digest.encode()):
                    raise ValueError
            finally:
                pinned[:] = b'\0' * len(pinned)
        else:
            if any(os.path.lexists(p) for p in family):
                raise ValueError
            # Pin immutable startup identity beside the existing M4 database.
            descriptor = os.open(marker, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(digest.encode())
                stream.flush()
                os.fsync(stream.fileno())
            parent = os.open(marker.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
        store = PersistentM4ExecutionStateStore(paths['execution_database_file'], paths['execution_hmac_key_file'])
        workflow = DisabledRouteLiveWorkflow(config, binding, store, authority_key=authority,
            create_enabled=create, recovery_enabled=recover, **manifest['identity'])
        return DisabledRouteMcpAction(workflow)
    except Exception:
        raise ValueError(_ERROR) from None
