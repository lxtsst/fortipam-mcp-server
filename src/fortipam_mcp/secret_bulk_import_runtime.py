"""Default-closed normal-host composition for one protected Text import.

The HTTP host must be listening before the fixed source process starts. Source
admission and row permissions remain distinct: only the independent existing
Reference bootstrap CLI receives its write-key path. No material is read here.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import asdict
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Literal

from starlette.types import ASGIApp, Message, Receive, Scope, Send
import uvicorn
from v4_planning import AuthenticatedRequester, PlanningStoreTail, canonical_digest
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.models import require_digest, require_ref
from v4_planning.persistence import PersistentProtectedPlanningStore

from .dlp_api_actor_guard import DlpApiActorGuardBinding
from .m4_execution_store import M4ExecutionStoreTail, M4MonotonicCheckpointError, PersistentM4ExecutionStateStore
from .material_checkpoint_sidecar import UnixMaterialCheckpointClient, UnixMaterialCheckpointClientSettings
from .owner_collector_runtime import PREFIX as OWNER_PREFIX, owner_login_provider
from .planning_checkpoint_sidecar import UnixPlanningCheckpointClient, UnixPlanningCheckpointClientSettings
from .m4_checkpoint_client import UnixM4ExecutionCheckpoint as _M4PlanningCheckpoint
from .reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings
from .reference_grant_bootstrap import ReferenceGrantBootstrapSettings
from .runtime_profile import RuntimeProfile
from .secret_bulk_import_file import _SourceIdentity, _read_owned, _wipe
from .secret_bulk_import_intake import OwnerFileIntakeBinding
from .secret_bulk_import_intake_authority import PinnedOwnerFileIntakeAuthority, _members, _publish_policy
from .secret_bulk_import_issuer_runtime import _OwnerFileIntakeIssuerRuntime
from .secret_bulk_import_mcp_action import SecretBulkImportMcpAction, register_secret_bulk_import_candidate_tools
from .secret_bulk_import_namespace_source import ImportSecretNamespaceSourceReader
from .secret_bulk_import_parent_handoff import _OriginalParentReceiver
from .secret_bulk_import_reference_eligibility import ReferenceOwnerFileEligibility
from .secret_bulk_import_row_wire import _Build29SecretWireDefaults, _project_build29_secret_wire_defaults
from .secret_bulk_import_session_authority import PinnedOwnerFileSessionAuthority, ReferenceOwnerFileSessionEligibility
from .secret_bulk_import_source_catalog import ImportTemplateFolderSourceReader, _TextOnlyImportSource
from .secret_bulk_import_submission_process import _OriginalTextSubmissionProcess, _launch_original_text_submission_process
from .secret_bulk_import_submission_startup import CONTRACT as SUBMISSION_CONTRACT, PinnedOwnerFileSubmissionStartup, _map, _path, _record
from .secret_bulk_import_text_batch_owner import _OriginalTextBatchOwner
from .secret_bulk_import_token_channel import _PinnedKey, _canonical
from .secret_metadata_http_transport import COLLECTION_PATH, ENV_PREFIX as API_PREFIX, load_secret_metadata_http_transport_config
from .target_api_dependency_reader import _private_http_logs
from .target_ssh_transport import ENV_PREFIX as SSH_PREFIX, TargetSshTransportConfig, load_target_ssh_transport_config
from .web_secret_create_ack import WebSecretCreateAckCapture
from .v4_plan_runtime import V4PlanningAuthorizationSettings, _human_identity_binding, _length_prefixed

PREFIX = 'FORTIPAM_MCP_V4_SECRET_BULK_IMPORT_'
CONTRACT = 'fortipam-original-text-import-runtime-v1'
_ERROR = 'Protected Text import runtime is unavailable.'
_OWNER_ENVIRONMENT = frozenset(OWNER_PREFIX + suffix for suffix in
    ('SESSION_ENABLED', 'LOGIN_ENV_FILE', 'USERNAME_VARIABLE', 'PASSWORD_VARIABLE'))
_FIELDS = frozenset({'contract', 'source', 'channel_options', 'permission', 'policy',
    'session_permission', 'session_policy', 'actor', 'ack_success_status',
    'submission_profile_path', 'submission_socket_path', 'parent', 'stores', 'row', 'bootstrap'})
_PERMISSION_FIELDS = frozenset({'authority_ref', 'reference', 'requester_digest',
    'scope_key_path', 'scope_key_sha256', 'socket_path'})
_POLICY_FIELDS = frozenset({'policy_path', 'policy_sha256', 'key_path', 'key_sha256'})
_CHANNEL_FIELDS = frozenset({'socket_path', 'request_key_path', 'request_key_sha256',
    'public_key_path', 'public_key_sha256'})
_STORE_FIELDS = frozenset({'database_path', 'hmac_key_path', 'checkpoint_socket_path',
    'checkpoint_authority_ref', 'checkpoint_store_ref'})
_ROW_FIELDS = frozenset({'authority_key_path', 'authority_key_sha256', 'transport_digest',
    'scope_key_path', 'scope_key_sha256', 'socket_path', 'request_key_path', 'request_key_sha256',
    'signing_key_path', 'signing_key_sha256', 'public_key_path', 'public_key_sha256',
    'product_source_path', 'product_source_digest', 'references'})
_TOOLS = ('preview_v4_secret_bulk_import_text_700', 'authorize_v4_secret_bulk_import_text_700',
    'execute_v4_secret_bulk_import_text_700')


def _load_native_ssh_config(environment: Mapping[str, str]) -> TargetSshTransportConfig:
    """Select explicit Owner references without materializing a password file."""
    owner_mode = environment.get(SSH_PREFIX + 'OWNER_LOGIN_ENABLED', 'false')
    if owner_mode == 'false':
        return load_target_ssh_transport_config(environment)
    try:
        if owner_mode != 'true' or environment.get(SSH_PREFIX + 'ENABLED') != 'true':
            raise ValueError
        credentials = owner_login_provider(environment)
        if credentials is None:
            raise ValueError
        username, password = credentials()
        if username != environment[SSH_PREFIX + 'SSH_USERNAME']:
            raise ValueError
        return TargetSshTransportConfig(
            host=environment[SSH_PREFIX + 'SSH_HOST'],
            port=int(environment.get(SSH_PREFIX + 'SSH_PORT', '22')),
            username=username, password=password,
            known_hosts_file=Path(environment[SSH_PREFIX + 'SSH_KNOWN_HOSTS_FILE']),
            timeout_seconds=float(environment.get(SSH_PREFIX + 'SSH_TIMEOUT_SECONDS', '15')),
        )
    except Exception:
        raise ValueError(_ERROR) from None


def _load_native_source(environment: Mapping[str, str], actor: DlpApiActorGuardBinding,
                        ack_success_status: Literal['OK', 'success'],
                        ) -> tuple[_TextOnlyImportSource, _Build29SecretWireDefaults, WebSecretCreateAckCapture]:
    """Use fixed actual actor/Folder/SSH reads and the native default projection."""
    config = load_secret_metadata_http_transport_config(environment)
    ssh = _load_native_ssh_config(environment)
    folders = ImportTemplateFolderSourceReader(config, actor)
    namespace: ImportSecretNamespaceSourceReader | None = None
    raw = bytearray()
    try:
        namespace = ImportSecretNamespaceSourceReader(config, ssh, actor)
        tls = folders._guard._tls_for_transport(config)
        namespace._guard._guard._context = tls
        observed = folders.read_once()
        with _private_http_logs(), folders._factory(verify=tls, follow_redirects=False, trust_env=False,
                timeout=min(10.0, observed.expires_at - time.monotonic())) as client:
            try:
                client.cookies.clear()
                with client.stream('GET', config.base_url.rstrip('/') + COLLECTION_PATH + '?action=default&vdom=root',
                        headers={'Authorization': 'Bearer ' + config.bearer_token, 'Accept': 'application/json',
                            'Accept-Encoding': 'identity', 'Cache-Control': 'no-store',
                            'User-Agent': 'fortipam-private-original-row/1'}) as response:
                    if (response.status_code != 200
                            or response.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json'
                            or response.headers.get('content-encoding', 'identity').strip().lower() != 'identity'):
                        raise ValueError
                    for chunk in response.iter_raw():
                        folders.check_current(observed)
                        if len(raw) + len(chunk) > 1048576:
                            raise ValueError
                        raw.extend(chunk)
            finally:
                client.cookies.clear()
        if not client.is_closed:
            raise ValueError
        defaults = _project_build29_secret_wire_defaults(raw, serial_digest=observed.serial_digest)
        observed_namespace = namespace.read_once()
        source = _TextOnlyImportSource(folders, observed, namespace, observed_namespace)
        return source, defaults, WebSecretCreateAckCapture(defaults.serial_digest, ack_success_status)
    except BaseException:
        folders.close()
        if namespace is not None:
            namespace.close()
        raise
    finally:
        _wipe(raw)


class _OriginalTextImportRuntime:
    """One host-bound, original-deadline source/parent/Owner lifetime."""

    def __init__(self, environment: Mapping[str, str], *, issuer: _OwnerFileIntakeIssuerRuntime,
                 profile_path: Path, profile_sha256: str, execution_enabled: bool = False) -> None:
        self._issuer = issuer
        self._path, self._sha = profile_path, profile_sha256
        self._identity: _SourceIdentity | None = None
        self._execution_enabled = execution_enabled
        self._environment = {name: value for name, value in environment.items()
            if name.startswith(API_PREFIX) or name.startswith(SSH_PREFIX) or name in _OWNER_ENVIRONMENT}
        self._server: Any = None
        self._authorization: V4PlanningAuthorizationSettings | None = None
        self._runner: uvicorn.Server | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._process: _OriginalTextSubmissionProcess | None = None
        self._bootstrap_process: subprocess.Popen[bytes] | None = None
        self._receiver: _OriginalParentReceiver | None = None
        self._source: _TextOnlyImportSource | None = None
        self._owner: _OriginalTextBatchOwner | None = None
        self._stop, self._ready, self._done = threading.Event(), threading.Event(), threading.Event()
        self._lock = threading.RLock()
        self._used = self._registered = self._failed = False
        self._last_wall, self._last_mono = time.time(), time.monotonic()
        self._deadline = self._last_mono + 60.0
        try:
            if type(issuer) is not _OwnerFileIntakeIssuerRuntime or type(execution_enabled) is not bool:
                raise ValueError
            require_digest(profile_sha256, 'runtime profile')
            value = self._load()
            source = dict(value['source'])
            source['path'] = _path(source['path'])
            self._binding = _record(source, OwnerFileIntakeBinding)
            channel = issuer._binding
            if (any(getattr(self._binding, name) != getattr(channel, name) for name in
                    ('issuer', 'planning_resource', 'intake_resource', 'deployment_digest', 'workload_digest'))
                    or not channel.issued_at <= self._binding.issued_at < self._binding.expires_at <= channel.expires_at
                    or not self._binding.issued_at <= self._last_wall < self._binding.expires_at):
                raise ValueError
            self._deadline = min(self._deadline, self._last_mono + self._binding.expires_at - self._last_wall)
            self._validate_profile(value)
            self._value = value
            self._check()
        except Exception:
            raise ValueError(_ERROR) from None

    def _load(self) -> dict[str, Any]:
        raw = bytearray()
        try:
            raw, identity = _read_owned(self._path, self._identity)
            if not 0 < len(raw) <= 65536 or hashlib.sha256(raw).hexdigest() != self._sha:
                raise ValueError
            value = _map(json.loads(raw, object_pairs_hook=_members), _FIELDS)
            if value['contract'] != CONTRACT:
                raise ValueError
            self._identity = identity
            return value
        finally:
            _wipe(raw)

    def _validate_profile(self, value: dict[str, Any]) -> None:
        channel = _map(value['channel_options'], _CHANNEL_FIELDS)
        if (channel['socket_path'] != str(self._issuer._socket)
                or channel['request_key_path'] != str(self._issuer._options['request_key_path'])
                or channel['request_key_sha256'] != self._issuer._options['request_key_sha256']):
            raise ValueError
        _record(value['actor'], DlpApiActorGuardBinding)
        if value['ack_success_status'] not in ('OK', 'success'):
            raise ValueError
        parent = _map(value['parent'], {'plan_ref', 'requester_digest', 'parent_idempotency_digest',
            'namespace_key_path', 'namespace_key_sha256'})
        require_ref(parent['plan_ref'], 'parent')
        row = _map(value['row'], _ROW_FIELDS)
        if (type(row['references']) is not list or not 1 <= len(row['references']) <= 256
                or any(type(item) is not str for item in row['references'])
                or len(set(row['references'])) != len(row['references'])):
            raise ValueError
        for reference in row['references']:
            require_ref(reference, 'row reference')
        stores = _map(value['stores'], {'planning', 'execution', 'material'})
        for item in stores.values():
            store = _map(item, _STORE_FIELDS)
            for name in ('checkpoint_authority_ref', 'checkpoint_store_ref'):
                require_ref(store[name], name)
        if len({item['checkpoint_store_ref'] for item in stores.values()}) != 3:
            raise ValueError
        if len({item['database_path'] for item in stores.values()}) != 3:
            raise ValueError
        permission = _map(value['permission'], _PERMISSION_FIELDS)
        session = _map(value['session_permission'], _PERMISSION_FIELDS)
        if (permission['requester_digest'] != parent['requester_digest']
                or session['requester_digest'] != parent['requester_digest']
                or permission['authority_ref'] != session['authority_ref']
                or permission['socket_path'] != session['socket_path']
                or permission['reference'] == session['reference']):
            raise ValueError
        bootstrap = _map(value['bootstrap'], {'database_path', 'hmac_key_path', 'authority_ref',
            'checkpoint_socket_path', 'checkpoint_authority_ref', 'checkpoint_store_ref', 'work_directory'})
        if bootstrap['authority_ref'] != permission['authority_ref']:
            raise ValueError
        for name in ('policy', 'session_policy'):
            _map(value[name], _POLICY_FIELDS)
        # Check selectors and digest syntax before any mutable state is opened.
        for item in (channel, parent, row, permission, session, bootstrap,
                     value['policy'], value['session_policy'], *stores.values()):
            for name, selected in item.items():
                if name.endswith('_path') or name == 'work_directory':
                    _path(selected)
                if name.endswith('_sha256') or name.endswith('_digest'):
                    require_digest(selected, name)
        for name in ('submission_profile_path', 'submission_socket_path'):
            _path(value[name])
        # The source never receives a Reference write key, checkpoint key or DB.
        protected_key = _path(bootstrap['hmac_key_path'])
        source_inputs = {self._binding.path, self._path, _path(value['submission_profile_path']),
            _path(parent['namespace_key_path'])}
        for item in (channel, permission, session, value['policy'], value['session_policy'], row):
            source_inputs.update(_path(item[name]) for name in item if name.endswith('_path'))
        if protected_key in source_inputs or protected_key in {_path(item['hmac_key_path']) for item in stores.values()}:
            raise ValueError

    def _check(self) -> None:
        wall, mono = time.time(), time.monotonic()
        if (self._stop.is_set() or not self._last_wall <= wall < self._binding.expires_at
                or not self._last_mono <= mono < self._deadline
                or self._load() != self._value or self._issuer._stop.is_set()
                or self._server is not None and self._server._v4_planning_authorization is not self._authorization):
            raise ValueError
        self._issuer._load()
        self._issuer._lifetime.check()
        self._last_wall, self._last_mono = wall, mono

    def bind_server(self, server: Any) -> None:
        from .server import FortiPamMcpServer
        with self._lock:
            try:
                self._check()
                if type(server) is not FortiPamMcpServer or self._server is not None or self._used:
                    raise ValueError
                settings = server._v4_planning_authorization
                binding = self._binding
                if (type(settings) is not V4PlanningAuthorizationSettings
                        or settings.expected_resource != binding.planning_resource):
                    raise ValueError
                subject, authority, namespace = _human_identity_binding(settings, issuer=binding.issuer,
                    subject=binding.subject, resource=binding.planning_resource)
                requester = AuthenticatedRequester(subject_ref=subject, principal_class='operator',
                    identity_authority_ref=authority, subject_namespace=namespace)
                transport = hmac.new(settings.namespace_hmac_key, _length_prefixed(('v4-plan-transport-v1',
                    binding.issuer, binding.planning_client, binding.subject, binding.planning_resource)),
                    hashlib.sha256).hexdigest()
                if (not hmac.compare_digest(requester.digest, self._value['parent']['requester_digest'])
                        or not hmac.compare_digest(transport, self._value['row']['transport_digest'])):
                    raise ValueError
                self._authorization, self._server = settings, server
            except Exception:
                raise ValueError(_ERROR) from None

    def bind_runner(self, runner: uvicorn.Server) -> None:
        with self._lock:
            self._check()
            if type(runner) is not uvicorn.Server or self._runner is not None or self._used:
                raise ValueError(_ERROR)
            self._runner = runner

    def wrap(self, app: ASGIApp) -> ASGIApp:
        async def wrapped(scope: Scope, receive: Receive, send: Send) -> None:
            if scope['type'] != 'lifespan':
                await app(scope, receive, send)
                return

            async def starting() -> Message:
                message = await receive()
                if message['type'] == 'lifespan.startup':
                    with self._lock:
                        self._check()
                        if self._used or self._server is None or self._runner is None:
                            raise ValueError(_ERROR)
                        self._used = True
                        self._loop = asyncio.get_running_loop()
                        self._thread = threading.Thread(target=self._run, name='original-text-import', daemon=True)
                        self._thread.start()
                return message
            try:
                await app(scope, starting, send)
            finally:
                await asyncio.to_thread(self.close)
        return wrapped

    def _stores(self) -> tuple[PersistentProtectedPlanningStore, PersistentM4ExecutionStateStore,
                               PersistentMaterialUseStateStore]:
        planning, execution, material = (self._value['stores'][name] for name in ('planning', 'execution', 'material'))
        def checkpoint(item: dict[str, Any]) -> UnixPlanningCheckpointClient:
            result = UnixPlanningCheckpointClient(UnixPlanningCheckpointClientSettings(
                _path(item['checkpoint_socket_path']), item['checkpoint_authority_ref']))
            result.verify_ready()
            return result
        parent = PersistentProtectedPlanningStore(_path(planning['database_path']), _path(planning['hmac_key_path']),
            monotonic_checkpoint=checkpoint(planning), checkpoint_store_ref=planning['checkpoint_store_ref'])
        m4 = PersistentM4ExecutionStateStore(_path(execution['database_path']), _path(execution['hmac_key_path']),
            monotonic_checkpoint=_M4PlanningCheckpoint(checkpoint(execution), execution['checkpoint_store_ref']),
            checkpoint_store_ref=execution['checkpoint_store_ref'])
        material_checkpoint = UnixMaterialCheckpointClient(UnixMaterialCheckpointClientSettings(
            _path(material['checkpoint_socket_path']), material['checkpoint_authority_ref']))
        material_checkpoint.verify_ready()
        c3 = PersistentMaterialUseStateStore(_path(material['database_path']), _path(material['hmac_key_path']),
            monotonic_checkpoint=material_checkpoint, checkpoint_store_ref=material['checkpoint_store_ref'])
        return parent, m4, c3

    def _admission(self) -> tuple[PinnedOwnerFileIntakeAuthority, PinnedOwnerFileSessionAuthority,
                                 UnixReferenceAuthorityClient]:
        value = self._value
        permission = value['permission']
        remote = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(
            _path(permission['socket_path']), permission['authority_ref']))
        def checker_options(item: dict[str, Any]) -> dict[str, Any]:
            return dict(authority=remote, authority_ref=item['authority_ref'], reference=item['reference'],
                requester_digest=item['requester_digest'], scope_key_path=_path(item['scope_key_path']),
                scope_key_sha256=item['scope_key_sha256'])
        def policy_options(item: dict[str, Any]) -> dict[str, Any]:
            return dict(policy_path=_path(item['policy_path']), policy_sha256=item['policy_sha256'],
                key_path=_path(item['key_path']), key_sha256=item['key_sha256'])
        eligibility = ReferenceOwnerFileEligibility(self._binding, **checker_options(permission))
        session_eligibility = ReferenceOwnerFileSessionEligibility(self._binding,
            **checker_options(value['session_permission']))
        authority = PinnedOwnerFileIntakeAuthority(self._binding, human_owner_verifier=eligibility,
            **policy_options(value['policy']))
        session = PinnedOwnerFileSessionAuthority(self._binding, human_owner_verifier=session_eligibility,
            **policy_options(value['session_policy']))
        authority.verify(self._binding, now_epoch=int(time.time()))
        session.verify_source_session(self._binding, now_epoch=int(time.time()))
        return authority, session, remote

    def _write(self, path: Path, value: object) -> str:
        raw = bytearray(_canonical(value))
        try:
            _publish_policy(path, raw, self._check)
            return hashlib.sha256(raw).hexdigest()
        finally:
            _wipe(raw)

    def _bootstrap(self, owner: _OriginalTextBatchOwner) -> None:
        selected = self._value['bootstrap']
        directory = _path(selected['work_directory'])
        project = Path(__file__).resolve().parents[2]
        for index, payload in enumerate(owner._reference_bootstrap()):
            self._check()
            settings = ReferenceGrantBootstrapSettings(_path(selected['database_path']),
                _path(selected['hmac_key_path']), selected['authority_ref'],
                directory / f'row-{index}-input.json', directory / f'row-{index}-grants.json',
                _path(selected['checkpoint_socket_path']), selected['checkpoint_authority_ref'],
                selected['checkpoint_store_ref'])
            self._write(settings.input_path, payload)
            environment = {'PATH': os.defpath, 'PYTHONDONTWRITEBYTECODE': '1',
                'PYTHONPATH': os.pathsep.join((str(project / 'src'), str(project)))}
            for suffix, item in {'DATABASE': settings.database_path, 'HMAC_KEY_FILE': settings.hmac_key_path,
                    'AUTHORITY_REF': settings.authority_ref, 'CHECKPOINT_SOCKET': settings.checkpoint_socket_path,
                    'CHECKPOINT_AUTHORITY_REF': settings.checkpoint_authority_ref,
                    'CHECKPOINT_STORE_REF': settings.checkpoint_store_ref,
                    'INPUT': settings.input_path, 'OUTPUT': settings.output_path}.items():
                environment['FORTIPAM_MCP_V4_REFERENCE_BOOTSTRAP_' + suffix] = str(item)
            # Only this independent fixed CLI receives the Reference write-key path.
            with self._lock:
                self._check()
                process = subprocess.Popen([sys.executable, '-m', 'fortipam_mcp.reference_grant_bootstrap'],
                    env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, close_fds=True, cwd=project)
                self._bootstrap_process = process
            try:
                if process.wait(timeout=max(0.01, min(self._deadline, owner._deadline) - time.monotonic())) != 0:
                    raise ValueError
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
                self._bootstrap_process = None
            self._check()
        # Publication verifies each independent grant against the original parent.
        # The preview performs the authoritative row reads before any authorization.
        for _, _, _, permission in owner._rows:
            checker = permission._checker
            checker(owner._source, canonical_digest(checker._reference), owner._check())
            owner._check()

    async def _register(self) -> None:
        self._check()
        if self._owner is None or self._server is None or self._registered:
            raise ValueError
        existing = {tool.name for tool in await self._server.mcp.list_tools()}
        if set(_TOOLS) & existing:
            raise ValueError
        register_secret_bulk_import_candidate_tools(self._server, SecretBulkImportMcpAction(self._owner))
        self._registered = True
        self._ready.set()

    def _run(self) -> None:
        child_peer: socket.socket | None = None
        try:
            assert self._runner is not None
            while not self._runner.started:
                self._check()
                if self._runner.should_exit or self._runner.force_exit:
                    raise ValueError
                self._stop.wait(0.01)
            self._check()
            authority, session, remote = self._admission()
            parent, execution, material = self._stores()
            value, row, parent_options = self._value, self._value['row'], self._value['parent']
            source, defaults, capture = _load_native_source(self._environment,
                _record(value['actor'], DlpApiActorGuardBinding), value['ack_success_status'])
            self._source = source
            self._deadline = min(self._deadline, source._folders.expires_at, source._namespace.expires_at)
            self._check()
            catalog = source.prepare_catalog(expected_file_digest=self._binding.file_sha256,
                scope_digest=self._binding.scope_digest)
            catalog_payload = asdict(catalog)
            for name in ('coverage', 'service_types'):
                catalog_payload[name] = sorted(catalog_payload[name])
            profile_path = _path(value['submission_profile_path'])
            digest = self._write(profile_path, dict(contract=SUBMISSION_CONTRACT,
                purpose='private-dependency-projection-only', source=value['source'],
                channel=asdict(self._issuer._binding), channel_options=value['channel_options'],
                permission=value['permission'], policy=value['policy'], catalog=catalog_payload))
            startup = PinnedOwnerFileSubmissionStartup(self._binding, profile_path=profile_path, profile_sha256=digest)
            peer, child_peer = socket.socketpair()
            self._receiver = _OriginalParentReceiver(peer, self._binding, catalog, store=parent, authority=authority,
                plan_ref=parent_options['plan_ref'], plan_digest=None,
                requester_digest=parent_options['requester_digest'],
                parent_idempotency_digest=parent_options['parent_idempotency_digest'],
                key_path=_path(parent_options['namespace_key_path']), key_sha256=parent_options['namespace_key_sha256'],
                standing_lab_authorization=True, text_source=source)
            # The source watcher and the blocking receive share the original host
            # horizon; time spent starting HTTP cannot create a later file window.
            self._receiver._endpoint._deadline = min(self._receiver._endpoint._deadline, self._deadline)
            self._process = _launch_original_text_submission_process(startup, session, self._receiver, child_peer,
                defaults, capture, socket_path=_path(value['submission_socket_path']),
                row_socket_path=_path(row['socket_path']), row_request_key_path=_path(row['request_key_path']),
                row_request_key_sha256=row['request_key_sha256'], row_public_key_path=_path(row['public_key_path']),
                row_public_key_sha256=row['public_key_sha256'])
            child_peer = None
            self._check()
            original, projected, graph = self._receiver.receive_once()
            self._check()
            authority_key = _PinnedKey(_path(row['authority_key_path']), row['authority_key_sha256']).load()
            control = self._process.control_peer.dup()
            try:
                self._owner = _OriginalTextBatchOwner(original, self._receiver, projected, graph, execution, material,
                    defaults, capture, control_peer=control,
                    authenticated_requester_digest=parent_options['requester_digest'], authority_key=bytes(authority_key),
                    transport_digest=row['transport_digest'], reference_authority=remote,
                    authority_ref=value['permission']['authority_ref'],
                    reference_by_index=dict(enumerate(row['references'])), scope_key_path=_path(row['scope_key_path']),
                    scope_key_sha256=row['scope_key_sha256'], socket_path=_path(row['socket_path']),
                    request_key_path=_path(row['request_key_path']), request_key_sha256=row['request_key_sha256'],
                    signing_key_path=_path(row['signing_key_path']), signing_key_sha256=row['signing_key_sha256'],
                    product_source_path=_path(row['product_source_path']), product_source_digest=row['product_source_digest'],
                    execution_enabled=self._execution_enabled)
            except BaseException:
                control.close()
                raise
            finally:
                _wipe(authority_key)
            self._deadline = min(self._deadline, self._owner._deadline)
            self._bootstrap(self._owner)
            self._check()
            assert self._loop is not None
            future = asyncio.run_coroutine_threadsafe(self._register(), self._loop)
            future.result(timeout=max(0.01, self._deadline - time.monotonic()))
            while not self._stop.wait(0.05):
                if self._owner._closed or self._process._closed.is_set() or self._runner.should_exit:
                    break
                self._check()
        except Exception:
            self._failed = True
        finally:
            if child_peer is not None:
                child_peer.close()
            self._stop.set()
            self._cleanup()
            self._done.set()

    def _unregister(self) -> None:
        if self._registered and self._server is not None:
            for name in _TOOLS:
                self._server.mcp.remove_tool(name)
            self._registered = False

    def _cleanup(self) -> None:
        # Close retained process/control endpoints before joining blocked work.
        with self._lock:
            process = self._bootstrap_process
            if process is not None and process.poll() is None:
                process.kill()
            try:
                if self._owner is not None and not self._owner._closed:
                    self._owner._abort()
                elif self._owner is None and self._receiver is not None and self._receiver._plan_digest is not None:
                    self._receiver._store.invalidate_plan(self._receiver._plan_ref,
                        evaluated_at=int(self._receiver._last_wall),
                        reason_codes=('current_state_unavailable_or_unsafe',))
            except Exception:
                self._failed = True
            for item in (self._process, self._receiver, self._owner, self._source):
                if item is not None:
                    try:
                        item.close()
                    except Exception:
                        self._failed = True
            loop = self._loop
            if self._registered and loop is not None and not loop.is_closed():
                loop.call_soon_threadsafe(self._unregister)

    def close(self) -> None:
        self._stop.set()
        self._cleanup()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, self._deadline - time.monotonic()) + 5.0)
            if thread.is_alive():
                self._failed = True
                raise ValueError(_ERROR)


def build_secret_bulk_import_runtime(environment: Mapping[str, str], *,
                                     issuer: _OwnerFileIntakeIssuerRuntime | None,
                                     runtime_profile: RuntimeProfile) -> _OriginalTextImportRuntime | None:
    """Require explicit controlled-host activation and one pinned local profile."""
    try:
        enabled = environment.get(PREFIX + 'ENABLED', 'false')
        execution = environment.get(PREFIX + 'EXECUTION_ENABLED', 'false')
        if enabled not in ('true', 'false') or execution not in ('true', 'false'):
            raise ValueError
        if enabled == 'false':
            if execution != 'false' or any(environment.get(PREFIX + name) for name in ('PROFILE_FILE', 'PROFILE_SHA256')):
                raise ValueError
            return None
        if runtime_profile is not RuntimeProfile.V4_CONTROLLED or type(issuer) is not _OwnerFileIntakeIssuerRuntime:
            raise ValueError
        return _OriginalTextImportRuntime(environment, issuer=issuer,
            profile_path=_path(environment[PREFIX + 'PROFILE_FILE']), profile_sha256=environment[PREFIX + 'PROFILE_SHA256'],
            execution_enabled=execution == 'true')
    except Exception:
        raise ValueError(_ERROR) from None
