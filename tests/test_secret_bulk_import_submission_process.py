"""Real private submission across fresh processes; synthetic files and grants.

Audit controls prove input-use behavior, not malicious same-UID containment.
No retained lab identity or asset is consumed by this disposable fixture.
"""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, ExitStack
from dataclasses import asdict, replace
import asyncio
import hashlib
import json
import os
import socket
from pathlib import Path
import subprocess
import sys
import tempfile
import time

import httpx
from mcp.server.auth.provider import ProviderTokenVerifier
import pytest

from fortipam_mcp.secret_bulk_import_reference_eligibility import REFERENCE_KIND
from fortipam_mcp.secret_bulk_import_reference_eligibility import ReferenceOwnerFileEligibility
from fortipam_mcp.secret_bulk_import_intake_authority import issue_prebound_owner_file_policy_once
from fortipam_mcp.secret_bulk_import_submission_startup import CONTRACT
from fortipam_mcp.secret_bulk_import_session_authority import (
    REFERENCE_KIND as SESSION_REFERENCE_KIND, ReferenceOwnerFileSessionEligibility,
    issue_prebound_owner_file_session_policy_once, source_session_scope_ref,
)
from fortipam_mcp.reference_grant_bootstrap import ReferenceGrantBootstrapSettings, bootstrap_reference_grants
from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, planning_principal_from_access_token
from test_secret_bulk_import_intake import prepared
from test_secret_bulk_import_dependencies import catalog
from test_secret_bulk_import_reference_eligibility import AUTHORITY, CHECKPOINT, REFERENCE, STORE, source
from test_secret_bulk_import_submission import frame
from test_secret_bulk_import_token_channel import SERVER, setup

REFERENCE_SERVER = r'''
import json, logging, socket, sys, threading
from pathlib import Path
import uvicorn
from fortipam_mcp.reference_authority_sidecar import create_reference_authority_sidecar_app
from fortipam_mcp.reference_checkpoint_sidecar import UnixReferenceCheckpointClient, UnixReferenceCheckpointClientSettings
from v4_planning import PersistentReferenceAuthority
value = json.loads(sys.stdin.readline())
checkpoint = UnixReferenceCheckpointClient(UnixReferenceCheckpointClientSettings(
    Path(value["checkpoint_socket"]), value["checkpoint_authority"]))
authority = PersistentReferenceAuthority(Path(value["database"]), Path(value["key"]), authority_ref=value["authority"],
    monotonic_checkpoint=checkpoint, checkpoint_store_ref=value["store"])
app = create_reference_authority_sidecar_app(authority)
logging.disable(logging.CRITICAL)
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
path = Path(value["socket_path"])
try:
    listener.bind(str(path))
    path.chmod(0o600)
    listener.listen(8)
    runner = uvicorn.Server(uvicorn.Config(app, access_log=False, log_config=None))
    def stop():
        if sys.stdin.readline() == "stop\n":
            runner.should_exit = True
    threading.Thread(target=stop, daemon=True).start()
    runner.run(sockets=[listener])
finally:
    listener.close()
    path.unlink(missing_ok=True)
'''

CHECKPOINT_SERVER = r'''
import json, logging, socket, sys, threading
from pathlib import Path
import uvicorn
from fortipam_mcp.reference_checkpoint_sidecar import create_reference_checkpoint_sidecar_app
from v4_planning import PersistentReferenceCheckpointAuthority
value = json.loads(sys.stdin.readline())
checkpoint = PersistentReferenceCheckpointAuthority(Path(value["database"]), Path(value["key"]),
    authority_ref=value["authority"])
app = create_reference_checkpoint_sidecar_app(checkpoint)
logging.disable(logging.CRITICAL)
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
path = Path(value["socket_path"])
try:
    listener.bind(str(path))
    path.chmod(0o600)
    listener.listen(8)
    runner = uvicorn.Server(uvicorn.Config(app, access_log=False, log_config=None))
    def stop():
        if sys.stdin.readline() == "stop\n":
            runner.should_exit = True
    threading.Thread(target=stop, daemon=True).start()
    runner.run(sockets=[listener])
finally:
    listener.close()
    path.unlink(missing_ok=True)
'''

INTAKE_SERVER = r'''
import json, logging, os, socket, sys, threading
from pathlib import Path
value = json.loads(sys.stdin.readline())
attempts, source_reads, frames = [], [], []
def guard(event, args):
    if event == "sqlite3.connect":
        attempts.append(True)
        raise PermissionError("Private authority input boundary")
    if event == "open" and isinstance(args[0], (str, bytes)):
        path = os.fsdecode(args[0])
        components = Path(path).parts
        if set(components).intersection({"oauth-state", "issuer-private", "reference", "checkpoint", "reference.key", "checkpoint.key", "signing.key"}):
            attempts.append(True)
            raise PermissionError("Private authority input boundary")
        if path == value["source"]["path"] or Path(path).name == Path(value["source"]["path"]).name:
            source_reads.append(True)
sys.addaudithook(guard)
import uvicorn
from fortipam_mcp import secret_bulk_import_submission as submission
from fortipam_mcp.secret_bulk_import_intake import OwnerFileIntakeBinding
from fortipam_mcp.secret_bulk_import_submission_startup import PinnedOwnerFileSubmissionStartup
source = value["source"]
source["path"] = Path(source["path"])
binding = OwnerFileIntakeBinding(**source)
wipe = submission._wipe
def clear(raw):
    frames.append(raw)
    wipe(raw)
submission._wipe = clear
startup = PinnedOwnerFileSubmissionStartup(binding, profile_path=Path(value["profile_path"]),
    profile_sha256=value["profile_sha256"])
retained_sessions, handoff_attempts = [], []
session_authority = None
if "session_policy" in value:
    from fortipam_mcp.reference_authority_sidecar import UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings
    from fortipam_mcp.secret_bulk_import_session_authority import PinnedOwnerFileSessionAuthority, ReferenceOwnerFileSessionEligibility
    permission = dict(value["session_permission"])
    permission["scope_key_path"] = Path(permission["scope_key_path"])
    remote = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(Path(value["reference_socket"]), permission["authority_ref"]))
    checker = ReferenceOwnerFileSessionEligibility(binding, authority=remote, **permission)
    policy = dict(value["session_policy"])
    for name in ("policy_path", "key_path"):
        policy[name] = Path(policy[name])
    session_authority = PinnedOwnerFileSessionAuthority(binding, human_owner_verifier=checker, **policy)
    admit = submission.admit_prebound_owner_file_session
    async def capture(*args, **kwargs):
        session = await admit(*args, **kwargs)
        retained_sessions.append(session)
        return session
    submission.admit_prebound_owner_file_session = capture
if "parent_handoff" in value:
    from fortipam_mcp import secret_bulk_import_parent_handoff as handoff
    forward = handoff._OriginalParentHandoff._forward
    def forward_once(self, graph):
        handoff_attempts.append(True)
        return forward(self, graph)
    handoff._OriginalParentHandoff._forward = forward_once
    handoff._wipe = clear
    pins = value["parent_handoff"]
    parent_peer = socket.socket(fileno=pins["fd"])
    app = startup.create_original_parent_app_once(parent_peer, context_digest=pins["context_digest"],
        deadline=pins["deadline"], session_authority=session_authority)
    assert not parent_peer.get_inheritable()
elif session_authority is not None:
    app = startup.create_source_session_app_once(session_authority)
else:
    app = startup.create_app_once()
violations, successful_reads = [], []
async def monitor(scope, receive, send):
    started = len(source_reads)
    forwarded = len(handoff_attempts)
    async def checked_send(message):
        if message["type"] == "http.response.start":
            if message["status"] == 409 and len(source_reads) != started and len(handoff_attempts) == forwarded:
                violations.append(True)
            if (message["status"] == 200 or len(handoff_attempts) > forwarded) and len(source_reads) > started:
                successful_reads.append(True)
        await send(message)
    await app(scope, receive, checked_send)
logging.disable(logging.CRITICAL)
listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
path = Path(value["socket_path"])
try:
    listener.bind(str(path))
    path.chmod(0o600)
    listener.listen(8)
    runner = uvicorn.Server(uvicorn.Config(monitor, access_log=False, log_config=None, lifespan="on"))
    def stop():
        if sys.stdin.readline() == "stop\n":
            runner.should_exit = True
    threading.Thread(target=stop, daemon=True).start()
    runner.run(sockets=[listener])
finally:
    listener.close()
    path.unlink(missing_ok=True)
assert not attempts and not violations
assert successful_reads and frames and all(not any(raw) for raw in frames)
report = {"authority_inputs_unread": True, "rejected_requests_did_not_read_source": True,
    "authenticated_projection_read_source": True, "mutable_frames_cleared": True}
if "session_policy" in value:
    assert len(retained_sessions) == 1
    assert all(not any(session._password) and not session._watchdog.is_alive() for session in retained_sessions)
    report["retained_unlocks_cleared_at_shutdown"] = True
if "parent_handoff" in value:
    assert len(handoff_attempts) == 1 and parent_peer.fileno() == -1
    report["parent_handoff_closed_once"] = True
print(json.dumps(report))
'''


def paths(value):
    return {name: str(item) if isinstance(item, Path) else item for name, item in value.items()}


@contextmanager
def running(script, bootstrap, root, *, report=False, sandbox_profile=None, pass_fds=()):
    project = Path(__file__).resolve().parents[1]
    environment = {"PATH": os.defpath, "PYTHONPATH": str(project / "src") + os.pathsep + str(project),
                   "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"}
    command = [sys.executable, "-c", script]
    if sandbox_profile is not None:
        command = ["/usr/bin/sandbox-exec", "-f", str(sandbox_profile), *command]
    process = subprocess.Popen(command, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, cwd=root, pass_fds=pass_fds)
    outcome = {}
    try:
        process.stdin.write(json.dumps(bootstrap).encode() + b"\n")
        process.stdin.flush()
        deadline = time.monotonic() + 5
        socket_path = Path(bootstrap["socket_path"])
        while not socket_path.exists():
            assert process.poll() is None, "Private candidate stopped before bind"
            assert time.monotonic() < deadline, "Private candidate did not bind"
            time.sleep(0.02)
        yield outcome
    finally:
        if process.poll() is None:
            try:
                process.stdin.write(b"stop\n")
                process.stdin.flush()
            except BrokenPipeError:
                pass
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        output, errors = process.stdout.read(), process.stderr.read()
        process.stdout.close()
        process.stderr.close()
        assert process.returncode == 0, "Private candidate failed"
        assert errors == b"", "Private candidate emitted diagnostics"
        if report:
            outcome.update(json.loads(output))
        else:
            assert output == b"", "Private authority emitted output"
        assert not Path(bootstrap["socket_path"]).exists()


def native_intake_profile(root, intake_input):
    """Disposable default-deny macOS test policy, not a production launcher."""
    allowed = [intake_input["profile_path"], intake_input["source"]["path"], intake_input["permission"]["scope_key_path"],
               intake_input["policy"]["policy_path"], intake_input["policy"]["key_path"],
               intake_input["channel_options"]["request_key_path"], intake_input["channel_options"]["public_key_path"]]
    if "session_policy" in intake_input:
        allowed.extend(intake_input["session_policy"][name] for name in ("policy_path", "key_path"))
    socket_path = intake_input["socket_path"]
    remotes = [intake_input["channel_options"]["socket_path"], intake_input["reference_socket"]]
    return native_private_input_profile(root, allowed_paths=allowed,
        remote_sockets=remotes, listener_socket=socket_path)


def native_private_input_profile(root, *, allowed_paths, remote_sockets, listener_socket=None):
    """Reuse native denial rules without granting an unused listener/write path."""
    project = Path(__file__).resolve().parents[1]
    def literal(path):
        return '(literal ' + json.dumps(str(Path(path).resolve())) + ')'
    def subtree(path):
        return '(subpath ' + json.dumps(str(Path(path).resolve())) + ')'
    rules = ['(version 1)', '(deny default)', '(import "system.sb")',
             '(allow file-read-metadata)', '(allow file-read-data (vnode-type DIRECTORY))',
             '(allow sysctl-read)', '(allow process-fork)', '(allow signal (target self) (target children))',
             '(allow process-exec ' + literal(sys.executable) + ')',
             '(allow file-read* file-map-executable ' + subtree(sys.base_prefix) + ' ' + subtree(sys.prefix) + ')',
             '(allow file-read* ' + subtree(project / 'src') + ' ' + subtree(project / 'v4_planning') + ')',
             # openpyxl's MimeTypes initialization reads this public system DB.
             '(allow file-read* ' + literal('/etc/apache2/mime.types') + ')',
             '(allow file-read* ' + ' '.join(literal(path) for path in allowed_paths) + ')',
             '(allow file-read* file-write* (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom"))']
    if remote_sockets:
        rules.append('(allow network-outbound ' + ' '.join('(remote unix-socket (path-literal ' + json.dumps(str(path)) + '))' for path in remote_sockets) + ')')
    if listener_socket is not None:
        rules.extend(['(allow file-write* ' + literal(listener_socket) + ')',
            '(allow network-bind network-inbound (local unix-socket (path-literal ' + json.dumps(str(listener_socket)) + ')))'])
    profile = root / 'intake.sb'
    profile.write_text('\n'.join(rules))
    profile.chmod(0o600)
    return profile


KERNEL_PROBE = r'''
# Runs before project imports and before the Python audit hook is installed.
import errno, subprocess
denied = 0
for path in value["kernel_probe_paths"]:
    try:
        opened = os.open(path, os.O_RDONLY)
    except PermissionError:
        denied += 1
    else:
        os.close(opened)
        raise AssertionError("OS private-input denial failed")
parent = os.open(str(Path(value["kernel_probe_paths"][0]).parent), os.O_RDONLY | os.O_DIRECTORY)
try:
    try:
        opened = os.open(Path(value["kernel_probe_paths"][0]).name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
    except PermissionError:
        denied += 1
    else:
        os.close(opened)
        raise AssertionError("OS descriptor-relative denial failed")
finally:
    os.close(parent)
child_code = "import sys,resource\nfrom pathlib import Path\nresource.setrlimit(resource.RLIMIT_CORE,(0,0))\nresource.setrlimit(resource.RLIMIT_FSIZE,(0,0))\nresource.setrlimit(resource.RLIMIT_CPU,(15,15))\ntry:\n Path(sys.argv[1]).read_bytes()\nexcept PermissionError:\n sys.exit(0)\nelse:\n sys.exit(3)\n"
child = subprocess.run([sys.executable, "-c", child_code, value["kernel_probe_paths"][0]],
    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
assert child.returncode == 0 and not child.stdout and not child.stderr
waiting = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"],
    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
waiting.kill()
waiting.wait(timeout=2)
assert not waiting.stdout.read() and not waiting.stderr.read()
waiting.stdout.close(); waiting.stderr.close()
try:
    os.kill(value["outside_process"], 0)
except PermissionError:
    pass
else:
    raise AssertionError("OS cross-role signal denial failed")
try:
    opened = os.open(value["unlisted_output"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
except PermissionError:
    pass
else:
    os.close(opened)
    raise AssertionError("OS unlisted persistence denial failed")
probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    try:
        probe.connect(("127.0.0.1", 9))
    except PermissionError as error:
        assert error.errno in (errno.EPERM, errno.EACCES)
    else:
        raise AssertionError("OS unlisted-network denial failed")
finally:
    probe.close()
assert denied == len(value["kernel_probe_paths"]) + 1
'''

@pytest.mark.parametrize("kind,kernel,session,parent_mode", [("csv", False, False, None), ("encrypted", False, False, None),
    ("csv", True, False, None), ("xlsm", True, False, None), ("encrypted", True, False, None), ("encrypted", True, True, None),
    pytest.param("csv", True, False, "success", id="parent-csv"),
    pytest.param("encrypted", True, True, "success", id="parent-encrypted-session"),
    pytest.param("encrypted", True, True, "lost-receipt", id="parent-lost-receipt")])
def test_real_private_submission_separated_roles_without_authority_inputs(kind, kernel, session, parent_mode, capfd, monkeypatch):
    if kernel and sys.platform != "darwin":
        pytest.skip("Native macOS isolation is required for this qualification")
    with tempfile.TemporaryDirectory(prefix="fpais-", dir=Path("/tmp").resolve()) as directory:
        root = Path(directory)
        fixture = setup(root)
        binding, _, _ = prepared(root, kind)
        channel = fixture["binding"]
        binding = replace(binding, issuer=channel.issuer, subject="operator", planning_resource=channel.planning_resource,
            intake_resource=channel.intake_resource, planning_client=fixture["planning_client"],
            intake_client=fixture["intake_client"], deployment_digest=channel.deployment_digest,
            workload_digest=channel.workload_digest, issued_at=channel.issued_at, expires_at=channel.expires_at)
        verified = asyncio.run(ProviderTokenVerifier(fixture["issuer"]).verify_token(fixture["planning_token"]))
        principal = planning_principal_from_access_token(verified, V4PlanningAuthorizationSettings(
            expected_resource=channel.planning_resource, namespace_hmac_key=b"N" * 32))
        _, permission, grant_kwargs, _ = source(root, binding, [int(time.time())], requester=principal.requester.digest)
        assert grant_kwargs["reference_kind"] == REFERENCE_KIND
        settings = asdict(fixture["issuer"].settings)
        settings["database_path"] = str(settings["database_path"])
        channel_options = paths(fixture["options"])
        issuer_input = dict(settings=settings, binding=asdict(channel),
            request_key_path=channel_options["request_key_path"], request_key_sha256=channel_options["request_key_sha256"],
            signing_key_path=str(fixture["signing_key"]), signing_key_sha256=fixture["signing_sha"],
            socket_path=channel_options["socket_path"])
        reference_input = dict(database=str(root / "reference/state.sqlite"), key=str(root / "reference/reference.key"),
            checkpoint_socket=str(root / "checkpoint.sock"),
            checkpoint_authority=CHECKPOINT, authority=AUTHORITY, store=STORE, socket_path=str(root / "reference.sock"))
        checkpoint_input = dict(database=str(root / "checkpoint/state.sqlite"), key=str(root / "checkpoint/checkpoint.key"),
            authority=CHECKPOINT, socket_path=reference_input["checkpoint_socket"])
        bootstrap_input = root / "owner-reference-input.json"
        bootstrap_input.write_text(json.dumps(dict(environment_ref=grant_kwargs["environment_ref"],
            expires_at=binding.expires_at, references=[dict(reference=REFERENCE, reference_kind=REFERENCE_KIND)],
            requester_digest=principal.requester.digest, scope_ref=grant_kwargs["scope_ref"])))
        bootstrap_input.chmod(0o600)
        bootstrap = ReferenceGrantBootstrapSettings(Path(reference_input["database"]), Path(reference_input["key"]),
            AUTHORITY, bootstrap_input, root / "owner-reference-output.json", Path(checkpoint_input["socket_path"]), CHECKPOINT, STORE)
        policy_key = root / "admission.key"
        policy_key.write_bytes(os.urandom(32))
        policy_key.chmod(0o600)
        policy = dict(policy_path=root / "admission.json", key_path=policy_key,
                      key_sha256=hashlib.sha256(policy_key.read_bytes()).hexdigest())
        permission = paths({key: item for key, item in permission.items() if key not in ("authority", "clock")})
        intake_input = dict(source=paths(asdict(binding)), channel=asdict(channel), channel_options=channel_options,
            policy=paths(policy), permission=permission, reference_socket=reference_input["socket_path"],
            socket_path=str(root / "project.sock"))
        parent_inputs = []
        if parent_mode is not None:
            from fortipam_mcp import secret_bulk_import_parent_handoff as handoff
            from fortipam_mcp.secret_bulk_import_intake_authority import PinnedOwnerFileIntakeAuthority
            from v4_planning.import_parent import FileImportParentRecord
            from test_v4_persistence import _ExternalCheckpoint, _new_store, CHECKPOINT_STORE_REF
            now = int(time.time())
            parent_store, parent_database, parent_key = _new_store(root, now_epoch=now,
                monotonic_checkpoint=_ExternalCheckpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)
            # The parent is now created after real process startup. Its store
            # must use the same advancing wall clock as the Owner receiver.
            monkeypatch.setattr(parent_store, '_clock', lambda: int(time.time()))
            original_parent_ref = 'file-import-parent-01'
            namespace_key = root / 'original-parent.key'
            namespace_key.write_bytes(os.urandom(32))
            namespace_key.chmod(0o600)
            parent_inputs = [str(parent_database), str(parent_key), str(namespace_key)]
        session_bootstrap = None
        if session:
            session_input = root / "owner-session-reference-input.json"
            session_reference = "owner-source-session-reference-02"
            scope_key = Path(permission['scope_key_path']).read_bytes()
            session_input.write_text(json.dumps(dict(environment_ref=grant_kwargs["environment_ref"],
                expires_at=binding.expires_at, references=[dict(reference=session_reference, reference_kind=SESSION_REFERENCE_KIND)],
                requester_digest=principal.requester.digest,
                scope_ref=source_session_scope_ref(binding, bytearray(scope_key)))))
            session_input.chmod(0o600)
            session_bootstrap = replace(bootstrap, input_path=session_input, output_path=root / "owner-session-reference-output.json")
            session_key = root / "session-admission.key"
            session_key.write_bytes(os.urandom(32))
            session_key.chmod(0o600)
            intake_input['session_policy'] = dict(policy_path=str(root / "session-admission.json"),
                key_path=str(session_key), key_sha256=hashlib.sha256(session_key.read_bytes()).hexdigest())
            intake_input['session_permission'] = dict(permission, reference=session_reference)
        startup_path = root / "private-startup.json"
        intake_input['profile_path'] = str(startup_path)
        profile, script = None, INTAKE_SERVER
        if kernel:
            assert Path('/usr/bin/sandbox-exec').is_file(), 'Native test policy runner is unavailable'
            intake_input['kernel_probe_paths'] = [str(fixture['signing_key']), str(root / 'reference/reference.key'),
                                                 str(root / 'checkpoint/checkpoint.key'), str(fixture['issuer'].settings.database_path)]
            alias = root / 'signing-alias.key'
            alias.symlink_to(fixture['signing_key'])
            intake_input['kernel_probe_paths'].append(str(alias))
            intake_input['kernel_probe_paths'].extend(parent_inputs)
            intake_input['unlisted_output'] = str(root / 'unlisted-output.bin')
            profile = native_intake_profile(root, intake_input)
            script = INTAKE_SERVER.replace('sys.addaudithook(guard)', KERNEL_PROBE + '\nsys.addaudithook(guard)')
        from fortipam_mcp.secret_bulk_import_submission import CONTENT_TYPE, PATH
        # Signal0 checks kernel permission without changing the control process.
        intake_input['outside_process'] = os.getpid()
        with running(CHECKPOINT_SERVER, checkpoint_input, root):
            bootstrap_reference_grants(bootstrap)
            if session_bootstrap is not None:
                bootstrap_reference_grants(session_bootstrap)
            with running(SERVER, issuer_input, root), running(REFERENCE_SERVER, reference_input, root):
                remote = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(Path(reference_input["socket_path"]), AUTHORITY))
                eligibility = ReferenceOwnerFileEligibility(binding, **dict(permission, authority=remote,
                    scope_key_path=Path(permission['scope_key_path'])))
                policy['policy_sha256'] = issue_prebound_owner_file_policy_once(binding, **policy, eligibility=eligibility)
                intake_input['policy'] = paths(policy)
                if session:
                    session_eligibility = ReferenceOwnerFileSessionEligibility(binding,
                        **dict(intake_input['session_permission'], authority=remote,
                               scope_key_path=Path(permission['scope_key_path'])))
                    session_policy = intake_input['session_policy']
                    session_policy['policy_sha256'] = issue_prebound_owner_file_session_policy_once(binding,
                        **dict(session_policy, policy_path=Path(session_policy['policy_path']),
                               key_path=Path(session_policy['key_path'])), eligibility=session_eligibility)
                snapshot = replace(catalog(), scope_digest=binding.scope_digest)
                metadata = asdict(snapshot)
                for field in ("coverage", "service_types"):
                    metadata[field] = sorted(metadata[field])
                startup_value = dict(contract=CONTRACT, purpose="private-dependency-projection-only",
                    source=intake_input["source"], channel=intake_input["channel"], channel_options=channel_options,
                    permission=dict(permission, socket_path=reference_input["socket_path"]),
                    policy=intake_input["policy"], catalog=metadata)
                startup_bytes = json.dumps(startup_value).encode()
                startup_path.write_bytes(startup_bytes)
                startup_path.chmod(0o600)
                intake_input['profile_sha256'] = hashlib.sha256(startup_bytes).hexdigest()
                with ExitStack() as stack:
                    inherited = ()
                    if parent_mode is not None:
                        left, right = socket.socketpair()
                        stack.callback(left.close)
                        stack.callback(right.close)
                        owner_permission = PinnedOwnerFileIntakeAuthority(binding, **policy, human_owner_verifier=eligibility)
                        receiver = handoff._OriginalParentReceiver(left, binding, snapshot, store=parent_store,
                            authority=owner_permission, plan_ref=original_parent_ref, plan_digest=None,
                            requester_digest=principal.requester.digest, parent_idempotency_digest='8' * 64,
                            key_path=namespace_key, key_sha256=hashlib.sha256(namespace_key.read_bytes()).hexdigest(),
                            standing_lab_authorization=True)
                        stack.callback(receiver.close)
                        endpoint = receiver._endpoint
                        intake_input['parent_handoff'] = dict(fd=right.fileno(), context_digest=endpoint._context,
                                                             deadline=endpoint._deadline)
                        inherited = (right.fileno(),)
                        if parent_mode == 'lost-receipt':
                            send = handoff._send
                            def lose_receipt(peer, deadline, payload):
                                if peer is left:
                                    raise OSError('Synthetic lost parent receipt')
                                return send(peer, deadline, payload)
                            monkeypatch.setattr(handoff, '_send', lose_receipt)
                        pool = stack.enter_context(ThreadPoolExecutor(max_workers=1))
                        future = pool.submit(receiver.receive_once)
                        protected = [binding.path, parent_key, namespace_key, policy_key, Path(policy['policy_path'])]
                        unchanged = {path: hashlib.sha256(path.read_bytes()).digest() for path in protected}
                    report = stack.enter_context(running(script, intake_input, root, report=True,
                        sandbox_profile=profile, pass_fds=inherited))
                    if parent_mode is not None:
                        right.close()
                    with httpx.Client(transport=httpx.HTTPTransport(uds=intake_input["socket_path"]),
                        base_url="http://private-owner-file", timeout=10, trust_env=False, follow_redirects=False) as client:
                        invalid = dict(fixture, planning_token=fixture["intake_token"], intake_token=fixture["planning_token"])
                        denied = client.post(PATH, content=frame(invalid), headers={"Content-Type": CONTENT_TYPE})
                        assert denied.status_code == 409 and denied.json() == {"status": "unavailable"}
                        positive = client.post(PATH, content=frame(fixture, b"synthetic-password" if kind == "encrypted" else b""),
                            headers={"Content-Type": CONTENT_TYPE})
                        if parent_mode == 'lost-receipt':
                            assert positive.status_code == 409 and positive.json() == {'status': 'unavailable'}
                            with pytest.raises(handoff.BulkImportIntakeError):
                                future.result(timeout=3)
                        else:
                            assert positive.status_code == 200 and positive.json() == {"status": "projected", "rows": 1, "targets": 1}
                            if parent_mode is not None:
                                original_rows, graph, compiled = future.result(timeout=3)
                                assert len(compiled.steps) == 2
                                assert compiled.steps[1].idempotency_digest == original_rows.row(0).idempotency_digest
                                original_rows._verify_dependencies_binding(binding, graph, snapshot,
                                    authenticated_requester_digest=principal.requester.digest)
                        repeated = client.post(PATH, content=frame(fixture), headers={"Content-Type": CONTENT_TYPE})
                        assert repeated.status_code == 409 and repeated.json() == {"status": "unavailable"}
                    if parent_mode is not None:
                        original_parent = parent_store.get_import_parent(original_parent_ref)
                        assert type(original_parent) is FileImportParentRecord and len(original_parent.lines) == 2
                        record = parent_store.get_original_import_binding(original_parent.plan_ref,
                            expected_plan_digest=original_parent.plan_digest, requester_digest=principal.requester.digest,
                            namespace_key_digest=receiver._key_digest)
                        assert record.row_count == 1
                        assert original_parent.plan_digest == receiver._plan_digest
                        with pytest.raises(handoff.BulkImportIntakeError):
                            receiver.receive_once()
                        assert all(hashlib.sha256(path.read_bytes()).digest() == digest for path, digest in unchanged.items())
                assert report == dict(authority_inputs_unread=True, rejected_requests_did_not_read_source=True,
                                      authenticated_projection_read_source=True, mutable_frames_cleared=True,
                                      **({'retained_unlocks_cleared_at_shutdown': True} if session else {}),
                                      **({'parent_handoff_closed_once': True} if parent_mode is not None else {}))
    assert capfd.readouterr() == ("", "")
