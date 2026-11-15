"""Private signed verification with synthetic local OAuth and process fixtures."""

import asyncio
from dataclasses import asdict, replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
import pytest
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_token_channel as channel
from test_secret_bulk_import_intake import prepared
from test_secret_bulk_import_oauth import PRIMARY, PRIVATE, fixture as oauth_fixture, issue


def write(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)
    return hashlib.sha256(raw).hexdigest()


def setup(tmp_path):
    issuer, oauth_client = oauth_fixture(tmp_path)
    shared, private = tmp_path / "channel", tmp_path / "issuer-private"
    shared.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    request_key, signer_key, public_key = shared / "request.key", private / "signing.key", shared / "issuer.pub"
    request_sha = write(request_key, b"R" * 32)
    signing_sha = write(signer_key, b"S" * 32)
    public_sha = write(public_key, Ed25519PrivateKey.from_private_bytes(b"S" * 32).public_key().public_bytes_raw())
    now = int(time.time())
    binding = channel.IntakeTokenChannelBinding(issuer.settings.issuer, PRIMARY, PRIVATE, "1" * 64, "2" * 64,
                                                now - 1, now + 120)
    app = channel.create_intake_token_verification_app(
        issuer, binding, request_key_path=request_key, request_key_sha256=request_sha,
        signing_key_path=signer_key, signing_key_sha256=signing_sha,
    )
    options = dict(socket_path=shared / "verify.sock", request_key_path=request_key,
                   request_key_sha256=request_sha, public_key_path=public_key, public_key_sha256=public_sha)
    with oauth_client:
        planner, planner_token, _ = issue(oauth_client)
        owner, owner_token, _ = issue(oauth_client, private=True)
    return dict(issuer=issuer, binding=binding, app=app, options=options, signing_key=signer_key,
                signing_sha=signing_sha, planning_client=planner, intake_client=owner,
                planning_token=planner_token["access_token"], intake_token=owner_token["access_token"])


def mock_client(fixture, monkeypatch, *, planning=False, app=None):
    monkeypatch.setattr(channel, "_socket_identity", lambda path: (1, 2, 3, 4, 5))
    monkeypatch.setattr(channel.httpx, "AsyncHTTPTransport",
                        lambda **kwargs: httpx.ASGITransport(app=app or fixture["app"]))
    return channel.UnixIntakeTokenVerifier(fixture["binding"], planning=planning, **fixture["options"])


def request(fixture, *, planning=False):
    payload = dict(contract=channel.CONTRACT, purpose="planning" if planning else "intake",
                   deployment_digest="1" * 64, workload_digest="2" * 64, nonce="a" * 32,
                   issued_at=int(time.time()), token=fixture["planning_token" if planning else "intake_token"])
    seal = hmac.new(b"R" * 32, channel._REQUEST_DOMAIN + channel._canonical(payload), hashlib.sha256).hexdigest()
    return {"payload": payload, "seal": seal}


def test_signed_rpc_verifies_both_resources_revocation_and_no_token_echo(tmp_path, monkeypatch, capfd):
    fixture = setup(tmp_path)
    private = mock_client(fixture, monkeypatch)
    planning = mock_client(fixture, monkeypatch, planning=True)
    own = asyncio.run(private.verify_token(fixture["intake_token"]))
    plan = asyncio.run(planning.verify_token(fixture["planning_token"]))
    assert own and plan and own.subject == plan.subject == "operator"
    assert own.resource == PRIVATE and plan.resource == PRIMARY
    assert asyncio.run(private.verify_token(fixture["planning_token"])) is None
    assert asyncio.run(planning.verify_token(fixture["intake_token"])) is None
    with TestClient(fixture["app"]) as client:
        response = client.post(channel._PREFIX + "intake", json=request(fixture))
        assert response.status_code == 200
        assert fixture["intake_token"].encode() not in response.content
    asyncio.run(fixture["issuer"].revoke_token(own))
    assert asyncio.run(private.verify_token(fixture["intake_token"])) is None
    assert asyncio.run(planning.verify_token(fixture["planning_token"])) is not None
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("fault", ["seal", "workload", "deployment", "purpose", "stale", "extra", "duplicate", "oversize"])
def test_server_rejects_unbound_or_malformed_request_without_reflection(tmp_path, fault):
    fixture = setup(tmp_path)
    value = request(fixture)
    if fault == "seal":
        value["seal"] = "0" * 64
    elif fault == "workload":
        value["payload"]["workload_digest"] = "3" * 64
    elif fault == "deployment":
        value["payload"]["deployment_digest"] = "3" * 64
    elif fault == "purpose":
        value["payload"]["purpose"] = "planning"
    elif fault == "stale":
        value["payload"]["issued_at"] -= 11
    elif fault == "extra":
        value["payload"]["endpoint"] = "/arbitrary"
    raw = channel._canonical(value)
    if fault == "duplicate":
        raw = raw.replace(b'"contract":', b'"contract":"other","contract":', 1)
    elif fault == "oversize":
        raw += b" " * channel._MAX_FRAME
    with TestClient(fixture["app"]) as client:
        response = client.post(channel._PREFIX + "intake", content=raw, headers={"Content-Type": "application/json"})
        assert response.status_code == 409 and response.json() == {"status": "unavailable"}
        assert fixture["intake_token"].encode() not in response.content


@pytest.mark.parametrize("fault", ["signature", "request-key-forgery", "nonce", "seal", "workload", "resource", "expired", "bool-expiry", "duplicate", "oversize", "redirect", "compressed"])
def test_client_rejects_forged_uncorrelated_or_invalid_reply(tmp_path, monkeypatch, fault):
    fixture = setup(tmp_path)

    async def transport(request):
        envelope = json.loads(request.content)
        sent = envelope["payload"]
        identity = dict(iss=fixture["binding"].issuer, sub="operator", client_id=fixture["intake_client"],
                        resource=PRIVATE, scopes=["fortipam:bulk-import-intake"], expires_at=int(time.time()) + 60)
        payload = dict(contract=channel.CONTRACT, purpose="intake", deployment_digest="1" * 64,
                       workload_digest="2" * 64, nonce=sent["nonce"], request_seal=envelope["seal"],
                       observed_at=sent["issued_at"], identity=identity)
        if fault == "nonce":
            payload["nonce"] = "b" * 32
        elif fault == "seal":
            payload["request_seal"] = "0" * 64
        elif fault == "workload":
            payload["workload_digest"] = "0" * 64
        elif fault == "resource":
            identity["resource"] = PRIMARY
        elif fault == "expired":
            identity["expires_at"] = int(time.time())
        elif fault == "bool-expiry":
            identity["expires_at"] = True
        key = b"R" * 32 if fault == "request-key-forgery" else b"S" * 32
        signature = Ed25519PrivateKey.from_private_bytes(key).sign(channel._RESPONSE_DOMAIN + channel._canonical(payload)).hex()
        if fault == "signature":
            signature = "0" * 128
        raw = channel._canonical({"payload": payload, "seal": signature})
        if fault == "duplicate":
            raw = raw.replace(b'"nonce":', b'"nonce":"other","nonce":', 1)
        elif fault == "oversize":
            raw += b" " * channel._MAX_FRAME
        return httpx.Response(302 if fault == "redirect" else 200, content=raw,
                              headers={"Content-Type": "application/json", **({"Content-Encoding": "gzip"} if fault == "compressed" else {})})

    private = mock_client(fixture, monkeypatch)
    monkeypatch.setattr(channel.httpx, "AsyncHTTPTransport", lambda **kwargs: httpx.MockTransport(transport))
    with pytest.raises(channel.IntakeTokenChannelError, match="Private intake token verification unavailable"):
        asyncio.run(private.verify_token(fixture["intake_token"]))


@pytest.mark.parametrize("fault", ["key-inode", "public-key", "key-mode", "socket", "expired", "rollback"])
def test_client_custody_or_lifetime_change_denies_before_io(tmp_path, monkeypatch, fault):
    fixture = setup(tmp_path)
    now = int(time.time())
    private = mock_client(fixture, monkeypatch)
    private._lifetime.clock = lambda: now
    if fault == "key-inode":
        path = fixture["options"]["request_key_path"]
        replacement = path.with_name("replacement.key")
        write(replacement, b"R" * 32)
        replacement.replace(path)
    elif fault == "public-key":
        write(fixture["options"]["public_key_path"], b"X" * 32)
    elif fault == "key-mode":
        fixture["options"]["request_key_path"].chmod(0o644)
    elif fault == "socket":
        monkeypatch.setattr(channel, "_socket_identity", lambda path: (9, 2, 3, 4, 5))
    elif fault == "expired":
        now = fixture["binding"].expires_at
    else:
        now = private._lifetime.wall - 1
    monkeypatch.setattr(channel.httpx, "AsyncHTTPTransport", lambda **kwargs: pytest.fail("Drift reached network"))
    with pytest.raises(channel.IntakeTokenChannelError):
        asyncio.run(private.verify_token(fixture["intake_token"]))


@pytest.mark.parametrize("outcome", ["success", "signature-error", "public-load-error", "cancel"])
def test_client_owned_buffers_clear_on_success_failure_and_cancellation(tmp_path, monkeypatch, outcome):
    fixture = setup(tmp_path)
    private = mock_client(fixture, monkeypatch)
    buffers = []
    original = channel._PinnedKey.load

    def key_load(self):
        value = original(self)
        buffers.append(value)
        return value

    def allocate(value=b""):
        raw = bytearray(value)
        buffers.append(raw)
        return raw

    monkeypatch.setattr(channel._PinnedKey, "load", key_load)
    monkeypatch.setattr(channel, "bytearray", allocate, raising=False)
    if outcome == "public-load-error":
        fixture["options"]["public_key_path"].chmod(0o644)
    elif outcome in {"signature-error", "cancel"}:
        async def transport(request):
            if outcome == "cancel":
                raise asyncio.CancelledError
            return httpx.Response(200, json={"payload": {}, "seal": "0" * 128})
        monkeypatch.setattr(channel.httpx, "AsyncHTTPTransport", lambda **kwargs: httpx.MockTransport(transport))
    if outcome == "success":
        assert asyncio.run(private.verify_token(fixture["intake_token"])) is not None
    else:
        with pytest.raises(asyncio.CancelledError if outcome == "cancel" else channel.IntakeTokenChannelError):
            asyncio.run(private.verify_token(fixture["intake_token"]))
    assert buffers and all(not any(buffer) for buffer in buffers)


@pytest.mark.parametrize("fault", ["wall-rollback", "monotonic-expiry"])
def test_server_lifetime_failure_cannot_resume_when_clock_recovers(tmp_path, monkeypatch, fault):
    fixture = setup(tmp_path)
    clocks = [int(time.time()), 100.0]
    app = channel.create_intake_token_verification_app(
        fixture["issuer"], fixture["binding"],
        request_key_path=fixture["options"]["request_key_path"], request_key_sha256=fixture["options"]["request_key_sha256"],
        signing_key_path=fixture["signing_key"], signing_key_sha256=fixture["signing_sha"],
        clock=lambda: clocks[0], monotonic=lambda: clocks[1],
    )
    original = channel.OwnerFileIntakeTokenVerifier.verify_token
    changed = False

    async def delayed(self, token):
        nonlocal changed
        result = await original(self, token)
        if not changed:
            changed = True
            if fault == "wall-rollback":
                clocks[0] -= 1
            else:
                clocks[1] += 901
        return result

    monkeypatch.setattr(channel.OwnerFileIntakeTokenVerifier, "verify_token", delayed)
    with TestClient(app) as client:
        assert client.post(channel._PREFIX + "intake", json=request(fixture)).status_code == 409
        clocks[:] = [int(time.time()), 100.0]
        assert client.post(channel._PREFIX + "intake", json=request(fixture)).status_code == 409


@pytest.mark.parametrize("fault", ["request-key", "public-key"])
def test_client_rechecks_key_custody_after_valid_response(tmp_path, monkeypatch, fault):
    fixture = setup(tmp_path)
    private = mock_client(fixture, monkeypatch)

    async def transport(request):
        sent = json.loads(request.content)
        with TestClient(fixture["app"]) as client:
            response = client.post(channel._PREFIX + "intake", json=sent)
            assert response.status_code == 200
        path = fixture["options"]["request_key_path" if fault == "request-key" else "public_key_path"]
        path.chmod(0o644)
        return httpx.Response(200, content=response.content, headers={"Content-Type": "application/json"})

    monkeypatch.setattr(channel.httpx, "AsyncHTTPTransport", lambda **kwargs: httpx.MockTransport(transport))
    with pytest.raises(channel.IntakeTokenChannelError):
        asyncio.run(private.verify_token(fixture["intake_token"]))


SERVER = r'''
import json, logging, os, socket, sys, threading
from pathlib import Path
import uvicorn
from fortipam_mcp.local_oauth import LocalOAuthSettings
from fortipam_mcp.secret_bulk_import_oauth import OwnerFileIntakeOAuthCandidate
from fortipam_mcp.secret_bulk_import_token_channel import IntakeTokenChannelBinding, create_intake_token_verification_app
value = json.loads(sys.stdin.readline())
settings = value["settings"]
settings["database_path"] = Path(settings["database_path"])
for name in ("available_scopes", "default_scopes"):
    settings[name] = tuple(settings[name])
issuer = OwnerFileIntakeOAuthCandidate(LocalOAuthSettings(**settings), intake_resource=value["binding"]["intake_resource"])
app = create_intake_token_verification_app(issuer, IntakeTokenChannelBinding(**value["binding"]),
    request_key_path=Path(value["request_key_path"]), request_key_sha256=value["request_key_sha256"],
    signing_key_path=Path(value["signing_key_path"]), signing_key_sha256=value["signing_key_sha256"])
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

WORKER = r'''
import asyncio, json, os, sys
from pathlib import Path
value = json.loads(sys.stdin.readline())
attempts = []
def guard(event, args):
    if event == "sqlite3.connect":
        attempts.append(True)
        raise PermissionError("Private issuer/source boundary")
    if event == "open" and isinstance(args[0], (str, bytes)):
        components = Path(os.fsdecode(args[0])).parts
        if set(components).intersection({"oauth-state", "issuer-private", "signing.key", "source.csv"}):
            attempts.append(True)
            raise PermissionError("Private issuer/source boundary")
sys.addaudithook(guard)
from fortipam_mcp import secret_bulk_import_intake as intake
from fortipam_mcp.secret_bulk_import_token_channel import IntakeTokenChannelBinding, UnixIntakeTokenVerifier
options = value["options"]
for name in ("socket_path", "request_key_path", "public_key_path"):
    options[name] = Path(options[name])
binding = IntakeTokenChannelBinding(**value["binding"])
planning = UnixIntakeTokenVerifier(binding, planning=True, **options)
private = UnixIntakeTokenVerifier(binding, planning=False, **options)
class DenyOwner:
    def verify(self, binding, *, now_epoch):
        raise ValueError("Owner authority unavailable")
async def run():
    plan = await planning.verify_token(value["planning_token"])
    own = await private.verify_token(value["intake_token"])
    assert plan is not None and own is not None
    assert plan.subject == own.subject and plan.client_id != own.client_id
    assert await planning.verify_token(value["intake_token"]) is None
    assert await private.verify_token(value["planning_token"]) is None
    source = value["source"]
    source["path"] = Path(source["path"])
    owner_binding = intake.OwnerFileIntakeBinding(**source)
    try:
        await intake.admit_prebound_owner_file(owner_binding,
            planning_token=value["planning_token"], intake_token=value["intake_token"],
            planning_verifier=planning, intake_verifier=private, authority=DenyOwner())
    except intake.BulkImportIntakeError:
        pass
    else:
        raise AssertionError("Owner authority bypass")
    assert not attempts
    print(json.dumps({"paired_identity_verified": True, "resource_substitution_denied": True,
        "issuer_inputs_unread": True, "source_denied_without_owner": True}))
asyncio.run(run())
'''


def test_worker_audit_guard_denies_dirfd_private_reads_and_path_database_input(tmp_path):
    # Exercise the actual guard installed by the fresh-worker proof, including
    # descriptor-relative no-follow reads that omit the full private path.
    for name in ("source.csv", "signing.key", "db.sqlite"):
        (tmp_path / name).write_bytes(b"synthetic-guard-fixture")
    script = WORKER.split("from fortipam_mcp import", 1)[0] + r'''
import sqlite3
descriptor = os.open(value["root"], os.O_RDONLY | os.O_DIRECTORY)
try:
    for name in ("source.csv", "signing.key"):
        try:
            opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=descriptor)
        except PermissionError:
            pass
        else:
            os.close(opened)
            raise AssertionError("Descriptor-relative private read was not denied")
finally:
    os.close(descriptor)
for database in (str(Path(value["root"]) / "db.sqlite"), Path(value["root"]) / "db.sqlite"):
    try:
        opened = sqlite3.connect(database)
    except PermissionError:
        pass
    else:
        opened.close()
        raise AssertionError("Private database input was not denied")
assert len(attempts) == 4
print(json.dumps({"relative_private_reads_denied": True, "database_inputs_denied": True}))
'''
    result = subprocess.run([sys.executable, "-c", script], input=json.dumps({"root": str(tmp_path)}).encode() + b"\n",
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": os.defpath}, cwd=tmp_path, timeout=5)
    assert result.returncode == 0, "Private audit guard regression failed"
    assert result.stderr == b"", "Private audit guard emitted diagnostics"
    assert json.loads(result.stdout) == {"relative_private_reads_denied": True, "database_inputs_denied": True}


@pytest.fixture
def private_uds_root():
    with tempfile.TemporaryDirectory(prefix="fpai-", dir=Path("/tmp").resolve()) as root:
        yield Path(root)


def test_fresh_intake_process_verifies_over_real_uds_without_issuer_inputs(private_uds_root, capfd):
    tmp_path = private_uds_root
    fixture = setup(tmp_path)
    source, _, _ = prepared(tmp_path)
    now = int(time.time())
    source = replace(source, issuer=fixture["binding"].issuer, subject="operator", planning_resource=PRIMARY,
                     intake_resource=PRIVATE, planning_client=fixture["planning_client"], intake_client=fixture["intake_client"],
                     issued_at=now - 1, expires_at=now + 60)
    # Rename the synthetic input to make any attempted read observable in child.
    original = source.path
    renamed = original.with_name("source.csv")
    original.rename(renamed)
    source = replace(source, path=renamed)
    options = {name: str(value) if isinstance(value, Path) else value for name, value in fixture["options"].items()}
    settings = asdict(fixture["issuer"].settings)
    settings["database_path"] = str(settings["database_path"])
    server_input = dict(settings=settings, binding=asdict(fixture["binding"]),
                        request_key_path=options["request_key_path"], request_key_sha256=options["request_key_sha256"],
                        signing_key_path=str(fixture["signing_key"]), signing_key_sha256=fixture["signing_sha"],
                        socket_path=options["socket_path"])
    project = Path(__file__).resolve().parents[1]
    environment = {"PATH": os.defpath, "PYTHONPATH": str(project / "src") + os.pathsep + str(project),
                   "PYTHONUNBUFFERED": "1"}
    server = subprocess.Popen([sys.executable, "-c", SERVER], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=environment, cwd=fixture["options"]["socket_path"].parent)
    try:
        server.stdin.write(json.dumps(server_input).encode() + b"\n")
        server.stdin.flush()
        deadline = time.monotonic() + 5
        while not fixture["options"]["socket_path"].exists():
            assert server.poll() is None, "Private verifier stopped before socket bind"
            assert time.monotonic() < deadline, "Private verifier did not bind"
            time.sleep(0.02)
        child_input = dict(binding=asdict(fixture["binding"]), options=options,
                           planning_token=fixture["planning_token"], intake_token=fixture["intake_token"], source=asdict(source))
        child_input["source"]["path"] = str(source.path)
        worker = subprocess.run([sys.executable, "-c", WORKER], input=json.dumps(child_input).encode() + b"\n",
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                                cwd=fixture["options"]["socket_path"].parent, timeout=10)
        assert worker.returncode == 0, "Private intake child failed"
        assert worker.stderr == b"", "Private intake child emitted diagnostics"
        assert json.loads(worker.stdout) == dict(paired_identity_verified=True, resource_substitution_denied=True,
                                                issuer_inputs_unread=True, source_denied_without_owner=True)
    finally:
        if server.poll() is None:
            try:
                server.stdin.write(b"stop\n")
                server.stdin.flush()
            except BrokenPipeError:
                pass
        server.stdin.close()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)
        diagnostics = server.stdout.read() or server.stderr.read()
        server.stdout.close()
        server.stderr.close()
        if diagnostics:
            raise AssertionError("Private verifier emitted diagnostics")
    assert server.returncode == 0
    assert not fixture["options"]["socket_path"].exists()
    assert capfd.readouterr() == ("", "")
