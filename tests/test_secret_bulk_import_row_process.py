"""Actual isolated encrypted row decoding; synthetic identity, no device writer."""

from contextlib import ExitStack
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import socket
import subprocess
import sys
import threading
import time

import pytest
from starlette.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
import uvicorn

from fortipam_mcp import secret_bulk_import_row_channel as boundary
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_m4_execution_store import _Adapter, _Verifier
from test_secret_bulk_import_row_channel import channel
from test_secret_bulk_import_submission_process import KERNEL_PROBE, native_private_input_profile
from v4_planning import M4AdapterAmbiguous, M4ExecutionKernel, M4Verification


WORKER = r'''
import asyncio, hashlib, json, os, socket, sys
from pathlib import Path
value = json.loads(sys.stdin.buffer.readline())
__KERNEL_PROBE__
private_paths = set(value["private_paths"])
private_names = {Path(path).name for path in private_paths}
def guard(event, args):
    if event == "sqlite3.connect":
        raise PermissionError("Private authority unavailable")
    if event == "open" and args and isinstance(args[0], (str, bytes)):
        path = os.fsdecode(args[0])
        if path in private_paths or Path(path).name in private_names:
            raise PermissionError("Private authority unavailable")
sys.addaudithook(guard)

from mcp.server.auth.provider import AccessToken
from fortipam_mcp.secret_bulk_import_file import PinnedBulkImportFile
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError, OwnerFileIntakeBinding
from fortipam_mcp.secret_bulk_import_session import admit_prebound_owner_file_session
from fortipam_mcp.secret_bulk_import_row_channel import (
    OriginalRowChannelBinding, UnixOriginalRowChannelClient, _RemoteOriginalImportRowLoader,
)
from fortipam_mcp.secret_bulk_import_row_authority import _OriginalRowPermissionPins
from v4_planning import M4ExecutionPlan, M4ExecutionAuthorization

# Fixed synthetic admission isolates this test from previously qualified SDK login.
source_values = value["source"]
source_values["path"] = Path(source_values["path"])
source = OwnerFileIntakeBinding(**source_values)
class Verifier:
    def __init__(self, planning):
        self.planning = planning
    async def verify_token(self, token):
        client = source.planning_client if self.planning else source.intake_client
        return AccessToken(token="synthetic", client_id=client,
            scopes=["fortipam:plan" if self.planning else "fortipam:bulk-import-intake"],
            expires_at=1100, resource=source.planning_resource if self.planning else source.intake_resource,
            subject=source.subject, claims={"iss": source.issuer, "sub": source.subject, "client_id": client})
class SourceAuthority:
    def verify(self, binding, *, now_epoch):
        assert binding == source and now_epoch == 1000
    verify_source_session = verify
    def source_session_expires_at(self, binding, *, now_epoch):
        assert binding == source and now_epoch == 1000
        return 1100

plan = M4ExecutionPlan(**value["plan"])
auth = M4ExecutionAuthorization(**value["authorization"])
binding = OriginalRowChannelBinding(source, plan, auth,
    value["parent_digest"], value["namespace_key_sha256"],
    _OriginalRowPermissionPins(plan, auth, **value["permission"]),
    material_requested_at=1000 if value.get("material") else None,
    material_expires_at=1060 if value.get("material") else None,
    ack_pins_digest=value.get("ack_pins_digest"))
settings = value["channel"]
for name in ("socket_path", "request_key_path", "public_key_path"):
    settings[name] = Path(settings[name])
settings["clock"] = lambda: 1000
password = bytearray(b"synthetic-password")
session = asyncio.run(admit_prebound_owner_file_session(source,
    planning_token="synthetic-planning-token", intake_token="synthetic-intake-token",
    planning_verifier=Verifier(True), intake_verifier=Verifier(False),
    authority=SourceAuthority(), session_authority=SourceAuthority(), workbook_password=password,
    clock=lambda: 1000, monotonic=lambda: 100.0))
frames, unlocks = [], []
decode = PinnedBulkImportFile.decode
def observed(self, **options):
    unlocks.append(options["workbook_password"])
    frame = decode(self, **options)
    frames.append(frame._ProtectedBulkImportRows__raw)
    return frame
PinnedBulkImportFile.decode = observed
client = UnixOriginalRowChannelClient(binding, **settings)
loader = None
try:
    loader = _RemoteOriginalImportRowLoader(session, client, index=0,
        key_path=Path(value["namespace_key_path"]), key_sha256=value["namespace_key_sha256"])
    assert not any(password) and any(session._password)
    assert not any(hasattr(obj, name) for obj in (loader, client)
                   for name in ("_parent", "_execution", "_signer"))
    print(json.dumps({"ready": True}), flush=True)
    assert sys.stdin.buffer.readline() == b"load\n"
    from fortipam_mcp.secret_bulk_import_row_adapter import _OriginalRowSecretCreateAdapter, _OriginalRowUseContext
    from fortipam_mcp.secret_bulk_import_row_loader import _OwnedOriginalImportRow
    from v4_planning.secret_create_adapter import SecretCreateAdapterOutcome
    from v4_planning.material_runtime import MaterialRuntimeError, MaterialRuntimeOutcome
    rows, borrowed = [], []
    initialize = _OwnedOriginalImportRow.__init__
    def capture(self, *args):
        initialize(self, *args)
        rows.append(self)
    _OwnedOriginalImportRow.__init__ = capture
    denied = False
    class SyntheticNativeTransport:
        def _create_and_verify_with_original_row(self, context, columns, *, deadline):
            # All sixteen private values are checked inside intake, never returned.
            from fortipam_mcp._secret_bulk_import_worker import HEADERS
            fields = dict.fromkeys(HEADERS, "")
            fields.update({"Secret Template": "Web Account", "Name": "Original first row",
                "Folder": "Synthetic folder", "Service Type": "WEB", "Username": "synthetic-user",
                "Password/Passphrase": " synthetic-only,\r\n密码 ", "URL": "https://example.invalid",
                "Port": "443", "Description": "first description"})
            assert all(part.readonly for part in columns)
            assert [bytes(part) for part in columns] == [fields[name].encode() for name in HEADERS]
            borrowed.extend(columns)
            return SecretCreateAdapterOutcome.VERIFIED_CREATED
    adapter = _OriginalRowSecretCreateAdapter(loader,
        _OriginalRowUseContext(loader._row, client._binding.permission, 1000, 1060), SyntheticNativeTransport())
    if value.get("native_ack"):
        from fortipam_mcp import secret_bulk_import_row_http_transport as native_http
        from fortipam_mcp.secret_bulk_import_row_conversion import _Build29OriginalRowConversion
        from fortipam_mcp.secret_bulk_import_row_wire import _Build29OriginalRowWireEncoder, _READBACK_FIELDS
        from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
        from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
        from fortipam_mcp.secret_bulk_import_dependencies import (
            ImportDependencyCatalog, ImportFolder, ImportTemplate, ImportTemplateField, ImportTarget, ImportExistingSecret,
        )
        metadata = value["catalog"]
        metadata["folders"] = tuple(ImportFolder(**item) for item in metadata["folders"])
        metadata["templates"] = tuple(ImportTemplate(item["name"], tuple(ImportTemplateField(**field)
            for field in item["fields"])) for item in metadata["templates"])
        metadata["targets"] = tuple(ImportTarget(**item) for item in metadata["targets"])
        metadata["secrets"] = tuple(ImportExistingSecret(**item) for item in metadata["secrets"])
        metadata["secret_names"] = tuple(metadata["secret_names"])
        for name in ("coverage", "service_types"):
            metadata[name] = frozenset(metadata[name])
        catalog = ImportDependencyCatalog(**metadata)
        projected = session.project_dependencies_once(catalog)
        converter = _Build29OriginalRowConversion(adapter, catalog, projected,
            target_name="Synthetic resolved target", associated_secret_id=None)
        from fortipam_mcp.secret_bulk_import_row_wire import _project_build29_secret_wire_defaults
        defaults = _project_build29_secret_wire_defaults(bytearray(json.dumps(value["default_response"]).encode()),
            serial_digest=value["serial_digest"])
        encoder = _Build29OriginalRowWireEncoder(converter, defaults,
            expected_defaults_digest=defaults.digest(), expected_serial_digest=value["serial_digest"])
        class Tls:
            def set_alpn_protocols(self, protocols): assert protocols == ["http/1.1"]
        native_http._ssl_context = lambda _: Tls()
        responses, native_requests, native_views = [], [], []
        class NativeResponse:
            status = 200
            def __init__(self, payload):
                self.raw = bytearray(json.dumps(payload).encode())
                self.length, self.offset = len(self.raw), 0
                responses.append(self)
            def getheader(self, name):
                return {"Content-Type": "application/json", "Content-Length": str(self.length)}.get(name)
            def readinto1(self, part):
                count = min(len(part), len(self.raw) - self.offset)
                part[:count] = memoryview(self.raw)[self.offset:self.offset+count]
                self.offset += count
                return count
            def close(self):
                self.raw[:] = b"\0" * len(self.raw)
        class NativeConnection:
            def __init__(self, *_a, **_k): pass
            def request(self, method, path, body, headers):
                native_requests.append(method)
                if method == "POST":
                    native_views.append(body)
                    self.expected = json.loads(bytes(body))
                    native_expected.update(self.expected)
                    payload = dict(version="v7.0.0", build=29, path="secret", name="database", vdom="root",
                        http_method="POST", http_status=200, status="success", serial="Synthetic wire-default device", mkey=71, error=0)
                elif "action=default" in path:
                    payload = value["default_response"]
                else:
                    assert path == "/api/v2/cmdb/secret/database/71?vdom=root"
                    row = {key: item for key, item in native_expected.items() if key in _READBACK_FIELDS}
                    row.update(id=71, q_origin_key=71)
                    payload = dict(version="v7.0.0", build=29, path="secret", name="database", vdom="root",
                        http_method="GET", http_status=200, status="OK", serial="Synthetic wire-default device", results=row)
                self.response = NativeResponse(payload)
            def getresponse(self): return self.response
            def close(self): pass
        native_expected = {}
        if value.get("product_action"):
            from fortipam_mcp.secret_bulk_import_action_process import _receive_original_action_client
            product_client = _receive_original_action_client(socket.socket(fileno=value["product_handoff"]))
            assert not product_client._peer.get_inheritable()
            native = native_http._Build29OriginalRowHttpTransport(None, encoder,
                WebSecretCreateAckCapture(value["serial_digest"], "success"), product_client=product_client)
        else:
            native = native_http._Build29OriginalRowHttpTransport(
                SecretMetadataHttpTransportConfig("https://synthetic.example.test", "synthetic", 10, None),
                encoder, WebSecretCreateAckCapture(value["serial_digest"], "success"), connection_factory=NativeConnection)
        adapter._transport = native
    runtime = None
    if value.get("material"):
        from fortipam_mcp.secret_bulk_import_row_channel import _OriginalRowMaterialStateClient
        from fortipam_mcp.secret_bulk_import_row_provider import _OriginalRowMaterialRuntime
        material_state = _OriginalRowMaterialStateClient(client, adapter._context, session)
        runtime = _OriginalRowMaterialRuntime(adapter, material_state)
        assert not any(hasattr(material_state, name) for name in ("_key", "_key_path", "_path"))
    try:
        if runtime is None:
            assert adapter.dispatch_once() is SecretCreateAdapterOutcome.VERIFIED_CREATED
        else:
            denied = runtime.execute_once(now_epoch=1000) is not MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    except (BulkImportIntakeError, MaterialRuntimeError):
        denied = True
    if not denied:
        try:
            if runtime is None:
                adapter.dispatch_once()
            else:
                runtime.execute_once(now_epoch=1000)
        except (BulkImportIntakeError, MaterialRuntimeError):
            pass
        else:
            raise AssertionError("Original row was replayed")
    for view in borrowed:
        try:
            view.tobytes()
        except ValueError:
            pass
        else:
            raise AssertionError("Borrowed material survived fixed use")
    owned = rows[0] if rows else None
    if value.get("native_ack"):
        assert native._ack_record is None
        if value.get("product_action"):
            assert native._config is None and product_client._phase == "closed"
        else:
            assert native_requests.count("POST") == 1
        assert all(not any(response.raw) for response in responses)
        assert not any(hasattr(loader, name) for name in ("_parent", "_execution"))
        for part in native_views:
            try: part.tobytes()
            except ValueError: pass
            else: raise AssertionError("Native material view survived")
    report = dict(denied=denied, decoded=len(frames) == (2 if value.get("native_ack") else 1),
        frame_cleared=all(not any(frame) for frame in frames),
        unlock_copy_cleared=all(not any(unlock) for unlock in unlocks),
        row_cleared=owned is None or all(not any(part) for part in owned._buffers),
        row_timer_stopped=owned is None or not owned._watchdog.is_alive(),
        source_closed=session._transaction._closed.is_set())
    if value.get("product_action"):
        report.update(product_submitted=native._post_attempted)
    print(json.dumps(report), flush=True)
    assert sys.stdin.buffer.readline() == b"stop\n"
finally:
    session.close()
assert not any(password) and not any(session._password) and not session._watchdog.is_alive()
print(json.dumps({"shutdown_cleared": True}), flush=True)
'''


def receive(process):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        assert selector.select(8), "Private intake did not respond"
        line = process.stdout.readline()
    if not line:
        process.wait(timeout=2)
        errors = process.stderr.read().decode("utf-8", errors="replace")
        # Report only code locations/categories, never private paths or values.
        locations = re.findall(r'line (\d+), in (<module>|[A-Za-z_][A-Za-z_0-9]*)', errors)
        categories = re.findall(r'^([A-Za-z_][A-Za-z_0-9]*(?:Error|Exception))(?::|$)', errors, re.M)
        raise AssertionError(f"Private intake stopped: {locations} {categories}")
    result = json.loads(line)
    assert type(result) is dict and all(type(v) is bool for v in result.values())
    return result


@pytest.mark.parametrize("fault,material,native_ack,product", [(None, False, False, False), ("unarmed", False, False, False), ("lost-claim-response", False, False, False),
    (None, True, False, False), ("unarmed", True, False, False), ("lost-claim-response", True, False, False),
    ("lost-material-claim", True, False, False), ("lost-material-release", True, False, False),
    pytest.param(None, True, True, False, id="nativeack-success"),
    pytest.param("lost-ack-retention", True, True, False, id="nativeack-lost-retention"),
    pytest.param("lost-material-release", True, True, False, id="nativeack-lost-release"),
    pytest.param(None, True, True, True, id="product-success"),
    pytest.param("lost-ack-retention", True, True, True, id="product-lost-retention"),
    pytest.param("lost-material-release", True, True, True, id="product-lost-release")])
def test_encrypted_row_in_independent_os_restricted_process(tmp_path, monkeypatch, fault, material, native_ack, product):
    if sys.platform != "darwin":
        pytest.skip("Native macOS isolation is required for this qualification")
    graph, ack_options = {}, {}
    if native_ack:
        from test_secret_bulk_import_row_wire import SERIAL, project, defaults_response
        from fortipam_mcp.web_secret_create_ack import WebSecretCreateAckCapture
        projected_defaults = project()
        if product:
            SERIAL = hashlib.sha256(b'SYNTHETIC01').hexdigest()
            projected_defaults = replace(projected_defaults, serial_digest=SERIAL)
        ack_options = dict(ack_capture=WebSecretCreateAckCapture(SERIAL, "success"), ack_defaults_digest=projected_defaults.digest())
    local, session, state, values, root, _, owner, _, reference, transport, uds, settings, _ = channel(
        tmp_path, monkeypatch, material=material, capture=graph, **ack_options)
    private_paths = [local._parent._path, local._parent._key_path, state._path, state._key_path,
                     root._path, root._key_path,
                     root._monotonic_checkpoint._path, root._monotonic_checkpoint._key_path,
                     settings["request_key_path"].parent / "signer.key"]
    changed_ledgers = {state._path}
    if native_ack:
        changed_ledgers.add(local._parent._path)
    if material:
        store = owner._material_store
        private_paths.extend([store._path, store._key_path, store._monotonic_checkpoint._path,
                              store._monotonic_checkpoint._key_path])
        changed_ledgers.update({store._path, store._monotonic_checkpoint._path})
    original = {path: path.read_bytes() for path in private_paths}
    target = {"lost-claim-response": "claim", "lost-material-claim": "material-claim",
              "lost-material-release": "material-release", "lost-ack-retention": "retain-ack"}.get(fault)
    if target is not None:
        async def lose_response(request, call_next):
            result = await call_next(request)
            if request.url.path == boundary._PREFIX + target and result.status_code == 200:
                return Response(status_code=409)
            return result
        transport.app.add_middleware(BaseHTTPMiddleware, dispatch=lose_response)
    server = uvicorn.Server(uvicorn.Config(transport.app, access_log=False, log_level="critical", lifespan="off"))
    thread = threading.Thread(target=lambda: server.run(sockets=[uds.socket]), daemon=True)
    process = handoff = child_handoff = product_handle = None
    endpoints = ExitStack()
    thread.start()
    try:
        until = time.monotonic() + 3
        while not server.started and thread.is_alive() and time.monotonic() < until:
            time.sleep(0.01)
        assert server.started
        if product:
            from test_secret_bulk_import_action_process import synthetic_product_endpoint
            from fortipam_mcp.secret_bulk_import_action_process import _launch_original_channel_action_process, _ProductSource
            from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
            directory = tmp_path / 'product'; directory.mkdir(mode=0o700)
            product_source, product_digest, requests, posts = endpoints.enter_context(synthetic_product_endpoint(directory))
            product_inputs = list(directory.iterdir())
            private_paths.extend(product_inputs)
            original.update({path: path.read_bytes() for path in product_inputs})
            handoff, child_handoff = socket.socketpair()
            monkeypatch.setattr(_ProductSource, '_load_product_config',
                lambda *_: pytest.fail('Owner loaded product credentials'))
        # The fixture creator no longer owns live unlock memory; the newly
        # admitted intake process owns its own non-renewable source session.
        session.close()
        assert not any(session._password) and not session._watchdog.is_alive()
        metadata = asdict(owner._binding.source)
        metadata["path"] = str(metadata["path"])
        channel_settings = {name: str(item) if isinstance(item, Path) else item
            for name, item in settings.items() if name not in {"clock", "monotonic"}}
        source_path = owner._binding.source.path
        key = local._rows._key.path
        directory = settings["socket_path"].parent
        alias = directory / "denied-alias"
        alias.symlink_to(private_paths[-1])
        bootstrap = dict(source=metadata, plan=asdict(local._plan), authorization=asdict(local._authorization),
            material=material, native_ack=native_ack, ack_pins_digest=owner._binding.ack_pins_digest,
            parent_digest=local._parent_digest, namespace_key_path=str(key), namespace_key_sha256=local._rows._key.digest,
            permission={name: getattr(owner._binding.permission, name)
                for name in ("policy_decision_digest", "scope_digest", "audience_digest")},
            channel=channel_settings, private_paths=[str(path) for path in private_paths],
            kernel_probe_paths=[str(path) for path in private_paths] + [str(alias)],
            outside_process=os.getpid(), unlisted_output=str(directory / "unlisted-output"))
        if native_ack:
            catalog = asdict(graph["catalog"])
            for name in ("coverage", "service_types"):
                catalog[name] = sorted(catalog[name])
            default_response = defaults_response()
            if product:
                default_response['serial'] = 'SYNTHETIC01'
                bootstrap.update(product_action=True, product_handoff=child_handoff.fileno())
            bootstrap.update(catalog=catalog, serial_digest=SERIAL, default_response=default_response)
        # Reuse the existing default-deny native profile; only these three input
        # files and the fixed row socket are needed in addition to the source.
        profile = native_private_input_profile(directory,
            allowed_paths=[source_path, key, settings["request_key_path"], settings["public_key_path"]],
            remote_sockets=[settings["socket_path"]])
        project = Path(__file__).resolve().parents[1]
        environment = {"PATH": os.defpath, "PYTHONPATH": str(project / "src") + os.pathsep + str(project),
                       "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        process = subprocess.Popen(["/usr/bin/sandbox-exec", "-f", str(profile), sys.executable, "-c",
            WORKER.replace("__KERNEL_PROBE__", KERNEL_PROBE)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment, cwd=directory,
            pass_fds=(child_handoff.fileno(),) if product else ())
        if child_handoff is not None:
            child_handoff.close()
        process.stdin.write(json.dumps(bootstrap).encode() + b"\n")
        process.stdin.flush()
        with reference:
            assert receive(process) == {"ready": True}
            held = []
            class Dispatch(_Adapter):
                def dispatch(self, plan):
                    nonlocal product_handle
                    self.calls.append("dispatch")
                    if product:
                        product_handle = _launch_original_channel_action_process(owner, graph['catalog'],
                            graph['projected'], projected_defaults, namespace_key_path=key, index=0,
                            target_name='Synthetic resolved target', associated_secret_id=None,
                            source_path=product_source, source_digest=product_digest)
                    if fault != "unarmed":
                        owner.arm_original_dispatch()
                    process.stdin.write(b"load\n")
                    process.stdin.flush()
                    if product:
                        product_handle._transfer_client_once(handoff)
                        with pytest.raises(BulkImportIntakeError):
                            product_handle._transfer_client_once(handoff)
                        with pytest.raises(BulkImportIntakeError):
                            product_handle.client.prepare_once()
                    proof = receive(process)
                    held.append(proof)
                    if proof["denied"]:
                        raise M4AdapterAmbiguous("Synthetic isolated intake unavailable")
            result = M4ExecutionKernel(Dispatch(), _Verifier(), state).execute(
                local._plan, local._authorization, now_epoch=1000)
            reopened = PersistentM4ExecutionStateStore(state._path, state._key_path,
                monotonic_checkpoint=state._monotonic_checkpoint,
                checkpoint_store_ref=state._checkpoint_store_ref)
            replay_adapter = Dispatch()
            replayed = M4ExecutionKernel(replay_adapter, _Verifier(), reopened).execute(
                local._plan, local._authorization, now_epoch=1000)
            assert replayed.verification is result.verification
            assert "dispatch" not in replay_adapter.calls and len(held) == 1
        proof = held[0]
        assert result.verification is (M4Verification.VERIFIED if fault is None else M4Verification.UNKNOWN), (
            (proof['decoded'], proof.get('product_submitted')), [method for method, _ in requests] if product else [],
            product_handle._process.wait(timeout=2) if product else None,
            owner._load_nonce is not None, owner._material_claim is not None)
        assert proof["decoded"] is (fault in {None, "lost-material-release", "lost-ack-retention"})
        assert all(proof[name] for name in ("frame_cleared", "unlock_copy_cleared", "row_cleared", "row_timer_stopped"))
        assert proof["source_closed"] is (fault in {"lost-claim-response", "lost-material-claim", "lost-material-release", "lost-ack-retention"})
        if native_ack:
            with reference:
                if fault is None:
                    assert owner._inspect_verified_ack().native_secret_id == 71
                else:
                    from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
                    with pytest.raises(BulkImportIntakeError): owner._inspect_verified_ack()
        if fault == "lost-claim-response":
            assert owner._load_nonce is not None
        if material and fault != "unarmed":
            from fortipam_mcp.secret_bulk_import_row_authority import _original_material_request_digest
            from v4_planning.material_runtime import MaterialUseClaimState, MaterialRuntimeOutcome
            claimed = owner._material_store.claim(request_digest=_original_material_request_digest(
                owner._binding.permission, 1000, 1060), authorization_digest=local._authorization.authorization_digest)
            if fault == "lost-material-claim":
                assert claimed.state is MaterialUseClaimState.IN_PROGRESS
            else:
                expected = MaterialRuntimeOutcome.VERIFIED_AND_RELEASED if fault in {None, "lost-material-release"} else MaterialRuntimeOutcome.RECONCILIATION_REQUIRED
                assert claimed.state is MaterialUseClaimState.REPLAY and claimed.outcome is expected
        process.stdin.write(b"stop\n")
        process.stdin.flush()
        assert receive(process) == {"shutdown_cleared": True}
        process.stdin.close()
        process.wait(timeout=5)
        assert process.returncode == 0 and not process.stdout.read() and not process.stderr.read()
        if product:
            product_handle.close()
            assert product_handle._process.poll() == (21 if fault == 'lost-ack-retention' else 0)
            assert not product_handle._watcher.is_alive() and not product_handle._connector_thread.is_alive()
            assert product_handle.client._peer.fileno() == -1 and handoff.fileno() == -1
            assert len(posts) == 1
            assert len(requests) == (5 if fault == 'lost-ack-retention' else 9)
            assert local._used is False and session._transaction._closed.is_set()
        # M4 changes its durable claim; intake cannot alter authority inputs.
        assert all(path.read_bytes() == raw for path, raw in original.items() if path not in changed_ledgers)
        assert hashlib.sha256(source_path.read_bytes()).hexdigest() == owner._binding.source.file_sha256
        assert not Path(bootstrap["unlisted_output"]).exists()
    finally:
        if product_handle is not None:
            product_handle.close()
        if handoff is not None: handoff.close()
        if child_handoff is not None: child_handoff.close()
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        session.close()
        server.should_exit = True
        thread.join(3)
        assert not thread.is_alive()
        uds.close()
        endpoints.close()
