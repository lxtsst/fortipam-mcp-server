"""Synthetic fixed RADIUS lifecycle, one-shot recovery and deadline regressions."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import socket
import threading
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from fortipam_mcp.radius_server_contract import (
    RadiusServerCandidateError, RadiusServerCreateObservation, RadiusServerCreateOutcome,
)
from fortipam_mcp.radius_server_http_transport import FortiPamRadiusServerHttpTransport
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning.material_provider import MaterialLeaseRequest, MaterialProviderClass, MaterialPurpose
from test_radius_server_contract import binding
from test_radius_server_projection import SERIAL, default_row, envelope, schema_document

TABLE = "/api/v2/cmdb/user/radius"
MATERIAL = b"synthetic-radius-material-32-bytes"


def request() -> MaterialLeaseRequest:
    return MaterialLeaseRequest("radius-server-create", "1.0.0", "1"*64, "2"*64, "3"*64, "4"*64, "5"*64,
        MaterialProviderClass.EXTERNAL_VAULT_LEASE, MaterialPurpose.INITIAL_ONBOARDING, 100, 160)


class Response:
    def __init__(self, document: object, status: int = 200) -> None:
        self.status, self.closed = status, False
        self.content = io.BytesIO(json.dumps(document).encode())

    def readinto(self, value: memoryview) -> int:
        return self.content.readinto(value)

    def getheader(self, name: str, default: str = "") -> str:
        return "application/json"

    def close(self) -> None:
        self.closed = True


class FakeSocket:
    def shutdown(self, how: int) -> None:
        pass


class Connection:
    def __init__(self, peer: Peer) -> None:
        self.peer, self.closed = peer, False
        self.sock: FakeSocket | None = FakeSocket()
        self.response: Response | None = None

    def connect(self) -> None:
        if self.peer.on_connect:
            self.peer.on_connect()

    def request(self, method: str, path: str, body: memoryview | None, headers: dict[str, str]) -> None:
        assert headers["User-Agent"] == "fortipam-private-radius-create/1"
        assert headers["Accept-Encoding"] == "identity"
        if body is not None:
            assert body.readonly
            self.peer.bodies.append(body.obj)
        self.response = self.peer.handle(method, path, body)
        # Model HTTPConnection detaching its socket on Connection: close.
        self.sock = None

    def getresponse(self) -> Response:
        assert self.response is not None
        return self.response

    def close(self) -> None:
        self.closed = True


class Peer:
    def __init__(self) -> None:
        self.binding = binding()
        self.defaults = default_row()
        self.row: dict[str, Any] | None = None
        self.posts = self.deletes = 0
        self.lost_post_ack = self.lost_delete_ack = self.failed_readback = False
        self.foreign_ack = self.truncated_collection = self.bad_absence = False
        self.on_connect: Any = None
        self.bodies: list[bytearray] = []
        self.connections: list[Connection] = []
        self.responses: list[Response] = []

    def connection(self, host: str, port: int, **kwargs: Any) -> Connection:
        assert host == "pam.example" and port == 443 and kwargs["context"].check_hostname
        connection = Connection(self)
        self.connections.append(connection)
        return connection

    def handle(self, method: str, path: str, body: memoryview | None) -> Response:
        parsed = urlsplit(path)
        query = parse_qs(parsed.query)
        if method == "POST":
            assert path == TABLE and body is not None
            submitted = json.loads(bytes(body))
            assert set(submitted) == {"name", "$originalName", "auth-type", "server", "secret",
                                      "secondary-server", "secondary-secret"}
            assert submitted.pop("secret").encode() == MATERIAL
            assert submitted.pop("secondary-secret") == "" and submitted.pop("$originalName") == ""
            self.posts += 1
            self.row = self.defaults | submitted | {"q_ref": 0, "secret": "SYNTHETIC_STORED_OPAQUE"}
            if self.lost_post_ack:
                raise TimeoutError("synthetic response lost")
            response = Response(envelope(http_method="POST", mkey="other" if self.foreign_ack else self.binding.name))
        elif method == "DELETE":
            assert path == TABLE + "/" + self.binding.name and body is None
            self.deletes += 1
            self.row = None
            if self.lost_delete_ack:
                raise TimeoutError("synthetic response lost")
            response = Response(envelope(http_method="DELETE", mkey=self.binding.name))
        elif query.get("action") == ["schema"]:
            response = Response(schema_document())
        elif query.get("action") == ["default"]:
            response = Response(envelope(action="default", results=self.defaults))
        elif query.get("format") == ["name"]:
            response = Response(envelope(results=[] if self.row is None else [{"name": self.binding.name}],
                                         limit_reached=self.truncated_collection))
        elif parsed.path == TABLE + "/" + self.binding.name:
            if self.row is None:
                response = Response(envelope(status="error", name="other" if self.bad_absence else "radius",
                                             http_status=404), 404)
            elif self.failed_readback:
                self.failed_readback = False
                raise TimeoutError("synthetic detail lost")
            else:
                response = Response(envelope(results=[self.row], mkey=self.binding.name))
        else:
            raise AssertionError("Unexpected route")
        self.responses.append(response)
        return response


def transport(state: Path, peer: Peer, now: list[int], *, expected: str | None = None,
              execute: bool = False, recover: bool = False, **kwargs: Any) -> FortiPamRadiusServerHttpTransport:
    return FortiPamRadiusServerHttpTransport(
        SecretMetadataHttpTransportConfig("https://pam.example", "synthetic-token", 1, None),
        peer.binding, expected_serial=SERIAL, state_directory=state,
        execution_request=request() if execute else None, expected_current_digest=expected,
        execution_enabled=execute, recovery_enabled=recover,
        create_authorizer=kwargs.pop("create_authorizer", lambda *args: True),
        recovery_authorizer=kwargs.pop("recovery_authorizer", lambda *args: True),
        clock=lambda: now[0], connection_factory=peer.connection, **kwargs)


def setup(tmp_path: Path) -> tuple[Peer, Path, list[int], str]:
    state = tmp_path.resolve() / "state"
    state.mkdir(mode=0o700)
    peer, now = Peer(), [100]
    digest = transport(state, peer, now).inspect_create().state_digest
    return peer, state, now, digest


def create(state: Path, peer: Peer, now: list[int], digest: str, **kwargs: Any) -> RadiusServerCreateOutcome:
    selected = transport(state, peer, now, expected=digest, execute=True, **kwargs)
    material = bytearray(MATERIAL)
    try:
        with memoryview(material).toreadonly() as view:
            return selected._create_and_verify_with_material(peer.binding, request(), view)
    finally:
        material[:] = bytes(len(material))
        material.clear()


def test_exact_lifecycle_and_separately_enabled_recovery(tmp_path: Path) -> None:
    peer, state, now, digest = setup(tmp_path)
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.VERIFIED_CREATED
    restarted = transport(state, peer, now)
    assert restarted.inspect_owned()
    with pytest.raises(RadiusServerCandidateError):
        restarted.delete_owned()
    assert peer.deletes == 0
    recovery = transport(state, peer, now, recover=True)
    assert recovery.delete_owned() and recovery.inspect_deleted()
    with pytest.raises(RadiusServerCandidateError):
        recovery.delete_owned()
    assert peer.posts == peer.deletes == 1
    assert all(not body for body in peer.bodies)
    assert all(value.closed for value in peer.connections + peer.responses)
    journal = "".join(path.read_text() for path in state.glob("*.json"))
    for private in (MATERIAL.decode(), peer.binding.name, peer.binding.server, peer.binding.private_nonce, SERIAL,
                    "SYNTHETIC_STORED_OPAQUE", "synthetic-token"):
        assert private not in journal


@pytest.mark.parametrize("fault", ["lost_ack", "foreign_ack", "failed_readback"])
def test_consumed_post_never_replays_and_requires_original_ack(tmp_path: Path, fault: str) -> None:
    peer, state, now, digest = setup(tmp_path)
    peer.lost_post_ack = fault == "lost_ack"
    peer.foreign_ack = fault == "foreign_ack"
    peer.failed_readback = fault == "failed_readback"
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert (state / "create.claim.json").exists() and peer.posts == 1
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == 1 and all(not value for value in peer.bodies)
    restarted = transport(state, peer, now, recover=True)
    if fault == "failed_readback":
        assert restarted.inspect_owned() and restarted.delete_owned()
    else:
        with pytest.raises(RadiusServerCandidateError):
            restarted.inspect_owned()
        with pytest.raises(RadiusServerCandidateError):
            restarted.delete_owned()
        assert peer.deletes == 0


@pytest.mark.parametrize("fault", ["q_ref", "missing_q_ref", "scalar", "opaque", "primary", "defaults"])
def test_recovery_refuses_references_or_any_created_state_drift(tmp_path: Path, fault: str) -> None:
    peer, state, now, digest = setup(tmp_path)
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.VERIFIED_CREATED
    assert peer.row is not None
    if fault == "q_ref": peer.row["q_ref"] = 1
    elif fault == "missing_q_ref": del peer.row["q_ref"]
    elif fault == "scalar": peer.row["timeout"] += 1
    elif fault == "opaque": peer.row["secondary-secret"] = "SYNTHETIC_DRIFT"
    elif fault == "primary": peer.row["secret"] = "SYNTHETIC_DIFFERENT_PRIMARY"
    elif fault == "defaults": peer.defaults["timeout"] += 1
    with pytest.raises(RadiusServerCandidateError):
        transport(state, peer, now, recover=True).delete_owned()
    assert peer.deletes == 0 and not (state / "delete.claim.json").exists()


def test_uncertain_delete_only_reconciles_without_ack_or_redispatch(tmp_path: Path) -> None:
    peer, state, now, digest = setup(tmp_path)
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.VERIFIED_CREATED
    peer.lost_delete_ack = True
    recovery = transport(state, peer, now, recover=True)
    with pytest.raises(RadiusServerCandidateError):
        recovery.delete_owned()
    assert (state / "delete.claim.json").exists() and not (state / "delete-ack.json").exists()
    assert recovery.inspect_deleted()
    with pytest.raises(RadiusServerCandidateError):
        transport(state, peer, now, recover=True).delete_owned()
    assert peer.deletes == 1
    peer.bad_absence = True
    with pytest.raises(RadiusServerCandidateError):
        recovery.inspect_deleted()


@pytest.mark.parametrize("fault", ["drift", "truncated", "absent_route", "expired", "authorization", "authorization_type"])
def test_prewrite_denials_do_not_claim_or_dispatch(tmp_path: Path, fault: str) -> None:
    peer, state, now, digest = setup(tmp_path)
    kwargs: dict[str, Any] = {}
    if fault == "drift": peer.defaults["timeout"] += 1
    elif fault == "truncated": peer.truncated_collection = True
    elif fault == "absent_route": peer.bad_absence = True
    elif fault == "expired": now[0] = 160
    elif fault == "authorization": kwargs["create_authorizer"] = lambda *args: False
    elif fault == "authorization_type": kwargs["create_authorizer"] = lambda *args: 1
    assert create(state, peer, now, digest, **kwargs) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == 0 and not (state / "create.claim.json").exists()


def test_authorization_revoked_after_tls_connection_consumes_claim_without_post(tmp_path: Path) -> None:
    peer, state, now, digest = setup(tmp_path)
    allowed = [True]
    def connected() -> None:
        if (state / "create.claim.json").exists():
            allowed[0] = False
    peer.on_connect = connected
    assert create(state, peer, now, digest, create_authorizer=lambda *args: allowed[0]) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == 0 and (state / "create.claim.json").exists()
    allowed[0] = True
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == 0


@pytest.mark.parametrize("fault", ["namespace", "claim_symlink", "claim_hardlink", "claim_duplicate", "ack_link", "directory", "lock"])
def test_journal_corruption_or_namespace_rebinding_refuses(tmp_path: Path, fault: str) -> None:
    peer, state, now, digest = setup(tmp_path)
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.VERIFIED_CREATED
    selected = transport(state, peer, now, recover=True)
    if fault == "namespace": peer.binding = type(peer.binding)(peer.binding.name, "192.0.2.11", "b"*64)
    elif fault == "claim_symlink":
        original = state / "create.claim.json"
        original.rename(state / "retained-claim.json")
        original.symlink_to(state / "retained-claim.json")
    elif fault == "claim_hardlink": os.link(state / "create.claim.json", state / "retained-claim.json")
    elif fault == "claim_duplicate":
        original = state / "create.claim.json"
        original.write_text(original.read_text()[:-1] + ',"claimed_at":100}')
    elif fault == "ack_link":
        original = state / "create-ack.json"
        record = json.loads(original.read_text())
        record["claim_digest"] = "0"*64
        original.write_text(json.dumps(record))
    elif fault == "directory":
        state.rename(state.parent / "retained-state")
        state.mkdir(mode=0o700)
    elif fault == "lock": (state / "operation.lock").chmod(0o644)
    with pytest.raises(RadiusServerCandidateError):
        (transport(state, peer, now, recover=True) if fault == "namespace" else selected).delete_owned()
    assert peer.deletes == 0


def test_competing_operator_cannot_observe_or_dispatch(tmp_path: Path) -> None:
    peer, state, now, digest = setup(tmp_path)
    first = transport(state, peer, now)
    with first._locked():
        with pytest.raises(RadiusServerCandidateError):
            transport(state, peer, now).inspect_create()
        assert create(state, peer, now, digest) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == 0


def test_closed_gate_never_dispatches_and_binding_uses_identity(tmp_path: Path) -> None:
    peer, state, now, digest = setup(tmp_path)
    closed = transport(state, peer, now)
    with memoryview(bytearray(MATERIAL)).toreadonly() as view:
        assert closed._create_and_verify_with_material(peer.binding, request(), view) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
        opened = transport(state, peer, now, expected=digest, execute=True)
        assert opened._create_and_verify_with_material(binding(), request(), view) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == 0


def test_slow_close_response_uses_retained_socket_and_absolute_deadline(tmp_path: Path) -> None:
    peer, state, now, _ = setup(tmp_path)
    left, right = socket.socketpair()
    sent = threading.Event()

    class SlowResponse(Response):
        def readinto(self, value: memoryview) -> int:
            return left.recv_into(value)

    class SlowConnection(Connection):
        def __init__(self) -> None:
            super().__init__(peer)
            self.sock = left  # type: ignore[assignment]

        def request(self, *args: Any) -> None:
            self.sock = None
            self.response = SlowResponse({})
            sent.set()

    def writer() -> None:
        sent.wait(2)
        for _ in range(50):
            try: right.send(b" ")
            except OSError: break
            time.sleep(.02)

    task = threading.Thread(target=writer, daemon=True)
    task.start()
    selected = transport(state, peer, now)
    selected._factory = lambda *args, **kwargs: SlowConnection()
    started = time.monotonic()
    try:
        with pytest.raises(RadiusServerCandidateError):
            selected._exchange("GET", TABLE + "?action=schema&with_meta=true", stop=started + .12)
        assert .08 < time.monotonic() - started < .8
    finally:
        left.close()
        right.close()
        task.join(2)


def test_no_arbitrary_route_or_native_test_can_be_dispatched(tmp_path: Path) -> None:
    peer, state, now, _ = setup(tmp_path)
    selected = transport(state, peer, now)
    before = len(peer.connections)
    with pytest.raises(RadiusServerCandidateError):
        selected._exchange("POST", "/api/v2/monitor/user/radius/test-connect", stop=time.monotonic()+1,
                           body=bytearray(b"{}"))
    assert len(peer.connections) == before


@pytest.mark.parametrize("marker", ["create.claim.json", "create-ack.json", "created.json"])
def test_create_persistence_failures_never_replay(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                                               marker: str) -> None:
    peer, state, now, digest = setup(tmp_path)
    original = FortiPamRadiusServerHttpTransport._write_once

    def failing(self: FortiPamRadiusServerHttpTransport, name: str, value: object) -> None:
        if name == marker:
            # Model a short/uncertain durable write: its occupied name is kept.
            original(self, name, {})
            raise OSError("synthetic persistence failure")
        original(self, name, value)

    monkeypatch.setattr(FortiPamRadiusServerHttpTransport, "_write_once", failing)
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == (0 if marker == "create.claim.json" else 1)
    monkeypatch.setattr(FortiPamRadiusServerHttpTransport, "_write_once", original)
    before = peer.posts
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == before
    with pytest.raises(RadiusServerCandidateError):
        transport(state, peer, now, recover=True).delete_owned()
    assert peer.deletes == 0


def test_recovery_authorizer_denial_never_consumes_delete(tmp_path: Path) -> None:
    peer, state, now, digest = setup(tmp_path)
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.VERIFIED_CREATED
    with pytest.raises(RadiusServerCandidateError):
        transport(state, peer, now, recover=True, recovery_authorizer=lambda *args: False).delete_owned()
    assert peer.deletes == 0 and not (state / "delete.claim.json").exists()


@pytest.mark.parametrize("kind", ["writable", "empty", "oversize", "control", "wrong_format"])
def test_invalid_material_never_claims_or_dispatches(tmp_path: Path, kind: str) -> None:
    peer, state, now, digest = setup(tmp_path)
    selected = transport(state, peer, now, expected=digest, execute=True)
    material = bytearray(MATERIAL)
    if kind == "empty": material.clear()
    elif kind == "oversize": material = bytearray(b"x"*129)
    elif kind == "control": material[0] = 0
    with memoryview(material) as writable:
        with (writable.cast("b") if kind == "wrong_format" else writable.toreadonly()) as view:
            actual = writable if kind == "writable" else view
            assert selected._create_and_verify_with_material(peer.binding, request(), actual) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == 0 and not (state / "create.claim.json").exists()


def test_authorizer_crossing_lease_expiry_cannot_send_material(tmp_path: Path) -> None:
    peer, state, now, digest = setup(tmp_path)
    after_claim = [0]

    def authorizer(*args: Any) -> bool:
        if (state / "create.claim.json").exists():
            after_claim[0] += 1
            now[0] = 159 if after_claim[0] == 1 else 160
        return True

    assert create(state, peer, now, digest, create_authorizer=authorizer) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert after_claim[0] == 2 and peer.posts == 0
    assert (state / "create.claim.json").exists() and all(not body for body in peer.bodies)
    now[0] = 200
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == 0


@pytest.mark.parametrize("observation", ["present", "absent", "drifted", "bad_absence", "incomplete_collection"])
def test_unacknowledged_create_has_readonly_diagnostics_without_ownership(tmp_path: Path, observation: str) -> None:
    peer, state, now, digest = setup(tmp_path)
    peer.lost_post_ack = True
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    before = {path.name: path.read_bytes() for path in state.iterdir()}
    assert peer.row is not None
    if observation in {"absent", "bad_absence", "incomplete_collection"}: peer.row = None
    elif observation == "drifted": peer.row["server"] = "192.0.2.11"
    peer.bad_absence = observation == "bad_absence"
    peer.truncated_collection = observation == "incomplete_collection"
    selected = transport(state, peer, now, recover=True)
    connections = len(peer.connections)
    result = selected.inspect_uncertain_create()
    expected = (RadiusServerCreateObservation.PRESENT_OBSERVED if observation in {"present", "drifted"}
                else RadiusServerCreateObservation.ABSENT_OBSERVED if observation == "absent"
                else RadiusServerCreateObservation.NOT_ASSESSED)
    assert result is expected and len(peer.connections) > connections
    assert {path.name: path.read_bytes() for path in state.iterdir()} == before
    with pytest.raises(RadiusServerCandidateError): selected.inspect_owned()
    with pytest.raises(RadiusServerCandidateError): selected.delete_owned()
    assert peer.posts == 1 and peer.deletes == 0
    assert create(state, peer, now, digest) is RadiusServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == 1


@pytest.mark.parametrize("existing_lock", [False, True])
def test_uncertain_diagnostic_without_claim_never_initializes_journal(tmp_path: Path, existing_lock: bool) -> None:
    state = tmp_path.resolve() / "empty-state"
    state.mkdir(mode=0o700)
    if existing_lock:
        lock = state / "operation.lock"
        lock.touch(mode=0o600)
    peer, now = Peer(), [100]
    before = {path.name: path.read_bytes() for path in state.iterdir()}
    assert transport(state, peer, now).inspect_uncertain_create() is RadiusServerCreateObservation.NOT_ASSESSED
    assert {path.name: path.read_bytes() for path in state.iterdir()} == before
    assert not peer.connections and peer.posts == peer.deletes == 0
