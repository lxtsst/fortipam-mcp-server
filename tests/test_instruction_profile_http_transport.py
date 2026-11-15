"""Fixed native profile lifecycle with synthetic network and durable claims."""
from __future__ import annotations

import copy
import hashlib
import io
import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from fortipam_mcp.instruction_profile_contract import InstructionPlainText, InstructionProfileCreatePlan
from fortipam_mcp.instruction_profile_http_transport import (
    InstructionProfileHttpTransportError, FortiPamInstructionProfileHttpTransport, Phase,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig

TABLE = "/api/v2/cmdb/secret/instruction-profile"


class Response:
    def __init__(self, value: dict[str, Any], status: int = 200) -> None:
        self.status = status
        self.content = io.BytesIO(json.dumps(value).encode())
        self.closed = False

    def readinto(self, value: memoryview) -> int:
        return self.content.readinto(value)

    def getheader(self, name: str, default: str = "") -> str:
        return "application/json"

    def close(self) -> None:
        self.closed = True


class Connection:
    def __init__(self, peer: Peer) -> None:
        self.peer = peer
        self.response: Response | None = None
        self.closed = False

    def connect(self) -> None:
        if self.peer.on_connect:
            self.peer.on_connect()

    def request(self, method: str, url: str, body: memoryview | None, headers: dict[str, str]) -> None:
        assert headers["Authorization"] == "Bearer synthetic-token"
        assert headers["Accept-Encoding"] == "identity"
        self.response = self.peer.handle(method, url, body)

    def getresponse(self) -> Response:
        assert self.response is not None
        return self.response

    def close(self) -> None:
        self.closed = True


class Peer:
    def __init__(self) -> None:
        self.defaults = {"name": "", "brief": "", "detail": ""}
        self.schema = {key: {"type": "string"} for key in self.defaults}
        self.schema_digest = hashlib.sha256(json.dumps(self.schema, sort_keys=True).encode()).hexdigest()
        self.serial_digest = hashlib.sha256(b"SYNTHETIC").hexdigest()
        self.brief, self.text = "Synthetic brief", "Synthetic private instructions."
        self.binding = InstructionProfileCreatePlan("mcp-v4-ip-synthetic", "a" * 64,
            InstructionPlainText(self.brief, self.text), self.defaults,
            schema_digest=self.schema_digest, serial_digest=self.serial_digest)
        self.created: dict[str, Any] | None = None
        self.connections: list[Connection] = []
        self.calls: list[tuple[str, str]] = []
        self.writes: list[str] = []
        self.bodies: list[bytearray] = []
        self.on_connect: Any = None
        self.lose_ack_at = 0
        self.fail_detail_after_write = False
        self.fail_detail = False
        self.bad_envelope: tuple[str, Any] | None = None
        self.reject_write = False

    def connection(self, host: str, port: int, **kwargs: Any) -> Connection:
        assert host == "pam.example" and port == 443 and kwargs["context"].check_hostname
        connection = Connection(self)
        self.connections.append(connection)
        return connection

    def handle(self, method: str, url: str, body: memoryview | None) -> Response:
        self.calls.append((method, url))
        parsed = urlsplit(url)
        parts = parsed.path.split("/")
        path, table = parts[4:6]
        assert (path, table) == ("secret", "instruction-profile")
        key = parts[6] if len(parts) == 7 else None
        query = parse_qs(parsed.query)
        status = 200
        result: Any
        if method != "GET":
            self.writes.append(method)
            if not self.reject_write:
                if method == "POST":
                    assert key is None and self.created is None and body is not None
                    assert isinstance(body.obj, bytearray)
                    self.bodies.append(body.obj)
                    submitted = json.loads(bytes(body))
                    assert set(submitted) == {"name", "brief", "detail"}
                    assert submitted["name"] == self.binding._name
                    self.created = {**submitted, "q_origin_key": self.binding._name,
                        "q_global_entry": False, "q_mkey_type": "string", "q_name": "instruction-profile",
                        "q_no_edit": False, "q_no_rename": False, "q_path": "secret", "q_ref": 0,
                        "q_static": False, "q_type": 0}
                else:
                    assert method == "DELETE" and key == self.binding._name and body is None
                    self.created = None
            if len(self.writes) == self.lose_ack_at:
                raise TimeoutError("Synthetic lost ACK with private details")
            if self.fail_detail_after_write:
                self.fail_detail = True
            result = {}
        elif query.get("action") == ["schema"]:
            result = self.schema and {"children": self.schema}
        elif query.get("action") == ["default"]:
            result = self.defaults
        elif key:
            assert key == self.binding._name and query == {"with_meta": ["true"]}
            if self.fail_detail:
                raise TimeoutError("Synthetic failed readback")
            if self.created is None:
                status, result = 404, []
            else:
                result = [self.created]
        else:
            assert query == {"format": ["name"]}
            result = [] if self.created is None else [{k: self.created[k] for k in ("name", "q_origin_key")}]
        payload = {"version": "v7.0.0", "build": 29, "serial": "SYNTHETIC", "path": path, "name": table,
            "http_method": method, "http_status": status, "status": "success" if status == 200 else "error",
            "results": copy.deepcopy(result)}
        if method != "GET":
            payload["mkey"] = self.binding._name
            if self.reject_write:
                payload.update(status="error", error=-37)
        if type(result) is list:
            payload.update(size=len(result), matched_count=len(result))
        if self.bad_envelope:
            payload[self.bad_envelope[0]] = self.bad_envelope[1]
        return Response(payload, status)


Fixture = tuple[Path, Peer, list[int]]


@pytest.fixture
def fixture(tmp_path: Path) -> Fixture:
    directory = tmp_path / "owned-instruction"
    directory.mkdir(mode=0o700)
    return directory, Peer(), [100]


def make(fixture: Fixture, phase: Phase = "create", *, enabled: bool = True) -> FortiPamInstructionProfileHttpTransport:
    path, peer, now = fixture
    return FortiPamInstructionProfileHttpTransport(
        SecretMetadataHttpTransportConfig("https://pam.example", "synthetic-token", 5, None), peer.binding,
        serial_digest=peer.serial_digest, schema_digest=peer.schema_digest, state_directory=path,
        phase=phase, execution_enabled=enabled, clock=lambda: now[0], connection_factory=peer.connection)


def run(fixture: Fixture, phase: Phase) -> str:
    client = make(fixture, phase)
    with client.operation_lock():
        current = client.inspect_current()
        expected = client.expected_state_digest()
        client.dispatch(expected_current_digest=current.state_digest, expires_at=fixture[2][0] + 60,
            plan_digest="1" * 64, authorization_digest="2" * 64, before_send=lambda: None)
        assert client.inspect_postcondition() == expected
    return expected


def test_exact_owned_roundtrip_preserves_creation_and_zeroizes_body(fixture: Fixture) -> None:
    state, peer, _ = fixture
    client = make(fixture)
    with pytest.raises(InstructionProfileHttpTransportError):
        client.inspect_current()
    run(fixture, "create")
    original = {p.name: p.read_bytes() for p in state.iterdir()}
    assert peer.created is not None and len(peer.created) == 13
    expected = run(fixture, "delete")
    assert peer.created is None and peer.writes == ["POST", "DELETE"]
    assert all((state / name).read_bytes() == data for name, data in original.items())
    assert all(not any(body) for body in peer.bodies)
    assert all(c.closed and (c.response is None or c.response.closed) for c in peer.connections)
    restarted = make(fixture, "delete")
    with restarted.operation_lock():
        assert restarted.inspect_postcondition() == expected
    for phase in ("create", "delete"):
        with pytest.raises(InstructionProfileHttpTransportError):
            run(fixture, phase)
    assert peer.writes == ["POST", "DELETE"]


@pytest.mark.parametrize("fault", ["lost_ack", "readback"])
def test_unknown_create_never_adopts_replays_or_deletes(fixture: Fixture, fault: str) -> None:
    state, peer, _ = fixture
    peer.lose_ack_at = 1 if fault == "lost_ack" else 0
    peer.fail_detail_after_write = fault == "readback"
    with pytest.raises(InstructionProfileHttpTransportError):
        run(fixture, "create")
    assert (state / "create.claim.json").exists() and not (state / "created.json").exists()
    for phase in ("create", "delete"):
        with pytest.raises(InstructionProfileHttpTransportError):
            run(fixture, phase)
    assert peer.writes == ["POST"] and not (state / "delete.claim.json").exists()


@pytest.mark.parametrize("field,value", [("q_ref", 1), ("q_ref", False), ("brief", "changed"),
    ("detail", "changed"), ("q_type", 1), ("q_static", True), ("q_no_rename", True)])
def test_every_owned_field_is_preserved_before_delete(fixture: Fixture, field: str, value: object) -> None:
    run(fixture, "create")
    state, peer, _ = fixture
    assert peer.created is not None
    peer.created[field] = value
    with pytest.raises(InstructionProfileHttpTransportError):
        run(fixture, "delete")
    assert peer.writes == ["POST"] and not (state / "delete.claim.json").exists()


@pytest.mark.parametrize("fault", ["default", "schema", "expiry", "rollback"])
def test_post_tls_drift_or_clock_refuses_send_and_consumes_claim(fixture: Fixture, fault: str) -> None:
    state, peer, now = fixture
    client = make(fixture)
    with client.operation_lock():
        current = client.inspect_current()
        def change() -> None:
            if fault == "default": peer.defaults["brief"] = "changed"
            elif fault == "schema": peer.schema["extra"] = {"type": "string"}
            else: now[0] = 160 if fault == "expiry" else 99
        peer.on_connect = change
        with pytest.raises(InstructionProfileHttpTransportError):
            client.dispatch(expected_current_digest=current.state_digest, expires_at=160,
                plan_digest="1" * 64, authorization_digest="2" * 64, before_send=lambda: None)
    assert not peer.writes and (state / "create.claim.json").exists()
    assert not (state / "create-ack.json").exists()


def test_backend_rejection_retains_response_without_success_or_retry(fixture: Fixture) -> None:
    state, peer, _ = fixture
    peer.reject_write = True
    with pytest.raises(InstructionProfileHttpTransportError): run(fixture, "create")
    captured = json.loads((state / "create-response.json").read_text())
    assert captured["payload"]["status"] == "error" and captured["payload"]["error"] == -37
    assert (state / "create-response.json").stat().st_mode & 0o777 == 0o600
    assert not (state / "create-ack.json").exists() and not (state / "created.json").exists()
    with pytest.raises(InstructionProfileHttpTransportError): run(fixture, "create")
    assert peer.writes == ["POST"]


def test_default_gate_and_missing_original_ack_prevent_dispatch(fixture: Fixture) -> None:
    client = make(fixture, enabled=False)
    with client.operation_lock():
        current = client.inspect_current()
        with pytest.raises(InstructionProfileHttpTransportError):
            client.dispatch(expected_current_digest=current.state_digest, expires_at=160,
                plan_digest="1" * 64, authorization_digest="2" * 64, before_send=lambda: None)
    assert not fixture[1].writes
    run(fixture, "create")
    (fixture[0] / "create-ack.json").unlink()
    with pytest.raises(InstructionProfileHttpTransportError): run(fixture, "delete")
    assert fixture[1].writes == ["POST"]
