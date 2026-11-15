"""Offline device simulation exercises feature ownership and uncertain outcomes."""
from __future__ import annotations

from collections.abc import Callable
import json
import os
from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp import instruction_feature_http_transport as t
from fortipam_mcp.instruction_feature_contract import InstructionFeatureTransition
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_instruction_feature_contract import SERIAL, state


class Device:
    def __init__(self) -> None:
        self.enabled = False
        self.sibling = "synthetic-private-value"
        self.status = 200
        self.ack_changes: dict[str, object] = {}
        self.reply: bytes | None = None
        self.on_connect: Callable[[], None] = lambda: None
        self.on_read: Callable[[], None] = lambda: None
        self.close_error = False
        self.clock = 1000
        self.connections: list[Connection] = []
        self.requests: list[bytes] = []
        self.buffers: list[bytearray] = []
        self.connection_options: list[dict[str,object]] = []

    def read(self, config: object, *, serial_digest: str) -> Any:
        assert serial_digest == SERIAL
        self.on_read()
        return state(self.enabled,self.sibling)

    def connect(self, *args: object, **kwargs: object) -> Connection:
        self.connection_options.append(kwargs)
        connection = Connection(self)
        self.connections.append(connection)
        return connection


class Response:
    def __init__(self, device: Device) -> None:
        self.device = device
        self.status = device.status
        fields: dict[str, object] = {"version":"v7.0.0","build":29,"path":"secret",
            "name":"setting","http_method":"PUT","http_status":200,"status":"success",
            "serial":"synthetic-device","error":0,"vdom":"root"}
        fields.update(device.ack_changes)
        self.raw = device.reply if device.reply is not None else b" \n"+json.dumps(fields).encode()+b"\n "
        self.offset = 0
        self.closed = False

    def getheader(self, name: str, default: str = "") -> str:
        return {"Content-Type":"application/json", "Content-Encoding":"identity"}.get(name,default)

    def readinto(self, view: memoryview) -> int:
        if not any(view.obj is raw for raw in self.device.buffers):
            self.device.buffers.append(view.obj)
        count = min(len(view),len(self.raw)-self.offset,137)
        view[:count] = self.raw[self.offset:self.offset+count]
        self.offset += count
        return count

    def close(self) -> None:
        self.closed = True
        if self.device.close_error:
            raise RuntimeError("synthetic-private-close-detail")


class Connection:
    sock = None

    def __init__(self, device: Device) -> None:
        self.device = device
        self.closed = False
        self.response: Response | None = None

    def connect(self) -> None:
        self.device.on_connect()

    def request(self, method: str, route: str, *, body: bytearray, headers: dict[str,str]) -> None:
        assert method == "PUT" and route == "/api/v2/cmdb/secret/setting"
        assert headers["User-Agent"] == "fortipam-mcp-target-lifecycle/1"
        assert headers["Authorization"] == "Bearer synthetic-token"
        self.device.requests.append(bytes(body))
        self.device.buffers.append(body)
        assert body in (b'{"guest-instruction":"enable"}',b'{"guest-instruction":"disable"}')
        self.device.enabled = json.loads(body)["guest-instruction"] == "enable"

    def getresponse(self) -> Response:
        self.response = Response(self.device)
        return self.response

    def close(self) -> None:
        self.closed = True


class Cycle:
    def __init__(self, path: Path, device: Device) -> None:
        self.path = path.resolve()
        self.path.chmod(0o700)
        self.device = device
        self.baseline = state()
        self.config = SecretMetadataHttpTransportConfig("https://synthetic.invalid","synthetic-token",30,None)

    def transport(self, phase: str = "enable", **overrides: Any) -> t.FortiPamInstructionFeatureHttpTransport:
        current = self.baseline if phase == "enable" else state(True)
        binding = InstructionFeatureTransition(self.baseline,current,phase=phase,operation_nonce=("a" if phase=="enable" else "b")*64)  # type: ignore[arg-type]
        values: dict[str, Any] = {"state_directory":self.path,"cycle_nonce":"c"*64,
            "state_key":b"k"*32,"execution_enabled":True,"clock":lambda:self.device.clock,
            "state_reader":self.device.read,"connection_factory":self.device.connect}
        values.update(overrides)
        return t.FortiPamInstructionFeatureHttpTransport(self.config,self.baseline,binding,**values)

    def dispatch(self, transport: t.FortiPamInstructionFeatureHttpTransport, **overrides: Any) -> None:
        values: dict[str, Any] = {"expected_current_digest":transport._binding._current,
            "plan_digest":"d"*64,"authorization_digest":"e"*64,"expires_at":1060,"before_send":lambda:None}
        values.update(overrides)
        transport.dispatch(**values)

    def enable(self) -> t.FortiPamInstructionFeatureHttpTransport:
        transport = self.transport()
        with transport.operation_lock():
            transport.inspect_precondition()
            self.dispatch(transport)
            transport.inspect_postcondition()
        return transport


@pytest.fixture
def cycle(tmp_path: Path) -> Cycle:
    return Cycle(tmp_path,Device())


def assert_closed(device: Device) -> None:
    assert all(c.closed and (c.response is None or c.response.closed) for c in device.connections)
    assert all(not any(raw) for raw in device.buffers)


def test_enable_restore_complete_cycle_and_no_replay(cycle: Cycle) -> None:
    enable = cycle.enable()
    assert cycle.device.enabled
    with enable.operation_lock():
        assert enable.inspect_postcondition() == state(True)._state
    for transport in (enable,cycle.transport()):
        with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
            cycle.dispatch(transport)
    restore = cycle.transport("restore")
    with restore.operation_lock():
        cycle.dispatch(restore)
        assert restore.inspect_postcondition() == cycle.baseline._state
    repeated_restore = cycle.transport("restore")
    with repeated_restore.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        repeated_restore.inspect_precondition()
    assert not cycle.device.enabled
    assert cycle.device.requests == [b'{"guest-instruction":"enable"}',b'{"guest-instruction":"disable"}']
    assert len(list(cycle.path.glob("*.json"))) == 6
    assert_closed(cycle.device)
    for path in cycle.path.glob("*.json"):
        assert path.stat().st_mode & 0o777 == 0o600
        assert b"synthetic-private-value" not in path.read_bytes()
        assert b"synthetic-token" not in path.read_bytes()


def test_closed_gate_and_missing_lock_prevent_connection(cycle: Cycle) -> None:
    transport = cycle.transport(execution_enabled=False)
    with pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(transport)
    with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(transport)
    assert not cycle.device.connections and not cycle.device.requests


def test_nested_lock_failure_preserves_outer_lock_and_excludes_second_instance(cycle: Cycle) -> None:
    transport, other = cycle.transport(), cycle.transport()
    with transport.operation_lock():
        for candidate in (transport,other):
            with pytest.raises(t.InstructionFeatureTransportError), candidate.operation_lock():
                pytest.fail("nested or competing lock accepted")
        assert transport.inspect_precondition()._state == cycle.baseline._state
    with other.operation_lock():
        other.inspect_precondition()


@pytest.mark.parametrize("stage", ["before","connect"])
def test_complete_sibling_drift_prevents_put(cycle: Cycle, stage: str) -> None:
    transport = cycle.transport()
    if stage == "before":
        cycle.device.sibling = "changed"
    else:
        cycle.device.on_connect = lambda:setattr(cycle.device,"sibling","changed")
    with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(transport)
    assert not cycle.device.requests and not (cycle.path/"enable.claim.json").exists()
    assert_closed(cycle.device)


@pytest.mark.parametrize("changes", [{"serial":"other-device"},{"status":"error"},{"http_method":"GET"},
    {"build":30},{"error":True},{"vdom":"foreign-vdom"},{"vdom":None},{"action":"schema"}])
def test_invalid_ack_consumes_dispatch_and_cannot_restore(cycle: Cycle, changes: dict[str,object]) -> None:
    cycle.device.ack_changes = changes
    transport = cycle.transport()
    with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(transport)
    assert len(cycle.device.requests) == 1
    assert (cycle.path/"enable.claim.json").exists()
    assert not (cycle.path/"enable.ack.json").exists()
    restore = cycle.transport("restore")
    with restore.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        restore.inspect_precondition()
    with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(transport)
    assert len(cycle.device.requests) == 1
    assert_closed(cycle.device)


def test_http_failure_has_terminal_claim(cycle: Cycle) -> None:
    cycle.device.status = 500
    transport = cycle.transport()
    with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(transport)
    assert len(cycle.device.requests)==1 and not (cycle.path/"enable.ack.json").exists()
    assert_closed(cycle.device)


def test_restore_requires_verified_full_readback_and_original_ack(cycle: Cycle) -> None:
    transport = cycle.transport()
    with transport.operation_lock():
        cycle.dispatch(transport)
        cycle.device.sibling = "changed"
        with pytest.raises(t.InstructionFeatureTransportError):
            transport.inspect_postcondition()
    assert not (cycle.path/"enable.result.json").exists()
    restore = cycle.transport("restore")
    with restore.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(restore)
    assert len(cycle.device.requests)==1
    cycle.device.sibling = "synthetic-private-value"
    with transport.operation_lock():
        transport.inspect_postcondition()
    with restore.operation_lock():
        restore.inspect_precondition()


@pytest.mark.parametrize("kind", ["tamper","mode","hardlink","missing","namespace"])
def test_restore_rejects_changed_original_records(cycle: Cycle, kind: str) -> None:
    cycle.enable()
    path = cycle.path/"enable.ack.json"
    if kind == "tamper":
        path.write_bytes(path.read_bytes().replace(b'"http_status":200',b'"http_status":201'))
    elif kind == "mode":
        path.chmod(0o644)
    elif kind == "hardlink":
        os.link(path,cycle.path/"duplicate")
    elif kind == "missing":
        path.unlink()
    restore = cycle.transport("restore",**({"cycle_nonce":"f"*64} if kind=="namespace" else {}))
    with restore.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(restore)
    assert len(cycle.device.requests)==1
    assert not (cycle.path/"restore.claim.json").exists()


def test_failed_claim_durability_prevents_put_and_remains_consumed(cycle: Cycle, monkeypatch: pytest.MonkeyPatch) -> None:
    transport = cycle.transport()
    def fail_sync(fd: int) -> None:
        raise OSError("synthetic-private-fsync-detail")
    with monkeypatch.context() as patch:
        patch.setattr(t.os,"fsync",fail_sync)
        with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
            cycle.dispatch(transport)
    assert (cycle.path/"enable.claim.json").exists() and not cycle.device.requests
    with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(transport)
    assert not cycle.device.requests
    assert_closed(cycle.device)


def test_clock_rollback_is_permanent_and_expiry_after_preflight_prevents_claim(cycle: Cycle) -> None:
    transport = cycle.transport()
    cycle.device.on_read = lambda:setattr(cycle.device,"clock",1031)
    with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(transport)
    assert not cycle.device.requests and not (cycle.path/"enable.claim.json").exists()
    cycle.device.on_read = lambda:None
    cycle.device.clock = 1000
    with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(transport)
    cycle.device.clock = 1040
    with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(transport)
    assert not cycle.device.requests


def test_configured_timeout_bounds_connect_and_full_preflight(cycle: Cycle) -> None:
    cycle.config = SecretMetadataHttpTransportConfig("https://synthetic.invalid","synthetic-token",1,None)
    transport = cycle.transport()
    cycle.device.on_read = lambda:setattr(cycle.device,"clock",1002)
    with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(transport)
    assert cycle.device.connection_options[0]["timeout"] == 1
    assert not cycle.device.requests and not (cycle.path/"enable.claim.json").exists()
    assert_closed(cycle.device)


def test_cleanup_exception_is_categorical_and_both_resources_close(cycle: Cycle) -> None:
    cycle.device.close_error = True
    transport = cycle.transport()
    with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError,match="^The private Instruction feature transport is unavailable.$"):
        cycle.dispatch(transport)
    assert len(cycle.device.requests)==1
    assert_closed(cycle.device)


@pytest.mark.parametrize("raw", [b'{}',b'{"status":"success","status":"success"}',b"x"*262145])
def test_bad_or_oversize_reply_does_not_create_ack(cycle: Cycle, raw: bytes) -> None:
    cycle.device.reply = raw
    transport = cycle.transport()
    with transport.operation_lock(), pytest.raises(t.InstructionFeatureTransportError):
        cycle.dispatch(transport)
    assert not (cycle.path/"enable.ack.json").exists()
    assert len(cycle.device.requests)==1
    assert_closed(cycle.device)


def test_url_userinfo_and_symlinked_lock_are_refused(cycle: Cycle) -> None:
    cycle.config = SecretMetadataHttpTransportConfig("https://user:pass@synthetic.invalid","synthetic-token",30,None)
    with pytest.raises(t.InstructionFeatureTransportError):
        cycle.transport()
    cycle.config = SecretMetadataHttpTransportConfig("https://synthetic.invalid","synthetic-token",30,None)
    (cycle.path/"operation.lock").symlink_to(cycle.path/"other")
    with pytest.raises(t.InstructionFeatureTransportError), cycle.transport().operation_lock():
        pytest.fail("symlink lock accepted")
    assert not cycle.device.connections
