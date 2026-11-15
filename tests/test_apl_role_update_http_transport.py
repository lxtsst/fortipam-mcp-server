"""Synthetic native HTTP lifecycle, original ownership and terminal claims."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import pickle
import shutil
import subprocess
import sys
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from fortipam_mcp.apl_role_update_contract import AplRoleUpdateBinding, CONFIG_FIELDS
from fortipam_mcp.apl_role_update_http_transport import (
    AplRoleUpdateHttpTransportError, FortiPamAplRoleUpdateHttpTransport, Phase,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning.material_provider import MaterialAccessDenied

from test_apl_role_update_contract import fixture as original_fixture

TABLE = "/api/v2/cmdb/user/auto-provision-rule"


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
        self.original, transition = original_fixture()
        self.binding = transition.binding
        self.defaults = {key: self.original[key] for key in CONFIG_FIELDS}
        self.defaults.update(name="", status="enable", accprofile={"name": "synthetic-default"})
        self.schema = {key: {"type": "string"} for key in CONFIG_FIELDS}
        self.schema_digest = hashlib.sha256(json.dumps(self.schema, sort_keys=True).encode()).hexdigest()
        self.serial_digest = hashlib.sha256(b"SYNTHETIC").hexdigest()
        self.deps: dict[str, dict[str, Any]] = {
            self.binding.group_name: {"name": self.binding.group_name, "q_origin_key": self.binding.group_name, "match": []},
            self.binding.original_role: {"name": self.binding.original_role, "q_origin_key": self.binding.original_role, "scope": "vdom"},
            self.binding.updated_role: {"name": self.binding.updated_role, "q_origin_key": self.binding.updated_role, "scope": "vdom"},
        }
        self.retained = [{**self.defaults, "name": "mcp-v4-apl-retained-" + suffix,
                          "status": "disable", "accprofile": self.binding.original_role} for suffix in ("a", "b")]
        self.created: dict[str, Any] | None = None
        self.connections: list[Connection] = []
        self.calls: list[tuple[str, str]] = []
        self.writes: list[str] = []
        self.bodies: list[bytearray] = []
        self.on_connect: Any = None
        self.lose_ack_at = 0
        self.fail_detail = False
        self.fail_detail_after_write = False
        self.bad_envelope: tuple[str, Any] | None = None

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
        key = parts[6] if len(parts) == 7 else None
        query = parse_qs(parsed.query)
        status = 200
        result: Any
        if method != "GET":
            assert path == "user" and table == "auto-provision-rule"
            self.writes.append(method)
            if body is not None:
                assert isinstance(body.obj, bytearray)
                self.bodies.append(body.obj)
                submitted = json.loads(bytes(body))
            if method == "POST":
                assert key is None and self.created is None
                assert submitted == {"name": self.binding.rule_name, "status": "disable",
                    "remote-group": self.binding.group_name, "accprofile": self.binding.original_role}
                self.created = {**self.original, **self.defaults, **submitted}
            elif method == "PUT":
                assert key == self.binding.rule_name and self.created is not None
                assert set(submitted) == {*CONFIG_FIELDS, "q_origin_key"}
                assert {k: v for k, v in submitted.items() if k != "accprofile"} == {
                    k: self.original[k] for k in submitted if k != "accprofile"}
                self.created.update(submitted)
            else:
                assert method == "DELETE" and key == self.binding.rule_name and body is None
                self.created = None
            if len(self.writes) == self.lose_ack_at:
                raise TimeoutError("Synthetic lost ACK with private native details")
            if self.fail_detail_after_write:
                self.fail_detail = True
            result = {}
        elif query.get("action") == ["schema"]:
            result = {"children": self.schema}
        elif query.get("action") == ["default"]:
            result = self.defaults
        elif table != "auto-provision-rule":
            assert key in self.deps
            result = [self.deps[key]]
        elif key:
            assert key == self.binding.rule_name
            if self.fail_detail:
                raise TimeoutError("Synthetic failed readback")
            if self.created is None:
                status, result = 404, []
            else:
                result = [self.created if query.get("with_meta") == ["true"] else {
                    k: self.created[k] for k in (*CONFIG_FIELDS, "q_origin_key")}]
        else:
            result = copy.deepcopy(self.retained)
            if self.created is not None:
                result.insert(1, {k: self.created[k] for k in (*CONFIG_FIELDS, "q_origin_key")})
        payload = {"version": "v7.0.0", "build": 29, "serial": "SYNTHETIC", "path": path, "name": table,
                   "http_method": method, "http_status": status, "status": "success" if status == 200 else "error",
                   "results": copy.deepcopy(result)}
        if method != "GET":
            payload["mkey"] = self.binding.rule_name
        if type(result) is list:
            payload.update(size=len(result), matched_count=len(result))
        if self.bad_envelope:
            payload[self.bad_envelope[0]] = self.bad_envelope[1]
        return Response(payload, status)


Fixture = tuple[Path, Peer, list[int]]


@pytest.fixture
def fixture(tmp_path: Path) -> Fixture:
    directory = tmp_path / "owned-apl"
    directory.mkdir(mode=0o700)
    return directory, Peer(), [100]


def make(fixture: Fixture, phase: Phase = "create", *, enabled: bool = True,
         binding: AplRoleUpdateBinding | None = None) -> FortiPamAplRoleUpdateHttpTransport:
    path, peer, now = fixture
    return FortiPamAplRoleUpdateHttpTransport(
        SecretMetadataHttpTransportConfig("https://pam.example", "synthetic-token", 5, None),
        binding or peer.binding, serial_digest=peer.serial_digest, schema_digest=peer.schema_digest,
        state_directory=path, phase=phase, execution_enabled=enabled, clock=lambda: now[0], connection_factory=peer.connection)


def run(fixture: Fixture, phase: Phase) -> str:
    client = make(fixture, phase)
    with client.operation_lock():
        current = client.inspect_current()
        expected = client.expected_state_digest()
        client.dispatch(expected_current_digest=current.state_digest, expires_at=fixture[2][0] + 60,
            plan_digest="1" * 64, authorization_digest="2" * 64, before_send=lambda: None)
        assert client.inspect_postcondition() == expected
    return expected


def test_complete_owned_roundtrip_preserves_records_rules_and_dependencies(fixture: Fixture) -> None:
    path, peer, _ = fixture
    original = copy.deepcopy((peer.retained, peer.deps))
    client = make(fixture)
    assert not list(path.iterdir()) and not peer.calls
    with pytest.raises(AplRoleUpdateHttpTransportError):
        client.inspect_current()
    run(fixture, "create")
    anchors = {p.name: p.read_bytes() for p in path.iterdir()}
    assert peer.created is not None and peer.created["status"] == "disable"
    for phase in ("update", "restore", "delete"):
        expected = run(fixture, phase)
        restarted = make(fixture, phase)
        with restarted.operation_lock():
            assert restarted.inspect_postcondition() == expected
            count = len(peer.calls)
            with pytest.raises(AplRoleUpdateHttpTransportError):
                restarted.inspect_current()
            assert len(peer.calls) == count
        assert all((path / name).read_bytes() == value for name, value in anchors.items())
    assert peer.writes == ["POST", "PUT", "PUT", "DELETE"] and peer.created is None
    assert original == (peer.retained, peer.deps)
    assert peer.bodies and all(not body for body in peer.bodies)
    assert all(c.closed and (c.response is None or c.response.closed) for c in peer.connections)


@pytest.mark.parametrize("phase", ["create", "update", "restore", "delete"])
def test_lost_ack_consumes_exact_phase_and_cannot_be_replayed(fixture: Fixture, phase: Phase) -> None:
    path, peer, _ = fixture
    if phase != "create":
        run(fixture, "create")
    if phase == "restore":
        run(fixture, "update")
    peer.lose_ack_at = len(peer.writes) + 1
    with pytest.raises(AplRoleUpdateHttpTransportError, match="^The private owned APL role transport is unavailable.$"):
        run(fixture, phase)
    assert (path / (phase + ".claim.json")).exists()
    assert not (path / (phase + "-ack.json")).exists()
    count = len(peer.calls)
    with make(fixture, phase).operation_lock():
        pass
    with pytest.raises(AplRoleUpdateHttpTransportError):
        run(fixture, phase)
    assert len(peer.calls) == count
    if phase in ("create", "update"):
        with pytest.raises(AplRoleUpdateHttpTransportError):
            run(fixture, "restore")
    assert all(not body for body in peer.bodies)


def test_acknowledged_update_failed_readback_allows_only_independent_fresh_restore(fixture: Fixture) -> None:
    path, peer, _ = fixture
    run(fixture, "create")
    peer.fail_detail_after_write = True
    with pytest.raises(AplRoleUpdateHttpTransportError):
        run(fixture, "update")
    assert (path / "update-ack.json").exists() and not (path / "update-verified.json").exists()
    peer.fail_detail_after_write = peer.fail_detail = False
    run(fixture, "restore")
    run(fixture, "delete")
    assert peer.writes == ["POST", "PUT", "PUT", "DELETE"]


@pytest.mark.parametrize("fault", ["enabled", "referenced", "metadata_type", "preserved_field", "rule_order", "group", "role", "schema"])
@pytest.mark.parametrize("phase", ["update", "restore"])
def test_drift_rejects_before_phase_claim(fixture: Fixture, fault: str, phase: Phase) -> None:
    path, peer, _ = fixture
    run(fixture, "create")
    if phase == "restore": run(fixture, "update")
    before = list(peer.writes)
    assert peer.created is not None
    if fault == "enabled": peer.created["status"] = "enable"
    elif fault == "referenced": peer.created["q_ref"] = 1
    elif fault == "metadata_type": peer.created["q_ref"] = False
    elif fault == "preserved_field": peer.created["trusthost10"] = "changed"
    elif fault == "rule_order": peer.retained.reverse()
    elif fault == "group": peer.deps[peer.binding.group_name]["match"] = [{"name": "other"}]
    elif fault == "role": peer.deps[peer.binding.updated_role]["scope"] = "global"
    else: peer.schema["description"]["type"] = "integer"
    with pytest.raises(AplRoleUpdateHttpTransportError):
        run(fixture, phase)
    assert not (path / (phase + ".claim.json")).exists() and peer.writes == before


@pytest.mark.parametrize("phase", ["create", "update", "restore", "delete"])
def test_closed_gate_prevents_dispatch(fixture: Fixture, phase: Phase) -> None:
    path, peer, now = fixture
    if phase != "create": run(fixture, "create")
    if phase == "restore": run(fixture, "update")
    client = make(fixture, phase, enabled=False)
    with client.operation_lock():
        current = client.inspect_current()
        count = len(peer.calls)
        with pytest.raises(AplRoleUpdateHttpTransportError):
            client.dispatch(expected_current_digest=current.state_digest, expires_at=now[0] + 60,
                plan_digest="1" * 64, authorization_digest="2" * 64, before_send=lambda: None)
    assert len(peer.calls) == count and not (path / (phase + ".claim.json")).exists()


@pytest.mark.parametrize("fault", ["expired", "long_ttl", "plan", "authorization", "current"])
def test_authority_context_and_deadline_refusals_create_no_claim(fixture: Fixture, fault: str) -> None:
    path, peer, now = fixture
    run(fixture, "create")
    client = make(fixture, "update")
    with client.operation_lock():
        current = client.inspect_current()
        with pytest.raises(AplRoleUpdateHttpTransportError):
            client.dispatch(expected_current_digest="0" * 64 if fault == "current" else current.state_digest,
                expires_at=now[0] + (0 if fault == "expired" else 61 if fault == "long_ttl" else 60),
                plan_digest="invalid" if fault == "plan" else "1" * 64,
                authorization_digest="invalid" if fault == "authorization" else "2" * 64, before_send=lambda: None)
    assert peer.writes == ["POST"] and not (path / "update.claim.json").exists()


def test_expiry_after_tls_consumes_claim_without_put_and_clock_rollback_remains_terminal(fixture: Fixture) -> None:
    path, peer, now = fixture
    run(fixture, "create")
    peer.on_connect = lambda: now.__setitem__(0, 160)
    with pytest.raises(AplRoleUpdateHttpTransportError):
        run(fixture, "update")
    assert (path / "update.claim.json").exists() and peer.writes == ["POST"]
    now[0] = 159
    with pytest.raises(AplRoleUpdateHttpTransportError):
        run(fixture, "update")
    assert peer.writes == ["POST"]


def test_authority_revocation_after_tls_consumes_claim_without_sending(fixture: Fixture) -> None:
    path, peer, now = fixture
    run(fixture, "create")
    allowed = [True]
    peer.on_connect = lambda: allowed.__setitem__(0, False)
    def authority() -> None:
        if not allowed[0]:
            raise PermissionError("Synthetic revoked authority")
    client = make(fixture, "update")
    with client.operation_lock():
        current = client.inspect_current()
        with pytest.raises(AplRoleUpdateHttpTransportError):
            client.dispatch(expected_current_digest=current.state_digest, expires_at=now[0] + 60,
                plan_digest="1" * 64, authorization_digest="2" * 64, before_send=authority)
    assert peer.writes == ["POST"] and (path / "update.claim.json").exists()


@pytest.mark.parametrize("phase", ["update", "restore", "delete"])
@pytest.mark.parametrize("late_clock", [160, 99])
def test_clock_failure_during_post_tls_ownership_check_cannot_send_or_replay(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch, phase: Phase, late_clock: int,
) -> None:
    path, peer, now = fixture
    run(fixture, "create")
    if phase == "restore":
        run(fixture, "update")
    writes = peer.writes.copy()
    connected = [False]
    peer.on_connect = lambda: connected.__setitem__(0, True)
    original_anchors = FortiPamAplRoleUpdateHttpTransport._anchors

    def delayed_anchors(self: FortiPamAplRoleUpdateHttpTransport, plan: dict[str, Any]) -> dict[str, str]:
        result = original_anchors(self, plan)
        if connected[0]:
            now[0] = late_clock
        return result

    monkeypatch.setattr(FortiPamAplRoleUpdateHttpTransport, "_anchors", delayed_anchors)
    with pytest.raises(AplRoleUpdateHttpTransportError):
        run(fixture, phase)
    claim_path = path / (phase + ".claim.json")
    claim = claim_path.read_bytes()
    assert connected[0] and peer.writes == writes
    assert not (path / (phase + "-ack.json")).exists()
    assert not (path / (phase + "-verified.json")).exists()
    connected[0], now[0], peer.on_connect = False, 100, None
    with pytest.raises(AplRoleUpdateHttpTransportError):
        run(fixture, phase)
    assert peer.writes == writes and claim_path.read_bytes() == claim


@pytest.mark.parametrize("fault", ["binding", "copied_directory"])
def test_changed_namespace_cannot_adopt_original_creation(fixture: Fixture, tmp_path: Path, fault: str) -> None:
    path, peer, now = fixture
    run(fixture, "create")
    count = len(peer.calls)
    changed = None
    if fault == "copied_directory":
        destination = tmp_path / "copied-apl"
        shutil.copytree(path, destination)
        fixture = destination, peer, now
    else:
        b = peer.binding
        changed = AplRoleUpdateBinding(b.rule_name, b.group_name, b.original_role, b.updated_role, "e" * 64)
    client = make(fixture, "update", binding=changed)
    with client.operation_lock():
        with pytest.raises(AplRoleUpdateHttpTransportError):
            client.inspect_current()
    assert peer.writes == ["POST"] and len(peer.calls) == count


@pytest.mark.parametrize("name", ["create-ack.json", "created.json", "legacy-create.claim.json", "creation.ownership.json"])
def test_missing_original_ownership_is_not_reconstructed(fixture: Fixture, name: str) -> None:
    path, peer, _ = fixture
    run(fixture, "create")
    (path / name).unlink()
    with pytest.raises(AplRoleUpdateHttpTransportError):
        run(fixture, "update")
    assert not (path / name).exists() and peer.writes == ["POST"]


def test_modified_creation_record_cannot_be_adopted_even_with_recomputed_transition(fixture: Fixture) -> None:
    path, peer, _ = fixture
    run(fixture, "create")
    record = json.loads((path / "created.json").read_text())
    assert peer.created is not None
    peer.created["description"] = record["record"]["description"] = "changed"
    client = make(fixture, "update")
    record["transition_digest"] = client._transition(client._plan(), record["record"]).digest
    (path / "created.json").write_text(json.dumps(record))
    with pytest.raises(AplRoleUpdateHttpTransportError):
        run(fixture, "update")
    assert peer.writes == ["POST"]


@pytest.mark.parametrize("fault", ["symlink", "hardlink", "mode", "content"])
def test_unsafe_lock_is_refused(fixture: Fixture, tmp_path: Path, fault: str) -> None:
    path, peer, _ = fixture
    lock = path / "operation.lock"
    other = tmp_path / "other"
    other.touch(mode=0o600)
    if fault == "symlink": lock.symlink_to(other)
    elif fault == "hardlink": os.link(other, lock)
    else:
        lock.touch(mode=0o600)
        if fault == "mode": lock.chmod(0o644)
        else: lock.write_text("unexpected")
    with pytest.raises(AplRoleUpdateHttpTransportError):
        with make(fixture).operation_lock():
            pytest.fail("Unsafe lock accepted")
    assert not peer.calls


def test_cross_process_lock_and_readiness_are_private(fixture: Fixture) -> None:
    path, _, _ = fixture
    client = make(fixture)
    with client.operation_lock():
        readiness = client.inspect_current()
        child = subprocess.run([sys.executable, "-c",
            "import fcntl,sys;f=open(sys.argv[1],'r+');fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)",
            str(path / "operation.lock")], capture_output=True)
        assert child.returncode != 0
    with make(fixture).operation_lock():
        pass
    for value in (client, readiness):
        assert "mcp-v4" not in repr(value)
        for operation in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(MaterialAccessDenied): operation(value)


@pytest.mark.parametrize("field,value", [("build", True), ("serial", "OTHER"), ("http_method", "POST"), ("http_status", True)])
def test_wrong_device_envelope_is_refused_without_mutation(fixture: Fixture, field: str, value: object) -> None:
    path, peer, _ = fixture
    peer.bad_envelope = (field, value)
    with pytest.raises(AplRoleUpdateHttpTransportError):
        run(fixture, "create")
    assert not peer.writes and not (path / "create.claim.json").exists()
