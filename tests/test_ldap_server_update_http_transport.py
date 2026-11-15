"""Synthetic fixed update/restore transport, original ownership and no replay."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from fortipam_mcp.ldap_server_contract import LdapServerCandidateError, LdapServerCreateOutcome
from fortipam_mcp.ldap_server_update_http_transport import FortiPamLdapServerUpdateHttpTransport, Phase
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig

from test_ldap_server_http_transport import Peer, Response, dispatch as create_dispatch, transport as create_transport
from test_ldap_server_projection import envelope


class UpdatePeer(Peer):
    def __init__(self) -> None:
        super().__init__()
        self.puts = 0
        self.info_tests = 0
        self.lose_ack_at: int | None = None
        self.fail_readback = False
        self.bodies: list[bytearray] = []

    def handle(self, method: str, url: str, body: memoryview | None) -> Response:
        parsed = urlsplit(url)
        if parsed.path == "/api/v2/monitor/service/ldap/query":
            value = json.loads(parse_qs(parsed.query)["json"][0])
            if value["mkey"] is not None:
                assert value["mkey"] == self.binding.name and value["info_only"] == 1
                assert "password" not in value["ldap"]
                assert value["ldap"]["username"] == self.binding.username
                self.info_tests += 1
                return Response(envelope(results={"schema": {"objectClasses": ["synthetic"],
                    "attributeTypes": {"synthetic": {}}}, "rootdse": {},
                    "general": {"configured_dn": self.binding.dn, "server_type": "synthetic"}}))
        if method == "PUT":
            assert parsed.path == "/api/v2/cmdb/user/ldap/" + self.binding.name
            assert self.row is not None and body is not None and isinstance(body.obj, bytearray)
            self.bodies.append(body.obj)
            submitted = json.loads(bytes(body))
            assert len(submitted) == 18 and submitted["password"] == self.row["password"]
            assert submitted["group-object-filter"] == ""
            self.row["group-filter"] = submitted["group-filter"]
            self.puts += 1
            if self.puts == self.lose_ack_at:
                raise TimeoutError("Synthetic lost response")
            return Response(envelope(http_method="PUT", mkey=self.binding.name, results={},
                old_revision="synthetic-before", revision="synthetic-after"))
        if self.fail_readback and self.puts and parsed.path == "/api/v2/cmdb/user/ldap/" + self.binding.name:
            raise TimeoutError("Synthetic failed readback")
        return super().handle(method, url, body)


@pytest.fixture
def fixture(tmp_path: Path) -> tuple[Path, Path, UpdatePeer, list[int]]:
    creation = tmp_path / "creation"
    operation = creation.with_name(creation.name + ".ldap-update")
    creation.mkdir(mode=0o700)
    operation.mkdir(mode=0o700)
    peer, now = UpdatePeer(), [100]
    original = create_transport(creation, peer, now)
    digest = original.inspect_create().state_digest
    creating = create_transport(creation, peer, now, expected=digest, execute=True)
    assert create_dispatch(creating, peer) is LdapServerCreateOutcome.VERIFIED_CREATED
    return creation, operation, peer, now


def make(fixture: tuple[Path, Path, UpdatePeer, list[int]], phase: Phase = "update", *,
         enabled: bool = True, operation: Path | None = None) -> FortiPamLdapServerUpdateHttpTransport:
    creation, state, peer, now = fixture
    return FortiPamLdapServerUpdateHttpTransport(
        SecretMetadataHttpTransportConfig("https://pam.example", "synthetic-token", 5, None),
        peer.binding, expected_serial="SYNTHETIC_DEVICE", creation_state_directory=creation,
        state_directory=operation or state, phase=phase, execution_enabled=enabled,
        clock=lambda: now[0], connection_factory=peer.connection)


def run(client: FortiPamLdapServerUpdateHttpTransport, now: list[int]) -> str:
    with client.operation_lock():
        readiness = client.inspect_current()
        expected = client.expected_state_digest()
        client.dispatch(expected_current_digest=readiness.state_digest, expires_at=now[0] + 60,
            plan_digest="1" * 64, authorization_digest="2" * 64, before_send=lambda: None)
        assert client.inspect_postcondition() == expected
        return expected


def test_full_fixed_roundtrip_restart_claims_and_original_creation_unchanged(fixture: tuple[Path, Path, UpdatePeer, list[int]]) -> None:
    creation, state, peer, now = fixture
    original = {p.name: p.read_bytes() for p in creation.iterdir()}
    connections = len(peer.connections)
    update = make(fixture)
    assert len(peer.connections) == connections and list(state.iterdir()) == []
    with pytest.raises(LdapServerCandidateError):
        update.expected_state_digest()
    expected = run(update, now)
    assert peer.puts == 1 and peer.info_tests == 2
    restarted = make(fixture)
    assert restarted.inspect_postcondition() == expected
    with pytest.raises(LdapServerCandidateError):
        restarted.inspect_current()
    claim = json.loads((state / "update.claim.json").read_text())
    assert claim["plan_digest"] == "1" * 64 and claim["authorization_digest"] == "2" * 64
    run(make(fixture, "restore"), now)
    assert peer.puts == 2 and peer.info_tests == 3
    assert peer.row is not None and peer.row["group-filter"] == ""
    assert original == {p.name: p.read_bytes() for p in creation.iterdir()}
    assert peer.bodies and all(not body for body in peer.bodies)
    with pytest.raises(LdapServerCandidateError):
        make(fixture, "restore").inspect_current()


@pytest.mark.parametrize("phase", ["update", "restore"])
def test_lost_ack_never_replays_or_qualifies_postcondition(fixture: tuple[Path, Path, UpdatePeer, list[int]], phase: Phase) -> None:
    _, state, peer, now = fixture
    if phase == "restore":
        run(make(fixture), now)
    peer.lose_ack_at = peer.puts + 1
    with pytest.raises(LdapServerCandidateError):
        run(make(fixture, phase), now)
    assert (state / (phase + ".claim.json")).exists()
    assert not (state / (phase + "-ack.json")).exists()
    puts, tests = peer.puts, peer.info_tests
    for action in (make(fixture, phase).inspect_current, make(fixture, phase).inspect_postcondition):
        with pytest.raises(LdapServerCandidateError):
            action()
    assert (peer.puts, peer.info_tests) == (puts, tests)
    if phase == "update":
        with pytest.raises(LdapServerCandidateError):
            make(fixture, "restore").inspect_current()
        assert not (state / "restore.claim.json").exists()
    assert all(not body for body in peer.bodies)


def test_acknowledged_update_with_failed_readback_can_restore_only_after_fresh_b(fixture: tuple[Path, Path, UpdatePeer, list[int]]) -> None:
    _, state, peer, now = fixture
    peer.fail_readback = True
    with pytest.raises(LdapServerCandidateError):
        run(make(fixture), now)
    assert (state / "update-ack.json").exists() and not (state / "update-verified.json").exists()
    with pytest.raises(LdapServerCandidateError):
        make(fixture).inspect_postcondition()
    peer.fail_readback = False
    run(make(fixture, "restore"), now)
    assert peer.puts == 2


@pytest.mark.parametrize("field,value", [("password", "changed-token"), ("obtain-user-info", "changed-opaque"), ("q_ref", 1)])
def test_restore_drift_refuses_before_claim(fixture: tuple[Path, Path, UpdatePeer, list[int]], field: str, value: object) -> None:
    _, state, peer, now = fixture
    run(make(fixture), now)
    assert peer.row is not None
    peer.row[field] = value
    with pytest.raises(LdapServerCandidateError):
        make(fixture, "restore").inspect_current()
    assert not (state / "restore.claim.json").exists() and peer.puts == 1


@pytest.mark.parametrize("failure", ["gate", "past", "long_ttl", "bad_plan", "bad_authorization", "bad_current"])
def test_dispatch_guards_leave_no_claim(fixture: tuple[Path, Path, UpdatePeer, list[int]], failure: str) -> None:
    _, state, peer, now = fixture
    client = make(fixture, enabled=failure != "gate")
    readiness = client.inspect_current()
    with pytest.raises(LdapServerCandidateError):
        client.dispatch(expected_current_digest="0" * 64 if failure == "bad_current" else readiness.state_digest,
            expires_at=now[0] + (0 if failure == "past" else 61 if failure == "long_ttl" else 60),
            plan_digest="invalid" if failure == "bad_plan" else "1" * 64,
            authorization_digest="invalid" if failure == "bad_authorization" else "2" * 64,
            before_send=lambda: None)
    assert peer.puts == peer.info_tests == 0 and not (state / "update.claim.json").exists()


def test_tls_expiry_and_clock_rollback_are_terminal(fixture: tuple[Path, Path, UpdatePeer, list[int]]) -> None:
    _, state, peer, now = fixture
    client = make(fixture)
    readiness = client.inspect_current()
    peer.on_connect = lambda: now.__setitem__(0, 160)
    with pytest.raises(LdapServerCandidateError):
        client.dispatch(expected_current_digest=readiness.state_digest, expires_at=160,
            plan_digest="1" * 64, authorization_digest="2" * 64, before_send=lambda: None)
    assert (state / "update.claim.json").exists() and peer.puts == peer.info_tests == 0
    now[0] = 159
    with pytest.raises(LdapServerCandidateError):
        client.inspect_current()
    now[0] = 160
    with pytest.raises(LdapServerCandidateError):
        client.inspect_current()


def test_fresh_state_directory_cannot_bypass_claims(fixture: tuple[Path, Path, UpdatePeer, list[int]], tmp_path: Path) -> None:
    alternate = tmp_path / "another-operation"
    alternate.mkdir(mode=0o700)
    with pytest.raises(LdapServerCandidateError):
        make(fixture, operation=alternate)


def test_restart_refuses_time_before_the_durable_update_ack(fixture: tuple[Path, Path, UpdatePeer, list[int]]) -> None:
    _, state, _, now = fixture
    now[0] = 110
    run(make(fixture), now)
    now[0] = 105
    with pytest.raises(LdapServerCandidateError):
        make(fixture, "restore").inspect_current()
    assert not (state / "restore.claim.json").exists()


def test_missing_creation_record_is_never_rebuilt(fixture: tuple[Path, Path, UpdatePeer, list[int]]) -> None:
    creation, state, peer, _ = fixture
    (creation / "created.json").unlink()
    with pytest.raises(LdapServerCandidateError):
        make(fixture).inspect_current()
    assert not (creation / "created.json").exists() and not (state / "update.plan.json").exists()
    assert peer.puts == 0


@pytest.mark.parametrize("fault", ["symlink", "hardlink", "mode", "content"])
def test_operation_lock_rejects_unsafe_files(fixture: tuple[Path, Path, UpdatePeer, list[int]], tmp_path: Path, fault: str) -> None:
    _, state, _, _ = fixture
    lock = state / "operation.lock"
    original = tmp_path / "external-lock"
    original.touch(mode=0o600)
    if fault == "symlink": lock.symlink_to(original)
    elif fault == "hardlink": os.link(original, lock)
    else:
        lock.touch(mode=0o600)
        if fault == "mode": lock.chmod(0o644)
        else: lock.write_text("unqualified")
    with pytest.raises(LdapServerCandidateError):
        with make(fixture).operation_lock():
            pytest.fail("Unsafe lock accepted")


def test_operation_lock_excludes_another_process_and_releases(fixture: tuple[Path, Path, UpdatePeer, list[int]]) -> None:
    _, state, _, _ = fixture
    script = """import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDWR)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit(17)
finally:
    os.close(fd)
"""
    command = [sys.executable, "-c", script, str(state / "operation.lock")]
    with make(fixture).operation_lock():
        assert subprocess.run(command, capture_output=True, timeout=5).returncode == 17
    assert subprocess.run(command, capture_output=True, timeout=5).returncode == 0
