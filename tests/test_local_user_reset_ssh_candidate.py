"""Synthetic end-to-end durable execution of the fixed SSH fallback."""

from dataclasses import replace
import asyncio
from pathlib import Path
import time
from types import SimpleNamespace

import pytest

from fortipam_mcp.local_user_reset_api_actor import LocalUserResetApiActor
from fortipam_mcp.local_user_reset_execution import (
    FortiPamLocalUserResetExecution, LocalUserResetExecutionError, LocalUserResetLabIntentVerifier,
)
from fortipam_mcp.local_user_reset_http_transport import LocalUserResetBinding, LocalUserResetMaterialLease, _POLICY_PATH
from fortipam_mcp.local_user_reset_material_source import OwnerOnlyLocalUserResetMaterialSource
from fortipam_mcp.local_user_reset_metadata_reader import _device_identity_digest
from fortipam_mcp.local_user_reset_policy_reader import FortiPamLocalUserResetPolicyReader
from fortipam_mcp.local_user_reset_preview import FortiPamLocalUserResetPreviewReader
from fortipam_mcp.local_user_reset_provenance_inspector import FortiPamLocalUserResetProvenanceInspector
from fortipam_mcp.local_user_reset_ssh_candidate import FortiPamLocalUserResetSshCandidate, _read_ssh_device_identity
from fortipam_mcp.cli_safety import CliTransportError
from fortipam_mcp.target_ssh_transport import TargetSshTransportError
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning import M4Outcome

from test_local_user_reset_api_actor import _Connection, _Response
from test_local_user_reset_execution import _policy
from test_local_user_reset_http_transport import _baseline
from test_local_user_reset_ssh_transport import _FakeSshSession, _FakeProcess, _config
from test_m4_execution_store import _store
import fortipam_mcp.local_user_reset_ssh_transport as ssh_module


@pytest.mark.parametrize("mode", ["complete", "split_marker", "wrong_prompt", "missing_serial",
                                  "duplicate_serial", "too_many_pages", "rejected"])
def test_fixed_device_status_reader_handles_bounded_pagination(mode: str) -> None:
    class Session(_FakeSshSession):
        pages = 0

        def dispatch(self, data):
            self.commands.append(data.decode())
            if data == b"get system status\n":
                serial = b"" if mode == "missing_serial" else b"Serial-Number: SYNTHETIC01\r\n"
                self._emit(serial + b"--More--")
            else:
                assert data == b" "
                self.pages += 1
                if mode == "too_many_pages":
                    self._emit(b"\n--More--")
                elif mode == "wrong_prompt":
                    self._emit(b"\nother #")
                elif mode == "duplicate_serial":
                    self._emit(b"\nSerial-Number: SYNTHETIC01\nfpa #")
                elif mode == "rejected":
                    self._emit(b"\npermission denied\nfpa #")
                else:
                    self._emit(b"\nfpa #")

    session = Session(compact=b"", full_outputs=[])
    session._reader._buffer.clear()
    if mode == "split_marker":
        read = session._reader.read

        async def small_read(size):
            return await read(min(size, 4))

        session._reader.read = small_read
    operation = _read_ssh_device_identity(_FakeProcess(session), b"fpa #", time.monotonic() + 5)
    if mode in {"complete", "split_marker"}:
        assert asyncio.run(operation) == _device_identity_digest(b"SYNTHETIC01")
    else:
        with pytest.raises((ValueError, CliTransportError, TargetSshTransportError)):
            asyncio.run(operation)
    assert session.pages == (4 if mode == "too_many_pages" else 1)
    assert session.commands[0] == "get system status\n"
    assert all(command == " " for command in session.commands[1:])


@pytest.mark.parametrize("failure", [None, "writer_before_intent", "writer_after_intent",
    "device_after_intent", "commit", "postread", "policy", "material", "trust_drift", "api_intent", "target_disappeared"])
def test_fixed_fallback_requires_exact_authority_and_preserves_uncertain_claims(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str | None,
) -> None:
    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "synthetic-token", 5, None)
    binding = LocalUserResetBinding(_baseline(status="enable", access_profile="Guest"))
    serial = _device_identity_digest(b"SYNTHETIC01")
    wrote = False
    inspector = object.__new__(FortiPamLocalUserResetProvenanceInspector)
    inspector._config, inspector._principal = config, "synthetic-api-principal"
    inspector._metadata = SimpleNamespace(read_device_identity_digest=lambda: serial)
    monkeypatch.setattr(FortiPamLocalUserResetProvenanceInspector, "read_nonmaterial_baseline",
        lambda self: replace(binding.expected, nonmaterial_state_digest="f" * 64)
        if failure == "postread" and wrote else binding.expected)
    policy = _policy()
    policy_reader = object.__new__(FortiPamLocalUserResetPolicyReader)
    policy_reader._config, policy_reader._host, policy_reader._port = config, "pam.example.test", 443
    monkeypatch.setattr(FortiPamLocalUserResetPolicyReader, "read_policy_snapshot", lambda self: policy)
    preview = FortiPamLocalUserResetPreviewReader(binding, inspector, policy, policy_reader,
                                                 clock=lambda: 1000).read_preview()
    source = object.__new__(OwnerOnlyLocalUserResetMaterialSource)
    source._binding, source._inspector, source._binding_digest = binding, inspector, "d" * 64
    source._enabled, source._current_selection_digest, source._current = True, None, None
    source._fixture = tmp_path / "fixture"
    source._fixture.mkdir(mode=0o700)
    old = bytearray(b"synthetic-old")
    new = bytearray(b"synthetic-new" if failure != "material" else b'synthetic-"-new')
    material_acquisitions = []
    store = _store(tmp_path)

    def material(self):
        assert store.audit_events == ()
        material_acquisitions.append(True)
        return LocalUserResetMaterialLease(lambda: (memoryview(old), memoryview(new)))

    monkeypatch.setattr(OwnerOnlyLocalUserResetMaterialSource, "__call__", material)
    calls = []

    class PolicyConnection(_Connection):
        def getresponse(self):
            return _Response(b'{"results":{"valid":false}}') if failure == "policy" else super().getresponse()

    actor = LocalUserResetApiActor(config, binding=binding, inspector=inspector, enabled=True,
        connection_factory=lambda *args, **kwargs: PolicyConnection(calls), clock=lambda: 100.0)
    sessions = []
    after_intent = False

    class Session(_FakeSshSession):
        def dispatch(self, data):
            nonlocal wrote
            command = data.decode().strip()
            if command == "get system status":
                self.commands.append(command)
                self._emit(b"Serial-Number: " +
                    (b"OTHERDEVICE" if failure == "device_after_intent" and after_intent else b"SYNTHETIC01")
                    + b"\r\nfpa #")
            elif command == "next" and failure == "commit":
                self.commands.append(command)
                self._emit(b"Command fail. Return code 1\nfpa (admin-entry) #")
            elif command.startswith("edit ") and failure == "target_disappeared":
                self.commands.append(command)
                self._emit(b"new entry 'synthetic-target' added\nfpa (admin-entry) #")
            else:
                if command.startswith("set password "):
                    wrote = True
                super().dispatch(data)

    def connect(*args, **kwargs):
        session = Session(compact=b"", full_outputs=[], writer_profile="custom"
            if failure == "writer_before_intent" or failure == "writer_after_intent" and after_intent
            else "super_admin")
        sessions.append(session)
        return session

    monkeypatch.setattr(ssh_module.asyncssh, "connect", connect)
    transport = FortiPamLocalUserResetSshCandidate(config, ssh_config=_config(tmp_path),
        binding=binding, inspector=inspector, owner_session=actor, material_lease_provider=source,
        device_identity_digest=serial, enabled=True)
    assert transport.reset().outcome == "gate_closed"
    assert not sessions and not material_acquisitions
    with actor.authenticated():
        if failure == "writer_before_intent":
            with pytest.raises(LocalUserResetExecutionError):
                LocalUserResetLabIntentVerifier.issue(binding=binding, inspector=inspector, actor=actor,
                    material_source=source, policy_snapshot=policy, policy_inspector=policy_reader,
                    preview=preview, now_epoch=1001, ssh_candidate=transport)
            assert not calls and not material_acquisitions and store.audit_events == ()
            return
        intent, verifier = LocalUserResetLabIntentVerifier.issue(
            binding=binding, inspector=inspector, actor=actor, material_source=source,
            policy_snapshot=policy, policy_inspector=policy_reader, preview=preview,
            now_epoch=1001, ssh_candidate=None if failure == "api_intent" else transport)
        after_intent = True
        kwargs = dict(intent=intent, authenticated_requester_digest=intent.requester_digest,
            authorized_scope_digest=intent.scope_digest, authorization_verifier=verifier,
            policy_snapshot=policy, policy_inspector=policy_reader, preflight_preview=preview,
            enabled=True, clock=lambda: 1001)
        if failure == "api_intent":
            with pytest.raises(LocalUserResetExecutionError):
                FortiPamLocalUserResetExecution(transport, store, **kwargs)
            assert not calls and not material_acquisitions and store.audit_events == ()
            return
        runner = FortiPamLocalUserResetExecution(transport, store, **kwargs)
        if failure == "trust_drift":
            transport._ssh_config.known_hosts_file.write_text("changed public trust file\n")
        result = runner.execute()
        if failure is None:
            before = sum(len(session.commands) for session in sessions)
            replay = runner.execute()
            assert replay.idempotent_replay and replay.outcome is M4Outcome.SUCCEEDED
            assert sum(len(session.commands) for session in sessions) == before
    expected = {None: M4Outcome.SUCCEEDED, "commit": M4Outcome.RECONCILIATION_REQUIRED,
        "postread": M4Outcome.RECONCILIATION_REQUIRED, "policy": M4Outcome.EXECUTION_FAILED,
        "trust_drift": M4Outcome.DENIED, "target_disappeared": M4Outcome.RECONCILIATION_REQUIRED}
    assert result.outcome is expected.get(failure, M4Outcome.PRECONDITION_FAILED)
    commands = [command for session in sessions for command in session.commands]
    writes = [command for command in commands if command.startswith("set password ")]
    assert writes == (['set password "synthetic-new" "synthetic-old"']
                      if failure in {None, "commit", "postread"} else [])
    assert calls == ([_POLICY_PATH] if failure in {None, "commit", "postread", "policy", "target_disappeared"} else [])
    assert len(material_acquisitions) == (0 if failure in {"writer_after_intent", "device_after_intent", "trust_drift"} else 1)
    if material_acquisitions:
        assert not any(old) and not any(new)
    assert len(store.audit_events) == (0 if failure == "trust_drift" else 1)
