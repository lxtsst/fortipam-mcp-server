"""Bound synthetic proof for the existing API actor's fixed BP002 path."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from fortipam_mcp.local_user_reset_api_actor import LocalUserResetApiActor
from fortipam_mcp.local_user_reset_execution import (
    FortiPamLocalUserResetExecution, LocalUserResetLabIntentVerifier,
)
from fortipam_mcp.local_user_reset_http_transport import (
    FortiPamLocalUserResetHttpTransport, LocalUserResetBinding,
    LocalUserResetHttpOutcome, LocalUserResetMaterialLease, _CHANGE_PATH, _POLICY_PATH,
)
from fortipam_mcp.local_user_reset_material_source import OwnerOnlyLocalUserResetMaterialSource
from fortipam_mcp.local_user_reset_policy_reader import FortiPamLocalUserResetPolicyReader
from fortipam_mcp.local_user_reset_preview import FortiPamLocalUserResetPreviewReader
from fortipam_mcp.local_user_reset_provenance_inspector import FortiPamLocalUserResetProvenanceInspector
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning import M4Outcome

from test_local_user_reset_execution import _policy
from test_local_user_reset_http_transport import _baseline
from test_m4_execution_store import _store


class _Response:
    def __init__(self, content: bytes) -> None:
        self.status, self._content, self._offset = 200, content, 0

    def getheader(self, name: str, default: str = "") -> str:
        return {"content-type": "application/json", "content-encoding": "identity"}.get(name, default)

    def readinto(self, target: memoryview) -> int:
        count = min(target.nbytes, len(self._content) - self._offset)
        target[:count] = self._content[self._offset:self._offset + count]
        self._offset += count
        return count

    def close(self) -> None:
        pass


class _Connection:
    def __init__(self, calls: list[str]) -> None:
        self._calls, self._path = calls, ""

    def request(self, method: str, path: str, *, body: memoryview,
                headers: dict[str, str]) -> None:
        assert method == "POST" and body.readonly
        assert headers["Authorization"] == "Bearer synthetic-token"
        self._path = path
        self._calls.append(path)

    def getresponse(self) -> _Response:
        return _Response(b'{"results":{"valid":true}}' if self._path == _POLICY_PATH
                         else b'{"results":{"changed":true}}')

    def close(self) -> None:
        pass


@pytest.mark.parametrize("rotate_after_intent", [False, True])
def test_real_material_path_requires_exact_issued_intent_and_durable_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, rotate_after_intent: bool,
) -> None:
    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "synthetic-token", 5, None)
    binding = LocalUserResetBinding(_baseline())
    inspector = object.__new__(FortiPamLocalUserResetProvenanceInspector)
    inspector._config, inspector._principal = config, "synthetic-api-principal"
    monkeypatch.setattr(FortiPamLocalUserResetProvenanceInspector,
                        "read_nonmaterial_baseline", lambda self: binding.expected)
    policy = _policy()
    policy_reader = object.__new__(FortiPamLocalUserResetPolicyReader)
    policy_reader._config, policy_reader._host, policy_reader._port = config, "pam.example.test", 443
    monkeypatch.setattr(FortiPamLocalUserResetPolicyReader,
                        "read_policy_snapshot", lambda self: policy)
    preview = FortiPamLocalUserResetPreviewReader(
        binding, inspector, policy, policy_reader, clock=lambda: 1000,
    ).read_preview()
    source = object.__new__(OwnerOnlyLocalUserResetMaterialSource)
    source._binding, source._inspector, source._binding_digest = binding, inspector, "d" * 64
    source._enabled = True
    source._current_selection_digest = None
    source._current = None
    source._fixture = tmp_path / "fixture"
    source._fixture.mkdir(mode=0o700)
    old, new = bytearray(b"synthetic-old"), bytearray(b"synthetic-new")
    monkeypatch.setattr(OwnerOnlyLocalUserResetMaterialSource, "__call__",
        lambda self: LocalUserResetMaterialLease(lambda: (memoryview(old), memoryview(new))))
    calls: list[str] = []
    actor = LocalUserResetApiActor(config, binding=binding, inspector=inspector,
        enabled=True, connection_factory=lambda *args, **kwargs: _Connection(calls),
        clock=lambda: 100.0)
    transport = FortiPamLocalUserResetHttpTransport(config, binding=binding,
        inspector=inspector, owner_session=actor, material_lease_provider=source, enabled=True)
    assert transport.reset().outcome is LocalUserResetHttpOutcome.GATE_CLOSED
    with actor.authenticated():
        intent, verifier = LocalUserResetLabIntentVerifier.issue(
            binding=binding, inspector=inspector, actor=actor, material_source=source,
            policy_snapshot=policy, policy_inspector=policy_reader, preview=preview,
            now_epoch=1001,
        )
        runner = FortiPamLocalUserResetExecution(transport, _store(tmp_path),
            intent=intent, authenticated_requester_digest=intent.requester_digest,
            authorized_scope_digest=intent.scope_digest, authorization_verifier=verifier,
            policy_snapshot=policy, policy_inspector=policy_reader,
            preflight_preview=preview, enabled=True, clock=lambda: 1001)
        if rotate_after_intent:
            (source._fixture / "current-login-binding.json").write_text("{}")
        result = runner.execute()
    if rotate_after_intent:
        assert result.outcome is M4Outcome.DENIED
        assert calls == [] and _store(tmp_path).audit_events == ()
        assert not verifier._consumed
        assert old == bytearray(b"synthetic-old") and new == bytearray(b"synthetic-new")
        return
    assert result.outcome is M4Outcome.SUCCEEDED
    assert calls == [_POLICY_PATH, _CHANGE_PATH]
    assert actor._observations == {
        operation: {"connection_reserved": True, "request_sent": True,
                    "response_received": True, "http_status": 200, "accepted": True}
        for operation in ("policy_conform", "change_password")
    }
    assert not any(old) and not any(new)
    assert _store(tmp_path).audit_events[0].authorization == "verified"
