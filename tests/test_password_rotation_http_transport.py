"""Behavior coverage for the fixed build-29 Unix rotation transport."""

from dataclasses import replace

import pytest

import fortipam_mcp.password_rotation_http_transport as module
from fortipam_mcp.password_rotation_http_transport import (
    FortiPamPasswordRotationHttpTransport,
    PasswordRotationHttpTransportError,
    PasswordRotationState,
)
from fortipam_mcp.password_verification_http_transport import PasswordVerificationBinding
from test_secret_session_controls_http_transport import _Connection, _Response, _config


BINDING = PasswordVerificationBinding(
    "Public/test", "unix-rotation-fixture", "test-target", "192.0.2.10", "test-user",
)
CURRENT = PasswordRotationState(23, 17, None, True, True, True, True)


@pytest.mark.parametrize("advanced", [True, False])
def test_rotation_requires_fresh_change_marker_for_verified_readback(monkeypatch, advanced):
    transport = FortiPamPasswordRotationHttpTransport(_config(), BINDING)
    after = replace(CURRENT, change_marker="a" * 64 if advanced else None)
    states = iter([CURRENT, after])
    calls = []
    monkeypatch.setattr(transport, "inspect", lambda: next(states))
    monkeypatch.setattr(transport, "_require_protected_account_match", lambda state: calls.append("match"))
    monkeypatch.setattr(transport, "_post_once", lambda identifier: calls.append(identifier) or True)
    result = transport.rotate_once(CURRENT)
    assert calls == ["match", 23]
    assert result.http_accepted and result.relations_preserved
    assert result.change_marker_advanced is advanced


def test_protected_account_mismatch_blocks_rotation_without_disclosing_material(monkeypatch):
    calls = []
    detail = {
        "results": [{
            "id": 23, "folder": 17, "name": BINDING.secret_name,
            "template": "Unix Account (SSH Password)", "target": BINDING.target_name,
            "field": [
                {"name": "Host", "value": BINDING.target_address},
                {"name": "Username", "value": "different-user"},
                {"name": "Password", "value": "synthetic-protected-value"},
            ],
        }],
    }
    monkeypatch.setattr(module, "_ssl_context", lambda _: object())
    transport = FortiPamPasswordRotationHttpTransport(
        _config(), BINDING,
        connection_factory=lambda *_a, **_k: _Connection(_Response(200, detail), calls),
    )
    with pytest.raises(PasswordRotationHttpTransportError) as error:
        transport._require_protected_account_match(CURRENT)
    assert "synthetic-protected-value" not in str(error.value)
    assert len(calls) == 1 and calls[0]["method"] == "GET"
    assert calls[0]["path"].startswith("/api/v2/cmdb/secret/database/23?")


def test_rotation_post_sends_only_secret_id_and_does_not_read_response(monkeypatch):
    calls = []
    monkeypatch.setattr(module, "_ssl_context", lambda _: object())
    transport = FortiPamPasswordRotationHttpTransport(
        _config(), BINDING,
        connection_factory=lambda *_a, **_k: _Connection(_Response(200, {"ignored": "protected"}), calls),
    )
    assert transport._post_once(23)
    assert len(calls) == 1 and calls[0]["method"] == "POST"
    assert calls[0]["path"] == "/api/v2/internal/password-change"
    assert calls[0]["body"] == b'{"secret-id":23}'
