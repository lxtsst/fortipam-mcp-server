"""One-shot Unix Password Changer rollback contract checks."""

from __future__ import annotations

from copy import deepcopy

import pytest

from fortipam_mcp.password_changer_delete_http_transport import (
    FortiPamUnixPasswordChangerDeleteHttpTransport,
    PasswordChangerDeleteHttpTransportError,
)
from fortipam_mcp.password_changer_http_transport import COLLECTION_PATH, _clone_body
from fortipam_mcp.password_changer_reference_ssh_transport import (
    FortiPamPasswordChangerReferenceSshTransport,
    PasswordChangerReferenceReadback,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


NAME = "mcp-v4-bp013-unix-changer-test-delete"


def _source() -> dict[str, object]:
    return {
        "name": "SSH Password (Unix)", "type": "ssh-pwd",
        "change-auth-mode": "self", "verify-auth-mode": "self",
        "new-line-mode": "unix", "q_origin_key": "opaque",
        "change": [
            {"seq-num": index, "type": "command", "command": "synthetic step", "q_id": index}
            for index in range(1, 10)
        ],
        "verify": [], "web-change": [], "web-verify": [],
    }


def _transport(monkeypatch: pytest.MonkeyPatch, *, refs_zero: bool = True):
    references = object.__new__(FortiPamPasswordChangerReferenceSshTransport)
    monkeypatch.setattr(
        references, "inspect", lambda _name: PasswordChangerReferenceReadback(
            True, refs_zero, True, True,
        ),
    )
    transport = FortiPamUnixPasswordChangerDeleteHttpTransport(
        SecretMetadataHttpTransportConfig("https://fpa.example.test", "synthetic-token", 10, None),
        NAME,
        references,
    )
    monkeypatch.setattr(transport._client, "read_product_version_and_build", lambda: ("7.0.0", 29))
    return transport


def test_exact_zero_reference_clone_deletes_once_and_preserves_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _transport(monkeypatch)
    source = _source()
    clone = _clone_body(source, NAME)
    deleted = False
    calls: list[str] = []

    def request(method: str, path: str, body: object, *, query: str):
        nonlocal deleted
        assert query == "vdom=root"
        assert body is None
        calls.append(method)
        if method == "DELETE":
            assert path.endswith(NAME) and not deleted
            deleted = True
            return 200, {"http_status": 200}
        if path == COLLECTION_PATH:
            return 200, {"results": [source] if deleted else [source, clone]}
        assert path.endswith(NAME)
        return (404, {}) if deleted else (200, {"results": [clone]})

    monkeypatch.setattr(transport._client, "_request", request)
    expected = transport.inspect()
    assert expected.eligible
    result = transport.delete_and_readback(expected)
    assert result.verified
    assert calls.count("DELETE") == 1
    assert "synthetic step" not in repr(result)


def test_drift_or_reference_blocks_delete(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _transport(monkeypatch)
    source = _source()
    clone = _clone_body(source, NAME)
    calls: list[str] = []

    def request(method: str, path: str, body: object, *, query: str):
        calls.append(method)
        if method == "DELETE":
            raise AssertionError("DELETE must not be sent")
        return (200, {"results": [source, clone]}) if path == COLLECTION_PATH else (200, {"results": [clone]})

    monkeypatch.setattr(transport._client, "_request", request)
    expected = transport.inspect()
    changed = deepcopy(clone)
    changed["description"] = "drifted"
    clone.clear()
    clone.update(changed)
    with pytest.raises(PasswordChangerDeleteHttpTransportError):
        transport.delete_and_readback(expected)
    assert "DELETE" not in calls

    unreferenced = _transport(monkeypatch, refs_zero=False)
    monkeypatch.setattr(unreferenced._client, "_request", request)
    with pytest.raises(PasswordChangerDeleteHttpTransportError):
        unreferenced.delete_and_readback(expected)
    assert "DELETE" not in calls
