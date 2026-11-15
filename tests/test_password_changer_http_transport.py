from __future__ import annotations

from copy import deepcopy

import pytest

from fortipam_mcp.password_changer_http_transport import (
    COLLECTION_PATH,
    FortiPamUnixPasswordChangerHttpTransport,
    PasswordChangerHttpTransportError,
    _clone_body,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


NAME = "mcp-v4-bp013-unix-changer-test01"


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


def _transport() -> FortiPamUnixPasswordChangerHttpTransport:
    config = SecretMetadataHttpTransportConfig(
        "https://fpa.example.test", "synthetic-token", 10, None,
    )
    return FortiPamUnixPasswordChangerHttpTransport(config, NAME)


def test_fixed_clone_rechecks_source_and_returns_categorical_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = _transport()
    source = _source()
    created = _clone_body(source, NAME)
    post_calls = 0

    def request(method: str, path: str, body: object, *, query: str) -> tuple[int, object]:
        nonlocal post_calls
        assert query == "vdom=root"
        if method == "POST":
            assert path == COLLECTION_PATH
            assert body == _clone_body(source, NAME)
            post_calls += 1
            return 200, {"http_status": 200}
        if path == COLLECTION_PATH:
            return 200, {"results": [source, created] if post_calls else [source]}
        assert path.endswith(NAME)
        return 200, {"results": [created]}

    monkeypatch.setattr(transport._client, "read_product_version_and_build", lambda: ("7.0.0", 29))
    monkeypatch.setattr(transport._client, "_request", request)
    expected = transport.inspect()
    result = transport.create_and_readback(expected)

    assert result.verified is True
    assert result.reference_count_known_zero is False
    assert post_calls == 1
    assert expected.target_exists is False
    assert "synthetic step" not in repr(result)


def test_source_drift_blocks_post(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = _transport()
    source = _source()
    calls: list[str] = []

    def request(method: str, path: str, body: object, *, query: str) -> tuple[int, object]:
        calls.append(method)
        if method == "POST":
            raise AssertionError("POST must not be sent")
        return 200, {"results": [source]}

    monkeypatch.setattr(transport._client, "read_product_version_and_build", lambda: ("7.0.0", 29))
    monkeypatch.setattr(transport._client, "_request", request)
    expected = transport.inspect()
    changed = deepcopy(source)
    changed["change"][0]["command"] = "different synthetic step"
    source.clear()
    source.update(changed)

    with pytest.raises(PasswordChangerHttpTransportError):
        transport.create_and_readback(expected)
    assert "POST" not in calls


def test_unknown_procedure_field_fails_closed() -> None:
    source = _source()
    source["change"][0]["unexpected"] = "synthetic"
    with pytest.raises(PasswordChangerHttpTransportError):
        _clone_body(source, NAME)
