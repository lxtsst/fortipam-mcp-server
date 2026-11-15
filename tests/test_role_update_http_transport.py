from __future__ import annotations

from dataclasses import dataclass
import json

import pytest

from fortipam_mcp.role_update_http_transport import (
    FortiPamRoleUpdateHttpTransport,
    RoleUpdateHttpTransportConfig,
    RoleUpdateHttpTransportError,
    load_role_update_http_transport_config,
)


@dataclass
class _Response:
    status_code: int = 200
    content: bytes = b'{"http_status":200,"status":"success"}'
    headers: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {"content-type": "application/json"}


class _Client:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.calls: list[dict[str, object]] = []

    def __enter__(self) -> _Client:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def request(self, *args: object, **kwargs: object) -> _Response:
        self.calls.append({"method": args[0], "url": args[1], **kwargs})
        return self.response


def _config() -> RoleUpdateHttpTransportConfig:
    return RoleUpdateHttpTransportConfig(
        base_url="https://fpa.example",
        bearer_token="token",
        timeout_seconds=15,
        ca_file=None,
    )


def test_enable_uses_only_the_fixed_minimal_put_body() -> None:
    client = _Client(_Response())
    transport = FortiPamRoleUpdateHttpTransport(
        _config(), client_factory=lambda **kwargs: client
    )

    transport.enable_diagnostics("mcp-v4-role-01")

    assert client.calls == [
        {
            "method": "PUT",
            "url": "https://fpa.example/api/v2/cmdb/system/accprofile/mcp-v4-role-01",
            "headers": {"Accept": "application/json", "Authorization": "Bearer token"},
            "json": {"system-diagnostics": "enable"},
        }
    ]


def test_enable_rejects_failed_response_or_non_laboratory_role() -> None:
    transport = FortiPamRoleUpdateHttpTransport(
        _config(), client_factory=lambda **kwargs: _Client(_Response(status_code=500))
    )

    with pytest.raises(RoleUpdateHttpTransportError):
        transport.enable_diagnostics("mcp-v4-role-01")
    with pytest.raises(RoleUpdateHttpTransportError):
        transport.enable_diagnostics("Default Administrator")


def test_loader_requires_explicit_dedicated_api_opt_in() -> None:
    environment = {
        "FPA_HOME_LAB_FPA1_V4_ROLE_UPDATE_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_ROLE_UPDATE_API_BASE_URL": "fpa.example",
        "FPA_HOME_LAB_FPA1_V4_ROLE_UPDATE_API_TOKEN": "token",
    }

    loaded = load_role_update_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example"


@pytest.mark.parametrize(
    "body",
    [
        b'{"http_status":200,"status":"error"}',
        b'{"http_status":200}',
        b'{}',
        b'{"status":"success"}',
        b'{"http_status":200.0,"status":"success"}',
        b'{"http_status":200,"status":"success","error":-1}',
        b'{"http_status":200,"status":"success","error":null}',
    ],
)
def test_http_200_requires_explicit_product_success(body: bytes) -> None:
    client = _Client(_Response(content=body))
    transport = FortiPamRoleUpdateHttpTransport(
        _config(), client_factory=lambda **kwargs: client
    )

    with pytest.raises(RoleUpdateHttpTransportError):
        transport.enable_diagnostics("mcp-v4-role-01")

    assert len(client.calls) == 1


def _read_response(name: str, rows: list[dict[str, object]]) -> _Response:
    return _Response(content=json.dumps({
        "http_status": 200, "status": "success", "http_method": "GET",
        "path": "system", "name": name, "version": "v7.0.0", "build": 29,
        "results": rows, "size": len(rows), "matched_count": len(rows),
    }).encode())


def _eligible_role(diagnostics: object = "disable") -> dict[str, object]:
    return {
        "name": "mcp-v4-role-01", "secfabgrp": "read", "ftviewgrp": "read",
        "authgrp": "read", "secretgrp": "custom", "cli": "enable",
        "sysgrp": "custom", "sysgrp-permission": {"admin": "read-write"},
        "system-diagnostics": diagnostics,
        "secretgrp-permission": {
            "launcher": "read", "pwd-changer": "read", "template": "read-write",
            "secret-policy": "read", "request": "read-write",
            "folder-table": "read-write", "secret-table": "read-write",
            "create-personal-folder": "read-write",
        },
    }


class _SequenceClient(_Client):
    def __init__(self, responses: list[_Response]) -> None:
        super().__init__(_Response())
        self.responses = iter(responses)

    def request(self, *args: object, **kwargs: object) -> _Response:
        self.calls.append({"method": args[0], "url": args[1], **kwargs})
        return next(self.responses)


def test_rest_flow_requires_explicit_disabled_then_enabled_state() -> None:
    client = _SequenceClient([
        _read_response("accprofile", [_eligible_role()]),
        _read_response("admin", [{"accprofile": "other-role"}]),
        _Response(),
        _read_response("accprofile", [_eligible_role("enable")]),
        _read_response("admin", [{"accprofile": "other-role"}]),
    ])
    transport = FortiPamRoleUpdateHttpTransport(_config(), client_factory=lambda **kw: client)

    assert transport.inspect_update("mcp-v4-role-01").verified
    assert transport.enable_diagnostics_and_readback("mcp-v4-role-01").verified
    assert [call["method"] for call in client.calls] == ["GET", "GET", "PUT", "GET", "GET"]
    assert client.calls[2]["json"] == {"system-diagnostics": "enable"}
    assert all("format=" in str(call["url"]) for call in client.calls if call["method"] == "GET")


@pytest.mark.parametrize("diagnostics", [None, "unknown", {}, [], "disable"])
def test_readback_never_treats_unknown_or_disabled_as_enabled(diagnostics: object) -> None:
    client = _SequenceClient([
        _Response(), _read_response("accprofile", [_eligible_role(diagnostics)]),
        _read_response("admin", []),
    ])
    transport = FortiPamRoleUpdateHttpTransport(_config(), client_factory=lambda **kw: client)
    if diagnostics == "disable":
        assert not transport.enable_diagnostics_and_readback("mcp-v4-role-01").verified
    else:
        with pytest.raises(RoleUpdateHttpTransportError):
            transport.enable_diagnostics_and_readback("mcp-v4-role-01")
    assert sum(call["method"] == "PUT" for call in client.calls) == 1


@pytest.mark.parametrize("fault", ["identity", "build", "truncated", "assignment", "cli", "admin"])
def test_rest_inspection_refuses_wrong_target_incomplete_assignments_or_dependencies(fault: str) -> None:
    role = _eligible_role()
    if fault == "identity":
        role["name"] = "mcp-v4-role-other"
    if fault == "cli":
        role["cli"] = "disable"
    if fault == "admin":
        role["sysgrp-permission"] = {"admin": "read"}
    role_response = _read_response("accprofile", [role])
    if fault == "build":
        payload = json.loads(role_response.content)
        payload["build"] = 30
        role_response.content = json.dumps(payload).encode()
    assignments = _read_response("admin", [{"accprofile": "mcp-v4-role-01"}] if fault == "assignment" else [])
    if fault == "truncated":
        payload = json.loads(assignments.content)
        payload["size"] = 1
        assignments.content = json.dumps(payload).encode()
    client = _SequenceClient([role_response, assignments])
    transport = FortiPamRoleUpdateHttpTransport(_config(), client_factory=lambda **kw: client)
    if fault in {"identity", "build", "truncated"}:
        with pytest.raises(RoleUpdateHttpTransportError):
            transport.inspect_update("mcp-v4-role-01")
    else:
        assert not transport.inspect_update("mcp-v4-role-01").verified
    assert all(call["method"] == "GET" for call in client.calls)
