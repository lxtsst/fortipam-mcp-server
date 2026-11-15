from __future__ import annotations

from pathlib import Path
import sys
from types import SimpleNamespace
from typing import Any

import pytest

import fortipam_mcp.http_server as module
from fortipam_mcp.approval_and_observe_execution_mcp_action import (
    V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV,
)
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
from tests.test_http_server import _v4_bound_environment


@pytest.mark.parametrize("enabled", [False, True])
def test_main_assembles_explicit_build29_host_and_optional_execution_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enabled: bool,
) -> None:
    environment, _ = _v4_bound_environment(tmp_path)
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    environment["FORTIPAM_MCP_V4_PLAN_HOST_MODE"] = "source-backed-approval-and-observe-build29"
    environment[V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV] = "true" if enabled else "false"
    settings = module.HttpServerSettings.from_environment(environment)
    path = tmp_path / "binding.json"
    host_settings = SimpleNamespace(host_mode="source-backed-approval-and-observe-build29",
                                    approval_and_observe_binding_path=path)
    context = SimpleNamespace(secret_transport=object(), approval_profile_transport=object(),
                              binding_resolver=object(), execution_factory=object())
    captured: dict[str, Any] = {}
    authenticator, authority = object(), object()

    def planning_authorities() -> tuple[object, object]:
        assert enabled
        captured["authorities"] = True
        return authenticator, authority

    context.planning_authorities = planning_authorities
    monkeypatch.setattr(module.os, "environ", environment)
    monkeypatch.setattr(module, "load_http_runtime_environment", lambda: False)
    monkeypatch.setattr(module.HttpServerSettings, "from_environment", classmethod(lambda cls: settings))
    monkeypatch.setattr(module, "synthetic_host_settings_from_environment", lambda env: host_settings)

    def build(env: object, *, binding_path: Path, execution_enabled: bool) -> object:
        assert env is environment and binding_path == path and execution_enabled is enabled
        captured["built"] = True
        return context

    monkeypatch.setitem(sys.modules, "fortipam_mcp.secret_approval_build29_main_factory",
                        SimpleNamespace(build_secret_approval_build29_main_context=build))

    def factory(actual_settings: object, **kwargs: object) -> object:
        assert actual_settings is host_settings
        assert kwargs == {"secret_transport": context.secret_transport,
                          "approval_profile_transport": context.approval_profile_transport,
                          "binding_resolver": context.binding_resolver,
                          "approval_receipt_authenticator": authenticator if enabled else None,
                          "approver_authorization_authority": authority if enabled else None}
        return "fixed-build29-host-factory"

    monkeypatch.setattr(module, "secret_approval_build29_v4_plan_host_factory", factory)
    monkeypatch.setattr(module, "approval_and_observe_v4_plan_host_factory",
                        lambda *args, **kwargs: pytest.fail("Legacy source cannot serve build29"))

    def create(actual: object, **kwargs: object) -> object:
        assert actual is settings
        captured["host"] = kwargs["v4_plan_host_factory"]
        captured["execution"] = kwargs["v4_approval_and_observe_execution_factory"]
        assert kwargs["v4_secret_request_observation"] is None
        return "unit-app"

    monkeypatch.setattr(module, "create_http_app", create)

    class Server:
        def __init__(self, config: object) -> None:
            pass

        async def serve(self) -> None:
            captured["served"] = True

    monkeypatch.setitem(sys.modules, "uvicorn", SimpleNamespace(Config=lambda *args, **kwargs: object(), Server=Server))
    module.main()
    expected = {"built": True, "host": "fixed-build29-host-factory",
                "execution": context.execution_factory if enabled else None, "served": True}
    if enabled:
        expected["authorities"] = True
    assert captured == expected


def test_build29_approval_execution_does_not_enable_legacy_request_create(tmp_path: Path) -> None:
    environment, _ = _v4_bound_environment(tmp_path)
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    environment["FORTIPAM_MCP_V4_PLAN_HOST_MODE"] = "source-backed-approval-and-observe-build29"
    environment[V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV] = "true"
    settings = module.HttpServerSettings.from_environment(environment)
    assert settings.v4_approval_and_observe_execution_enabled
    from fortipam_mcp.secret_request_create_mcp_action import V4_SECRET_REQUEST_CREATE_FEATURE_ENV
    environment[V4_SECRET_REQUEST_CREATE_FEATURE_ENV] = "true"
    with pytest.raises(module.HttpConfigurationError, match="Secret Request Create"):
        module.HttpServerSettings.from_environment(environment)


def test_main_real_context_requires_authorities_in_actual_host_composition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise real context/host/app wiring; only private device and UDS are fake."""
    from tests.test_secret_approval_build29_main_factory import _fixture, _private_dependencies, _write
    from fortipam_mcp.approver_authority_sidecar import UnixApproverAuthorizationClient
    from fortipam_mcp.secret_approval_build29_main_factory import PREFIX

    fixture = _fixture(tmp_path)
    device_calls = _private_dependencies(fixture, monkeypatch)
    environment, host = _v4_bound_environment(tmp_path)
    state = host.planning_database_path.parent
    for name in ("reference", "draft"):
        _write(state / (name + ".key"), name.encode() * 16)
    environment.update(fixture["environment"])
    environment.update({
        RUNTIME_PROFILE_ENV: "v4-controlled",
        V4_APPROVAL_AND_OBSERVE_EXECUTION_FEATURE_ENV: "true",
        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": "source-backed-approval-and-observe-build29",
        "FORTIPAM_MCP_V4_PLAN_STORE_DB": str(host.planning_database_path),
        "FORTIPAM_MCP_V4_PLAN_STORE_HMAC_KEY_FILE": str(host.planning_hmac_key_path),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_DB": str(state / "reference.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_HMAC_KEY_FILE": str(state / "reference.key"),
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_DB": str(state / "draft.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE": str(state / "draft.key"),
        "FORTIPAM_MCP_V4_PLAN_APPROVAL_AND_OBSERVE_BINDING_FILE": str(fixture["binding"]),
        PREFIX + "RUNTIME_FILE": str(fixture["runtime"]),
    })
    _write(host.planning_hmac_key_path, b"p" * 32)
    # Remote delegation/checkpoint availability is deliberately not asserted
    # by this offline regression; it is proved separately by live acceptance.
    ready_calls: list[object] = []
    monkeypatch.setattr(UnixApproverAuthorizationClient, "verify_ready", lambda self: ready_calls.append(self))
    monkeypatch.setattr(module.os, "environ", environment)
    monkeypatch.setattr(module, "load_http_runtime_environment", lambda: False)
    served: list[object] = []

    class Server:
        def __init__(self, config: object) -> None:
            served.append(config)

        async def serve(self) -> None:
            pass

    monkeypatch.setitem(sys.modules, "uvicorn", SimpleNamespace(Config=lambda app, **kwargs: app, Server=Server))
    module.main()
    assert len(served) == len(ready_calls) == 1
    assert device_calls["sources"] == device_calls["producer"] == 1
    assert device_calls["produce"] == 0
