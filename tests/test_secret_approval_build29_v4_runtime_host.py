"""Independent build-29 planning host registration and readiness boundaries."""

from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

import fortipam_mcp.v4_runtime_host as module
from fortipam_mcp.local_oauth import LocalOAuthProvider, LocalOAuthSettings, hash_local_password
from fortipam_mcp.secret_approval_build29_projection_source import (
    FortiPamSecretApprovalBuild29ProjectionSource, PROJECTION_CONTRACT, SOURCE_REF,
    SecretApprovalBuild29ProjectionSourceError,
)
from fortipam_mcp.v4_confirmation_http import V4ConfirmationSettings
from fortipam_mcp.v4_runtime_host import (
    V4PersistentReferenceAuthoritySettings, V4PersistentSchemeDraftAuthoritySettings,
    V4RuntimeHostError, V4SyntheticHostSettings,
    secret_approval_build29_v4_plan_host_factory, synthetic_host_settings_from_environment,
)
from test_secret_approval_build29_projection_source import _draft, _REQUESTER, _source
from test_v4_runtime_host import _owner_file
from v4_planning import ObjectClass, SchemeId


_MODE = "source-backed-approval-and-observe-build29"


def _settings(path: Path) -> V4SyntheticHostSettings:
    return V4SyntheticHostSettings(
        path / "planning.sqlite3", path / "planning.hmac",
        reference_authority=V4PersistentReferenceAuthoritySettings(path / "reference.sqlite3", path / "reference.hmac"),
        scheme_draft_authority=V4PersistentSchemeDraftAuthoritySettings(path / "draft.sqlite3", path / "draft.hmac"),
        host_mode=_MODE, approval_and_observe_binding_path=path / "approval-binding.json",
    )


def _dependencies() -> tuple[dict[str, Any], Any, Any]:
    source, profile, secret = _source()
    return {"secret_transport": secret, "approval_profile_transport": profile,
            "binding_resolver": source._resolver}, profile, secret


def _environment(path: Path) -> dict[str, str]:
    return {
        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": _MODE,
        "FORTIPAM_MCP_V4_PLAN_STORE_DB": str(path / "planning.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_STORE_HMAC_KEY_FILE": str(path / "planning.hmac"),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_DB": str(path / "reference.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_HMAC_KEY_FILE": str(path / "reference.hmac"),
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_DB": str(path / "draft.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE": str(path / "draft.hmac"),
        "FORTIPAM_MCP_V4_PLAN_APPROVAL_AND_OBSERVE_BINDING_FILE": str(path / "approval-binding.json"),
    }


def test_explicit_build29_mode_uses_same_bounded_paths_without_old_request_observation(tmp_path: Path) -> None:
    environment = _environment(tmp_path)
    assert synthetic_host_settings_from_environment(environment) == _settings(tmp_path)
    environment["FORTIPAM_MCP_V4_PLAN_SECRET_REQUEST_OBSERVATION_BINDING_FILE"] = str(tmp_path / "observation.json")
    with pytest.raises(V4RuntimeHostError, match="request observation"):
        synthetic_host_settings_from_environment(environment)
    old_environment = {**environment, "FORTIPAM_MCP_V4_PLAN_HOST_MODE": "source-backed-approval-and-observe"}
    old = synthetic_host_settings_from_environment(old_environment)
    assert old is not None and old.host_mode == "source-backed-approval-and-observe"
    assert old.secret_request_observation_binding_path == tmp_path / "observation.json"


@pytest.mark.parametrize("missing", ["reference", "draft", "binding"])
def test_new_mode_requires_both_authorities_and_one_private_binding(tmp_path: Path, missing: str) -> None:
    environment = _environment(tmp_path)
    if missing == "binding":
        del environment["FORTIPAM_MCP_V4_PLAN_APPROVAL_AND_OBSERVE_BINDING_FILE"]
    else:
        prefix = "REFERENCE_AUTHORITY" if missing == "reference" else "SCHEME_DRAFT_AUTHORITY"
        for name in tuple(environment):
            if prefix in name:
                del environment[name]
    with pytest.raises(V4RuntimeHostError):
        synthetic_host_settings_from_environment(environment)


@pytest.mark.parametrize("missing", ["reference", "draft", "mode", "profile_callback"])
def test_factory_denies_incomplete_or_cross_mode_binding_before_callbacks(tmp_path: Path, missing: str) -> None:
    settings = _settings(tmp_path)
    dependencies, profile, secret = _dependencies()
    if missing == "reference":
        settings = replace(settings, reference_authority=None)
    elif missing == "draft":
        settings = replace(settings, scheme_draft_authority=None)
    elif missing == "mode":
        settings = replace(settings, host_mode="source-backed-approval-and-observe")
    else:
        dependencies["approval_profile_transport"] = object()
    with pytest.raises(V4RuntimeHostError):
        secret_approval_build29_v4_plan_host_factory(settings, **dependencies)
    assert profile.calls == secret.calls == 0


def test_factory_installs_only_new_contract_and_narrow_registered_provider(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    settings = _settings(tmp_path)
    dependencies, profile, secret = _dependencies()

    def compose(actual: V4SyntheticHostSettings, **kwargs: Any) -> Any:
        assert actual is settings
        captured.update(kwargs)
        return "factory"

    monkeypatch.setattr(module, "synthetic_v4_plan_host_factory", compose)
    assert cast(Any, secret_approval_build29_v4_plan_host_factory(settings, **dependencies)) == "factory"
    provider = captured["projection_provider_factory"](None)
    assert type(provider) is FortiPamSecretApprovalBuild29ProjectionSource
    assert provider.contract_registered is True
    assert profile.calls == secret.calls == 0
    assert not hasattr(provider, "inspect_transition") and not hasattr(provider, "bind_request_observation")
    resolver = captured["projection_contract_resolver"]
    for kind in (ObjectClass.APPROVAL_PROFILE_BINDING, ObjectClass.SECRET_APPROVAL_BINDING):
        contract = resolver(SchemeId.APPROVAL_AND_OBSERVE, kind)
        assert contract.contract_id == PROJECTION_CONTRACT and contract.source_ref == SOURCE_REF
        assert contract.version == "1.0.0"
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        resolver(SchemeId.ACCESS_DOMAIN, ObjectClass.SECRET_APPROVAL_BINDING)
    with pytest.raises(SecretApprovalBuild29ProjectionSourceError):
        resolver(SchemeId.APPROVAL_AND_OBSERVE, ObjectClass.SECRET_METADATA)
    projections = provider.project(_draft(), _REQUESTER, now_epoch=1)
    assert all(projection.contract.contract_id == PROJECTION_CONTRACT for projection in projections)
    assert profile.calls == secret.calls == 1


def test_direct_synthetic_factory_cannot_supply_unbound_new_mode(tmp_path: Path) -> None:
    with pytest.raises(V4RuntimeHostError, match="fixed projection binding"):
        module.synthetic_v4_plan_host_factory(_settings(tmp_path))
    settings = replace(_settings(tmp_path), secret_request_observation_binding_path=tmp_path / "request.json")
    assert module._valid_host_state_paths(settings) is False


def test_build29_components_and_readiness_are_read_only_without_actual_reads(tmp_path: Path) -> None:
    state = tmp_path / "state"
    oauth = tmp_path / "oauth"
    state.mkdir(mode=0o700)
    oauth.mkdir(mode=0o700)
    settings = _settings(state)
    for name, key in (("planning", b"p" * 32), ("reference", b"f" * 32), ("draft", b"d" * 32)):
        _owner_file(state / (name + ".hmac"), key)
    provider = LocalOAuthProvider(LocalOAuthSettings(
        issuer="https://mcp.example.com/fpamcp-v4/oauth", resource="https://mcp.example.com/fpamcp-v4",
        database_path=oauth / "oauth.sqlite3", username="operator",
        password_hash=hash_local_password("synthetic-local-unit-password", salt=b"0123456789abcdef"),
    ))
    confirmation = V4ConfirmationSettings(
        state / "confirmation.sqlite3", _owner_file(state / "confirmation.hmac", b"c" * 32),
        _owner_file(state / "receipt.hmac", b"r" * 32),
    )
    dependencies, profile, secret = _dependencies()
    factory = secret_approval_build29_v4_plan_host_factory(settings, **dependencies, clock=lambda: 1_950_000_000)
    components = factory(provider, confirmation)
    assert type(components.approval_and_observe_projection_source) is FortiPamSecretApprovalBuild29ProjectionSource
    status = components.plan_services.status()
    assert status["projection_mode"] == "source_backed"
    assert status["projection_contract_registered"] is True
    assert "live_projection_unbound" not in cast(list[str], status["blocker_codes"])
    assert status["dispatchable"] is status["product_write_enabled"] is False
    assert status["executor_mcp_exposed"] is False
    assert profile.calls == secret.calls == 0

    class RunnerFactory:
        def bind(self, *args: object, **kwargs: object) -> object:
            raise AssertionError("Readiness does not bind an execution runner.")

    coordinator = components.bind_approval_and_observe_action_coordinator(cast(Any, RunnerFactory()))
    assert cast(Any, coordinator._resolver)._projection_source is components.approval_and_observe_projection_source
    assert profile.calls == secret.calls == 0
