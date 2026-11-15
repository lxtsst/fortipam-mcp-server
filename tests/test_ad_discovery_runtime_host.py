"""Protected startup binds exact factories without credential or network access."""

from dataclasses import replace
import os
from types import SimpleNamespace

import pytest

import fortipam_mcp.ad_discovery_runtime_host as runtime
import fortipam_mcp.http_server as http
import fortipam_mcp.owner_collector_runtime as owner_login
from fortipam_mcp.ad_discovery_mcp_action import V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV
from fortipam_mcp.v4_runtime_host import V4RuntimeHostError
from test_ad_discovery_runtime_config import files
from test_ad_discovery_v4_host import _host_settings


@pytest.fixture
def startup(files, tmp_path, monkeypatch):
    path, _, _, domain = files
    settings, provider, confirmation = _host_settings(tmp_path)
    prefix = runtime.AD_DISCOVERY_RUNTIME_PREFIX
    env = {
        prefix + "BINDING_FILE": str(path),
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_BASE_URL": "https://pam.example.test",
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_API_TOKEN": "synthetic-source-bearer",
        owner_login.PREFIX + "SESSION_ENABLED": "true",
        owner_login.PREFIX + "LOGIN_ENV_FILE": str(tmp_path / "not-opened.env"),
        owner_login.PREFIX + "USERNAME_VARIABLE": "SYNTHETIC_OWNER_USERNAME",
        owner_login.PREFIX + "PASSWORD_VARIABLE": "SYNTHETIC_OWNER_PASSWORD",
    }
    directory = settings.planning_database_path.parent
    for suffix, name, marker in (
        ("AUTHORITY_KEY_FILE", "ad-authority.hmac", b"a"),
        ("EXECUTION_STATE_HMAC_KEY_FILE", "ad-execution.hmac", b"e"),
    ):
        key = directory / name
        key.write_bytes(marker * 32)
        key.chmod(0o600)
        env[prefix + suffix] = str(key)
    env[prefix + "EXECUTION_STATE_DB"] = str(directory / "ad-execution.sqlite3")
    env[prefix + "AUTHORIZED_ENVIRONMENT_REF"] = domain["environment_ref"]
    env[prefix + "AUTHORIZED_SCOPE_REF"] = domain["scope_ref"]

    def forbidden(*args, **kwargs):
        pytest.fail("Startup must not resolve Owner credentials or contact a device")

    monkeypatch.setattr(owner_login, "_read_owner_only_secret_env_file", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    return settings, provider, confirmation, env


def _deny(settings, env):
    with pytest.raises(V4RuntimeHostError) as caught:
        runtime.build_ad_discovery_runtime_host(settings, env)
    assert str(caught.value) == runtime._UNAVAILABLE
    assert caught.value.__suppress_context__
    assert all(value not in str(caught.value) for key, value in env.items()
               if value and key.endswith(("FILE", "DB", "TOKEN")))


def test_default_startup_is_fixed_planning_only_without_execution_store(startup):
    settings, provider, confirmation, env = startup
    factory, execution = runtime.build_ad_discovery_runtime_host(settings, env)
    components = factory(provider, confirmation)
    assert execution is None
    assert components.ad_discovery_projection_source is not None
    assert components.ad_discovery_projection_source._owner._allow_secret_create is False
    assert not os.path.exists(env[runtime.AD_DISCOVERY_RUNTIME_PREFIX + "EXECUTION_STATE_DB"])


@pytest.mark.parametrize("gate,standing,expected", [
    (None, None, False), ("false", "true", False),
    ("true", "false", False), ("true", "true", True),
])
def test_feature_standing_authority_and_execution_gates_are_independent(startup, gate, standing, expected):
    settings, provider, confirmation, env = startup
    env[V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV] = "true"
    for suffix, value in (("EXECUTION_ENABLED", gate), ("STANDING_LAB_AUTHORIZATION", standing)):
        if value is not None:
            env[runtime.AD_DISCOVERY_RUNTIME_PREFIX + suffix] = value
    factory, execution = runtime.build_ad_discovery_runtime_host(settings, env)
    assert execution is not None
    action = execution(factory(provider, confirmation))
    assert action.execution_preflight_available() is expected
    assert action._coordinator._resolver._factory._store.claim_count == 0
    assert action._coordinator._resolver._factory._writer._config.bearer_token == "synthetic-source-bearer"


@pytest.mark.parametrize("suffix,value", [
    ("EXECUTION_ENABLED", "TRUE"), ("STANDING_LAB_AUTHORIZATION", "1"),
    ("BINDING_FILE", "relative.json"), ("AUTHORIZED_SCOPE_REF", "wrong-scope-ref01"),
    ("AUTHORIZED_ENVIRONMENT_REF", "wrong-environment-ref01"),
    ("AUTHORITY_KEY_FILE", ""), ("EXECUTION_STATE_DB", "relative.sqlite3"),
])
def test_invalid_protected_configuration_fails_closed(startup, suffix, value):
    settings, _, _, env = startup
    env[V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV] = "true"
    env[runtime.AD_DISCOVERY_RUNTIME_PREFIX + suffix] = value
    _deny(settings, env)


def test_execution_gate_cannot_enable_a_disabled_tool_feature(startup):
    settings, _, _, env = startup
    env[runtime.AD_DISCOVERY_RUNTIME_PREFIX + "EXECUTION_ENABLED"] = "true"
    _deny(settings, env)


@pytest.mark.parametrize("mode", ["owner", "host"])
def test_fixed_owner_references_and_mode_are_required(startup, mode):
    settings, _, _, env = startup
    if mode == "owner":
        env.pop(owner_login.PREFIX + "SESSION_ENABLED")
    else:
        settings = replace(settings, host_mode="synthetic")
    _deny(settings, env)


@pytest.mark.parametrize("mode", ["same_path", "same_key", "planning_key", "symlink", "fifo"])
def test_authority_and_execution_state_are_protected_and_independent(startup, mode):
    from pathlib import Path
    settings, _, _, env = startup
    prefix = runtime.AD_DISCOVERY_RUNTIME_PREFIX
    env[V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV] = "true"
    authority = Path(env[prefix + "AUTHORITY_KEY_FILE"])
    if mode == "same_path":
        env[prefix + "EXECUTION_STATE_DB"] = str(settings.planning_database_path)
    elif mode == "same_key":
        authority.write_bytes(b"e" * 32)
    elif mode == "planning_key":
        authority.write_bytes(b"p" * 32)
    elif mode == "symlink":
        alias = authority.with_name("alias.hmac")
        alias.symlink_to(authority)
        env[prefix + "AUTHORITY_KEY_FILE"] = str(alias)
    else:
        authority.unlink()
        os.mkfifo(authority, 0o600)
    _deny(settings, env)


@pytest.mark.parametrize("mode", ["same_path", "same_key"])
def test_confirmation_cannot_share_ad_execution_authority(startup, mode):
    settings, provider, confirmation, env = startup
    prefix = runtime.AD_DISCOVERY_RUNTIME_PREFIX
    env[V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV] = "true"
    if mode == "same_path":
        from pathlib import Path
        confirmation = replace(confirmation, database_path=Path(env[prefix + "EXECUTION_STATE_DB"]))
    else:
        confirmation.receipt_hmac_key_path.write_bytes(b"a" * 32)
    factory, _ = runtime.build_ad_discovery_runtime_host(settings, env)
    with pytest.raises(V4RuntimeHostError, match="protected startup"):
        factory(provider, confirmation)


def test_execution_factory_rejects_unbound_host(startup):
    settings, provider, confirmation, env = startup
    env[V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV] = "true"
    factory, execution = runtime.build_ad_discovery_runtime_host(settings, env)
    assert execution is not None
    with pytest.raises(V4RuntimeHostError):
        execution(replace(factory(provider, confirmation), ad_discovery_projection_source=None))


@pytest.mark.parametrize("feature", [False, True])
def test_main_selects_and_forwards_ad_factories_before_synthetic_fallback(tmp_path, monkeypatch, feature):
    from test_http_server import _v4_bound_environment
    env, _ = _v4_bound_environment(tmp_path)
    if feature:
        env[V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV] = "true"
    settings = replace(http.HttpServerSettings.from_environment(
        {key: value for key, value in env.items() if key != V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV}),
        v4_ad_discovery_execution_enabled=feature)
    host = SimpleNamespace(host_mode="source-backed-ad-discovery")
    monkeypatch.setattr(http.os, "environ", env)
    monkeypatch.setattr(http, "load_http_runtime_environment", lambda: False)
    monkeypatch.setattr(http.HttpServerSettings, "from_environment",
                        classmethod(lambda cls: settings))
    monkeypatch.setattr(http, "synthetic_host_settings_from_environment", lambda env: host)
    plan_factory = object()
    execution_factory = object() if feature else None

    class Selected(Exception):
        pass

    def selected(settings, env):
        assert settings is host
        assert env.get(V4_AD_DISCOVERY_EXECUTION_FEATURE_ENV, "false") == ("true" if feature else "false")
        return plan_factory, execution_factory

    def captured(actual_settings, **kwargs):
        assert actual_settings is settings
        assert kwargs["v4_plan_host_factory"] is plan_factory
        assert kwargs["v4_ad_discovery_execution_factory"] is execution_factory
        raise Selected

    monkeypatch.setattr(runtime, "build_ad_discovery_runtime_host", selected)
    monkeypatch.setattr(http, "create_http_app", captured)
    with pytest.raises(Selected):
        http.main()
