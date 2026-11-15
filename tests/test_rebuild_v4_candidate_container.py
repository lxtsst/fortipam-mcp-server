"""Focused safety checks for the disposable V4 candidate rebuild helper."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import pytest


_PATH = Path(__file__).parents[1] / "scripts" / "rebuild_v4_candidate_container.py"
_SPEC = spec_from_file_location("rebuild_v4_candidate_container", _PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


@pytest.mark.parametrize(
    ("source", "candidate"),
    (
        (
            "fortipam-mcp-http-v4-bp006-ready-candidate",
            "fortipam-mcp-http-v4-bp006-exec-candidate",
        ),
        (
            "fortipam-mcp-http-v4-bp007-ready-candidate",
            "fortipam-mcp-http-v4-bp007-exec-candidate",
        ),
    ),
)
def test_accepts_only_paired_bp006_or_bp007_candidate(
    source: str,
    candidate: str,
) -> None:
    _MODULE._validate_candidate_pair(source, candidate)


def test_rejects_source_container_as_replacement_target() -> None:
    with pytest.raises(ValueError, match="limited"):
        _MODULE._validate_candidate_pair(
            "fortipam-mcp-http-v4-bp007-ready-candidate",
            "fortipam-mcp-http-v4-bp007-ready-candidate",
        )


@pytest.mark.parametrize(
    ("source", "proxy"),
    (
        (
            "fortipam-mcp-http-v4-bp006-ready-candidate",
            "fortipam-bp006-mcp-tls-proxy",
        ),
        (
            "fortipam-mcp-http-v4-bp007-ready-candidate",
            "fortipam-bp007-mcp-tls-proxy",
        ),
    ),
)
def test_accepts_only_paired_bp006_or_bp007_proxy(
    source: str,
    proxy: str,
) -> None:
    _MODULE._validate_proxy_pair(source, proxy)


def test_rejects_unpaired_candidate_proxy() -> None:
    with pytest.raises(ValueError, match="paired"):
        _MODULE._validate_proxy_pair(
            "fortipam-mcp-http-v4-bp007-ready-candidate",
            "fortipam-bp006-mcp-tls-proxy",
        )


def _candidate_environment() -> dict[str, str]:
    return {
        "FORTIPAM_MCP_HTTP_AUTH_MODE": "local_oauth",
        "FORTIPAM_MCP_HTTP_PUBLIC_URL": "https://mcp.example/fpamcp-v4-b108",
        "FORTIPAM_MCP_HTTP_ALLOWED_HOSTS": "mcp.example",
        "FORTIPAM_MCP_HTTP_LOCAL_OAUTH_ISSUER": (
            "https://mcp.example/fpamcp-v4-b108/oauth"
        ),
        "FORTIPAM_MCP_HTTP_LOCAL_OAUTH_DB": "/var/lib/fortipam-mcp/oauth.sqlite3",
        "FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_TOOLS_ENABLED": "true",
        "FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_ENABLED": "false",
        "FORTIPAM_MCP_V4_PLAN_SECRET_ONBOARDING_BINDING_FILE": "/tmp/binding.json",
    }


def _validate(environment: dict[str, str]) -> None:
    _MODULE._validate_candidate_runtime_contract(
        environment,
        user="10001:10001",
        state_mount="/srv/state:/var/lib/fortipam-mcp:rw",
        secrets_mount="/srv/secrets:/run/secrets/v4:ro",
        binding_mount="/srv/binding.json:/tmp/binding.json:ro",
    )


def test_accepts_coherent_local_oauth_candidate_contract() -> None:
    _validate(_candidate_environment())


def test_rejects_public_host_port_missing_from_allowlist() -> None:
    environment = _candidate_environment()
    environment["FORTIPAM_MCP_HTTP_PUBLIC_URL"] = (
        "https://mcp.example:18443/fpamcp-v4-b108"
    )
    with pytest.raises(ValueError, match="host contract"):
        _validate(environment)


def test_rejects_oauth_database_outside_candidate_state_mount() -> None:
    environment = _candidate_environment()
    environment["FORTIPAM_MCP_HTTP_LOCAL_OAUTH_DB"] = "/tmp/oauth.sqlite3"
    with pytest.raises(ValueError, match="state path"):
        _validate(environment)


def test_rejects_candidate_when_onboarding_binding_differs_from_mount() -> None:
    environment = _candidate_environment()
    environment["FORTIPAM_MCP_V4_PLAN_SECRET_ONBOARDING_BINDING_FILE"] = (
        "/tmp/stale-binding.json"
    )
    with pytest.raises(ValueError, match="binding contract"):
        _validate(environment)


def test_rejects_candidate_without_explicit_onboarding_gate() -> None:
    environment = _candidate_environment()
    del environment["FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_ENABLED"]
    with pytest.raises(ValueError, match="Gate contract"):
        _validate(environment)


def test_rejects_duplicate_onboarding_gate_across_environment_files(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.env"
    second = tmp_path / "second.env"
    first.write_text(
        "FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_ENABLED=false\n",
        encoding="utf-8",
    )
    second.write_text(
        "FORTIPAM_MCP_V4_ONBOARDING_EXECUTION_ENABLED=true\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="defined more than once"):
        _MODULE._load_environment_files([str(first), str(second)])


def test_uses_distinct_tmpfs_for_candidate_only_sidecars() -> None:
    assert _MODULE._candidate_tmpfs_arguments("10001:10002") == (
        "--tmpfs",
        (
            "/var/lib/fortipam-mcp/sidecars:"
            "rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10002,mode=0700"
        ),
        "--tmpfs",
        (
            "/var/lib/fortipam-mcp/private-runtime:"
            "rw,nosuid,nodev,noexec,size=16m,uid=10001,gid=10002,mode=0700"
        ),
    )


def test_uses_explicit_read_only_bind_mount() -> None:
    assert _MODULE._bind_mount_arguments(
        "/srv/binding.json:/tmp/binding.json:ro"
    ) == (
        "--mount",
        "type=bind,source=/srv/binding.json,target=/tmp/binding.json,readonly",
    )


def test_application_readiness_requires_http_auth_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    monkeypatch.setattr(_MODULE, "_container_running", lambda _name: True)

    def run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(_MODULE.subprocess, "run", run)

    assert _MODULE._application_ready(
        "candidate",
        path="/fpamcp-v4-b108",
        host="mcp.example",
        seconds=1,
    ) is True
    assert calls[0][:4] == ["docker", "exec", "candidate", "python"]
    assert calls[0][-2:] == ["/fpamcp-v4-b108", "mcp.example"]


def test_proxy_reload_validates_configuration_before_reload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> SimpleNamespace:
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(_MODULE.subprocess, "run", run)

    _MODULE._reload_proxy("fortipam-bp007-mcp-tls-proxy")

    assert calls == [
        ["docker", "exec", "fortipam-bp007-mcp-tls-proxy", "nginx", "-t"],
        [
            "docker",
            "exec",
            "fortipam-bp007-mcp-tls-proxy",
            "nginx",
            "-s",
            "reload",
        ],
    ]
