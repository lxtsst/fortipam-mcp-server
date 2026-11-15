from __future__ import annotations

import asyncio
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3
from typing import Any

import httpx
import pytest

import scripts.bp008_build29_lab_approver_authentication as module
from fortipam_mcp.local_oauth import LocalOAuthProvider, hash_local_password, local_oauth_settings_from_environment
from fortipam_mcp.v4_plan_runtime import (
    V4PlanningPrincipal, _human_identity_binding, planning_authorization_settings_from_environment,
)
from v4_planning import AuthenticatedRequester


def _write(path: Path, raw: bytes) -> None:
    path.write_bytes(raw)
    path.chmod(0o600)


def _fixture(tmp_path: Path) -> dict[str, Any]:
    tmp_path.chmod(0o700)
    root = tmp_path.resolve()
    namespace = root / "namespace.key"
    _write(namespace, b"12" * 32)
    environment = {
        "FORTIPAM_MCP_HTTP_PUBLIC_URL": "https://unit.example.test/fpamcp-v4",
        "FORTIPAM_MCP_HTTP_LOCAL_OAUTH_DB": str(root / "oauth.sqlite3"),
        "FORTIPAM_MCP_HTTP_LOCAL_OAUTH_USERNAME": "requester-unit",
        "FORTIPAM_MCP_HTTP_LOCAL_OAUTH_PASSWORD_HASH": hash_local_password("requester-private-unit-password"),
        "FORTIPAM_MCP_V4_PLAN_PRINCIPAL_HMAC_KEY_FILE": str(namespace),
    }
    settings = local_oauth_settings_from_environment(
        environment, prefix=module.HTTP_PREFIX, public_url=environment["FORTIPAM_MCP_HTTP_PUBLIC_URL"],
    )
    provider = LocalOAuthProvider(settings)
    identity = planning_authorization_settings_from_environment(environment, expected_resource=settings.resource)
    subject, authority, namespace_ref = _human_identity_binding(
        identity, issuer=settings.issuer, subject=settings.username, resource=settings.resource,
    )
    principal = V4PlanningPrincipal(AuthenticatedRequester(
        subject_ref=subject, principal_class="operator", identity_authority_ref=authority, subject_namespace=namespace_ref,
    ), "a" * 64)
    main, requester, login, output = (root / name for name in ("main.env", "requester.json", "login.env", "approver.json"))
    _write(main, "".join(name + "=" + value + "\n" for name, value in environment.items()).encode())
    _write(requester, json.dumps(asdict(principal)).encode())
    login_values = {
        module.LOGIN_PREFIX + "USERNAME": "approver-unit",
        module.LOGIN_PREFIX + "PASSWORD": "approver-private-unit-password",
        module.LOGIN_PREFIX + "PASSWORD_HASH": hash_local_password("approver-private-unit-password"),
    }
    _write(login, "".join(name + "=" + value + "\n" for name, value in login_values.items()).encode())
    return {"main": main, "requester": requester, "login": login, "output": output, "provider": provider,
            "settings": settings, "principal": principal, "login_values": login_values}


def _run(fixture: dict[str, Any]) -> dict[str, object]:
    return asyncio.run(module.authenticate_bp008_build29_lab_approver(
        fixture["main"], fixture["requester"], fixture["login"], fixture["output"],
    ))


def _login_update(fixture: dict[str, Any], name: str, value: str) -> None:
    fixture["login_values"][module.LOGIN_PREFIX + name] = value
    _write(fixture["login"], "".join(key + "=" + item + "\n" for key, item in fixture["login_values"].items()).encode())


def test_real_sdk_authentication_separates_identity_revokes_and_preserves_requester(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path)
    buffers: list[bytearray] = []
    original = module._read_private_buffer
    def selected(path: Path, limit: int) -> bytearray:
        result = original(path, limit)
        buffers.append(result)
        return result
    monkeypatch.setattr(module, "_read_private_buffer", selected)
    proof = _run(fixture)
    assert proof == {"sdk_authenticated": True, "comparable_namespace": True, "separate_subject": True, "token_revoked": True}
    metadata = json.loads(fixture["output"].read_bytes())
    requester = fixture["principal"].requester
    assert set(metadata) == {"identity_authority_ref", "subject_namespace", "subject_ref"}
    assert metadata["identity_authority_ref"] == requester.identity_authority_ref
    assert metadata["subject_namespace"] == requester.subject_namespace
    assert metadata["subject_ref"] != requester.subject_ref
    assert fixture["output"].stat().st_mode & 0o777 == 0o600
    assert buffers and all(not any(raw) for raw in buffers)
    assert asyncio.run(fixture["provider"].authenticate_operator("requester-unit", "requester-private-unit-password"))
    with sqlite3.connect(fixture["settings"].database_path) as connection:
        assert connection.execute("SELECT username FROM local_users ORDER BY username").fetchall() == [("approver-unit",), ("requester-unit",)]
        assert connection.execute("SELECT COUNT(*) FROM oauth_tokens WHERE revoked_at IS NULL").fetchone()[0] == 0
        scope_rows = connection.execute("SELECT scopes_json FROM oauth_tokens").fetchall()
    assert scope_rows and all(json.loads(row[0]) == ["fortipam:approve"] for row in scope_rows)
    public = json.dumps(proof)
    private = fixture["output"].read_text()
    for sentinel in ("approver-private-unit-password", "requester-private-unit-password", "approver-unit", metadata["subject_ref"]):
        assert sentinel not in public
    assert "password" not in private and "token" not in private


def test_wrong_password_does_not_create_metadata_or_token(tmp_path: Path) -> None:
    fixture = _fixture(tmp_path)
    _login_update(fixture, "PASSWORD", "wrong-private-unit-password")
    with pytest.raises(module.LabApproverAuthenticationError) as failure:
        _run(fixture)
    assert not fixture["output"].exists()
    assert "wrong-private-unit-password" not in str(failure.value) and failure.value.__cause__ is None
    with sqlite3.connect(fixture["settings"].database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM oauth_tokens").fetchone()[0] == 0


def test_same_subject_is_refused_before_provider_bootstrap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path)
    _login_update(fixture, "USERNAME", "requester-unit")
    bootstraps: list[object] = []
    monkeypatch.setattr(module.LocalOAuthProvider, "_bootstrap_operator", lambda self: bootstraps.append(self))
    with pytest.raises(module.LabApproverAuthenticationError):
        _run(fixture)
    assert not bootstraps and not fixture["output"].exists()
    assert asyncio.run(fixture["provider"].authenticate_operator("requester-unit", "requester-private-unit-password"))


def test_wrong_scope_is_refused_by_sdk_authorization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path)
    original = httpx.AsyncClient.get
    async def changed(self: httpx.AsyncClient, url: Any, **kwargs: Any) -> httpx.Response:
        if str(url).endswith("/authorize"):
            kwargs["params"]["scope"] = "fortipam:plan"
        return await original(self, url, **kwargs)
    monkeypatch.setattr(httpx.AsyncClient, "get", changed)
    with pytest.raises(module.LabApproverAuthenticationError):
        _run(fixture)
    assert not fixture["output"].exists()
    with sqlite3.connect(fixture["settings"].database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM oauth_tokens").fetchone()[0] == 0


def test_failed_sdk_revocation_cleans_up_but_never_reports_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fixture = _fixture(tmp_path)
    original = httpx.AsyncClient.post
    async def failed(self: httpx.AsyncClient, url: Any, **kwargs: Any) -> httpx.Response:
        if str(url).endswith("/revoke"):
            return httpx.Response(500)
        return await original(self, url, **kwargs)
    monkeypatch.setattr(httpx.AsyncClient, "post", failed)
    with pytest.raises(module.LabApproverAuthenticationError):
        _run(fixture)
    assert not fixture["output"].exists()
    with sqlite3.connect(fixture["settings"].database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM oauth_tokens WHERE revoked_at IS NULL").fetchone()[0] == 0


@pytest.mark.parametrize("change", ["existing_output", "login_permissions", "login_symlink", "login_unknown", "namespace_drift"])
def test_fixed_private_inputs_and_exclusive_output_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str,
) -> None:
    fixture = _fixture(tmp_path)
    if change == "existing_output":
        _write(fixture["output"], b"existing-private-unit-output")
    elif change == "login_permissions":
        fixture["login"].chmod(0o644)
    elif change == "login_symlink":
        replacement = tmp_path / "replacement.env"
        fixture["login"].rename(replacement)
        fixture["login"].symlink_to(replacement)
    elif change == "login_unknown":
        _login_update(fixture, "OTHER", "unknown-private-unit-value")
    else:
        value = json.loads(fixture["requester"].read_bytes())
        value["requester"]["subject_namespace"] = "b" * 64
        _write(fixture["requester"], json.dumps(value).encode())
    bootstraps: list[object] = []
    monkeypatch.setattr(module.LocalOAuthProvider, "_bootstrap_operator", lambda self: bootstraps.append(self))
    with pytest.raises(module.LabApproverAuthenticationError):
        _run(fixture)
    assert not bootstraps
    if change == "existing_output":
        assert fixture["output"].read_bytes() == b"existing-private-unit-output"
    else:
        assert not fixture["output"].exists()
