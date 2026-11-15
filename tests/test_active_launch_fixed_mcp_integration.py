"""Normal main, real OAuth/MCP and durable M4 with synthetic SSH I/O only."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import time

import pytest
from starlette.testclient import TestClient
import uvicorn

from fortipam_mcp import active_launch_ssh_transport as ssh
from fortipam_mcp import http_server
from fortipam_mcp.active_launch_live_workflow import (
    FIXED_DISCONNECT_CONTRACT,
    FixedActiveLaunchLiveWorkflow,
)
from fortipam_mcp.active_launch_mcp_action import (
    V4_ACTIVE_LAUNCH_ACTION_PREFIX as PREFIX,
    V4_ACTIVE_LAUNCH_DISCONNECT_EXECUTION_ENV,
)
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.runtime_profile import RUNTIME_PROFILE_ENV
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token

from test_http_server import _v4_environment
from test_ldap_server_mcp_action import _call, _login

_OBSERVE = "observe_v4_active_launches"
_PREVIEW = "preview_v4_active_launch_disconnect"
_CONFIRM = "confirm_v4_active_launch_disconnect"
_EXECUTE = "execute_confirmed_v4_active_launch_disconnect"
_OWNER = "synthetic-owner"
_PASSWORD = "synthetic-owner-password"
_TOKEN = "synthetic-selected-token"
_COMPANION = "synthetic-companion-token"
_SERIAL_DIGEST = hashlib.sha256(b"synthetic-serial").hexdigest()
_IDENTITY_DIGEST = hashlib.sha256(b"synthetic-selected-record").hexdigest()


def test_normal_main_fixed_candidate_oauth_m4_scope_and_terminal_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment = _v4_environment(tmp_path / "oauth")
    environment[RUNTIME_PROFILE_ENV] = "v4-controlled"
    settings = http_server.HttpServerSettings.from_environment(environment)
    # Obtain the actual server-validated identity before binding this candidate.
    with TestClient(http_server.create_http_app(settings), base_url="https://mcp.example.com") as client:
        operator = _login(client, "fortipam:read fortipam:plan fortipam:operate")
        planning = _login(client, "fortipam:read fortipam:plan")
        response = client.post("/fpamcp", headers=operator, json={
            "jsonrpc": "2.0", "id": "closed", "method": "tools/list", "params": {},
        })
        assert response.status_code == 200
        assert not {_OBSERVE, _PREVIEW, _CONFIRM, _EXECUTE}.intersection(
            tool["name"] for tool in response.json()["result"]["tools"])
    assert settings.local_oauth is not None and settings.v4_planning_authorization is not None
    access = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(
        operator["authorization"].removeprefix("Bearer ")))
    principal = planning_principal_from_access_token(access, settings.v4_planning_authorization)

    private = (tmp_path / "fixed").resolve()
    private.mkdir(mode=0o700)

    def write(name: str, content: bytes) -> Path:
        path = private / name
        path.write_bytes(content)
        path.chmod(0o600)
        return path

    execution_key = write("execution.key", b"e" * 32)
    authority_key = write("authority.key", b"a" * 32)
    login = write("owner.env", (
        f"SYNTHETIC_OWNER_USERNAME={_OWNER}\nSYNTHETIC_OWNER_PASSWORD={_PASSWORD}\n"
    ).encode())
    known_hosts = write("known_hosts", b"synthetic.example ssh-ed25519 AAAAsynthetic\n")
    now = int(time.time())
    profile = {
        "contract": FIXED_DISCONNECT_CONTRACT,
        "serial_digest": _SERIAL_DIGEST,
        "token_id": _TOKEN,
        "identity_digest": _IDENTITY_DIGEST,
        "owner_name": _OWNER,
        "allowed_requester_digest": principal.requester.digest,
        "allowed_transport_digest": principal.transport_namespace_digest,
        "issued_at": now - 1,
        "expires_at": now + 120,
        "execution_database": str(private / "execution.sqlite3"),
        "execution_key_path": str(execution_key),
        "execution_key_sha256": hashlib.sha256(b"e" * 32).hexdigest(),
        "authority_key_path": str(authority_key),
        "authority_key_sha256": hashlib.sha256(b"a" * 32).hexdigest(),
    }
    raw_profile = json.dumps(profile).encode()
    path = write("candidate.json", raw_profile)
    environment.update({
        PREFIX + "ENABLED": "true",
        PREFIX + "CANDIDATE_PROFILE_FILE": str(path),
        PREFIX + "CANDIDATE_PROFILE_SHA256": hashlib.sha256(raw_profile).hexdigest(),
        V4_ACTIVE_LAUNCH_DISCONNECT_EXECUTION_ENV: "true",
        ssh.ENV_PREFIX + "ENABLED": "true",
        ssh.ENV_PREFIX + "OWNER_LOGIN_ENABLED": "true",
        ssh.ENV_PREFIX + "LOGIN_ENV_FILE": str(login),
        ssh.ENV_PREFIX + "USERNAME_VARIABLE": "SYNTHETIC_OWNER_USERNAME",
        ssh.ENV_PREFIX + "PASSWORD_VARIABLE": "SYNTHETIC_OWNER_PASSWORD",
        ssh.ENV_PREFIX + "SSH_HOST": "synthetic.example",
        ssh.ENV_PREFIX + "SSH_USERNAME": _OWNER,
        ssh.ENV_PREFIX + "SSH_KNOWN_HOSTS_FILE": str(known_hosts),
    })
    captured = {}
    tokens = [_TOKEN, _COMPANION]
    calls = []

    def check_transport(transport):
        assert transport._config.host == "synthetic.example"
        assert transport._config.username == _OWNER and transport._config.password == _PASSWORD
        assert transport._expected_serial_digest == _SERIAL_DIGEST

    def listing(transport):
        check_transport(transport)
        calls.append("list")
        return ssh.ActiveLaunchListing(True, tuple(tokens), tuple(
            (token, _IDENTITY_DIGEST if token == _TOKEN else "c" * 64)
            for token in tokens), _SERIAL_DIGEST)

    def clear(transport, token_id, *, expected_identity_digest=None, guard=None):
        check_transport(transport)
        workflow = captured["action"]._workflow
        assert workflow._store.claim_count == 1
        assert token_id == _TOKEN and expected_identity_digest == _IDENTITY_DIGEST
        assert calls.count("clear") == 0 and tokens == [_TOKEN, _COMPANION]
        assert guard is not None
        guard()
        calls.append("clear")
        tokens.remove(token_id)
        return ssh.ActiveLaunchClearReadback(True, True, True)

    monkeypatch.setattr(ssh.FortiPamActiveLaunchSshTransport, "list_active_launches", listing)
    monkeypatch.setattr(ssh.FortiPamActiveLaunchSshTransport, "clear_active_launch_and_readback", clear)
    original_create = http_server.create_http_app

    def create(current, **options):
        captured["action"] = options["v4_active_launch_action"]
        assert type(captured["action"]._workflow) is FixedActiveLaunchLiveWorkflow
        assert type(captured["action"]._workflow._store) is PersistentM4ExecutionStateStore
        assert calls == []
        return original_create(current, **options)

    def exercise(app):
        workflow = captured["action"]._workflow
        store = workflow._store
        with TestClient(app, base_url="https://mcp.example.com") as client:
            observation = _call(client, operator, _OBSERVE, {})
            assert not observation["isError"]
            body = observation["structuredContent"]
            assert body["observation"] == "verified" and body["active_launch_count"] == 1
            launch_ref = body["active_launch_refs"][0]["launch_ref"]
            preview = _call(client, operator, _PREVIEW, {"launch_ref": launch_ref})
            assert not preview["isError"]
            confirmation = _call(client, operator, _CONFIRM, {
                "preview_ref": preview["structuredContent"]["preview_ref"],
            })
            assert not confirmation["isError"]
            arguments = {"authorization_ref": confirmation["structuredContent"]["authorization_ref"]}
            before = tuple(calls)
            assert _call(client, planning, _EXECUTE, arguments)["isError"]
            assert tuple(calls) == before and store.claim_count == 0 and store.audit_events == ()
            result = _call(client, operator, _EXECUTE, arguments)
            assert not result["isError"]
            public = result["structuredContent"]
            assert public["outcome"] == "succeeded" and public["verification"] == "verified"
            assert public["idempotent_replay"] is False and public["durable_execution_consumed"] is True
            assert store.claim_count == 1 and len(store.audit_events) == 1
            assert store.audit_events[0].outcome == "succeeded"
            assert store.audit_events[0].verification == "verified"
            before = tuple(calls)
            repeated = _call(client, operator, _EXECUTE, arguments)
            assert not repeated["isError"] and repeated["structuredContent"]["idempotent_replay"] is True
            assert tuple(calls) == before and store.claim_count == 1 and len(store.audit_events) == 1
            assert calls.count("clear") == 1 and tokens == [_COMPANION]
            public_frames = json.dumps((observation, preview, confirmation, result, repeated))
            assert all(value not in public_frames for value in (_TOKEN, _COMPANION, _OWNER, _PASSWORD,
                _SERIAL_DIGEST, _IDENTITY_DIGEST, str(private)))
        captured["exercised"] = True

    async def serve(runner, sockets=None):
        # Run the actual app produced by main, without opening a TCP listener.
        await asyncio.to_thread(exercise, runner.config.app)

    monkeypatch.setattr(os, "environ", environment)
    monkeypatch.setattr(http_server, "load_http_runtime_environment", lambda: False)
    monkeypatch.setattr(http_server, "create_http_app", create)
    monkeypatch.setattr(uvicorn.Server, "serve", serve)
    try:
        http_server.main()
        assert captured["exercised"] is True
    finally:
        if "action" in captured:
            captured["action"]._workflow.close()
