"""Client refusal before dispatch and irreversible marker/token cleanup."""
import asyncio
from contextlib import asynccontextmanager
import json
from types import SimpleNamespace

import pytest
from v4_planning import canonical_digest
from scripts import v4_jwt_manual_key_owner_mcp_oauth_acceptance as c


def payloads():
    preview = {"contract":c.CONTRACT,"phase":"create","policy_mode":"lab_auto",
        "preview_ref":"jwt-owner-preview-"+"a"*32,"expires_at":220,
        "Current State":{"owner_context_verified":True,"original_creation_qualified":False,"current_digest":"b"*64},
        "Proposed Changes":{"operation":"create_one_manual_public_key","maximum_native_mutations":1,"user_or_role_changes":False},
        "Expected State":{"digest":"c"*64,"full_owned_state_or_absence_required":True,"jwt_login_qualified":False},
        "recovery":"original_ack_and_terminal_ledger_only_no_retry_or_adoption","device_write_executed":False}
    preview["summary_digest"] = canonical_digest(preview)
    return {c.PREVIEW:preview,
        c.AUTHORIZE:{"contract":c.CONTRACT,"phase":"create","policy_mode":"lab_auto","expires_at":220,"authorization_ref":"jwt-owner-auth-"+"d"*64},
        c.EXECUTE:{"contract":c.CONTRACT,"phase":"create","outcome":"succeeded","verification":"verified","idempotent_replay":False}}


@pytest.mark.parametrize("fault", ["none", "wrong-phase", "widened-effect", "bad-digest", "bad-auth", "unknown-result", "transport", "cancelled"])
def test_client_never_replays_and_always_revokes_after_token_acquisition(tmp_path, monkeypatch, fault):
    tmp_path.chmod(0o700); login = tmp_path / "login.json"; login.write_text(json.dumps({"username":"SYNTHETIC_LOGIN","password":"SYNTHETIC_PASSWORD"})); login.chmod(0o600)
    state = tmp_path / "client.env"; state.write_text("SYNTHETIC_CLIENT"); state.chmod(0o600)
    marker = tmp_path / "dispatch.json"; values = payloads(); calls = []; revoked = []
    if fault == "wrong-phase": values[c.PREVIEW]["phase"] = "remove"
    if fault == "widened-effect": values[c.PREVIEW]["Proposed Changes"]["maximum_native_mutations"] = 2
    if fault == "bad-digest": values[c.PREVIEW]["summary_digest"] = "f"*64
    if fault == "bad-auth": values[c.AUTHORIZE]["expires_at"] = 219
    if fault == "unknown-result": values[c.EXECUTE]["outcome"] = "reconciliation_required"
    class Session:
        async def initialize(self): pass
        async def list_tools(self): return SimpleNamespace(tools=[SimpleNamespace(name=n) for n in c.TOOLS])
        async def call_tool(self, name, arguments):
            calls.append(name)
            if name == c.EXECUTE:
                assert marker.exists() and json.loads(marker.read_bytes())["retry_allowed"] is False
                if fault == "transport": raise RuntimeError("PRIVATE_NATIVE_DETAIL")
                if fault == "cancelled": raise asyncio.CancelledError
            return SimpleNamespace(is_error=False, structured_content=values[name])
    @asynccontextmanager
    async def session(*a, **k): yield Session()
    async def token(*a, **k):
        assert k["require_existing_client"] and k["include_operation_scope"]
        return "SYNTHETIC_TOKEN", False, True, "SYNTHETIC_CLIENT"
    async def revoke(*a, **k): revoked.append(True); return True
    monkeypatch.setattr(c.time, "time", lambda:100.0)
    monkeypatch.setattr(c.oauth, "_mcp_session", session)
    monkeypatch.setattr(c.oauth, "_oauth_token", token)
    monkeypatch.setattr(c.oauth, "_revoke_and_prove_401", revoke)
    async def run(): return await c.run_jwt_manual_key_owner_mcp_oauth_acceptance("https://mcp.example/fpamcp", login, state, marker, phase="create")
    if fault == "none": assert asyncio.run(run())["completed"]
    else:
        with pytest.raises(asyncio.CancelledError if fault == "cancelled" else c.JwtOwnerAcceptanceError): asyncio.run(run())
    attempted = fault in {"none", "unknown-result", "transport", "cancelled"}
    assert calls.count(c.EXECUTE) == int(attempted) and marker.exists() is attempted and revoked == [True]
    if attempted:
        with pytest.raises(c.JwtOwnerAcceptanceError): asyncio.run(run())
        assert calls.count(c.EXECUTE) == 1 and revoked == [True]
