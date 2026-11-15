"""The SSH source profile is explicit, device-bound and cannot replay RDP records."""
from copy import deepcopy
import hashlib
import json
from urllib.parse import parse_qs, unquote

import httpx
import pytest

from fortipam_mcp.launcher_clone_http_transport import (
    CONTRACT, PUTTY_CONTRACT, FortiPamLauncherCloneHttpTransport, PuttyLauncherCloneBinding,
    LauncherCloneTransportError, configuration_digest, load_launcher_clone_binding,
    load_putty_launcher_clone_binding,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_client_integrity_association_contract import detail

SOURCE = "PuTTY"
DESTINATION = "mcp-v4-putty-clone-20261006-r2"
SERIAL = "synthetic-device-serial"


class PuttyAppliance:
    def __init__(self):
        row = detail()["results"]
        row.update(name=SOURCE, q_origin_key=SOURCE, q_ref=4)
        self.rows = {SOURCE: row}; self.calls = []
        self.serial = SERIAL; self.references = []; self.lose_post = False; self.ack_extra = {}
        self.omit_clone_subtable = False

    def projection(self):
        return [{"name": name, "type": row["type"], "q_ref": row["q_ref"], "q_static": row["q_static"]}
                for name, row in self.rows.items()]

    def binding(self):
        proposed = dict(deepcopy(self.rows[SOURCE]), name=DESTINATION, q_origin_key=DESTINATION, q_ref=0)
        return PuttyLauncherCloneBinding(SOURCE, DESTINATION, configuration_digest(self.rows[SOURCE]),
            configuration_digest(proposed), configuration_digest({r["name"]:configuration_digest(r) for r in self.projection()}),
            hashlib.sha256(SERIAL.encode()).hexdigest())

    def handle(self, request):
        self.calls.append(request)
        query = parse_qs(request.url.query.decode()); name = unquote(request.url.path.rsplit("/", 1)[-1])
        if name == "usage":
            assert request.method == "GET" and query == {"qtypes":["[17]"],"mkey":[DESTINATION]}
            return httpx.Response(200,json={"version":"v7.0.0","build":29,"http_method":"GET",
                "path":"system/object","name":"usage","action":"","status":"success",
                "mkey":DESTINATION,"serial":self.serial,
                "results":{} if self.references is None else {"currently_using":self.references}})
        status = 200; result = None
        if request.method == "POST":
            assert name == SOURCE and query == {"action":["clone"],"nkey":[DESTINATION],"vdom":["root"]}
            assert request.content == b"" and DESTINATION not in self.rows
            self.rows[DESTINATION] = dict(deepcopy(self.rows[SOURCE]), name=DESTINATION, q_origin_key=DESTINATION, q_ref=0)
            if self.omit_clone_subtable: self.rows[DESTINATION]["os_app"] = []
            if self.lose_post: raise httpx.ReadTimeout("private-sentinel")
        elif request.method == "DELETE":
            assert name == DESTINATION and request.content == b"" and self.references == []
            del self.rows[name]
        elif name == "launcher": result = self.projection()
        elif name in self.rows: result = [self.rows[name]]
        else: status = 404
        body = {"version":"v7.0.0","build":29,"http_method":request.method,"http_status":status,
                "path":"secret","name":"launcher","vdom":"root","serial":self.serial,
                "status":"success" if status == 200 else "error"}
        if request.method == "GET": body["results"] = result
        else: body.update(self.ack_extra)
        if name == "launcher": body.update(matched_count=len(result),size=len(result),next_idx=len(result)-1,limit_reached=False)
        return httpx.Response(status,json=body)


def adapter(tmp_path, device, binding=None, **gates):
    tmp_path = tmp_path.resolve(); tmp_path.chmod(0o700)
    config = SecretMetadataHttpTransportConfig("https://pam.example.test","synthetic-token",5,None)
    return FortiPamLauncherCloneHttpTransport(config,binding or device.binding(),tmp_path,
        client_factory=lambda **kw:httpx.Client(transport=httpx.MockTransport(device.handle),**kw),**gates)


def test_used_builtin_source_is_unchanged_clone_is_fresh_and_both_operations_cannot_replay(tmp_path):
    device = PuttyAppliance(); baseline = deepcopy(device.rows); binding = device.binding()
    transport = adapter(tmp_path,device,binding,clone_enabled=True,recovery_enabled=True)
    assert transport.putty_profile and transport.execute()["clone_present"]
    assert device.rows[SOURCE] == baseline[SOURCE] and device.rows[DESTINATION]["q_ref"] == 0
    assert transport.execute(recovery=True)["clone_present"] is False and device.rows == baseline
    before = len(device.calls)
    for recovery in (False,True):
        with pytest.raises(LauncherCloneTransportError):
            adapter(tmp_path,device,binding,clone_enabled=True,recovery_enabled=True).execute(recovery=recovery)
    assert len(device.calls) == before
    assert [r.method for r in device.calls if r.method != "GET"] == ["POST","DELETE"]
    for path in tmp_path.iterdir():
        value = json.loads(path.read_bytes()); assert value["contract"] == PUTTY_CONTRACT
        assert SOURCE not in path.read_text() and path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("references", [None,[{"object":"private-sentinel"}],False])
def test_reference_unknown_or_used_never_authorizes_delete(tmp_path,references):
    device = PuttyAppliance(); transport = adapter(tmp_path,device,clone_enabled=True,recovery_enabled=True)
    transport.execute(); device.references = references
    with pytest.raises(LauncherCloneTransportError): transport.execute(recovery=True)
    assert DESTINATION in device.rows and not (tmp_path/"recover.claim.json").exists()
    assert all(r.method != "DELETE" for r in device.calls)


@pytest.mark.parametrize("extra", [{"unknown":"private-sentinel"},{"error":-1},{"old_revision":False}])
def test_uncertain_or_contradictory_ack_is_consumed_without_cleanup_authority(tmp_path,extra):
    device = PuttyAppliance(); binding = device.binding(); device.ack_extra = extra
    transport = adapter(tmp_path,device,binding,clone_enabled=True,recovery_enabled=True)
    with pytest.raises(LauncherCloneTransportError): transport.execute()
    assert (tmp_path/"clone.claim.json").exists() and not (tmp_path/"clone.verified.json").exists()
    before = len(device.calls)
    for recovery in (False,True):
        with pytest.raises(LauncherCloneTransportError):
            adapter(tmp_path,device,binding,clone_enabled=True,recovery_enabled=True).execute(recovery=recovery)
    assert len(device.calls) == before


def test_wrong_device_gate_and_cross_profile_records_or_binding_are_refused(tmp_path):
    device = PuttyAppliance(); binding = device.binding(); transport = adapter(tmp_path,device,binding)
    with pytest.raises(LauncherCloneTransportError): transport.execute()
    assert device.calls == []
    device.serial = "synthetic-other-device"
    with pytest.raises(LauncherCloneTransportError): adapter(tmp_path,device,binding,clone_enabled=True).execute()
    assert not (tmp_path/"clone.claim.json").exists()
    device.serial = SERIAL
    path = tmp_path/"binding.private.json"
    path.write_text(json.dumps({"contract":PUTTY_CONTRACT,**{k:getattr(binding,k) for k in binding.__slots__}}));path.chmod(0o600)
    assert load_putty_launcher_clone_binding(path) == binding
    with pytest.raises(LauncherCloneTransportError): load_launcher_clone_binding(path)
    for kind,state in (("claim","reserved"),("verified","verified")):
        path = tmp_path/("clone."+kind+".json")
        path.write_text(json.dumps({"contract":CONTRACT,"binding_digest":binding.digest,"direction":"clone","state":state}));path.chmod(0o600)
    before = len(device.calls)
    with pytest.raises(LauncherCloneTransportError): adapter(tmp_path,device,binding,recovery_enabled=True).execute(recovery=True)
    assert len(device.calls) == before


def test_lost_post_and_custom_source_cannot_be_reinterpreted(tmp_path):
    device = PuttyAppliance(); binding = device.binding(); device.lose_post = True
    transport = adapter(tmp_path,device,binding,clone_enabled=True,recovery_enabled=True)
    with pytest.raises(LauncherCloneTransportError) as failure: transport.execute()
    assert "private-sentinel" not in str(failure.value)
    assert DESTINATION in device.rows and not (tmp_path/"clone.verified.json").exists()
    before = len(device.calls)
    with pytest.raises(LauncherCloneTransportError): transport.execute(recovery=True)
    assert len(device.calls) == before
    with pytest.raises(LauncherCloneTransportError):
        PuttyLauncherCloneBinding("mcp-v4-launcher-test-b97",DESTINATION,binding.source_digest,binding.clone_digest,
                                   binding.collection_digest,binding.device_identity_digest)


def test_empty_backend_clone_subtable_remains_unverified_and_cannot_be_deleted(tmp_path):
    device = PuttyAppliance(); source = deepcopy(device.rows[SOURCE]); binding = device.binding()
    device.omit_clone_subtable = True
    transport = adapter(tmp_path,device,binding,clone_enabled=True,recovery_enabled=True)
    with pytest.raises(LauncherCloneTransportError): transport.execute()
    assert device.rows[SOURCE] == source and device.rows[DESTINATION]["os_app"] == []
    assert (tmp_path/"clone.claim.json").exists() and not (tmp_path/"clone.verified.json").exists()
    before = len(device.calls)
    for recovery in (False,True):
        with pytest.raises(LauncherCloneTransportError):
            adapter(tmp_path,device,binding,clone_enabled=True,recovery_enabled=True).execute(recovery=recovery)
    assert len(device.calls) == before
    assert [r.method for r in device.calls if r.method != "GET"] == ["POST"]


def test_putty_builder_requires_exclusive_profile_and_never_guesses_from_a_binding(tmp_path):
    from fortipam_mcp.launcher_clone_mcp_action import PREFIX, PUTTY_PREFIX, build_launcher_clone_candidate
    from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX
    device = PuttyAppliance(); binding = device.binding(); tmp_path.chmod(0o700)
    path = tmp_path/"binding.private.json"
    path.write_text(json.dumps({"contract":PUTTY_CONTRACT,**{k:getattr(binding,k) for k in binding.__slots__}}));path.chmod(0o600)
    env = {PUTTY_PREFIX+"ENABLED":"true",PUTTY_PREFIX+"BINDING_FILE":str(path),PUTTY_PREFIX+"STATE_DIRECTORY":str(tmp_path),
           ENV_PREFIX+"ENABLED":"true",ENV_PREFIX+"BASE_URL":"https://pam.example.test",ENV_PREFIX+"API_TOKEN":"synthetic-token"}
    assert build_launcher_clone_candidate({}) is None
    assert build_launcher_clone_candidate(env) is not None
    for extra in ({PREFIX+"ENABLED":"true"},{PREFIX+"EXECUTION_ENABLED":"true"},
                  {PUTTY_PREFIX+"RECOVERY_EXECUTION_ENABLED":"1"}, {PUTTY_PREFIX+"BINDING_FILE":"relative.json"}):
        with pytest.raises(ValueError): build_launcher_clone_candidate({**env,**extra})
    with pytest.raises(ValueError): build_launcher_clone_candidate({k.replace(PUTTY_PREFIX,PREFIX):v for k,v in env.items()})
    assert device.calls == []


@pytest.mark.parametrize("enabled", [False, True])
def test_real_local_mcp_preserves_schemas_scopes_closed_gate_and_profile_identity(tmp_path,enabled):
    import asyncio
    from types import SimpleNamespace
    import anyio
    from mcp import ClientSession
    from mcp.server.auth.provider import AccessToken
    from mcp.shared.memory import create_client_server_memory_streams
    from fortipam_mcp.folder_mcp_action import folder_action_principal_from_access_token
    from fortipam_mcp.launcher_clone_live_workflow import LauncherCloneLiveWorkflow, PUTTY_CONTRACT as WORKFLOW_CONTRACT
    from fortipam_mcp.launcher_clone_mcp_action import LauncherCloneActions, LauncherCloneMcpAction, register_launcher_clone_tools
    from fortipam_mcp.server import MCP_SERVER_CLASS
    from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, planning_principal_from_access_token

    device = PuttyAppliance(); transport = adapter(tmp_path,device,clone_enabled=enabled,recovery_enabled=enabled)
    actions = LauncherCloneActions(
        LauncherCloneMcpAction(LauncherCloneLiveWorkflow(transport),execution_enabled=enabled),
        LauncherCloneMcpAction(LauncherCloneLiveWorkflow(transport,recovery=True),execution_enabled=enabled))
    authority = V4PlanningAuthorizationSettings("https://mcp.example.test/fpamcp-v4",b"p"*32)
    token = AccessToken(token="synthetic-validated-token",client_id="client-0001",subject="operator-0001",
        scopes=["fortipam:read","fortipam:plan"],expires_at=2_000_000_000,
        resource=authority.expected_resource,claims={"iss":"https://mcp.example.test/oauth"})
    server = SimpleNamespace(mcp=MCP_SERVER_CLASS("putty-clone"),
        _v4_planning_principal=lambda:planning_principal_from_access_token(token,authority),
        _v4_password_policy_action_principal=lambda:folder_action_principal_from_access_token(token,authority))
    register_launcher_clone_tools(server,actions)

    async def run():
        async with create_client_server_memory_streams() as (client,service):
            async with anyio.create_task_group() as group:
                low = server.mcp._lowlevel_server
                group.start_soon(low.run,*service,low.create_initialization_options())
                async with ClientSession(*client) as session:
                    await session.initialize()
                    tools = (await session.list_tools()).tools; assert len(tools)==6
                    for tool in tools:
                        keys = set() if tool.name.startswith("preview") else {"preview_ref"} if tool.name.startswith("confirm") else {"authorization_ref"}
                        assert set(tool.input_schema.get("properties",{})) == keys
                    for recovery in (False,True):
                        name = "v4_launcher_clone"+("_recovery" if recovery else "")+"_700"
                        preview = await session.call_tool("preview_"+name,{})
                        assert not preview.is_error
                        value = preview.structured_content
                        assert value["contract"]==WORKFLOW_CONTRACT
                        assert value["Proposed Changes"]["operation"] == ("remove_owned_clone" if recovery else "clone_fixed_putty_launcher")
                        assert value["Current State"]["destination_reported_usage_empty"] is recovery
                        assert "zero_references" not in value["Current State"]
                        before = len(device.calls)
                        denied = await session.call_tool("confirm_"+name,{"preview_ref":value["preview_ref"]})
                        assert denied.is_error and len(device.calls)==before
                        token.scopes.append("fortipam:operate")
                        intent = await session.call_tool("confirm_"+name,{"preview_ref":value["preview_ref"]})
                        assert not intent.is_error and intent.structured_content["contract"]==WORKFLOW_CONTRACT
                        result = await session.call_tool("execute_confirmed_"+name,{"authorization_ref":intent.structured_content["authorization_ref"]})
                        if not enabled:
                            assert result.is_error and not (tmp_path/"clone.intent.json").exists()
                            break
                        assert not result.is_error and result.structured_content["verification"]=="verified"
                        token.scopes.remove("fortipam:operate")
                group.cancel_scope.cancel()
    asyncio.run(run())
    assert [r.method for r in device.calls if r.method!="GET"]==(["POST","DELETE"] if enabled else [])
    assert DESTINATION not in device.rows
