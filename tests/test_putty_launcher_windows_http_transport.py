"""One fixed Windows definition has independent claims and complete readback."""
from copy import deepcopy
import json
from urllib.parse import parse_qs

import httpx
import pytest

from fortipam_mcp.launcher_clone_http_transport import (
    COPY_CONTRACT, WINDOWS_CONTRACT, PuttyLauncherWindowsBinding, LauncherCloneTransportError,
    configuration_digest, load_putty_launcher_windows_binding, load_putty_launcher_copy_binding,
)
from fortipam_mcp.launcher_clone_live_workflow import WINDOWS_CONTRACT as WORKFLOW_CONTRACT, LauncherCloneLiveWorkflow
from fortipam_mcp.putty_launcher_windows_http_contract import compile_native_windows_putty_body
from test_putty_launcher_windows_http_contract import APPLICATION, source
from test_putty_launcher_clone_http_transport import PuttyAppliance, adapter, SOURCE, DESTINATION


class WindowsAppliance(PuttyAppliance):
    def __init__(self):
        super().__init__(); self.rows[SOURCE] = source()["results"]; self.source_reads = 0; self.drift_before_form = False

    def binding(self):
        original = super().binding()
        body = compile_native_windows_putty_body(
            {"version":"v7.0.0","build":29,"http_method":"GET","http_status":200,"path":"secret",
             "name":"launcher","vdom":"root","status":"success","results":self.rows[SOURCE]},
            launcher_name=DESTINATION, application=APPLICATION,
            expected_source_configuration_digest=original.source_digest)
        row = dict(deepcopy(self.rows[SOURCE]), **body, q_origin_key=DESTINATION, q_ref=0)
        row["os_app"][0]["q_origin_key"] = 1
        fields = {k:getattr(original,k) for k in original.__slots__}; fields["clone_digest"] = configuration_digest(row)
        return PuttyLauncherWindowsBinding(**fields,executable_path=APPLICATION.executable_path,
            executable_sha256=APPLICATION.executable_sha256)

    def handle(self, request):
        if request.method == "POST":
            self.calls.append(request)
            assert request.url.path == "/api/v2/cmdb/secret/launcher" and parse_qs(request.url.query.decode()) == {"vdom":["root"]}
            body = json.loads(request.content)
            assert body["name"] == DESTINATION and "$originalName" not in body
            assert body["os_app"][0]["exe"] == APPLICATION.executable_path
            row = dict(deepcopy(self.rows[SOURCE]), **body, q_origin_key=DESTINATION, q_ref=0)
            row["os_app"][0]["q_origin_key"] = 1
            assert DESTINATION not in self.rows; self.rows[DESTINATION] = row
            if self.omit_clone_subtable: row["os_app"] = []
            if self.lose_post: raise httpx.ReadTimeout("private-sentinel")
            return httpx.Response(200,json={"version":"v7.0.0","build":29,"http_method":"POST","http_status":200,
                "path":"secret","name":"launcher","vdom":"root","serial":self.serial,"status":"OK",
                "mkey":DESTINATION,"action":"",**self.ack_extra})
        if request.method == "GET" and request.url.path.endswith("/"+SOURCE):
            self.source_reads += 1
            if self.drift_before_form and self.source_reads == 2: self.rows[SOURCE]["launch-timeout"] += 1
        return super().handle(request)


def test_fixed_windows_create_and_owned_cleanup_are_one_shot_and_preserve_foreign_state(tmp_path):
    device = WindowsAppliance(); baseline = deepcopy(device.rows); binding = device.binding()
    transport = adapter(tmp_path,device,binding,clone_enabled=True,recovery_enabled=True)
    workflow = LauncherCloneLiveWorkflow(transport)
    preview = workflow.preview(requester_digest="a"*64)
    assert preview["contract"] == WORKFLOW_CONTRACT
    assert preview["Proposed Changes"]["operation"] == "create_fixed_windows_putty_launcher"
    assert preview["Proposed Changes"]["fixed_executable_and_variable_parameters"] is True
    assert APPLICATION.executable_path not in json.dumps(preview)
    authorization = workflow.confirm(preview["preview_ref"],requester_digest="a"*64)
    assert workflow.execute(authorization["authorization_ref"],requester_digest="a"*64)["verification"] == "verified"
    assert transport.execute(recovery=True)["clone_present"] is False and device.rows == baseline
    before = len(device.calls)
    for recovery in (False,True):
        with pytest.raises(LauncherCloneTransportError):
            adapter(tmp_path,device,binding,clone_enabled=True,recovery_enabled=True).execute(recovery=recovery)
    assert len(device.calls) == before
    assert [r.method for r in device.calls if r.method != "GET"] == ["POST","DELETE"]
    for path in tmp_path.iterdir():
        assert json.loads(path.read_bytes())["contract"] == WINDOWS_CONTRACT
        assert APPLICATION.executable_path not in path.read_text()


@pytest.mark.parametrize("failure", ["lost_response","missing_child","source_mkey","clone_action"])
def test_windows_partial_or_uncertain_result_cannot_gain_ownership_replay_or_delete(tmp_path,failure):
    device = WindowsAppliance(); binding = device.binding()
    if failure == "lost_response": device.lose_post = True
    elif failure == "missing_child": device.omit_clone_subtable = True
    elif failure == "source_mkey": device.ack_extra = {"mkey":SOURCE}
    else: device.ack_extra = {"action":"clone"}
    with pytest.raises(LauncherCloneTransportError): adapter(tmp_path,device,binding,clone_enabled=True).execute()
    assert (tmp_path/"clone.claim.json").exists() and not (tmp_path/"clone.verified.json").exists()
    before = len(device.calls)
    for recovery in (False,True):
        with pytest.raises(LauncherCloneTransportError): adapter(tmp_path,device,binding,clone_enabled=True,recovery_enabled=True).execute(recovery=recovery)
    assert len(device.calls) == before and DESTINATION in device.rows


def test_windows_fresh_source_drift_after_claim_prevents_post(tmp_path):
    device = WindowsAppliance(); binding = device.binding(); device.drift_before_form = True
    with pytest.raises(LauncherCloneTransportError): adapter(tmp_path,device,binding,clone_enabled=True).execute()
    assert (tmp_path/"clone.claim.json").exists() and not (tmp_path/"clone.verified.json").exists()
    assert all(r.method == "GET" for r in device.calls) and DESTINATION not in device.rows


def test_windows_binding_profile_and_records_cannot_adopt_prior_copy(tmp_path):
    from fortipam_mcp.launcher_clone_mcp_action import WINDOWS_PREFIX, COPY_PREFIX, PUTTY_PREFIX, PREFIX, build_launcher_clone_candidate
    from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX
    device = WindowsAppliance(); binding = device.binding(); tmp_path.chmod(0o700)
    path = tmp_path/"binding.private.json"
    path.write_text(json.dumps({"contract":WINDOWS_CONTRACT,**{k:getattr(binding,k) for k in binding.__slots__}})); path.chmod(0o600)
    assert load_putty_launcher_windows_binding(path) == binding
    with pytest.raises(LauncherCloneTransportError): load_putty_launcher_copy_binding(path)
    env = {WINDOWS_PREFIX+"ENABLED":"true",WINDOWS_PREFIX+"BINDING_FILE":str(path),WINDOWS_PREFIX+"STATE_DIRECTORY":str(tmp_path),
           ENV_PREFIX+"ENABLED":"true",ENV_PREFIX+"BASE_URL":"https://pam.example.test",ENV_PREFIX+"API_TOKEN":"synthetic-token"}
    actions = build_launcher_clone_candidate(env); assert actions and not actions.clone._enabled
    assert actions.clone._workflow._transport.putty_windows_profile
    for other in (COPY_PREFIX,PUTTY_PREFIX,PREFIX):
        with pytest.raises(ValueError): build_launcher_clone_candidate({**env,other+"ENABLED":"true"})
    for kind,state in (("claim","reserved"),("verified","verified")):
        record = tmp_path/("clone."+kind+".json")
        record.write_text(json.dumps({"contract":COPY_CONTRACT,"binding_digest":binding.digest,"direction":"clone","state":state})); record.chmod(0o600)
    with pytest.raises(LauncherCloneTransportError): adapter(tmp_path,device,binding,recovery_enabled=True).execute(recovery=True)
    assert device.calls == []
