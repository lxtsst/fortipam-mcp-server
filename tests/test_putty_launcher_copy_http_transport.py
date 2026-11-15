"""Complete-form copies preserve children and cannot adopt old clone records."""
from copy import deepcopy
import json

import pytest

from fortipam_mcp.launcher_clone_http_transport import (
    COPY_CONTRACT, PUTTY_CONTRACT, PuttyLauncherCopyBinding, LauncherCloneTransportError,
    load_putty_launcher_copy_binding, load_putty_launcher_clone_binding,
)
from fortipam_mcp.launcher_clone_live_workflow import LauncherCloneLiveWorkflow
from test_putty_launcher_clone_http_transport import PuttyAppliance, adapter, SOURCE, DESTINATION


class CopyAppliance(PuttyAppliance):
    def binding(self):
        original = super().binding()
        return PuttyLauncherCopyBinding(**{k:getattr(original,k) for k in original.__slots__})


@pytest.mark.parametrize("entrypoint", ["inspect", "preview", "execute"])
def test_implicit_builtin_executable_cannot_qualify_custom_copy_or_dispatch(tmp_path, entrypoint):
    from fortipam_mcp.launcher_clone_live_workflow import LauncherCloneWorkflowError

    device = CopyAppliance(); before = deepcopy(device.rows); binding = device.binding()
    transport = adapter(tmp_path,device,binding,clone_enabled=True,recovery_enabled=True)
    with pytest.raises((LauncherCloneTransportError, LauncherCloneWorkflowError)):
        if entrypoint == "preview":
            LauncherCloneLiveWorkflow(transport).preview(requester_digest="a"*64)
        else:
            getattr(transport, entrypoint)()
    assert device.rows == before and DESTINATION not in device.rows
    assert device.calls and all(request.method == "GET" for request in device.calls)
    assert list(tmp_path.iterdir()) == []


def test_copy_loader_builder_and_record_domain_refuse_old_profile_adoption(tmp_path):
    from fortipam_mcp.launcher_clone_mcp_action import COPY_PREFIX, PUTTY_PREFIX, PREFIX, build_launcher_clone_candidate
    from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX
    device = CopyAppliance(); binding = device.binding(); tmp_path.chmod(0o700)
    path = tmp_path/"binding.private.json"
    path.write_text(json.dumps({"contract":COPY_CONTRACT,**{k:getattr(binding,k) for k in binding.__slots__}})); path.chmod(0o600)
    assert load_putty_launcher_copy_binding(path) == binding
    with pytest.raises(LauncherCloneTransportError): load_putty_launcher_clone_binding(path)
    env = {COPY_PREFIX+"ENABLED":"true",COPY_PREFIX+"BINDING_FILE":str(path),COPY_PREFIX+"STATE_DIRECTORY":str(tmp_path),
           ENV_PREFIX+"ENABLED":"true",ENV_PREFIX+"BASE_URL":"https://pam.example.test",ENV_PREFIX+"API_TOKEN":"synthetic-token"}
    actions = build_launcher_clone_candidate(env); assert actions is not None and actions.clone._enabled is False
    assert actions.clone._workflow._transport.putty_copy_profile is True
    for other in (PUTTY_PREFIX,PREFIX):
        with pytest.raises(ValueError): build_launcher_clone_candidate({**env,other+"ENABLED":"true"})
        with pytest.raises(ValueError): build_launcher_clone_candidate({**env,other+"EXECUTION_ENABLED":"true"})
    for kind,state in (("claim","reserved"),("verified","verified")):
        record = tmp_path/("clone."+kind+".json")
        record.write_text(json.dumps({"contract":PUTTY_CONTRACT,"binding_digest":binding.digest,"direction":"clone","state":state})); record.chmod(0o600)
    with pytest.raises(LauncherCloneTransportError): adapter(tmp_path,device,binding,recovery_enabled=True).execute(recovery=True)
    assert device.calls == []
