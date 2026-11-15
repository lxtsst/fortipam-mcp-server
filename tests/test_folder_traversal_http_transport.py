from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from fortipam_mcp.folder_traversal_http_transport import FolderTraversalHttpTransport
from fortipam_mcp.folder_acl_live_workflow import FolderAclLiveWorkflowError
from test_folder_traversal_candidate import record
from test_folder_traversal_mcp_action import binding_fixture


@pytest.mark.parametrize("change", [None, "drift", "version", "owner", "provider_error"])
def test_fixed_put_rechecks_binding_and_preserves_original_acl_fields(change):
    transport = object.__new__(FolderTraversalHttpTransport)
    current = record()
    if change == "drift":
        current["name"] = "changed"
    transport.read_folder = lambda identifier: deepcopy(current)
    transport.read_product_version_and_build = lambda: ("7.0.0", 30 if change == "version" else 29)
    transport.owner_is_available = lambda username: change != "owner"
    calls = []
    def request(method, path, content):
        calls.append((method, path, json.loads(content)))
        return SimpleNamespace(status_code=200, data={"status": "error" if change == "provider_error" else "success"})
    transport._folders = SimpleNamespace(_request=request)
    if change is None:
        transport.update_traversal(binding_fixture())
        assert calls[0][:2] == ("PUT", "/api/v2/cmdb/secret/folder/12")
        body = calls[0][2]
        assert body["parent-folder"] == 0
        assert body["user-permission"][:-1] == current["user-permission"]
        assert body["user-permission"][-1]["secret-permission"] == "none"
    else:
        with pytest.raises((ValueError, FolderAclLiveWorkflowError)):
            transport.update_traversal(binding_fixture())
    assert len(calls) == int(change in {None, "provider_error"})
