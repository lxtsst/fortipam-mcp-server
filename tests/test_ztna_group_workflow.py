"""One combined native group regression; shared kernel/auth controls are reused."""
from contextlib import contextmanager
from copy import deepcopy
import json
from urllib.parse import parse_qs

import httpx
import pytest

from fortipam_mcp.ztna_group_transport import NativeZtnaGroupTransport, COLLECTION, TAGS, _FIELDS, digest
from fortipam_mcp.ztna_group_workflow import NativeZtnaGroupWorkflow
from fortipam_mcp.ztna_group_runtime import build_ztna_group_candidate, PREFIX
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore

NONCE = "0123456789abcdef"
NAME = "mcp-v4-ztna-" + NONCE
MEMBER = "synthetic-ems-tag"
SERIAL = "synthetic-ztna-serial"
OWNER = "synthetic-ztna-owner"
IDENTITY = dict(requester_digest="1" * 64, transport_digest="2" * 64)


def frame(result, *, name="addrgrp", path="firewall", method="GET", **extra):
    return dict(http_method=method, status="success", http_status=200, version="v7.0.0", build=29,
        serial=SERIAL, vdom="root", name=name, path=path, results=deepcopy(result), **extra)


class Peer:
    def __init__(self, fault):
        self.fault = fault
        self.defaults = dict(name="", uuid="00000000-0000-0000-0000-000000000000", member=[], comment="",
            type="default", category="default", color=0, tagging=[], exclude="disable", **{
                "exclude-member": [], "allow-routing": "disable", "fabric-object": "disable"})
        self.schema = {key: dict(type=value) for key, value in _FIELDS.items()}
        self.schema["name"].update(size=79, required=True)
        self.schema["member"].update(required=True, children={"name": dict(type="string")})
        self.tags = [dict(name=MEMBER, type="dynamic", **{"sub-type": "ems-tag"})]
        self.original = dict(self.defaults, name="synthetic-original-group", category="ztna-ems-tag",
            uuid="abcdef12-1234-5678-9012-123456789abc", member=[dict(name=MEMBER)])
        self.rows = [self.original]
        self.writes = []
        self.logouts = self.sessions = 0
        self.store = None

    def owner(self):
        peer = self
        class Owner:
            logout_verified = False
            @contextmanager
            def authenticated(self):
                peer.sessions += 1
                self._client = httpx.Client(base_url="https://synthetic.example", cookies={"ccsrftoken": "synthetic-csrf"},
                    transport=httpx.MockTransport(peer.handle))
                try:
                    yield self
                finally:
                    self._client.close(); self.logout_verified = True; peer.logouts += 1
        return Owner()

    def handle(self, request):
        path, method = request.url.path, request.method
        query = parse_qs(request.url.query.decode())
        if method == "GET":
            if path == "/api/v2/monitor/web-ui/state":
                return httpx.Response(200, json=frame({"admin": dict(name=OWNER, login_name=OWNER,
                    sponsored_group_name="", guest_admin=False)}, name="state", path="web-ui"))
            if path == COLLECTION:
                action = query.get("action")
                result = {"children": self.schema} if action == ["schema"] else self.defaults if action == ["default"] else self.rows
                if action not in (["schema"], ["default"]):
                    result = [dict(row, q_no_edit=bool(self.sessions % 2)) for row in result]
                return httpx.Response(200, json=frame(result))
            if path == TAGS.split("?")[0]:
                return httpx.Response(200, json=frame(self.tags, name="address"))
            if path == "/api/v2/monitor/web-ui/object-urls":
                return httpx.Response(200, json=frame({"by_type": {"123": {"path": "firewall.addrgrp"}}}, name="object-urls", path="web-ui"))
            if path == "/api/v2/monitor/system/object/usage":
                assert query == {"mkey": [NAME], "qtypes": ["[123]"]}
                return httpx.Response(200, json=frame({"currently_using": ["synthetic-reference"] if self.fault == "referenced" else []},
                    name="object", path="system", mkey=NAME))
            raise AssertionError("unexpected native route")
        assert request.headers["X-CSRFTOKEN"] == "synthetic-csrf"
        assert self.store.claim_count == len(self.writes) + 1
        self.writes.append(method)
        if method == "POST":
            assert path == COLLECTION
            body = json.loads(request.content)
            assert body == dict(self.defaults, name=NAME, category="ztna-ems-tag",
                member=[dict(name=MEMBER, q_origin_key=MEMBER, datasource="firewall.address")])
            self.rows.append(dict(body, uuid="12345678-1234-5678-9012-123456789abc", member=[dict(name=MEMBER, q_origin_key=MEMBER)]))
            if self.fault == "field-drift": self.rows[-1]["fabric-object"] = "enable"
            if self.fault == "original-drift": self.original["comment"] = "external-change"
            if self.fault == "tag-drift": self.tags[0]["sub-type"] = "different"
            if self.fault == "lost-ack": raise httpx.ReadTimeout("synthetic")
        else:
            assert method == "DELETE" and path == COLLECTION + "/" + NAME and not request.content
            self.rows = [self.original]
        return httpx.Response(200, json=frame({}, method=method, mkey=NAME))


def make(root, peer):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = root / "execution.key"
    if not key.exists(): key.write_bytes(b"e" * 32); key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(root / "execution.sqlite3", key); peer.store = store
    transport = NativeZtnaGroupTransport(owner_factory=peer.owner, owner_name=OWNER, serial=SERIAL,
        name=NAME, member=MEMBER, nonce=NONCE, schema_digest=digest(peer.schema), defaults=peer.defaults,
        tags_digest=digest(peer.tags), baseline_groups=[peer.original])
    return NativeZtnaGroupWorkflow(transport, store, authority_key=b"a" * 32, environment_ref="synthetic-environment",
        scope_ref="synthetic-scope", audience_ref="synthetic-audience", allowed_requester_digest=IDENTITY["requester_digest"],
        allowed_transport_digest=IDENTITY["transport_digest"], create_enabled=True, recovery_enabled=True, clock=lambda: 1000)


def run(workflow, phase):
    preview = workflow.preview(phase, **IDENTITY)
    assert preview["Expected State"]["initial_group_table_restored"] == (phase == "recover")
    assert "crl" not in json.dumps(preview)
    auth = workflow.authorize(phase, preview["preview_ref"], **IDENTITY)
    plan, authorization = workflow._issued[phase]
    assert plan.target_ref == "fixed-new-unbound-ztna-group"
    assert authorization.confirmation_ref.startswith("ztna-group-intent-")
    assert authorization.approval_ref.startswith("ztna-group-approval-")
    result = workflow.execute(phase, auth["authorization_ref"], **IDENTITY)
    return result, auth


def test_native_body_complete_cycle_and_fail_closed_differences(tmp_path):
    assert build_ztna_group_candidate({}) is None
    with pytest.raises(ValueError): build_ztna_group_candidate({PREFIX + "CREATE_ENABLED": "true"})
    for fault in ("none", "lost-ack", "field-drift", "tag-drift", "referenced", "original-drift"):
        peer = Peer(fault); root = (tmp_path / fault).resolve(); workflow = make(root, peer)
        result, auth = run(workflow, "create")
        assert workflow.execute("create", auth["authorization_ref"], **IDENTITY)["idempotent_replay"]
        if fault == "none":
            assert result["outcome"] == "succeeded" and result["verification"] == "verified"
            assert run(workflow, "recover")[0]["outcome"] == "succeeded"
            assert peer.writes == ["POST", "DELETE"] and peer.rows == [peer.original] and workflow._store.claim_count == 2
        else:
            assert result["outcome"] != "succeeded"
            for phase in ("create", "recover"):
                with pytest.raises(ValueError): workflow.preview(phase, **IDENTITY)
            assert peer.writes == ["POST"] and workflow._store.claim_count == 1
        # Restart cannot adopt the old object or recreate its original receipt.
        if fault != "tag-drift":
            replacement = make(root, peer)
            for phase in ("create", "recover"):
                with pytest.raises(ValueError): replacement.preview(phase, **IDENTITY)
            replacement.close()
        assert peer.logouts == peer.sessions
        assert MEMBER not in json.dumps(result) and SERIAL not in json.dumps(result)
        workflow.close()
