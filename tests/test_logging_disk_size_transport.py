"""Synthetic fixed singleton lifecycle using real workflow and persistent M4."""
from copy import deepcopy
import json
from urllib.parse import parse_qs

import httpx
import pytest

from fortipam_mcp.logging_disk_size_transport import (
    DISK, MEMORY, LoggingDiskSizeTransport, _DISK_FIELDS, _RANGES, digest, disk_projection,
)
from fortipam_mcp.logging_disk_size_workflow import LoggingDiskSizeWorkflow
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_ems_timeout_workflow import IDENTITY, OWNER, SERIAL, Peer as EmsPeer, frame

PROTECTED = "SYNTHETIC_PROTECTED_OPAQUE_TOKEN"


class Peer:
    owner = EmsPeer.owner

    def __init__(self, fault):
        self.fault = fault
        self.disk = {}
        children = {}
        for key, kind in _DISK_FIELDS.items():
            spec = {"type": kind}
            if kind == "integer":
                low, high = _RANGES[key]
                spec.update({"min-value": low, "max-value": high})
                self.disk[key] = 20 if key == "max-log-file-size" else low
            elif kind == "option":
                choices = ["enable", "disable"] if key == "status" else ["synthetic-option"]
                spec["options"] = [{"name": choice} for choice in choices]
                self.disk[key] = choices[0]
            else:
                self.disk[key] = (PROTECTED if kind == "password" else "192.0.2.1"
                                  if kind == "ipv4-address" else "synthetic-value")
            children[key] = spec
        children["max-log-file-size"]["default"] = 20
        self.schemas = {
            DISK: {"category": "complex", "mkey": None, "mkey_type": None, "children": children},
            MEMORY: {"category": "complex", "mkey": None, "mkey_type": None,
                     "children": {"status": {"type": "option", "options": [{"name": "enable"}, {"name": "disable"}]}}},
        }
        self.memory = {"status": "disable"}
        self.original = deepcopy(self.disk)
        self.writes = []
        self.sessions = self.logouts = 0
        self.store = None

    def handle(self, request):
        path, method = request.url.path, request.method
        if method == "GET":
            if path == "/api/v2/monitor/web-ui/state":
                return httpx.Response(200, json=frame({"admin": dict(name=OWNER, login_name=OWNER,
                    sponsored_group_name="", guest_admin=False)}, name="state", path="web-ui"))
            assert path in {DISK, MEMORY}
            query = parse_qs(request.url.query.decode())
            assert query in ({"action": ["schema"], "with_meta": ["true"]}, {"with_meta": ["true"]})
            row = self.schemas[path] if query.get("action") else self.disk if path == DISK else self.memory
            return httpx.Response(200, json=frame(row, name="setting", path="log.disk" if path == DISK else "log.memory"))
        assert method == "PUT" and path == DISK
        assert request.headers["X-CSRFTOKEN"] == "synthetic-csrf"
        assert self.store.claim_count == len(self.writes) + 1
        value = 21 if not self.writes else 20
        assert request.content == ('{"max-log-file-size":' + str(value) + '}').encode()
        self.writes.append(value)
        self.disk["max-log-file-size"] = value
        if self.fault == "field-drift":
            self.disk["uploaduser"] = "changed"
        if self.fault == "opaque-drift":
            self.disk["uploadpass"] += "_CHANGED"
        if self.fault == "memory-drift":
            self.memory["status"] = "enable"
        if self.fault == "lost-ack":
            raise httpx.ReadTimeout("synthetic")
        echoed = {"uploadpass": PROTECTED} if self.fault == "ack-opaque" else {}
        return httpx.Response(200, json=frame(echoed, method="PUT", name="setting",
            path="log.memory" if self.fault == "wrong-ack" else "log.disk"))


def make(root, peer):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = root / "execution.key"
    if not key.exists():
        key.write_bytes(b"e" * 32)
        key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(root / "execution.sqlite3", key)
    peer.store = store
    raw = bytearray(json.dumps(peer.original).encode())
    try:
        baseline = disk_projection(raw)
    finally:
        raw[:] = bytes(len(raw))
    transport = LoggingDiskSizeTransport(owner_factory=peer.owner, owner_name=OWNER, serial=SERIAL,
        nonce="0123456789abcdef", disk_schema_digest=digest(peer.schemas[DISK]),
        memory_schema_digest=digest(peer.schemas[MEMORY]), baseline_disk=baseline,
        baseline_memory={"status": "disable"})
    return LoggingDiskSizeWorkflow(transport, store, authority_key=b"a" * 32,
        environment_ref="synthetic-environment", scope_ref="synthetic-scope", audience_ref="synthetic-audience",
        allowed_requester_digest=IDENTITY["requester_digest"], allowed_transport_digest=IDENTITY["transport_digest"],
        update_enabled=True, recovery_enabled=True, clock=lambda: 100)


def run(workflow, phase):
    preview = workflow.preview(phase, **IDENTITY)
    assert preview["Proposed Changes"]["max_log_file_size_mb"] == (21 if phase == "update" else 20)
    auth = workflow.authorize(phase, preview["preview_ref"], **IDENTITY)
    return workflow.execute(phase, auth["authorization_ref"], **IDENTITY), auth


def test_fixed_size_lifecycle_preserves_singletons_and_rejects_unowned_recovery(tmp_path, monkeypatch):
    original_loads = json.loads
    def safe_loads(value, *args, **kwargs):
        encoded = value.encode() if isinstance(value, str) else bytes(value)
        assert PROTECTED.encode() not in encoded, "opaque protected token must never be decoded"
        return original_loads(value, *args, **kwargs)
    monkeypatch.setattr(json, "loads", safe_loads)

    for fault in ("none", "ack-opaque", "field-drift", "opaque-drift", "memory-drift", "lost-ack", "wrong-ack"):
        peer = Peer(fault)
        root = (tmp_path / fault).resolve()
        workflow = make(root, peer)
        transport = workflow._transport
        with pytest.raises(ValueError):
            workflow.preview("recover", **IDENTITY)
        # The internal request boundary rejects every broader body before a client is used.
        for path, body in ((MEMORY, b'{"max-log-file-size":21}'),
                           (DISK, b'{"max-log-file-size":22}'),
                           (DISK, b'{"max-log-file-size":21,"status":"disable"}')):
            with pytest.raises(ValueError):
                transport._request(None, "PUT", path, body=body, guard=lambda: None)
        peer.disk["uploaduser"] = "prewrite-drift"
        with pytest.raises(ValueError):
            transport.inspect("update")
        peer.disk = deepcopy(peer.original)
        assert peer.writes == [] and workflow._store.claim_count == 0

        result, auth = run(workflow, "update")
        sessions = peer.sessions
        assert workflow.execute("update", auth["authorization_ref"], **IDENTITY)["idempotent_replay"]
        assert peer.sessions == sessions
        if fault in {"none", "ack-opaque"}:
            assert result["outcome"] == "succeeded" and result["verification"] == "verified"
            assert run(workflow, "recover")[0]["outcome"] == "succeeded"
            assert peer.writes == [21, 20] and peer.disk == peer.original
            assert peer.memory == {"status": "disable"} and workflow._store.claim_count == 2
        else:
            assert result["outcome"] != "succeeded"
            with pytest.raises(ValueError):
                workflow.preview("recover", **IDENTITY)
            assert peer.writes == [21] and workflow._store.claim_count == 1
        replacement = make(root, peer)
        for phase in ("update", "recover"):
            with pytest.raises(ValueError):
                replacement.preview(phase, **IDENTITY)
        assert peer.logouts == peer.sessions
        assert PROTECTED not in json.dumps(result) and PROTECTED not in json.dumps(transport._baseline_disk)
        replacement.close()
        workflow.close()
