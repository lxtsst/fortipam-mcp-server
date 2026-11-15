"""Original signed ownership and fresh fixed projections with synthetic peers."""
from copy import deepcopy
from dataclasses import replace
import io
import json
import ssl

import httpx
import pytest

from fortipam_mcp import windows_execution_secret_preflight as p
from fortipam_mcp.isolated_folder_http_transport import IsolatedFolderHttpTransport
from fortipam_mcp.isolated_folder_live_workflow import IsolatedFolderLiveWorkflow
from fortipam_mcp.isolated_folder_m4_adapter import IsolatedFolderBinding
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.target_creation_http_transport import TargetCreationHttpTransport
from fortipam_mcp.target_creation_serializer import compile_windows_execution_target_request
from fortipam_mcp.target_api_dependency_reader import TargetApiDependencyReader
from fortipam_mcp.windows_execution_secret_contract import WindowsExecutionSecretBinding
from test_isolated_folder_creation_snapshot_transport import Peer as FolderPeer
from test_target_api_dependency_reader import Harness
from test_target_creation_evidence import envelope
from test_target_preservation_contract import response
from test_windows_execution_target_serializer import windows


class TargetPeer:
    def __init__(self, value):
        self.initial, self.created = deepcopy(value), None
        self.calls, self.buffers = [], []
        self.hook = lambda: None

    def factory(self, *args, **kwargs):
        peer = self
        class Connection:
            def connect(self): peer.hook()
            def request(self, method, path, body, headers):
                peer.calls.append(method)
                if method == "POST":
                    assert json.loads(body.tobytes())["template"] == "Windows Machine"
                    peer.created = deepcopy(peer.initial)
                    peer.created.update(id=10, uuid="synthetic-created-uuid", **{"creation-time":1234})
                    data = json.loads(envelope())
                    status = 200
                elif peer.created is None:
                    data = json.loads(envelope(absent=True))
                    status = 404
                else:
                    data = json.loads(response(peer.created))
                    status = 200
                data["mkey"] = peer.initial["name"]
                self.response = Response(bytearray(json.dumps(data).encode()), status)
            def getresponse(self): return self.response
            def close(self): pass
        class Response:
            def __init__(self, raw, status): self.raw, self.status = io.BytesIO(raw), status
            def getheader(self, name, default=""): return "application/json" if name == "Content-Type" else default
            def readinto(self, view): return self.raw.readinto(view)
            def close(self): pass
        return Connection()


def setup(tmp_path, monkeypatch, *, initial_target=None, privilege_metadata=True):
    tmp_path.chmod(0o700)
    trust = ssl.create_default_context()
    monkeypatch.setattr(ssl, "create_default_context", lambda **kwargs: trust)
    ca = tmp_path / "ca.pem"
    ca.write_bytes(b"Synthetic pinned public CA")
    config = SecretMetadataHttpTransportConfig("https://pam.example", "synthetic-token", 30, str(ca))
    peer = FolderPeer()
    peer.serial = "SYNTHETIC"
    folders = IsolatedFolderHttpTransport(config, parent_path="Public/BoundParent", child_name="Collector",
        owner_name="test-owner", owner_credentials=lambda: ("test-owner", "synthetic-password"),
        owner_client_factory=lambda **kwargs: httpx.Client(**kwargs, transport=httpx.MockTransport(peer.respond)))
    monkeypatch.setattr(folders._metadata, "resolve_folder_id", lambda path: 17)
    writes = []
    monkeypatch.setattr(folders, "read_product_version_and_build", lambda: ("7.0.0", 29))
    monkeypatch.setattr(folders, "read_parent_digest", lambda parent: "a" * 64)
    monkeypatch.setattr(folders, "owner_is_available", lambda owner: True)
    monkeypatch.setattr(folders, "find_child_ids", lambda name, parent: (23,) if writes else ())
    monkeypatch.setattr(folders, "read_creation_device_serial", lambda: peer.serial)
    def create_folder(**kwargs):
        kwargs["before_dispatch"]()
        writes.append("folder")
        return {"http_status": 200, "mkey":23}
    monkeypatch.setattr(folders, "create_isolated_child", create_folder)
    monkeypatch.setattr(folders, "verify_isolated_child", lambda *args, **kwargs: True)
    key = tmp_path / "folder.key"
    key.write_bytes(b"f" * 32)
    key.chmod(0o600)
    binding = IsolatedFolderBinding("Collector", 17, "test-owner", "a" * 64, empty_inactive_policy=True)
    workflow = IsolatedFolderLiveWorkflow(tmp_path / "folder.sqlite", key, folders,
        binding=binding, ownership_expected_serial=peer.serial, clock=lambda: 1000)
    requester = "b" * 64
    preview = workflow.preview(folder_name="Collector", parent_folder_id=17, requester_digest=requester)
    auth = workflow.confirm(preview["preview_ref"], requester_digest=requester)
    assert workflow.execute(auth["authorization_ref"], requester_digest=requester)["outcome"] == "succeeded"
    target_fields = {"q_ref":0, "q_static":False,
        "user-permission":[{"id":1, "user-name":[{"name":"test-owner"}], "permission":"owner"}]}
    if privilege_metadata:
        target_fields["priv_acct"] = 0
    target_fields.update(initial_target or {})
    target, proposal, expected = windows(**target_fields)
    wire = compile_windows_execution_target_request(proposal, bytearray(expected))
    native = TargetPeer(target)
    state = tmp_path / "target"
    state.mkdir(mode=0o700)
    creator = TargetCreationHttpTransport(config, proposal, wire, expected_material=expected,
        state_directory=state, provenance_key=b"t" * 32, execution_enabled=True,
        clock=lambda:1000, connection_factory=native.factory)
    creator.create(plan_digest="a" * 64, authorization_digest="b" * 64,
        expires_at=1030, before_send=lambda:None)
    harness = Harness()
    template = harness.values[3]["results"][0]
    template.update(name="Windows Machine", field=[
        {"name":"Host", "type":"target-address", "mandatory":"enable"},
        {"name":"Username", "type":"username", "mandatory":"disable"},
        {"name":"Password", "type":"password", "mandatory":"disable"}])
    handle = harness.handle
    def fixed_template(request):
        if len(harness.requests) == 8:
            harness.requests.append(request)
            return httpx.Response(200, headers={"content-type":"application/json"},
                stream=httpx.ByteStream(json.dumps(harness.values[3]).encode()))
        return handle(request)
    harness.handle = fixed_template
    api = TargetApiDependencyReader(config, serial_digest=proposal.serial_digest,
        client_factory=harness.factory, clock=lambda:harness.now)
    profile = WindowsExecutionSecretBinding("MCPV4WinExec20261021R1", proposal.name,
        proposal.coordinates.address, "UNIT-WINDOWS", 23, proposal.serial_digest, "d" * 64)
    kwargs = dict(creator=creator, folder_workflow=workflow, folder_preview_ref=preview["preview_ref"],
        requester_digest=requester, api=api, clock=lambda:harness.now)
    preflight = p.WindowsExecutionOwnedDependencies(profile, **kwargs)
    return dict(reader=preflight, kwargs=kwargs, profile=profile, creator=creator,
        folder=peer, workflow=workflow, target=native, api=api, harness=harness, writes=writes)


def test_original_seals_join_fresh_complete_target_folder_and_api_dependencies(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    before = list(cmp["target"].calls), len(cmp["writes"])
    scalar = p.m._scalar
    def metadata_only(raw, span):
        assert b"MATERIAL_SENTINEL" not in raw[slice(*span)]
        return scalar(raw, span)
    monkeypatch.setattr(p.m, "_scalar", metadata_only)
    observed = cmp["reader"].read_once()
    cmp["reader"].check_current(observed)
    assert observed.target_creation_digest == cmp["creator"].load_creation_evidence().evidence_digest
    assert len(cmp["harness"].requests) == 9
    assert cmp["target"].calls == before[0] + ["GET"] and len(cmp["writes"]) == before[1]
    assert cmp["folder"].active is False
    assert all(client.is_closed for client in cmp["harness"].clients)
    assert "Collector" not in repr(observed) and "test-owner" not in repr(observed)


@pytest.mark.parametrize("fault", ["target-drift", "target-owner", "target-ref", "target-privilege", "target-service",
    "folder-policy", "folder-acl", "folder-logout", "parent-drift", "role", "template", "template-kind",
    "template-drift", "api-http", "ca", "source", "clock"])
def test_drift_or_incomplete_source_never_produces_owned_dependencies(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path, monkeypatch)
    if fault == "target-drift": cmp["target"].created["description"] = "changed"
    if fault == "target-owner": cmp["target"].created["user-permission"][0]["user-name"][0]["name"] = "other"
    if fault == "target-ref": cmp["target"].created["q_ref"] = 1
    if fault == "target-privilege": cmp["target"].created["priv_acct"] = 5
    if fault == "target-service": cmp["target"].created["winrm-https"] = "enable"
    if fault == "folder-policy": cmp["folder"].folder["secret-policy"] = "background-policy"
    if fault == "folder-acl": cmp["folder"].folder["inherit-permission"] = "enable"
    if fault == "folder-logout": cmp["folder"].fault = "logout"
    if fault == "parent-drift":
        monkeypatch.setattr(cmp["reader"]._folders, "read_parent_digest", lambda parent: "f" * 64)
    if fault == "role": cmp["harness"].values[2]["results"]["secretgrp"] = "read"
    if fault == "template": cmp["harness"].values[3]["results"][0]["name"] = "Other"
    if fault == "template-kind": cmp["harness"].values[3]["results"][0]["field"][1]["name"] = "Other"
    if fault == "template-drift":
        handle = cmp["harness"].handle
        def changed_template(request):
            if len(cmp["harness"].requests) == 8:
                cmp["harness"].values[3]["results"][0]["field"][1]["name"] = "Other"
            return handle(request)
        cmp["harness"].handle = changed_template
    if fault == "api-http": cmp["harness"].fault = "status"
    if fault == "ca": (tmp_path / "ca.pem").write_bytes(b"Changed synthetic CA")
    if fault == "source": object.__setattr__(cmp["creator"]._config, "bearer_token", "other-token")
    if fault == "clock": cmp["harness"].now = True
    with pytest.raises(p.WindowsExecutionPreflightError): cmp["reader"].read_once()
    calls = list(cmp["target"].calls), len(cmp["harness"].requests), len(cmp["folder"].calls)
    with pytest.raises(p.WindowsExecutionPreflightError): cmp["reader"].read_once()
    assert calls == (cmp["target"].calls, len(cmp["harness"].requests), len(cmp["folder"].calls))
    assert cmp["target"].calls.count("POST") == len(cmp["writes"]) == 1


@pytest.mark.parametrize("fault", ["unsigned-target", "unsigned-folder", "folder-binding", "profile", "requester", "no-ca"])
def test_missing_original_ownership_or_wrong_binding_refuses_before_network(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path, monkeypatch)
    profile, kwargs = cmp["profile"], dict(cmp["kwargs"])
    if fault == "unsigned-target": (cmp["creator"]._directory / "create.verified.json").write_text("{}")
    if fault == "unsigned-folder":
        with cmp["workflow"]._connect() as connection:
            connection.execute("DELETE FROM v4_isolated_folder_creation_ownership")
    if fault == "folder-binding": cmp["workflow"]._binding = replace(cmp["workflow"]._binding, empty_inactive_policy=False)
    if fault == "profile": profile = replace(profile, folder_id=99)
    if fault == "requester": kwargs["requester_digest"] = "f" * 64
    if fault == "no-ca": object.__setattr__(cmp["creator"]._config, "ca_file", None)
    before = len(cmp["target"].calls), len(cmp["folder"].calls)
    with pytest.raises(p.WindowsExecutionPreflightError): p.WindowsExecutionOwnedDependencies(profile, **kwargs)
    assert before == (len(cmp["target"].calls), len(cmp["folder"].calls))
    assert not cmp["harness"].requests


def test_local_seal_drift_revokes_a_fresh_observation_without_renewing_reads(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    observed = cmp["reader"].read_once()
    before = len(cmp["target"].calls), len(cmp["folder"].calls), len(cmp["harness"].requests)
    (cmp["creator"]._directory / "create.verified.json").write_text("{}")
    with pytest.raises(p.WindowsExecutionPreflightError): cmp["reader"].check_current(observed)
    assert before == (len(cmp["target"].calls), len(cmp["folder"].calls), len(cmp["harness"].requests))


def test_native_target_privilege_omission_keeps_only_the_owned_dependency_observation(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch, privilege_metadata=False)
    assert "priv_acct" not in cmp["target"].created
    observed = cmp["reader"].read_once()
    cmp["reader"].check_current(observed)
    assert observed.target_creation_digest == cmp["creator"].load_creation_evidence().evidence_digest


def test_reader_clocks_enforce_their_own_windows_without_mixing_epochs(tmp_path, monkeypatch):
    cmp = setup(tmp_path, monkeypatch)
    reader = p.WindowsExecutionOwnedDependencies(cmp["profile"],
        **{**cmp["kwargs"], "clock": lambda: cmp["harness"].now + 500})
    observed = reader.read_once()
    reader.check_current(observed)
    assert observed.observed_at == 510 and observed.expires_at == 540
    assert reader._dependency.observed_at == 10


@pytest.mark.parametrize("fields", [{"q_ref":1}, {"q_static":True}, {"priv_acct":5},
    {"user-permission":[{"id":1, "user-name":[{"name":"other-owner"}], "permission":"owner"}]}])
def test_matching_original_seal_alone_does_not_qualify_a_broader_prerequisite(tmp_path, monkeypatch, fields):
    cmp = setup(tmp_path, monkeypatch, initial_target=fields)
    with pytest.raises(p.WindowsExecutionPreflightError): cmp["reader"].read_once()
    assert cmp["target"].calls.count("POST") == len(cmp["writes"]) == 1


@pytest.mark.parametrize("fault", ["expiry", "rollback", "closed", "foreign", "profile-drift"])
def test_current_observation_cannot_be_renewed_or_rebound(tmp_path, monkeypatch, fault):
    cmp = setup(tmp_path, monkeypatch)
    observed = cmp["reader"].read_once()
    before = len(cmp["target"].calls), len(cmp["folder"].calls), len(cmp["harness"].requests)
    if fault == "expiry": cmp["harness"].now = observed.expires_at
    if fault == "rollback": cmp["harness"].now -= 1
    if fault == "closed": cmp["reader"].close()
    if fault == "foreign": observed = replace(observed)
    if fault == "profile-drift": object.__setattr__(cmp["profile"], "private_nonce", "f" * 64)
    with pytest.raises(p.WindowsExecutionPreflightError): cmp["reader"].check_current(observed)
    assert before == (len(cmp["target"].calls), len(cmp["folder"].calls), len(cmp["harness"].requests))
