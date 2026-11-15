"""Fixed Job C/P/E sources use actual Owner HTTP and complete CLI projections."""
from dataclasses import replace
import json

import httpx
import pytest

from fortipam_mcp import job_namespace_ssh_reader as namespace
from fortipam_mcp import job_definition_reference_reader as references
from fortipam_mcp.job_definition_sources import JobDefinitionSources, JobDefinitionSourceError
from fortipam_mcp.job_definition_detail_reader import JobDefinitionDetailReader
from fortipam_mcp.job_definition_projection import JobDefinitionExpectation
from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig, FortiPamSecretMetadataHttpTransport, SYSTEM_STATUS_PATH,
)
from fortipam_mcp.target_ssh_transport import TargetSshTransportConfig
from test_job_definition_detail_reader import _body, SERIAL, ACTOR
from test_job_definition_http_transport import SOURCE, TARGET, _source
from test_job_namespace_ssh_reader import JobPeer, names_frame
from test_job_definition_reference_reader import Peer as ReferencePeer

CANDIDATE = "mcp-v4-bp008-job-20261022-r31"


def envelope(results, *, path="secret", name="job", method="GET", status="success", **extra):
    return dict(version="v7.0.0", build=29, http_status=200, http_method=method,
        status=status, serial=SERIAL, vdom="root", path=path, name=name, results=results, **extra)


class Api:
    def __init__(self):
        self.active = self.present = False
        self.failure = None
        self.clients = []
        self.calls = []
        self.reads = {}
        self.now = 100.0
        self.secret_reads = 0

    def factory(self, **kwargs):
        client = httpx.Client(**kwargs, transport=httpx.MockTransport(self.respond))
        self.clients.append(client)
        return client

    def job(self, name):
        row = {key: value for key, value in _body().items() if key != "$originalName"}
        row.update(name=name, **{"q_origin_key": name, "approval-status": "approved", "max-timeout": 0,
            "q_ref": 0, "q_static": False, "execution-time-start": "native-not-started",
            "execution-time-end": "native-not-started", "result-txt": "",
            "opaque": {"password": "SYNTHETIC_NEVER_DECODE"}})
        if name == SOURCE:
            row.update(_source())
        return row

    def respond(self, request):
        path = request.url.path
        bearer = "authorization" in request.headers
        self.calls.append((request.method, path, bearer))
        if path == "/remote/login": return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            self.active = True
            return httpx.Response(303, headers={"location": "/", "set-cookie": 'ccsrftoken="synthetic-csrf"; Secure; Path=/'})
        if path == "/": return httpx.Response(200)
        if path == "/logout":
            self.active = self.failure == "logout"
            return httpx.Response(200)
        if not bearer and not self.active: return httpx.Response(401)
        if path == SYSTEM_STATUS_PATH: return httpx.Response(200, json=dict(version="v7.0.0", build=29))
        if path == "/api/v2/monitor/web-ui/state":
            name = "adminapi" if bearer else ACTOR
            role = "job-role" if bearer else "super_admin"
            admin = dict(name=name, login_name=name, guest_admin=False, sponsored_group_name="", global_admin=True,
                super_admin=not bearer, profile={"name": role})
            if self.failure == "owner" and not bearer: admin["super_admin"] = False
            if self.failure == "writer" and bearer: admin["login_name"] = "foreign-api"
            value = envelope(dict(admin=admin, vdom_mode="on" if self.failure == "vdom" else "",
                maintenance_mode={"mode": "enable" if self.failure == "maintenance" else "disable"}), path="web-ui", name="state")
        elif path == "/api/v2/cmdb/system/api-user/adminapi":
            value = envelope([dict(name="adminapi", accprofile="other" if self.failure == "api-user" else "job-role")], path="system", name="api-user")
        elif path == "/api/v2/cmdb/system/accprofile/job-role":
            value = envelope([dict(name="job-role", secretgrp="custom", **{"secretgrp-permission": {
                "secret-job": "read" if self.failure == "role" else "read-write"}})], path="system", name="accprofile")
        elif path == "/api/v2/cmdb/system/admin/" + ACTOR:
            value = envelope([dict(name=ACTOR, accprofile="super_admin", status="enable", **{"remote-auth": "disable", "wildcard": "disable"})], path="system", name="admin")
        elif path == "/api/v2/cmdb/secret/database/999":
            self.secret_reads += 1
            assert not bearer and set(request.url.params["format"].split("|")) == {
                "id", "folder", "template", "need-approval-job", "approval-profile"}
            row = {"id": 998 if self.failure == "secret-id" else 999, "folder": 17, "template": "Windows Machine",
                "need-approval-job": "enable" if self.failure == "secret-approval" else "disable", "approval-profile": "",
                "$native-ui-metadata": {"unselected": "SYNTHETIC_NEVER_DECODE"},
                "field": [{"name": "Password", "value": "SYNTHETIC_NEVER_DECODE"}]}
            if self.failure == "secret-drift" and self.secret_reads == 2: row["template"] = "Changed template"
            value = envelope([row], name="database", status="OK")
        elif path in ("/api/v2/cmdb/secret/folder/17", "/api/v2/cmdb/secret/folder/8"):
            identifier = int(path.rsplit("/", 1)[1])
            row = {"id": identifier, "parent-folder": 8 if identifier == 17 else 0,
                "inherit-policy": "enable" if identifier == 17 else "disable", "secret-policy": "job-safe"}
            if self.failure == "secret-cycle" and identifier == 17: row["parent-folder"] = 17
            if self.failure == "missing-policy" and identifier == 8: row["inherit-policy"] = "enable"
            value = envelope([row], name="folder", status="OK")
        elif path == "/api/v2/cmdb/secret/policy/job-safe":
            flag = "enable" if self.failure == "forced-approval" else "not-set"
            value = envelope([{"name": "job-safe", "need-approval-job": flag}], name="policy")
        elif path == "/api/v2/cmdb/secret/job" and request.url.params.get("action") == "default":
            row = {key: value for key, value in _source().items() if key != "approval-status"}
            row.update({"max-timeout": 2 if self.failure == "default-timeout" else 0, "script": ""})
            value = envelope([row], action="default")
        elif path == "/api/v2/cmdb/secret/job":
            assert request.method == "POST" and request.headers["X-HTTP-Method-Override"] == "GET"
            assert request.headers["X-CSRFTOKEN"] == "synthetic-csrf" and request.content == b'{"json_filter":[]}'
            rows = [self.job(SOURCE), self.job(TARGET)] + ([self.job(CANDIDATE)] if self.present else [])
            for row in rows:
                row.update({"execution-time-start": 1 if self.failure == "started" else 0, "execution-time-end": 0})
            value = envelope(rows, method="POST", status="OK")
        else:
            prefix = "/api/v2/cmdb/secret/job/"
            assert path.startswith(prefix)
            name = path.removeprefix(prefix)
            assert name in (SOURCE, TARGET, CANDIDATE)
            assert name != CANDIDATE or self.present
            row = self.job(name)
            self.reads[name] = self.reads.get(name, 0) + 1
            if self.failure == "clone-source" and name == SOURCE: row["script"] = "UNQUALIFIED_SCRIPT"
            if self.failure == "full-anchor-drift" and name == TARGET and self.reads[name] == 2: row["opaque"] = {"changed": True}
            if self.failure == "candidate-ref" and name == CANDIDATE: row["q_ref"] = 1
            value = envelope([row], mkey=name)
        return httpx.Response(200, stream=httpx.ByteStream(json.dumps(value).encode()), headers={"content-type": "application/json"})


def make(tmp_path, monkeypatch):
    api = Api()
    config = SecretMetadataHttpTransportConfig("https://pam.example.test", "synthetic-token", 30, None)
    owner = OwnerSessionMetadataTransport(config, owner_name=ACTOR, credentials=lambda: (ACTOR, "synthetic-password"),
        folder_path="JobRead", secret_name="JobRead", target_name="JobRead",
        witness=FortiPamSecretMetadataHttpTransport(config), client_factory=api.factory, clock=lambda: api.now)
    def detail(name):
        body = dict(_body(), name=name)
        return JobDefinitionDetailReader(owner, expected_serial=SERIAL,
            expected=JobDefinitionExpectation(name, "adminapi", 999, "echo BP008_JOB_OK"),
            expected_create_body=body, expected_max_timeout=0)
    hosts = tmp_path / "known_hosts"
    hosts.write_text("Synthetic pinned SSH peer"); hosts.chmod(0o600)
    ssh = TargetSshTransportConfig("pam.example.test", 22, ACTOR, "synthetic-password", hosts, 30)
    peers = []
    def factory(config):
        peer = JobPeer(); peer._config = config
        peer.serial = namespace._SERIAL_COMMAND.encode() + b"\r\r\nSerial-Number: " + SERIAL.encode() + b"\r\n" + peer.root
        peer.names = names_frame((SOURCE, TARGET) + ((CANDIDATE,) if api.present else ()))
        peers.append(peer)
        return peer
    monkeypatch.setattr(namespace, "FortiPamTargetReferenceSshTransport", factory)
    async def read(process, command, prompt, deadline): return await process.read(process, command, prompt, deadline)
    async def dynamic(process, command, prompt, deadline): return await process.dynamic(process, command, prompt, deadline)
    async def close(process): return await process.close(process)
    monkeypatch.setattr(namespace, "_send_and_read", read)
    monkeypatch.setattr(namespace, "_send_and_read_dynamic_prompt", dynamic)
    monkeypatch.setattr(namespace, "_close_cli", close)
    def reference_factory(config):
        peer = ReferencePeer(); peer._config = config
        peer.serial = namespace._SERIAL_COMMAND.encode() + b"\r\r\nSerial-Number: " + SERIAL.encode() + b"\r\n" + peer.root
        if api.failure == "reference-nonzero": peer.failure = CANDIDATE
        peers.append(peer)
        return peer
    monkeypatch.setattr(references, "FortiPamTargetReferenceSshTransport", reference_factory)
    monkeypatch.setattr(references, "_send_and_read", read)
    monkeypatch.setattr(references, "_close_cli", close)
    candidate, anchor = detail(CANDIDATE), detail(TARGET)
    source = JobDefinitionSources(candidate=candidate, anchor=anchor, ssh=ssh,
        client_factory=api.factory, clock=lambda: api.now)
    return source, api, peers, hosts


@pytest.mark.parametrize("present", [False, True])
def test_fixed_role_pristine_defaults_and_global_namespace_join_without_mutation(tmp_path, monkeypatch, present):
    source, api, peers, _ = make(tmp_path, monkeypatch)
    api.present = present
    observation = source.observe_candidate_presence() if present else source.observe_absence()
    source.check_current(observation)
    assert observation.absent is not present and (observation.state_digest is not None) is present
    assert observation.job_count == 2 + int(present) and source.logout_verified
    assert all(peer.closed == peer.connection_closed for peer in peers)
    assert all(client.is_closed and not client.cookies for client in api.clients)
    assert not any(method in ("PUT", "DELETE") for method, _, _ in api.calls)
    assert not hasattr(source, "execute") and not hasattr(source, "issue")
    assert "adminapi" not in repr(observation) and CANDIDATE not in repr(observation)
    source.close()
    with pytest.raises(JobDefinitionSourceError): source.check_current(observation)


@pytest.mark.parametrize("fault", ["role", "writer", "api-user", "owner", "vdom", "maintenance", "clone-source",
    "default-timeout", "started", "full-anchor-drift", "candidate-ref", "logout", "secret-id", "secret-approval",
    "forced-approval", "secret-cycle", "missing-policy", "secret-drift", "reference-nonzero"])
def test_incomplete_current_state_never_qualifies_and_cannot_retry(tmp_path, monkeypatch, fault):
    source, api, peers, _ = make(tmp_path, monkeypatch)
    api.failure, api.present = fault, fault == "candidate-ref"
    with pytest.raises(JobDefinitionSourceError):
        source.observe_candidate_presence() if api.present else source.observe_absence()
    before = len(api.calls), len(peers)
    with pytest.raises(JobDefinitionSourceError): source.observe_absence()
    assert before == (len(api.calls), len(peers)) and source._current is None and not source._names
    assert all(client.is_closed for client in api.clients)
    source.close()


def test_secret_fields_are_redacted_before_any_generic_value_decoder(tmp_path, monkeypatch):
    source, api, peers, _ = make(tmp_path, monkeypatch)
    loads = json.loads
    def metadata_only(raw, *args, **kwargs):
        data = raw.encode() if isinstance(raw, str) else bytes(raw)
        assert b"SYNTHETIC_NEVER_DECODE" not in data
        return loads(raw, *args, **kwargs)
    monkeypatch.setattr(json, "loads", metadata_only)
    observation = source.observe_absence()
    source.check_current(observation)
    assert api.secret_reads == 2 and source.logout_verified
    assert not any("password" in path or "credential" in path for _, path, _ in api.calls)
    source.close()


@pytest.mark.parametrize("fault", ["copy", "tamper", "names", "hosts", "timeout", "expiry"])
def test_current_source_observation_is_identity_sealed_and_fresh(tmp_path, monkeypatch, fault):
    source, api, peers, hosts = make(tmp_path, monkeypatch)
    observation = source.observe_absence()
    if fault == "copy": observation = replace(observation)
    if fault == "tamper": object.__setattr__(observation, "dependency_digest", "f" * 64)
    if fault == "names": source._names = (SOURCE, TARGET, "hidden")
    if fault == "hosts": hosts.write_text("Changed source")
    if fault == "timeout": source._candidate._expected_tokens["max-timeout"] = b"1"
    if fault == "expiry": api.now = observation.expires_at
    before = len(api.calls), len(peers)
    with pytest.raises(JobDefinitionSourceError): source.check_current(observation)
    assert before == (len(api.calls), len(peers)) and source._failed
    source.close()
