"""Real source projections and Owner/SSH joins over synthetic fixed transports."""

import copy
from dataclasses import replace
import hashlib
import json
import logging
import pickle
import ssl
from urllib.parse import quote

import httpx
import pytest

from fortipam_mcp import dlp_api_actor_guard as actor_module
from fortipam_mcp import secret_bulk_import_namespace_reader as namespace_module
from fortipam_mcp import secret_bulk_import_namespace_source as source
from test_dlp_api_actor_guard import ACTOR, Harness, _ACTOR, _envelope, _role
from test_secret_bulk_import_metadata import MATERIAL, response
from test_target_qualified_reference_reader import Peer, ROOT, SERIAL, frame

_CONTEXT = ROOT[:-2] + b" (database) #"
_NAMES = ("Visible A", "Visible B", "Hidden", "Visible A")


@pytest.mark.parametrize("fault", [None, "missing-ca", "api-profile-mismatch",
    "ca-before", "pin-before", "actor-before", "role-before", "owner-disabled", "owner-remote",
    "owner-wildcard", "owner-role", "owner-name", "owner-serial", "owner-build", "owner-extra-material",
    "owner-after", "api-size-missing", "api-filtered", "api-device", "api-envelope", "api-multiplicity",
    "ssh-drift", "ssh-device", "ssh-close", "ssh-pin-during", "api-drift", "api-revision",
    "api-size-drift", "ca-during", "actor-after", "expiry", "rollback", "http-close", "response-close",
    "foreign-observation", "pin-after", "ca-after", "ssh-config-after", "api-config-after",
    "clock-after", "clock-rollback-after", "replay", "closed"])
def test_same_owner_native_namespace_is_fresh_complete_and_never_association_authority(
        tmp_path, monkeypatch, caplog, fault):
    _exercise_namespace(tmp_path, monkeypatch, caplog, fault)


def _exercise_namespace(tmp_path, monkeypatch, caplog, fault, *, owner_name=ACTOR,
                        api_profile="super_admin"):
    role = _role()
    role.update(name=api_profile, secretgrp="read-write" if api_profile == "super_admin" else "custom")
    role["secretgrp-permission"]["secret-table"] = "read" if fault == "api-permission" else "read-write"
    actor = Harness(role)
    actor.binding = replace(actor.binding, expected_profile=api_profile, expected_serial=SERIAL.decode())
    user_path = "/api/v2/cmdb/system/api-user/" + ACTOR + "?format=name%7Caccprofile"
    role_path = "/api/v2/cmdb/system/accprofile/" + quote(api_profile, safe="") + "?format=" + quote("|".join(actor_module._ROLE_FIELDS), safe="")
    actor.bodies = {
        _ACTOR: _envelope("state", {"admin": {"name": ACTOR, "login_name": ACTOR,
            "guest_admin": False, "sponsored_group_name": ""}}, monitor=True, serial=SERIAL.decode()),
        user_path: _envelope("api-user", [{"name": ACTOR, "accprofile": api_profile}], serial=SERIAL.decode()),
        role_path: _envelope("accprofile", [role], serial=SERIAL.decode()),
    }
    if fault == "role-before":
        actor.bodies[role_path] = _envelope("accprofile", [{**role, "secretgrp": "read"}], serial=SERIAL.decode())
    binding = replace(actor.binding, expected_profile="other") if fault == "api-profile-mismatch" else actor.binding
    ca, known_hosts = tmp_path / "ca.pem", tmp_path / "known_hosts"
    ca.write_bytes(b"Synthetic public CA snapshot")
    known_hosts.write_bytes(b"Synthetic SSH host pin")
    known_hosts.chmod(0o600)
    config = source.SecretMetadataHttpTransportConfig(actor.config.base_url,
        actor.config.bearer_token, 5, None if fault == "missing-ca" else str(ca))
    ssh = source.TargetSshTransportConfig("synthetic.invalid", 22,
        owner_name, "synthetic-password", known_hosts, 10)
    trust = ssl.create_default_context()
    monkeypatch.setattr(actor_module, "_ssl_context", lambda _: trust)
    now, events, requests, clients, streams, cleared = [100.0], [], [], [], [], []
    peer = Peer()
    projections = [0]

    async def connect_ssh():
        events.append("ssh")
        peer.connected += 1
        return peer

    async def read_cli(process, command, prompt, deadline):
        if command == namespace_module.r._SERIAL and fault == "ssh-device":
            peer.commands.append(command)
            return frame(command, [b"Serial-Number: OTHER"])
        if command not in (namespace_module._NAMES, namespace_module._FOLDERS):
            return await peer.read(process, command, prompt, deadline)
        assert prompt == _CONTEXT
        peer.commands.append(command)
        if command == namespace_module._NAMES:
            projections[0] += 1
            names = tuple(reversed(_NAMES)) if fault == "ssh-drift" and projections[0] == 2 else _NAMES
            lines = [b'        set name "' + value.encode() + b'"' for value in names]
        else:
            lines = [b"        set folder " + str(value).encode() for value in (1, 2, 3, 1)]
        return frame(command, lines, prompt=_CONTEXT)

    async def dynamic(process, command, prompt, deadline):
        peer.commands.append(command)
        return _CONTEXT if command == "config secret database" else ROOT

    async def wait_closed():
        peer.waited += 1
        if fault == "ssh-close":
            raise OSError("synthetic private SSH close detail")
        if fault == "ssh-pin-during":
            known_hosts.write_bytes(b"Changed synthetic SSH host pin")
        if fault == "expiry":
            now[0] = 105.0
        if fault == "rollback":
            now[0] = 99.0

    def ssh_transport(actual):
        assert actual.username == owner_name and actual.host == ssh.host
        assert actual.known_hosts_file == known_hosts and actual.password == ssh.password
        assert 1 <= actual.timeout_seconds <= 5
        return peer

    peer._connection, peer.wait_closed = connect_ssh, wait_closed
    monkeypatch.setattr(namespace_module, "FortiPamTargetReferenceSshTransport", ssh_transport)
    monkeypatch.setattr(namespace_module, "_complete_pre_login", peer.login)
    monkeypatch.setattr(namespace_module, "_send_and_read", read_cli)
    monkeypatch.setattr(namespace_module, "_send_and_read_dynamic_prompt", dynamic)

    def connection(host, port, **options):
        assert options["context"] is trust and 0 < options["timeout"] <= 5
        options["timeout"] = 5
        result = actor.connect(host, port, **options)
        send = result.request

        def request(method, path, **values):
            events.append("actor")
            if fault == "actor-before" or fault == "actor-after" and len(actor.calls) == 3:
                actor.bodies[_ACTOR] = _envelope("state", {"admin": {"name": "different",
                    "login_name": "different", "guest_admin": False, "sponsored_group_name": ""}},
                    monitor=True, serial=SERIAL.decode())
            send(method, path, **values)

        result.request = request
        return result

    class Stream(httpx.SyncByteStream):
        def __init__(self, raw):
            self.raw, self.closed = raw, False
            streams.append(self)

        def __iter__(self):
            yield self.raw

        def close(self):
            self.closed = True
            if fault == "response-close":
                raise OSError("synthetic private response close detail")

    def handle(request):
        requests.append(request)
        database = request.url.path.endswith("/secret/database")
        events.append("database" if database else "owner")
        assert request.headers["authorization"] == "Bearer " + config.bearer_token
        assert request.headers["accept-encoding"] == "identity" and "cookie" not in request.headers
        assert request.headers["user-agent"] == "fortipam-mcp-bulk-import-namespace-source/1"
        if database:
            assert request.method == "POST" and request.content == source._BODY
            assert request.headers["x-http-method-override"] == "GET"
            assert str(request.url).endswith(source._COLLECTION + source._QUERY)
            payload = response()
            base = payload["results"][0]
            payload.update(serial=SERIAL.decode(), size=4, filtered_count=3, revision="revision")
            payload["results"] = [{**base, "id": i, "name": name,
                "permissions": {} if i == 3 else {"user": "owner" if i == 1 else "view"}}
                for i, name in enumerate(("Visible A", "Visible B", "Visible A"), 1)]
            if fault == "api-size-missing":
                del payload["size"]
            elif fault == "api-filtered":
                payload["filtered_count"] = 2
            elif fault == "api-device":
                payload["serial"] = "OTHER"
            elif fault == "api-envelope":
                payload.update(http_method="GET", status="success")
            elif fault == "api-multiplicity":
                payload["results"][0]["name"] = "Unobserved"
            elif len(requests) == 3:
                if fault == "api-drift":
                    payload["results"][1]["permissions"]["user"] = "owner"
                elif fault == "api-revision":
                    payload["revision"] = "different"
                elif fault == "api-size-drift":
                    payload["size"] = 5
            raw = json.dumps(payload).encode()
        else:
            assert request.method == "GET" and not request.content
            assert "x-http-method-override" not in request.headers
            assert request.url.path == "/api/v2/cmdb/system/admin/" + owner_name
            assert str(request.url).endswith(source._OWNER_QUERY)
            row = {"name": owner_name, "accprofile": "super_admin", "status": "enable",
                "remote-auth": "disable", "wildcard": "disable"}
            changes = {"owner-disabled": ("status", "disable"), "owner-remote": ("remote-auth", "enable"),
                "owner-wildcard": ("wildcard", "enable"), "owner-role": ("accprofile", "other"),
                "owner-name": ("name", "different"), "owner-extra-material": ("password", MATERIAL)}
            if fault in changes:
                key, value = changes[fault]
                row[key] = value
            if fault == "owner-after" and len(requests) == 4:
                row["status"] = "disable"
            if fault == "owner-name-after" and len(requests) == 4:
                row["name"] = ACTOR
            raw = _envelope("admin", [row], serial="OTHER" if fault == "owner-serial" else SERIAL.decode(),
                build=30 if fault == "owner-build" else 29)
        if fault == "ca-during" and len(requests) == 2:
            ca.write_bytes(b"Changed synthetic public CA")
        return httpx.Response(200, headers={"content-type": "application/json", "set-cookie": "blocked=value"},
            stream=Stream(raw))

    class Client(httpx.Client):
        def __exit__(self, *values):
            super().__exit__(*values)
            if fault == "http-close":
                raise OSError("synthetic private HTTP close detail")

    def client(**options):
        assert options["verify"] is trust
        assert options["trust_env"] is False and options["follow_redirects"] is False
        result = Client(transport=httpx.MockTransport(handle), **options)
        clients.append(result)
        return result

    wipe = source._zeroize_mutable

    def clear(raw):
        cleared.append(raw)
        wipe(raw)

    monkeypatch.setattr(source, "_zeroize_mutable", clear)
    loads = json.loads

    def selected_only(raw, *args, **options):
        assert MATERIAL not in str(raw)
        return loads(raw, *args, **options)

    monkeypatch.setattr(source.m.json, "loads", selected_only)
    caplog.set_level(logging.DEBUG)
    if fault == "missing-ca":
        with pytest.raises(source.BulkImportNamespaceSourceError, match="^" + source._ERROR + "$"):
            source.ImportSecretNamespaceSourceReader(config, ssh, binding,
                connection_factory=connection, client_factory=client, clock=lambda: now[0])
        assert not events and not peer.connected
        return
    reader = source.ImportSecretNamespaceSourceReader(config, ssh, binding,
        connection_factory=connection, client_factory=client, clock=lambda: now[0])
    assert not events and not peer.connected
    if fault == "ca-before":
        ca.write_bytes(b"Changed synthetic public CA")
    elif fault == "pin-before":
        known_hosts.write_bytes(b"Changed synthetic SSH host pin")
    post_read_faults = {"foreign-observation", "pin-after", "ca-after", "ssh-config-after", "owner-config-after", "api-config-after",
        "clock-after", "clock-rollback-after", "replay", "closed"}
    if fault is None or fault in post_read_faults:
        observed = reader.read_once()
        reader.check_current(observed)
        assert events == ["actor"] * 3 + ["owner", "database", "ssh", "database", "owner"] + ["actor"] * 3
        assert observed.namespace.names == tuple(sorted(_NAMES))
        assert observed.namespace.names.count("Visible A") == 2
        assert observed.api_view is observed.namespace.api_view
        assert (observed.api_view.size, observed.api_view.filtered_count, observed.api_view.revision) == (4, 3, "revision")
        assert tuple(row.permission for row in observed.api_view.rows) == ("owner", "view", None)
        assert (observed.observed_at, observed.expires_at) == (100.0, 105.0)
        assert observed.serial_digest == hashlib.sha256(SERIAL).hexdigest()
        assert observed.source_context_digest == source._api_source_context(config.base_url,
            hashlib.sha256(config.bearer_token.encode()).hexdigest(), hashlib.sha256(ca.read_bytes()).hexdigest(),
            observed.serial_digest)
        assert observed.actor_evidence_digest == reader._guard._before.evidence_digest
        assert observed.ssh_source_digest == reader._ssh_snapshot() and len(observed.owner_evidence_digest) == 64
        assert not any(hasattr(observed, field) for field in ("coverage", "can_associate", "catalog"))
        for item in (reader, observed):
            assert "Visible" not in repr(item) and "synthetic" not in repr(item).lower()
            for operation in (copy.copy, copy.deepcopy, pickle.dumps):
                with pytest.raises(RuntimeError):
                    operation(item)
        if fault == "foreign-observation":
            with pytest.raises(source.BulkImportNamespaceSourceError):
                reader.check_current(replace(observed))
        elif fault == "pin-after":
            known_hosts.write_bytes(b"Changed synthetic SSH host pin")
        elif fault == "ca-after":
            ca.write_bytes(b"Changed synthetic public CA")
        elif fault == "ssh-config-after":
            object.__setattr__(ssh, "host", "different.invalid")
        elif fault == "owner-config-after":
            object.__setattr__(ssh, "username", ACTOR)
        elif fault == "api-config-after":
            object.__setattr__(config, "bearer_token", "different-token")
        elif fault == "clock-after":
            now[0] = 105.0
        elif fault == "clock-rollback-after":
            now[0] = 99.0
        elif fault == "replay":
            with pytest.raises(source.BulkImportNamespaceSourceError):
                reader.read_once()
        elif fault == "closed":
            reader.close()
        if fault is not None:
            with pytest.raises(source.BulkImportNamespaceSourceError):
                reader.check_current(observed)
    else:
        with pytest.raises(source.BulkImportNamespaceSourceError) as caught:
            reader.read_once()
        assert str(caught.value) == source._ERROR and caught.value.__suppress_context__
        assert reader._current is None
        if fault == "api-permission":
            assert events == ["actor"] * 3 and not requests and not peer.connected
    before = tuple(events)
    with pytest.raises(source.BulkImportNamespaceSourceError):
        reader.read_once()
    assert tuple(events) == before
    actor.disposed()
    assert all(client.is_closed and not client.cookies for client in clients)
    assert all(stream.closed for stream in streams) and all(not any(raw) for raw in cleared)
    if peer.connected:
        assert (peer.closed, peer.waited, peer.disconnected) == (1, 1, 1)
    assert MATERIAL not in caplog.text and "synthetic-token" not in caplog.text and "synthetic-password" not in caplog.text
    reader.close()
    assert tuple(events) == before


def test_separate_custom_api_actor_and_privileged_ssh_owner_remain_independently_bound(
        tmp_path, monkeypatch, caplog):
    for fault in ("owner-config-after", "owner-name-after", "actor-after", "api-permission"):
        scenario = tmp_path / fault
        scenario.mkdir()
        with monkeypatch.context() as scoped:
            _exercise_namespace(scenario, scoped, caplog, fault,
                owner_name="synthetic-ssh-owner", api_profile="Synthetic Import Role")
