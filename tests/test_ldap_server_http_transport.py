"""Synthetic fixed HTTP/C3/persistent-ledger joins; no live endpoints."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from fortipam_mcp.ldap_server_contract import LdapServerCandidateError, LdapServerCreateBinding, LdapServerCreateOutcome
from fortipam_mcp.ldap_server_http_transport import FortiPamLdapServerHttpTransport
from fortipam_mcp.ldap_server_material_provider import LdapServerMaterialProvider, LdapServerLeaseTransport
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from v4_planning.material_persistence import PersistentMaterialUseStateStore
from v4_planning.material_provider import MaterialBindingStatus, MaterialLeaseRequest, MaterialProviderClass, MaterialPurpose
from v4_planning.material_runtime import MaterialLeaseCoordinator, MaterialRuntimeOutcome

from test_ldap_server_projection import SERIAL, binding as projection_binding, default_row, envelope, schema_document

PASSWORD = b'synthetic!password7'
DER = b"synthetic-public-certificate"
PEM = b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(DER) + b"\n-----END CERTIFICATE-----\n"
TABLE = "/api/v2/cmdb/user/ldap"


def binding(pin: str | None = None) -> LdapServerCreateBinding:
    original = projection_binding()
    return LdapServerCreateBinding(original.name, original.server, original.dn, original.ca_name,
        original.username, original.private_nonce, pin or hashlib.sha256(DER).hexdigest())


def request() -> MaterialLeaseRequest:
    return MaterialLeaseRequest("ldap-server-create", "1.0.0", "1"*64, "2"*64, "3"*64, "4"*64, "5"*64,
        MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE, MaterialPurpose.INITIAL_ONBOARDING, 100, 160)


class Response:
    def __init__(self, document: object, status: int = 200, certificate: bool = False):
        self.status, self.certificate = status, certificate
        self.content = io.BytesIO(PEM if certificate else json.dumps(document).encode())
        self.closed = False

    def readinto(self, value: memoryview) -> int:
        return self.content.readinto(value)

    def getheader(self, name: str, default: str = "") -> str:
        return "application/x-pem-file" if self.certificate else "application/json"

    def close(self) -> None:
        self.closed = True


class Peer:
    def __init__(self) -> None:
        self.binding = binding()
        self.defaults = default_row()
        self.row: dict[str, Any] | None = None
        self.connections: list[Connection] = []
        self.responses: list[Response] = []
        self.posts = self.deletes = self.binds = 0
        self.lost_post_ack = self.first_detail_failure = self.lost_delete_ack = False
        self.after_info: Any = None
        self.on_connect: Any = None

    def connection(self, host: str, port: int, **kwargs: Any) -> Connection:
        assert host == "pam.example" and port == 443 and kwargs["context"].check_hostname
        result = Connection(self)
        self.connections.append(result)
        return result

    def handle(self, method: str, url: str, body: memoryview | None) -> Response:
        parsed = urlsplit(url)
        query = parse_qs(parsed.query)
        if parsed.path.startswith("/api/v2/monitor/system/certificate/download/"):
            assert query == {"scope": ["vdom"], "type": ["remote-ca"]}
            result = Response(None, certificate=True)
        elif parsed.path == "/api/v2/monitor/service/ldap/query":
            self.binds += 1
            value = json.loads(query["json"][0])
            assert value["info_only"] == 1 and value["mkey"] is None
            assert value["ldap"]["password"].encode() == PASSWORD
            assert value["ldap"]["secure"] == 2 and value["ldap"]["server-identity-check"] == 1
            result = Response(envelope(results={"schema": {"objectClasses": ["synthetic"],
                "attributeTypes": {"synthetic": {}}}, "rootdse": {},
                "general": {"configured_dn": self.binding.dn, "server_type": "synthetic"}}))
            if self.after_info:
                self.after_info()
        elif method == "POST":
            assert parsed.path == TABLE and body is not None
            self.posts += 1
            submitted = json.loads(bytes(body))
            assert submitted["password"].encode() == PASSWORD and len(submitted) == 18
            del submitted["password"]
            self.row = self.defaults | submitted
            self.row.update(q_ref=0, q_origin_key=self.binding.name)
            self.row["group-object-filter"] = self.defaults["group-object-filter"]
            if self.lost_post_ack:
                raise TimeoutError("synthetic response lost")
            result = Response(envelope(http_method="POST", mkey=self.binding.name))
        elif method == "DELETE":
            assert parsed.path == TABLE + "/" + self.binding.name and body is None
            self.deletes += 1
            self.row = None
            if self.lost_delete_ack:
                raise TimeoutError("synthetic response lost")
            result = Response(envelope(http_method="DELETE", mkey=self.binding.name))
        elif query.get("action") == ["schema"]:
            result = Response(schema_document())
        elif query.get("action") == ["default"]:
            result = Response(envelope(action="default", results=self.defaults))
        elif query.get("format") == ["name"]:
            result = Response(envelope(results=[] if self.row is None else [{"name": self.binding.name}]))
        elif parsed.path == TABLE + "/" + self.binding.name:
            if self.row is None:
                result = Response(envelope(status="error", http_status=404), 404)
            elif self.first_detail_failure:
                self.first_detail_failure = False
                raise TimeoutError("synthetic detail lost")
            else:
                result = Response(envelope(results=[self.row], mkey=self.binding.name))
        else:
            raise AssertionError("Unexpected fixed route")
        self.responses.append(result)
        return result


class Connection:
    def __init__(self, peer: Peer):
        self.peer, self.closed = peer, False
        self.response: Response | None = None

    def connect(self) -> None:
        if self.peer.on_connect:
            self.peer.on_connect()

    def request(self, method: str, url: str, body: memoryview | None, headers: dict[str, str]) -> None:
        assert headers["Accept-Encoding"] == "identity"
        assert headers["User-Agent"] == "fortipam-mcp-v4-ldap-server/1"
        self.response = self.peer.handle(method, url, body)

    def getresponse(self) -> Response:
        assert self.response is not None
        return self.response

    def close(self) -> None:
        self.closed = True


class Loader:
    def __init__(self, selected: LdapServerCreateBinding):
        self.binding, self.loads = selected, 0
        self.buffers: tuple[bytearray, bytearray] | None = None

    def validate_prebound(self) -> MaterialBindingStatus:
        return MaterialBindingStatus.AVAILABLE

    def load_secret_create_material_once(self) -> tuple[bytearray, bytearray]:
        self.loads += 1
        self.buffers = bytearray(self.binding.username.encode()), bytearray(PASSWORD)
        return self.buffers


def transport(state: Path, peer: Peer, now: list[int], *, expected: str | None = None,
              execute: bool = False, recover: bool = False) -> FortiPamLdapServerHttpTransport:
    return FortiPamLdapServerHttpTransport(
        SecretMetadataHttpTransportConfig("https://pam.example", "synthetic-token", 5, None),
        peer.binding, expected_serial=SERIAL, state_directory=state,
        execution_request=request() if execute else None, expected_current_digest=expected,
        execution_enabled=execute, recovery_enabled=recover, clock=lambda: now[0],
        connection_factory=peer.connection)


def setup(tmp_path: Path) -> tuple[FortiPamLdapServerHttpTransport, Peer, Path, list[int]]:
    state = tmp_path / "transport"
    state.mkdir(mode=0o700)
    peer, now = Peer(), [100]
    return transport(state, peer, now), peer, state, now


def dispatch(client: FortiPamLdapServerHttpTransport, peer: Peer) -> LdapServerCreateOutcome:
    user, password = bytearray(peer.binding.username.encode()), bytearray(PASSWORD)
    with memoryview(user) as username, memoryview(password) as value:
        return client._create_and_verify_with_material(peer.binding, request(), username, value)


def test_http_c3_durable_ledger_roundtrip_and_restart(tmp_path: Path) -> None:
    client, peer, state, now = setup(tmp_path)
    preview = client.inspect_create()
    executing = transport(state, peer, now, expected=preview.state_digest, execute=True)
    material_dir = tmp_path / "material"
    material_dir.mkdir(mode=0o700)
    key = material_dir / "key"
    key.write_bytes(os.urandom(32))
    key.chmod(0o600)
    loader = Loader(peer.binding)
    store = PersistentMaterialUseStateStore(material_dir / "ledger.sqlite", key)
    provider = LdapServerMaterialProvider(loader, binding=peer.binding, request=request(), clock=lambda: now[0])
    bridge = LdapServerLeaseTransport(provider, executing)
    outcome = MaterialLeaseCoordinator(provider, store).execute_once(peer.binding, request(), bridge.consume, now_epoch=100)
    assert outcome is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED
    assert not (state / "create-diagnostic.json").exists()
    assert loader.loads == 1 and loader.buffers is not None and not any(any(value) for value in loader.buffers)
    reloaded = Loader(peer.binding)
    new_provider = LdapServerMaterialProvider(reloaded, binding=peer.binding, request=request(), clock=lambda: now[0])
    restarted = MaterialLeaseCoordinator(new_provider, PersistentMaterialUseStateStore(material_dir / "ledger.sqlite", key))
    replay = restarted.execute_once(peer.binding, request(), LdapServerLeaseTransport(new_provider, executing).consume, now_epoch=100)
    assert replay is MaterialRuntimeOutcome.VERIFIED_AND_RELEASED and reloaded.loads == 0
    recovery = transport(state, peer, now, recover=True)
    assert recovery.inspect_owned() and recovery.delete_owned() and recovery.inspect_deleted()
    assert (peer.binds, peer.posts, peer.deletes) == (1, 1, 1)
    assert all(item.closed for item in peer.connections + peer.responses)
    with pytest.raises(LdapServerCandidateError):
        recovery.delete_owned()
    assert peer.deletes == 1


@pytest.mark.parametrize(("failure", "stage", "status", "entered", "posts"), [
    ("info_projection", "directory_test", 200, False, 0),
    ("info_status", "directory_test", 503, False, 0),
    ("refresh", "refresh", None, False, 0),
    ("post_ack", "post", None, True, 1),
    ("readback", "readback", None, True, 1),
])
@pytest.mark.parametrize("diagnostic_write_fails", [False, True])
def test_create_failure_diagnostic_is_closed_and_preserves_no_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str, stage: str,
    status: int | None, entered: bool, posts: int, diagnostic_write_fails: bool,
) -> None:
    client, peer, state, now = setup(tmp_path)
    digest = client.inspect_create().state_digest
    raw_failure = " ".join((PASSWORD.decode(), peer.binding.username,
                            peer.binding.name, "synthetic-token", "?json=private"))
    original_handle = Peer.handle

    def failing_handle(self: Peer, method: str, url: str, body: memoryview | None) -> Response:
        try:
            result = original_handle(self, method, url, body)
        except TimeoutError:
            raise TimeoutError(raw_failure) from None
        if urlsplit(url).path == "/api/v2/monitor/service/ldap/query":
            if failure == "info_projection":
                result.content = io.BytesIO(json.dumps({"raw": raw_failure}).encode())
            elif failure == "info_status":
                result.status = 503
        return result

    monkeypatch.setattr(Peer, "handle", failing_handle)
    peer.lost_post_ack = failure == "post_ack"
    peer.first_detail_failure = failure == "readback"
    if failure == "refresh":
        peer.after_info = lambda: peer.defaults.__setitem__("secondary-server", "changed")
    original_write = FortiPamLdapServerHttpTransport._write_once

    def failing_diagnostic(self: FortiPamLdapServerHttpTransport, name: str, value: object) -> None:
        if name == "create-diagnostic.json" and diagnostic_write_fails:
            raise OSError(raw_failure)
        original_write(self, name, value)

    monkeypatch.setattr(FortiPamLdapServerHttpTransport, "_write_once", failing_diagnostic)
    executing = transport(state, peer, now, expected=digest, execute=True)
    outcome = dispatch(executing, peer)
    assert outcome is LdapServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == posts and peer.binds == 1
    assert not (state / "created.json").exists()
    claim = (state / "create.claim.json").read_bytes()
    diagnostic = state / "create-diagnostic.json"
    if diagnostic_write_fails:
        assert not diagnostic.exists()
    else:
        rendered = diagnostic.read_text()
        assert json.loads(rendered) == {
            "stage": stage, "http_status": status, "post_stage_entered": entered,
        }
        assert diagnostic.stat().st_mode & 0o777 == 0o600
        for protected in (PASSWORD.decode(), peer.binding.username, peer.binding.name,
                          "synthetic-token", "?json=", raw_failure):
            assert protected not in rendered and protected not in repr(outcome)
    connections = len(peer.connections)
    restarted = transport(state, peer, now, expected=digest, execute=True)
    assert dispatch(restarted, peer) is LdapServerCreateOutcome.RECONCILIATION_REQUIRED
    assert len(peer.connections) == connections and peer.posts == posts and peer.binds == 1
    assert (state / "create.claim.json").read_bytes() == claim
    if diagnostic_write_fails:
        assert not diagnostic.exists()
    else:
        assert diagnostic.read_text() == rendered


@pytest.mark.parametrize("failure", ["post_ack", "first_detail"])
def test_post_uncertainty_cannot_retry_and_requires_ack_for_adoption(tmp_path: Path, failure: str) -> None:
    client, peer, state, now = setup(tmp_path)
    digest = client.inspect_create().state_digest
    peer.lost_post_ack = failure == "post_ack"
    peer.first_detail_failure = failure == "first_detail"
    executing = transport(state, peer, now, expected=digest, execute=True)
    assert dispatch(executing, peer) is LdapServerCreateOutcome.RECONCILIATION_REQUIRED
    restarted = transport(state, peer, now, expected=digest, execute=True, recover=True)
    assert dispatch(restarted, peer) is LdapServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == 1 and peer.binds == 1
    if failure == "post_ack":
        with pytest.raises(LdapServerCandidateError):
            restarted.inspect_owned()
        with pytest.raises(LdapServerCandidateError):
            restarted.delete_owned()
        assert peer.deletes == 0
    else:
        assert restarted.inspect_owned() and restarted.delete_owned()
        assert peer.deletes == 1


def test_delete_uncertainty_and_opaque_or_reference_drift(tmp_path: Path) -> None:
    client, peer, state, now = setup(tmp_path)
    digest = client.inspect_create().state_digest
    executing = transport(state, peer, now, expected=digest, execute=True, recover=True)
    assert dispatch(executing, peer) is LdapServerCreateOutcome.VERIFIED_CREATED
    assert peer.row is not None
    for key, changed in (("password", "changed-mask"), ("q_ref", 1), ("obtain-user-info", "changed-extra")):
        original = peer.row[key]
        peer.row[key] = changed
        with pytest.raises(LdapServerCandidateError):
            executing.delete_owned()
        assert peer.deletes == 0 and not (state / "delete.claim.json").exists()
        peer.row[key] = original
    peer.lost_delete_ack = True
    with pytest.raises(LdapServerCandidateError):
        executing.delete_owned()
    assert executing.inspect_deleted()
    with pytest.raises(LdapServerCandidateError):
        executing.delete_owned()
    assert peer.deletes == 1


@pytest.mark.parametrize("failure", ["gate", "source_drift", "ca_pin", "expiry", "rollback", "tls_expiry", "fsync_expiry"])
def test_final_dispatch_guards(tmp_path: Path, failure: str, monkeypatch: pytest.MonkeyPatch) -> None:
    client, peer, state, now = setup(tmp_path)
    digest = client.inspect_create().state_digest
    if failure == "source_drift":
        peer.defaults["secondary-server"] = "changed"
    if failure == "ca_pin":
        peer.binding = binding("b"*64)
    if failure in {"expiry", "rollback"}:
        peer.after_info = lambda: now.__setitem__(0, 160 if failure == "expiry" else 99)
    if failure == "tls_expiry":
        peer.on_connect = lambda: now.__setitem__(0, 160)
    executing = transport(state, peer, now, expected=digest, execute=failure != "gate")
    if failure == "fsync_expiry":
        original_write = FortiPamLdapServerHttpTransport._write_once
        def late_claim(self: FortiPamLdapServerHttpTransport, name: str, value: object) -> None:
            original_write(self, name, value)
            if name == "create.claim.json":
                now[0] = 160
        monkeypatch.setattr(FortiPamLdapServerHttpTransport, "_write_once", late_claim)
    assert dispatch(executing, peer) is LdapServerCreateOutcome.RECONCILIATION_REQUIRED
    assert peer.posts == 0
    assert peer.binds == (1 if failure in {"expiry", "rollback"} else 0)


def test_partial_state_and_opaque_binding_refuse_reuse(tmp_path: Path) -> None:
    client, peer, state, now = setup(tmp_path)
    (state / "created.json").write_text("{}")
    with pytest.raises(LdapServerCandidateError):
        client.inspect_create()
    import copy
    import dataclasses
    from v4_planning.material_provider import MaterialAccessDenied
    with pytest.raises(MaterialAccessDenied):
        copy.copy(peer.binding)
    with pytest.raises(TypeError):
        dataclasses.asdict(peer.binding)  # type: ignore[call-overload]
    with pytest.raises(LdapServerCandidateError):
        del peer.binding.username
