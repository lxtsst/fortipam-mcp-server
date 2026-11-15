"""Combined native CRL, durable ownership, default startup and OAuth/MCP checks."""
import asyncio
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import time
from urllib.parse import parse_qs

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import httpx
import pytest
from starlette.testclient import TestClient

from fortipam_mcp.crl_import_transport import COLLECTION, IMPORT, SELECTOR, NativeCrlTransport, _TYPES
from fortipam_mcp.crl_import_workflow import NativeCrlWorkflow
from fortipam_mcp.crl_import_mcp_action import NativeCrlMcpAction
from fortipam_mcp.crl_import_runtime import CONTRACT as STARTUP, PREFIX, build_crl_candidate
from fortipam_mcp.http_server import HttpConfigurationError, create_http_app
from fortipam_mcp.local_oauth import LocalOAuthProvider
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from fortipam_mcp.owner_collector_runtime import PREFIX as OWNER_PREFIX
from fortipam_mcp.runtime_profile import RuntimeProfile
from fortipam_mcp.secret_metadata_http_transport import ENV_PREFIX
from fortipam_mcp.v4_plan_runtime import planning_principal_from_access_token
from test_ldap_server_mcp_action import _settings, _login, _call

IDENTITY = {"requester_digest": "1" * 64, "transport_digest": "2" * 64}
NONCE = "0123456789abcdef"
NAME = "CRL_" + NONCE
SERIAL = "synthetic-crl-appliance"
ACTOR = "synthetic-crl-owner"


def frame(result, *, name="crl", path="vpn.certificate", method="GET", **extra):
    return dict(http_method=method, status="success", http_status=200, version="v7.0.0",
        build=29, serial=SERIAL, vdom="root", path=path, name=name, results=deepcopy(result), **extra)


class Peer:
    def __init__(self, fault="none"):
        self.now = int(time.time())
        now = datetime.fromtimestamp(self.now, timezone.utc)
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "synthetic-" + NONCE)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(1).not_valid_before(now - timedelta(hours=1))
            .not_valid_after(now + timedelta(hours=2)).add_extension(x509.BasicConstraints(True, None), True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), True)
            .sign(key, hashes.SHA256()))
        crl = (x509.CertificateRevocationListBuilder().issuer_name(subject).last_update(now)
            .next_update(now + timedelta(hours=1)).add_extension(x509.CRLNumber(1), False).sign(key, hashes.SHA256()))
        self.issuer = cert.public_bytes(serialization.Encoding.PEM)
        self.crl = crl.public_bytes(serialization.Encoding.PEM)
        self.defaults = {key: "" for key in _TYPES}
        self.defaults.update({"range": "vdom", "source": "user", "update-vdom": "root",
            "scep-cert": "synthetic-inactive-default", "update-interval": 0, "source-ip": "0.0.0.0", "last-updated": 0})
        self.schema = {key: {"type": value} for key, value in _TYPES.items()}
        self.schema["name"].update(required=True, size=35)
        self.rows = []
        self.certificates = [{"name": "synthetic-existing-ca", "type": "remote-ca", "trusted": True,
                              "fingerprint": "f" * 64, "q_ref": 0, "q_type": 99}]
        self.writes = []
        self.fault = fault
        self.logouts = self.sessions = 0
        self.before_write = None

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
                    self._client.close()
                    self.logout_verified = True
                    peer.logouts += 1
        return Owner()

    def handle(self, request):
        path, method = request.url.path, request.method
        query = parse_qs(request.url.query.decode())
        if method == "GET":
            if path == "/api/v2/monitor/web-ui/state":
                actor = dict(name=ACTOR, login_name=ACTOR, sponsored_group_name="", guest_admin=False)
                return httpx.Response(200, json=frame({"admin": actor}, name="state", path="web-ui"))
            if path == COLLECTION:
                if query.get("action") == ["schema"]:
                    result = {"children": self.schema}
                elif query.get("action") == ["default"]:
                    result = self.defaults
                else:
                    result = self.rows
                return httpx.Response(200, json=frame(result))
            if path == SELECTOR.split("?")[0]:
                return httpx.Response(200, json=frame(self.certificates, name="available-certificates", path="system"))
            if path == "/api/v2/monitor/web-ui/object-urls":
                return httpx.Response(200, json=frame({"by_type": {"123": {"path": "vpn.certificate.crl"}}},
                    name="object-urls", path="web-ui"))
            if path == "/api/v2/monitor/system/object/usage":
                assert query["mkey"] == [NAME] and query["qtypes"] == ["[123]"]
                refs = ["synthetic-reference"] if self.fault == "referenced" else []
                return httpx.Response(200, json=frame({"currently_using": refs}, name="object", path="system", mkey=NAME))
            if path == "/api/v2/monitor/system/certificate/download/" + NAME:
                assert query == {"scope": ["vdom"], "type": ["crl"]}
                body = b"unqualified" if self.fault == "wrong-download" else self.crl
                return httpx.Response(200, content=body)
            raise AssertionError("unexpected fixed GET")
        assert request.headers["X-CSRFTOKEN"] == "synthetic-csrf"
        if self.before_write:
            self.before_write()
        self.writes.append(method)
        if method == "POST":
            assert path == IMPORT
            import base64
            assert json.loads(request.content) == {"scope": "vdom", "file_content": base64.b64encode(self.crl).decode()}
            self.rows = [{**self.defaults, "name": NAME, "q_origin_key": NAME, "q_ref": 0, "last-updated": self.now}]
            self.certificates.append({"name": NAME, "type": "crl"})
            if self.fault == "extra-crl": self.certificates.append({"name": "different-crl", "type": "crl"})
            if self.fault == "field-drift": self.rows[0]["http-url"] = "https://synthetic.invalid/"
            if self.fault == "unrelated-change": self.certificates[0]["trusted"] = False
            if self.fault == "lost-ack": raise httpx.ReadTimeout("synthetic")
            ack = frame({}, method="POST", path="vpn-certificate", action="import")
            if self.fault == "wrong-ack": ack["serial"] = "different-appliance"
            return httpx.Response(200, json=ack)
        assert method == "DELETE" and path == COLLECTION + "/" + NAME
        self.rows = []
        self.certificates = [entry for entry in self.certificates if entry["type"] != "crl"]
        return httpx.Response(200, json=frame({}, method="DELETE", mkey=NAME))


def make(root, peer, **options):
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    key = root / "execution.key"
    if not key.exists(): key.write_bytes(b"e" * 32); key.chmod(0o600)
    store = PersistentM4ExecutionStateStore(root / "execution.sqlite3", key)
    transport = NativeCrlTransport(owner_factory=peer.owner, owner_name=ACTOR, serial=SERIAL,
        crl_pem=peer.crl, issuer_pem=peer.issuer, nonce=NONCE, clock=lambda: peer.now)
    kwargs = dict(authority_key=b"a" * 32, environment_ref="synthetic-environment", scope_ref="synthetic-scope",
        audience_ref="synthetic-audience", allowed_requester_digest=IDENTITY["requester_digest"],
        allowed_transport_digest=IDENTITY["transport_digest"], import_enabled=True, recovery_enabled=True,
        clock=lambda: peer.now)
    kwargs.update(options)
    return NativeCrlWorkflow(transport, store, **kwargs)


def run(workflow, phase):
    preview = workflow.preview(phase, **IDENTITY)
    auth = workflow.authorize(phase, preview["preview_ref"], **IDENTITY)
    return workflow.execute(phase, auth["authorization_ref"], **IDENTITY), auth


def test_one_native_file_import_download_and_original_owned_recovery(tmp_path):
    peer = Peer(); workflow = make(tmp_path, peer); original = deepcopy(peer.certificates)
    def reserved():
        assert PersistentM4ExecutionStateStore(tmp_path / "execution.sqlite3", tmp_path / "execution.key").claim_count == len(peer.writes) + 1
    peer.before_write = reserved
    result, auth = run(workflow, "import")
    assert result["outcome"] == "succeeded" and result["verification"] == "verified"
    assert workflow.execute("import", auth["authorization_ref"], **IDENTITY)["idempotent_replay"]
    replacement = make(tmp_path, peer)
    for phase in ("import", "recover"):
        with pytest.raises(ValueError): replacement.preview(phase, **IDENTITY)
    assert run(workflow, "recover")[0]["outcome"] == "succeeded"
    assert peer.rows == [] and peer.certificates == original and peer.writes == ["POST", "DELETE"]
    assert workflow._store.claim_count == 2 and peer.sessions == peer.logouts
    assert "X509" not in json.dumps(result) and SERIAL not in json.dumps(result)
    workflow.close()


@pytest.mark.parametrize("fault", ["lost-ack", "wrong-ack", "wrong-download", "field-drift", "unrelated-change", "referenced", "extra-crl"])
def test_uncertain_import_never_replays_or_grants_cleanup_ownership(tmp_path, fault):
    peer = Peer(fault); workflow = make(tmp_path, peer)
    result, auth = run(workflow, "import")
    assert result["outcome"] != "succeeded"
    assert workflow.execute("import", auth["authorization_ref"], **IDENTITY)["idempotent_replay"]
    for phase in ("import", "recover"):
        with pytest.raises(ValueError): workflow.preview(phase, **IDENTITY)
    assert peer.writes == ["POST"] and peer.sessions == peer.logouts


@pytest.mark.parametrize("fault", ["issuer-bare", "issuer-colon", "invalid-fingerprint", "orphan-crl"])
def test_installed_issuer_and_unowned_crl_reject_before_claim(tmp_path, fault):
    peer = Peer()
    fingerprint = x509.load_pem_x509_certificate(peer.issuer).fingerprint(hashes.SHA256()).hex()
    if fault.startswith("issuer-"):
        peer.certificates[0]["fingerprint"] = (fingerprint if fault == "issuer-bare"
            else ":".join(fingerprint[index:index + 2] for index in range(0, 64, 2)).upper())
    elif fault == "invalid-fingerprint":
        peer.certificates[0]["fingerprint"] = "unqualified"
    else:
        peer.certificates.append({"name": "unowned-crl", "type": "crl"})
    workflow = make(tmp_path, peer)
    with pytest.raises(ValueError): workflow.preview("import", **IDENTITY)
    assert peer.writes == [] and workflow._store.claim_count == 0


def test_drift_wrong_operator_closed_gate_and_expiry_reject_without_dispatch(tmp_path):
    peer = Peer(); workflow = make(tmp_path, peer)
    with pytest.raises(ValueError): workflow.preview("import", **dict(IDENTITY, transport_digest="3" * 64))
    preview = workflow.preview("import", **IDENTITY)
    peer.defaults["http-url"] = "https://synthetic.invalid/"
    with pytest.raises(ValueError): workflow.authorize("import", preview["preview_ref"], **IDENTITY)
    peer.defaults["http-url"] = ""
    with pytest.raises(ValueError): workflow.authorize("import", preview["preview_ref"], **IDENTITY)
    preview = workflow.preview("import", **IDENTITY)
    peer.now += 60
    with pytest.raises(ValueError): workflow.authorize("import", preview["preview_ref"], **IDENTITY)
    assert peer.writes == [] and workflow._store.claim_count == 0
    closed = make(tmp_path / "closed", peer, import_enabled=False)
    preview = closed.preview("import", **IDENTITY)
    with pytest.raises(ValueError): closed.authorize("import", preview["preview_ref"], **IDENTITY)


def test_exact_http_oauth_mcp_surface_combines_both_phases_and_rejects_material_input(tmp_path):
    peer = Peer(); workflow = make(tmp_path / "crl", peer)
    settings = _settings(tmp_path)
    with TestClient(create_http_app(settings, v4_crl_candidate_action=NativeCrlMcpAction(workflow)),
                    base_url="https://mcp.example.com") as client:
        headers = _login(client, "fortipam:read fortipam:plan fortipam:operate")
        token = asyncio.run(LocalOAuthProvider(settings.local_oauth).load_access_token(headers["authorization"].split(" ", 1)[1]))
        principal = planning_principal_from_access_token(token, settings.v4_planning_authorization)
        workflow._namespace.update(requester_digest=principal.requester.digest, transport_digest=principal.transport_namespace_digest)
        for phase in ("import", "recover"):
            denied = _call(client, headers, f"preview_v4_crl_{phase}_700", {"file_content": "private-marker"})
            assert denied["isError"] and "private-marker" not in json.dumps(denied)
            preview = _call(client, headers, f"preview_v4_crl_{phase}_700", {})["structuredContent"]
            auth = _call(client, headers, f"authorize_v4_crl_{phase}_700", {"preview_ref": preview["preview_ref"]})["structuredContent"]
            result = _call(client, headers, f"execute_v4_crl_{phase}_700", {"authorization_ref": auth["authorization_ref"]})["structuredContent"]
            assert result["outcome"] == "succeeded" and "X509" not in json.dumps((preview, auth, result))
    assert peer.writes == ["POST", "DELETE"] and peer.rows == []
    with pytest.raises(HttpConfigurationError):
        create_http_app(replace(settings, runtime_profile=RuntimeProfile.READONLY), v4_crl_candidate_action=NativeCrlMcpAction(workflow))


def test_startup_closed_pin_and_consumed_database_preservation(tmp_path):
    assert build_crl_candidate({}) is None
    for name in ("IMPORT_ENABLED", "RECOVERY_ENABLED"):
        with pytest.raises(ValueError): build_crl_candidate({PREFIX + name: "true"})
    tmp_path.chmod(0o700); peer = Peer()
    for name, body in (("issuer.pem", peer.issuer), ("crl.pem", peer.crl), ("authority.key", b"a" * 32), ("execution.key", b"e" * 32)):
        path = tmp_path / name; path.write_bytes(body); path.chmod(0o600)
    manifest = {"contract": STARTUP, "binding": {"nonce": NONCE, "serial": SERIAL, "owner_name": ACTOR},
        "identity": dict(environment_ref="synthetic-environment", scope_ref="synthetic-scope", audience_ref="synthetic-audience",
            allowed_requester_digest=IDENTITY["requester_digest"], allowed_transport_digest=IDENTITY["transport_digest"])}
    path = tmp_path / "startup.json"; path.write_text(json.dumps(manifest)); path.chmod(0o600)
    env = {PREFIX + "ENABLED": "true", PREFIX + "STARTUP_MANIFEST_FILE": str(path),
        ENV_PREFIX + "ENABLED": "true", ENV_PREFIX + "BASE_URL": "https://synthetic.example", ENV_PREFIX + "API_TOKEN": "synthetic",
        OWNER_PREFIX + "SESSION_ENABLED": "true", OWNER_PREFIX + "LOGIN_ENV_FILE": str(tmp_path / "unused.env"),
        OWNER_PREFIX + "USERNAME_VARIABLE": "SYNTHETIC_USERNAME", OWNER_PREFIX + "PASSWORD_VARIABLE": "SYNTHETIC_PASSWORD"}
    action = build_crl_candidate(env)
    assert action._workflow._enabled == {"import": False, "recover": False}
    assert build_crl_candidate(env) is not None
    (tmp_path / "execution.sqlite3").unlink()
    with pytest.raises(ValueError): build_crl_candidate(env)
