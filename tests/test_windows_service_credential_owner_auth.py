"""Explicit Owner identity and full service lifecycle with synthetic native IO."""
from dataclasses import replace
import json
import logging
import pickle
import ssl

import httpx
import pytest

from fortipam_mcp import windows_service_credential_owner_auth as a
from fortipam_mcp import windows_service_credential_http_transport as h
from fortipam_mcp import windows_service_credential_readback as reader
from fortipam_mcp import windows_service_credential_recovery as recovery
from fortipam_mcp import windows_service_credential_authority as create_authority
from fortipam_mcp import windows_service_credential_recovery_authority as removal_authority
from fortipam_mcp.windows_service_credential_birth import WindowsServiceCredentialBirthCustody
from fortipam_mcp.windows_service_credential_material import windows_service_credential_material_runtime
from fortipam_mcp.secret_create_m4_runtime import ProtectedSecretCreateM4Runtime
from fortipam_mcp.secret_metadata_http_transport import SYSTEM_STATUS_PATH
from test_secret_create_m4_runtime import _Resolver, _Verifier, _Reader
from test_windows_service_credential_lifecycle import fixture, execute, SERIAL
from test_windows_service_credential_http_transport import Source as CreateSource
from test_windows_service_credential_recovery import Source as RecoverySource, authorize
from test_windows_service_credential_target_sources import payloads
from test_windows_execution_secret_recovery import Verifier
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_m4_execution_store import _ExternalM4Checkpoint
from v4_planning import M4Outcome

OWNER = "synthetic-owner"


class Login:
    def __init__(self, fault=None, *, host="lab.example.test", serial=SERIAL):
        self.fault, self.active, self.now = fault, False, 10.0
        self.host=host
        self.serial=serial
        self.clients, self.calls = [], []
        self.identities = 0

    def handle(self, request):
        logging.getLogger("httpcore.http11").debug("PRIVATE_LOGIN_LOG_SENTINEL")
        self.calls.append((request.method, request.url.path))
        assert request.url.host == self.host and "authorization" not in request.headers
        path = request.url.path
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            self.active = True
            cookies = ["testsession=PRIVATE_COOKIE_SENTINEL; Secure; HttpOnly; Path=/"]
            if self.fault != "missing-csrf":
                cookies.append("ccsrftoken=PRIVATE_CSRF_SENTINEL; Secure; Path=/")
            location="/api/v2/cmdb/secret/database/70" if self.fault=="api-redirect" else "/"
            if self.fault=="ui-query-redirect":location="/ng/index.html?session=PRIVATE_REDIRECT_SENTINEL"
            return httpx.Response(303, headers=[("location", location)] + [("set-cookie", value) for value in cookies])
        if path == "/logout":
            self.active = self.fault == "logout"
            return httpx.Response(200)
        if path in ("/", "/ng/index.html"):
            return httpx.Response(200)
        if not self.active:
            return httpx.Response(401, json={})
        if path == SYSTEM_STATUS_PATH:
            return httpx.Response(200, json=dict(version="v7.0.0", build=29, serial=self.serial))
        if path == a._ACTOR:
            self.identities += 1
            value = payloads()[0]
            value["serial"] = self.serial
            admin = value["results"]["admin"]
            admin.update(name=OWNER, login_name=OWNER, super_admin=True, profile=dict(name="super_admin"))
            if self.fault == "actor" or self.fault == "late-actor" and self.identities == 2:
                admin["name"] = "other-owner"
            if self.fault == "sponsored": admin["sponsored_group_name"] = "other-group"
            if self.fault == "profile": admin["profile"]["name"] = "other-profile"
            return httpx.Response(200, json=value)
        if path == "/api/v2/cmdb/system/admin/" + OWNER:
            value = dict(version="v7.0.0", build=29, http_method="GET", http_status=200, status="success",
                path="system", name="admin", vdom="root", serial=self.serial,
                results=dict(name=OWNER, accprofile="super_admin", status="enable", **{"remote-auth":"disable", "wildcard":"disable"}))
            if self.fault == "disabled": value["results"]["status"] = "disable"
            if self.fault == "remote": value["results"]["remote-auth"] = "enable"
            if self.fault == "wildcard": value["results"]["wildcard"] = "enable"
            if self.fault == "length":
                return httpx.Response(200, content=json.dumps(value), headers={"content-type":"application/json", "content-length":"1"})
            return httpx.Response(200, json=value)
        raise AssertionError("Unexpected fixed Owner route")

    def factory(self, **options):
        client = httpx.Client(transport=httpx.MockTransport(self.handle), **options)
        self.clients.append(client)
        return client

    def session(self, config, binding, *, purpose="create", enabled=True):
        return a.WindowsServiceCredentialOwnerSession(config, owner_name=OWNER,
            credentials=lambda: (OWNER, "PRIVATE_LOGIN_PASSWORD_SENTINEL"), binding=binding,
            purpose=purpose, enabled=enabled, client_factory=self.factory, clock=lambda:self.now)


class OwnerWire:
    """Authenticate the synthetic peer using Cookie/CSRF before response reuse."""
    def __init__(self, connection, source, log):
        self.connection, self.source, self.log = connection, source, log
    @property
    def sock(self): return self.connection.sock
    def connect(self): self.connection.connect()
    def getresponse(self): return self.connection.getresponse()
    def close(self): self.connection.close()
    def request(self, method, path, *, body=None, headers=None):
        assert "Authorization" not in headers
        assert "testsession=PRIVATE_COOKIE_SENTINEL" in headers["Cookie"]
        assert headers["User-Agent"] == "fortipam-mcp-service-credential/1"
        if method in ("POST", "DELETE"):
            assert headers["X-CSRFTOKEN"] == "PRIVATE_CSRF_SENTINEL"
        else:
            assert "X-CSRFTOKEN" not in headers
        self.log.append((method, path))
        # The existing response builders assert a synthetic Bearer. Their wire
        # authentication is replaced above; reuse only the fixed response data.
        self.connection.request(method, path, body=body, headers={**headers,"Authorization":"Bearer "+self.source.token})


def owner_birth(tmp_path):
    cmp = fixture(tmp_path)
    config = cmp["birth_kwargs"]["config"]
    binding = a.service_credential_owner_binding(config, owner_name=OWNER,
        serial_digest=cmp["kwargs"]["profile"].serial_digest,
        folder_context_digest=cmp["kwargs"]["profile"].folder_context_digest)
    cmp["custody"].close()
    cmp["birth_kwargs"]["owner_binding"] = binding
    cmp["custody"] = WindowsServiceCredentialBirthCustody(cmp["directory"], cmp["key"], **cmp["birth_kwargs"])
    cmp["peer"].custody = cmp["custody"]
    cmp["owner_binding"] = binding
    return cmp


def owner_create(tmp_path, monkeypatch, *, fault=None, read_fault=None, real_authority=True):
    monkeypatch.setattr(h, "_ssl_context", lambda config:ssl.create_default_context())
    monkeypatch.setattr(reader, "_ssl_context", lambda config:ssl.create_default_context())
    cmp = owner_birth(tmp_path)
    source, login, log = CreateSource(read_fault=read_fault), Login(fault), []
    session = login.session(cmp["birth_kwargs"]["config"], cmp["owner_binding"])
    if real_authority:
        path=tmp_path/"authority.key";path.write_bytes(b"a"*32);path.chmod(0o600)
        identity=dict(requester_digest=cmp["bound"].plan.requester_digest,transport_digest="b"*64)
        authority=create_authority.WindowsServiceCredentialLabAuthority(profile=cmp["kwargs"]["profile"],
            defaults=cmp["kwargs"]["defaults"],material_binding=cmp["kwargs"]["material_binding"],
            execution_store=cmp["execution"],material_store=cmp["material"],authority_key_file=path,witness_key_file=cmp["key"],
            source_context_digest="c"*64,environment_ref="owner-lab-development",scope_ref="one-service-credential",
            audience_ref="fixed-client",check_source=source.guard,execution_enabled=True,clock=lambda:cmp["now"][0],
            owner_binding=cmp["owner_binding"],**identity)
        preview=authority.preview(current_digest=create_authority.windows_service_credential_state_digest(cmp["kwargs"]["profile"],exists=False),**identity)
        issued=authority.issue(preview,**identity)
        cmp["custody"].close()
        cmp["kwargs"].update(plan=issued.plan,authorization=issued.authorization,request=issued.lease_request,material_binding=issued.material_binding)
        cmp["birth_kwargs"].update(plan=issued.plan,authorization=issued.authorization,request=issued.lease_request)
        cmp["custody"]=WindowsServiceCredentialBirthCustody(cmp["directory"],cmp["key"],**cmp["birth_kwargs"])
        cmp.update(authority=authority,bound=issued)
    transport = h.WindowsServiceCredentialHttpTransport(cmp["birth_kwargs"]["config"], cmp["custody"],
        execution_enabled=True, source_guard=source.guard, owner_session=session,owner_authority=cmp.get("authority"),
        connection_factory=lambda *args,**kwargs:OwnerWire(source.factory(*args,**kwargs), source, log), http_clock=lambda:0)
    runtime = windows_service_credential_material_runtime(**{**cmp["kwargs"],"transport":transport})
    current_reader=_Reader(post=cmp["bound"].plan.expected_state_digest,onboarding_binding_digest=cmp["kwargs"]["profile"].parameters_digest) if real_authority else _Reader()
    if real_authority:current_reader.read_current=lambda plan:plan.expected_current_digest
    cmp["outer"] = ProtectedSecretCreateM4Runtime(cmp["authority"] if real_authority else _Resolver(cmp["bound"]),
        cmp["authority"] if real_authority else _Verifier(), cmp["execution"], runtime, current_reader,
        authenticated_requester_digest=cmp["bound"].plan.requester_digest, clock=lambda:cmp["now"][0])
    cmp.update(source=source, session=session, login=login, wire=log, transport=transport)
    return cmp


def owner_recovery(cmp, tmp_path, monkeypatch):
    if "authority" in cmp:cmp["authority"].close()
    cmp["custody"].close(); cmp["now"][0] = 2000
    custody = WindowsServiceCredentialBirthCustody(cmp["directory"], cmp["key"], **cmp["birth_kwargs"])
    for name,value in (("recovery.key",b"r"*32),("recovery-witness.key",b"w"*32)):
        path=tmp_path/name;path.write_bytes(value);path.chmod(0o600)
    store=PersistentM4ExecutionStateStore(tmp_path/"recovery.sqlite",tmp_path/"recovery.key",
        monotonic_checkpoint=_ExternalM4Checkpoint("owner-recovery"),checkpoint_store_ref="owner-recovery")
    source, login, log = RecoverySource(), Login(), []
    config=replace(cmp["birth_kwargs"]["config"], bearer_token="independent-synthetic-token")
    session=login.session(config,cmp["owner_binding"],purpose="recovery")
    verifier=Verifier()
    if "authority" in cmp:
        path=tmp_path/"removal-authority.key";path.write_bytes(b"h"*32);path.chmod(0o600)
        identity=dict(requester_digest=cmp["bound"].plan.requester_digest,transport_digest="d"*64)
        verifier=removal_authority.WindowsServiceCredentialRemovalLabAuthority(custody,execution_store=store,
            authority_key_file=path,witness_key_file=tmp_path/"recovery-witness.key",environment_ref="owner-lab-development",
            scope_ref="one-original-service-credential",audience_ref="independent-client",execution_enabled=True,
            clock=lambda:cmp["now"][0],**identity)
        cmp.update(removal_authority=verifier,recovery_identity=identity)
    monkeypatch.setattr(recovery,"_ssl_context",lambda config:ssl.create_default_context())
    runtime=recovery.WindowsServiceCredentialRecovery(custody,execution_store=store,witness_key_file=tmp_path/"recovery-witness.key",
        authorization_verifier=verifier,execution_enabled=True,config=config,source_guard=source.guard,owner_session=session,
        connection_factory=lambda *args,**kwargs:OwnerWire(source.factory(*args,**kwargs),source,log),clock=lambda:2000,http_clock=lambda:0)
    cmp.update(recovery=runtime, recovery_store=store, recovery_session=session, recovery_login=login,
        recovery_wire=log, independent_custody=custody, recovery_source=source)


@pytest.mark.parametrize("read_fault",[None,"password"])
def test_explicit_owner_creation_full_material_preservation_and_independent_recovery(tmp_path,monkeypatch,caplog,read_fault):
    real_authority=True
    caplog.set_level(logging.DEBUG)
    cmp=owner_create(tmp_path,monkeypatch,read_fault=read_fault,real_authority=real_authority)
    with cmp["session"].authenticated():
        assert execute(cmp).outcome is (M4Outcome.RECONCILIATION_REQUIRED if read_fault else M4Outcome.SUCCEEDED)
    assert len(cmp["wire"])==8 and cmp["session"].logout_verified
    if real_authority:
        assert cmp["authority"]._binding["creator_binding"]==cmp["owner_binding"].binding_digest
    original=cmp["custody"].inspect_original_creation()
    before={p.name:p.read_bytes() for p in cmp["directory"].iterdir()}
    owner_recovery(cmp,tmp_path,monkeypatch)
    with cmp["recovery_session"].authenticated():
        if real_authority:
            issued=cmp["removal_authority"].issue(cmp["recovery"],**cmp["recovery_identity"])
            plan,authorization=issued.plan,issued.authorization
        else:
            plan,authorization=authorize(cmp)
        assert cmp["recovery"].execute(plan,authorization).outcome is M4Outcome.SUCCEEDED
    assert cmp["recovery_session"].logout_verified and len(cmp["recovery_wire"])==16
    assert cmp["independent_custody"].inspect_original_creation()==original
    assert all((cmp["directory"]/name).read_bytes()==data for name,data in before.items())
    assert cmp["loader"].loads==cmp["execution"].claim_count==cmp["material"].claim_count==cmp["recovery_store"].claim_count==1
    assert all(client.is_closed and not client.cookies for login in (cmp["login"],cmp["recovery_login"]) for client in login.clients)
    assert "PRIVATE_LOGIN_LOG_SENTINEL" not in caplog.text
    for path in cmp["directory"].iterdir():
        assert all(value not in path.read_bytes() for value in (b"PRIVATE_COOKIE_SENTINEL",b"PRIVATE_CSRF_SENTINEL",b"PRIVATE_LOGIN_PASSWORD_SENTINEL"))
    with pytest.raises(a.WindowsServiceCredentialOwnerAuthError):
        with cmp["session"].authenticated(): pass
    assert len(cmp["wire"])==8
    assert (cmp["directory"]/"create.full-birth.json").exists()==(read_fault is None)


@pytest.mark.parametrize("fault",["actor","sponsored","profile","disabled","remote","wildcard","length","missing-csrf","api-redirect"])
def test_unqualified_owner_identity_or_role_closes_before_material_or_secret_requests(tmp_path,monkeypatch,fault):
    cmp=owner_create(tmp_path,monkeypatch,fault=fault)
    with pytest.raises(a.WindowsServiceCredentialOwnerAuthError):
        with cmp["session"].authenticated(): execute(cmp)
    assert cmp["loader"].loads==cmp["execution"].claim_count==cmp["material"].claim_count==0
    assert not cmp["wire"] and not list(cmp["directory"].iterdir())
    assert cmp["session"].logout_verified and all(client.is_closed and not client.cookies for client in cmp["login"].clients)


@pytest.mark.parametrize("drift",["expired","clock-rollback","cookie","client","purpose","binding","clock"])
def test_live_owner_drift_refuses_before_material_or_post(tmp_path,monkeypatch,drift):
    cmp=owner_create(tmp_path,monkeypatch)
    with pytest.raises(a.WindowsServiceCredentialOwnerAuthError):
        with cmp["session"].authenticated():
            session=cmp["session"]
            if drift=="expired":cmp["login"].now+=61
            if drift=="clock-rollback":cmp["login"].now-=1
            if drift=="cookie":session._session._client.cookies.set("other","changed")
            if drift=="client":session._client_pin=object()
            if drift=="purpose":session._purpose="recovery"
            if drift=="binding":session._binding=replace(session.binding,owner_digest="0"*64)
            if drift=="clock":session._clock=lambda:10.0
            result=execute(cmp)
            assert result.outcome is not M4Outcome.SUCCEEDED
            # Explicitly exercise the refusal even when the M4 kernel rejects
            # readiness before the Owner session's next identity bracket.
            session.require_current(cmp["custody"],config=cmp["birth_kwargs"]["config"],purpose="create")
    assert not cmp["wire"] and cmp["loader"].loads==cmp["material"].claim_count==0


def test_owner_custody_cannot_silently_use_bearer_or_another_owner(tmp_path):
    cmp=owner_birth(tmp_path)
    with pytest.raises(h.WindowsServiceCredentialHttpError):
        h.WindowsServiceCredentialHttpTransport(cmp["birth_kwargs"]["config"],cmp["custody"])
    bare=tmp_path/"bare";bare.mkdir()
    bearer=fixture(bare)
    login=Login();session=login.session(cmp["birth_kwargs"]["config"],cmp["owner_binding"])
    with pytest.raises(h.WindowsServiceCredentialHttpError):
        h.WindowsServiceCredentialHttpTransport(bearer["birth_kwargs"]["config"],bearer["custody"],owner_session=session)
    other=replace(cmp["owner_binding"],folder_context_digest="1"*64)
    with pytest.raises(Exception):
        WindowsServiceCredentialBirthCustody(cmp["directory"],cmp["key"],**{**cmp["birth_kwargs"],"owner_binding":other})
    assert not login.calls


def test_default_closed_owner_login_and_opaque_bindings(tmp_path):
    cmp=owner_birth(tmp_path);login=Login()
    session=login.session(cmp["birth_kwargs"]["config"],cmp["owner_binding"],enabled=False)
    with pytest.raises(a.WindowsServiceCredentialOwnerAuthError):
        with session.authenticated(): pass
    assert not login.calls
    for value in (session,cmp["owner_binding"]):
        assert OWNER not in repr(value)
        with pytest.raises(Exception):pickle.dumps(value)


def test_only_this_auth_ui_landing_is_followed_and_the_private_query_is_not_retained(tmp_path,monkeypatch,caplog):
    caplog.set_level(logging.DEBUG)
    cmp=owner_create(tmp_path,monkeypatch,fault="ui-query-redirect")
    with cmp["session"].authenticated():assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    assert cmp["session"]._landing_url is None and cmp["session"]._request_count==10
    assert cmp["login"].calls.count(("GET","/ng/index.html"))==1
    assert "PRIVATE_REDIRECT_SENTINEL" not in caplog.text
    assert all(b"PRIVATE_REDIRECT_SENTINEL" not in p.read_bytes() for p in cmp["directory"].iterdir())


def test_owner_transport_requires_the_exact_creator_bound_issuer(tmp_path,monkeypatch):
    rejected=tmp_path/"without-issuer";rejected.mkdir()
    with pytest.raises(h.WindowsServiceCredentialHttpError):owner_create(rejected,monkeypatch,real_authority=False)
    valid=tmp_path/"valid";valid.mkdir()
    cmp=owner_create(valid,monkeypatch)
    foreign=replace(cmp["owner_binding"],owner_digest="f"*64)
    custody=WindowsServiceCredentialBirthCustody(cmp["directory"],cmp["key"],**{**cmp["birth_kwargs"],"owner_binding":foreign})
    from v4_planning import M4AuthorizationDenied
    with pytest.raises(M4AuthorizationDenied):cmp["authority"].validate_owner_creation(custody)
    cmp["authority"]._owner_binding=foreign
    with pytest.raises(M4AuthorizationDenied):cmp["authority"].validate_owner_creation(cmp["custody"])
    assert cmp["loader"].loads==cmp["execution"].claim_count==cmp["material"].claim_count==0
    assert not cmp["wire"]


def test_fixed_owner_operation_scope_and_custody_binding(tmp_path,monkeypatch):
    cmp=owner_create(tmp_path,monkeypatch)
    other=tmp_path/"other";other.mkdir()
    unrelated=owner_birth(other)
    with cmp["session"].authenticated():
        for operation in ("delete","absence","foreign"):
            with pytest.raises(a.WindowsServiceCredentialOwnerAuthError):
                cmp["session"]._headers(operation,cmp["custody"],config=cmp["birth_kwargs"]["config"])
        with pytest.raises(a.WindowsServiceCredentialOwnerAuthError):
            cmp["session"].require_current(unrelated["custody"],config=cmp["birth_kwargs"]["config"],purpose="create")
    assert cmp["loader"].loads==0 and not cmp["wire"]


def test_independent_owner_custody_rejects_removed_authentication_and_creator_session_reuse(tmp_path,monkeypatch):
    cmp=owner_create(tmp_path,monkeypatch)
    with cmp["session"].authenticated():assert execute(cmp).outcome is M4Outcome.SUCCEEDED
    snapshot={p.name:p.read_bytes() for p in cmp["directory"].iterdir()}
    bare=WindowsServiceCredentialBirthCustody(cmp["directory"],cmp["key"],**{**cmp["birth_kwargs"],"owner_binding":None})
    with pytest.raises(Exception):bare.inspect_original_creation()
    owner_recovery(cmp,tmp_path,monkeypatch)
    with pytest.raises(ValueError):
        a.check_owner_session_binding(cmp["birth_kwargs"]["config"],cmp["owner_binding"],cmp["session"],purpose="recovery")
    with pytest.raises(reader.WindowsServiceCredentialReadbackError):
        reader.WindowsServiceCredentialFullReader(cmp["independent_custody"],phase="recovery-preview",read_enabled=True,
            source_guard=cmp["recovery_source"].guard,connection_factory=cmp["recovery_source"].factory)
    assert not cmp["recovery_wire"] and all((cmp["directory"]/name).read_bytes()==data for name,data in snapshot.items())


@pytest.mark.parametrize("fault",["late-actor","logout"])
def test_uncertain_owner_closure_preserves_original_without_replay(tmp_path,monkeypatch,fault):
    cmp=owner_create(tmp_path,monkeypatch,fault=fault)
    try:
        with cmp["session"].authenticated():
            outcome=execute(cmp).outcome
    except a.WindowsServiceCredentialOwnerAuthError:
        assert fault in ("late-actor","logout")
    assert outcome is M4Outcome.SUCCEEDED and len(cmp["wire"])==8
    assert cmp["custody"].inspect_original_creation().original_outcome=="succeeded"
    count=len(cmp["wire"])
    with pytest.raises(a.WindowsServiceCredentialOwnerAuthError):
        with cmp["session"].authenticated(): pass
    assert len(cmp["wire"])==count
