"""Synthetic native JWT login/lease peer; no product writes or actual tokens."""
import base64
import hashlib
import json
import secrets
import ssl

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding,rsa
import httpx
import pytest

from fortipam_mcp import jwt_rotation_authentication as c
from fortipam_mcp.jwt_manual_key_owner_http import JwtManualKeyOwnerHttpConfig
from test_jwt_manual_rotation_contract import fixture,replacement
from test_jwt_manual_key_contract import synthetic_key
from test_jwt_manual_key_owner_actor import sources
from test_jwt_manual_key_preflight import SERIAL


class Peer:
    def __init__(self,root,old,new,monkeypatch,fault="none"):
        self.binding,self.keys = fixture(old,new); self.signers = {"old":old,"new":new}
        self.active = {"old"}; self.allowed = True; self.revoked = False; self.clock = 1000
        self.requests = []; self.assertions = set(); self.tokens = {}; self.clients = []; self.fault = fault
        self.denial_html = False
        ca = root / "ca.pem"; ca.write_bytes(b"SYNTHETIC_CA")
        self.config = JwtManualKeyOwnerHttpConfig("https://synthetic.invalid","synthetic-owner","a"*64,str(ca),"b"*64,"c"*64)
        monkeypatch.setattr(c.ssl,"create_default_context",lambda **_:ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))

    @staticmethod
    def decode(value): return json.loads(base64.urlsafe_b64decode(value + b"="*((-len(value))%4)))

    def reply(self,req):
        assert "cookie" not in req.headers
        self.requests.append((req.method,req.url.path))
        if req.url.path == c._LOGIN:
            assert req.method == "POST" and "authorization" not in req.headers
            if self.fault == "timeout": raise httpx.ReadTimeout("PRIVATE_RESPONSE")
            if self.fault in {"gui-guard","gui-guard-large","gui-guard-source-inflight"}:
                if self.fault == "gui-guard-source-inflight": self.allowed = False
                body = '<html><script>window.location="/remote/login?private=SYNTHETIC_PRIVATE";</script></html>'
                if self.fault == "gui-guard-large": body += "x"*1024
                return httpx.Response(401,text=body,headers={"Content-Type":"text/html"})
            signed = json.loads(req.content)["jwt"].encode(); header,body,signature = signed.split(b".")
            assert self.decode(header) == {"alg":"RS256","typ":"JWT"}
            assert signed not in self.assertions; self.assertions.add(signed)
            payload = self.decode(body); key = None
            for name,signer in self.signers.items():
                try: signer.public_key().verify(base64.urlsafe_b64decode(signature+b"="*((-len(signature))%4)),header+b"."+body,padding.PKCS1v15(),hashes.SHA256())
                except Exception: continue
                key = name; break
            assert key is not None
            b = self.binding
            valid = key in self.active and payload["iss"] == b._issuer and payload["aud"] == b._audience and payload["sub"] == b._subject and payload["nbf"] <= self.clock < payload["exp"]
            assert set(payload) == {"iss","aud","sub","iat","nbf","exp","jti"}
            if not valid:
                if self.denial_html:
                    return httpx.Response(401,text='<script>window.location="/remote/login";</script>',headers={"Content-Type":"text/html"})
                return httpx.Response(401,json={"status":"error"})
            if self.fault == "duplicate": return httpx.Response(200,content=b'{"access-token":"FIRST","access-token":"SECOND"}',headers={"Content-Type":"application/json"})
            if self.fault == "missing-token": return httpx.Response(200,json={"status":"error"})
            if self.fault == "oversized": return httpx.Response(200,json={"access-token":"x"*32768})
            token = secrets.token_hex(32); self.tokens[token] = key
            if self.fault == "invalid-token": token = "PRIVATE_TOKEN\nBAD"
            return httpx.Response(200,json={"access-token":token},headers={"Set-Cookie":"owner=SYNTHETIC_OWNER_COOKIE; Path=/; Secure"})
        assert req.url.path == c._STATE and req.method == "GET"
        assert req.headers["authorization"].removeprefix("Bearer ") in self.tokens
        if self.revoked:
            if self.fault == "source-inflight": self.allowed = False
            return httpx.Response(401,json={"status":"error"})
        state = sources()[0]; state["results"]["admin"].update(name=self.binding._user_name,super_admin=False)
        state["results"]["admin"]["profile"]["name"] = "pam_standard_user"
        if self.fault == "wrong-owner": state["results"]["admin"]["name"] = "FOREIGN"
        if self.fault == "wrong-role": state["results"]["admin"]["profile"]["name"] = "super_admin"
        if self.fault == "super-admin": state["results"]["admin"]["super_admin"] = True
        if self.fault == "wrong-device": state["serial"] = "FOREIGN"
        return httpx.Response(200,json=state)

    def factory(self,**kwargs):
        assert kwargs["verify"].check_hostname and kwargs["verify"].verify_mode == ssl.CERT_REQUIRED
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        client = httpx.Client(**kwargs,transport=httpx.MockTransport(self.reply)); self.clients.append(client); return client

    def probe(self,*,enabled=True,guard=True):
        return c.JwtRotationAuthenticationProbe(self.config,self.binding,self.keys,self.signers["old"],self.signers["new"],
            probe_enabled=enabled,source_guard=(lambda:self.allowed) if guard else None,client_factory=self.factory,clock=lambda:self.clock)


@pytest.mark.parametrize("fresh", [False,True])
def test_connection_snapshot_control_uses_one_new_verified_client_per_assertion_without_retry(tmp_path,synthetic_key,replacement,monkeypatch,fresh):
    peer = Peer(tmp_path,synthetic_key,replacement,monkeypatch)
    def factory(**kwargs):
        snapshot = set(peer.active)
        actual = peer.reply
        def reply(request):
            current = peer.active
            try:
                peer.active = snapshot
                return actual(request)
            finally:
                peer.active = current
        with monkeypatch.context() as scoped:
            scoped.setattr(peer,"reply",reply)
            return peer.factory(**kwargs)
    with c.JwtRotationAuthenticationProbe(peer.config,peer.binding,peer.keys,synthetic_key,replacement,
            probe_enabled=True,source_guard=lambda:peer.allowed,client_factory=factory,clock=lambda:peer.clock,
            fresh_assertion_clients=fresh) as probe:
        assert probe.authenticate("old") is not None
        peer.active = {"new"}
        assert (probe.authenticate("old") is None) is fresh
        assert (probe.authenticate("new") is not None) is fresh
        assert probe._auth_count == 3 and sum(path==c._LOGIN for _,path in peer.requests) == 3
        assert len(peer.clients) == (4 if fresh else 1)
        assert all(client.is_closed for client in peer.clients[1:])
    assert all(client.is_closed for client in peer.clients)


def test_fresh_assertion_timeout_closes_its_client_and_never_retries(tmp_path,synthetic_key,replacement,monkeypatch):
    peer = Peer(tmp_path,synthetic_key,replacement,monkeypatch,fault="timeout")
    with c.JwtRotationAuthenticationProbe(peer.config,peer.binding,peer.keys,synthetic_key,replacement,
            probe_enabled=True,source_guard=lambda:peer.allowed,client_factory=peer.factory,clock=lambda:peer.clock,
            fresh_assertion_clients=True) as probe:
        with pytest.raises(c.JwtRotationAuthenticationError):probe.authenticate("old")
        assert probe._auth_count == 1 and len(peer.clients) == 2 and peer.clients[1].is_closed
        assert not peer.clients[0].is_closed
    assert all(client.is_closed for client in peer.clients)


@pytest.mark.parametrize("large", [False,True])
def test_gui_login_guard_is_unqualified_and_never_becomes_a_jwt_denial(tmp_path,synthetic_key,replacement,monkeypatch,large):
    peer = Peer(tmp_path,synthetic_key,replacement,monkeypatch,fault="gui-guard-large"if large else"gui-guard")
    with peer.probe() as probe:
        with pytest.raises(c.JwtRotationAuthenticationError): probe.authenticate("old")
        assert probe._leases == [] and peer.requests == [("POST",c._LOGIN)]
        expected = {"operation":"assertion","key":"old","case":"valid","stage":"html_rejection"if large else"gui_login_guard",
            "http_status":401,"json_content":False,"bounded_body_complete":not large,"gui_login_script":not large}
        if large:
            expected["html_observation"] = {"captured_complete":True,"captured_bytes":len('<html><script>window.location="/remote/login?private=SYNTHETIC_PRIVATE";</script></html>')+1024,
                "lockout_language":False,"rate_limit_language":False,"login_form":False,"padding_comments":False,"redirect_script":True}
        assert probe.observations == [expected]
        assert "SYNTHETIC_PRIVATE" not in json.dumps(probe.observations)
    assert peer.clients[0].is_closed and probe._old is probe._new is None


@pytest.mark.parametrize("denial_html", [False,True])
def test_fresh_assertions_overlap_cutover_and_existing_lease_observation_are_distinct(tmp_path,synthetic_key,replacement,monkeypatch,denial_html):
    peer = Peer(tmp_path,synthetic_key,replacement,monkeypatch)
    peer.denial_html = denial_html
    with peer.probe() as p:
        original = p.authenticate("old"); assert original is not None
        assert p.authenticate("new") is None
        for case in ("wrong-issuer","wrong-audience","wrong-subject","expired"): assert p.authenticate("old",case=case) is None
        peer.active = {"old","new"}
        assert p.authenticate("old") is not None and p.authenticate("new") is not None
        peer.active = {"new"}
        assert p.authenticate("old") is None and p.authenticate("new") is not None
        assert p.check(original) is True
        peer.revoked = True
        assert all(p.check(lease) is False for lease in p._leases)
        assert len(peer.assertions) == 10
    assert not p._enabled and p._closed and p._old is p._new is None
    assert all(lease._closed and not lease._token for lease in p._leases)
    assert all(client.is_closed for client in peer.clients)


@pytest.mark.parametrize("fault", ["gui-guard","gui-guard-large","gui-guard-source-inflight"])
def test_qualified_handler_does_not_admit_truncated_guard_or_lost_source(tmp_path,synthetic_key,replacement,monkeypatch,fault):
    peer = Peer(tmp_path,synthetic_key,replacement,monkeypatch)
    with peer.probe() as probe:
        assert probe.authenticate("old") is not None
        peer.fault = fault
        if fault == "gui-guard":
            assert probe.authenticate("new") is None
            assert probe.observations[-1]["prior_login_identity_qualified"] is True
        else:
            with pytest.raises(c.JwtRotationAuthenticationError): probe.authenticate("new")
    assert all(client.is_closed for client in peer.clients)


@pytest.mark.parametrize("fault", ["wrong-owner","wrong-role","super-admin","wrong-device","duplicate","missing-token","invalid-token","oversized","timeout"])
def test_uncertain_authentication_or_identity_never_counts_as_denial_or_success(tmp_path,synthetic_key,replacement,monkeypatch,fault):
    peer = Peer(tmp_path,synthetic_key,replacement,monkeypatch,fault)
    with peer.probe() as p:
        with pytest.raises(c.JwtRotationAuthenticationError,match="^The protected JWT authentication probe is unavailable.$"):
            p.authenticate("old")
    assert all(client.is_closed for client in peer.clients)
    assert all(lease._closed and not lease._token for lease in p._leases)


@pytest.mark.parametrize("gate", ["disabled","no-source","false-source","wrong-signer"])
def test_closed_provider_gates_precede_any_tls_client_or_authentication(tmp_path,synthetic_key,replacement,monkeypatch,gate):
    peer = Peer(tmp_path,synthetic_key,replacement,monkeypatch)
    if gate == "false-source": peer.allowed = False
    with pytest.raises(c.JwtRotationAuthenticationError):
        if gate == "wrong-signer":
            c.JwtRotationAuthenticationProbe(peer.config,peer.binding,peer.keys,replacement,synthetic_key)
        else:
            with peer.probe(enabled=gate != "disabled",guard=gate != "no-source"): pass
    assert not peer.clients and not peer.requests


def test_late_source_failure_or_foreign_lease_and_request_budget_refuse_without_fallback(tmp_path,synthetic_key,replacement,monkeypatch):
    peer = Peer(tmp_path,synthetic_key,replacement,monkeypatch)
    with peer.probe() as p:
        lease = p.authenticate("old"); assert lease is not None
        foreign = c.JwtRotationLease("FOREIGN","b"*64,"c"*64,1000)
        count = len(peer.requests)
        with pytest.raises(c.JwtRotationAuthenticationError): p.check(foreign)
        assert len(peer.requests) == count
        peer.revoked = True; peer.fault = "source-inflight"
        with pytest.raises(c.JwtRotationAuthenticationError): p.check(lease)
        assert p._check_count == 2
        peer.allowed = True; peer.fault = "none"
        for _ in range(15): assert p.authenticate("new") is None
        count = len(peer.requests)
        with pytest.raises(c.JwtRotationAuthenticationError): p.authenticate("new")
        assert len(peer.requests) == count


def test_assertion_and_response_buffers_clear_on_stream_interruption(tmp_path,synthetic_key,replacement,monkeypatch):
    peer = Peer(tmp_path,synthetic_key,replacement,monkeypatch); observed = []
    zero = c._zeroize_mutable
    def erased(raw):
        if b'SYNTHETIC_PARTIAL_ACCESS' in raw: observed.append(raw)
        zero(raw)
    monkeypatch.setattr(c,"_zeroize_mutable",erased)
    original = peer.reply
    def interrupted(req):
        if req.url.path == c._LOGIN:
            class Stream(httpx.SyncByteStream):
                def __iter__(self):
                    yield b'{"access-token":"SYNTHETIC_PARTIAL_ACCESS'
                    raise KeyboardInterrupt
            return httpx.Response(200,stream=Stream(),headers={"Content-Type":"application/json"})
        return original(req)
    peer.reply = interrupted
    with pytest.raises(KeyboardInterrupt):
        with peer.probe() as p: p.authenticate("old")
    assert observed and all(not raw for raw in observed)
    assert p._closed and not p._leases and all(client.is_closed for client in peer.clients)
