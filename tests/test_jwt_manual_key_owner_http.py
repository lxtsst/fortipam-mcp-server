"""Real M4 dispatch ownership with a synthetic Owner cookie/product peer."""
from copy import deepcopy
from datetime import datetime, timezone
from email.utils import format_datetime
import json
import ssl

import httpx
import pytest

from fortipam_mcp import jwt_manual_key_owner_http as c
from fortipam_mcp.jwt_manual_key_owned_state import expected_jwt_manual_key_created_state
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from test_jwt_manual_key_contract import synthetic_key
from test_jwt_manual_key_owned_state import request, owned_row
from test_jwt_manual_key_owner_actor import sources as owner_sources, OWNER
from test_jwt_manual_key_preflight import inputs, packet, NAME
from test_m4_execution_store import _ExternalM4Checkpoint, CHECKPOINT_STORE_REF
from test_v4_execution_kernel import _authorization, _Verifier, REQUESTER, _plan
from v4_planning import M4ExecutionKernel, M4ExecutionPlan, M4AdapterAmbiguous, canonical_digest


class Lab:
    def __init__(self, root, key, monkeypatch, fault="none"):
        root.chmod(0o700); self.root = root; self.fault = fault
        self.request = request(key); self.row = owned_row(self.request)
        self.exists = self.logout = False; self.source = True
        self.posts = self.deletes = self.full_reads = 0; self.calls = []
        self.wire = root / "wire"; self.wire.mkdir(mode=0o700)
        self.key = root / "witness.key"; self.key.write_bytes(b"w" * 32); self.key.chmod(0o600)
        self.ca = root / "ca.pem"; self.ca.write_bytes(b"SYNTHETIC_CA")
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        monkeypatch.setattr(c.ssl, "create_default_context", lambda **kwargs: tls)
        self.config = c.JwtManualKeyOwnerHttpConfig("https://synthetic.invalid", OWNER, "c" * 64,
            str(self.ca), REQUESTER, "d" * 64)
        self.clients = []

    def handler(self, req):
        assert "authorization" not in req.headers
        self.calls.append((req.method, str(req.url)))
        path = req.url.path; query = req.url.query
        date = {"Date": format_datetime(datetime.now(timezone.utc), usegmt=True)}
        if path == "/remote/login": return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            self.logout = False
            return httpx.Response(303, headers={"Location": "/", "Set-Cookie": 'csrf="synthetic-csrf"; Path=/'})
        if path == "/logout": self.logout = True; return httpx.Response(200)
        if path == c._STATE:
            if self.logout and self.fault != "logout-live": return httpx.Response(401)
            state = owner_sources()[0]
            state["results"]["ccsrf_token_cookie_name"] = "csrf"
            if self.fault == "wrong-owner": state["results"]["admin"]["name"] = "synthetic-other"
            return httpx.Response(200, json=state, headers=date)
        if path == "/api/v2/cmdb/system/admin/" + OWNER:
            return httpx.Response(200, json=owner_sources()[1], headers=date)
        if req.method == "POST":
            assert path == c._JWT and query == b"with_meta=true"
            assert req.headers["X-CSRFTOKEN"] == "synthetic-csrf"
            assert (self.wire / "create.claim.json").is_file()
            self.posts += 1
            if self.fault == "403":
                return httpx.Response(403, json=packet("jwt-key", None,
                    http_method="POST", http_status=403, status="error"), headers=date)
            self.exists = True
            if self.fault == "timeout": raise httpx.ReadTimeout("PRIVATE_SYNTHETIC_DETAIL")
            if self.fault == "interrupt":
                class InterruptedBody(httpx.SyncByteStream):
                    def __iter__(self):
                        yield b'{"private":"SYNTHETIC_PARTIAL_RESPONSE"'
                        raise KeyboardInterrupt
                return httpx.Response(200, stream=InterruptedBody(),
                    headers={**date, "Content-Type": "application/json"})
            if self.fault == "source-inflight": self.source = False
            return httpx.Response(200, json=packet("jwt-key", [], http_method="POST", mkey=NAME), headers=date)
        if req.method == "DELETE":
            assert path == c._JWT + "/" + NAME and not query
            assert (self.wire / "remove.claim.json").is_file()
            self.deletes += 1; self.exists = False
            return httpx.Response(200, json=packet("jwt-key", [], http_method="DELETE", mkey=NAME), headers=date)
        values = inputs()
        if path == c._JWT:
            if query == b"action=schema&with_meta=true": return httpx.Response(200, json=values[0], headers=date)
            if query == b"action=default&with_meta=true": return httpx.Response(200, json=values[1], headers=date)
            assert query == b"format=name%7Ctype&with_meta=true"
            payload = packet("jwt-key", [{"name": NAME, "type": "manually"}], size=1, matched_count=1, next_idx=0) if self.exists else values[2]
            return httpx.Response(200, json=payload, headers=date)
        if path == "/api/v2/cmdb/system/api-user":
            assert query == b"format=name%7Ctype%7Cjwt-key&with_meta=true"
            return httpx.Response(200, json=values[3], headers=date)
        if path == c._JWT + "/" + NAME:
            if query == b"format=name%7Ctype&with_meta=true":
                return httpx.Response(200 if self.exists else 404, json=values[4], headers=date)
            assert query == b"with_meta=true" and self.exists
            assert (self.wire / "create.ack.json").is_file()
            self.full_reads += 1; row = deepcopy(self.row)
            if self.fault == "bad-post": row["unqualified-field"] = True
            return httpx.Response(200, json=packet("jwt-key", [row], mkey=NAME), headers=date)
        assert path == "/"
        return httpx.Response(200)

    def factory(self, **kwargs):
        assert kwargs["verify"].check_hostname and kwargs["verify"].verify_mode == ssl.CERT_REQUIRED
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        client = httpx.Client(**kwargs, transport=httpx.MockTransport(self.handler)); self.clients.append(client)
        return client

    def session(self, enabled=True, guard=True):
        return c.JwtManualKeyOwnerHttp(self.config, self.request, lambda:(OWNER,"synthetic-password"),
            directory=self.wire, witness_key_file=self.key, source_guard=(lambda:self.source) if guard else None,
            execution_enabled=enabled, client_factory=self.factory, clock=lambda:1000)

    def store(self, phase):
        key = self.root / (phase + ".key"); key.write_bytes((b"s" if phase == "create" else b"r") * 32); key.chmod(0o600)
        return PersistentM4ExecutionStateStore(self.root / (phase + ".sqlite"), key,
            monotonic_checkpoint=_ExternalM4Checkpoint(), checkpoint_store_ref=CHECKPOINT_STORE_REF)


def planned_operation(session, *, remove=False):
    if remove: current, expected = session.removal_current()
    else:
        before = session.preflight(); current = before.current_digest
        expected = expected_jwt_manual_key_created_state(session._request, before.state)
    data = _plan().canonical_content()
    data.update(plan_ref="owner-remove-plan" if remove else "owner-create-plan", action_id=c.REMOVE_ACTION if remove else c.CREATE_ACTION,
        action_version="1.0.0", adapter_ref=c.REMOVE_ADAPTER if remove else c.CREATE_ADAPTER, target_ref=c.TARGET,
        expected_current_digest=current, expected_state_digest=expected, parameters_digest=session._request.digest)
    plan = M4ExecutionPlan(**data, plan_digest=canonical_digest(data)); auth = _authorization(plan)
    return plan, auth


def operation(session, store, *, remove=False):
    plan, auth = planned_operation(session, remove=remove)
    class Adapter:
        post = None
        def read_current(self, p):
            return session.removal_current()[0] if remove else session.preflight().current_digest
        def dispatch(self, p):
            try:
                result = session.remove_under_m4(p, auth, store) if remove else session.create_under_m4(p, auth, store)
                self.post = result if remove else result.postcondition_digest
            except Exception: raise M4AdapterAmbiguous("Synthetic Owner operation is uncertain.") from None
        def read_postcondition(self, p): return self.post
    return M4ExecutionKernel(Adapter(), _Verifier(), store, clock=lambda:1000).execute(plan, auth), plan, auth


def test_kernel_owned_create_and_separate_remove_preserve_context_and_close(tmp_path, synthetic_key, monkeypatch):
    lab = Lab(tmp_path, synthetic_key, monkeypatch); create_store = lab.store("create"); remove_store = lab.store("remove")
    with lab.session() as session:
        created, _, _ = operation(session, create_store)
        assert created.outcome == "succeeded" and lab.request._closed and lab.posts == 1
        removed, _, _ = operation(session, remove_store, remove=True)
        assert removed.outcome == "succeeded" and lab.deletes == 1 and not lab.exists
    assert session.logout_verified and session.inspect_wire()["http_status"] == 200
    assert all(client.is_closed for client in lab.clients)


@pytest.mark.parametrize("fault", ["403", "timeout", "source-inflight"])
def test_uncertain_native_post_retains_original_response_and_never_reads_unowned_body(tmp_path, synthetic_key, monkeypatch, fault):
    lab = Lab(tmp_path, synthetic_key, monkeypatch, fault); store = lab.store("create")
    with lab.session() as session:
        result, plan, auth = operation(session, store)
        assert result.outcome == "reconciliation_required" and lab.posts == 1 and lab.full_reads == 0
        assert not (lab.wire / "create.ack.json").exists()
        with pytest.raises(Exception): session.create_under_m4(plan, auth, store)
        assert lab.posts == 1 and not (lab.wire / "remove.claim.json").exists()
    response = session.inspect_wire()
    assert response["http_status"] == (403 if fault == "403" else None if fault == "timeout" else 200)
    assert session.logout_verified


def test_original_ack_allows_independent_session_recovery_after_bad_post_without_adoption(tmp_path, synthetic_key, monkeypatch):
    lab = Lab(tmp_path, synthetic_key, monkeypatch, "bad-post")
    with lab.session() as first:
        result, _, _ = operation(first, lab.store("create"))
        assert result.outcome == "reconciliation_required" and (lab.wire / "create.ack.json").is_file()
    original = (lab.wire / "create.ack.json").read_bytes()
    lab.fault = "none"
    with lab.session() as recovery:
        removed, _, _ = operation(recovery, lab.store("remove"), remove=True)
        assert removed.outcome == "succeeded" and lab.posts == lab.deletes == 1
    assert (lab.wire / "create.ack.json").read_bytes() == original


@pytest.mark.parametrize("fault", ["closed-execution", "outside-kernel", "missing-source", "wrong-owner"])
def test_source_and_kernel_gates_precede_native_dispatch(tmp_path, synthetic_key, monkeypatch, fault):
    lab = Lab(tmp_path, synthetic_key, monkeypatch, fault); store = lab.store("create")
    if fault in {"missing-source", "wrong-owner"}:
        with pytest.raises(c.JwtManualKeyOwnerHttpError):
            with lab.session(guard=fault != "missing-source"): pass
    else:
        with lab.session(enabled=fault != "closed-execution") as session:
            if fault == "closed-execution":
                result, _, _ = operation(session, store); assert result.outcome == "reconciliation_required"
            else:
                plan, auth = planned_operation(session)
                store.claim(plan_ref=plan.plan_ref, requester_digest=plan.requester_digest,
                    idempotency_digest=plan.idempotency_digest,
                    authorization_digest=auth.authorization_digest,
                    context_digest=canonical_digest({"plan_digest":plan.plan_digest,
                        "authorization_digest":auth.authorization_digest,"revision":plan.revision}))
                with pytest.raises(Exception): session.create_under_m4(plan, auth, store)
    assert lab.posts == lab.deletes == 0 and not (lab.wire / "create.claim.json").exists()


def test_logout_failure_is_observable_and_never_keeps_the_client_open(tmp_path, synthetic_key, monkeypatch):
    lab = Lab(tmp_path, synthetic_key, monkeypatch, "logout-live")
    with lab.session(enabled=False) as session: session.preflight()
    assert not session.logout_verified and all(client.is_closed for client in lab.clients)


def test_interrupted_response_retains_custody_erases_partial_bytes_and_never_replays(tmp_path, synthetic_key, monkeypatch):
    lab = Lab(tmp_path, synthetic_key, monkeypatch, "interrupt"); store = lab.store("create")
    erased = []; zeroize = c._zeroize_mutable
    def observe(raw):
        if b"SYNTHETIC_PARTIAL_RESPONSE" in raw: erased.append(raw)
        zeroize(raw)
    monkeypatch.setattr(c, "_zeroize_mutable", observe)
    with lab.session() as session:
        with pytest.raises(KeyboardInterrupt): operation(session, store)
        assert lab.posts == 1 and lab.request._closed and erased and not any(erased[0])
        assert session.inspect_wire()["complete"] is False
        assert session.inspect_wire()["body_bytes"] > 0
        assert not (lab.wire / "create.ack.json").exists()
        plan = session._sealed("create.claim.json")["plan"]
        assert store.claim_count == 1 and lab.full_reads == 0
        assert plan["action_id"] == c.CREATE_ACTION
    assert session.logout_verified and all(client.is_closed for client in lab.clients)
