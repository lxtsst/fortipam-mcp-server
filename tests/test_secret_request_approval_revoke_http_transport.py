from copy import deepcopy
from dataclasses import asdict, FrozenInstanceError
from datetime import timedelta
from email.utils import format_datetime
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from fortipam_mcp.secret_request_approval_revoke_http_transport import (
    FortiPamSecretRequestApprovalRevokeHttpTransport,
    SecretRequestApprovalRevokeHttpTransportError,
    SecretRequestApprovalRevokeInspection,
)
from test_secret_request_approval_revoke_detail_contract import _BINDING, _Clock, _NOW, _payload, _relation_payloads

_KEY = b"synthetic-independent-claim-key-32"


class _Lab:
    def __init__(self, path: Path, *, case: str = "ordinary") -> None:
        path.chmod(0o700)
        self.claim = path / "claim.json"
        self.case, self.request = case, _payload()
        self.secret, self.profile = _relation_payloads()
        self.role: dict[str, Any] = {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
                     "vdom": "root", "path": "system", "name": "admin", "status": "success",
                     "serial": "SYNTHETIC29", "mkey": "synthetic-reviewer",
                     "results": [{"name": "synthetic-reviewer", "q_origin_key": "synthetic-reviewer",
                                  "accprofile": "super_admin", "status": "enable",
                                  "remote-auth": "disable", "wildcard": "disable"}]}
        self.calls: list[tuple[str, str]] = []
        self.deletes: list[bytes] = []
        self.logout = False
        self.credentials_read = 0
        self.profile_date = _NOW
        self.config = SecretMetadataHttpTransportConfig("https://synthetic.invalid", "unused-token", 1, None)

    def credentials(self) -> tuple[str, str]:
        self.credentials_read += 1
        return "synthetic-reviewer", "synthetic-password"

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        self.calls.append((request.method, path))
        if path == "/remote/login":
            return httpx.Response(200, text='<form action="/XX/YY/ZZ/AUTH">')
        if path == "/XX/YY/ZZ/AUTH":
            self.logout = False
            return httpx.Response(303, headers={"Location": "/", "Set-Cookie": 'csrf="synthetic-csrf"; Path=/'})
        if path == "/logout":
            self.logout = True
            if self.case == "logout_cookie_only":
                return httpx.Response(200, headers={"Set-Cookie": "csrf=; Max-Age=0; Path=/"})
            return httpx.Response(200)
        if path == "/api/v2/monitor/web-ui/state":
            retained_session_live = self.case == "logout_cookie_only" and "csrf=" in request.headers.get("Cookie", "")
            if self.logout and self.case != "logout_live" and not retained_session_live:
                return httpx.Response(401)
            return httpx.Response(200, json={
                "http_method": "GET", "status": "success", "version": "v7.0.0", "build": 29,
                "path": "web-ui", "name": "state", "vdom": "root", "serial": "SYNTHETIC29",
                "results": {"admin": {"name": "other" if self.case == "wrong_actor" else "synthetic-reviewer",
                            "login_name": "synthetic-reviewer", "sponsored_group_name": "", "guest_admin": False},
                            "ccsrf_token_cookie_name": "csrf",
                            "unrelated": "SYNTHETIC_UNRELATED_STATE_DO_NOT_DECODE"},
            })
        if path == "/api/v2/cmdb/system/admin/synthetic-reviewer":
            assert request.method == "GET"
            assert request.url.query == b"format=name%7Caccprofile%7Cstatus%7Cremote-auth%7Cwildcard"
            return httpx.Response(200, json=self.role)
        if request.method == "DELETE":
            assert path == "/api/v2/internal/request-review/19"
            assert self.claim.exists() and self.claim.stat().st_mode & 0o777 == 0o600
            assert request.headers["X-CSRFTOKEN"] == "synthetic-csrf"
            assert json.loads(request.content) == {"request-id": 19, "tier": 1}
            self.deletes.append(request.content)
            # Unknown post-change grammar is preserved, never mapped to success.
            self.request["results"][0]["final-status"] = "unqualified-post-state"
            if self.case == "timeout":
                raise httpx.ReadTimeout("synthetic private timeout")
            if self.case == "non_json_ack":
                return httpx.Response(200, text="unsafe unqualified ACK")
            if self.case == "duplicate_ack":
                return httpx.Response(200, content=b'{"opaque":1,"opaque":1}', headers={"content-type": "application/json"})
            return httpx.Response(403 if self.case == "refused" else 201 if self.case == "created_ack" else 200, json={
                "opaque": "unqualified ACK", "field": [{"value": "SYNTHETIC_MATERIAL"}],
                "keyinfo": "SYNTHETIC_MATERIAL", "shared-key": "SYNTHETIC_MATERIAL",
            })
        metadata = {"/api/v2/cmdb/secret/request/19": self.request,
                    "/api/v2/cmdb/secret/database/7": self.secret,
                    "/api/v2/cmdb/secret/approval-profile/synthetic-original-profile": self.profile}
        if path in metadata:
            assert request.url.query == b"with_meta=true&vdom=root"
            payload = deepcopy(metadata[path])
            row = payload["results"][0]
            if self.case == "material":
                if "approval-profile/" not in path:
                    row["field"] = [{"value": "SYNTHETIC_MATERIAL"}]
                row["keyinfo"] = "SYNTHETIC_MATERIAL"
            date = self.profile_date if "approval-profile/" in path else _NOW
            response = httpx.Response(200, json=payload, headers={"Date": format_datetime(date, usegmt=True)})
            if self.case == "secret_duplicate" and path.endswith("database/7"):
                raw = response.content.replace(b'"id":7', b'"id":7,"opaque":1,"opaque":1', 1)
                return httpx.Response(200, content=raw, headers=response.headers)
            return response
        return httpx.Response(200)

    def factory(self, **kwargs: Any) -> httpx.Client:
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        assert kwargs["verify"].check_hostname is True
        return httpx.Client(**kwargs, transport=httpx.MockTransport(self.handler))

    def transport(self, *, enabled: bool = True) -> FortiPamSecretRequestApprovalRevokeHttpTransport:
        return FortiPamSecretRequestApprovalRevokeHttpTransport(
            self.config, _BINDING, self.credentials, claim_path=self.claim, hmac_key=_KEY,
            execution_enabled=enabled, client_factory=self.factory,
        )


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("fortipam_mcp.secret_request_http_transport.datetime", _Clock)


def test_withdrawal_inspect_has_no_delete_or_claim(tmp_path: Path) -> None:
    lab = _Lab(tmp_path)
    result = lab.transport(enabled=False).inspect()
    assert isinstance(result, SecretRequestApprovalRevokeInspection)
    assert not lab.deletes and not lab.claim.exists() and lab.logout
    assert "synthetic" not in repr(result)
    with pytest.raises(FrozenInstanceError):
        setattr(result, "detail", None)


def test_withdrawal_gate_closed_before_session(tmp_path: Path) -> None:
    lab = _Lab(tmp_path)
    expected = lab.transport().inspect()
    lab.calls.clear()
    lab.credentials_read = 0
    with pytest.raises(SecretRequestApprovalRevokeHttpTransportError) as error:
        lab.transport(enabled=False).execute(expected)
    assert error.value.stage == "gate"
    assert lab.calls == [] and lab.credentials_read == 0 and not lab.claim.exists()


@pytest.mark.parametrize("drift", ["request", "secret", "profile", "expired", "wrong_actor", "unsafe_profile"])
def test_withdrawal_drift_and_expiry_refuse_before_delete(tmp_path: Path, drift: str) -> None:
    lab = _Lab(tmp_path)
    transport = lab.transport()
    expected = transport.inspect()
    if drift in {"request", "secret", "profile"}:
        getattr(lab, drift)["results"][0]["extra-metadata"] = "drift"
    elif drift == "expired":
        lab.request["results"][0]["expiration-time"] = "2026-10-08 19:59:59"
    elif drift == "unsafe_profile":
        lab.profile["results"][0]["field"] = [{"value": "SYNTHETIC_MATERIAL"}]
    else:
        lab.case = drift
    with pytest.raises(SecretRequestApprovalRevokeHttpTransportError):
        transport.execute(expected)
    assert not lab.deletes and not lab.claim.exists() and lab.logout


@pytest.mark.parametrize("case", ["ordinary", "timeout", "refused", "created_ack", "non_json_ack", "duplicate_ack", "material", "secret_duplicate"])
def test_withdrawal_claim_once_unknown_sources_and_replay_refusal(tmp_path: Path, case: str) -> None:
    lab = _Lab(tmp_path, case=case)
    transport = lab.transport()
    expected = transport.inspect()
    result = transport.execute(expected)
    assert result.dispatch_consumed and result.reviewer_logout_verified
    assert result.reconciliation_required and result.source_qualification_only
    assert result.http_status_class == ("none" if case == "timeout" else "4xx" if case == "refused" else "2xx")
    assert result.private_ack_http_status == (None if case == "timeout" else 403 if case == "refused" else 201 if case == "created_ack" else 200)
    assert result.ack_source_safe == (case not in {"timeout", "non_json_ack", "duplicate_ack"})
    assert result.private_post_source is not None
    post = result.private_post_source
    assert all(source is not None for source in (post.request_metadata, post.secret_metadata, post.profile_metadata))
    assert post.request_metadata is not None and b"unqualified-post-state" in post.request_metadata
    assert "unqualified" not in repr(result) and "synthetic" not in repr(post)
    assert not hasattr(result, "accepted") and not hasattr(result, "revoked")
    if result.private_ack_metadata is not None:
        assert b"SYNTHETIC_MATERIAL" not in result.private_ack_metadata
    claim = json.loads(lab.claim.read_text())
    assert set(claim) == {"contract", "retry_allowed", "intent_binding_hmac"}
    assert claim["retry_allowed"] is False
    exact = json.dumps({"contract": claim["contract"], "origin": lab.config.base_url,
                        "binding": asdict(_BINDING), "inspection": asdict(expected), "method": "DELETE",
                        "body": {"request-id": 19, "tier": 1}}, sort_keys=True,
                       separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert hmac.compare_digest(claim["intent_binding_hmac"], hmac.new(_KEY, exact, hashlib.sha256).hexdigest())
    count, credentials = len(lab.calls), lab.credentials_read
    for candidate in (transport, lab.transport()):
        with pytest.raises(SecretRequestApprovalRevokeHttpTransportError):
            candidate.execute(expected)
    assert len(lab.calls) == count and lab.credentials_read == credentials and len(lab.deletes) == 1


def test_withdrawal_logout_failure_is_not_acceptance(tmp_path: Path) -> None:
    lab = _Lab(tmp_path)
    transport = lab.transport()
    expected = transport.inspect()
    lab.case = "logout_live"
    result = transport.execute(expected)
    assert result.dispatch_consumed and not result.reviewer_logout_verified
    assert result.failure_stage == "logout" and result.reconciliation_required


def test_withdrawal_cookie_removal_does_not_prove_session_revocation(tmp_path: Path) -> None:
    lab = _Lab(tmp_path, case="logout_cookie_only")
    with pytest.raises(SecretRequestApprovalRevokeHttpTransportError):
        lab.transport(enabled=False).inspect()
    assert lab.logout and not lab.deletes and not lab.claim.exists()


def test_withdrawal_all_value_decoders_receive_redacted_material(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lab = _Lab(tmp_path, case="material")
    loads = json.loads

    def safe_loads(value: Any, *args: Any, **kwargs: Any) -> Any:
        assert "SYNTHETIC_MATERIAL" not in str(value)
        assert "SYNTHETIC_UNRELATED_STATE_DO_NOT_DECODE" not in str(value)
        return loads(value, *args, **kwargs)

    monkeypatch.setattr(json, "loads", safe_loads)
    transport = lab.transport()
    result = transport.execute(transport.inspect())
    assert result.ack_source_safe and result.private_post_source is not None
    assert "SYNTHETIC_MATERIAL" not in repr(result)


def test_withdrawal_owner_only_parent_and_symlink_claim(tmp_path: Path) -> None:
    lab = _Lab(tmp_path)
    tmp_path.chmod(0o755)
    with pytest.raises(SecretRequestApprovalRevokeHttpTransportError):
        lab.transport()
    tmp_path.chmod(0o700)
    lab.claim.symlink_to(tmp_path / "absent")
    with pytest.raises(SecretRequestApprovalRevokeHttpTransportError):
        lab.transport().inspect()
    assert not lab.calls and not lab.credentials_read


def test_withdrawal_window_rechecked_against_final_read_date(tmp_path: Path) -> None:
    lab = _Lab(tmp_path)
    lab.request["results"][0]["expiration-time"] = "2026-10-08 20:00:10"
    transport = lab.transport()
    expected = transport.inspect()
    # Request Date and all metadata still match; expiry occurs during later reads.
    lab.profile_date = _NOW + timedelta(seconds=11)
    with pytest.raises(SecretRequestApprovalRevokeHttpTransportError):
        transport.execute(expected)
    assert not lab.deletes and not lab.claim.exists() and lab.logout


@pytest.mark.parametrize("kind,raw", [
    ("request", b'{"field":[{"value":"a","value":"a"}]}'),
    ("profile", b'{"results":[{"field":[],"opaque":1,"opaque":1}]}'),
    ("secret", b'{"results":[{"id":7,"id":7}]}'),
    ("secret", b'{"results":[{"opaque":1,"opaque":2}]}'),
    ("secret", b'{"results":[{"opaque":1,"opaque":1,"other":2,"other":2}]}'),
    ("ack", b'{"field":[{"value":"a","value":"a"}]}'),
    ("ack", b'{"field":[{"value":invalid}]}'),
    ("ack", b'{}' + b' ' * 1_048_576),
])
def test_withdrawal_reader_rejects_unsafe_source_before_decode(kind: str, raw: bytes) -> None:
    with pytest.raises(Exception):
        FortiPamSecretRequestApprovalRevokeHttpTransport._safe_source(
            httpx.Response(200, content=raw, headers={"content-type": "application/json"}), kind=kind,
        )


def test_withdrawal_ack_stream_timeout_preserves_status_closes_and_never_resends(tmp_path: Path) -> None:
    lab = _Lab(tmp_path)
    closed: list[bool] = []

    class BrokenAck(httpx.SyncByteStream):
        def __iter__(self) -> Any:
            yield b'{"partial":'
            raise httpx.ReadTimeout("synthetic private ACK stream failure")

        def close(self) -> None:
            closed.append(True)

    original_handler = lab.handler

    def handler(request: httpx.Request) -> httpx.Response:
        response = original_handler(request)
        if request.method == "DELETE":
            return httpx.Response(200, stream=BrokenAck(), headers={"content-type": "application/json"})
        return response

    lab.handler = handler  # type: ignore[method-assign]
    transport = lab.transport()
    expected = transport.inspect()
    result = transport.execute(expected)
    assert result.dispatch_consumed and result.private_ack_http_status == 200
    assert not result.ack_source_safe and result.private_ack_metadata is None
    assert result.failure_stage == "ack_source" and result.private_post_source is not None
    assert result.reviewer_logout_verified and closed == [True]
    count = len(lab.calls)
    with pytest.raises(SecretRequestApprovalRevokeHttpTransportError):
        lab.transport().execute(expected)
    assert len(lab.calls) == count and len(lab.deletes) == 1


def test_withdrawal_exclusive_reservation_race_has_zero_delete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lab = _Lab(tmp_path)
    transport = lab.transport()
    expected = transport.inspect()
    reserve = transport._reserve

    def racing_reserve(inspection: Any, body: Any) -> None:
        lab.claim.write_bytes(b"synthetic concurrent reservation")
        lab.claim.chmod(0o600)
        reserve(inspection, body)

    monkeypatch.setattr(transport, "_reserve", racing_reserve)
    with pytest.raises(SecretRequestApprovalRevokeHttpTransportError) as error:
        transport.execute(expected)
    assert error.value.stage == "claim_reserve"
    assert not lab.deletes and lab.logout


@pytest.mark.parametrize("phase", ["inspect", "execute"])
@pytest.mark.parametrize("change", ["name", "origin", "profile", "status", "remote", "wildcard",
                                    "serial", "build", "boolean_build", "mkey", "extra_row"])
def test_withdrawal_same_session_owner_role_refuses_drift_before_claim(
    tmp_path: Path, phase: str, change: str,
) -> None:
    lab = _Lab(tmp_path)
    transport = lab.transport()
    expected = transport.inspect() if phase == "execute" else None
    row = lab.role["results"][0]
    changes: dict[str, tuple[dict[str, Any], str, object]] = {
        "name": (row, "name", "other"), "origin": (row, "q_origin_key", "other"),
        "profile": (row, "accprofile", "other"), "status": (row, "status", "disable"),
        "remote": (row, "remote-auth", "enable"), "wildcard": (row, "wildcard", "enable"),
        "serial": (lab.role, "serial", "OTHER"), "build": (lab.role, "build", 30),
        "boolean_build": (lab.role, "build", True), "mkey": (lab.role, "mkey", "other"),
        "extra_row": (row, "unknown", "extra"),
    }
    target, key, value = changes[change]
    target[key] = value
    with pytest.raises(SecretRequestApprovalRevokeHttpTransportError) as error:
        if expected is None:
            transport.inspect()
        else:
            transport.execute(expected)
    assert error.value.stage == "reviewer_role"
    assert not lab.deletes and not lab.claim.exists() and lab.logout
    assert lab.calls[-3:] == [("GET", "/api/v2/cmdb/system/admin/synthetic-reviewer"),
                             ("GET", "/logout"), ("GET", "/api/v2/monitor/web-ui/state")]


@pytest.mark.parametrize("categorical", [False, True])
@pytest.mark.parametrize("case", ["qualified", "retained_marker", "revision_transition", "revision_and_post_drift",
                                  "wrong_ack", "post_drift", "relation_drift", "logout_live"])
def test_qualified_sources_still_require_runtime_authority(tmp_path: Path, case: str, categorical: bool) -> None:
    lab = _Lab(tmp_path)
    row = lab.request["results"][0]
    row.update({"tier-last-sent": 1, "tier2-status": "pending", "tier3-status": "pending"})
    original_handler = lab.handler

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method != "DELETE":
            return original_handler(request)
        original_handler(request)
        row.update({"final-status": "pending", "tier1-status": "pending", "tier1": [],
                    "start-time": "0000-00-00 00:00:00", "expiration-time": "0000-00-00 00:00:00",
                    "tier-last-sent": 1 if case == "retained_marker" else 0})
        if case in {"revision_transition", "revision_and_post_drift"}:
            lab.request["revision"] = "synthetic-post-revision"
        if case in {"post_drift", "revision_and_post_drift"}:
            row["comments"] = "unexpected concurrent mutation"
        if case == "relation_drift":
            lab.secret["results"][0]["unexpected"] = "drift"
        return httpx.Response(200, json={"status": "OK", "http_status": 200,
            "http_method": "DELETE", "vdom": "", "path": "secret", "name": "request-approval",
            "msg": "unknown" if case == "wrong_ack" else "Successfully deleted approval entry"})

    lab.handler = handler  # type: ignore[method-assign]
    transport = lab.transport()
    expected = transport.inspect()
    if case == "logout_live":
        lab.case = "logout_live"
    if categorical:
        readback = transport.withdraw_and_readback(expected)
        assert readback.http_accepted is (case != "wrong_ack")
        assert readback.pending_and_metadata_preserved is (case not in {"post_drift", "relation_drift", "revision_and_post_drift"})
        assert readback.reconciliation_required is (case not in {"qualified", "retained_marker", "revision_transition"})
        assert readback.reviewer_logout_verified is (case != "logout_live")
        assert set(asdict(readback)) == {"dispatch_consumed", "http_accepted",
            "pending_and_metadata_preserved", "reviewer_logout_verified", "reconciliation_required"}
        diagnostics = transport.withdrawal_diagnostics
        assert diagnostics is not None
        assert diagnostics.dispatch_consumed and diagnostics.ack_source_safe
        assert diagnostics.http_status_class == "2xx" and diagnostics.ack_http_status == 200
        assert diagnostics.ack_contract_qualified is (case != "wrong_ack")
        assert diagnostics.post_contract_qualified is (case not in {"post_drift", "relation_drift", "revision_and_post_drift"})
        assert diagnostics.reviewer_logout_verified is (case != "logout_live")
        assert diagnostics.failure_stage == ("logout" if case == "logout_live" else "none")
        assert "synthetic" not in repr(diagnostics) and "Successfully" not in repr(diagnostics)
        with pytest.raises(FrozenInstanceError):
            setattr(diagnostics, "ack_http_status", 201)
        with pytest.raises(SecretRequestApprovalRevokeHttpTransportError):
            transport.withdraw_and_readback(expected)
        assert transport.withdrawal_diagnostics is diagnostics
    else:
        result = transport.execute(expected)
        assert result.ack_contract_qualified is (case != "wrong_ack")
        assert result.post_contract_qualified is (case not in {"post_drift", "relation_drift", "revision_and_post_drift"})
        assert result.source_qualification_only and result.reconciliation_required
        assert result.reviewer_logout_verified is (case != "logout_live")
    assert len(lab.deletes) == 1
    with pytest.raises(SecretRequestApprovalRevokeHttpTransportError):
        transport.execute(transport.inspect())
    assert len(lab.deletes) == 1


@pytest.mark.parametrize("expiry_stage", ["entry", "read", "reserved"])
def test_authorization_expiry_at_device_boundary_never_sends_delete(tmp_path, monkeypatch, expiry_stage):
    lab = _Lab(tmp_path)
    transport = lab.transport()
    expected = transport.inspect()
    now = [10.0 if expiry_stage == "entry" else 0.0]
    monkeypatch.setattr("fortipam_mcp.secret_request_approval_revoke_http_transport.time.time", lambda: now[0])
    original_handler = lab.handler
    def handler(request):
        response = original_handler(request)
        if expiry_stage == "read" and request.url.path.endswith("approval-profile/synthetic-original-profile"):
            now[0] = 10.0
        return response
    lab.handler = handler
    reserve = transport._reserve
    def reserve_and_expire(*args):
        reserve(*args)
        now[0] = 10.0
    if expiry_stage == "reserved":
        monkeypatch.setattr(transport, "_reserve", reserve_and_expire)
        result = transport.withdraw_and_readback(expected, authorization_expires_at=10.0)
        assert result.dispatch_consumed and result.reconciliation_required
        assert lab.claim.exists()
    else:
        with pytest.raises(SecretRequestApprovalRevokeHttpTransportError):
            transport.withdraw_and_readback(expected, authorization_expires_at=10.0)
        assert not lab.claim.exists()
    assert not lab.deletes


@pytest.mark.parametrize("case,stage,status", [("timeout", "delete", None),
                                               ("non_json_ack", "ack_source", 200)])
def test_withdrawal_diagnostics_retain_consumed_failure_without_private_sources(
    tmp_path: Path, case: str, stage: str, status: int | None,
) -> None:
    lab = _Lab(tmp_path, case=case)
    transport = lab.transport()
    assert transport.withdrawal_diagnostics is None
    expected = transport.inspect()
    assert transport.withdrawal_diagnostics is None
    result = transport.withdraw_and_readback(expected)
    assert result.dispatch_consumed and result.reconciliation_required
    diagnostics = transport.withdrawal_diagnostics
    assert diagnostics is not None
    assert diagnostics.failure_stage == stage and diagnostics.ack_http_status == status
    assert not diagnostics.ack_source_safe and not diagnostics.ack_contract_qualified
    assert not diagnostics.post_contract_qualified and diagnostics.reviewer_logout_verified
    assert all(type(value) in (bool, int, str, type(None)) for value in asdict(diagnostics).values())
    with pytest.raises(SecretRequestApprovalRevokeHttpTransportError):
        transport.withdraw_and_readback(expected)
    assert transport.withdrawal_diagnostics is diagnostics
    assert len(lab.deletes) == 1
