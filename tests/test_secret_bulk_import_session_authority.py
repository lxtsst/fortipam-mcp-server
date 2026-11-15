"""Separate checkpoint-bound session grant, signed policy and ASGI ownership."""

import asyncio
from dataclasses import replace
import hashlib
import subprocess
import sys
import threading

import httpx
import pytest
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_session_authority as authority
from fortipam_mcp import secret_bulk_import_submission as submission
from fortipam_mcp.secret_bulk_import_intake import BulkImportIntakeError
from fortipam_mcp.secret_bulk_import_intake_authority import PinnedOwnerFileIntakeAuthority
from test_secret_bulk_import_submission import configured, frame, send


def session_permission(tmp_path, fixture, *, issue=True, changes=None):
    binding = fixture["owner_binding"]
    projection = fixture["options"]["authority"]._human_owner_verifier
    reference = "owner-file-source-session-reference-02"
    checker = authority.ReferenceOwnerFileSessionEligibility(binding,
        authority=projection._authority, authority_ref=projection._authority_ref,
        reference=reference, requester_digest=projection._requester,
        scope_key_path=projection._key.path, scope_key_sha256=projection._key.digest,
        clock=lambda: fixture["clocks"][0])
    grant = dict(reference_kind=authority.REFERENCE_KIND, requester_digest=checker._requester,
        environment_ref=checker._environment, scope_ref=checker._scope,
        now_epoch=fixture["clocks"][0], expires_at=binding.expires_at)
    if changes:
        grant.update(changes)
    handle = fixture["root_authority"].issue(reference, **grant) if issue else None
    key = tmp_path / "source-session-policy.key"
    key.write_bytes(b"s" * 32)
    key.chmod(0o600)
    settings = dict(policy_path=tmp_path / "source-session-policy.json", key_path=key,
        key_sha256=hashlib.sha256(b"s" * 32).hexdigest(), eligibility=checker,
        clock=lambda: fixture["clocks"][0], monotonic=lambda: fixture["clocks"][1])
    return settings, handle


def session_authority(tmp_path, fixture):
    settings, handle = session_permission(tmp_path, fixture)
    digest = authority.issue_prebound_owner_file_session_policy_once(fixture["owner_binding"], **settings)
    verifier = authority.PinnedOwnerFileSessionAuthority(fixture["owner_binding"],
        **{name: settings[name] for name in ("policy_path", "key_path", "key_sha256")}, policy_sha256=digest,
        human_owner_verifier=settings["eligibility"], clock=settings["clock"])
    return verifier, handle


@pytest.mark.parametrize("fault", ["projection-only", "wrong-kind", "wrong-scope", "wrong-requester"])
def test_projection_permission_cannot_issue_or_extend_a_source_session_policy(tmp_path, monkeypatch, fault):
    fixture = configured(tmp_path, monkeypatch, "encrypted")
    changes = {
        "wrong-kind": {"reference_kind": "owner_file_dependency_projection"},
        "wrong-scope": {"scope_ref": "owner-file-projection-other"},
        "wrong-requester": {"requester_digest": "8" * 64},
    }.get(fault)
    settings, _ = session_permission(tmp_path, fixture, issue=fault != "projection-only", changes=changes)
    with fixture["reference_transport"], pytest.raises(BulkImportIntakeError):
        authority.issue_prebound_owner_file_session_policy_once(fixture["owner_binding"], **settings)
    assert not settings["policy_path"].exists()


def test_session_cap_uses_verified_decision_not_the_longer_policy_expiry(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch, "encrypted")
    now = fixture["clocks"][0]
    with fixture["reference_transport"]:
        verifier, _ = session_authority(tmp_path, fixture)
        verifier.verify_source_session(fixture["owner_binding"], now_epoch=now)
        assert now < verifier.source_session_expires_at(fixture["owner_binding"], now_epoch=now) <= now + 60
        assert verifier.source_session_expires_at(fixture["owner_binding"], now_epoch=now) < fixture["owner_binding"].expires_at


def test_short_source_grant_caps_idle_session_instead_of_inheriting_policy_lifetime(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch, "encrypted")
    sessions = capture_sessions(monkeypatch)
    now = fixture["clocks"][0]
    with fixture["reference_transport"]:
        settings, _ = session_permission(tmp_path, fixture, changes={"expires_at": now + 2})
        digest = authority.issue_prebound_owner_file_session_policy_once(fixture["owner_binding"], **settings)
        verifier = authority.PinnedOwnerFileSessionAuthority(fixture["owner_binding"],
            **{name: settings[name] for name in ("policy_path", "key_path", "key_sha256")}, policy_sha256=digest,
            human_owner_verifier=settings["eligibility"], clock=settings["clock"])
        app = submission.create_owner_file_session_submission_app(fixture["owner_binding"],
            session_authority=verifier, **fixture["options"])
        with TestClient(app) as client:
            assert send(client, frame(fixture, b"synthetic-password")).status_code == 200
            assert sessions[0]._transaction._expires == now + 2
            fixture["clocks"][0] = now + 2
            sessions[0]._watchdog.join(1)
            assert not sessions[0]._watchdog.is_alive() and not any(sessions[0]._password)


def test_separate_policy_is_exact_exclusive_revocable_and_not_a_projection_policy(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch, "encrypted")
    with fixture["reference_transport"]:
        verifier, handle = session_authority(tmp_path, fixture)
        binding = fixture["owner_binding"]
        verifier.verify_source_session(binding, now_epoch=fixture["clocks"][0])
        before = verifier._policy.read_bytes()
        settings = dict(policy_path=verifier._policy, key_path=verifier._key, key_sha256=verifier._key_digest,
            eligibility=verifier._human_owner_verifier, clock=lambda: fixture["clocks"][0])
        with pytest.raises(BulkImportIntakeError):
            authority.issue_prebound_owner_file_session_policy_once(binding, **settings)
        assert verifier._policy.read_bytes() == before
        with pytest.raises(BulkImportIntakeError):
            PinnedOwnerFileIntakeAuthority(binding, policy_path=verifier._policy, key_path=verifier._key,
                policy_sha256=verifier._policy_digest, key_sha256=verifier._key_digest,
                human_owner_verifier=verifier._human_owner_verifier)
        with pytest.raises(BulkImportIntakeError):
            verifier.verify_source_session(replace(binding, workload_digest="8" * 64), now_epoch=fixture["clocks"][0])
        fixture["root_authority"].revoke(handle, now_epoch=fixture["clocks"][0])
        with pytest.raises(BulkImportIntakeError):
            verifier.verify_source_session(binding, now_epoch=fixture["clocks"][0])


def test_projection_policy_and_eligibility_cannot_be_used_as_session_authority(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch, "encrypted")
    projection = fixture["options"]["authority"]
    with pytest.raises(BulkImportIntakeError):
        submission.create_owner_file_session_submission_app(fixture["owner_binding"],
            session_authority=projection, **fixture["options"])
    with pytest.raises(BulkImportIntakeError):
        authority.PinnedOwnerFileSessionAuthority(fixture["owner_binding"], policy_path=projection._policy,
            key_path=projection._key, policy_sha256=projection._policy_digest, key_sha256=projection._key_digest,
            human_owner_verifier=projection._human_owner_verifier)


def capture_sessions(monkeypatch):
    sessions = []
    original = submission.admit_prebound_owner_file_session
    async def capture(*args, **kwargs):
        session = await original(*args, **kwargs)
        sessions.append(session)
        return session
    monkeypatch.setattr(submission, "admit_prebound_owner_file_session", capture)
    return sessions


@pytest.mark.parametrize("exit_kind", ["shutdown", "idle-expiry"])
def test_fixed_application_owns_and_disposes_retained_unlock(tmp_path, monkeypatch, exit_kind, capfd):
    fixture = configured(tmp_path, monkeypatch, "encrypted")
    sessions = capture_sessions(monkeypatch)
    with fixture["reference_transport"]:
        verifier, _ = session_authority(tmp_path, fixture)
        app = submission.create_owner_file_session_submission_app(fixture["owner_binding"],
            session_authority=verifier, **fixture["options"])
        with TestClient(app) as client:
            response = send(client, frame(fixture, b"synthetic-password"))
            assert response.status_code == 200 and response.json() == {"status": "projected", "rows": 1, "targets": 1}
            assert len(sessions) == 1 and any(sessions[0]._password)
            assert send(client, frame(fixture, b"synthetic-password")).status_code == 409
            if exit_kind == "idle-expiry":
                fixture["clocks"][1] += 901
                sessions[0]._watchdog.join(1)
                assert not any(sessions[0]._password)
        assert not any(sessions[0]._password) and not sessions[0]._watchdog.is_alive()
    assert capfd.readouterr() == ("", "")


def test_session_application_without_lifespan_denies_before_admission(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch, "encrypted")
    with fixture["reference_transport"]:
        verifier, _ = session_authority(tmp_path, fixture)
        app = submission.create_owner_file_session_submission_app(fixture["owner_binding"],
            session_authority=verifier, **fixture["options"])
        async def forbidden(*args, **kwargs):
            pytest.fail("Session admitted without owning lifespan")
        monkeypatch.setattr(submission, "admit_prebound_owner_file_session", forbidden)
        client = TestClient(app)
        assert send(client, frame(fixture, b"synthetic-password")).status_code == 409
        client.close()


def test_revoked_source_session_grant_denies_before_source_pin(tmp_path, monkeypatch):
    from fortipam_mcp import secret_bulk_import_intake as intake
    fixture = configured(tmp_path, monkeypatch, "encrypted")
    with fixture["reference_transport"]:
        verifier, handle = session_authority(tmp_path, fixture)
        app = submission.create_owner_file_session_submission_app(fixture["owner_binding"],
            session_authority=verifier, **fixture["options"])
        fixture["root_authority"].revoke(handle, now_epoch=fixture["clocks"][0])
        monkeypatch.setattr(intake, "PinnedBulkImportFile", lambda *args, **kwargs: pytest.fail("Revoked session read source"))
        with TestClient(app) as client:
            response = send(client, frame(fixture, b"synthetic-password"))
            assert response.status_code == 409 and response.json() == {"status": "unavailable"}


def test_cancelled_request_kills_active_parser_and_clears_session(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch, "encrypted")
    sessions = capture_sessions(monkeypatch)
    entered, children = threading.Event(), []
    original_spawn = subprocess.Popen
    def stalled(argv, **kwargs):
        child = original_spawn([sys.executable, "-I", "-c", "import time; time.sleep(60)"], **kwargs)
        children.append(child)
        entered.set()
        return child
    monkeypatch.setattr(subprocess, "Popen", stalled)
    with fixture["reference_transport"]:
        verifier, _ = session_authority(tmp_path, fixture)
        app = submission.create_owner_file_session_submission_app(fixture["owner_binding"],
            session_authority=verifier, **fixture["options"])
        async def run():
            async with app.router.lifespan_context(app):
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://candidate") as client:
                    task = asyncio.create_task(client.post(submission.PATH, content=frame(fixture, b"synthetic-password"),
                        headers={"Content-Type": submission.CONTENT_TYPE}))
                    try:
                        assert await asyncio.to_thread(entered.wait, 2)
                        task.cancel()
                        with pytest.raises(asyncio.CancelledError):
                            await task
                        assert sessions and not any(sessions[0]._password)
                    finally:
                        task.cancel()
                        for session in sessions:
                            session.close()
            for child in children:
                await asyncio.to_thread(child.wait, 2)
        asyncio.run(run())
    assert children and all(child.poll() is not None for child in children)
    assert all(not session._watchdog.is_alive() for session in sessions)


def test_response_delivery_failure_disposes_retained_session(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch, "encrypted")
    sessions = capture_sessions(monkeypatch)
    with fixture["reference_transport"]:
        verifier, _ = session_authority(tmp_path, fixture)
        app = submission.create_owner_file_session_submission_app(fixture["owner_binding"],
            session_authority=verifier, **fixture["options"])
        raw = frame(fixture, b"synthetic-password")
        scope = dict(type="http", http_version="1.1", scheme="http", method="POST", path=submission.PATH,
            raw_path=submission.PATH.encode(), query_string=b"", server=("candidate", 80), client=("local", 1),
            headers=[(b"content-type", submission.CONTENT_TYPE.encode()), (b"content-length", str(len(raw)).encode())])
        async def receive():
            return dict(type="http.request", body=raw, more_body=False)
        async def failed_send(message):
            raise asyncio.CancelledError
        async def run():
            async with app.router.lifespan_context(app):
                with pytest.raises(asyncio.CancelledError):
                    await app(scope, receive, failed_send)
                assert len(sessions) == 1 and not any(sessions[0]._password)
        asyncio.run(run())
