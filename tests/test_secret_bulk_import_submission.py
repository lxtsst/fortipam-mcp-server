"""Fixed private projection protocol; synthetic inputs, no deployed intake."""

import asyncio
from dataclasses import replace
import struct
import time

import pytest
from starlette.testclient import TestClient

from fortipam_mcp import secret_bulk_import_intake as intake
from fortipam_mcp import secret_bulk_import_submission as submission
from fortipam_mcp.reference_authority_sidecar import (
    UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings, create_reference_authority_sidecar_app,
)
from fortipam_mcp.secret_bulk_import_reference_eligibility import ReferenceOwnerFileEligibility
from test_secret_bulk_import_dependencies import catalog
from test_secret_bulk_import_intake import prepared
from test_secret_bulk_import_reference_eligibility import AUTHORITY, pinned, source
from test_secret_bulk_import_token_channel import setup, mock_client


def configured(tmp_path, monkeypatch, kind="csv"):
    fixture = setup(tmp_path)
    binding, options, _ = prepared(tmp_path, kind)
    channel = fixture["binding"]
    binding = replace(binding, issuer=channel.issuer, subject="operator", planning_resource=channel.planning_resource,
        intake_resource=channel.intake_resource, planning_client=fixture["planning_client"],
        intake_client=fixture["intake_client"], deployment_digest=channel.deployment_digest,
        workload_digest=channel.workload_digest, issued_at=channel.issued_at, expires_at=channel.expires_at)
    clocks = [int(time.time()), time.monotonic()]
    authority, kwargs, grant_kwargs, _ = source(tmp_path, binding, clocks)
    handle = authority.issue("owner-file-eligibility-reference-01", **grant_kwargs)
    remote = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(tmp_path / "reference.sock", AUTHORITY))
    transport = TestClient(create_reference_authority_sidecar_app(authority))
    monkeypatch.setattr(UnixReferenceAuthorityClient, "_post", lambda self, path, payload: transport.post(path, json=payload))
    kwargs["authority"] = remote
    checker = ReferenceOwnerFileEligibility(binding, **kwargs)
    pinned(tmp_path, binding, options, clocks, checker)
    fixture.update(owner_binding=binding, root_authority=authority, handle=handle, clocks=clocks,
                   options=dict(planning_verifier=mock_client(fixture, monkeypatch, planning=True),
                                intake_verifier=mock_client(fixture, monkeypatch), authority=options["authority"],
                                catalog=catalog(), clock=lambda: clocks[0], monotonic=lambda: clocks[1]),
                   reference_transport=transport)
    return fixture


def frame(fixture, password=b""):
    plan, private = fixture["planning_token"].encode(), fixture["intake_token"].encode()
    return submission._MAGIC + struct.pack("!HHH", len(plan), len(private), len(password)) + plan + private + password


def send(client, raw, **kwargs):
    return client.post(submission.PATH, content=raw, headers={"Content-Type": submission.CONTENT_TYPE}, **kwargs)


def test_submission_fixture_keeps_admission_and_permission_on_the_same_clock(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch)
    sample = intake._clock_sample
    # Reproduce the wall tick while the synthetic Authority remains fixed.
    monkeypatch.setattr(intake, '_clock_sample', lambda clock:
        float(fixture['clocks'][0] + 1) if clock is time.time else sample(clock))
    app = submission.create_owner_file_submission_app(fixture['owner_binding'], **fixture['options'])
    with fixture['reference_transport'], TestClient(app) as client:
        response = send(client, frame(fixture))
    assert response.status_code == 200 and response.json() == {'status': 'projected', 'rows': 1, 'targets': 1}


@pytest.mark.parametrize("kind", ["csv", "xlsm", "encrypted"])
def test_actual_authenticated_private_submission_returns_counts_once_and_clears(tmp_path, monkeypatch, capfd, kind):
    fixture = configured(tmp_path, monkeypatch, kind)
    owned = []
    wipe = submission._wipe
    monkeypatch.setattr(submission, "_wipe", lambda raw: (owned.append(raw), wipe(raw))[-1])
    app = submission.create_owner_file_submission_app(fixture["owner_binding"], **fixture["options"])
    with fixture["reference_transport"], TestClient(app) as client:
        response = send(client, frame(fixture, b"synthetic-password" if kind == "encrypted" else b""))
        assert response.status_code == 200
        assert response.json() == {"status": "projected", "rows": 1, "targets": 1}
        assert send(client, frame(fixture)).status_code == 409
        assert client.get(submission.PATH).status_code == 405
        assert client.post("/v1/owner-file-intake/upload", content=b"unused").status_code == 404
    assert owned and all(not any(raw) for raw in owned)
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("fault", ["revoked-grant", "revoked-token", "swapped-token", "bad-token", "expired-grant"])
def test_auth_failure_never_opens_prebound_source_and_reflects_no_private_input(tmp_path, monkeypatch, fault):
    fixture = configured(tmp_path, monkeypatch)
    app = submission.create_owner_file_submission_app(fixture["owner_binding"], **fixture["options"])
    if fault == "revoked-grant":
        fixture["root_authority"].revoke(fixture["handle"], now_epoch=fixture["clocks"][0])
    elif fault == "revoked-token":
        token = asyncio.run(fixture["issuer"].load_access_token(fixture["planning_token"]))
        asyncio.run(fixture["issuer"].revoke_token(token))
    elif fault == "swapped-token":
        fixture["planning_token"], fixture["intake_token"] = fixture["intake_token"], fixture["planning_token"]
    elif fault == "bad-token":
        fixture["intake_token"] = "synthetic-invalid-private-token"
    else:
        fixture["clocks"][0] = fixture["owner_binding"].expires_at
    monkeypatch.setattr(intake, "PinnedBulkImportFile", lambda *a, **k: pytest.fail("Unauthenticated source read"))
    with fixture["reference_transport"], TestClient(app) as client:
        response = send(client, frame(fixture, b"synthetic-private-unlock"))
    assert response.status_code == 409 and response.json() == {"status": "unavailable"}


@pytest.mark.parametrize("fault", ["magic", "token-size", "password-size", "suffix", "short", "ascii", "space",
                                  "query", "origin", "type", "encoding", "length"])
def test_bad_frame_denies_before_verifiers_or_source(tmp_path, monkeypatch, fault):
    fixture = configured(tmp_path, monkeypatch)
    app = submission.create_owner_file_submission_app(fixture["owner_binding"], **fixture["options"])
    raw = frame(fixture)
    if fault == "magic":
        raw = b"not-magic" + raw[9:]
    elif fault == "token-size":
        raw = raw[:8] + struct.pack("!HHH", 16385, 1, 0) + raw[14:]
    elif fault == "password-size":
        raw = frame(fixture, b"x" * 1025)
    elif fault == "suffix":
        raw += b"extra-private-field"
    elif fault == "short":
        raw = raw[:13]
    elif fault in ("ascii", "space"):
        raw = raw[:14] + (b"\xff" if fault == "ascii" else b" ") + raw[15:]
    monkeypatch.setattr(submission.UnixIntakeTokenVerifier, "verify_token", lambda *a: pytest.fail("Malformed frame reached auth"))
    headers = {"Content-Type": submission.CONTENT_TYPE}
    if fault == "origin":
        headers["Origin"] = "https://untrusted.example.invalid"
    elif fault == "type":
        headers["Content-Type"] = "application/json"
    elif fault == "encoding":
        headers["Content-Encoding"] = "gzip"
    elif fault == "length":
        headers["Content-Length"] = str(len(raw) + 1)
    with fixture["reference_transport"], TestClient(app) as client:
        response = client.post(submission.PATH + ("?path=other" if fault == "query" else ""), content=raw, headers=headers)
    assert response.status_code == 409 and response.json() == {"status": "unavailable"}


@pytest.mark.parametrize("fault", ["local-authority", "callback", "local-token-verifier", "same-purpose", "workload", "catalog"])
def test_private_workload_composition_denies_shared_or_mismatched_dependencies(tmp_path, monkeypatch, fault):
    fixture = configured(tmp_path, monkeypatch)
    options = fixture["options"]
    if fault == "local-authority":
        options["authority"]._human_owner_verifier._authority = fixture["root_authority"]
    elif fault == "callback":
        options["authority"]._human_owner_verifier = lambda *a: None
    elif fault == "local-token-verifier":
        from mcp.server.auth.provider import ProviderTokenVerifier
        options["planning_verifier"] = ProviderTokenVerifier(fixture["issuer"])
    elif fault == "same-purpose":
        options["intake_verifier"] = options["planning_verifier"]
    elif fault == "workload":
        fixture["owner_binding"] = replace(fixture["owner_binding"], workload_digest="9" * 64)
    else:
        options["catalog"] = replace(options["catalog"], scope_digest="9" * 64)
    with pytest.raises(intake.BulkImportIntakeError):
        submission.create_owner_file_submission_app(fixture["owner_binding"], **options)


def test_failed_decode_spends_live_projection_and_clears_unlock(tmp_path, monkeypatch):
    fixture = configured(tmp_path, monkeypatch, "encrypted")
    owned = []
    wipe = submission._wipe
    monkeypatch.setattr(submission, "_wipe", lambda raw: (owned.append(raw), wipe(raw))[-1])
    app = submission.create_owner_file_submission_app(fixture["owner_binding"], **fixture["options"])
    with fixture["reference_transport"], TestClient(app) as client:
        assert send(client, frame(fixture, b"wrong-synthetic-unlock")).status_code == 409
        assert send(client, frame(fixture, b"synthetic-password")).status_code == 409
    assert owned and all(not any(raw) for raw in owned)


@pytest.mark.parametrize("fault", ["duplicate-length", "missing-length", "duplicate-type", "transfer", "chunks", "deadline"])
def test_stream_bounds_clear_partial_input(tmp_path, monkeypatch, fault):
    from starlette.requests import Request
    fixture = configured(tmp_path, monkeypatch)
    raw = frame(fixture, b"synthetic-private-unlock")
    headers = [(b"content-type", submission.CONTENT_TYPE.encode()), (b"content-length", str(len(raw)).encode())]
    if fault == "duplicate-length":
        headers.append(headers[1])
    elif fault == "missing-length":
        headers.pop()
    elif fault == "duplicate-type":
        headers.append(headers[0])
    elif fault == "transfer":
        headers.append((b"transfer-encoding", b"chunked"))
    owned = []
    wipe = submission._wipe
    monkeypatch.setattr(submission, "_wipe", lambda value: (owned.append(value), wipe(value))[-1])
    async def run():
        count = 0
        async def receive():
            nonlocal count
            count += 1
            if fault == "deadline" and count > 1:
                await asyncio.Event().wait()
            return dict(type="http.request", body=raw[:1], more_body=True)
        request = Request(dict(type="http", method="POST", scheme="http", path=submission.PATH,
                               query_string=b"", headers=headers, server=("private-owner-intake", 80)), receive)
        with pytest.raises((ValueError, TimeoutError)):
            await submission._read_frame(request)
    asyncio.run(run())
    assert owned and all(not any(value) for value in owned)


def test_inflight_frame_rejects_concurrency_and_cancel_clears_then_unlocks(tmp_path, monkeypatch):
    from starlette.requests import Request
    fixture = configured(tmp_path, monkeypatch)
    app = submission.create_owner_file_submission_app(fixture["owner_binding"], **fixture["options"])
    endpoint = app.routes[0].endpoint
    raw = frame(fixture, b"synthetic-private-unlock")
    owned = []
    wipe = submission._wipe
    monkeypatch.setattr(submission, "_wipe", lambda value: (owned.append(value), wipe(value))[-1])
    async def run():
        entered = asyncio.Event()
        count = 0
        async def receive():
            nonlocal count
            count += 1
            if count == 1:
                return dict(type="http.request", body=raw[:20], more_body=True)
            entered.set()
            await asyncio.Event().wait()
        scope = dict(type="http", method="POST", scheme="http", path=submission.PATH, query_string=b"",
                     headers=[(b"content-type", submission.CONTENT_TYPE.encode()),
                              (b"content-length", str(len(raw)).encode())], server=("private-owner-intake", 80))
        active = asyncio.create_task(endpoint(Request(scope, receive)))
        await entered.wait()
        blocked = await endpoint(Request(scope, receive))
        assert blocked.status_code == 409
        active.cancel()
        with pytest.raises(asyncio.CancelledError):
            await active
        assert owned and all(not any(value) for value in owned)
        # The cancelled unauthenticated frame did not consume file admission.
        async def complete():
            return dict(type="http.request", body=frame(fixture), more_body=False)
        scope["headers"][1] = (b"content-length", str(len(frame(fixture))).encode())
        projected = await endpoint(Request(scope, complete))
        assert projected.status_code == 200
    with fixture["reference_transport"]:
        asyncio.run(run())
