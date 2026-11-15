"""Synthetic private admission guards; no deployed intake or real credentials."""

import asyncio
import copy
from dataclasses import replace
import hashlib
import pickle
import threading
import time
from types import SimpleNamespace

import pytest
from mcp.server.auth.provider import AccessToken

from fortipam_mcp import secret_bulk_import_intake as intake
from test_secret_bulk_import_file import csv_bytes, encrypted_bytes, private_file, workbook_bytes
from test_secret_bulk_import_dependencies import catalog, item


class Verifier:
    def __init__(self, binding, planning):
        self.calls = []
        self.result = AccessToken(
            token="synthetic", client_id=binding.planning_client if planning else binding.intake_client,
            scopes=["fortipam:plan" if planning else intake._INTAKE_SCOPE],
            expires_at=1100, resource=binding.planning_resource if planning else binding.intake_resource,
            subject=binding.subject, claims={"iss": binding.issuer, "sub": binding.subject,
                "client_id": binding.planning_client if planning else binding.intake_client},
        )

    async def verify_token(self, token):
        self.calls.append(token)
        return self.result


class Authority:
    def __init__(self, binding):
        self.binding, self.calls, self.denied = binding, 0, False

    def verify(self, binding, *, now_epoch):
        self.calls += 1
        if self.denied or binding != self.binding or not binding.issued_at <= now_epoch < binding.expires_at:
            raise ValueError("Synthetic private grant denied")


def prepared(tmp_path, kind="csv"):
    raw = csv_bytes([item()]) if kind == "csv" else workbook_bytes([item()])
    if kind == "encrypted":
        raw = encrypted_bytes(raw)
    path = private_file(tmp_path, raw)
    binding = intake.OwnerFileIntakeBinding(
        path=path, file_sha256=hashlib.sha256(raw).hexdigest(),
        file_format="csv" if kind == "csv" else "xlsm",
        issuer="https://issuer.example.invalid", subject="synthetic-human",
        planning_resource="https://example.invalid/mcp", intake_resource="https://example.invalid/intake",
        planning_client="synthetic-planner", intake_client="synthetic-owner-intake",
        deployment_digest="2" * 64, scope_digest="1" * 64,
        batch_digest="3" * 64, workload_digest="4" * 64, issued_at=990, expires_at=1120,
    )
    clocks = [1000.0, 100.0]
    options = dict(planning_token="synthetic-planning-token", intake_token="synthetic-intake-token",
                   planning_verifier=Verifier(binding, True), intake_verifier=Verifier(binding, False),
                   authority=Authority(binding), clock=lambda: clocks[0], monotonic=lambda: clocks[1])
    return binding, options, clocks


def test_local_oauth_verified_planning_identity_joins_without_intake_authority(tmp_path, monkeypatch):
    from mcp.server.auth.provider import ProviderTokenVerifier
    from starlette.testclient import TestClient

    from fortipam_mcp.http_server import HttpServerSettings, create_http_app
    from fortipam_mcp.local_oauth import LocalOAuthProvider
    from test_http_server import (
        _authorize_and_login, _local_oauth_environment, _register_public_client,
    )

    binding, _, _ = prepared(tmp_path)
    settings = HttpServerSettings.from_environment(_local_oauth_environment(tmp_path))
    provider = LocalOAuthProvider(settings.local_oauth)
    verifier = ProviderTokenVerifier(provider)
    with TestClient(create_http_app(settings), base_url="https://mcp.example.com") as client:
        client_id = _register_public_client(client, "fortipam:read fortipam:plan")
        code, pkce = _authorize_and_login(client, client_id, "fortipam:read fortipam:plan")
        response = client.post("/fpamcp/oauth/token", data={
            "grant_type": "authorization_code", "client_id": client_id, "code": code,
            "code_verifier": pkce, "redirect_uri": "https://client.example/callback",
            "resource": settings.public_url,
        })
        assert response.status_code == 200
        raw_token = response.json()["access_token"]
        verified = asyncio.run(verifier.verify_token(raw_token))
        assert verified is not None
        binding = replace(binding, issuer=settings.local_oauth.issuer, subject="operator",
                          planning_resource=settings.public_url, planning_client=client_id)
        assert intake._verified_expiry(verified, binding, planning=True) == verified.expires_at

        # Actual MCP credentials still cannot authenticate the private channel.
        with pytest.raises(ValueError):
            intake._verified_expiry(verified, binding, planning=False)
        now = int(time.time())
        binding = replace(binding, issued_at=now - 1, expires_at=now + 60)
        monkeypatch.setattr(intake, "PinnedBulkImportFile",
                            lambda *a, **k: pytest.fail("Read without private-channel authority"))
        with pytest.raises(intake.BulkImportIntakeError):
            asyncio.run(intake.admit_prebound_owner_file(
                binding, planning_token=raw_token, intake_token=raw_token,
                planning_verifier=verifier, intake_verifier=verifier, authority=Authority(binding),
            ))
        asyncio.run(provider.revoke_token(verified))
        assert asyncio.run(verifier.verify_token(raw_token)) is None


@pytest.mark.parametrize("kind", ["csv", "xlsm", "encrypted"])
def test_admitted_projection_is_once_opaque_and_clears_password(tmp_path, kind, capfd):
    binding, options, _ = prepared(tmp_path, kind)
    transaction = asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    for value in (binding, transaction):
        assert "synthetic" not in repr(value) and "synthetic" not in str(value)
        for serialize in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(RuntimeError):
                serialize(value)
    password = bytearray(b"synthetic-password") if kind == "encrypted" else None
    result = transaction.project_dependencies_once(catalog(), workbook_password=password)
    assert repr(result) == "<ResolvedImportDependencies redacted>"
    if password is not None:
        assert not any(password)
    assert options["authority"].calls == 4
    with pytest.raises(intake.BulkImportIntakeError):
        transaction.project_dependencies_once(catalog())
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("fault", ["defaults", "authority", "subject", "issuer", "client", "resource", "expired", "scope", "approve", "unverified", "scope-string", "scope-extra", "client-claim"])
def test_admission_denial_never_opens_file(tmp_path, monkeypatch, fault):
    binding, options, _ = prepared(tmp_path)
    monkeypatch.setattr(intake, "PinnedBulkImportFile", lambda *a, **k: pytest.fail("Read before admission"))
    if fault == "defaults":
        options = {k: v for k, v in options.items() if k.endswith("token")}
    elif fault == "authority":
        options["authority"].denied = True
    elif fault == "unverified":
        options["intake_verifier"].result = None
    else:
        changes = {
            "subject": {"subject": "other-human"},
            "issuer": {"claims": {"iss": "https://other.example.invalid", "sub": binding.subject}},
            "client": {"client_id": binding.planning_client},
            "resource": {"resource": binding.planning_resource},
            "expired": {"expires_at": 1000},
            "scope": {"scopes": ["fortipam:plan"]},
            "approve": {"scopes": [intake._INTAKE_SCOPE, "fortipam:approve"]},
            "scope-string": {"scopes": intake._INTAKE_SCOPE},
            "scope-extra": {"scopes": [intake._INTAKE_SCOPE, "fortipam:read"]},
            "client-claim": {"claims": {"iss": binding.issuer, "sub": binding.subject}},
        }[fault]
        options["intake_verifier"].result = options["intake_verifier"].result.model_copy(update=changes)
    with pytest.raises(intake.BulkImportIntakeError, match="Private bulk-import intake unavailable"):
        asyncio.run(intake.admit_prebound_owner_file(binding, **options))


@pytest.mark.parametrize("fault", ["wall-expired", "mono-expired", "wall-rollback", "mono-rollback", "cancel", "revoked", "scope", "wrong-password"])
def test_projection_failure_clears_password_and_prevents_reuse(tmp_path, fault):
    binding, options, clocks = prepared(tmp_path, "encrypted")
    transaction = asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    snapshot = catalog()
    if fault == "wall-expired":
        clocks[0] = 1100
    elif fault == "mono-expired":
        clocks[1] = 200
    elif fault == "wall-rollback":
        clocks[0] = 999
    elif fault == "mono-rollback":
        clocks[1] = 99
    elif fault == "cancel":
        transaction.close()
    elif fault == "revoked":
        options["authority"].denied = True
    elif fault == "scope":
        snapshot = replace(snapshot, scope_digest="f" * 64)
    password = bytearray(b"wrong" if fault == "wrong-password" else b"synthetic-password")
    with pytest.raises(intake.BulkImportIntakeError):
        transaction.project_dependencies_once(snapshot, workbook_password=password)
    assert not any(password)
    clocks[:] = [1000, 100]
    options["authority"].denied = False
    with pytest.raises(intake.BulkImportIntakeError):
        transaction.project_dependencies_once(catalog(), workbook_password=bytearray(b"synthetic-password"))


def test_verification_elapsed_time_does_not_refresh_admission_deadline(tmp_path, monkeypatch):
    binding, options, clocks = prepared(tmp_path)
    original = options["intake_verifier"].verify_token

    async def delayed(token):
        clocks[1] += 101
        return await original(token)

    options["intake_verifier"].verify_token = delayed
    monkeypatch.setattr(intake, "PinnedBulkImportFile", lambda *a, **k: pytest.fail("Read after deadline"))
    with pytest.raises(intake.BulkImportIntakeError):
        asyncio.run(intake.admit_prebound_owner_file(binding, **options))


@pytest.mark.parametrize("decision", [True, False, "allowed"])
def test_authority_must_not_return_a_boolean_or_label(tmp_path, monkeypatch, decision):
    binding, options, _ = prepared(tmp_path)
    options["authority"].verify = lambda *args, **kwargs: decision
    monkeypatch.setattr(intake, "PinnedBulkImportFile", lambda *a, **k: pytest.fail("Read without authority"))
    with pytest.raises(intake.BulkImportIntakeError):
        asyncio.run(intake.admit_prebound_owner_file(binding, **options))


@pytest.mark.parametrize("fault", ["timeout", "cancel"])
def test_token_verification_timeout_or_cancellation_reads_nothing(tmp_path, monkeypatch, fault):
    binding, options, _ = prepared(tmp_path)

    async def fail(token):
        if fault == "cancel":
            raise asyncio.CancelledError("Synthetic private token context")
        await asyncio.sleep(30)

    options["planning_verifier"].verify_token = fail
    monkeypatch.setattr(intake, "_TOKEN_VERIFY_SECONDS", 0.01)
    monkeypatch.setattr(intake, "PinnedBulkImportFile", lambda *a, **k: pytest.fail("Read after failure"))
    with pytest.raises(intake.BulkImportIntakeError) as caught:
        asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    assert str(caught.value) == "Private bulk-import intake unavailable."
    assert options["intake_verifier"].calls == []


@pytest.mark.parametrize("limiter,offset", [("grant", 50), ("token", 40), ("session", 900)])
def test_admission_expiry_uses_earliest_bound(tmp_path, limiter, offset):
    binding, options, clocks = prepared(tmp_path)
    binding = replace(binding, expires_at=1050 if limiter == "grant" else 5000)
    options["authority"] = Authority(binding)
    for name in ("planning_verifier", "intake_verifier"):
        options[name].result = options[name].result.model_copy(update={"expires_at": 5000})
    if limiter == "token":
        options["planning_verifier"].result = options["planning_verifier"].result.model_copy(update={"expires_at": 1040})
    transaction = asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    clocks[1] += offset
    with pytest.raises(intake.BulkImportIntakeError):
        transaction.project_dependencies_once(catalog())


@pytest.mark.parametrize("which", ["planning", "intake"])
def test_synchronously_blocking_verifier_cannot_finish_beyond_shared_deadline(tmp_path, monkeypatch, which):
    binding, options, _ = prepared(tmp_path)
    original = options[which + "_verifier"].verify_token
    reads = []

    async def blocking(token):
        time.sleep(0.02)
        return await original(token)

    options[which + "_verifier"].verify_token = blocking
    monkeypatch.setattr(intake, "_TOKEN_VERIFY_SECONDS", 0.005)
    monkeypatch.setattr(intake, "PinnedBulkImportFile", lambda *a, **k: reads.append(True))
    with pytest.raises(intake.BulkImportIntakeError):
        asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    assert reads == []
    if which == "planning":
        assert options["intake_verifier"].calls == []


@pytest.mark.parametrize("fault", ["deadline", "cancel"])
def test_catalog_work_cannot_start_decode_after_deadline_or_cancellation(tmp_path, monkeypatch, fault):
    binding, options, clocks = prepared(tmp_path)
    transaction = asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    original = intake.dependency_catalog_digest
    decodes = []

    def delayed(snapshot):
        result = original(snapshot)
        if fault == "deadline":
            clocks[1] = 200
        else:
            transaction.close()
        return result

    monkeypatch.setattr(intake, "dependency_catalog_digest", delayed)
    monkeypatch.setattr(intake.PinnedBulkImportFile, "decode", lambda *a, **k: decodes.append(True))
    password = bytearray(b"synthetic-password")
    with pytest.raises(intake.BulkImportIntakeError):
        transaction.project_dependencies_once(catalog(), workbook_password=password)
    assert not any(password) and decodes == []
    clocks[:] = [1000, 100]
    with pytest.raises(intake.BulkImportIntakeError):
        transaction.project_dependencies_once(catalog())
    assert decodes == []


def test_concurrent_projection_cannot_cancel_or_clear_active_private_copy(tmp_path, monkeypatch):
    binding, options, _ = prepared(tmp_path, "encrypted")
    transaction = asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    entered, release = threading.Event(), threading.Event()
    original = transaction._source.decode
    outcomes = []
    password = bytearray(b"synthetic-password")

    def paused(source, *, workbook_password=None):
        entered.set()
        assert release.wait(2)
        assert bytes(workbook_password) == b"synthetic-password"
        return original(workbook_password=workbook_password)

    monkeypatch.setattr(intake.PinnedBulkImportFile, "decode", paused)

    def work():
        try:
            outcomes.append(transaction.project_dependencies_once(catalog(), workbook_password=password))
        except BaseException as error:
            outcomes.append(type(error))

    thread = threading.Thread(target=work)
    thread.start()
    try:
        assert entered.wait(2)
        with pytest.raises(intake.BulkImportIntakeError):
            transaction.project_dependencies_once(catalog(), workbook_password=password)
    finally:
        release.set()
        thread.join(2)
    assert not thread.is_alive() and len(outcomes) == 1
    assert isinstance(outcomes[0], intake.ResolvedImportDependencies)
    assert not any(password)


@pytest.mark.parametrize("fault", ["cancel", "deadline"])
def test_inflight_projection_discards_and_clears_rows_on_cancellation_or_expiry(tmp_path, monkeypatch, fault):
    binding, options, clocks = prepared(tmp_path)
    transaction = asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    original = intake.resolve_import_dependencies
    frames = []

    def finish(*args, **kwargs):
        frames.append(args[0]._ProtectedBulkImportRows__raw)
        result = original(*args, **kwargs)
        if fault == "cancel":
            transaction.close()
        else:
            clocks[1] = 200
        return result

    monkeypatch.setattr(intake, "resolve_import_dependencies", finish)
    with pytest.raises(intake.BulkImportIntakeError):
        transaction.project_dependencies_once(catalog())
    assert frames and not any(frames[0])


@pytest.mark.parametrize("valid_signature", [True, False])
def test_existing_jwt_verifier_validates_signatures_before_intake(tmp_path, monkeypatch, valid_signature):
    import jwt
    from fortipam_mcp.http_server import OAuthJwtTokenVerifier

    binding, options, _ = prepared(tmp_path)
    now = int(time.time())
    binding = replace(binding, issued_at=now - 1, expires_at=now + 120)
    key = b"synthetic-offline-jwt-signing-key-0001"
    options.update(authority=Authority(binding), clock=time.time, monotonic=time.monotonic)
    for planning in (True, False):
        resource = binding.planning_resource if planning else binding.intake_resource
        prefix = "planning" if planning else "intake"
        verifier = OAuthJwtTokenVerifier(issuer=binding.issuer, jwks_url="https://example.invalid/jwks",
                                         audience=resource, algorithms=("HS256",))
        verifier._jwks_client = SimpleNamespace(get_signing_key_from_jwt=lambda _: SimpleNamespace(key=key))
        options[prefix + "_verifier"] = verifier
        signing_key = key if planning or valid_signature else b"synthetic-incorrect-signing-key-0002"
        options[prefix + "_token"] = jwt.encode({
            "iss": binding.issuer, "sub": binding.subject, "aud": resource, "exp": now + 100,
            "client_id": binding.planning_client if planning else binding.intake_client,
            "scope": "fortipam:plan" if planning else intake._INTAKE_SCOPE,
        }, signing_key, algorithm="HS256")
    if valid_signature:
        transaction = asyncio.run(intake.admit_prebound_owner_file(binding, **options))
        transaction.close()
    else:
        monkeypatch.setattr(intake, "PinnedBulkImportFile", lambda *a, **k: pytest.fail("Unauthenticated read"))
        with pytest.raises(intake.BulkImportIntakeError):
            asyncio.run(intake.admit_prebound_owner_file(binding, **options))
