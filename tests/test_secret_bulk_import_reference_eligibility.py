"""Exact private source grants; synthetic principals, no device or live roles."""

import asyncio
from dataclasses import replace
import hashlib
from pathlib import Path
import time
from types import SimpleNamespace

import pytest
from mcp.server.auth.provider import ProviderTokenVerifier
from starlette.testclient import TestClient

from v4_planning import PersistentReferenceAuthority, PersistentReferenceCheckpointAuthority, canonical_digest
from fortipam_mcp import secret_bulk_import_intake as intake
from fortipam_mcp import secret_bulk_import_reference_eligibility as eligibility
from fortipam_mcp.secret_bulk_import_file import BulkImportFileError
from fortipam_mcp.secret_bulk_import_intake_authority import PinnedOwnerFileIntakeAuthority
from fortipam_mcp.secret_bulk_import_oauth import OwnerFileIntakeTokenVerifier
from fortipam_mcp.reference_authority_sidecar import (
    UnixReferenceAuthorityClient, UnixReferenceAuthorityClientSettings, create_reference_authority_sidecar_app,
)
from fortipam_mcp.v4_plan_runtime import V4PlanningAuthorizationSettings, planning_principal_from_access_token
from test_secret_bulk_import_dependencies import catalog
from test_secret_bulk_import_intake import prepared
from test_secret_bulk_import_intake_authority import signed_policy
from test_secret_bulk_import_oauth import PRIMARY, PRIVATE, fixture as oauth_fixture, issue

REFERENCE = "owner-file-eligibility-reference-01"
AUTHORITY = "owner-file-reference-authority-01"
CHECKPOINT = "owner-file-reference-checkpoint-01"
STORE = "owner-file-reference-store-01"


def write(path, value):
    path.write_bytes(value)
    path.chmod(0o600)
    return hashlib.sha256(value).hexdigest()


def source(tmp_path, binding, clocks, *, requester="7" * 64, checkpoint=True):
    root, cp_root = tmp_path / "reference", tmp_path / "checkpoint"
    root.mkdir(mode=0o700)
    cp_root.mkdir(mode=0o700)
    write(root / "reference.key", b"r" * 32)
    write(cp_root / "checkpoint.key", b"c" * 32)
    cp = PersistentReferenceCheckpointAuthority(cp_root / "state.sqlite", cp_root / "checkpoint.key",
                                              authority_ref=CHECKPOINT)
    authority = PersistentReferenceAuthority(root / "state.sqlite", root / "reference.key", authority_ref=AUTHORITY,
                monotonic_checkpoint=cp if checkpoint else None, checkpoint_store_ref=STORE if checkpoint else None,
                clock=lambda: int(clocks[0]))
    key = tmp_path / "scope.key"
    sha = write(key, b"e" * 32)
    kwargs = dict(authority=authority, authority_ref=AUTHORITY, reference=REFERENCE, requester_digest=requester,
                  scope_key_path=key, scope_key_sha256=sha, clock=lambda: int(clocks[0]))
    grant_kwargs = dict(reference_kind=eligibility.REFERENCE_KIND, requester_digest=requester,
                        environment_ref=eligibility.eligibility_environment_ref(binding),
                        scope_ref=eligibility.eligibility_scope_ref(binding, bytearray(b"e" * 32)),
                        expires_at=binding.expires_at, now_epoch=int(clocks[0]))
    return authority, kwargs, grant_kwargs, cp


def pinned(tmp_path, binding, options, clocks, checker):
    options["authority"] = PinnedOwnerFileIntakeAuthority(binding,
        **signed_policy(tmp_path, binding, changes={"owner_decision_digest": canonical_digest(REFERENCE)}),
        human_owner_verifier=checker, clock=lambda: int(clocks[0]))


def test_live_exact_reference_grant_admits_and_revocation_denies_projection(tmp_path, monkeypatch, capfd):
    binding, options, clocks = prepared(tmp_path)
    authority, kwargs, grant_kwargs, _ = source(tmp_path, binding, clocks)
    checker = eligibility.ReferenceOwnerFileEligibility(binding, **kwargs)
    with pytest.raises(intake.BulkImportIntakeError):
        checker(binding, canonical_digest(REFERENCE), 1000)
    handle = authority.issue(REFERENCE, **grant_kwargs)
    pinned(tmp_path, binding, options, clocks, checker)
    transaction = asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    authority.revoke(handle, now_epoch=1000)
    monkeypatch.setattr(intake.PinnedBulkImportFile, "decode", lambda *args, **kwargs: pytest.fail("Revoked grant reached decoding"))
    with pytest.raises(intake.BulkImportIntakeError):
        transaction.project_dependencies_once(catalog())
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("field,value", [("subject", "other-human"), ("planning_client", "other-client"),
    ("intake_client", "other-client"), ("file_sha256", "8" * 64), ("path", Path("/private/tmp/other-file.csv")),
    ("batch_digest", "8" * 64), ("workload_digest", "8" * 64), ("scope_digest", "8" * 64),
    ("deployment_digest", "8" * 64), ("expires_at", 1119)])
def test_new_binding_and_valid_policy_cannot_reuse_another_file_grant(tmp_path, monkeypatch, field, value):
    binding, options, clocks = prepared(tmp_path)
    authority, kwargs, grant_kwargs, _ = source(tmp_path, binding, clocks)
    authority.issue(REFERENCE, **grant_kwargs)
    altered = replace(binding, **{field: value})
    checker = eligibility.ReferenceOwnerFileEligibility(altered, **kwargs)
    pinned(tmp_path, altered, options, clocks, checker)
    monkeypatch.setattr(intake, "PinnedBulkImportFile", lambda *a, **k: pytest.fail("Substitution opened a source"))
    with pytest.raises(intake.BulkImportIntakeError):
        options["authority"].verify(altered, now_epoch=1000)


@pytest.mark.parametrize("fault", ["uncheckpointed", "fake-authority", "wrong-authority", "same-key", "source-alias"])
def test_default_closed_eligibility_rejects_untrusted_source_before_read(tmp_path, monkeypatch, fault):
    binding, _, clocks = prepared(tmp_path)
    authority, kwargs, _, _ = source(tmp_path, binding, clocks, checkpoint=fault != "uncheckpointed")
    if fault == "fake-authority":
        kwargs["authority"] = SimpleNamespace(monotonic_checkpoint_protocol_bound=True, authority_ref=AUTHORITY)
    elif fault == "wrong-authority":
        kwargs["authority_ref"] = "other-reference-authority-01"
    elif fault == "same-key":
        kwargs["scope_key_sha256"] = write(kwargs["scope_key_path"], b"r" * 32)
    elif fault == "source-alias":
        kwargs["scope_key_path"] = Path("/" + str(binding.path))
        monkeypatch.setattr(eligibility, "_PinnedKey", lambda *a: pytest.fail("Unauthenticated source alias read"))
    with pytest.raises(intake.BulkImportIntakeError):
        eligibility.ReferenceOwnerFileEligibility(binding, **kwargs)


@pytest.mark.parametrize("fault", ["wrong-requester", "wrong-kind", "wrong-decision", "expired", "key-drift", "ledger-rollback"])
def test_reference_state_and_exact_decision_must_still_match(tmp_path, fault):
    binding, _, clocks = prepared(tmp_path)
    authority, kwargs, grant_kwargs, _ = source(tmp_path, binding, clocks)
    checker = eligibility.ReferenceOwnerFileEligibility(binding, **kwargs)
    if fault == "wrong-requester":
        grant_kwargs["requester_digest"] = "8" * 64
    elif fault == "wrong-kind":
        grant_kwargs["reference_kind"] = "object_public_folder"
    db = authority._path
    before = db.read_bytes()
    authority.issue(REFERENCE, **grant_kwargs)
    decision = canonical_digest(REFERENCE)
    if fault == "wrong-decision":
        decision = "8" * 64
    elif fault == "expired":
        clocks[0] = binding.expires_at
    elif fault == "key-drift":
        kwargs["scope_key_path"].chmod(0o644)
    elif fault == "ledger-rollback":
        db.write_bytes(before)
    with pytest.raises(intake.BulkImportIntakeError):
        checker(binding, decision, int(clocks[0]))


@pytest.mark.parametrize("phase", ["pin", "decode"])
def test_revocation_during_source_read_denies_and_clears_rows(tmp_path, monkeypatch, phase):
    binding, options, clocks = prepared(tmp_path)
    authority, kwargs, grant_kwargs, _ = source(tmp_path, binding, clocks)
    checker = eligibility.ReferenceOwnerFileEligibility(binding, **kwargs)
    handle = authority.issue(REFERENCE, **grant_kwargs)
    pinned(tmp_path, binding, options, clocks, checker)
    if phase == "pin":
        original = intake.PinnedBulkImportFile
        def pin(*args, **kwargs):
            result = original(*args, **kwargs)
            authority.revoke(handle, now_epoch=1000)
            return result
        monkeypatch.setattr(intake, "PinnedBulkImportFile", pin)
        with pytest.raises(intake.BulkImportIntakeError):
            asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    else:
        transaction = asyncio.run(intake.admit_prebound_owner_file(binding, **options))
        original = transaction._source.decode
        rows = []
        def decode(self, **kwargs):
            result = original(**kwargs)
            rows.append(result)
            authority.revoke(handle, now_epoch=1000)
            return result
        monkeypatch.setattr(intake.PinnedBulkImportFile, "decode", decode)
        with pytest.raises(intake.BulkImportIntakeError):
            transaction.project_dependencies_once(catalog())
        assert rows
        assert not any(rows[0]._ProtectedBulkImportRows__raw)
        with pytest.raises(BulkImportFileError):
            rows[0]._consume_once(lambda values: None)
        with pytest.raises(intake.BulkImportIntakeError):
            transaction.project_dependencies_once(catalog())


def test_sdk_authenticated_human_exact_grant_and_signed_policy_join_projection(tmp_path, capfd):
    binding, options, _ = prepared(tmp_path)
    issuer, client = oauth_fixture(tmp_path)
    with client:
        planning_id, planning_token, _ = issue(client)
        private_id, private_token, _ = issue(client, private=True)
    planning = ProviderTokenVerifier(issuer)
    verified = asyncio.run(planning.verify_token(planning_token["access_token"]))
    principal = planning_principal_from_access_token(verified, V4PlanningAuthorizationSettings(
        expected_resource=PRIMARY, namespace_hmac_key=b"N" * 32))
    now = int(time.time())
    clocks = [now, 100.0]
    binding = replace(binding, issuer=issuer.settings.issuer, subject="operator", planning_resource=PRIMARY,
                      intake_resource=PRIVATE, planning_client=planning_id, intake_client=private_id,
                      issued_at=now - 1, expires_at=now + 120)
    options.update(planning_token=planning_token["access_token"], intake_token=private_token["access_token"],
                   planning_verifier=planning, intake_verifier=OwnerFileIntakeTokenVerifier(issuer),
                   clock=lambda: clocks[0], monotonic=lambda: clocks[1])
    authority, kwargs, grant_kwargs, _ = source(tmp_path, binding, clocks, requester=principal.requester.digest)
    authority.issue(REFERENCE, **grant_kwargs)
    pinned(tmp_path, binding, options, clocks, eligibility.ReferenceOwnerFileEligibility(binding, **kwargs))
    transaction = asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    assert repr(transaction.project_dependencies_once(catalog())) == "<ResolvedImportDependencies redacted>"
    assert capfd.readouterr() == ("", "")


def test_existing_reference_client_joins_without_local_authority_keys(tmp_path, monkeypatch, capfd):
    binding, options, clocks = prepared(tmp_path)
    authority, kwargs, grant_kwargs, _ = source(tmp_path, binding, clocks)
    handle = authority.issue(REFERENCE, **grant_kwargs)
    client = UnixReferenceAuthorityClient(UnixReferenceAuthorityClientSettings(tmp_path / "reference.sock", AUTHORITY))
    with TestClient(create_reference_authority_sidecar_app(authority)) as transport:
        # Exercise actual typed RPC codecs; transport is in-process, not socket isolation evidence.
        monkeypatch.setattr(UnixReferenceAuthorityClient, "_post", lambda self, path, payload: transport.post(path, json=payload))
        kwargs["authority"] = client
        checker = eligibility.ReferenceOwnerFileEligibility(binding, **kwargs)
        pinned(tmp_path, binding, options, clocks, checker)
        transaction = asyncio.run(intake.admit_prebound_owner_file(binding, **options))
        assert repr(transaction.project_dependencies_once(catalog())) == "<ResolvedImportDependencies redacted>"
        authority.revoke(handle, now_epoch=1000)
        # Recreating a verifier does not clear independent revocation state.
        replacement = eligibility.ReferenceOwnerFileEligibility(binding, **kwargs)
        with pytest.raises(intake.BulkImportIntakeError):
            replacement(binding, canonical_digest(REFERENCE), 1000)
    assert capfd.readouterr() == ("", "")
