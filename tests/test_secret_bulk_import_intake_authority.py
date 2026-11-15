"""Synthetic signed admission grants; no deployed issuer or live source."""

import asyncio
import copy
from dataclasses import asdict, replace
import hashlib
import hmac
import json
import pickle
from pathlib import Path

import pytest

from fortipam_mcp import secret_bulk_import_intake as intake
from fortipam_mcp import secret_bulk_import_intake_authority as authority
from test_secret_bulk_import_intake import prepared
from test_secret_bulk_import_dependencies import catalog


def signed_policy(tmp_path, binding, *, changes=None, seal_valid=True):
    key = b"synthetic-owner-policy-key-00000000"
    value = asdict(binding)
    value["path"] = str(binding.path)

    def mac(purpose, payload):
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        return hmac.new(key, b"fortipam-owner-file-intake-admission/v1\0" + purpose + b"\0" + raw,
                        hashlib.sha256).hexdigest()

    payload = {"contract": authority.CONTRACT, "purpose": "private-dependency-projection-only",
               "intent_digest": mac(b"intent", value), "owner_decision_digest": "5" * 64,
               "issued_at": binding.issued_at, "expires_at": binding.expires_at}
    payload.update(changes or {})
    raw = json.dumps({"payload": payload, "seal": mac(b"policy", payload) if seal_valid else "0" * 64}).encode()
    policy_path, key_path = (tmp_path / "synthetic-admission.json").resolve(), (tmp_path / "synthetic-admission.key").resolve()
    for path, content in ((policy_path, raw), (key_path, key)):
        path.write_bytes(content)
        path.chmod(0o600)
    return {"policy_path": policy_path, "key_path": key_path,
            "policy_sha256": hashlib.sha256(raw).hexdigest(), "key_sha256": hashlib.sha256(key).hexdigest()}


def pinned(tmp_path, binding, options, clocks, *, verifier=None, changes=None, seal_valid=True):
    def eligible(candidate, decision, now):
        assert candidate == binding and decision == "5" * 64 and now == int(clocks[0])

    return authority.PinnedOwnerFileIntakeAuthority(
        binding, **signed_policy(tmp_path, binding, changes=changes, seal_valid=seal_valid),
        human_owner_verifier=verifier or eligible, clock=lambda: int(clocks[0]),
    )


def test_signed_authority_joins_existing_admission_without_exposing_source(tmp_path, capfd):
    binding, options, clocks = prepared(tmp_path)
    grant = pinned(tmp_path, binding, options, clocks)
    options["authority"] = grant
    transaction = asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    assert repr(transaction.project_dependencies_once(catalog())) == "<ResolvedImportDependencies redacted>"
    assert repr(grant) == "<PinnedOwnerFileIntakeAuthority redacted>"
    for serialize in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(RuntimeError):
            serialize(grant)
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("fault", ["missing-owner", "signature", "purpose", "intent", "grant-expired", "lifetime-mismatch",
                                  "grant-too-long", "boolean-owner", "label-owner", "denied-owner"])
def test_signed_policy_never_substitutes_for_owner_eligibility_or_source_authority(
    tmp_path, monkeypatch, capfd, fault,
):
    binding, options, clocks = prepared(tmp_path)
    monkeypatch.setattr(intake, "PinnedBulkImportFile", lambda *a, **kw: pytest.fail("Unauthorized source read"))
    if fault == "grant-too-long":
        binding = replace(binding, expires_at=3000)
    changes = {"purpose": {"purpose": "secret-create"}, "intent": {"intent_digest": "0" * 64},
               "grant-expired": {"expires_at": 1000}, "lifetime-mismatch": {"expires_at": 1119},
               "grant-too-long": {"expires_at": 2000}}.get(fault)
    kwargs = signed_policy(tmp_path, binding, changes=changes, seal_valid=fault != "signature")

    def denied(*args):
        raise RuntimeError("synthetic-private-eligibility-detail")

    verifier = {"missing-owner": None, "boolean-owner": lambda *args: True,
                "label-owner": lambda *args: "approved", "denied-owner": denied}.get(fault, lambda *args: None)
    with pytest.raises(intake.BulkImportIntakeError) as caught:
        grant = authority.PinnedOwnerFileIntakeAuthority(binding, **kwargs,
                    human_owner_verifier=verifier, clock=lambda: int(clocks[0]))
        options["authority"] = grant
        asyncio.run(intake.admit_prebound_owner_file(binding, **options))
    assert str(caught.value) == "Private bulk-import intake unavailable."
    assert capfd.readouterr() == ("", "")


@pytest.mark.parametrize("field,value", [
    ("subject", "synthetic-other-human"), ("planning_client", "synthetic-other-planner"),
    ("intake_resource", "https://other.example.invalid/intake"), ("batch_digest", "6" * 64),
    ("deployment_digest", "6" * 64), ("scope_digest", "6" * 64), ("workload_digest", "6" * 64),
    ("file_sha256", "6" * 64),
])
def test_exact_grant_rejects_other_human_workload_batch_and_file(tmp_path, field, value):
    binding, options, clocks = prepared(tmp_path)
    grant = pinned(tmp_path, binding, options, clocks)
    with pytest.raises(intake.BulkImportIntakeError):
        grant.verify(replace(binding, **{field: value}), now_epoch=1000)


@pytest.mark.parametrize("fault", ["policy-inode", "key-bytes", "key-symlink", "policy-mode", "owner-expiry", "rollback"])
def test_custody_and_deadline_are_checked_after_eligibility_work(tmp_path, capfd, fault):
    binding, options, clocks = prepared(tmp_path)
    paths = signed_policy(tmp_path, binding)

    def change(candidate, decision, now):
        if fault == "policy-inode":
            raw = paths["policy_path"].read_bytes()
            paths["policy_path"].unlink()
            paths["policy_path"].write_bytes(raw)
            paths["policy_path"].chmod(0o600)
        elif fault == "key-bytes":
            paths["key_path"].write_bytes(b"synthetic-other-key-00000000000000")
        elif fault == "key-symlink":
            target = tmp_path / "synthetic-other-key"
            paths["key_path"].rename(target)
            paths["key_path"].symlink_to(target)
        elif fault == "policy-mode":
            paths["policy_path"].chmod(0o644)
        elif fault == "owner-expiry":
            clocks[0] = binding.expires_at
        else:
            clocks[0] -= 1

    grant = authority.PinnedOwnerFileIntakeAuthority(binding, **paths,
                human_owner_verifier=change, clock=lambda: int(clocks[0]))
    with pytest.raises(intake.BulkImportIntakeError):
        grant.verify(binding, now_epoch=1000)
    assert capfd.readouterr() == ("", "")


def test_duplicate_policy_members_are_rejected_even_with_matching_custody_pin(tmp_path):
    binding, _, clocks = prepared(tmp_path)
    paths = signed_policy(tmp_path, binding)
    raw = paths["policy_path"].read_bytes().replace(b'{"payload":', b'{"seal":"duplicate", "payload":', 1)
    paths["policy_path"].write_bytes(raw)
    paths["policy_sha256"] = hashlib.sha256(raw).hexdigest()
    with pytest.raises(intake.BulkImportIntakeError):
        authority.PinnedOwnerFileIntakeAuthority(binding, **paths,
            human_owner_verifier=lambda *args: None, clock=lambda: int(clocks[0]))


@pytest.mark.parametrize("allowed", [True, False])
def test_verification_clears_every_policy_and_key_buffer(tmp_path, monkeypatch, allowed):
    binding, _, clocks = prepared(tmp_path)
    paths = signed_policy(tmp_path, binding)
    read, buffers = authority._read_owned, []

    def capture(*args):
        raw, identity = read(*args)
        buffers.append(raw)
        return raw, identity

    monkeypatch.setattr(authority, "_read_owned", capture)
    grant = authority.PinnedOwnerFileIntakeAuthority(binding, **paths,
        human_owner_verifier=lambda *args: None if allowed else False, clock=lambda: int(clocks[0]))
    if allowed:
        grant.verify(binding, now_epoch=1000)
    else:
        with pytest.raises(intake.BulkImportIntakeError):
            grant.verify(binding, now_epoch=1000)
    assert buffers
    cleared = all(not any(raw) for raw in buffers)
    assert cleared


@pytest.mark.parametrize("which", ["policy_path", "key_path"])
@pytest.mark.parametrize("double_root", [False, True])
def test_policy_constructor_cannot_alias_the_unauthenticated_source(tmp_path, monkeypatch, which, double_root):
    binding, _, clocks = prepared(tmp_path)
    paths = signed_policy(tmp_path, binding)
    paths[which] = Path("/" + str(binding.path)) if double_root else binding.path
    monkeypatch.setattr(authority, "_read_owned", lambda *args: pytest.fail("Source read before authentication"))
    with pytest.raises(intake.BulkImportIntakeError):
        authority.PinnedOwnerFileIntakeAuthority(binding, **paths,
            human_owner_verifier=lambda *args: None, clock=lambda: int(clocks[0]))


def test_recursive_owner_verification_cannot_enter_the_same_authority_twice(tmp_path):
    binding, _, clocks = prepared(tmp_path)
    paths = signed_policy(tmp_path, binding)
    nested = []

    def eligible(candidate, decision, now):
        with pytest.raises(intake.BulkImportIntakeError):
            grant.verify(candidate, now_epoch=now)
        nested.append(True)

    grant = authority.PinnedOwnerFileIntakeAuthority(binding, **paths,
        human_owner_verifier=eligible, clock=lambda: int(clocks[0]))
    grant.verify(binding, now_epoch=1000)
    assert nested == [True]
