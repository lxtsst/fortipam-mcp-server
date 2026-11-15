"""Protected persisted creation joins, including tamper/restart denials."""
from dataclasses import replace
import hashlib
import json
import os

import pytest

from fortipam_mcp.secret_request_approval_revoke_resolver import (
    OwnerOnlySecretRequestApprovalRevokeResolver, SecretRequestApprovalRevokeResolverError,
)
from fortipam_mcp.secret_request_create_invocation_witness import OwnerOnlySecretRequestCreateInvocationWitnessStore
from test_secret_request_approval_revoke_continuity import _fixture, _signed, _KEY, _encode
from test_secret_request_approval_revoke_invocation_join import _invocation


def _setup(tmp_path):
    tmp_path.chmod(0o700)
    payload, expected = _fixture()
    claim = {"contract": "fortipam-v4-secret-request-create-claim-v1", "dispatch_attempted": True,
        "retry_allowed": False, "terminal_outcome": "bound", "failure_stage": "none",
        "http_status_class": "none", "post_http_status": 200, "intent_binding_hmac": "f" * 64}
    continuity_path, claim_path, invocation_path = [tmp_path / name for name in ("continuity.json", "claim.json", "invocation.json")]
    for path, data in ((continuity_path, _signed(payload)), (claim_path, _encode(claim))):
        path.write_bytes(data)
        path.chmod(0o600)
    invocation = replace(_invocation(payload, expected), create_claim_digest=hashlib.sha256(_encode(claim)).hexdigest())
    key = b"j" * 32
    OwnerOnlySecretRequestCreateInvocationWitnessStore(invocation_path, key).publish(invocation)
    args = dict(continuity_path=continuity_path, create_claim_path=claim_path,
        invocation_path=invocation_path, continuity_key=_KEY, invocation_key=key,
        expected=expected, intent_ref=invocation.intent_ref)
    return args, claim


def test_restart_resolves_bound_original_records_without_dispatch(tmp_path):
    args, _ = _setup(tmp_path)
    first = OwnerOnlySecretRequestApprovalRevokeResolver(**args).resolve()
    second = OwnerOnlySecretRequestApprovalRevokeResolver(**args).resolve()
    assert first == second
    assert "synthetic" not in repr(first)
    assert not hasattr(first, "authorized")


@pytest.mark.parametrize("fault", ["hmac", "reconciliation", "unknown", "duplicate", "bool_status",
    "claim_mode", "claim_symlink", "claim_hardlink", "parent_mode", "continuity_tamper",
    "invocation_tamper", "wrong_intent", "same_key"])
def test_protected_resolver_refuses_missing_or_changed_original_provenance(tmp_path, fault):
    args, claim = _setup(tmp_path)
    path = args["create_claim_path"]
    if fault == "hmac": claim["intent_binding_hmac"] = "a" * 64
    elif fault == "reconciliation": claim["terminal_outcome"] = "reconciliation_required"
    elif fault == "unknown": claim["unknown"] = True
    elif fault == "bool_status": claim["post_http_status"] = True
    if fault in {"hmac", "reconciliation", "unknown", "bool_status"}:
        path.write_bytes(_encode(claim))
    elif fault == "duplicate": path.write_bytes(_encode(claim)[:-1] + b',"terminal_outcome":"bound"}')
    elif fault == "claim_mode": path.chmod(0o644)
    elif fault == "claim_symlink":
        target = tmp_path / "original.json"
        path.rename(target)
        path.symlink_to(target)
    elif fault == "claim_hardlink": os.link(path, tmp_path / "alias.json")
    elif fault == "parent_mode": tmp_path.chmod(0o755)
    elif fault in {"continuity_tamper", "invocation_tamper"}:
        target = args["continuity_path" if fault == "continuity_tamper" else "invocation_path"]
        data = json.loads(target.read_bytes())
        data["hmac_sha256"] = "0" * 64
        target.write_bytes(_encode(data))
    elif fault == "wrong_intent": args["intent_ref"] = "different-original-intent"
    elif fault == "same_key": args["invocation_key"] = _KEY
    with pytest.raises(SecretRequestApprovalRevokeResolverError):
        OwnerOnlySecretRequestApprovalRevokeResolver(**args).resolve()
