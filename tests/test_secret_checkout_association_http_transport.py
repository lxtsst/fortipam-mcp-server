from contextlib import contextmanager
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from fortipam_mcp.secret_checkout_association_contract import CONTROLS, IDLE_FIELD, PREREQUISITES
from fortipam_mcp.secret_checkout_association_http_transport import (
    SecretCheckoutAssociationHttpTransport, SecretCheckoutBinding,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig
from test_secret_checkout_association_contract import (
    IDENTITY, BASELINE, CHECKOUT, CHECKIN, SCRIPTS, IDLE,
    EXECUTION_ID, EXECUTION_NAME, EXECUTION_METADATA,
)


@pytest.mark.parametrize("mode", ["attach", "restore", "basic", "metadata_drift", "account_drift", "script_drift", "idle_drift",
                                  "unknown_put", "html_put", "changed_fields", "changed_other_metadata",
                                  "execution_drift", "execution_account_drift", "association_drift",
                                  "changed_permissions", "unexpected_checkout_state"])
def test_claimed_fixed_checkout_delta_retains_fields_and_denies_restart_replay(tmp_path, mode):
    tmp_path.chmod(0o700)
    controls = {**BASELINE, "checkout": "enable", "checkout-duration": 5,
                "checkout-script": CHECKOUT, "checkin-script": CHECKIN} if mode == "restore" else BASELINE
    row = {**IDENTITY, **controls, **EXECUTION_METADATA, IDLE_FIELD: IDLE, "proxy": "enable", "target": "synthetic-target", "description": "preserve",
           "recording": "enable", "permissions": {
               "checkout_status": "required" if mode == "restore" else "none",
               "passwd_change": "forbidden" if mode == "restore" else "allowed", "edit": True}, "field": [
               {"id": 1, "name": "Password", "value": "synthetic-opaque-token"},
               {"id": 2, "name": "Username", "value": "synthetic-account"},
               {"id": 3, "name": "Host", "value": "192.0.2.1"},
           ]}
    execution_row = {**deepcopy(row), **BASELINE, "id": EXECUTION_ID, "name": EXECUTION_NAME,
                     "associated-secret": 0, "ssh-service-status": "up"}
    calls = []; scripts = deepcopy(SCRIPTS)

    class Client:
        cookies = {"ccsrftoken": "synthetic-csrf"}

        @contextmanager
        def stream(self, method, path, **kwargs):
            calls.append(method)
            selected = execution_row if path.endswith("/" + str(EXECUTION_ID)) else row
            if method == "PUT":
                assert claim.exists()
                body = json.loads(kwargs["content"])
                assert set(body) == set(IDENTITY) | CONTROLS | PREREQUISITES | {
                    IDLE_FIELD, "target", "field", "associated-secret", "target-privilege-account"}
                assert body["field"] == row["field"][:2]
                assert body["target"] == row["target"]
                assert kwargs["headers"]["X-CSRFTOKEN"] == "synthetic-csrf"
                if mode == "html_put":
                    yield SimpleNamespace(status_code=500, headers={"content-type": "text/html"},
                                          iter_bytes=lambda: pytest.fail("raw HTML must not be read"))
                    return
                row.update(body)
                row["permissions"].update(checkout_status="required" if body["checkout"] == "enable" else "none",
                                          passwd_change="forbidden" if body["checkout"] == "enable" else "allowed")
                if mode == "changed_permissions": row["permissions"]["edit"] = False
                if mode == "unexpected_checkout_state": row["permissions"]["checkout_status"] = "waiting"
                if mode == "changed_fields": row["field"][0]["value"] = "changed-token"
                if mode == "changed_other_metadata": row["recording"] = "disable"
                if mode in {"unknown_put", "html_put"}: raise TimeoutError("private-upstream-error")
            payload = {"version": "v7.0.0", "build": 29, "http_status": 200,
                       "http_method": method, "status": "OK", "path": "secret", "name": "database",
                       "results": deepcopy(selected)}
            yield SimpleNamespace(status_code=200, headers={"content-type": "application/json"},
                                  iter_bytes=lambda: iter([json.dumps(payload).encode()]))

    class Owner:
        def __init__(self): self._client = Client(); self.logout_verified = False

        @contextmanager
        def authenticated(self):
            calls.append("login")
            try: yield self
            finally: self.logout_verified = True

        def resolve_folder_id(self, path): return IDENTITY["folder"]

        def _lookup_id(self, kind, path): return EXECUTION_ID if path.endswith("/" + EXECUTION_NAME) else IDENTITY["id"]

    claim = tmp_path / "claim.json"
    config = SecretMetadataHttpTransportConfig("https://example.test", "synthetic-token", 15, None)
    binding = SecretCheckoutBinding(owner_name="synthetic-owner", folder_path="Root/fixture",
        secret_name=IDENTITY["name"], target_name="synthetic-target", template_name=IDENTITY["template"],
        target_address="192.0.2.1", checkout_script="" if mode == "basic" else CHECKOUT,
        checkin_script="" if mode == "basic" else CHECKIN,
        execution_secret_name=EXECUTION_NAME,
        baseline_controls=tuple(sorted(BASELINE.items())), force_checkout_idle_time=IDLE)
    adapter = SecretCheckoutAssociationHttpTransport(config, binding, lambda: ("synthetic-owner", "synthetic-password"),
        retained_account=lambda: "synthetic-account", claim_path=claim, restore=mode == "restore",
        owner_factory=Owner,
        script_reader=lambda: pytest.fail("basic checkout must not read Scripts") if mode == "basic" else scripts,
        sleep=lambda delay: None)
    before = adapter.inspect()
    assert "synthetic" not in repr(before)
    if mode == "idle_drift": row[IDLE_FIELD] = IDLE + 1
    if mode == "metadata_drift": row["recording"] = "disable"
    if mode == "account_drift": row["field"][1]["value"] = "other-account"
    if mode == "script_drift": scripts["results"][0]["script"] = "private-command"
    if mode == "execution_drift": execution_row["ssh-service-status"] = "down"
    if mode == "execution_account_drift": execution_row["field"][1]["value"] = "other-execution-account"
    if mode == "association_drift": row["associated-secret"] = 42
    denied = {"metadata_drift", "account_drift", "script_drift", "idle_drift",
              "execution_drift", "execution_account_drift", "association_drift"}
    if mode in denied | {"unknown_put", "html_put"}:
        with pytest.raises(RuntimeError, match="^The fixed Secret checkout association transport is unavailable.$"):
            adapter.associate_and_readback(before)
    else:
        result = adapter.associate_and_readback(before)
        assert result.verified == (mode in {"attach", "restore", "basic"})
        assert result.owner_logout_verified
        if mode == "restore": assert all(row[k] == BASELINE[k] for k in CONTROLS)
    if mode == "basic":
        assert row["checkout-script"] == row["checkin-script"] == ""
        assert row["checkout"] == "enable" and row["checkout-duration"] == 5
        assert json.loads(claim.read_text())["operation"] == "configure_basic_checkout"
    assert calls.count("PUT") == (0 if mode in denied else 1)
    if mode in denied:
        assert not claim.exists()
    if claim.exists():
        assert claim.stat().st_mode & 0o777 == 0o600
        assert "synthetic-opaque-token" not in claim.read_text()
        receipts = list(tmp_path.glob("claim.json.*.json"))
        assert receipts
        for receipt in receipts:
            assert receipt.stat().st_mode & 0o777 == 0o600
            assert "synthetic-opaque-token" not in receipt.read_text()
            assert "synthetic-account" not in receipt.read_text()
            assert json.loads(receipt.read_text())["replay_permitted"] is False
        if mode in {"unknown_put", "html_put"}:
            assert not (tmp_path / "claim.json.http-result.json").exists()
            assert json.loads((tmp_path / "claim.json.failure.json").read_text())["failure_stage"] == "put"
            if mode == "html_put":
                assert json.loads((tmp_path / "claim.json.http-status.json").read_text())["http_status"] == 500
            else:
                assert not (tmp_path / "claim.json.http-status.json").exists()
        else:
            assert json.loads((tmp_path / "claim.json.http-result.json").read_text())["http_accepted"]
            assert json.loads((tmp_path / "claim.json.readback-result.json").read_text())["controls_match"]
        fresh = SecretCheckoutAssociationHttpTransport(config, binding, lambda: pytest.fail("credential replay"),
            retained_account=lambda: pytest.fail("account replay"), claim_path=claim, restore=mode == "restore",
            owner_factory=lambda: pytest.fail("network replay"), script_reader=lambda: pytest.fail("script replay"))
        with pytest.raises(RuntimeError): fresh.associate_and_readback(before)
        with pytest.raises(RuntimeError): fresh.inspect()
    assert not hasattr(adapter, "update_and_readback")


def test_native_error_category_never_retains_private_error_text():
    from fortipam_mcp.secret_checkout_association_http_transport import _native_error_category
    category = _native_error_category({"error": -651,
        "cli_error": "Invalid value for parameter 'checkout-script': synthetic-private-secret-token"})
    assert category["native_error_code"] == -651
    assert category["invalid_value_hint"]
    assert category["checkout_field_hints"] == ["checkout-script"]
    assert "synthetic-private-secret-token" not in json.dumps(category)
    assert "Invalid value" not in json.dumps(category)
    assert "native_error_code" not in _native_error_category({"error": True})
    assert "native_error_code" not in _native_error_category({"error": 651})


def test_default_owner_reads_only_bound_companion_without_rebinding_mutation_target(tmp_path):
    from fortipam_mcp.secret_metadata_http_transport import (
        SecretMetadataHttpTransportError, UTILITY_ID_PATH, _path_for_url,
    )
    tmp_path.chmod(0o700)
    binding = SecretCheckoutBinding(owner_name="synthetic-owner", folder_path="Root/fixture",
        secret_name=IDENTITY["name"], target_name="synthetic-target", template_name=IDENTITY["template"],
        execution_secret_name=EXECUTION_NAME, target_address="192.0.2.1",
        checkout_script=CHECKOUT, checkin_script=CHECKIN,
        baseline_controls=tuple(sorted(BASELINE.items())), force_checkout_idle_time=IDLE)
    adapter = SecretCheckoutAssociationHttpTransport(
        SecretMetadataHttpTransportConfig("https://example.test", "synthetic-token", 15, None),
        binding, lambda: pytest.fail("credentials must not be loaded"),
        retained_account=lambda: pytest.fail("account must not be loaded"),
        claim_path=tmp_path / "claim.json")
    owner = adapter._private._owner()
    calls = []

    class LookupClient:
        @contextmanager
        def stream(self, method, path, **kwargs):
            calls.append((method, path))
            yield SimpleNamespace(status_code=200, headers={"content-type": "application/json"},
                iter_bytes=lambda: iter([json.dumps({"results": {"id": EXECUTION_ID}}).encode()]))

    owner._client = LookupClient()
    owner._expires_at = float("inf")
    path = UTILITY_ID_PATH + "/" + _path_for_url(binding.folder_path + "/" + EXECUTION_NAME)
    assert owner._lookup_id("secret", binding.folder_path + "/" + EXECUTION_NAME) == EXECUTION_ID
    assert owner._secret_id is None
    with pytest.raises(SecretMetadataHttpTransportError):
        owner._request("POST", path, {})
    with pytest.raises(SecretMetadataHttpTransportError):
        owner._lookup_id("secret", binding.folder_path + "/unbound-account")
    assert len(calls) == 1


def test_only_exact_checkout_derived_permission_pair_is_separately_qualified():
    from fortipam_mcp.secret_checkout_association_http_transport import (
        _checkout_permission_state_matches, _stable_checkout_metadata_digest,
    )
    before = {"checkout": "disable", "permissions": {
        "checkout_status": "none", "passwd_change": "allowed", "edit": True}}
    after = {"checkout": "enable", "permissions": {
        "checkout_status": "required", "passwd_change": "forbidden", "edit": True}}
    assert _checkout_permission_state_matches(before, "disable")
    assert _checkout_permission_state_matches(after, "enable")
    assert _stable_checkout_metadata_digest(before) == _stable_checkout_metadata_digest(after)
    for bad in ({}, {"checkout_status": "checked", "passwd_change": "allowed"},
                {"checkout_status": "required", "passwd_change": "allowed"},
                {"checkout_status": True, "passwd_change": "forbidden"}):
        assert not _checkout_permission_state_matches({"permissions": bad}, "enable")
    changed = {**after, "permissions": {**after["permissions"], "edit": False}}
    assert _stable_checkout_metadata_digest(changed) != _stable_checkout_metadata_digest(before)
