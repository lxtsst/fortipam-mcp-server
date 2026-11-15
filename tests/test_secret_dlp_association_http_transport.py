from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict
import json
from pathlib import Path
import ssl
from types import SimpleNamespace
from typing import Any
from urllib.parse import unquote

import pytest

from fortipam_mcp.owner_session_metadata import OwnerSessionMetadataTransport
from fortipam_mcp.secret_dlp_association_contract import (
    SecretDlpAssociationIdentity, fixed_log_only_sensor_profile,
)
from fortipam_mcp.secret_dlp_association_http_transport import (
    FortiPamSecretDlpAssociationHttpTransport, SecretDlpAssociationHttpBinding,
    SecretDlpAssociationHttpTransportError, SecretDlpDispatchPhase, SecretDlpPreservationMatch,
    SecretDlpQualification,
)
from fortipam_mcp.secret_metadata_http_transport import (
    SYSTEM_STATUS_PATH, FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig,
)

SERIAL = "SYNTHETIC01"
NAME = "mcp-v4-bp005-dlp-audit-test"
SENSOR = "mcp-v4-dlp-sftp-audit-test"


def envelope(path: str, name: str, row: object, method: str = "GET") -> dict[str, Any]:
    return {"version": "v7.0.0", "build": 29, "serial": SERIAL, "http_method": method,
            "http_status": 200, "path": path, "name": name, "status": "success", "vdom": "root",
            "results": row}


class Harness:
    def __init__(self, directory: Path) -> None:
        directory.chmod(0o700)
        self.directory = directory
        self.calls: list[tuple[str, str]] = []
        self.puts: list[dict[str, Any]] = []
        self.now = 0.0
        self.mode = "success"
        self.ack_changes: dict[str, Any] = {}
        self.actor = "synthetic-owner"
        self.profile = "super_admin"
        self.csrf = 'ccsrftoken="synthetic-csrf"'
        self.role_reads = 0
        self.template_reads = 0
        self.row: dict[str, Any] = {
            "id": 17, "folder": 9, "name": NAME, "template": "Unix Account (SSH Password)",
            "target": "synthetic-target", "description": "Before", "proxy": "enable", "recording": "enable",
            "ssh-service-status": "up", "sftp-service-status": "up", "ssh-filter": "disable",
            "ssh-filter-profile": "", "dlp-status": "disable", "dlp-sensor": "", "uuid": "synthetic-uuid",
            "q_origin_key": 17, "field": [
                {"desc": "Password", "id": 1, "q_origin_key": 1, "name": "Password", "type": "password",
                 "value": "synthetic-opaque-password"},
                {"desc": "Username", "id": 2, "q_origin_key": 2, "name": "Username", "type": "username",
                 "value": "synthetic-account"},
                {"desc": "Host", "id": 3, "q_origin_key": 3, "name": "Host", "type": "target-address",
                 "value": "192.0.2.1"}],
        }
        self.sensor: dict[str, Any] = dict(fixed_log_only_sensor_profile(sensor_name=SENSOR))
        self.sensor["q_origin_key"] = SENSOR
        self.sensor["filter"][0]["q_origin_key"] = 1
        self.template: dict[str, Any] = {
            "access": "", "description": "", "enforce-sso-launch": "disable", "group-permission": [],
            "launcher": [], "name": self.row["template"], "password-changer": "", "q_origin_key": self.row["template"],
            "server-info": "", "ssh-term": "", "totp-setting": "", "user-permission": [], "web-filler": "",
            "field": [{"name": n, "type": t, "q_origin_key": n, "mandatory": "enable", "need-edit": "disable"}
                      for n, t in (("Host", "target-address"), ("Username", "username"), ("Password", "password"))],
        }
        self.config = SecretMetadataHttpTransportConfig("https://pam.example.test:9443", "synthetic-token", 5, None)
        self.binding = SecretDlpAssociationHttpBinding(
            SecretDlpAssociationIdentity(17, NAME, 9, self.row["template"], "synthetic-target"),
            "synthetic-owner", SERIAL, SENSOR,
        )
        self.owner = OwnerSessionMetadataTransport(
            self.config, owner_name="synthetic-owner", credentials=lambda: ("synthetic-owner", "synthetic-login"),
            folder_path="Root/fixture", secret_name=NAME, target_name="synthetic-target",
            witness=FortiPamSecretMetadataHttpTransport(self.config), client_factory=self.client,
        )
        self.transport = self.new_transport()

    def new_transport(self) -> FortiPamSecretDlpAssociationHttpTransport:
        return FortiPamSecretDlpAssociationHttpTransport(self.config, self.owner, self.binding, claim_dir=self.directory)

    def client(self, **kwargs: Any) -> Client:
        assert kwargs["follow_redirects"] is False and kwargs["trust_env"] is False
        assert isinstance(kwargs["verify"], ssl.SSLContext)
        assert kwargs["verify"].verify_mode == ssl.CERT_REQUIRED and kwargs["verify"].check_hostname
        return Client(self)

    def inspect(self) -> Any:
        return self.transport.inspect_association()

    def associate(self, digest: str) -> Any:
        return self.transport.associate_and_readback(digest, expires_at=10, clock=lambda: self.now)


class Client:
    def __init__(self, harness: Harness) -> None:
        self.h = harness
        self.cookies = SimpleNamespace(clear=lambda: None)
        self.logged_out = False

    def get(self, path: str) -> Any:
        self.h.calls.append(("lifecycle", path))
        if path == "/remote/login?lang=en":
            return SimpleNamespace(status_code=200, text='action="/XX/YY/ZZ/AUTH"')
        if path == "/logout":
            self.logged_out = True
            return SimpleNamespace(status_code=200)
        if path == SYSTEM_STATUS_PATH and self.logged_out:
            return SimpleNamespace(status_code=403)
        return SimpleNamespace(status_code=200)

    def post(self, path: str, **kwargs: Any) -> Any:
        self.h.calls.append(("login", path))
        return SimpleNamespace(status_code=303, headers={"location": "/"})

    def close(self) -> None:
        self.h.calls.append(("close", ""))

    def build_request(self, *args: Any) -> Any:
        if self.h.mode == "client_metadata_drift":
            self.h.row["uuid"] = "changed-after-body"
        elif self.h.mode == "client_sensor_drift":
            self.h.sensor["filter"][0]["action"] = "block"
        return SimpleNamespace(headers={"cookie": self.h.csrf})

    @contextmanager
    def stream(self, method: str, path: str, **kwargs: Any) -> Iterator[Any]:
        h = self.h
        h.calls.append((method, path))
        decoded = unquote(path)
        if method == "PUT":
            assert path == "/api/v2/cmdb/secret/database/17"
            assert kwargs["headers"]["X-CSRFTOKEN"] == "synthetic-csrf"
            assert kwargs["headers"]["User-Agent"] == "fortipam-bp005-secret-dlp/1"
            assert len(list(h.directory.glob("*.claim"))) == len(h.puts) + 1
            body = json.loads(kwargs["content"])
            h.puts.append(body)
            assert set(body) == {"id", "name", "folder", "template", "target", "dlp-status", "dlp-sensor", "field"}
            assert body["field"] == [{k: item[k] for k in ("id", "name", "value", "keyinfo") if k in item}
                                     for item in h.row["field"] if item["name"] != "Host"]
            h.row.update({k: body[k] for k in ("dlp-status", "dlp-sensor")})
            if h.mode == "timeout":
                raise TimeoutError
            if h.mode == "readback_metadata":
                h.row["uuid"] = "changed"
            if h.mode == "readback_field":
                h.row["field"][0]["value"] = "changed"
            if h.mode == "readback_unqualified":
                h.row["ssh-service-status"] = "down"
            payload = envelope("secret", "database", None, "PUT")
            payload.pop("results")
            payload.update({"mkey": 17, "old_revision": "synthetic-before", "revision": "synthetic-after", "revision_changed": True})
            payload.update(h.ack_changes)
            if h.mode == "missing_ack_mkey":
                payload.pop("mkey")
        elif path == SYSTEM_STATUS_PATH:
            payload = {"version": "v7.0.0", "build": 29}
        elif decoded.startswith("/api/v2/monitor/web-ui/state"):
            payload = envelope("web-ui", "state", {"admin": {"name": h.actor, "login_name": h.actor,
                "sponsored_group_name": "", "guest_admin": False}})
        elif decoded.startswith("/api/v2/cmdb/system/admin/"):
            h.role_reads += 1
            payload = envelope("system", "admin", {"name": "synthetic-owner", "q_origin_key": "synthetic-owner",
                "accprofile": h.profile, "status": "enable", "remote-auth": "disable", "wildcard": "disable"})
            if h.mode == "expire_final_actor" and h.role_reads == 3:
                h.now = 10
        elif decoded.startswith("/api/v2/cmdb/dlp/sensor/"):
            payload = envelope("dlp", "sensor", deepcopy(h.sensor))
        elif decoded == "/api/v2/cmdb/secret/database/17":
            payload = envelope("secret", "database", deepcopy(h.row))
        elif decoded.startswith("/api/v2/cmdb/secret/template/"):
            h.template_reads += 1
            payload = envelope("secret", "template", deepcopy(h.template))
            if h.mode == "expire":
                h.now = 10
            if h.mode == "expire_final_read" and h.template_reads == 3:
                h.now = 10
        else:
            raise AssertionError(path)
        raw = json.dumps(payload, separators=(",", ":")).encode()
        if h.mode == "duplicate" and decoded.startswith("/api/v2/cmdb/secret/database/"):
            raw = raw.replace(b'"id":17', b'"id":17,"id":17')
        if h.mode == "oversize" and decoded.startswith("/api/v2/cmdb/dlp/sensor/"):
            raw = b" " * (1_048_576 + 1)
        yield SimpleNamespace(status_code=200, headers={"content-type": "application/json"},
                              iter_bytes=lambda **kwargs: iter([raw]))


def test_verified_association_and_same_instance_restore(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    before = h.inspect()
    assert NAME not in repr(before) and "synthetic-opaque" not in repr(before)
    result = h.associate(before.state_digest)
    assert result.acknowledged and result.logout_verified and result.opaque_fields_match
    assert result.after.phase == "associated"
    assert h.transport.dispatch_observation.phase == SecretDlpDispatchPhase.COMPLETE
    assert h.transport.dispatch_observation.ack_qualified == SecretDlpQualification.QUALIFIED
    associated = h.transport.inspect_owned_restore()
    restored = h.transport.restore_and_readback(associated.state_digest, expires_at=10, clock=lambda: h.now)
    assert restored.acknowledged and restored.opaque_fields_match and restored.logout_verified
    assert h.transport.dispatch_observation.phase == SecretDlpDispatchPhase.COMPLETE
    assert all(category == SecretDlpPreservationMatch.MATCH
               for category in asdict(h.transport.dispatch_observation.preservation).values())
    assert restored.after == before and len(h.puts) == 2
    assert h.owner._client is None and h.owner.logout_verified
    for claim in tmp_path.glob("*.claim"):
        assert claim.stat().st_mode & 0o777 == 0o600
        assert NAME not in claim.read_text() and SERIAL not in claim.read_text() and "synthetic-opaque" not in claim.read_text()
    count = len(h.calls)
    with pytest.raises(SecretDlpAssociationHttpTransportError):
        h.transport.inspect_owned_restore()
    with pytest.raises(SecretDlpAssociationHttpTransportError):
        h.new_transport().inspect_association()
    assert len(h.calls) == count
    h.transport.close()


@pytest.mark.parametrize("change", ["uuid", "field", "sensor", "inactive_shape", "actor", "role", "expire",
                                   "expire_final_actor", "expire_final_read", "client_metadata_drift", "client_sensor_drift", "csrf"])
def test_fresh_pre_dispatch_drift_or_expiry_sends_zero_put(tmp_path: Path, change: str) -> None:
    h = Harness(tmp_path)
    before = h.inspect()
    if change == "uuid": h.row["uuid"] = "changed"
    elif change == "field": h.row["field"][0]["value"] = "changed"
    elif change == "sensor": h.sensor["filter"][0]["action"] = "block"
    elif change == "inactive_shape": h.sensor["filter"][0].pop("file-size")
    elif change == "actor": h.actor = "different-owner"
    elif change == "role": h.profile = "different-role"
    elif change == "csrf": h.csrf = "othercookie=value"
    else: h.mode = change
    with pytest.raises(SecretDlpAssociationHttpTransportError): h.associate(before.state_digest)
    assert not h.puts and not list(tmp_path.glob("*.claim")) and h.owner._client is None
    h.transport.close()


@pytest.mark.parametrize("changes", [{"mkey": "17"}, {"mkey": 18}, {"error": True}, {"error": -1},
    {"results": None}, {"old_revision": 1}, {"revision_changed": False}, {"serial": "OTHER"},
    {"http_method": "POST"}, {"path": "other"}, {"build": True}, {"revision": "bad\n"}])
def test_uncertain_ack_consumes_claim_without_ownership_or_retry(tmp_path: Path, changes: dict[str, Any]) -> None:
    h = Harness(tmp_path)
    before = h.inspect()
    h.ack_changes = changes
    with pytest.raises(SecretDlpAssociationHttpTransportError): h.associate(before.state_digest)
    assert len(h.puts) == 1 and len(list(tmp_path.glob("*.claim"))) == 1
    count = len(h.calls)
    for transport in (h.transport, h.new_transport()):
        with pytest.raises(SecretDlpAssociationHttpTransportError): transport.inspect_owned_restore()
        with pytest.raises(SecretDlpAssociationHttpTransportError): transport.inspect_association()
    assert len(h.calls) == count and h.owner._client is None
    h.transport.close()


@pytest.mark.parametrize("mode", ["timeout", "missing_ack_mkey", "readback_metadata", "readback_field"])
def test_uncertain_or_failed_preservation_cannot_restore(tmp_path: Path, mode: str) -> None:
    h = Harness(tmp_path)
    before = h.inspect()
    h.mode = mode
    if mode in {"timeout", "missing_ack_mkey"}:
        with pytest.raises(SecretDlpAssociationHttpTransportError): h.associate(before.state_digest)
    else:
        result = h.associate(before.state_digest)
        assert not result.opaque_fields_match
    with pytest.raises(SecretDlpAssociationHttpTransportError): h.transport.inspect_owned_restore()
    assert len(h.puts) == 1
    h.transport.close()


@pytest.mark.parametrize("mode", ["expire", "timeout", "readback_metadata"])
def test_owned_restore_is_fresh_bounded_and_uncertain_restore_not_replayable(tmp_path: Path, mode: str) -> None:
    h = Harness(tmp_path)
    h.associate(h.inspect().state_digest)
    current = h.transport.inspect_owned_restore()
    h.mode = mode
    if mode == "readback_metadata":
        result = h.transport.restore_and_readback(current.state_digest, expires_at=10, clock=lambda: h.now)
        assert not result.opaque_fields_match
    else:
        with pytest.raises(SecretDlpAssociationHttpTransportError):
            h.transport.restore_and_readback(current.state_digest, expires_at=10, clock=lambda: h.now)
    assert len(h.puts) == (1 if mode == "expire" else 2)
    assert len(list(tmp_path.glob("*.claim"))) == (1 if mode == "expire" else 2)
    if mode != "expire":
        count = len(h.calls)
        with pytest.raises(SecretDlpAssociationHttpTransportError): h.transport.inspect_owned_restore()
        assert len(h.calls) == count
    h.transport.close()


def test_consumed_in_memory_attempt_cannot_be_revived_by_removed_claim(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    before = h.inspect()
    h.mode = "timeout"
    with pytest.raises(SecretDlpAssociationHttpTransportError): h.associate(before.state_digest)
    next(tmp_path.glob("*.claim")).unlink()
    count = len(h.calls)
    with pytest.raises(SecretDlpAssociationHttpTransportError): h.associate(before.state_digest)
    assert len(h.calls) == count and len(h.puts) == 1
    h.transport.close()


def test_expiry_after_durable_reservation_still_sends_zero_put_and_consumes_claim(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    before = h.inspect()
    calls = 0

    def clock() -> float:
        nonlocal calls
        calls += 1
        return 10.0 if calls >= 4 else 0.0

    with pytest.raises(SecretDlpAssociationHttpTransportError):
        h.transport.associate_and_readback(before.state_digest, expires_at=10, clock=clock)
    assert len(list(tmp_path.glob("*.claim"))) == 1 and not h.puts
    assert not h.transport.dispatch_observation.put_dispatch_attempted
    assert h.transport.dispatch_observation.ack_qualified == SecretDlpQualification.UNKNOWN
    count = len(h.calls)
    with pytest.raises(SecretDlpAssociationHttpTransportError): h.inspect()
    assert len(h.calls) == count
    h.transport.close()


@pytest.mark.parametrize("mode", ["duplicate", "oversize"])
def test_bounded_predecode_denies_invalid_reads(tmp_path: Path, mode: str) -> None:
    h = Harness(tmp_path)
    h.mode = mode
    with pytest.raises(SecretDlpAssociationHttpTransportError): h.inspect()
    assert not h.puts and h.owner._client is None
    h.transport.close()


def test_new_instance_cannot_import_restore_ownership_and_close_denies_login(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    before = h.inspect()
    h.associate(before.state_digest)
    count = len(h.calls)
    with pytest.raises(SecretDlpAssociationHttpTransportError): h.new_transport().inspect_owned_restore()
    assert len(h.calls) == count
    h.transport.close()
    with pytest.raises(SecretDlpAssociationHttpTransportError): h.transport.inspect_owned_restore()
    assert len(h.calls) == count


def test_concrete_owner_same_config_required_and_private_directory_denied(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    other = SecretMetadataHttpTransportConfig(h.config.base_url, "synthetic-token", 5, None)
    with pytest.raises(SecretDlpAssociationHttpTransportError):
        FortiPamSecretDlpAssociationHttpTransport(other, h.owner, h.binding, claim_dir=tmp_path)
    with pytest.raises(SecretDlpAssociationHttpTransportError):
        FortiPamSecretDlpAssociationHttpTransport(h.config, SimpleNamespace(qualified=True), h.binding, claim_dir=tmp_path)  # type: ignore[arg-type]
    tmp_path.chmod(0o755)
    with pytest.raises(SecretDlpAssociationHttpTransportError): h.inspect()
    assert not h.calls
    h.transport.close()


@pytest.mark.parametrize("mode,phase,ack,after,mismatches", [
    ("missing_ack_mkey", SecretDlpDispatchPhase.ACK, SecretDlpQualification.REJECTED,
     SecretDlpQualification.UNKNOWN, set()),
    ("readback_unqualified", SecretDlpDispatchPhase.AFTER_READ, SecretDlpQualification.QUALIFIED,
     SecretDlpQualification.REJECTED, set()),
    ("readback_field", SecretDlpDispatchPhase.PRESERVATION, SecretDlpQualification.QUALIFIED,
     SecretDlpQualification.QUALIFIED, {"opaque_field_digest"}),
    ("readback_metadata", SecretDlpDispatchPhase.PRESERVATION, SecretDlpQualification.QUALIFIED,
     SecretDlpQualification.QUALIFIED, {"preservation_digest", "redacted_metadata_witness_digest"}),
    ("timeout", SecretDlpDispatchPhase.PUT, SecretDlpQualification.UNKNOWN,
     SecretDlpQualification.UNKNOWN, set()),
])
def test_private_dispatch_observation_classifies_only_observed_failure_conditions(
    tmp_path: Path, mode: str, phase: SecretDlpDispatchPhase, ack: SecretDlpQualification,
    after: SecretDlpQualification, mismatches: set[str],
) -> None:
    h = Harness(tmp_path)
    before = h.inspect()
    assert h.transport.dispatch_observation.phase == SecretDlpDispatchPhase.IDLE
    h.mode = mode
    if phase == SecretDlpDispatchPhase.PRESERVATION:
        result = h.associate(before.state_digest)
        assert not result.opaque_fields_match
    else:
        with pytest.raises(SecretDlpAssociationHttpTransportError): h.associate(before.state_digest)
    observation = h.transport.dispatch_observation
    assert observation.phase == phase and observation.put_dispatch_attempted
    assert observation.ack_qualified == ack and observation.after_read_qualified == after
    assert observation.logout_verified == SecretDlpQualification.QUALIFIED
    for field, category in asdict(observation.preservation).items():
        expected = (SecretDlpPreservationMatch.UNKNOWN if after != SecretDlpQualification.QUALIFIED
                    else SecretDlpPreservationMatch.MISMATCH if field in mismatches
                    else SecretDlpPreservationMatch.MATCH)
        assert category == expected
    assert observation.proposed_state_match == (SecretDlpPreservationMatch.MATCH
        if after == SecretDlpQualification.QUALIFIED else SecretDlpPreservationMatch.UNKNOWN)
    text = repr(asdict(observation))
    for private_value in (NAME, SENSOR, SERIAL, before.state_digest, before.opaque_field_digest,
                          "synthetic-opaque-password", "synthetic-account", "synthetic-owner"):
        assert private_value not in text
    count = len(h.calls)
    with pytest.raises(SecretDlpAssociationHttpTransportError): h.transport.inspect_owned_restore()
    with pytest.raises(SecretDlpAssociationHttpTransportError): h.associate(before.state_digest)
    assert len(h.calls) == count and len(h.puts) == 1
    assert h.transport.dispatch_observation == observation
    h.transport.close()
