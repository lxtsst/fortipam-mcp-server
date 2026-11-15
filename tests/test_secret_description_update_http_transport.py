from contextlib import contextmanager
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from fortipam_mcp.secret_description_update_http_transport import (
    FortiPamSecretDescriptionUpdateHttpTransport, SecretDescriptionBinding,
    SecretDescriptionUpdateHttpTransportError, _field_witness,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


@pytest.mark.parametrize("mode", ["success", "success_list", "ambiguous", "drift", "credential_drift", "retained_success", "retained_drift", "retained_identity_drift"])
def test_fixed_owner_delta_durably_denies_replay_and_preserves_metadata(tmp_path: Path, mode: str) -> None:
    tmp_path.chmod(0o700)
    calls = []
    row = {"id": 17, "folder": 9, "name": "mcp-v4-secret-metadata-update-r1",
           "template": "Unix Account (SSH Password)", "target": "synthetic-target",
           "description": "Before", "recording": "enable", "uuid": "synthetic",
           "field": [{"id": 1, "name": "Password", "value": "synthetic-material", "keyinfo": ""},
                     {"id": 2, "name": "Username", "value": "synthetic-account", "keyinfo": ""},
                     {"id": 3, "name": "Host", "value": "192.0.2.1", "keyinfo": ""}]}

    if mode == "retained_success":
        for item in row["field"]:
            item.pop("keyinfo")

    class Client:
        def build_request(self, *args):
            return SimpleNamespace(headers={"cookie": "ccsrftoken=synthetic-csrf"})

        @contextmanager
        def stream(self, method, path, **kwargs):
            calls.append((method, path, kwargs))
            if method == "PUT":
                assert claim.exists()
                body = json.loads(kwargs["content"])
                if mode.startswith("retained_"):
                    assert set(body) == {"id", "name", "folder", "template", "description", "target", "field"}
                    assert [item["name"] for item in body["field"]] == ["Password", "Username"]
                    assert body["field"] == row["field"][:2]
                    row["field"] = body["field"]
                else:
                    assert set(body) == {"id", "name", "folder", "template", "description"}
                assert kwargs["headers"]["X-CSRFTOKEN"] == "synthetic-csrf"
                row["description"] = body["description"]
                if mode in {"credential_drift", "retained_drift"}:
                    row["field"][0]["value"] = "changed-synthetic-material"
                if mode == "ambiguous":
                    raise TimeoutError
            payload = {"version": "v7.0.0", "build": 29, "http_status": 200,
                       "http_method": method, "status": "OK", "path": "secret",
                       "name": "database", "results": [dict(row)] if mode == "success_list" else dict(row)}
            yield SimpleNamespace(status_code=200, headers={"content-type": "application/json"},
                                  iter_bytes=lambda: iter([json.dumps(payload).encode()]))

    class Owner:
        def __init__(self):
            self._client = Client()
            self.logout_verified = False

        @contextmanager
        def authenticated(self):
            calls.append(("login",))
            try:
                yield self
            finally:
                self.logout_verified = True

        def resolve_folder_id(self, path):
            return 9

        def _lookup_id(self, kind, path):
            return 17

    claim = tmp_path / "claim.json"
    config = SecretMetadataHttpTransportConfig("https://example.test", "synthetic-token", 15, None)
    binding = SecretDescriptionBinding("owner", "Root/fixture", row["name"], row["target"], row["template"], "192.0.2.1")

    def transport():
        return FortiPamSecretDescriptionUpdateHttpTransport(
            config, binding, lambda: ("owner", "synthetic-password"), description="After",
            claim_path=claim, owner_factory=Owner, sleep=lambda _: None,
            retained_account=(lambda: "synthetic-account")
                if mode.startswith("retained_") else None,
        )

    adapter = transport()
    before = adapter.inspect()
    assert "synthetic-material" not in repr(before)
    if mode == "drift":
        row["recording"] = "disable"
    if mode == "retained_identity_drift":
        row["field"][1]["value"] = "different-account"
    if mode in {"success", "success_list", "credential_drift", "retained_success", "retained_drift"}:
        result = adapter.update_and_readback(before)
        assert result.verified is (mode not in {"credential_drift", "retained_drift"})
        assert result.credential_field_bytes_preserved is (mode not in {"credential_drift", "retained_success", "retained_drift"})
        assert result.retained_field_values_match is (mode == "retained_success")
    else:
        with pytest.raises(SecretDescriptionUpdateHttpTransportError):
            adapter.update_and_readback(before)
    if mode in {"drift", "retained_identity_drift"}:
        assert not claim.exists()
        assert all(call[0] != "PUT" for call in calls)
    else:
        assert claim.stat().st_mode & 0o777 == 0o600
        assert len([call for call in calls if call[0] == "PUT"]) == 1
        count = len(calls)
        with pytest.raises(SecretDescriptionUpdateHttpTransportError):
            transport().inspect()
        assert len(calls) == count


def test_witness_accepts_only_identical_duplicate_values_without_decoding_fields() -> None:
    key = bytearray(b"synthetic-key")
    identical = bytearray(b'{"results":[{"other":1,"other":1,"field":[{"value":"synthetic"}]}]}')
    assert len(_field_witness(identical, key)) == 32
    conflicting = bytearray(b'{"results":[{"other":1,"other":2,"field":[]}]}')
    with pytest.raises(ValueError, match="witness_duplicate_conflict"):
        _field_witness(conflicting, key)
    multi = bytearray(b'{"results":[{"field":[]},{"field":[]}]}')
    with pytest.raises(ValueError, match="witness_multiple_results"):
        _field_witness(multi, key)
