from __future__ import annotations

import hashlib
import json
from collections.abc import Callable

import pytest

from fortipam_mcp.bp015_sponsored_group_projection import (
    BP015SponsoredGroupProjectionError,
    COLLECTION_BODY,
    COLLECTION_PATH,
    FortiPamBP015SponsoredGroupProjection,
)
from fortipam_mcp.secret_metadata_http_transport import SecretMetadataHttpTransportConfig


class _Response:
    def __init__(self, body: bytes, *, status: int = 200, content_type: str = "application/json") -> None:
        self.status = status
        self._body = body
        self._offset = 0
        self._content_type = content_type

    def getheader(self, name: str, default: str = "") -> str:
        return self._content_type if name.lower() == "content-type" else default

    def readinto(self, view: memoryview) -> int:
        remaining = self._body[self._offset :]
        count = min(len(view), len(remaining))
        view[:count] = remaining[:count]
        self._offset += count
        return count

    def close(self) -> None:
        pass


class _Connection:
    def __init__(self, response: _Response) -> None:
        self.response = response
        self.request_args: tuple[object, ...] | None = None
        self.closed = False

    def request(self, *args: object, **kwargs: object) -> None:
        self.request_args = (*args, kwargs)

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.closed = True


def _config() -> SecretMetadataHttpTransportConfig:
    return SecretMetadataHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _sponsor(*, maximum: int = 10, permissions: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "id": 999,
        "name": "must-not-escape",
        "group-type": "sponsor",
        "group-max-users": maximum,
        "user-permission": permissions if permissions is not None else [],
    }


def _relation(permission: str = "use") -> dict[str, object]:
    return {
        "id": 71,
        "permission": permission,
        "user-name": [{"name": "must-not-escape"}],
    }


def _payload(records: list[dict[str, object]] | None = None) -> dict[str, object]:
    return {
        "http_method": "POST",
        "http_status": 200,
        "results": records if records is not None else [],
        "status": "OK",
        "version": "v7.0.0",
        "build": 29,
        "vdom": "root",
        "path": "user",
        "name": "group",
    }


def _probe(payload: object) -> tuple[FortiPamBP015SponsoredGroupProjection, _Connection]:
    connection = _Connection(_Response(json.dumps(payload).encode("utf-8")))
    return (
        FortiPamBP015SponsoredGroupProjection(
            _config(), connection_factory=lambda *args, **kwargs: connection
        ),
        connection,
    )


def test_inspect_projects_only_safe_sponsor_bands() -> None:
    payload = _payload(
        [
            _sponsor(permissions=[_relation("use"), _relation("owner")]),
            _sponsor(maximum=10_000, permissions=[_relation("use")]),
        ]
    )
    probe, connection = _probe(payload)

    result = probe.inspect()

    categorical = {
        "sponsored_group_count_band": "multiple",
        "sponsored_group_records_observed": True,
        "group_max_users_in_range": True,
        "permission_relation_count_band": "multiple",
        "permission_relations_observed": True,
        "permission_levels_use_or_owner_only": True,
    }
    assert result == {
        **categorical,
        "projection_digest": hashlib.sha256(
            json.dumps(categorical, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
        "device_access": True,
        "device_write_executed": False,
        "source_contract_ready": False,
    }
    assert connection.request_args is not None
    assert connection.request_args[0:2] == ("POST", COLLECTION_PATH)
    request_kwargs = connection.request_args[2]
    assert isinstance(request_kwargs, dict)
    assert request_kwargs["body"] == COLLECTION_BODY
    headers = request_kwargs["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == "Bearer unit-test-token"
    assert headers["Content-Type"] == "application/json"
    assert headers["X-HTTP-Method-Override"] == "GET"
    assert "must-not-escape" not in repr(result)
    assert "999" not in repr(result)
    assert connection.closed is True


def test_inspect_returns_zero_bands_when_no_sponsored_groups_exist() -> None:
    probe, _ = _probe(_payload([]))

    result = probe.inspect()

    assert result["sponsored_group_count_band"] == "zero"
    assert result["sponsored_group_records_observed"] is False
    assert result["group_max_users_in_range"] is False
    assert result["permission_relation_count_band"] == "zero"
    assert result["permission_relations_observed"] is False
    assert result["permission_levels_use_or_owner_only"] is False
    assert result["device_access"] is True
    assert result["source_contract_ready"] is False


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.__setitem__("version", "v7.0.1"),
        lambda payload: payload.__setitem__("build", 30),
        lambda payload: payload.__setitem__("unexpected", True),
        lambda payload: payload["results"].append({"name": "bad", "group-type": "pam-users"}),
        lambda payload: payload["results"][0].__setitem__("group-type", "unknown"),
        lambda payload: payload["results"][0].__setitem__("group-max-users", 0),
        lambda payload: payload["results"][0]["user-permission"][0].__setitem__("permission", "none"),
        lambda payload: payload["results"][0]["user-permission"][0]["user-name"].__setitem__(0, {"identity": "bad"}),
    ),
)
def test_inspect_fails_closed_for_drift_or_malformed_sponsor_records(
    mutate: Callable[[dict[str, object]], None],
) -> None:
    payload = _payload([_sponsor(permissions=[_relation()])])
    mutate(payload)
    probe, _ = _probe(payload)

    with pytest.raises(BP015SponsoredGroupProjectionError, match="unavailable"):
        probe.inspect()


def test_inspect_fails_closed_for_non_json_and_oversized_responses() -> None:
    connection = _Connection(_Response(b"{}", content_type="text/html"))
    probe = FortiPamBP015SponsoredGroupProjection(
        _config(), connection_factory=lambda *args, **kwargs: connection
    )
    with pytest.raises(BP015SponsoredGroupProjectionError, match="unavailable"):
        probe.inspect()

    oversized_connection = _Connection(_Response(b"x" * 1_048_577))
    oversized_probe = FortiPamBP015SponsoredGroupProjection(
        _config(), connection_factory=lambda *args, **kwargs: oversized_connection
    )
    with pytest.raises(BP015SponsoredGroupProjectionError, match="unavailable"):
        oversized_probe.inspect()
