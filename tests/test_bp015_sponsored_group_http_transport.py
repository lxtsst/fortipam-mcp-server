from __future__ import annotations

import hashlib
import json
from typing import cast

import pytest

import fortipam_mcp.bp015_sponsored_group_http_transport as module
from fortipam_mcp.bp015_sponsored_group_create_contract import SponsoredGroupCreateInput
from fortipam_mcp.bp015_sponsored_group_http_transport import (
    BP015SponsoredGroupHttpTransportError,
    FortiPamBP015SponsoredGroupHttpTransport,
    GROUP_COLLECTION_PATH,
    GROUP_DEFAULT_PATH,
    MEMBER_COLLECTION_PATH,
    OWNER_COLLECTION_PATH,
)
from fortipam_mcp.secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES,
    SecretMetadataHttpTransportConfig,
)


GROUP = "mcp-v4-bp015-sponsored-01"
OWNER = "bp015.owner"


class _Response:
    def __init__(
        self, payload: object, *, status: int = 200, content_type: str = "application/json"
    ) -> None:
        self.status = status
        self._content = json.dumps(payload).encode("utf-8")
        self._offset = 0
        self._content_type = content_type
        self.closed = False

    def getheader(self, name: str, default: str = "") -> str:
        return self._content_type if name.lower() == "content-type" else default

    def readinto(self, target: memoryview) -> int:
        remaining = self._content[self._offset :]
        count = min(len(target), len(remaining))
        target[:count] = remaining[:count]
        self._offset += count
        return count

    def close(self) -> None:
        self.closed = True


class _Connection:
    def __init__(self, response: _Response, calls: list[dict[str, object]]) -> None:
        self._response = response
        self._calls = calls
        self.closed = False

    def request(self, method: str, path: str, **kwargs: object) -> None:
        body = kwargs.get("body")
        if isinstance(body, (bytearray, bytes)):
            kwargs["body"] = bytes(body)
        self._calls.append({"method": method, "path": path, **kwargs})

    def getresponse(self) -> _Response:
        return self._response

    def close(self) -> None:
        self.closed = True


def _config() -> SecretMetadataHttpTransportConfig:
    return SecretMetadataHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _default() -> dict[str, object]:
    return {
        "action": "default", "build": 29, "http_method": "GET", "http_status": 200,
        "name": "group", "path": "user", "revision": "r", "serial": "s",
        "status": "success", "vdom": "root", "version": "v7.0.0",
        "results": {
            "access": "everyone", "auth-concurrent-override": "disable",
            "auth-concurrent-value": 0, "authtimeout": 0, "company": "",
            "creation-time": "", "email": "", "expire": 1, "expire-type": "time",
            "group-max-users": 10, "group-type": "firewall", "guest": [],
            "http-digest-realm": "", "id": 0, "logic-type": "or", "match": [],
            "max-accounts": 0, "member": [], "mobile-phone": "",
            "multiple-guest-add": "disable", "name": "", "password": "",
            "sms-custom-server": "", "sms-server": "", "sponsor": "",
            "sso-attribute-value": "", "user-id": "", "user-name": "",
            "user-permission": [],
        },
    }


def _collection(results: list[object], *, path: str, name: str) -> dict[str, object]:
    envelope: dict[str, object] = {
        "build": 29, "http_method": "POST", "http_status": 200,
        "name": name, "path": path,
        "results": results,
        "status": "OK" if (path, name) == ("user", "group") else "success",
        "version": "v7.0.0",
    }
    if (path, name) == ("system", "admin"):
        envelope["matched_count"] = len(results)
        envelope["next_idx"] = 3 if results else 0
        envelope["size"] = 7
    return envelope


def _group() -> dict[str, object]:
    return {
        "name": GROUP, "group-type": "sponsor", "group-max-users": 7,
        "access": "customized", "member": [],
        "user-permission": [
            {"id": 1, "permission": "owner", "user-name": [{"name": OWNER}]}
        ],
    }


def _group_with_origin_metadata() -> dict[str, object]:
    record = _group()
    record["user-permission"] = [
        {
            "id": 1,
            "permission": "owner",
            "q_origin_key": 1,
            "user-name": [{"name": OWNER, "q_origin_key": OWNER}],
        }
    ]
    return record


def _write_success(method: str) -> dict[str, object]:
    return {
        "build": 29,
        "http_method": method,
        "http_status": 200,
        "name": "group",
        "path": "user",
        "status": "success",
        "version": "v7.0.0",
    }


def _transport(
    monkeypatch: pytest.MonkeyPatch, responses: list[_Response]
) -> tuple[FortiPamBP015SponsoredGroupHttpTransport, list[dict[str, object]]]:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(module, "_ssl_context", lambda _: object())

    def _factory(*_args: object, **_kwargs: object) -> _Connection:
        return _Connection(responses.pop(0), calls)

    return FortiPamBP015SponsoredGroupHttpTransport(_config(), connection_factory=_factory), calls


def _create_responses(*, readback: dict[str, object] | None = None, post_status: int = 200) -> list[_Response]:
    return [
        _Response(_default()),
        _Response(_collection([{"name": OWNER}], path="system", name="admin")),
        _Response(_collection([], path="user", name="group")),
        _Response(_write_success("POST"), status=post_status),
        _Response(_collection([readback or _group()], path="user", name="group")),
    ]


def test_create_uses_only_fixed_routes_filters_headers_and_minimal_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, calls = _transport(monkeypatch, _create_responses())

    result = transport.create_and_readback(SponsoredGroupCreateInput(GROUP, OWNER, 7))

    assert result.verified is True
    assert result.create_response_category == "accepted"
    assert [call["path"] for call in calls] == [
        GROUP_DEFAULT_PATH, OWNER_COLLECTION_PATH, GROUP_COLLECTION_PATH,
        "/api/v2/cmdb/user/group", GROUP_COLLECTION_PATH,
    ]
    assert [call["method"] for call in calls] == ["GET", "POST", "POST", "POST", "POST"]
    assert all(call["headers"] != {} for call in calls)
    for call in calls:
        headers = call["headers"]
        assert isinstance(headers, dict)
        assert headers["Authorization"] == "Bearer unit-test-token"
        assert headers["Connection"] == "close"
    owner_headers = cast(dict[str, str], calls[1]["headers"])
    group_headers = cast(dict[str, str], calls[2]["headers"])
    create_headers = cast(dict[str, str], calls[3]["headers"])
    assert owner_headers["X-HTTP-Method-Override"] == "GET"
    assert group_headers["X-HTTP-Method-Override"] == "GET"
    assert create_headers.get("X-HTTP-Method-Override") is None
    assert json.loads(calls[1]["body"]) == module._owner_filter_body(OWNER)  # type: ignore[arg-type]
    assert json.loads(calls[2]["body"]) == module._group_filter_body(GROUP)  # type: ignore[arg-type]
    assert json.loads(calls[3]["body"]) == SponsoredGroupCreateInput(GROUP, OWNER, 7).body(  # type: ignore[arg-type]
        module.SponsoredGroupDefaultEvidence()
    )
    assert "mcp-v4-bp015" not in repr(result)
    assert OWNER not in repr(result)


def test_already_existing_group_stops_before_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = [
        _Response(_default()),
        _Response(_collection([{"name": OWNER}], path="system", name="admin")),
        _Response(_collection([{"name": GROUP}], path="user", name="group")),
    ]
    transport, calls = _transport(monkeypatch, responses)

    with pytest.raises(BP015SponsoredGroupHttpTransportError, match="unavailable"):
        transport.create_and_readback(SponsoredGroupCreateInput(GROUP, OWNER, 7))

    assert len(calls) == 3


def test_ambiguous_create_is_reconciled_by_exact_readback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, calls = _transport(monkeypatch, _create_responses(post_status=500))

    result = transport.create_and_readback(SponsoredGroupCreateInput(GROUP, OWNER, 7))

    assert result.verified is True
    assert result.create_response_category == "ambiguous"
    assert [call["method"] for call in calls].count("POST") == 4


def test_readback_accepts_only_the_known_q_origin_key_metadata() -> None:
    relation = cast(list[object], _group_with_origin_metadata()["user-permission"])
    assert module._exact_owner(relation, OWNER) is True

    bad = cast(dict[str, object], relation[0]).copy()
    bad["unexpected"] = True
    assert module._exact_owner([bad], OWNER) is False


@pytest.mark.parametrize(
    "field,value",
    [("group-type", "firewall"), ("group-max-users", True), ("member", [{"name": "x"}])],
)
def test_readback_drift_is_categorical_and_not_cleanup_eligible(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    record = _group()
    record[field] = value
    transport, _ = _transport(monkeypatch, _create_responses(readback=record))

    result = transport.create_and_readback(SponsoredGroupCreateInput(GROUP, OWNER, 7))

    assert result.verified is False
    with pytest.raises(BP015SponsoredGroupHttpTransportError, match="unavailable"):
        transport.cleanup_bound_disposable()


@pytest.mark.parametrize("owners", [[], [{"name": OWNER}, {"name": OWNER}]])
def test_owner_no_match_or_multiple_blocks_create(
    monkeypatch: pytest.MonkeyPatch, owners: list[object]
) -> None:
    transport, calls = _transport(
        monkeypatch,
        [_Response(_default()), _Response(_collection(owners, path="system", name="admin"))],
    )

    with pytest.raises(BP015SponsoredGroupHttpTransportError, match="unavailable"):
        transport.create_and_readback(SponsoredGroupCreateInput(GROUP, OWNER, 7))

    assert len(calls) == 2


def test_protected_api_owner_binding_skips_system_admin_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = [
        _Response(_default()),
        _Response(_collection([], path="user", name="group")),
        _Response(_write_success("POST")),
        _Response(_collection([_group_with_origin_metadata()], path="user", name="group")),
    ]
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(module, "_ssl_context", lambda _: object())

    def _factory(*_args: object, **_kwargs: object) -> _Connection:
        return _Connection(responses.pop(0), calls)

    transport = FortiPamBP015SponsoredGroupHttpTransport(
        _config(), bound_api_owner_name=OWNER, connection_factory=_factory
    )

    result = transport.create_and_readback(
        SponsoredGroupCreateInput(GROUP, OWNER, 7)
    )

    assert result.verified is True
    assert OWNER_COLLECTION_PATH not in [call["path"] for call in calls]


def test_collection_envelopes_keep_group_and_admin_shapes_distinct() -> None:
    group = _collection([], path="user", name="group")
    admin = _collection([], path="system", name="admin")

    assert module._collection_records(group, 200, path="user", name="group") == []
    assert module._collection_records(admin, 200, path="system", name="admin") == []

    group["status"] = "success"
    with pytest.raises(BP015SponsoredGroupHttpTransportError, match="unavailable"):
        module._collection_records(group, 200, path="user", name="group")

    admin["size"] = True
    with pytest.raises(BP015SponsoredGroupHttpTransportError, match="unavailable"):
        module._collection_records(admin, 200, path="system", name="admin")


def test_cleanup_checks_member_relation_then_group_then_delete_and_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = _create_responses() + [
        _Response(_collection([], path="system", name="admin")),
        _Response(_collection([_group()], path="user", name="group")),
        _Response(_write_success("DELETE")),
        _Response(_collection([], path="user", name="group")),
    ]
    transport, calls = _transport(monkeypatch, responses)
    transport.create_and_readback(SponsoredGroupCreateInput(GROUP, OWNER, 7))

    result = transport.cleanup_bound_disposable()

    categorical = {
        "member_relation_zero": True, "group_readback_verified": True,
        "delete_response_category": "accepted", "group_absent_after_delete": True,
    }
    assert result.verified is True
    assert result.cleanup_digest == hashlib.sha256(
        json.dumps(categorical, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert [call["path"] for call in calls[-4:]] == [
        MEMBER_COLLECTION_PATH, GROUP_COLLECTION_PATH,
        "/api/v2/cmdb/user/group/mcp-v4-bp015-sponsored-01", GROUP_COLLECTION_PATH,
    ]
    assert calls[-2]["method"] == "DELETE"
    assert json.loads(calls[-4]["body"]) == module._member_filter_body(GROUP)  # type: ignore[arg-type]


def test_member_relation_nonzero_blocks_delete_and_ambiguous_delete_reconciles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    blocked = _create_responses() + [_Response(_collection([{"name": "private"}], path="system", name="admin"))]
    transport, calls = _transport(monkeypatch, blocked)
    transport.create_and_readback(SponsoredGroupCreateInput(GROUP, OWNER, 7))
    with pytest.raises(BP015SponsoredGroupHttpTransportError, match="unavailable"):
        transport.cleanup_bound_disposable()
    assert not any(call["method"] == "DELETE" for call in calls)

    ambiguous = _create_responses() + [
        _Response(_collection([], path="system", name="admin")),
        _Response(_collection([_group()], path="user", name="group")),
        _Response(_write_success("DELETE"), status=500),
        _Response(_collection([], path="user", name="group")),
    ]
    transport, _ = _transport(monkeypatch, ambiguous)
    transport.create_and_readback(SponsoredGroupCreateInput(GROUP, OWNER, 7))
    result = transport.cleanup_bound_disposable()
    assert result.verified is True
    assert result.delete_response_category == "ambiguous"


def test_rejects_unsafe_input_and_response_limits_without_leaking_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(Exception):
        SponsoredGroupCreateInput("bad/group", OWNER, 7)
    oversized = _Response({})
    oversized._content = b"x" * (MAX_RESPONSE_BYTES + 1)
    transport, calls = _transport(monkeypatch, [oversized])
    with pytest.raises(BP015SponsoredGroupHttpTransportError, match="unavailable"):
        transport.create_and_readback(SponsoredGroupCreateInput(GROUP, OWNER, 7))


def test_delete_path_quotes_even_if_private_method_is_misused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, calls = _transport(monkeypatch, [_Response(_write_success("DELETE"))])

    assert transport._delete_once("mcp-v4-bp015-a/b") == "accepted"

    assert calls[0]["path"] == "/api/v2/cmdb/user/group/mcp-v4-bp015-a%2Fb"
    assert len(calls) == 1
    transport, _ = _transport(monkeypatch, [_Response({}, content_type="text/html")])
    with pytest.raises(BP015SponsoredGroupHttpTransportError, match="unavailable"):
        transport.create_and_readback(SponsoredGroupCreateInput(GROUP, OWNER, 7))
