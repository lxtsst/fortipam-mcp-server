from __future__ import annotations

from collections.abc import Iterator, Mapping
import inspect
import json
from pathlib import Path
import ssl
from typing import Any, Literal

import pytest

import fortipam_mcp.folder_http_transport as transport_module
from fortipam_mcp.folder_create_contract import FolderCreateRequest
from fortipam_mcp.folder_m4_adapter import ChildFolderMutationTransport
from fortipam_mcp.folder_http_transport import (
    COLLECTION_PATH,
    FolderTransportConfig,
    FolderTransportConfigurationError,
    FolderTransportError,
    FortiPamFolderHttpTransport,
    MAX_RESPONSE_BYTES,
    ResponseStream,
    ResponseStreamContext,
    SyncHttpClient,
    load_folder_archive_transport_config,
    load_folder_transport_config,
)


class _FakeResponse(ResponseStream, ResponseStreamContext):
    def __init__(
        self,
        *,
        status_code: int = 200,
        headers: Mapping[str, str] | None = None,
        chunks: list[bytes] | None = None,
    ) -> None:
        self.status_code = status_code
        self.headers = dict(headers or {"content-type": "application/json"})
        self._chunks = chunks if chunks is not None else [b'{"ok":true}']

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None:
        return None

    def iter_bytes(self) -> Iterator[bytes]:
        yield from self._chunks


class _FakeClient(SyncHttpClient):
    def __init__(self, response: _FakeResponse, *, failure: Exception | None = None) -> None:
        self.response = response
        self.failure = failure
        self.calls: list[dict[str, object]] = []

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> bool | None:
        return None

    def stream(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str],
        content: bytes | None,
    ) -> _FakeResponse:
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": dict(headers),
                "content": content,
            }
        )
        if self.failure is not None:
            raise self.failure
        return self.response


class _FakeFactory:
    def __init__(self, client: _FakeClient) -> None:
        self.client = client
        self.arguments: dict[str, object] | None = None

    def __call__(
        self,
        *,
        verify: ssl.SSLContext,
        timeout: float,
        follow_redirects: Literal[False],
        trust_env: Literal[False],
    ) -> _FakeClient:
        self.arguments = {
            "verify": verify,
            "timeout": timeout,
            "follow_redirects": follow_redirects,
            "trust_env": trust_env,
        }
        return self.client


def _environment(**overrides: str) -> dict[str, str]:
    environment = {
        "FPA_HOME_LAB_FPA1_V4_FOLDER_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_FOLDER_HOST": "fortipam.example.test",
        "FPA_HOME_LAB_FPA1_V4_FOLDER_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_FOLDER_TIMEOUT_SECONDS": "12",
    }
    environment.update(overrides)
    return environment


def _transport(
    response: _FakeResponse | None = None,
    *,
    failure: Exception | None = None,
) -> tuple[FortiPamFolderHttpTransport, _FakeClient, _FakeFactory]:
    config = load_folder_transport_config(_environment())
    client = _FakeClient(response or _FakeResponse(), failure=failure)
    factory = _FakeFactory(client)
    return (
        FortiPamFolderHttpTransport(config, client_factory=factory),
        client,
        factory,
    )


def _child_body() -> dict[str, object]:
    return FolderCreateRequest.child("Contractor-Secrets", 101).body()


def _update_body() -> dict[str, object]:
    return {
        "id": 42,
        "name": "Contractor-Secrets",
        "parent-folder": 101,
        "folder-type": "public",
        "secret-policy": "default",
        "inherit-policy": "enable",
        "inherit-permission": "disable",
        "inherit-folder-ztna": "enable",
        "ztna-ems-tag": [],
        "ztna-tags-match-logic": "or",
        "user-permission": [
            {
                "id": 0,
                "user-name": [{"name": "mcp-folder-user-01"}],
                "folder-permission": "view",
                "secret-permission": "view",
            }
        ],
        "group-permission": [],
    }


def _require_m4_transport(
    value: ChildFolderMutationTransport,
) -> ChildFolderMutationTransport:
    return value


def test_transport_is_disabled_by_default_and_uses_only_dedicated_environment() -> None:
    with pytest.raises(FolderTransportConfigurationError, match="exactly true"):
        load_folder_transport_config(
            {
                "FPA_HOME_LAB_FPA1_HOST": "legacy.example.test",
                "FPA_HOME_LAB_FPA1_API_TOKEN": "legacy-token",
            }
        )
    with pytest.raises(FolderTransportConfigurationError, match="disabled by default"):
        FolderTransportConfig(
            base_url="https://fortipam.example.test",
            bearer_token="unit-test-token",
            timeout_seconds=12,
            ca_file=None,
        )


@pytest.mark.parametrize(
    "target",
    (
        "http://fortipam.example.test",
        "https://user:pass@fortipam.example.test",
        "https://fortipam.example.test/api",
        "https://fortipam.example.test?query=yes",
        "https://fortipam.example.test#fragment",
    ),
)
def test_configuration_requires_a_clean_https_origin(target: str) -> None:
    with pytest.raises(FolderTransportConfigurationError, match="HTTPS origin"):
        load_folder_transport_config(
            _environment(
                FPA_HOME_LAB_FPA1_V4_FOLDER_BASE_URL=target,
                FPA_HOME_LAB_FPA1_V4_FOLDER_HOST="",
            )
        )


def test_collection_and_detail_reads_use_only_fixed_urls_and_tls_policy() -> None:
    transport, client, factory = _transport()

    assert transport.read_collection() == {"ok": True, "http_status": 200}
    assert transport.read_folder(42) == {"ok": True, "http_status": 200}

    assert [(call["method"], call["url"], call["content"]) for call in client.calls] == [
        ("GET", f"https://fortipam.example.test{COLLECTION_PATH}", None),
        ("GET", f"https://fortipam.example.test{COLLECTION_PATH}/42", None),
    ]
    assert factory.arguments is not None
    assert factory.arguments["follow_redirects"] is False
    assert factory.arguments["trust_env"] is False
    assert factory.arguments["timeout"] == 12.0
    context = factory.arguments["verify"]
    assert isinstance(context, ssl.SSLContext)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    headers = client.calls[0]["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == "Bearer unit-test-token"


@pytest.mark.parametrize("folder_id", (0, -1, True, "1", 2_147_483_648))
def test_detail_read_rejects_every_non_positive_int32_id(folder_id: object) -> None:
    transport, client, _factory = _transport()
    with pytest.raises(FolderTransportError, match="positive signed int32"):
        transport.read_folder(folder_id)  # type: ignore[arg-type]
    assert client.calls == []


def test_post_accepts_the_exact_evidence_aware_child_body() -> None:
    transport, client, _factory = _transport()

    response = transport.create_child(_child_body())

    assert response == {"ok": True, "http_status": 200}
    assert len(client.calls) == 1
    call = client.calls[0]
    assert (call["method"], call["url"]) == (
        "POST",
        f"https://fortipam.example.test{COLLECTION_PATH}",
    )
    assert json.loads(call["content"]) == _child_body()  # type: ignore[arg-type]
    headers = call["headers"]
    assert isinstance(headers, dict)
    assert headers["Content-Type"] == "application/json"


def test_put_accepts_only_the_fixed_folder_detail_and_documented_acl_projection() -> None:
    transport, client, _factory = _transport()

    response = transport.update_folder(42, _update_body())

    assert response == {"ok": True, "http_status": 200}
    assert len(client.calls) == 1
    call = client.calls[0]
    assert (call["method"], call["url"]) == (
        "PUT",
        f"https://fortipam.example.test{COLLECTION_PATH}/42",
    )
    assert json.loads(call["content"]) == _update_body()  # type: ignore[arg-type]


def test_put_rejects_product_error_envelope_over_http_200_without_disclosure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    response_secret = "response-super-secret"
    transport, client, _factory = _transport(
        _FakeResponse(
            chunks=[
                json.dumps(
                    {
                        "status": "error",
                        "message": response_secret,
                    }
                ).encode()
            ]
        )
    )

    with pytest.raises(FolderTransportError) as captured:
        transport.update_folder(42, _update_body())

    assert str(captured.value) == "FortiPAM reported an unsuccessful Folder update."
    assert "method=PUT product_status=error" in caplog.text
    assert response_secret not in str(captured.value)
    assert response_secret not in caplog.text
    assert "unit-test-token" not in str(captured.value)
    assert len(client.calls) == 1


def test_delete_accepts_only_one_positive_int32_folder_id_from_its_own_namespace() -> None:
    environment = {
        "FPA_HOME_LAB_FPA1_V4_FOLDER_ARCHIVE_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_FOLDER_ARCHIVE_HOST": "fortipam.example.test",
        "FPA_HOME_LAB_FPA1_V4_FOLDER_ARCHIVE_API_TOKEN": "unit-test-token",
    }
    client = _FakeClient(_FakeResponse())
    factory = _FakeFactory(client)
    transport = FortiPamFolderHttpTransport(
        load_folder_archive_transport_config(environment),
        client_factory=factory,
    )

    response = transport.delete_empty_folder(42)

    assert response == {"ok": True, "http_status": 200}
    assert [(call["method"], call["url"], call["content"]) for call in client.calls] == [
        ("DELETE", f"https://fortipam.example.test{COLLECTION_PATH}/42", None),
    ]
    with pytest.raises(FolderTransportError, match="positive signed int32"):
        transport.delete_empty_folder(0)
    assert len(client.calls) == 1


def test_archive_transport_requires_its_own_explicit_enablement() -> None:
    with pytest.raises(FolderTransportConfigurationError, match="exactly true"):
        load_folder_archive_transport_config(
            {
                "FPA_HOME_LAB_FPA1_V4_FOLDER_ARCHIVE_HOST": "fortipam.example.test",
                "FPA_HOME_LAB_FPA1_V4_FOLDER_ARCHIVE_API_TOKEN": "unit-test-token",
            }
        )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda body: body.update({"unexpected": "value"}),
        lambda body: body.pop("secret-policy"),
        lambda body: body.update({"id": 41}),
        lambda body: body.update({"parent-folder": 0}),
        lambda body: body.update({"folder-type": "private"}),
        lambda body: body.update({"inherit-permission": "enable"}),
        lambda body: body.update({"user-permission": [{"user-name": []}]}),
        lambda body: body.update(
            {
                "user-permission": [
                    {
                        "id": 0,
                        "user-name": [{"name": "mcp-folder-user-01"}],
                        "folder-permission": "view",
                        "secret-permission": "view",
                        "allowed-launcher-type": "all",
                    }
                ]
            }
        ),
    ),
)
def test_put_rejects_non_contract_acl_projections(mutation: Any) -> None:
    body = _update_body()
    mutation(body)
    transport, client, _factory = _transport()

    with pytest.raises(FolderTransportError):
        transport.update_folder(42, body)
    assert client.calls == []


@pytest.mark.parametrize(
    "mutation",
    (
        lambda body: body.update({"unexpected": "value"}),
        lambda body: body.pop("group-permission"),
        lambda body: body.update({"id": 1}),
        lambda body: body.update({"id": False}),
        lambda body: body.update({"parent-folder": 0}),
        lambda body: body.update({"parent-folder": True}),
        lambda body: body.update({"parent-folder": 2_147_483_648}),
        lambda body: body.update({"name": "bad/name"}),
        lambda body: body.update({"name": "bad\\name"}),
        lambda body: body.update({"name": "x" * 65}),
        lambda body: body.update({"inherit-policy": "disable"}),
        lambda body: body.update({"inherit-permission": "disable"}),
        lambda body: body.update({"inherit-folder-ztna": "disable"}),
        lambda body: body.update({"ztna-ems-tag": ["unproven-tag-shape"]}),
        lambda body: body.update({"ztna-tags-match-logic": "unknown"}),
        lambda body: body.update({"user-permission": [{"user": "admin"}]}),
        lambda body: body.update({"group-permission": ["operators"]}),
        lambda body: body.update({"user-permission": ()}),
    ),
)
def test_post_rejects_root_permission_unknown_or_drifted_body(
    mutation: Any,
) -> None:
    body = _child_body()
    mutation(body)
    transport, client, _factory = _transport()

    with pytest.raises(FolderTransportError):
        transport.create_child(body)
    assert client.calls == []


def test_post_enforces_the_encoded_request_size_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(transport_module, "MAX_REQUEST_BYTES", 1)
    transport, client, _factory = _transport()

    with pytest.raises(FolderTransportError, match="request exceeded"):
        transport.create_child(_child_body())
    assert client.calls == []


def test_status_error_never_includes_response_body_or_bearer_token(caplog) -> None:
    response_secret = "response-super-secret"
    transport, _client, _factory = _transport(
        _FakeResponse(
            status_code=403,
            chunks=[json.dumps({"password": response_secret}).encode()],
        )
    )

    with pytest.raises(FolderTransportError) as captured:
        transport.read_collection()

    assert str(captured.value) == "FortiPAM returned HTTP 403."
    assert response_secret not in str(captured.value)
    assert "unit-test-token" not in str(captured.value)
    assert "method=GET http_status=403" in caplog.text
    assert response_secret not in caplog.text
    assert "unit-test-token" not in caplog.text
    assert "fortipam.example.test" not in caplog.text


@pytest.mark.parametrize(
    ("response", "message"),
    (
        (
            _FakeResponse(headers={"content-type": "text/html"}, chunks=[b"secret"]),
            "content type",
        ),
        (
            _FakeResponse(headers={"content-type": "application/json"}, chunks=[b"{"]),
            "malformed JSON",
        ),
        (
            _FakeResponse(
                headers={"content-type": "application/json", "content-length": "invalid"}
            ),
            "content length",
        ),
        (
            _FakeResponse(
                headers={
                    "content-type": "application/json",
                    "content-length": str(MAX_RESPONSE_BYTES + 1),
                },
                chunks=[],
            ),
            "1 MiB",
        ),
        (
            _FakeResponse(
                headers={"content-type": "application/json"},
                chunks=[b"a" * MAX_RESPONSE_BYTES, b"b"],
            ),
            "1 MiB",
        ),
    ),
)
def test_response_content_and_size_fail_closed(
    response: _FakeResponse,
    message: str,
) -> None:
    transport, _client, _factory = _transport(response)
    with pytest.raises(FolderTransportError, match=message):
        transport.read_collection()


def test_network_exception_is_replaced_by_a_non_disclosing_error() -> None:
    transport, _client, _factory = _transport(
        failure=OSError("connect failed with unit-test-token")
    )
    with pytest.raises(FolderTransportError) as captured:
        transport.read_collection()
    assert str(captured.value) == "Unable to complete the fixed FortiPAM folder request."
    assert "unit-test-token" not in str(captured.value)


def test_http_status_is_bound_to_the_actual_response_not_body_data() -> None:
    transport, _client, _factory = _transport(
        _FakeResponse(chunks=[b'{"http_status":999,"results":[],"mkey":77}'])
    )
    assert transport.read_collection() == {
        "http_status": 200,
        "results": [],
        "mkey": 77,
    }


def test_transport_directly_satisfies_the_unregistered_m4_protocol() -> None:
    transport, _client, _factory = _transport()
    assert _require_m4_transport(transport) is transport


def test_non_object_json_is_rejected_before_m4_adapter_consumption() -> None:
    transport, _client, _factory = _transport(_FakeResponse(chunks=[b"[]"]))
    with pytest.raises(FolderTransportError, match="JSON shape"):
        transport.read_collection()


def test_module_has_no_server_registration_or_runtime_binding() -> None:
    source = inspect.getsource(transport_module)
    assert "FastMCP" not in source
    assert ".tool(" not in source
    assert "folder_m4_adapter" not in source
    # The only destructive verb is the bounded exact-ID empty-Folder deletion
    # used by the independently gated V4 folder.archive action.
    assert "def delete_empty_folder" in source
    assert '"DELETE"' in source
    assert '"PATCH"' not in source
    repository = Path(__file__).resolve().parents[1]
    for relative in (
        "src/fortipam_mcp/server.py",
        "src/fortipam_mcp/v31_admin_mcp.py",
        "src/fortipam_mcp/v4_runtime_host.py",
    ):
        assert "folder_http_transport" not in (repository / relative).read_text(
            encoding="utf-8"
        )


@pytest.mark.parametrize(
    "change,expected",
    [
        ("none", True),
        ("read_response", True),
        ("zero_relation_id", False),
        ("multiple_principals", False),
        ("inheritance", False),
        ("shared_group", False),
        ("second_user", False),
        ("wrong_owner", False),
        ("view_permission", False),
        ("wrong_folder", False),
        ("missing_groups", False),
        ("ambiguous_records", False),
    ],
)
def test_collector_folder_requires_exact_owner_only_acl(change, expected):
    record = {
        "id": 17,
        "inherit-permission": "disable",
        "user-permission": [{
            "id": 1, "user-name": [{"name": "collector-owner"}],
            "folder-permission": "owner", "secret-permission": "owner",
        }],
        "group-permission": [],
    }
    if change == "read_response":
        record["user-permission"][0]["user-name"] = ["collector-owner"]
        record["user-permission"][0]["allowed-launcher-type"] = "all"
    elif change == "zero_relation_id":
        record["user-permission"][0]["id"] = 0
    elif change == "multiple_principals":
        record["user-permission"][0]["user-name"] = ["collector-owner", "another-owner"]
    elif change == "inheritance":
        record["inherit-permission"] = "enable"
    elif change == "shared_group":
        record["group-permission"] = [{"id": 2}]
    elif change == "second_user":
        record["user-permission"] *= 2
    elif change == "wrong_owner":
        record["user-permission"][0]["user-name"] = [{"name": "another-owner"}]
    elif change == "view_permission":
        record["user-permission"][0]["secret-permission"] = "view"
    elif change == "wrong_folder":
        record["id"] = 18
    elif change == "missing_groups":
        del record["group-permission"]
    records = [record, record] if change == "ambiguous_records" else [record]
    transport, client, _ = _transport(_FakeResponse(
        chunks=[json.dumps({"results": records}).encode()],
    ))
    assert transport.verify_owner_only_folder(17, "collector-owner") is expected
    assert len(client.calls) == 1
    assert client.calls[0]["method"] == "GET"


def test_isolated_child_candidate_posts_only_one_owner_without_shared_acl():
    transport, client, _ = _transport()
    transport.create_isolated_child(name="Collector", parent_folder_id=101, owner_name="collector-owner")
    assert len(client.calls) == 1
    call = client.calls[0]
    assert call["method"] == "POST" and call["url"].endswith(COLLECTION_PATH)
    body = json.loads(call["content"])
    assert body == {
        "id": 0, "name": "Collector", "parent-folder": 101,
        "inherit-policy": "enable", "inherit-folder-ztna": "enable", "inherit-permission": "disable",
        "user-permission": [{"id": 0, "user-name": [{"name": "collector-owner"}],
            "folder-permission": "owner", "secret-permission": "owner"}],
        "group-permission": [],
    }
    with pytest.raises(FolderTransportError):
        transport.create_child(body)
    assert len(client.calls) == 1


@pytest.mark.parametrize("overrides", [{"name": "bad/name"}, {"parent_folder_id": 0}, {"parent_folder_id": True}, {"owner_name": ""}, {"owner_name": "bad\nowner"}])
def test_isolated_child_candidate_rejects_invalid_private_selectors_before_http(overrides):
    transport, client, _ = _transport()
    args = dict(name="Collector", parent_folder_id=101, owner_name="collector-owner")
    args.update(overrides)
    with pytest.raises(FolderTransportError):
        transport.create_isolated_child(**args)
    assert client.calls == []


def test_empty_inactive_policy_fixed_post_preserves_default_bytes_and_adds_only_empty_relation():
    transport, client, _ = _transport()
    args = dict(name="Collector", parent_folder_id=101, owner_name="collector-owner")
    transport.create_isolated_child(**args)
    legacy = client.calls[-1]["content"]
    transport.create_isolated_child(**args, empty_inactive_policy=False)
    assert client.calls[-1]["content"] == legacy
    transport.create_isolated_child(**args, empty_inactive_policy=True)
    assert json.loads(client.calls[-1]["content"]) == {**json.loads(legacy), "secret-policy": ""}
    assert len(client.calls) == 3


@pytest.mark.parametrize("flag", [None, 0, 1, "true", "false"])
def test_empty_inactive_policy_fixed_post_requires_exact_bool_before_http(flag):
    transport, client, _ = _transport()
    with pytest.raises(FolderTransportError):
        transport.create_isolated_child(name="Collector", parent_folder_id=101,
            owner_name="collector-owner", empty_inactive_policy=flag)
    assert client.calls == []
