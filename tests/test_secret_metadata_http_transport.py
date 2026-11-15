from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

import fortipam_mcp.secret_metadata_http_transport as transport_module
from fortipam_mcp.secret_metadata_http_transport import (
    FortiPamSecretMetadataHttpTransport,
    SecretMetadataHttpTransportConfig,
    SecretMetadataHttpTransportConfigurationError,
    SecretMetadataHttpTransportError,
    SecretMetadataReadback,
    SecretSessionControlsProjectionInspection,
    load_secret_metadata_http_transport_config,
    secret_session_controls_event_filter_profile_digest,
)


FOLDER_PATH = "Public/mcp-v4-folder-01"
SECRET_NAME = "mcp-v4-secret-metadata-01"
TEMPLATE = "Unix Account (SSH Password)"
TARGET = "mcp-v4-target-01"
EVENT_FILTER_PROFILE = "mcp-v4-rdp-event-filter-existing"
_REMOVE = object()


class _Response:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self.content = json.dumps(payload).encode("utf-8")
        self.headers = {"content-type": "application/json"}


class _Client:
    def __init__(self, responses: list[_Response], calls: list[dict[str, object]]) -> None:
        self._responses = responses
        self._calls = calls

    def __enter__(self) -> "_Client":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def request(self, method: str, url: str, **kwargs: object) -> _Response:
        self._calls.append({"method": method, "url": url, **kwargs})
        return self._responses.pop(0)


class _DetailResponse:
    def __init__(self, payload: object) -> None:
        self.status = 200
        self._content = json.dumps(payload).encode("utf-8")
        self._offset = 0
        self.closed = False

    def getheader(self, name: str, default: str = "") -> str:
        return "application/json" if name.lower() == "content-type" else default

    def readinto(self, target: memoryview) -> int:
        remaining = self._content[self._offset :]
        count = min(len(target), len(remaining))
        target[:count] = remaining[:count]
        self._offset += count
        return count

    def close(self) -> None:
        self.closed = True


class _DetailConnection:
    def __init__(self, response: _DetailResponse, calls: list[dict[str, object]]) -> None:
        self._response = response
        self._calls = calls
        self.closed = False

    def request(self, method: str, path: str, **kwargs: object) -> None:
        self._calls.append({"method": method, "path": path, **kwargs})

    def getresponse(self) -> _DetailResponse:
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


def _session_controls_detail(
    replacements: dict[str, object] | None = None,
) -> dict[str, object]:
    detail: dict[str, object] = {
        "id": 23,
        "name": SECRET_NAME,
        "folder": 17,
        "template": TEMPLATE,
        "target": TARGET,
        "inherit-permission": "enable",
        "proxy": "enable",
        "rdp-tcp-forward": "disable",
        "recording": "disable",
        "block-clipboard": "disable",
        "rdp-event-filter": "disable",
        "rdp-event-filter-profile": "",
    }
    if replacements:
        for name, value in replacements.items():
            if value is _REMOVE:
                detail.pop(name, None)
            else:
                detail[name] = value
    return detail


def _session_controls_transport(
    monkeypatch: pytest.MonkeyPatch,
    detail: dict[str, object],
    *,
    resolved_secret_id: int = 23,
    folder_fields: dict[str, object] | None = None,
    policy_fields: dict[str, object] | None = None,
    bound_secret_name: str | None = None,
) -> tuple[FortiPamSecretMetadataHttpTransport, list[dict[str, object]]]:
    responses = [
        _Response(200, {"results": {"id": 17}}),
        _Response(200, {"results": {"id": resolved_secret_id}}),
        _Response(200, {"results": [{"id": 17, "name": FOLDER_PATH.rsplit("/", 1)[-1], "inherit-policy": "disable", "secret-policy": "mcp-v4-secret-policy-test", **(folder_fields or {})}]}),
        _Response(200, {"results": [{"name": "mcp-v4-secret-policy-test", "recording": "not-set", "block-clipboard": "not-set", "rdp-event-filter": "not-set", **(policy_fields or {})}]}),
    ]
    detail_calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(),
        bound_secret_name=bound_secret_name,
        client_factory=lambda **_: _Client(responses, []),
        detail_connection_factory=lambda *_args, **_kwargs: _DetailConnection(
            _DetailResponse({"results": [detail]}),
            detail_calls,
        ),
    )
    return transport, detail_calls


def test_config_representation_never_exposes_transport_material() -> None:
    config = _config()

    assert repr(config) == "<SecretMetadataHttpTransportConfig redacted>"
    assert str(config) == "<SecretMetadataHttpTransportConfig redacted>"
    assert config.bearer_token not in repr(config)


def test_constructor_bound_secret_name_does_not_expand_default_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"results": {"id": 17}}),
        _Response(404, {"http_status": 404}),
        _Response(200, {"results": [{"name": TEMPLATE}]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(),
        bound_secret_name="doecker-server",
        client_factory=lambda **_: _Client(responses, calls),
    )

    inspection = transport.inspect(FOLDER_PATH, "doecker-server", TEMPLATE)

    assert inspection.secret_exists is False
    with pytest.raises(SecretMetadataHttpTransportError):
        FortiPamSecretMetadataHttpTransport(
            _config(), client_factory=lambda **_: _Client([], [])
        ).inspect(FOLDER_PATH, "doecker-server", TEMPLATE)


def test_loader_requires_exact_opt_in_and_dedicated_configuration(tmp_path: Path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_CA_FILE": str(ca_file),
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_TIMEOUT_SECONDS": "12",
    }

    loaded = load_secret_metadata_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    environment["FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_ENABLED"] = "false"
    with pytest.raises(SecretMetadataHttpTransportConfigurationError, match="ENABLED"):
        load_secret_metadata_http_transport_config(environment)


@pytest.mark.parametrize("drift_field", ["ssh-filter", "target-privilege-account"])
@pytest.mark.parametrize("drift_value", ["enable", None])
def test_secret_create_uuid_requires_exact_191_defaults(
    monkeypatch: pytest.MonkeyPatch,
    drift_field: str,
    drift_value: str | None,
) -> None:
    calls: list[dict[str, object]] = []
    defaults = {
        "approval-profile": "",
        "av-profile": "",
        "av-scan": "disable",
        "bypass-ssh-filter-for-owner": "disable",
        "dlp-sensor": "",
        "dlp-status": "disable",
        "need-approval": "disable",
        "need-approval-job": "disable",
        "pwd-chg-sch-frequency": "month",
        "pwd-chg-sch-interval": 1,
        "pwd-chg-sch-month-day": "1",
        "pwd-chg-sch-month-type": "specific",
        "pwd-chg-sch-week-day": "",
        "rdp-event-filter": "disable",
        "rdp-event-filter-profile": "",
        "secret-auth": "disable",
        "secret-auth-duration": 60,
        "secret-auth-server": "",
        "server-info": "Inherit",
        "ssh-filter": "disable",
        "ssh-filter-profile": "",
        "winappfilter": "disable",
        "winappfilter-profile": "",
        "target-privilege-account": "disable",
        "uuid": "11111111-2222-4333-8444-555555555555",
    }
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": defaults})], calls
        ),
    )

    assert (
        transport.resolve_secret_create_uuid()
        == "11111111-2222-4333-8444-555555555555"
    )
    assert calls[0]["url"] == (
        "https://fpa.example.test/api/v2/cmdb/secret/database?action=default"
    )

    drifted = dict(defaults)
    if drift_value is None:
        del drifted[drift_field]
    else:
        drifted[drift_field] = drift_value
    invalid = FortiPamSecretMetadataHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": drifted})], []
        ),
    )
    with pytest.raises(SecretMetadataHttpTransportError):
        invalid.resolve_secret_create_uuid()


def test_inspect_uses_only_id_lookup_routes_and_returns_presence_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"http_status": 200, "results": {"id": 17}}),
        _Response(404, {"http_status": 404}),
        _Response(200, {"http_status": 200, "results": [{"name": TEMPLATE}]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.inspect(FOLDER_PATH, SECRET_NAME, TEMPLATE)

    assert result.secret_exists is False
    assert result.folder_exists is True
    assert result.template_exists is True
    assert calls == [
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/utility/id/Public/mcp-v4-folder-01?type=folder",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        },
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/utility/id/Public/mcp-v4-folder-01/mcp-v4-secret-metadata-01?type=secret",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        },
        {
            "method": "GET",
            "url": "https://fpa.example.test/api/v2/cmdb/secret/template/Unix%20Account%20%28SSH%20Password%29",
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
            },
            "json": None,
        },
    ]


def test_policy_binding_requires_exact_folder_path_id_before_detail_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exact_calls: list[dict[str, object]] = []
    exact_responses = [
        _Response(200, {"results": {"id": 17}}),
        _Response(
            200,
            {
                "results": {
                    "id": 17,
                    "name": "mcp-v4-folder-01",
                    "inherit-policy": "disable",
                    "secret-policy": "RDP Restricted Policy",
                }
            },
        ),
    ]
    calls: list[dict[str, object]] = []
    responses = [_Response(200, {"results": {"id": 18}})]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    exact = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client(exact_responses, exact_calls)
    )
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    assert exact.verify_folder_policy_binding(
        FOLDER_PATH,
        expected_folder_id=17,
        expected_folder_name="mcp-v4-folder-01",
        expected_policy_name="RDP Restricted Policy",
    ) is True
    verified = transport.verify_folder_policy_binding(
        FOLDER_PATH,
        expected_folder_id=17,
        expected_folder_name="mcp-v4-folder-01",
        expected_policy_name="RDP Restricted Policy",
    )

    assert len(exact_calls) == 2
    assert exact_calls[1]["url"] == (
        "https://fpa.example.test/api/v2/cmdb/secret/folder/17"
    )
    assert verified is False
    assert len(calls) == 1
    assert calls[0]["url"] == (
        "https://fpa.example.test/api/v2/utility/id/"
        "Public/mcp-v4-folder-01?type=folder"
    )


def test_inspect_rejects_missing_or_mismatched_template_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    missing_responses = [
        _Response(200, {"results": {"id": 17}}),
        _Response(404, {"http_status": 404}),
        _Response(404, {"http_status": 404}),
    ]
    missing = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client(missing_responses, [])
    )
    assert missing.inspect(FOLDER_PATH, SECRET_NAME, TEMPLATE).template_exists is False

    mismatched_responses = [
        _Response(200, {"results": {"id": 17}}),
        _Response(404, {"http_status": 404}),
        _Response(200, {"results": [{"name": "different"}]}),
    ]
    mismatched = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client(mismatched_responses, [])
    )
    with pytest.raises(SecretMetadataHttpTransportError):
        mismatched.inspect(FOLDER_PATH, SECRET_NAME, TEMPLATE)


@pytest.mark.parametrize(
    ("path_fields", "compatible"),
    [
        ({"proxy": "enable", "rdp-tcp-forward": "disable", "rdp-service-status": "up", "ssh-service-status": "up"}, True),
        ({"proxy": "enable", "rdp-tcp-forward": "disable", "rdp-service-status": "down"}, True),
        ({"proxy": "enable", "rdp-tcp-forward": "enable"}, False),
        ({"proxy": "disable", "rdp-tcp-forward": "disable"}, False),
        ({"proxy": "enable"}, False),
        ({"proxy": "unknown", "rdp-tcp-forward": "disable"}, False),
        ({}, False),
    ],
)
def test_projection_inspection_filters_fields_and_fails_closed_for_existing_secret(
    monkeypatch: pytest.MonkeyPatch,
    path_fields: dict[str, str],
    compatible: bool,
) -> None:
    calls: list[dict[str, object]] = []
    detail_calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"results": {"id": 17}}),
        _Response(200, {"results": {"id": 23}}),
        _Response(200, {"results": [{"name": TEMPLATE}]}),
    ]
    detail_response = _DetailResponse(
        {
            "results": [
                {
                    "folder": 17,
                    "template": TEMPLATE,
                        "target": TARGET,
                        "inherit-permission": "enable",
                        **path_fields,
                        "block-clipboard": "disable",
                        "rdp-event-filter": "enable",
                        "rdp-event-filter-profile": EVENT_FILTER_PROFILE,
                    "field": [
                        {"name": "Password", "value": "must-not-reach-json-loads"}
                    ],
                }
            ]
        }
    )
    original_loads = json.loads

    def guarded_loads(value: object, *args: object, **kwargs: object) -> object:
        if isinstance(value, bytearray):
            assert b"must-not-reach-json-loads" not in value
        return original_loads(value, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    monkeypatch.setattr(transport_module.json, "loads", guarded_loads)
    transport = FortiPamSecretMetadataHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, calls),
        detail_connection_factory=lambda *_args, **_kwargs: _DetailConnection(
            detail_response,
            detail_calls,
        ),
    )

    result = transport.inspect_projection(
        FOLDER_PATH,
        SECRET_NAME,
        TEMPLATE,
        TARGET,
        expected_rdp_event_filter_profile=EVENT_FILTER_PROFILE,
    )

    assert result.metadata_relation_verified is True
    assert result.field_values_attached is True
    assert result.rdp_event_filter_matches is True
    assert result.rdp_clipboard_control_compatible is compatible
    assert result.clipboard_blocking_matches is (path_fields.get("block-clipboard") == "enable")
    assert result.rdp_service_enabled is (path_fields.get("rdp-service-status") == "up")
    assert result.ssh_service_enabled is (path_fields.get("ssh-service-status") == "up")
    assert detail_calls == [
        {
            "method": "GET",
            "path": (
                    "/api/v2/cmdb/secret/database/23"
                    "?format=id%7Cname%7Cfolder%7Ctemplate%7Ctarget%7C"
                    "inherit-permission%7Cproxy%7Crdp-tcp-forward%7C"
                    "block-clipboard%7Crdp-service-status%7Cssh-service-status%7Chttp-service-status%7C"
                        "rdp-event-filter%7Crdp-event-filter-profile%7Crecording%7C"
                        "need-approval%7Cneed-approval-job%7Cbypass-approval%7C"
                        "approval-profile"
                ),
            "headers": {
                "Accept": "application/json",
                "Authorization": "Bearer unit-test-token",
                "Connection": "close",
                "User-Agent": "fortipam-mcp-v4-secret-metadata/1",
                "Cache-Control": "no-cache, no-store",
                "Pragma": "no-cache",
            },
        }
    ]
    assert detail_response.closed is True
    assert not hasattr(result, "field")
    assert all(
        "must-not-reach-json-loads" not in repr(value)
        for value in (result, calls, detail_calls)
    )


def test_session_controls_projection_returns_exact_baseline_and_postcontrol_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_loads = json.loads

    def guarded_loads(value: object, *args: object, **kwargs: object) -> object:
        if isinstance(value, bytearray):
            assert b"must-not-reach-json-loads" not in value
        return original_loads(value, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(transport_module.json, "loads", guarded_loads)
    baseline_detail = _session_controls_detail()
    baseline_detail.update(
        {
            "field": [{"name": "Password", "value": "must-not-reach-json-loads"}],
            "totp": {"unknown": "synthetic-unpreserved-metadata"},
        }
    )
    baseline_transport, baseline_calls = _session_controls_transport(
        monkeypatch,
        baseline_detail,
    )
    postcontrol_detail = _session_controls_detail(
        {
            "recording": "enable",
            "block-clipboard": "enable",
            "rdp-event-filter": "enable",
            "rdp-event-filter-profile": EVENT_FILTER_PROFILE,
        }
    )
    postcontrol_detail["totp"] = {"unknown": "different-unpreserved-metadata"}
    postcontrol_transport, _ = _session_controls_transport(
        monkeypatch,
        postcontrol_detail,
    )
    inherited_transport, _ = _session_controls_transport(
        monkeypatch,
        _session_controls_detail({"inherit-permission": "disable"}),
    )

    baseline = baseline_transport.inspect_session_controls_projection(
        FOLDER_PATH,
        SECRET_NAME,
        TEMPLATE,
        TARGET,
        EVENT_FILTER_PROFILE,
        expected_secret_id=23,
    )
    postcontrol = postcontrol_transport.inspect_session_controls_projection(
        FOLDER_PATH,
        SECRET_NAME,
        TEMPLATE,
        TARGET,
        EVENT_FILTER_PROFILE,
        expected_secret_id=23,
    )
    inherited = inherited_transport.inspect_session_controls_projection(
        FOLDER_PATH,
        SECRET_NAME,
        TEMPLATE,
        TARGET,
        EVENT_FILTER_PROFILE,
        expected_secret_id=23,
    )

    assert isinstance(baseline, SecretSessionControlsProjectionInspection)
    assert baseline.original_name == postcontrol.original_name == SECRET_NAME
    assert baseline.original_template == postcontrol.original_template == TEMPLATE
    assert SECRET_NAME not in repr(baseline)
    assert TEMPLATE not in repr(baseline)
    assert baseline.recording_enabled is False
    assert baseline.clipboard_blocking_enabled is False
    assert baseline.rdp_event_filter_enabled is False
    assert baseline.rdp_event_filter_profile_matches is False
    assert baseline.rdp_event_filter_profile_digest != (
        secret_session_controls_event_filter_profile_digest(EVENT_FILTER_PROFILE)
    )
    assert baseline.proxy_enabled is True
    assert baseline.rdp_tcp_forwarding_disabled is True
    assert baseline.inherit_permission_matches is True
    assert postcontrol.recording_enabled is True
    assert postcontrol.clipboard_blocking_enabled is True
    assert postcontrol.rdp_event_filter_enabled is True
    assert postcontrol.rdp_event_filter_profile_matches is True
    assert postcontrol.rdp_event_filter_profile_digest == (
        secret_session_controls_event_filter_profile_digest(EVENT_FILTER_PROFILE)
    )
    assert (
        postcontrol.preserved_identity_relations_digest
        == baseline.preserved_identity_relations_digest
    )
    expected_digest = hashlib.sha256(
        json.dumps(
            {
                "id": 23,
                "name": SECRET_NAME,
                "folder": 17,
                "template": TEMPLATE,
                "target": TARGET,
                "inherit-permission": "enable",
                "proxy": "enable",
                "rdp-tcp-forward": "disable",
                "direct-folder-policy": baseline.folder_policy.preserved_fields(),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
    ).hexdigest()
    assert baseline.preserved_identity_relations_digest == expected_digest
    assert inherited.inherit_permission_matches is False
    assert (
        inherited.preserved_identity_relations_digest
        != baseline.preserved_identity_relations_digest
    )
    headers = baseline_calls[0]["headers"]
    assert isinstance(headers, dict)
    assert headers["Cache-Control"] == "no-cache, no-store"
    assert headers["Pragma"] == "no-cache"
    detail_path = baseline_calls[0]["path"]
    assert isinstance(detail_path, str)
    assert detail_path.startswith(
        "/api/v2/cmdb/secret/database/23?format=id%7Cname%7C"
    )
    assert not hasattr(baseline, "field")
    assert "totp" not in repr(baseline)


def test_session_controls_projection_accepts_syntactically_valid_bound_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bound_name = "bp006-rdp-identity-validation-20260915"
    transport, detail_calls = _session_controls_transport(
        monkeypatch,
        _session_controls_detail({"name": bound_name}),
        bound_secret_name=bound_name,
    )

    inspection = transport.inspect_session_controls_projection(
        FOLDER_PATH,
        bound_name,
        TEMPLATE,
        TARGET,
        EVENT_FILTER_PROFILE,
        expected_secret_id=23,
    )

    assert inspection.original_name == bound_name
    assert len(detail_calls) == 1
    with pytest.raises(SecretMetadataHttpTransportError):
        replace(inspection, original_name="invalid/name")


def test_session_controls_projection_rejects_replaced_same_name_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport, detail_calls = _session_controls_transport(
        monkeypatch,
        _session_controls_detail(),
        resolved_secret_id=24,
    )

    with pytest.raises(SecretMetadataHttpTransportError):
        transport.inspect_session_controls_projection(
            FOLDER_PATH,
            SECRET_NAME,
            TEMPLATE,
            TARGET,
            EVENT_FILTER_PROFILE,
            expected_secret_id=23,
        )

    assert detail_calls == []


@pytest.mark.parametrize(
    ("field_name", "drifted_value"),
    [
        ("id", 24),
        ("name", f"{SECRET_NAME}-replacement"),
        ("folder", 18),
        ("template", "Windows Account (RDP Password)"),
        ("target", "mcp-v4-target-replacement"),
        ("name", _REMOVE),
    ],
)
def test_session_controls_projection_rejects_identity_or_relation_drift(
    monkeypatch: pytest.MonkeyPatch,
    field_name: str,
    drifted_value: object,
) -> None:
    transport, _ = _session_controls_transport(
        monkeypatch,
        _session_controls_detail({field_name: drifted_value}),
    )

    with pytest.raises(SecretMetadataHttpTransportError):
        transport.inspect_session_controls_projection(
            FOLDER_PATH,
            SECRET_NAME,
            TEMPLATE,
            TARGET,
            EVENT_FILTER_PROFILE,
            expected_secret_id=23,
        )


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("inherit-permission", _REMOVE),
        ("proxy", "unknown"),
        ("rdp-tcp-forward", []),
        ("recording", _REMOVE),
        ("block-clipboard", None),
        ("rdp-event-filter", "unknown"),
        ("rdp-event-filter-profile", _REMOVE),
        ("rdp-event-filter-profile", [EVENT_FILTER_PROFILE]),
    ],
)
def test_session_controls_projection_rejects_missing_or_unknown_control_fields(
    monkeypatch: pytest.MonkeyPatch,
    field_name: str,
    invalid_value: object,
) -> None:
    transport, _ = _session_controls_transport(
        monkeypatch,
        _session_controls_detail({field_name: invalid_value}),
    )

    with pytest.raises(SecretMetadataHttpTransportError):
        transport.inspect_session_controls_projection(
            FOLDER_PATH,
            SECRET_NAME,
            TEMPLATE,
            TARGET,
            EVENT_FILTER_PROFILE,
            expected_secret_id=23,
        )


@pytest.mark.parametrize("service_status", ["up", "down", None])
@pytest.mark.parametrize("expected_id", [None, 24])
def test_web_projection_requires_non_target_recorded_web_account(
    monkeypatch: pytest.MonkeyPatch,
    service_status: str | None,
    expected_id: int | None,
) -> None:
    responses = [
        _Response(200, {"results": {"id": 17}}),
        _Response(200, {"results": {"id": 24}}),
        _Response(200, {"results": [{"name": "Web Account"}]}),
    ]
    detail_response = _DetailResponse(
        {
            "results": [
                {
                    "id": 24,
                    "name": SECRET_NAME,
                    "folder": 17,
                    "template": "Web Account",
                    **({"http-service-status": service_status} if service_status is not None else {}),
                    "target": "",
                    "inherit-permission": "enable",
                    "recording": "enable",
                    "field": [{"name": "Password", "value": "never-decode"}],
                }
            ]
        }
    )
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, []),
        detail_connection_factory=lambda *_args, **_kwargs: _DetailConnection(
            detail_response,
            [],
        ),
    )

    if expected_id is not None and service_status is None:
        with pytest.raises(SecretMetadataHttpTransportError):
            transport.inspect_web_projection(
                FOLDER_PATH, SECRET_NAME, "Web Account", expected_secret_id=expected_id
            )
        assert detail_response.closed is True
        return

    result = transport.inspect_web_projection(
        FOLDER_PATH,
        SECRET_NAME,
        "Web Account",
        expected_secret_id=expected_id,
    )

    assert result.metadata_relation_verified is True
    assert result.recording_matches is True
    assert result.http_service_enabled is (service_status == "up")
    assert result.field_values_attached is True
    assert detail_response.closed is True
    assert not hasattr(result, "field")


@pytest.mark.parametrize("expected_id", [23, True, 0, -1, 2_147_483_648])
def test_web_projection_rejects_changed_or_invalid_bound_identity(expected_id: int) -> None:
    responses = [
        _Response(200, {"results": {"id": 17}}),
        _Response(200, {"results": {"id": 24}}),
    ]
    calls: list[dict[str, object]] = []
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls),
        detail_connection_factory=lambda *_args, **_kwargs: pytest.fail(
            "A mismatched identity must not reach the detail reader."
        ),
    )
    with pytest.raises(SecretMetadataHttpTransportError):
        transport.inspect_web_projection(
            FOLDER_PATH, SECRET_NAME, "Web Account", expected_secret_id=expected_id
        )
    assert len(calls) == 2


@pytest.mark.parametrize("field,value", [
    ("id", 25), ("id", "24"), ("name", "replacement"),
    ("folder", 18), ("template", "Unix Account (SSH Password)"),
    ("target", "unexpected-target"), ("target", None),
    ("http-service-status", "unknown"), ("recording", None),
    ("inherit-permission", None),
])
def test_pinned_web_projection_rejects_detail_drift(
    monkeypatch: pytest.MonkeyPatch, field: str, value: object,
) -> None:
    detail = {
        "id": 24, "name": SECRET_NAME, "folder": 17,
        "template": "Web Account", "target": "",
        "http-service-status": "down", "recording": "enable",
        "inherit-permission": "enable", field: value,
    }
    response = _DetailResponse({"results": [detail]})
    responses = [
        _Response(200, {"results": {"id": 17}}),
        _Response(200, {"results": {"id": 24}}),
        _Response(200, {"results": [{"name": "Web Account"}]}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, []),
        detail_connection_factory=lambda *_args, **_kwargs: _DetailConnection(response, []),
    )
    with pytest.raises(SecretMetadataHttpTransportError):
        transport.inspect_web_projection(
            FOLDER_PATH, SECRET_NAME, "Web Account", expected_secret_id=24,
        )
    assert response.closed is True


def test_approval_projection_returns_only_categorical_secret_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = [_Response(200, {"results": {"id": 24}})]
    detail_response = _DetailResponse(
        {
            "results": [
                {
                    "id": 24,
                    "name": SECRET_NAME,
                    "need-approval": "enable",
                    "need-approval-job": "disable",
                    "bypass-approval": "disable",
                    "approval-profile": "mcp-v4-approval-profile-01",
                    "field": [{"name": "Password", "value": "never-decode"}],
                }
            ]
        }
    )
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, []),
        detail_connection_factory=lambda *_args, **_kwargs: _DetailConnection(
            detail_response,
            [],
        ),
    )

    result = transport.inspect_approval_projection(
        FOLDER_PATH,
        SECRET_NAME,
        "mcp-v4-approval-profile-01",
    )

    assert result.secret_exists is True
    assert result.interactive_approval_required is True
    assert result.job_approval_required is False
    assert result.owner_bypass_allowed is False
    assert result.approval_profile_matches is True
    assert result.approval_profile_unset is False
    assert result.field_values_attached is True
    assert not hasattr(result, "field")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        (field, value)
        for field in ("need-approval", "need-approval-job", "bypass-approval")
        for value in (_REMOVE, None, True, "unknown")
    ]
    + [
        ("approval-profile", value)
        for value in (_REMOVE, None, False, "other-profile")
    ]
    + [("id", value) for value in (_REMOVE, 25, True, "24")]
    + [("name", value) for value in (_REMOVE, "other-secret", None)],
)
def test_approval_projection_rejects_incomplete_or_mismatched_detail(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
) -> None:
    detail: dict[str, object] = {
        "id": 24,
        "name": SECRET_NAME,
        "need-approval": "disable",
        "need-approval-job": "disable",
        "bypass-approval": "disable",
        "approval-profile": "",
    }
    if value is _REMOVE:
        detail.pop(field)
    else:
        detail[field] = value
    responses = [_Response(200, {"results": {"id": 24}})]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, []),
        detail_connection_factory=lambda *_args, **_kwargs: _DetailConnection(
            _DetailResponse({"results": [detail]}), [],
        ),
    )

    with pytest.raises(SecretMetadataHttpTransportError):
        transport.inspect_approval_projection(
            FOLDER_PATH, SECRET_NAME, "mcp-v4-approval-profile-01",
            expected_secret_id=24,
        )


def test_approval_projection_accepts_explicit_disabled_empty_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    responses = [_Response(200, {"results": {"id": 24}})]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, []),
        detail_connection_factory=lambda *_args, **_kwargs: _DetailConnection(
            _DetailResponse({"results": [{
                "id": 24,
                "name": SECRET_NAME,
                "need-approval": "disable",
                "need-approval-job": "disable",
                "bypass-approval": "disable",
                "approval-profile": "",
            }]}), [],
        ),
    )

    result = transport.inspect_approval_projection(
        FOLDER_PATH, SECRET_NAME, "mcp-v4-approval-profile-01",
        expected_secret_id=24,
    )

    assert result.secret_exists is True
    assert result.interactive_approval_required is False
    assert result.job_approval_required is False
    assert result.owner_bypass_allowed is False
    assert result.approval_profile_matches is False
    assert result.approval_profile_unset is True


def test_create_posts_only_metadata_body_and_safely_verifies_empty_field_array(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"http_status": 200, "results": {"id": 17}}),
        _Response(200, {"http_status": 200}),
        _Response(200, {"http_status": 200, "results": {"id": 23}}),
        _Response(
            200,
            {
                "results": [
                    {
                        "folder": 17,
                        "template": TEMPLATE,
                        "inherit-permission": "enable",
                        "field": [],
                    }
                ]
            },
        ),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls)
    )

    result = transport.create_and_readback(FOLDER_PATH, SECRET_NAME, TEMPLATE)

    assert result.verified is True
    assert result.field_values_attached is False
    assert calls[1] == {
        "method": "POST",
        "url": "https://fpa.example.test/api/v2/cmdb/secret/database",
        "headers": {
            "Accept": "application/json",
            "Authorization": "Bearer unit-test-token",
        },
        "json": {
            "id": 0,
            "name": SECRET_NAME,
            "inherit-permission": "enable",
            "folder": 17,
            "template": TEMPLATE,
            "field": [],
        },
    }
    assert calls[3]["url"] == "https://fpa.example.test/api/v2/cmdb/secret/database/23"


def test_nonempty_field_array_never_traverses_or_returns_field_content(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    responses = [
        _Response(200, {"results": {"id": 17}}),
        _Response(200, {"http_status": 200}),
        _Response(200, {"results": {"id": 23}}),
        _Response(
            200,
            {
                "results": [
                    {
                        "folder": 17,
                        "template": TEMPLATE,
                        "inherit-permission": "enable",
                        "field": [{}],
                    }
                ]
            },
        ),
    ]
    transport = FortiPamSecretMetadataHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(responses, []),
    )

    result = transport.create_and_readback(FOLDER_PATH, SECRET_NAME, TEMPLATE)

    assert result.verified is False
    assert result == SecretMetadataReadback(True, True, True, True, True)


def test_rejects_unsafe_metadata_inputs_and_unsuccessful_create_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client([], [])
    )

    with pytest.raises(SecretMetadataHttpTransportError):
        transport.inspect("../outside", SECRET_NAME, TEMPLATE)
    with pytest.raises(SecretMetadataHttpTransportError):
        transport.inspect(FOLDER_PATH, "not-lab-scoped", TEMPLATE)
    with pytest.raises(SecretMetadataHttpTransportError):
        transport.inspect(FOLDER_PATH, SECRET_NAME, "bad/template")
    with pytest.raises(SecretMetadataHttpTransportError):
        transport.create_and_readback(FOLDER_PATH, SECRET_NAME, "bad/template")

    rejected_responses = [
        _Response(200, {"results": {"id": 17}}),
        _Response(400, {"http_status": 400}),
    ]
    rejected = FortiPamSecretMetadataHttpTransport(
        _config(),
        client_factory=lambda **_: _Client(rejected_responses, []),
    )
    with pytest.raises(SecretMetadataHttpTransportError):
        rejected.create_and_readback(FOLDER_PATH, SECRET_NAME, TEMPLATE)


@pytest.mark.parametrize("folder_fields,policy_fields", [
    ({"id": 18}, {}),
    ({"name": "different-folder"}, {}),
    ({"inherit-policy": "enable"}, {}),
    ({"secret-policy": "different-policy"}, {}),
    ({}, {"name": "different-policy"}),
    ({}, {"recording": "unknown"}),
    ({}, {"block-clipboard": None}),
    ({}, {"rdp-event-filter": True}),
])
def test_controls_policy_evidence_requires_exact_direct_binding_and_typed_states(
    monkeypatch, folder_fields, policy_fields,
) -> None:
    transport, _ = _session_controls_transport(
        monkeypatch, _session_controls_detail(), folder_fields=folder_fields, policy_fields=policy_fields,
    )
    with pytest.raises(SecretMetadataHttpTransportError):
        transport.inspect_session_controls_projection(
            FOLDER_PATH, SECRET_NAME, TEMPLATE, TARGET, EVENT_FILTER_PROFILE, expected_secret_id=23,
        )


@pytest.mark.parametrize("policy_fields,folder_fields", [
    ({"recording": "enable"}, {}),
    ({"block-clipboard": "enable"}, {}),
    ({"rdp-event-filter": "disable"}, {}),
    ({"name": "different-policy"}, {"secret-policy": "different-policy"}),
])
def test_policy_control_or_association_drift_changes_preserved_identity_digest(
    monkeypatch, policy_fields, folder_fields,
) -> None:
    first, _ = _session_controls_transport(monkeypatch, _session_controls_detail())
    second, _ = _session_controls_transport(
        monkeypatch, _session_controls_detail(), folder_fields=folder_fields, policy_fields=policy_fields,
    )
    def inspect(transport):
        return transport.inspect_session_controls_projection(
            FOLDER_PATH, SECRET_NAME, TEMPLATE, TARGET, EVENT_FILTER_PROFILE, expected_secret_id=23,
        )
    assert inspect(first).preserved_identity_relations_digest != inspect(second).preserved_identity_relations_digest


@pytest.mark.parametrize("version", ["v1.9.1", "1.9.1", "v7.0.0"])
def test_product_version_read_is_fixed_tls_and_returns_only_version(version):
    calls = []
    options = []
    def factory(**kwargs):
        options.append(kwargs)
        return _Client([_Response(200, {"version": version, "results": {"serial": "private"}})], calls)
    transport = FortiPamSecretMetadataHttpTransport(_config(), client_factory=factory)
    assert transport.read_product_version() == version.removeprefix("v")
    assert len(calls) == 1
    assert calls[0]["method"] == "GET"
    assert calls[0]["url"] == "https://fpa.example.test/api/v2/monitor/system/status"
    assert options[0]["verify"].check_hostname is True
    assert options[0]["verify"].verify_mode == 2
    assert options[0]["follow_redirects"] is False
    assert options[0]["trust_env"] is False


@pytest.mark.parametrize("status,payload", [
    (403, {"version": "v1.9.1"}), (200, {}),
    (200, {"results": {"version": "v1.9.1"}}),
    (200, {"version": "v1.9.1,build123"}), (200, {"version": 191}),
])
def test_product_version_read_fails_closed_on_invalid_status_or_shape(status, payload):
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(status, payload)], []),
    )
    with pytest.raises(SecretMetadataHttpTransportError):
        transport.read_product_version()


@pytest.mark.parametrize("build", [29, "29", True, None])
def test_candidate_product_identity_requires_integer_build(build):
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(200, {"version": "v7.0.0", "build": build})], []),
    )
    if type(build) is int:
        assert transport.read_product_version_and_build() == ("7.0.0", 29)
    else:
        with pytest.raises(SecretMetadataHttpTransportError):
            transport.read_product_version_and_build()


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, True),
        ({"target-info": {"priv_acct": 0}}, False),
        ({"target-info": {"priv_acct": 24}}, False),
        ({"target-info": {"priv_acct": "23"}}, False),
        ({"target-info": {"priv_acct": 23.0}}, False),
        ({"target-info": {}}, False),
        ({"target-info": None}, False),
        ({"target-privilege-account": "disable"}, False),
        ({"name": "different-secret"}, False),
        ({"id": 24}, False),
        ({"folder": 18}, False),
        ({"target": "different-target"}, False),
        ({"template": "Unix Account (SSH Password)"}, False),
        ({"inherit-permission": "disable"}, False),
        ({"recording": "disable"}, False),
        ({"rdp-event-filter": "disable"}, False),
        ({"rdp-event-filter-profile": "different-profile"}, False),
        *[({key: value}, False) for key in (
            "ssh-service-status", "http-service-status",
            "samba-service-status", "telnet-service-status",
        ) for value in ("up", None)],
        *[({"rdp-service-status": value}, False) for value in ("down", None)],
    ],
)
def test_winrm_collector_requires_exact_association_and_fixed_controls(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object], expected: bool,
) -> None:
    detail = {
        "id": 23, "name": SECRET_NAME, "folder": 17,
        "template": "Windows Machine", "target": TARGET,
        "inherit-permission": "enable", "target-privilege-account": "enable",
        "target-info": {"priv_acct": 23},
        "rdp-service-status": "up", "ssh-service-status": "down",
        "http-service-status": "down", "samba-service-status": "down",
        "telnet-service-status": "down",
        "recording": "enable", "rdp-event-filter": "enable",
        "rdp-event-filter-profile": "mcp-v4-rdp-event-filter-example",
        "field": [{"value": "synthetic-material-must-be-redacted"}],
        **overrides,
    }
    responses = [
        _Response(200, {"version": "v7.0.0", "build": 29}),
        _Response(200, {"results": {"id": 17}}),
        _Response(200, {"results": {"id": 23}}),
    ]
    calls: list[dict[str, object]] = []
    detail_calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls),
        detail_connection_factory=lambda *_args, **_kwargs: _DetailConnection(
            _DetailResponse({"results": [detail]}), detail_calls,
        ),
    )
    monkeypatch.setattr(transport, "_verify_winrm_target", lambda *_: True)
    monkeypatch.setattr(transport, "_verify_collector_folder_acl", lambda *_: True)
    original_loads = json.loads

    def decode_without_material(value: object, *args: object, **kwargs: object) -> object:
        assert "synthetic-material-must-be-redacted" not in str(value)
        return original_loads(value, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(transport_module.json, "loads", decode_without_material)
    assert transport.verify_winrm_collector(
        FOLDER_PATH, SECRET_NAME, TARGET, expected_secret_id=23, owner_name="collector-owner", expected_target_address="192.0.2.10",
        expected_rdp_event_filter_profile="mcp-v4-rdp-event-filter-example",
    ) is expected
    assert len(calls) == 3 and all(call["method"] == "GET" for call in calls)
    assert len(detail_calls) == 1 and detail_calls[0]["method"] == "GET"
    assert "target-info" in str(detail_calls[0]["path"])


@pytest.mark.parametrize("defect", [
    None, "field_omitted", "absent", "absent_array", "post_absent", "forbidden_lookup", "malformed_lookup",
    "populated_404", "populated_array_404", "top_id_404", "malformed_404", "missing_results_404",
    "lookup_id_zero", "lookup_id_negative", "lookup_id_float", "lookup_id_bool", "lookup_id_overflow",
    "lookup_id_drift", "forbidden_detail", "missing_detail", "malformed_detail", "missing_folder",
    "dependency", "unbound",
    *["identity:" + key for key in ("id", "name", "folder", "template", "target", "inherit-permission")],
    "id_type", "folder_type",
    *[mode + ":" + key for key in (
        "rdp-service-status", "ssh-service-status", "sftp-service-status", "http-service-status",
        "samba-service-status", "telnet-service-status", "target-privilege-account",
    ) for mode in ("drift", "missing")],
])
def test_domain_projection_reads_fixed_wire_metadata_and_rejects_drift(monkeypatch, defect):
    from fortipam_mcp.secret_create_191_private_adapter import SecretCreate700DomainBinding
    from fortipam_mcp.target_contract import DOMAIN_TEMPLATE_FIELD_TYPES

    binding = SecretCreate700DomainBinding(
        "fortipam-700-build29-domain-account-create-candidate-v1", "7.0.0", "1" * 64,
        FOLDER_PATH, SECRET_NAME, "Windows Domain Account", TARGET,
        "192.0.2.10", "ad.example.test", "domain-owner",
    )
    envelope = {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
                "status": "success", "path": "secret", "vdom": "root"}
    target = {"name": TARGET, "address": "192.0.2.10", "domain": "ad.example.test",
              "template": binding.template_name, "class": "Other", "ldaps-port": 636,
              "user-naming-attribute": "sAMAccountName", "user-base": "", "access": "customized",
              "web-proxy-status": "disable",
              "user-permission": [{"permission": "owner", "user-name": [{"name": "domain-owner"}]}]}
    if defect == "dependency":
        target["class"] = "Changed Tag"
    fields = [{"name": name, "type": kind} for name, kind in DOMAIN_TEMPLATE_FIELD_TYPES]
    missing_cases = {"absent", "absent_array", "post_absent", "populated_404", "populated_array_404",
                     "top_id_404", "malformed_404", "missing_results_404"}
    secret_lookup_status = 404 if defect in missing_cases else 403 if defect == "forbidden_lookup" else 200
    lookup = {"results": {} if defect in {"malformed_lookup", "absent", "post_absent"} else {"id": 23}}
    if defect in {"absent_array", "top_id_404"}:
        lookup = {"results": []}
        if defect == "top_id_404":
            lookup["id"] = 23
    elif defect == "populated_array_404":
        lookup = {"results": [{"id": 23}]}
    elif defect == "malformed_404":
        lookup = {"results": None}
    elif defect == "missing_results_404":
        lookup = {}
    invalid_ids = {"lookup_id_zero": 0, "lookup_id_negative": -1, "lookup_id_float": 23.0,
                   "lookup_id_bool": True, "lookup_id_overflow": 2_147_483_648}
    if defect in invalid_ids:
        lookup = {"results": {"id": invalid_ids[defect]}}
    responses = [
        _Response(200, {**envelope, "name": "target", "results": [target]}),
        _Response(200, {**envelope, "name": "template", "results": [{"name": binding.template_name, "field": fields}]}),
        _Response(404 if defect == "missing_folder" else 200, {"results": {"id": 17}}),
        _Response(secret_lookup_status, lookup),
    ]
    sentinel = "synthetic-domain-material-must-not-be-decoded"
    detail = {"id": 23, "name": SECRET_NAME, "folder": 17, "template": binding.template_name,
              "target": TARGET, "inherit-permission": "enable", "target-privilege-account": "disable",
              **{service + "-service-status": "down" for service in ("rdp", "ssh", "sftp", "http", "samba", "telnet")},
              "field": [{"name": "Password", "value": sentinel}]}
    if defect == "field_omitted":
        del detail["field"]
    elif defect == "id_type":
        detail["id"] = 23.0
    elif defect == "folder_type":
        detail["folder"] = 17.0
    elif isinstance(defect, str) and ":" in defect:
        mode, key = defect.split(":")
        if mode == "missing":
            del detail[key]
        else:
            detail[key] = 24 if key in {"id", "folder"} else "changed" if mode == "identity" else (
                "enable" if key == "target-privilege-account" else "up")
    response = _DetailResponse({"results": [] if defect == "malformed_detail" else [detail]})
    response.status = 403 if defect == "forbidden_detail" else 404 if defect == "missing_detail" else 200
    calls, detail_calls = [], []
    connection = _DetailConnection(response, detail_calls)
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), bound_secret_name=None if defect == "unbound" else SECRET_NAME,
        client_factory=lambda **_: _Client(responses, calls),
        detail_connection_factory=lambda *_args, **_kwargs: connection,
    )
    original_loads = json.loads
    def decode_without_material(value, *args, **kwargs):
        assert sentinel not in str(value)
        return original_loads(value, *args, **kwargs)
    monkeypatch.setattr(transport_module.json, "loads", decode_without_material)
    expected_id = None if defect in missing_cases - {"post_absent"} else 24 if defect == "lookup_id_drift" else 23
    if defect in {None, "field_omitted"}:
        result = transport.inspect_domain_account_projection(binding, expected_secret_id=expected_id)
        assert result.secret_exists is True
        assert result.metadata_verified is True
        assert result.field_was_redacted is (defect is None)
    else:
        with pytest.raises(SecretMetadataHttpTransportError):
            transport.inspect_domain_account_projection(binding, expected_secret_id=expected_id)
    assert all(call["method"] == "GET" for call in calls + detail_calls)
    secret_lookups = [call for call in calls if call["url"].endswith("?type=secret")]
    assert len(secret_lookups) == (0 if defect in {"dependency", "unbound", "missing_folder"} else 1)
    if detail_calls:
        assert len(detail_calls) == 1
        assert detail_calls[0]["path"] == (
            "/api/v2/cmdb/secret/database/23?" + transport_module._DOMAIN_ACCOUNT_DETAIL_QUERY)
        assert "target-info" not in detail_calls[0]["path"]
        assert "format=field" not in detail_calls[0]["path"]
        assert response.closed and connection.closed
    else:
        assert not connection.closed and response._offset == 0
    if defect in {"dependency", "unbound"}:
        assert len(calls) == (1 if defect == "dependency" else 0)
    call_count = len(detail_calls)
    with pytest.raises(SecretMetadataHttpTransportError):
        transport._request_projection_detail(23, winrm_collector=True, domain_account=True)
    assert len(detail_calls) == call_count


@pytest.mark.parametrize("lookup", [{"results": {}}, {"results": []}])
def test_domain_unqualified_empty_404_never_establishes_absence(monkeypatch, lookup):
    from fortipam_mcp.secret_create_191_private_adapter import SecretCreate700DomainBinding
    binding = SecretCreate700DomainBinding(
        "fortipam-700-build29-domain-account-create-candidate-v1", "7.0.0", "1" * 64,
        FOLDER_PATH, SECRET_NAME, "Windows Domain Account", TARGET,
        "192.0.2.10", "ad.example.test", "domain-owner",
    )
    calls = []
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), bound_secret_name=SECRET_NAME,
        client_factory=lambda **_: _Client([_Response(404, lookup)], calls),
    )
    monkeypatch.setattr(transport, "verify_domain_account_preflight", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(transport, "_lookup_id", lambda *_: 17)
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    with pytest.raises(SecretMetadataHttpTransportError):
        transport.inspect_domain_account_projection(binding)
    assert len(calls) == 1 and calls[0]["method"] == "GET"


def test_winrm_collector_denies_other_build_before_secret_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client(
            [_Response(200, {"version": "v7.0.0", "build": 30})], calls,
        ),
    )
    assert not transport.verify_winrm_collector(
        FOLDER_PATH, SECRET_NAME, TARGET, expected_secret_id=23, owner_name="collector-owner", expected_target_address="192.0.2.10",
        expected_rdp_event_filter_profile="mcp-v4-rdp-event-filter-example",
    )
    assert len(calls) == 1


@pytest.mark.parametrize("association, target_matches, expected", [
    (0, True, True), (23, True, False), ("0", True, False),
    (False, True, False), (None, True, False), (0.0, True, False),
    (0, False, False),
])
def test_target_collector_absence_requires_integer_zero_on_exact_witness(
    monkeypatch: pytest.MonkeyPatch, association: object,
    target_matches: bool, expected: bool,
) -> None:
    responses = [
        _Response(200, {"version": "v7.0.0", "build": 29}),
        _Response(200, {"results": {"id": 17}}),
        _Response(200, {"results": {"id": 23}}),
    ]
    detail = {"id": 23, "name": SECRET_NAME, "folder": 17,
              "target": TARGET if target_matches else "other-target",
              "target-privilege-account": "disable",
              "target-info": {"priv_acct": association}}
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client(responses, calls),
        detail_connection_factory=lambda *_args, **_kwargs: _DetailConnection(
            _DetailResponse({"results": [detail]}), calls,
        ),
    )
    assert transport.verify_target_has_no_collector(FOLDER_PATH, SECRET_NAME, TARGET) is expected
    assert len(calls) == 4 and all(c["method"] == "GET" for c in calls)


@pytest.mark.parametrize("candidate_exists, isolated, unassigned, expected", [
    (False, True, True, True), (True, True, True, False),
    (False, False, True, False), (False, True, False, False),
])
def test_collector_preflight_combines_isolation_absence_and_target_conflict(
    monkeypatch: pytest.MonkeyPatch, candidate_exists: bool,
    isolated: bool, unassigned: bool, expected: bool,
) -> None:
    from fortipam_mcp.folder_http_transport import FortiPamFolderHttpTransport

    transport = FortiPamSecretMetadataHttpTransport(_config())
    monkeypatch.setattr(transport, "read_product_version_and_build", lambda: ("7.0.0", 29))
    monkeypatch.setattr(transport, "_lookup_id", lambda kind, name: 17 if kind == "folder" else (23 if candidate_exists else None))
    monkeypatch.setattr(transport, "_verify_winrm_target", lambda *_: True)
    stages: list[str] = []

    def check_folder(self, folder_id, owner_name):
        assert self._config.base_url == _config().base_url
        assert self._config.bearer_token == _config().bearer_token
        assert folder_id == 17 and owner_name == "collector-owner"
        stages.append("folder")
        return isolated

    def check_target(self, folder_path, secret_name, target_name):
        assert self._bound_secret_name == "existing-witness"
        assert target_name == TARGET
        stages.append("target")
        return unassigned

    monkeypatch.setattr(FortiPamFolderHttpTransport, "verify_owner_only_folder", check_folder)
    monkeypatch.setattr(FortiPamSecretMetadataHttpTransport, "verify_target_has_no_collector", check_target)
    assert transport.verify_winrm_collector_preflight(
        FOLDER_PATH, SECRET_NAME, "collector-owner", FOLDER_PATH, "existing-witness", TARGET, "192.0.2.10",
    ) is expected
    assert stages == ([] if candidate_exists else ["folder"] if not isolated else ["folder", "target"])


@pytest.mark.parametrize("failure", [None, "different_device", "missing_identity", "version", "wrong_witness", "conflict"])
def test_separate_collector_witness_requires_same_authenticated_device(monkeypatch, failure):
    witness = FortiPamSecretMetadataHttpTransport(_config(),
        bound_secret_name="other" if failure == "wrong_witness" else "existing-witness")
    owner = FortiPamSecretMetadataHttpTransport(_config(), collector_witness_transport=witness)
    monkeypatch.setattr(owner, "read_product_version_and_build", lambda: ("7.0.0", 29))
    monkeypatch.setattr(witness, "read_product_version_and_build", lambda: ("7.0.0", 30 if failure == "version" else 29))
    monkeypatch.setattr(owner, "_lookup_id", lambda kind, _: 17 if kind == "folder" else None)
    monkeypatch.setattr(owner, "_verify_winrm_target", lambda *_: True)
    monkeypatch.setattr(owner, "_verify_collector_folder_acl", lambda *_: True)
    monkeypatch.setattr(owner, "_request", lambda *_: (200, {"serial": "synthetic-device"}))
    monkeypatch.setattr(witness, "_request", lambda *_: (200,
        {} if failure == "missing_identity" else {"serial": "other-device" if failure == "different_device" else "synthetic-device"}))
    calls = []
    def check(folder, secret, target):
        calls.append((folder, secret, target))
        return failure != "conflict"
    monkeypatch.setattr(witness, "verify_target_has_no_collector", check)
    assert owner.verify_winrm_collector_preflight(FOLDER_PATH, SECRET_NAME,
        "collector-owner", FOLDER_PATH, "existing-witness", TARGET, "192.0.2.10") is (failure is None)
    assert len(calls) == int(failure in {None, "conflict"})


@pytest.mark.parametrize("overrides, expected", [
    ({}, True), ({"address": "192.0.2.11"}, False),
    ({"name": "other-target"}, False), ({"winrm-https": "enable"}, False),
    ({"template": "Web Account"}, False), ({"address": None}, False),
])
def test_winrm_target_rejects_address_template_and_transport_drift(monkeypatch, overrides, expected):
    calls = []
    detail = {"name": TARGET, "address": "192.0.2.10", "template": "Windows Machine",
              "winrm-https": "disable", **overrides}
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), client_factory=lambda **_: _Client([_Response(200, {"results": [detail]})], calls),
    )
    assert transport._verify_winrm_target(TARGET, "192.0.2.10") is expected
    assert len(calls) == 1 and calls[0]["method"] == "GET"


@pytest.mark.parametrize("field_redacted,frequency,interval,accepted", [
    (True, "month", 1, True),
    (False, "month", 1, False),
    (True, "hour", 1, False),
    (True, "month", True, False),
])
def test_automatic_password_change_inspection_requires_redacted_fixed_shape(
    monkeypatch: pytest.MonkeyPatch,
    field_redacted: bool,
    frequency: str,
    interval: object,
    accepted: bool,
) -> None:
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), bound_secret_name=SECRET_NAME,
    )
    monkeypatch.setattr(transport, "read_product_version_and_build", lambda: ("7.0.0", 29))
    monkeypatch.setattr(transport, "resolve_existing_secret_id", lambda *_: 37)
    detail = {
        "id": 37,
        "name": SECRET_NAME,
        "password-changer": "disable",
        "pwd-chg-use-policy-default": "enable",
        "pwd-chg-sch-frequency": frequency,
        "pwd-chg-sch-interval": interval,
        "pwd-chg-sch-start-date": 0,
        "next-password-change-time": 0,
        "last-success-password-change-time": 42,
    }
    monkeypatch.setattr(
        transport, "_request_projection_detail",
        lambda *_: (200, {"results": [detail]}, field_redacted),
    )

    if not accepted:
        with pytest.raises(SecretMetadataHttpTransportError):
            transport.inspect_automatic_password_change(FOLDER_PATH, SECRET_NAME)
        return
    result = transport.inspect_automatic_password_change(FOLDER_PATH, SECRET_NAME)
    assert result.enabled is False
    assert result.uses_policy_default is True
    assert result.frequency == "month" and result.interval == 1
    assert result.start_date_present is False
    assert result.next_change_present is False
    assert result.successful_change_recorded is True
    assert result.successful_change_after_start is False


@pytest.mark.parametrize("start,last_success,after_start", [
    (100, 99, False),
    (100, 100, True),
    (100, 101, True),
    (0, 101, False),
    ("", 101, False),
    (100, "", False),
])
def test_automatic_change_success_must_follow_configured_start(
    monkeypatch: pytest.MonkeyPatch, start: object, last_success: object,
    after_start: bool,
) -> None:
    transport = FortiPamSecretMetadataHttpTransport(
        _config(), bound_secret_name=SECRET_NAME,
    )
    monkeypatch.setattr(transport, "read_product_version_and_build", lambda: ("7.0.0", 29))
    monkeypatch.setattr(transport, "resolve_existing_secret_id", lambda *_: 37)
    detail = {
        "id": 37, "name": SECRET_NAME,
        "password-changer": "disable",
        "pwd-chg-use-policy-default": "enable",
        "pwd-chg-sch-frequency": "day", "pwd-chg-sch-interval": 1,
        "pwd-chg-sch-start-date": start,
        "next-password-change-time": 200,
        "last-success-password-change-time": last_success,
    }
    monkeypatch.setattr(
        transport, "_request_projection_detail",
        lambda *_: (200, {"results": [detail]}, True),
    )
    result = transport.inspect_automatic_password_change(FOLDER_PATH, SECRET_NAME)
    assert result.successful_change_after_start is after_start
    # Cached next-time presence does not imply an enabled scheduler.
    assert result.enabled is False and result.next_change_present is True


@pytest.mark.parametrize("defect", [None, "target_url", "target_template", "target_proxy", "version", "secret_target", "secret_id", "proxy_missing", "proxy_disabled", "not_found", "pinned_absent"])
def test_target_bound_web_projection_requires_exact_dependencies_and_redacts_fields(monkeypatch, defect) -> None:
    from fortipam_mcp.target_contract import WebTargetCreateInput
    target = WebTargetCreateInput("mcp-v4-target-web-20261003-r1", "https://app.example.test")
    dependency = {"name": target.target_name, "template": "Web Account", "url": target.web_url,
                  "address": "", "web-proxy-status": "disable"}
    if defect == "target_url": dependency["url"] = "https://other.example.test"
    if defect == "target_template": dependency["template"] = TEMPLATE
    if defect == "target_proxy": dependency["web-proxy-status"] = "enable"
    responses = [_Response(200, {"version": "v7.0.0", "build": 30 if defect == "version" else 29}),
        _Response(200, {"version": "v7.0.0", "build": 29, "results": [dependency]}),
        _Response(200, {"results": {"id": 17}}),
        _Response(404, {}) if defect in {"not_found", "pinned_absent"} else _Response(200, {"results": {"id": 24}}),
        _Response(200, {"results": [{"name": "Web Account"}]})]
    detail = {"id": 25 if defect == "secret_id" else 24, "name": SECRET_NAME, "folder": 17,
              "template": "Web Account", "target": "" if defect == "secret_target" else target.target_name,
              "inherit-permission": "enable", "recording": "enable", "http-service-status": "up",
              "proxy": "enable", "field": [{"name": "Password", "value": "never-decode"}]}
    if defect == "proxy_missing": detail.pop("proxy")
    if defect == "proxy_disabled": detail["proxy"] = "disable"
    detail_response = _DetailResponse({"results": [detail]})
    calls = []; detail_calls = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretMetadataHttpTransport(_config(), client_factory=lambda **_: _Client(responses, calls),
        detail_connection_factory=lambda *_a, **_kw: _DetailConnection(detail_response, detail_calls))
    if defect in (None, "not_found", "proxy_disabled"):
        result = transport.inspect_target_bound_web_projection(FOLDER_PATH, SECRET_NAME, target=target)
        if defect in (None, "proxy_disabled"):
            assert result.proxy_mode_enabled is (defect is None)
            assert result.metadata_relation_verified and result.recording_matches and result.http_service_enabled
            assert result.field_values_attached and detail_response.closed
            assert "never-decode" not in repr(result) and target.web_url not in repr(result)
        else:
            assert not result.secret_exists and result.folder_exists and result.template_exists
            assert not detail_calls
    else:
        with pytest.raises(SecretMetadataHttpTransportError):
            transport.inspect_target_bound_web_projection(FOLDER_PATH, SECRET_NAME, target=target,
                expected_secret_id=24 if defect == "pinned_absent" else None)
        if defect.startswith("target_") or defect in {"version", "pinned_absent"}:
            assert not detail_calls
    assert all(call["method"] == "GET" for call in calls)
