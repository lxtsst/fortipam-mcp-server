from __future__ import annotations

import json
from dataclasses import replace
from fortipam_mcp.secret_metadata_http_transport import SecretSessionControlsFolderPolicy, SecretSessionControlsProjectionInspection

import pytest

import fortipam_mcp.secret_session_controls_http_transport as transport_module
from fortipam_mcp.secret_metadata_http_transport import (
    MAX_RESPONSE_BYTES,
    SecretMetadataHttpTransportConfig,
)
from fortipam_mcp.secret_session_controls_http_transport import (
    FortiPamSecretSessionControlsHttpTransport,
    SecretSessionControlsHttpTransportError,
)


PROFILE = "mcp-v4-rdp-event-filter-existing01"


def _baseline() -> SecretSessionControlsProjectionInspection:
    return SecretSessionControlsProjectionInspection(
            original_name="mcp-v4-secret-metadata-01",
            original_template="Windows Local Account",
        recording_enabled=False, clipboard_blocking_enabled=False,
        rdp_event_filter_enabled=False, rdp_event_filter_profile_matches=False,
        rdp_event_filter_profile_digest="a" * 64, proxy_enabled=True,
        rdp_tcp_forwarding_disabled=True, inherit_permission_matches=True,
        preserved_identity_relations_digest="b" * 64,
        folder_policy=SecretSessionControlsFolderPolicy(
            17, "folder", "mcp-v4-secret-policy-test", "not-set", "not-set", "not-set",
        ),
    )


class _Response:
    def __init__(self, status: int, payload: object, *, content_type: str = "application/json") -> None:
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
        if isinstance(kwargs.get("body"), bytearray):
            kwargs["body"] = bytes(kwargs["body"])
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


def _transport(
    monkeypatch: pytest.MonkeyPatch, response: _Response, calls: list[dict[str, object]]
) -> FortiPamSecretSessionControlsHttpTransport:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    return FortiPamSecretSessionControlsHttpTransport(
        _config(), connection_factory=lambda *_args, **_kwargs: _Connection(response, calls)
    )


def test_enable_controls_sends_fixed_controls_with_original_folder(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[dict[str, object]] = []
    transport = _transport(monkeypatch, _Response(200, {"http_status": 200}), calls)

    transport.enable_controls(23, PROFILE, prewrite=_baseline())

    assert len(calls) == 1
    assert calls[0]["method"] == "PUT"
    assert calls[0]["path"] == "/api/v2/cmdb/secret/database/23"
    assert json.loads(calls[0]["body"]) == {
        "id": 23, "name": "mcp-v4-secret-metadata-01",
        "folder": 17, "template": "Windows Local Account",
        "recording": "enable",
        "block-clipboard": "enable",
        "rdp-event-filter": "enable",
        "rdp-event-filter-profile": PROFILE,
    }
    assert "field" not in json.loads(calls[0]["body"])
    assert calls[0]["headers"] == {
        "Accept": "application/json",
        "Authorization": "Bearer unit-test-token",
        "Connection": "close",
        "Content-Type": "application/json",
        "Content-Length": str(len(calls[0]["body"])),
        "User-Agent": "fortipam-mcp-v4-secret-session-controls/1",
    }
    assert not caplog.records


@pytest.mark.parametrize(
    "secret_id, profile", [(0, PROFILE), (True, PROFILE), (23, "outside-scope")]
)
def test_invalid_input_fails_before_any_request(
    monkeypatch: pytest.MonkeyPatch, secret_id: object, profile: object
) -> None:
    calls: list[dict[str, object]] = []
    transport = _transport(monkeypatch, _Response(200, {"http_status": 200}), calls)

    with pytest.raises(SecretSessionControlsHttpTransportError):
        transport.enable_controls(secret_id, profile, prewrite=_baseline())  # type: ignore[arg-type]

    assert calls == []


@pytest.mark.parametrize(
    "response",
    [
        _Response(500, {"http_status": 500}),
        _Response(200, {"http_status": 500}),
        _Response(302, {"http_status": 200}),
        _Response(200, {"http_status": 200, "status": "error", "error": -1}),
        _Response(200, {"http_status": 200}, content_type="text/plain"),
    ],
)
def test_unsuccessful_or_unexpected_response_is_categorical_and_never_retried(
    monkeypatch: pytest.MonkeyPatch, response: _Response
) -> None:
    calls: list[dict[str, object]] = []
    transport = _transport(monkeypatch, response, calls)

    with pytest.raises(SecretSessionControlsHttpTransportError) as failure:
        transport.enable_controls(23, PROFILE, prewrite=_baseline())

    assert str(failure.value) == "FortiPAM V4 Secret session-controls transport is unavailable."
    assert len(calls) == 1


def test_oversized_response_fails_after_one_put(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    transport = _transport(
        monkeypatch,
        _Response(200, {"http_status": 200, "padding": "x" * MAX_RESPONSE_BYTES}),
        calls,
    )

    with pytest.raises(SecretSessionControlsHttpTransportError):
        transport.enable_controls(23, PROFILE, prewrite=_baseline())

    assert len(calls) == 1


def test_response_field_is_redacted_before_json_decode_and_buffers_are_zeroed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    decoded: list[bytes] = []
    original_loads = transport_module.json.loads

    def _loads(value: object, *args: object, **kwargs: object) -> object:
        if isinstance(value, bytearray):
            decoded.append(bytes(value))
        return original_loads(value, *args, **kwargs)

    zeroed: list[bytearray] = []
    original_zeroize = transport_module._zeroize_mutable

    def _zeroize(content: bytearray) -> None:
        zeroed.append(content)
        original_zeroize(content)

    monkeypatch.setattr(transport_module.json, "loads", _loads)
    monkeypatch.setattr(transport_module, "_zeroize_mutable", _zeroize)
    transport = _transport(
        monkeypatch,
        _Response(200, {"http_status": 200, "results": {"field": [{"value": "secret"}]}}),
        calls,
    )

    transport.enable_controls(23, PROFILE, prewrite=_baseline())

    assert decoded and b"secret" not in decoded[-1]
    assert original_loads(decoded[-1])["results"]["field"] is None
    assert len(zeroed) == 2
    assert all(content == bytearray() for content in zeroed)


@pytest.mark.parametrize(
    "status,error,expected_status,expected_error",
    [
        (500, -5, 500, -5),
        (200, -1, 200, -1),
        (302, -2_147_483_648, 302, -2_147_483_648),
        (500, "-5", 500, None),
        (500, True, 500, None),
        (500, -2_147_483_649, 500, None),
        (500, 23, 500, None),
        (999, -5, None, -5),
        ("500", -5, None, -5),
    ],
)
def test_failure_logs_only_typed_bounded_status_codes(
    monkeypatch, caplog, status, error, expected_status, expected_error,
) -> None:
    marker = "private-response-selector-token"
    response = _Response(status, {
        "status": "error", "error": error,
        "message": marker, "results": {"field": [{"value": marker}]},
    })
    calls: list[dict[str, object]] = []
    with pytest.raises(SecretSessionControlsHttpTransportError):
        _transport(monkeypatch, response, calls).enable_controls(23, PROFILE, prewrite=_baseline())

    stage = "vendor_status" if status == 200 else "http_status"
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.getMessage().startswith(
        f"Secret session-controls PUT failed: stage={stage} "
        f"http_status={expected_status} vendor_error={expected_error} category=unclassified required_field=none"
    )
    assert record.exc_info is None and record.stack_info is None
    assert marker not in caplog.text
    assert PROFILE not in caplog.text and "unit-test-token" not in caplog.text
    assert len(calls) == 1


@pytest.mark.parametrize("content_type,stage", [
    ("text/plain", "response_content_type"),
    ("application/json", "response_json"),
])
def test_non_json_failure_does_not_log_response_or_headers(
    monkeypatch, caplog, content_type, stage,
) -> None:
    response = _Response(502, {}, content_type=content_type)
    response._content = b"private-invalid-response-token"
    calls: list[dict[str, object]] = []
    with pytest.raises(SecretSessionControlsHttpTransportError):
        _transport(monkeypatch, response, calls).enable_controls(23, PROFILE, prewrite=_baseline())
    assert len(caplog.records) == 1
    assert caplog.records[0].getMessage().startswith(
        f"Secret session-controls PUT failed: stage={stage} "
        "http_status=502 vendor_error=None category=unclassified required_field=none"
    )
    assert "private-invalid-response-token" not in caplog.text
    assert content_type not in caplog.text
    assert len(calls) == 1


@pytest.mark.parametrize("exception,stage", [
    (TimeoutError("private-timeout-token"), "timeout"),
    (OSError("private-network-token"), "response_headers"),
])
def test_transport_exceptions_are_logged_without_exception_details(
    monkeypatch, caplog, exception, stage,
) -> None:
    calls: list[dict[str, object]] = []
    response = _Response(200, {"http_status": 200})

    class FailingConnection(_Connection):
        def getresponse(self):
            raise exception

    connection = FailingConnection(response, calls)
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamSecretSessionControlsHttpTransport(
        _config(), connection_factory=lambda *a, **k: connection,
    )
    with pytest.raises(SecretSessionControlsHttpTransportError) as failure:
        transport.enable_controls(23, PROFILE, prewrite=_baseline())
    assert str(failure.value) == transport_module._UNAVAILABLE
    assert len(caplog.records) == 1
    record = caplog.records[0]
    assert record.getMessage().startswith(
        f"Secret session-controls PUT failed: stage={stage} "
        "http_status=None vendor_error=None category=unclassified required_field=none"
    )
    assert record.exc_info is None and record.stack_info is None
    assert str(exception) not in caplog.text
    assert PROFILE not in caplog.text and "unit-test-token" not in caplog.text
    assert connection.closed and len(calls) == 1


def test_satisfied_forced_controls_are_omitted_from_the_single_put(monkeypatch) -> None:
    baseline = _baseline()
    baseline = replace(
        baseline, recording_enabled=True, clipboard_blocking_enabled=True,
        folder_policy=replace(baseline.folder_policy, recording="enable", block_clipboard="enable"),
    )
    calls: list[dict[str, object]] = []
    _transport(monkeypatch, _Response(200, {"status": "success"}), calls).enable_controls(
        23, PROFILE, prewrite=baseline,
    )
    assert len(calls) == 1
    assert json.loads(calls[0]["body"]) == {
        "id": 23, "name": "mcp-v4-secret-metadata-01",
        "folder": 17, "template": "Windows Local Account", "rdp-event-filter": "enable", "rdp-event-filter-profile": PROFILE,
    }


@pytest.mark.parametrize("policy_change,current_change", [
    ({"recording": "disable"}, {}),
    ({"block_clipboard": "disable"}, {}),
    ({"recording": "enable"}, {}),
    ({"rdp_event_filter": "enable"}, {"rdp_event_filter_enabled": True}),
    ({"rdp_event_filter": "disable"}, {}),
    ({}, {"recording_enabled": True, "clipboard_blocking_enabled": True,
          "rdp_event_filter_enabled": True, "rdp_event_filter_profile_matches": True}),
])
def test_policy_conflicts_unproved_forced_filter_and_noop_never_put(
    monkeypatch, policy_change, current_change,
) -> None:
    baseline = _baseline()
    baseline = replace(baseline, folder_policy=replace(baseline.folder_policy, **policy_change), **current_change)
    calls: list[dict[str, object]] = []
    with pytest.raises(SecretSessionControlsHttpTransportError):
        _transport(monkeypatch, _Response(200, {}), calls).enable_controls(23, PROFILE, prewrite=baseline)
    assert calls == []


def test_only_the_changed_profile_is_written_when_mutable_controls_are_satisfied(monkeypatch) -> None:
    calls: list[dict[str, object]] = []
    baseline = replace(_baseline(), recording_enabled=True, clipboard_blocking_enabled=True, rdp_event_filter_enabled=True)
    _transport(monkeypatch, _Response(200, {}), calls).enable_controls(23, PROFILE, prewrite=baseline)
    assert json.loads(calls[0]["body"]) == {
        "id": 23, "name": "mcp-v4-secret-metadata-01",
        "folder": 17, "template": "Windows Local Account",
        "rdp-event-filter-profile": PROFILE,
    }


def test_private_policy_names_do_not_enter_projection_representations() -> None:
    baseline = _baseline()
    assert baseline.folder_policy.policy_name not in repr(baseline)
    assert baseline.folder_policy.policy_name not in repr(baseline.folder_policy)
    assert baseline.folder_policy.folder_name not in repr(baseline.folder_policy)


@pytest.mark.parametrize("error,cli_error,category,field", [
    ("Permission denied.", None, "permission_denied", "none"),
    ("Invalid CSRF token", None, "csrf_rejected", "none"),
    ("Invalid data", None, "invalid_data", "none"),
    ("Entry already exists", None, "conflict", "none"),
    (None, "Missing required field: id", "required_data_missing", "id"),
    (-5, "Parameter 'uuid' is required.", "required_data_missing", "uuid"),
    ("Missing required parameter: \"field\"", None, "required_data_missing", "field"),
    (None, "Missing required field: private-marker", "unclassified", "none"),
    (None, "Missing required field: name private-marker", "unclassified", "none"),
    (None, "Missing required field: 'id\"", "unclassified", "none"),
    (None, "Missing required field: \u0130d", "unclassified", "none"),
    (None, "Permission denied for private-marker", "unclassified", "none"),
    ("unrecognized-private-marker", None, "unclassified", "none"),
    ("Invalid data", "Permission denied", "unclassified", "none"),
    ("Missing required field: name", "Missing required field: uuid", "unclassified", "none"),
    ("x" * 512 + "Permission denied", None, "unclassified", "none"),
    ({"private-marker": "value"}, ["private-marker"], "unclassified", "none"),
])
def test_vendor_text_classification_never_exposes_response_values(
    monkeypatch, caplog, error, cli_error, category, field,
) -> None:
    calls: list[dict[str, object]] = []
    response = _Response(400, {
        "error": error, "cli_error": cli_error, "message": "private-marker",
        "name": PROFILE, "id": 23, "token": "unit-test-token",
    })
    with pytest.raises(SecretSessionControlsHttpTransportError) as failure:
        _transport(monkeypatch, response, calls).enable_controls(23, PROFILE, prewrite=_baseline())
    assert str(failure.value) == transport_module._UNAVAILABLE
    assert len(caplog.records) == 1 and len(calls) == 1
    record = caplog.records[0]
    numeric_error = -5 if error == -5 else None
    assert record.getMessage().startswith(
        "Secret session-controls PUT failed: stage=http_status http_status=400 "
        f"vendor_error={numeric_error} category={category} required_field={field}"
    )
    assert record.exc_info is None and record.stack_info is None
    for private in ("private-marker", PROFILE, "unit-test-token"):
        assert private not in caplog.text and private not in repr(record.args)


@pytest.mark.parametrize("field", ["id", "name", "folder", "template", "uuid", "field"])
def test_required_field_classifier_has_only_fixed_field_identifiers(field) -> None:
    assert transport_module._classify_error({"cli_error": f"Missing required field: {field}"}) == (
        "required_data_missing", field,
    )


def test_multiline_diagnostics_emit_only_sorted_fixed_terms_and_presence(monkeypatch, caplog) -> None:
    calls: list[dict[str, object]] = []
    response = _Response(400, {
        "error": "Invalid secret for private-marker-7391",
        "cli_error": "private-selector: missing parameter\nrequired UUID; INVALID token private-value-9282",
        "message": "permission csrf duplicate",
    })
    with pytest.raises(SecretSessionControlsHttpTransportError):
        _transport(monkeypatch, response, calls).enable_controls(23, PROFILE, prewrite=_baseline())
    assert len(caplog.records) == 1 and len(calls) == 1
    record = caplog.records[0]
    assert record.args == (
        "http_status", 400, None, "unclassified", "none", True, True,
        ("invalid", "missing", "parameter", "required", "secret", "token", "uuid"),
    )
    for private in ("private-marker-7391", "private-selector", "private-value-9282", PROFILE):
        assert private not in caplog.text and private not in repr(record.args)


def test_diagnostic_terms_ignore_oversized_text_and_partial_words(monkeypatch, caplog) -> None:
    calls: list[dict[str, object]] = []
    response = _Response(400, {
        "error": "invalid " + "private" * 100,
        "cli_error": "id99 field_name requiredValue nameSuffix secretStuff private-marker",
    })
    with pytest.raises(SecretSessionControlsHttpTransportError):
        _transport(monkeypatch, response, calls).enable_controls(23, PROFILE, prewrite=_baseline())
    assert len(caplog.records) == 1 and len(calls) == 1
    record = caplog.records[0]
    assert record.args == ("http_status", 400, None, "unclassified", "none", False, True, ())
    assert "private" not in caplog.text
    assert record.exc_info is None and record.stack_info is None


def test_required_field_vocabulary_survives_unclassified_error_wording() -> None:
    # Exact phrase classification must remain conservative, while known schema
    # names remain available for diagnosis without exposing surrounding values.
    for field in ("id", "name", "folder", "template", "uuid", "field"):
        payload = {"error": f"{field.upper()} field missing (private-marker-7391)"}
        assert transport_module._classify_error(payload) == ("unclassified", "none")
        assert transport_module._diagnostic_text_evidence(payload) == (
            True, False, tuple(sorted({field, "field", "missing"})),
        )


def test_identity_envelope_uses_only_original_protected_snapshot(monkeypatch) -> None:
    calls: list[dict[str, object]] = []
    original = _baseline()
    baseline = replace(original, folder_policy=replace(original.folder_policy, folder_id=73))
    _transport(monkeypatch, _Response(200, {}), calls).enable_controls(
        23, PROFILE, prewrite=baseline,
    )
    body = json.loads(calls[0]["body"])
    assert body["id"] == 23 and type(body["id"]) is int
    assert body["name"] == baseline.original_name
    assert body["folder"] == 73 and type(body["folder"]) is int
    assert body["template"] == baseline.original_template
    assert set(body) == {"id", "name", "folder", "template", "recording", "block-clipboard", "rdp-event-filter", "rdp-event-filter-profile"}
    assert baseline == replace(original, folder_policy=replace(original.folder_policy, folder_id=73))
