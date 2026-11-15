from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import fortipam_mcp.dlp_file_pattern_delete_http_transport as transport_module
from fortipam_mcp.dlp_file_pattern_delete_http_transport import (
    DLP_FILE_PATTERN_DELETE_ID,
    DLP_FILE_PATTERN_DELETE_NAME,
    DLP_REGEXP_SENSOR_NAME,
    DlpFilePatternDeleteHttpTransportConfig,
    DlpFilePatternDeleteHttpTransportConfigurationError,
    DlpFilePatternDeleteHttpTransportError,
    FortiPamDlpFilePatternDeleteHttpTransport,
    load_dlp_file_pattern_delete_http_transport_config,
)
from fortipam_mcp.dlp_file_pattern_ssh_transport import (
    DlpFilePatternInspection,
    DlpFilePatternReadback,
)
from fortipam_mcp.dlp_sensor_ssh_transport import DlpRegexpSensorReadback


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


class _PatternSshTransport:
    def __init__(self) -> None:
        self.readback_verified = True
        self.exists = True
        self.readback_calls: list[tuple[int, str]] = []
        self.inspect_calls: list[tuple[int, str]] = []

    def readback(self, pattern_id: int, pattern_name: str) -> DlpFilePatternReadback:
        self.readback_calls.append((pattern_id, pattern_name))
        return DlpFilePatternReadback(*([self.readback_verified] * 3))

    def inspect(self, pattern_id: int, pattern_name: str) -> DlpFilePatternInspection:
        self.inspect_calls.append((pattern_id, pattern_name))
        return DlpFilePatternInspection(self.exists, self.exists)


class _SensorSshTransport:
    def __init__(self) -> None:
        self.reference_count = 0
        self.regexp_verified = True
        self.regexp_results: list[bool] = []
        self.reference_calls: list[int] = []
        self.regexp_calls: list[str] = []

    def file_pattern_reference_count(self, pattern_id: int) -> int:
        self.reference_calls.append(pattern_id)
        return self.reference_count

    def readback_regexp_sensor(self, name: str) -> DlpRegexpSensorReadback:
        self.regexp_calls.append(name)
        verified = (
            self.regexp_results.pop(0)
            if self.regexp_results
            else self.regexp_verified
        )
        return DlpRegexpSensorReadback(*([verified] * 8))


def _config() -> DlpFilePatternDeleteHttpTransportConfig:
    return DlpFilePatternDeleteHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _pattern_record() -> dict[str, object]:
    return {
        "id": DLP_FILE_PATTERN_DELETE_ID,
        "q_origin_key": DLP_FILE_PATTERN_DELETE_ID,
        "name": DLP_FILE_PATTERN_DELETE_NAME,
        "entries": [{"filter-type": "type", "file-type": "pdf"}],
        "comment": "accepted",
    }


def _regexp_record() -> dict[str, object]:
    return {
        "name": DLP_REGEXP_SENSOR_NAME,
        "q_origin_key": DLP_REGEXP_SENSOR_NAME,
        "filter": [
            {
                "id": 1,
                "name": "mcp-v4-dlp-filter-regexp-block",
                "type": "file",
                "proto": "http-get",
                "filter-by": "regexp",
                "regexp": "withheld-test-sentinel",
                "action": "block",
            }
        ],
    }


def _digest(record: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(
            record,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _detail(record: dict[str, object]) -> dict[str, object]:
    return {"results": [record]}


def _sensors(*, referenced: bool = False) -> dict[str, object]:
    file_type = DLP_FILE_PATTERN_DELETE_ID if referenced else 9999
    return {
        "results": [
            {
                "filter": [
                    {
                        "filter-by": "file-type",
                        "file-type": file_type,
                    }
                ]
            }
        ]
    }


def _transport(
    responses: list[_Response],
    pattern_ssh: _PatternSshTransport,
    sensor_ssh: _SensorSshTransport,
    calls: list[dict[str, object]] | None = None,
) -> FortiPamDlpFilePatternDeleteHttpTransport:
    request_calls = calls if calls is not None else []
    return FortiPamDlpFilePatternDeleteHttpTransport(
        _config(),
        pattern_ssh,  # type: ignore[arg-type]
        sensor_ssh,  # type: ignore[arg-type]
        client_factory=lambda **_: _Client(responses, request_calls),
        accepted_digest=_digest(_pattern_record()),
    )


def _inspection_responses(*, referenced: bool = False) -> list[_Response]:
    return [
        _Response(200, _detail(_pattern_record())),
        _Response(200, _sensors(referenced=referenced)),
        _Response(200, _detail(_regexp_record())),
    ]


def test_loader_requires_exact_opt_in_and_dedicated_configuration(tmp_path: Path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_API_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_API_CA_FILE": str(ca_file),
        "FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_API_TIMEOUT_SECONDS": "12",
    }

    loaded = load_dlp_file_pattern_delete_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    environment["FPA_HOME_LAB_FPA1_V4_DLP_FILE_PATTERN_API_ENABLED"] = "false"
    with pytest.raises(
        DlpFilePatternDeleteHttpTransportConfigurationError,
        match="ENABLED",
    ):
        load_dlp_file_pattern_delete_http_transport_config(environment)


def test_inspect_requires_digest_dual_projection_and_zero_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    pattern_ssh = _PatternSshTransport()
    sensor_ssh = _SensorSshTransport()
    transport = _transport(_inspection_responses(), pattern_ssh, sensor_ssh)

    inspection = transport.inspect_delete_target()

    assert inspection.exists is True
    assert inspection.eligible_fixed_pattern is True
    assert inspection.sensor_reference_count_rest == 0
    assert inspection.sensor_reference_count_ssh == 0
    assert inspection.target_digest == _digest(_pattern_record())
    assert inspection.regexp_sensor_digest == _digest(_regexp_record())
    assert pattern_ssh.readback_calls == [
        (DLP_FILE_PATTERN_DELETE_ID, DLP_FILE_PATTERN_DELETE_NAME)
    ]
    assert sensor_ssh.reference_calls == [DLP_FILE_PATTERN_DELETE_ID]
    assert sensor_ssh.regexp_calls == [DLP_REGEXP_SENSOR_NAME]

    sensor_ssh = _SensorSshTransport()
    sensor_ssh.reference_count = 1
    referenced = _transport(
        _inspection_responses(referenced=True),
        _PatternSshTransport(),
        sensor_ssh,
    ).inspect_delete_target()
    assert referenced.eligible_fixed_pattern is False
    assert referenced.sensor_reference_count_rest == 1
    assert referenced.sensor_reference_count_ssh == 1


def test_inspect_fails_closed_on_record_api_or_ssh_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    drifted = _pattern_record()
    drifted["comment"] = "changed"
    with pytest.raises(DlpFilePatternDeleteHttpTransportError):
        _transport(
            [_Response(200, _detail(drifted))],
            _PatternSshTransport(),
            _SensorSshTransport(),
        ).inspect_delete_target()

    wrong_projection = _pattern_record()
    assert isinstance(wrong_projection["entries"], list)
    wrong_projection["entries"][0]["file-type"] = "docx"  # type: ignore[index]
    wrong = FortiPamDlpFilePatternDeleteHttpTransport(
        _config(),
        _PatternSshTransport(),  # type: ignore[arg-type]
        _SensorSshTransport(),  # type: ignore[arg-type]
        client_factory=lambda **_: _Client(
            [_Response(200, _detail(wrong_projection))],
            [],
        ),
        accepted_digest=_digest(wrong_projection),
    )
    with pytest.raises(DlpFilePatternDeleteHttpTransportError):
        wrong.inspect_delete_target()

    pattern_ssh = _PatternSshTransport()
    pattern_ssh.readback_verified = False
    with pytest.raises(DlpFilePatternDeleteHttpTransportError):
        _transport(
            [_Response(200, _detail(_pattern_record()))],
            pattern_ssh,
            _SensorSshTransport(),
        ).inspect_delete_target()


def test_delete_rechecks_bodyless_then_proves_absence_and_regexp_preservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    calls: list[dict[str, object]] = []
    pattern_ssh = _PatternSshTransport()
    pattern_ssh.exists = False
    transport = _transport(
        _inspection_responses()
        + [
            _Response(200, {"http_status": 200}),
            _Response(404, {}),
            _Response(200, _detail(_regexp_record())),
        ],
        pattern_ssh,
        _SensorSshTransport(),
        calls,
    )

    result = transport.delete_and_readback(
        _digest(_pattern_record()),
        _digest(_regexp_record()),
    )

    assert result.verified is True
    assert [call["method"] for call in calls] == [
        "GET",
        "GET",
        "GET",
        "DELETE",
        "GET",
        "GET",
    ]
    assert all(call["json"] is None for call in calls)
    assert pattern_ssh.inspect_calls == [
        (DLP_FILE_PATTERN_DELETE_ID, DLP_FILE_PATTERN_DELETE_NAME)
    ]


def test_delete_rejects_reference_ambiguous_response_or_regexp_loss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    referenced = _transport(
        _inspection_responses(referenced=True),
        _PatternSshTransport(),
        _SensorSshTransport(),
    )
    with pytest.raises(DlpFilePatternDeleteHttpTransportError):
        referenced.delete_and_readback(
            _digest(_pattern_record()),
            _digest(_regexp_record()),
        )

    ambiguous = _transport(
        _inspection_responses() + [_Response(503, {})],
        _PatternSshTransport(),
        _SensorSshTransport(),
    )
    with pytest.raises(DlpFilePatternDeleteHttpTransportError):
        ambiguous.delete_and_readback(
            _digest(_pattern_record()),
            _digest(_regexp_record()),
        )

    pattern_ssh = _PatternSshTransport()
    pattern_ssh.exists = False
    sensor_ssh = _SensorSshTransport()
    sensor_ssh.regexp_results = [True, False]
    result = _transport(
        _inspection_responses()
        + [
            _Response(200, {"http_status": 200}),
            _Response(404, {}),
            _Response(200, _detail(_regexp_record())),
        ],
        pattern_ssh,
        sensor_ssh,
    ).delete_and_readback(
        _digest(_pattern_record()),
        _digest(_regexp_record()),
    )
    assert result.verified is False
