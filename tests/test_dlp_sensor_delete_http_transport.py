from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import fortipam_mcp.dlp_sensor_delete_http_transport as transport_module
from fortipam_mcp.dlp_sensor_delete_http_transport import (
    DLP_SENSOR_DELETE_NAME,
    DLP_SENSOR_PATTERN_ID,
    DLP_SENSOR_PATTERN_NAME,
    DlpSensorDeleteHttpTransportConfig,
    DlpSensorDeleteHttpTransportConfigurationError,
    DlpSensorDeleteHttpTransportError,
    FortiPamDlpSensorDeleteHttpTransport,
    load_dlp_sensor_delete_http_transport_config,
)
from fortipam_mcp.dlp_sensor_ssh_transport import (
    DlpSensorInspection,
    DlpSensorReadback,
)


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


class _SshTransport:
    def __init__(self) -> None:
        self.readback_verified = True
        self.exists = True
        self.pattern_preserved = True
        self.readback_calls: list[tuple[str, int]] = []
        self.inspect_calls: list[tuple[str, int, str]] = []

    def readback(self, name: str, pattern_id: int) -> DlpSensorReadback:
        self.readback_calls.append((name, pattern_id))
        return DlpSensorReadback(*([self.readback_verified] * 7))

    def inspect(
        self, name: str, pattern_id: int, pattern_name: str
    ) -> DlpSensorInspection:
        self.inspect_calls.append((name, pattern_id, pattern_name))
        return DlpSensorInspection(
            self.exists,
            self.pattern_preserved,
            self.pattern_preserved,
            self.pattern_preserved,
        )


def _config() -> DlpSensorDeleteHttpTransportConfig:
    return DlpSensorDeleteHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _record() -> dict[str, object]:
    return {
        "name": DLP_SENSOR_DELETE_NAME,
        "q_origin_key": DLP_SENSOR_DELETE_NAME,
        "filter": [
            {
                "id": 1,
                "name": "mcp-v4-dlp-filter-pdf-block",
                "proto": "http-get",
                "filter-by": "file-type",
                "file-type": DLP_SENSOR_PATTERN_ID,
                "action": "block",
            }
        ],
        "comment": "accepted",
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


def _detail(record: dict[str, object] | None = None) -> dict[str, object]:
    return {"results": [record or _record()]}


def _dependencies(*, referenced: bool = False, count: int = 1) -> dict[str, object]:
    return {
        "results": [
            {
                "id": index,
                "dlp-sensor": DLP_SENSOR_DELETE_NAME if referenced and index == 0 else "other",
            }
            for index in range(count)
        ]
    }


def _transport(
    responses: list[_Response],
    ssh: _SshTransport,
    calls: list[dict[str, object]] | None = None,
) -> FortiPamDlpSensorDeleteHttpTransport:
    request_calls = calls if calls is not None else []
    return FortiPamDlpSensorDeleteHttpTransport(
        _config(),
        ssh,  # type: ignore[arg-type]
        client_factory=lambda **_: _Client(responses, request_calls),
        accepted_digest=_digest(_record()),
    )


def test_loader_requires_exact_opt_in_and_dedicated_configuration(tmp_path: Path) -> None:
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("unit-test-ca\n", encoding="utf-8")
    environment = {
        "FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_API_BASE_URL": "https://fpa.example.test",
        "FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_API_API_TOKEN": "unit-test-token",
        "FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_API_CA_FILE": str(ca_file),
        "FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_API_TIMEOUT_SECONDS": "12",
    }

    loaded = load_dlp_sensor_delete_http_transport_config(environment)

    assert loaded.base_url == "https://fpa.example.test"
    assert loaded.timeout_seconds == 12
    environment["FPA_HOME_LAB_FPA1_V4_DLP_SENSOR_API_ENABLED"] = "false"
    with pytest.raises(DlpSensorDeleteHttpTransportConfigurationError, match="ENABLED"):
        load_dlp_sensor_delete_http_transport_config(environment)


def test_inspect_requires_digest_dual_projection_and_zero_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    ssh = _SshTransport()
    transport = _transport(
        [
            _Response(200, _detail()),
            _Response(200, _dependencies()),
            _Response(200, _dependencies()),
        ],
        ssh,
    )

    inspection = transport.inspect_delete_target()

    assert inspection.exists is True
    assert inspection.eligible_fixed_sensor is True
    assert inspection.secret_reference_count == 0
    assert inspection.policy_reference_count == 0
    assert inspection.target_digest == _digest(_record())
    assert ssh.readback_calls == [(DLP_SENSOR_DELETE_NAME, DLP_SENSOR_PATTERN_ID)]

    referenced = _transport(
        [
            _Response(200, _detail()),
            _Response(200, _dependencies()),
            _Response(200, _dependencies(referenced=True)),
        ],
        _SshTransport(),
    ).inspect_delete_target()
    assert referenced.eligible_fixed_sensor is False
    assert referenced.policy_reference_count == 1


def test_inspect_fails_closed_on_record_api_or_ssh_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    drifted = _record()
    drifted["comment"] = "changed"
    with pytest.raises(DlpSensorDeleteHttpTransportError):
        _transport([_Response(200, _detail(drifted))], _SshTransport()).inspect_delete_target()

    wrong_projection = _record()
    assert isinstance(wrong_projection["filter"], list)
    wrong_projection["filter"][0]["action"] = "allow"  # type: ignore[index]
    wrong = FortiPamDlpSensorDeleteHttpTransport(
        _config(),
        _SshTransport(),  # type: ignore[arg-type]
        client_factory=lambda **_: _Client([_Response(200, _detail(wrong_projection))], []),
        accepted_digest=_digest(wrong_projection),
    )
    with pytest.raises(DlpSensorDeleteHttpTransportError):
        wrong.inspect_delete_target()

    ssh = _SshTransport()
    ssh.readback_verified = False
    with pytest.raises(DlpSensorDeleteHttpTransportError):
        _transport([_Response(200, _detail())], ssh).inspect_delete_target()


def test_delete_rechecks_bodyless_then_proves_absence_and_pattern_preservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    calls: list[dict[str, object]] = []
    ssh = _SshTransport()
    ssh.exists = False
    transport = _transport(
        [
            _Response(200, _detail()),
            _Response(200, _dependencies()),
            _Response(200, _dependencies()),
            _Response(200, {"http_status": 200}),
            _Response(404, {}),
        ],
        ssh,
        calls,
    )

    result = transport.delete_and_readback(_digest(_record()))

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "GET", "GET", "DELETE", "GET"]
    assert all(call["json"] is None for call in calls)
    assert ssh.inspect_calls == [
        (DLP_SENSOR_DELETE_NAME, DLP_SENSOR_PATTERN_ID, DLP_SENSOR_PATTERN_NAME)
    ]


def test_delete_rejects_reference_ambiguous_response_or_pattern_loss(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    referenced = _transport(
        [
            _Response(200, _detail()),
            _Response(200, _dependencies(referenced=True)),
            _Response(200, _dependencies()),
        ],
        _SshTransport(),
    )
    with pytest.raises(DlpSensorDeleteHttpTransportError):
        referenced.delete_and_readback(_digest(_record()))

    ambiguous = _transport(
        [
            _Response(200, _detail()),
            _Response(200, _dependencies()),
            _Response(200, _dependencies()),
            _Response(503, {}),
        ],
        _SshTransport(),
    )
    with pytest.raises(DlpSensorDeleteHttpTransportError):
        ambiguous.delete_and_readback(_digest(_record()))

    ssh = _SshTransport()
    ssh.exists = False
    ssh.pattern_preserved = False
    result = _transport(
        [
            _Response(200, _detail()),
            _Response(200, _dependencies()),
            _Response(200, _dependencies()),
            _Response(200, {"http_status": 200}),
            _Response(404, {}),
        ],
        ssh,
    ).delete_and_readback(_digest(_record()))
    assert result.verified is False
