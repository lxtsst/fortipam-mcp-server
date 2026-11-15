from __future__ import annotations

import json

import pytest

import fortipam_mcp.classification_tag_delete_http_transport as transport_module
from fortipam_mcp.classification_tag_assign_contract import (
    ClassificationTagAssignInspection,
)
from fortipam_mcp.classification_tag_delete_http_transport import (
    ClassificationTagDeleteHttpTransportError,
    FortiPamClassificationTagDeleteHttpTransport,
    _record_digest,
)
from fortipam_mcp.folder_http_transport import FolderTransportConfig


TAG = "mcp-v4-classification-tag-b29"
TARGET = "mcp-v4-target-b104"
TARGET_DIGEST = "2" * 64


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


class _Target:
    def __init__(self, inspections: list[ClassificationTagAssignInspection]) -> None:
        self._inspections = inspections

    def inspect_classification_tag_assignment(
        self,
        target_name: str,
        classification_tag_name: str,
    ) -> ClassificationTagAssignInspection:
        assert target_name == TARGET
        assert classification_tag_name == TAG
        return self._inspections.pop(0)


class _References:
    def __init__(self, counts: list[int]) -> None:
        self._counts = counts

    def reference_count(self, tag_name: str) -> int:
        assert tag_name == TAG
        return self._counts.pop(0)


def _config() -> FolderTransportConfig:
    return FolderTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
        explicitly_enabled=True,
    )


def _record() -> dict[str, object]:
    return {
        "name": TAG,
        "q_origin_key": TAG,
        "description": "Lab ownership marker",
    }


def _target(*, tag_exists: bool = True, default: bool = True) -> ClassificationTagAssignInspection:
    return ClassificationTagAssignInspection(
        target_exists=True,
        classification_tag_exists=tag_exists,
        current_class_is_other=default,
        target_non_class_state_digest=TARGET_DIGEST,
        classification_tag_state_digest=(
            _record_digest(_record()) if tag_exists else _record_digest({})
        ),
        state_digest="3" * 64,
        current_class_matches_tag=not default,
    )


def test_inspect_requires_exact_digest_default_target_and_zero_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamClassificationTagDeleteHttpTransport(
        _config(),
        _Target([_target()]),
        _References([0]),
        tag_name=TAG,
        target_name=TARGET,
        accepted_digest=_record_digest(_record()),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": [_record()]})],
            calls,
        ),
    )

    result = transport.inspect_delete_target()

    assert result.exists is True
    assert result.eligible_fixed_tag is True
    assert result.tag_reference_count == 0
    assert result.target_is_default is True
    assert result.target_non_class_state_digest == TARGET_DIGEST
    assert [call["method"] for call in calls] == ["GET"]


def test_delete_is_bodyless_and_proves_absence_and_target_preservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"results": [_record()]}),
        _Response(200, {"http_status": 200}),
        _Response(404, {}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamClassificationTagDeleteHttpTransport(
        _config(),
        _Target([_target(), _target(tag_exists=False)]),
        _References([0, 0]),
        tag_name=TAG,
        target_name=TARGET,
        accepted_digest=_record_digest(_record()),
        client_factory=lambda **_: _Client(responses, calls),
    )

    result = transport.delete_and_readback(
        _record_digest(_record()),
        TARGET_DIGEST,
    )

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "DELETE", "GET"]
    assert "json" not in calls[1]


def test_delete_rejects_digest_drift_and_live_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    changed = _record()
    changed["description"] = "changed"
    drifted = FortiPamClassificationTagDeleteHttpTransport(
        _config(),
        _Target([]),
        _References([]),
        tag_name=TAG,
        target_name=TARGET,
        accepted_digest=_record_digest(_record()),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": [changed]})],
            [],
        ),
    )
    with pytest.raises(ClassificationTagDeleteHttpTransportError):
        drifted.inspect_delete_target()

    referenced = FortiPamClassificationTagDeleteHttpTransport(
        _config(),
        _Target([_target()]),
        _References([1]),
        tag_name=TAG,
        target_name=TARGET,
        accepted_digest=_record_digest(_record()),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": [_record()]})],
            [],
        ),
    )
    assert referenced.inspect_delete_target().eligible_fixed_tag is False
