from __future__ import annotations

import json
from pathlib import Path
import stat

import pytest

import fortipam_mcp.target_delete_http_transport as transport_module
from fortipam_mcp.classification_tag_assign_contract import (
    ClassificationTagAssignInspection,
)
from fortipam_mcp.target_contract import TargetInspection
from fortipam_mcp.target_delete_http_transport import (
    FortiPamTargetDeleteHttpTransport,
    TargetDeleteHttpTransportError,
    _record_digest,
    _record_digest_without_key,
)
from fortipam_mcp.target_http_transport import TargetHttpTransportConfig


TARGET = "mcp-v4-target-b104"
TAG = "mcp-v4-classification-tag-b29"


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


class _SshTarget:
    def __init__(self, states: list[TargetInspection]) -> None:
        self._states = states

    def inspect(self, target_name: str) -> TargetInspection:
        assert target_name == TARGET
        return self._states.pop(0)


class _References:
    def __init__(self, counts: list[int]) -> None:
        self._counts = counts

    def reference_count(self, target_name: str) -> int:
        assert target_name == TARGET
        return self._counts.pop(0)


def _config() -> TargetHttpTransportConfig:
    return TargetHttpTransportConfig(
        base_url="https://fpa.example.test",
        bearer_token="unit-test-token",
        timeout_seconds=15,
        ca_file=None,
    )


def _record() -> dict[str, object]:
    return {
        "name": TARGET,
        "q_origin_key": TARGET,
        "class": "Other",
        "template": "Unix Account (SSH Password)",
        "description": "Accepted laboratory Target",
    }


def _related(*, target_exists: bool = True) -> ClassificationTagAssignInspection:
    return ClassificationTagAssignInspection(
        target_exists=target_exists,
        classification_tag_exists=False,
        current_class_is_other=target_exists,
        target_non_class_state_digest=(
            _record_digest_without_key(_record(), "class")
            if target_exists
            else "0" * 64
        ),
        classification_tag_state_digest="1" * 64,
        state_digest="2" * 64,
        current_class_matches_tag=False,
    )


def _qualified(payload: dict[str, object], *, method: str = "GET", build: int = 29) -> dict[str, object]:
    return {"version": "v7.0.0", "build": build, "status": "success", "http_status": 200,
            "http_method": method, "path": "secret", "name": "target", **payload}


def test_ambiguous_delete_claim_blocks_fresh_process_before_network(tmp_path: Path) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    claim = directory / "delete.claim.json"
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, _qualified({"results": [_record()]})),
        _Response(200, _qualified({}, method="DELETE")),
        _Response(200, _qualified({"results": [_record()]}, build=30)),
    ]
    def build() -> FortiPamTargetDeleteHttpTransport:
        return FortiPamTargetDeleteHttpTransport(
            _config(), _Target([_related()]), _SshTarget([TargetInspection(True)]), _References([0]),
            target_name=TARGET, classification_tag_name=TAG, accepted_digest=_record_digest(_record()),
            claim_path=claim, client_factory=lambda **_: _Client(responses, calls),
        )
    with pytest.raises(TargetDeleteHttpTransportError):
        build().delete_and_readback(_record_digest(_record()), _record_digest_without_key(_record(), "class"))
    assert [call["method"] for call in calls] == ["GET", "DELETE", "GET"]
    assert stat.S_IMODE(claim.stat().st_mode) == 0o600
    assert json.loads(claim.read_text())["state"] == "delete_attempt_reserved"
    before = list(calls)
    with pytest.raises(TargetDeleteHttpTransportError):
        build().inspect_delete_target()
    assert calls == before


def test_persistent_delete_rejects_unqualified_build_before_dispatch(tmp_path: Path) -> None:
    directory = tmp_path / "private"
    directory.mkdir(mode=0o700)
    claim = directory / "delete.claim.json"
    calls: list[dict[str, object]] = []
    transport = FortiPamTargetDeleteHttpTransport(
        _config(), _Target([]), _SshTarget([]), _References([]), target_name=TARGET,
        classification_tag_name=TAG, accepted_digest=_record_digest(_record()), claim_path=claim,
        client_factory=lambda **_: _Client([_Response(200, _qualified({"results": [_record()]}, build=30))], calls),
    )
    with pytest.raises(TargetDeleteHttpTransportError):
        transport.delete_and_readback(_record_digest(_record()), _record_digest_without_key(_record(), "class"))
    assert [call["method"] for call in calls] == ["GET"]
    assert not claim.exists()


def test_owner_dispatch_uncertainty_consumes_outer_claim_and_blocks_network(tmp_path: Path) -> None:
    directory = tmp_path / "owner"
    directory.mkdir(mode=0o700)
    claim = directory / "delete.claim.json"
    calls: list[dict[str, object]] = []
    owner_calls: list[str] = []
    class Owner:
        def inspect(self) -> None:
            owner_calls.append("inspect")
        def dispatch(self) -> tuple[int, object]:
            assert claim.exists()
            owner_calls.append("dispatch")
            raise TargetDeleteHttpTransportError("uncertain Owner logout")
    def build() -> FortiPamTargetDeleteHttpTransport:
        return FortiPamTargetDeleteHttpTransport(
            _config(), _Target([_related()]), _SshTarget([TargetInspection(True)]), _References([0]),
            target_name=TARGET, classification_tag_name=TAG, accepted_digest=_record_digest(_record()),
            claim_path=claim, session_dispatcher=Owner(),
            client_factory=lambda **_: _Client([_Response(200, _qualified({"results": [_record()]}))], calls),
        )
    with pytest.raises(TargetDeleteHttpTransportError):
        build().delete_and_readback(_record_digest(_record()), _record_digest_without_key(_record(), "class"))
    assert owner_calls == ["inspect", "dispatch"]
    assert [call["method"] for call in calls] == ["GET"]
    before = list(calls), list(owner_calls)
    with pytest.raises(TargetDeleteHttpTransportError):
        build().inspect_delete_target()
    assert (calls, owner_calls) == before


@pytest.mark.parametrize("build,status_text,results,accepted", [
    (29, "Not Found", [], True), (29, "error", [], True),
    (30, "Not Found", [], False), (29, "unknown", [], False),
    (29, "Not Found", [_record()], False),
])
def test_build29_missing_target_envelope_is_exactly_qualified(tmp_path: Path, build, status_text, results, accepted) -> None:
    directory = tmp_path / "missing"
    directory.mkdir(mode=0o700)
    transport = FortiPamTargetDeleteHttpTransport(
        _config(), _Target([]), _SshTarget([]), _References([]), target_name=TARGET,
        classification_tag_name=TAG, accepted_digest=_record_digest(_record()),
        claim_path=directory / "claim.json",
    )
    payload = _qualified({"http_status": 404, "status": status_text, "results": results}, build=build)
    if accepted:
        transport._qualify_response(payload, 404, "GET")
    else:
        with pytest.raises(TargetDeleteHttpTransportError):
            transport._qualify_response(payload, 404, "GET")
    if status_text == "Not Found":
        with pytest.raises(TargetDeleteHttpTransportError):
            transport._qualify_response({**payload, "http_method": "DELETE"}, 404, "DELETE")


def test_inspect_requires_exact_digest_absent_tag_ssh_presence_and_zero_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTargetDeleteHttpTransport(
        _config(),
        _Target([_related()]),
        _SshTarget([TargetInspection(True)]),
        _References([0]),
        target_name=TARGET,
        classification_tag_name=TAG,
        accepted_digest=_record_digest(_record()),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": [_record()]})],
            calls,
        ),
    )

    result = transport.inspect_delete_target()

    assert result.exists is True
    assert result.eligible_fixed_target is True
    assert result.target_reference_count == 0
    assert result.target_class_is_other is True
    assert result.classification_tag_absent is True
    assert result.ssh_target_exists is True
    assert [call["method"] for call in calls] == ["GET"]


def test_delete_is_bodyless_and_proves_api_ssh_tag_and_reference_absence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    responses = [
        _Response(200, {"results": [_record()]}),
        _Response(200, {"http_status": 200}),
        _Response(404, {}),
    ]
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    transport = FortiPamTargetDeleteHttpTransport(
        _config(),
        _Target([_related(), _related(target_exists=False)]),
        _SshTarget([TargetInspection(True), TargetInspection(False)]),
        _References([0, 0]),
        target_name=TARGET,
        classification_tag_name=TAG,
        accepted_digest=_record_digest(_record()),
        client_factory=lambda **_: _Client(responses, calls),
    )

    result = transport.delete_and_readback(
        _record_digest(_record()),
        _record_digest_without_key(_record(), "class"),
    )

    assert result.verified is True
    assert [call["method"] for call in calls] == ["GET", "DELETE", "GET"]
    assert "json" not in calls[1]


def test_delete_rejects_record_drift_and_live_references(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(transport_module, "_ssl_context", lambda _: object())
    changed = _record()
    changed["description"] = "drifted"
    drifted = FortiPamTargetDeleteHttpTransport(
        _config(),
        _Target([]),
        _SshTarget([]),
        _References([]),
        target_name=TARGET,
        classification_tag_name=TAG,
        accepted_digest=_record_digest(_record()),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": [changed]})],
            [],
        ),
    )
    with pytest.raises(TargetDeleteHttpTransportError):
        drifted.inspect_delete_target()

    referenced = FortiPamTargetDeleteHttpTransport(
        _config(),
        _Target([_related()]),
        _SshTarget([TargetInspection(True)]),
        _References([1]),
        target_name=TARGET,
        classification_tag_name=TAG,
        accepted_digest=_record_digest(_record()),
        client_factory=lambda **_: _Client(
            [_Response(200, {"results": [_record()]})],
            [],
        ),
    )
    assert referenced.inspect_delete_target().eligible_fixed_target is False
