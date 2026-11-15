"""Durable one-dispatch behavior for the fixed Unix rotation candidate."""

from dataclasses import replace
import json
import sqlite3

import pytest

from fortipam_mcp.password_rotation_http_transport import (
    FortiPamPasswordRotationHttpTransport,
    PasswordRotationReadback,
    PasswordRotationState,
)
from fortipam_mcp.password_rotation_live_workflow import (
    PasswordRotationLiveWorkflow,
    PasswordRotationLiveWorkflowError,
)
from fortipam_mcp.password_verification_http_transport import PasswordVerificationBinding


BINDING = PasswordVerificationBinding(
    "Public/test", "unix-rotation-fixture", "test-target", "192.0.2.10", "test-user",
)
CURRENT = PasswordRotationState(23, 17, None, True, True, True, True)
REQUESTER = "b" * 64


class FakeTransport(FortiPamPasswordRotationHttpTransport):
    def __init__(self, *, ambiguous: bool = False):
        self.state = CURRENT
        self.ambiguous = ambiguous
        self.writes = 0

    def inspect(self):
        return self.state

    def rotate_once(self, expected):
        assert expected == CURRENT
        self.writes += 1
        if self.ambiguous:
            raise TimeoutError("synthetic lost response")
        self.state = replace(CURRENT, change_marker="a" * 64)
        return PasswordRotationReadback(True, True, True)


def factory(tmp_path, transport):
    tmp_path.chmod(0o700)
    key = tmp_path / "key"
    key.write_bytes(b"a" * 32)
    key.chmod(0o600)
    return lambda: PasswordRotationLiveWorkflow(
        tmp_path / "rotation.sqlite3", key, transport, BINDING, clock=lambda: 1000,
    )


@pytest.mark.parametrize("ambiguous", [False, True])
def test_one_dispatch_survives_restart_and_never_replays(tmp_path, ambiguous):
    transport = FakeTransport(ambiguous=ambiguous)
    build = factory(tmp_path, transport)
    previews = [build().preview(requester_digest=REQUESTER) for _ in range(2)]
    assert BINDING.secret_name not in json.dumps(previews)
    refs = [build().confirm(item["preview_ref"], requester_digest=REQUESTER)["authorization_ref"]
            for item in previews]
    result = build().execute(refs[0], requester_digest=REQUESTER)
    assert result["outcome"] == ("reconciliation_required" if ambiguous else "succeeded")
    assert result["target_login_verified"] is False
    assert build().execute(refs[0], requester_digest=REQUESTER)["idempotent_replay"]
    with pytest.raises(PasswordRotationLiveWorkflowError):
        build().execute(refs[1], requester_digest=REQUESTER)
    transport.state = CURRENT
    with pytest.raises(PasswordRotationLiveWorkflowError):
        build().preview(requester_digest=REQUESTER)
    assert transport.writes == 1


def test_drift_and_requester_mismatch_prevent_rotation(tmp_path):
    transport = FakeTransport()
    build = factory(tmp_path, transport)
    preview = build().preview(requester_digest=REQUESTER)
    with pytest.raises(PasswordRotationLiveWorkflowError):
        build().confirm(preview["preview_ref"], requester_digest="c" * 64)
    ref = build().confirm(preview["preview_ref"], requester_digest=REQUESTER)["authorization_ref"]
    transport.state = replace(CURRENT, secret_id=24)
    result = build().execute(ref, requester_digest=REQUESTER)
    assert result["outcome"] == "not_executed"
    assert result["device_write_may_have_occurred"] is False
    assert transport.writes == 0


def test_tampering_cannot_hide_consumed_claim(tmp_path):
    transport = FakeTransport()
    build = factory(tmp_path, transport)
    preview = build().preview(requester_digest=REQUESTER)
    ref = build().confirm(preview["preview_ref"], requester_digest=REQUESTER)["authorization_ref"]
    assert build().execute(ref, requester_digest=REQUESTER)["outcome"] == "succeeded"
    with sqlite3.connect(tmp_path / "rotation.sqlite3") as connection:
        connection.execute("UPDATE password_rotation_workflow SET state='previewed'")
    transport.state = CURRENT
    with pytest.raises(PasswordRotationLiveWorkflowError):
        build().preview(requester_digest=REQUESTER)
    assert transport.writes == 1
