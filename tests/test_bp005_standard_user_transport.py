from __future__ import annotations

import json
from pathlib import Path
import stat
from typing import Any

import pytest

from fortipam_mcp.bp005_standard_user_transport import (
    FortiPamBp005StandardUserTransport,
    Bp005StandardUserTransportError,
    _CREATE,
)
from fortipam_mcp.local_user_create_live_workflow import (
    BP005_STANDARD_USER_WORKFLOW_CONTRACT,
    LocalUserCreateLiveWorkflow,
    LocalUserCreateLiveWorkflowError,
)
from fortipam_mcp.m4_execution_store import PersistentM4ExecutionStateStore
from v4_planning import M4Outcome

from test_bp005_standard_user_preflight import (
    Harness as PreflightHarness,
    _DEFAULT,
)
from test_local_user_reset_name_reader import PRINCIPAL
from test_local_user_reset_projection import _body

NAME = "mcp-v4-user-bp005-standard-synthetic"


class Harness:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.directory = root / "standard-user-material"
        self.directory.mkdir(mode=0o700)
        self.key = root / "execution.key"
        self.key.write_bytes(b"k" * 32)
        self.key.chmod(0o600)
        self.state = PersistentM4ExecutionStateStore(root / "execution.sqlite3", self.key)
        self.source = PreflightHarness()
        self.detail = bytearray()
        self.create_calls = 0
        self.detail_reads = 0
        self.fail_ack = False
        self.late_gate_close = False
        self.workflow: LocalUserCreateLiveWorkflow | None = None
        self.transport = self.new_transport()
        self.workflow = LocalUserCreateLiveWorkflow(
            self.transport,
            execution_store=self.state,
            workflow_contract=BP005_STANDARD_USER_WORKFLOW_CONTRACT,
        )

    def new_transport(self) -> FortiPamBp005StandardUserTransport:
        return FortiPamBp005StandardUserTransport(
            self.source.network.reader._config,
            username=NAME,
            api_principal=PRINCIPAL,
            material_directory=self.directory,
            enabled=True,
            connection_factory=self.connect,
        )

    def connect(self, host: str, port: int, **kwargs: Any) -> Any:
        assert (host, port) == ("pam.example.test", 9443)
        h = self

        class Response:
            status = 200
            offset = 0
            body = bytearray()
            closed = False

            def getheader(self, key: str, default: str = "") -> str:
                return {"content-type": "application/json", "content-encoding": "identity"}.get(key, default)

            def readinto(self, view: memoryview) -> int:
                count = min(len(view), len(self.body) - self.offset)
                view[:count] = self.body[self.offset:self.offset + count]
                self.offset += count
                return count

            def close(self) -> None:
                self.closed = True

        class Connection:
            response = Response()
            closed = False

            def request(self, method: str, path: str, *, body: Any = None, headers: dict[str, str]) -> None:
                if method == "POST" and headers.get("X-HTTP-Method-Override") == "GET":
                    delegate = h.source.network.connect(host, port, **kwargs)
                    delegate.request(method, path, body=body, headers=headers)
                    self.response = delegate.response
                    self._delegate = delegate
                    return
                assert "X-HTTP-Method-Override" not in headers
                assert headers["Accept-Encoding"] == "identity"
                if path in h.source.bodies:
                    assert method == "GET" and body is None
                    h.source.network.calls.append(path)
                    self.response.body = h.source.bodies[path]
                elif path == _CREATE:
                    assert method == "POST" and isinstance(body, memoryview)
                    assert "password" in headers["Content-Type"] or headers["Content-Type"] == "application/json"
                    if h.late_gate_close:
                        h.transport._enabled = False
                    if not h.transport._enabled:
                        raise AssertionError("transport must block a closed final gate")
                    selected = json.loads(body.tobytes())
                    password = selected.pop("password")
                    assert password.encode("ascii") == (h.directory / "initial-password").read_bytes()
                    assert selected["accprofile"] == "pam_standard_user"
                    assert selected["status"] == "enable"
                    selected.update(id=17, q_ref=0)
                    selected["vdom"] = [{"name": "synthetic-scope", "q_origin_key": "synthetic-scope"}]
                    h.detail = _body(selected, mkey=NAME)
                    h.create_calls += 1
                    self.response.body = _body(
                        {}, http_method="POST", mkey=NAME, revision_changed=True,
                        old_revision="synthetic-before", revision="synthetic-after",
                    ).replace(b',"results":{}', b"")
                    if h.fail_ack:
                        self.response.body = _body({}, http_method="POST", mkey="different-user")
                elif path == h.transport._detail:
                    assert method == "GET" and body is None
                    h.detail_reads += 1
                    self.response.body = h.detail
                else:
                    raise AssertionError("unexpected fixed route")

            def getresponse(self) -> Response:
                return self.response

            def close(self) -> None:
                self.closed = True
                delegate = getattr(self, "_delegate", None)
                if delegate is not None:
                    delegate.close()

        return Connection()

    def execute(self) -> dict[str, object]:
        assert self.workflow is not None
        preview = self.workflow.preview(username=NAME, requester_digest="a" * 64)
        authorization = self.workflow.confirm(
            str(preview["preview_ref"]), requester_digest="a" * 64,
        )
        return self.workflow.execute(
            str(authorization["authorization_ref"]), requester_digest="a" * 64,
        )


def test_standard_user_post_is_guarded_once_and_retains_only_owner_files(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    assert h.execute()["outcome"] == "succeeded"
    assert h.create_calls == h.detail_reads == 1
    assert h.transport._created is not None
    assert stat.S_IMODE((h.directory / "initial-password").stat().st_mode) == 0o600
    evidence = json.loads((h.directory / "created-readback.json").read_bytes())
    assert evidence["user_id"] == 17 and "password" not in evidence
    assert h.state.audit_events[-1].outcome is M4Outcome.SUCCEEDED
    h.source.disposed()


def test_standard_user_transport_rejects_unguarded_dispatch(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    with pytest.raises(Bp005StandardUserTransportError):
        h.transport.create_and_readback(NAME)
    assert h.create_calls == 0 and not list(h.directory.iterdir())
    with pytest.raises(LocalUserCreateLiveWorkflowError):
        LocalUserCreateLiveWorkflow(h.transport)
    h.source.disposed()


def test_bad_post_ack_is_reconciled_once_but_never_claimed_as_created(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    h.fail_ack = True
    assert h.execute()["outcome"] == "reconciliation_required"
    assert h.create_calls == h.detail_reads == 1
    assert h.transport._created is None
    assert not (h.directory / "created-readback.json").exists()
    assert h.state.audit_events[-1].outcome is M4Outcome.RECONCILIATION_REQUIRED
    h.source.disposed()


def test_final_gate_is_checked_at_request_boundary(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    h.late_gate_close = True
    assert h.execute()["outcome"] == "reconciliation_required"
    assert h.create_calls == 0
    assert (h.directory / "initial-password").is_file()
    h.source.disposed()
