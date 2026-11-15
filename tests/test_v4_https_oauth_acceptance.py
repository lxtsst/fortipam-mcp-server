from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import TracebackType
from typing import cast
from urllib.parse import parse_qs, urlencode

import pytest
import httpx2

import scripts.v4_https_oauth_acceptance as acceptance
from scripts.v4_https_oauth_acceptance import (
    V4HttpsOAuthAcceptanceError,
    RestartMarkerConfig,
    _cleanup_marker,
    _confirmation_url,
    _create_ready_marker,
    _hidden_inputs,
    _revision,
    _poll_restart_readiness,
    _restart_readiness_status_class,
    _restart_marker_config,
    _synchronized_restart_retry,
    _validate_marker_paths,
    _validate_https_mcp_url,
    _validate_plan,
    _validate_preview,
    _validate_status,
    _wait_for_continue_marker,
)


@pytest.mark.parametrize(
    ("pass_scope_option", "scope_option", "expected_scope"),
    [
        (False, None, "fortipam:read fortipam:plan"),
        (True, False, "fortipam:read fortipam:plan"),
        (True, True, "fortipam:read fortipam:plan fortipam:operate"),
        (True, None, None),
        (True, 0, None),
        (True, 1, None),
        (True, "true", None),
    ],
)
def test_oauth_operation_scope_requires_explicit_boolean_opt_in_before_io(
    tmp_path: Path,
    pass_scope_option: bool,
    scope_option: object,
    expected_scope: str | None,
) -> None:
    origin = "https://mcp.example.com"
    url = f"{origin}/fpamcp-v4"
    issuer = f"{url}/oauth"
    client_id = "acceptance-client-0123456789"
    state_directory = tmp_path / "state"
    scopes: list[str] = []
    requests: list[str] = []
    authorization_state = ""

    def handle(request: httpx2.Request) -> httpx2.Response:
        nonlocal authorization_state
        path = request.url.path
        requests.append(path)
        if path.startswith("/.well-known/"):
            return httpx2.Response(200, json={})
        if path == "/fpamcp-v4/oauth/register":
            scopes.append(json.loads(request.content)["scope"])
            return httpx2.Response(201, json={"client_id": client_id})
        if path == "/fpamcp-v4/oauth/authorize":
            query = parse_qs(request.url.query.decode("ascii"))
            scopes.append(query["scope"][0])
            authorization_state = query["state"][0]
            return httpx2.Response(302, headers={"location": f"{issuer}/login"})
        if path == "/fpamcp-v4/oauth/login" and request.method == "GET":
            return httpx2.Response(
                200,
                text='<input name="request_id" value="test-request">'
                '<input name="csrf_token" value="test-csrf">',
            )
        if path == "/fpamcp-v4/oauth/login" and request.method == "POST":
            callback_query = urlencode(
                {"state": authorization_state, "iss": issuer, "code": "test-code"}
            )
            return httpx2.Response(
                302, headers={"location": f"{acceptance.REDIRECT_URI}?{callback_query}"},
            )
        if path == "/fpamcp-v4/oauth/token":
            return httpx2.Response(200, json={"access_token": "test-token"})
        raise AssertionError(f"Unexpected offline OAuth request: {request.method} {path}")

    async def run() -> tuple[str, bool, bool, str]:
        options = (
            {"include_operation_scope": cast(bool, scope_option)}
            if pass_scope_option else {}
        )
        async with httpx2.AsyncClient(transport=httpx2.MockTransport(handle)) as client:
            return await acceptance._oauth_token(
                client,
                url=url,
                origin=origin,
                issuer=issuer,
                username="test-user",
                password="test-password",
                client_state_file=state_directory / "client.env",
                **options,
            )

    if expected_scope is None:
        with pytest.raises(V4HttpsOAuthAcceptanceError, match="scope is invalid"):
            asyncio.run(run())
        assert requests == []
        assert not state_directory.exists()
    else:
        _owner_directory(state_directory)
        assert asyncio.run(run()) == ("test-token", True, False, client_id)
        assert scopes == [expected_scope, expected_scope]


@pytest.mark.parametrize("failure_phase", ["stream_enter", "session_enter", "session_exit"])
@pytest.mark.parametrize("cancelled", [False, True])
def test_mcp_session_failure_unwinds_resources_before_outer_revoke(
    monkeypatch: pytest.MonkeyPatch,
    failure_phase: str,
    cancelled: bool,
) -> None:
    events: list[str] = []
    tool_failure = RuntimeError("tool failed")
    failure: BaseException = (
        asyncio.CancelledError("session cancelled")
        if cancelled
        else ExceptionGroup("session failed", [RuntimeError("inner failure")])
    )

    class HttpClient:
        def __init__(self, **kwargs: object) -> None:
            events.append("http_created")

        async def aclose(self) -> None:
            await asyncio.sleep(0)
            events.append("http_closed")

    class Stream:
        async def __aenter__(self) -> tuple[object, object]:
            events.append("stream_enter")
            if failure_phase == "stream_enter":
                raise failure
            return object(), object()

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: TracebackType | None,
        ) -> None:
            assert exc_value is failure
            await asyncio.sleep(0)
            events.append("stream_exit")

    class Session:
        def __init__(self, read_stream: object, write_stream: object) -> None:
            pass

        async def __aenter__(self) -> Session:
            events.append("session_enter")
            if failure_phase == "session_enter":
                raise failure
            return self

        async def __aexit__(
            self,
            exc_type: type[BaseException] | None,
            exc_value: BaseException | None,
            traceback: TracebackType | None,
        ) -> None:
            assert exc_value is tool_failure
            events.append("session_exit")
            raise failure

    def stream_client(url: str, **kwargs: object) -> Stream:
        return Stream()

    monkeypatch.setattr(acceptance.httpx2, "AsyncClient", HttpClient)
    monkeypatch.setattr(acceptance, "streamable_http_client", stream_client)
    monkeypatch.setattr(acceptance, "ClientSession", Session)

    async def run() -> None:
        try:
            async with acceptance._mcp_session("https://mcp.example.com/fpamcp-v4", "test", True):
                raise tool_failure
        finally:
            await asyncio.sleep(0)
            events.append("outer_revoke")

    with pytest.raises(type(failure)) as caught:
        asyncio.run(run())
    assert caught.value is failure
    expected = ["http_created", "stream_enter"]
    if failure_phase != "stream_enter":
        expected.append("session_enter")
        if failure_phase == "session_exit":
            expected.append("session_exit")
            assert caught.value.__context__ is tool_failure
        expected.append("stream_exit")
    assert events == expected + ["http_closed", "outer_revoke"]


def test_v4_acceptance_requires_https_before_any_network_access() -> None:
    with pytest.raises(V4HttpsOAuthAcceptanceError, match="URL is invalid"):
        _validate_https_mcp_url("http://127.0.0.1/fpamcp-v4")
    with pytest.raises(V4HttpsOAuthAcceptanceError, match="URL is invalid"):
        _validate_https_mcp_url("https://mcp.example.com/fpamcp-v4/")


def test_v4_acceptance_validates_only_the_no_device_plan_contract() -> None:
    status = {
        "runtime_profile": "v4-plan-only",
        "device_access": False,
        "product_write_enabled": False,
        "dispatchable": False,
        "host_services_bound": True,
        "confirmation_transport_bound": True,
    }
    _validate_status(status)
    with pytest.raises(V4HttpsOAuthAcceptanceError, match="no-device"):
        _validate_status({**status, "device_access": True})

    preview = {
        "state": "awaiting_confirmation",
        "confirmation_state": "awaiting_human_reauthentication",
        "summary_ref": "summary-ref-00000001",
        "revision": 1,
        "confirmation_url": "https://mcp.example.com/fpamcp-v4/oauth/v4/confirm/token",
    }
    _validate_preview(preview)
    assert _revision(preview) == 1
    assert _confirmation_url(preview, "https://mcp.example.com") == preview[
        "confirmation_url"
    ]
    with pytest.raises(V4HttpsOAuthAcceptanceError, match="confirmation URL"):
        _confirmation_url(
            {**preview, "confirmation_url": "https://other.example/confirm/token"},
            "https://mcp.example.com",
        )

    plan = {
        "dispatchable": False,
        "adapter_registry_bound": False,
        "executor_runtime_packaged": False,
        "executor_mcp_exposed": False,
        "planner_mcp_exposed": True,
        "plan_ref": "plan-ref-00000001",
    }
    _validate_plan(plan)
    with pytest.raises(V4HttpsOAuthAcceptanceError, match="execution boundary"):
        _validate_plan({**plan, "dispatchable": True})


def test_v4_acceptance_form_parser_requires_exact_expected_fields() -> None:
    assert _hidden_inputs(
        '<input name="request_id" value="request"><input name="csrf_token" value="csrf">'
        '<button name="action" value="allow">Allow</button>'
        '<button name="action" value="deny">Deny</button>',
        {"request_id", "csrf_token"},
    ) == {"request_id": "request", "csrf_token": "csrf"}
    with pytest.raises(V4HttpsOAuthAcceptanceError, match="form was invalid"):
        _hidden_inputs('<input name="csrf_token" value="csrf">', {"request_id", "csrf_token"})


def _owner_directory(path: Path) -> None:
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)


def test_restart_marker_handshake_accepts_only_fresh_matching_continue_marker(
    tmp_path: Path,
) -> None:
    state = tmp_path / "restart-state"
    _owner_directory(state)
    ready = state / "ready.marker"
    continue_file = state / "continue.marker"
    config = RestartMarkerConfig(ready, continue_file, 5)
    _validate_marker_paths(config)
    nonce, ready_fingerprint = _create_ready_marker(ready)

    async def operator_continue(_: float) -> None:
        descriptor = os.open(
            continue_file,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY,
            0o600,
        )
        try:
            os.write(
                descriptor,
                f"v4-restart-continue {nonce}\n".encode("ascii"),
            )
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    continue_fingerprint = asyncio.run(
        _wait_for_continue_marker(
            continue_file,
            nonce=nonce,
            timeout_seconds=5,
            sleep=operator_continue,
        )
    )
    _cleanup_marker(ready, ready_fingerprint)
    _cleanup_marker(continue_file, continue_fingerprint)
    assert not ready.exists()
    assert not continue_file.exists()


def test_restart_readiness_retries_only_startup_statuses_then_requires_authorized_init() -> None:
    outcomes = iter((503, 502, 200))
    clock = [0.0]

    async def probe() -> int:
        return next(outcomes)

    async def advance(seconds: float) -> None:
        clock[0] += seconds

    assert asyncio.run(
        _poll_restart_readiness(
            probe,
            timeout_seconds=5,
            monotonic=lambda: clock[0],
            sleep=advance,
        )
    ) == "authorized_initialize_ready_after_retry"
    assert _restart_readiness_status_class(401) == "authorization_denied"
    assert _restart_readiness_status_class(403) == "authorization_denied"
    assert _restart_readiness_status_class(404) == "non_retryable_http"


def test_restart_readiness_never_retries_authorization_or_nonstartup_http() -> None:
    async def denied() -> int:
        return 401

    with pytest.raises(V4HttpsOAuthAcceptanceError, match="authorization"):
        asyncio.run(_poll_restart_readiness(denied, timeout_seconds=5))

    async def inconsistent() -> int:
        return 409

    with pytest.raises(V4HttpsOAuthAcceptanceError, match="non-retryable"):
        asyncio.run(_poll_restart_readiness(inconsistent, timeout_seconds=5))


def test_restart_readiness_recovers_only_a_transport_startup_failure() -> None:
    attempts = [0]
    clock = [0.0]

    async def probe() -> int:
        attempts[0] += 1
        if attempts[0] == 1:
            raise httpx2.ConnectError("startup transport unavailable")
        return 200

    async def advance(seconds: float) -> None:
        clock[0] += seconds

    assert asyncio.run(
        _poll_restart_readiness(
            probe,
            timeout_seconds=5,
            monotonic=lambda: clock[0],
            sleep=advance,
        )
    ) == "authorized_initialize_ready_after_retry"


def test_restart_record_mismatch_never_becomes_a_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "restart-state"
    _owner_directory(state)
    ready = state / "ready.marker"
    continue_file = state / "continue.marker"

    async def continue_after_restart(
        path: Path,
        *,
        nonce: str,
        timeout_seconds: int,
    ) -> tuple[int, int]:
        del timeout_seconds
        path.write_text(f"v4-restart-continue {nonce}\n", encoding="ascii")
        os.chmod(path, 0o600)
        metadata = path.lstat()
        return (metadata.st_dev, metadata.st_ino)

    async def readiness(*args: object, **kwargs: object) -> str:
        del args, kwargs
        return "authorized_initialize_ready"

    async def mismatched_retry(*args: object, **kwargs: object) -> bool:
        del args, kwargs
        return False

    monkeypatch.setattr(acceptance, "_await_authorized_restart_readiness", readiness)
    monkeypatch.setattr(acceptance, "_verify_restart_retry", mismatched_retry)
    with pytest.raises(V4HttpsOAuthAcceptanceError, match="different confirmation"):
        asyncio.run(
            _synchronized_restart_retry(
                "https://mcp.example.com/fpamcp-v4",
                "opaque-token",
                True,
                {"summary_ref": "summary-ref-00000001", "revision": 1},
                {"confirmation_ref": "confirmation-ref-000001"},
                {"plan_ref": "plan-ref-00000001"},
                RestartMarkerConfig(ready, continue_file, 5),
                wait_for_continue=continue_after_restart,
            )
        )
    assert not ready.exists()
    assert not continue_file.exists()


def test_restart_marker_timeout_cleans_only_the_owned_ready_marker(tmp_path: Path) -> None:
    state = tmp_path / "restart-state"
    _owner_directory(state)
    ready = state / "ready.marker"
    continue_file = state / "continue.marker"
    _nonce, ready_fingerprint = _create_ready_marker(ready)
    clock = [0.0]

    async def advance(seconds: float) -> None:
        clock[0] += seconds

    with pytest.raises(V4HttpsOAuthAcceptanceError, match="Timed out"):
        asyncio.run(
            _wait_for_continue_marker(
                continue_file,
                nonce="unused",
                timeout_seconds=1,
                monotonic=lambda: clock[0],
                sleep=advance,
            )
        )
    _cleanup_marker(ready, ready_fingerprint)
    assert not ready.exists()
    assert not continue_file.exists()


def test_restart_marker_rejects_stale_or_unsafe_paths(tmp_path: Path) -> None:
    state = tmp_path / "restart-state"
    _owner_directory(state)
    ready = state / "ready.marker"
    continue_file = state / "continue.marker"
    continue_file.write_text("v4-restart-continue stale\n", encoding="ascii")
    os.chmod(continue_file, 0o600)
    with pytest.raises(V4HttpsOAuthAcceptanceError, match="stale"):
        _validate_marker_paths(RestartMarkerConfig(ready, continue_file, 5))

    continue_file.unlink()
    continue_file.write_text("unsafe\n", encoding="ascii")
    os.chmod(continue_file, 0o640)
    with pytest.raises(V4HttpsOAuthAcceptanceError, match="unsafe"):
        _validate_marker_paths(RestartMarkerConfig(ready, continue_file, 5))

    with pytest.raises(V4HttpsOAuthAcceptanceError, match="requires URL"):
        _restart_marker_config(
            "https://mcp.example.com/fpamcp-v4",
            ready,
            None,
            5,
        )


def test_synchronized_restart_retry_cleans_only_markers_it_created(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "restart-state"
    _owner_directory(state)
    ready = state / "ready.marker"
    continue_file = state / "continue.marker"
    markers = RestartMarkerConfig(ready, continue_file, 5)

    async def continue_after_restart(
        path: Path,
        *,
        nonce: str,
        timeout_seconds: int,
    ) -> tuple[int, int]:
        del timeout_seconds
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        try:
            os.write(descriptor, f"v4-restart-continue {nonce}\n".encode("ascii"))
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
        metadata = path.lstat()
        return (metadata.st_dev, metadata.st_ino)

    async def retry(*args: object, **kwargs: object) -> bool:
        del args, kwargs
        return True

    async def readiness(*args: object, **kwargs: object) -> str:
        del args, kwargs
        return "authorized_initialize_ready"

    monkeypatch.setattr(acceptance, "_verify_restart_retry", retry)
    monkeypatch.setattr(acceptance, "_await_authorized_restart_readiness", readiness)
    assert asyncio.run(
        _synchronized_restart_retry(
            "https://mcp.example.com/fpamcp-v4",
            "opaque-token",
            True,
            {"summary_ref": "summary-ref-00000001", "revision": 1},
            {"confirmation_ref": "confirmation-ref-000001"},
            {"plan_ref": "plan-ref-00000001"},
            markers,
            wait_for_continue=continue_after_restart,
        )
    ) == (True, "authorized_initialize_ready")
    assert not ready.exists()
    assert not continue_file.exists()

    async def timed_out(*args: object, **kwargs: object) -> tuple[int, int]:
        del args, kwargs
        raise V4HttpsOAuthAcceptanceError("Timed out waiting for the restart continue marker.")

    with pytest.raises(V4HttpsOAuthAcceptanceError, match="Timed out"):
        asyncio.run(
            _synchronized_restart_retry(
                "https://mcp.example.com/fpamcp-v4",
                "opaque-token",
                True,
                {"summary_ref": "summary-ref-00000001", "revision": 1},
                {"confirmation_ref": "confirmation-ref-000001"},
                {"plan_ref": "plan-ref-00000001"},
                markers,
                wait_for_continue=timed_out,
            )
        )
    assert not ready.exists()
    assert not continue_file.exists()


def test_required_existing_client_never_registers_after_missing_state(tmp_path: Path) -> None:
    from types import SimpleNamespace
    tmp_path.chmod(0o700)
    calls: list[str] = []
    class Client:
        async def get(self, url: str) -> object:
            calls.append('get')
            return SimpleNamespace(status_code=200)
        async def post(self, *args: object, **kwargs: object) -> object:
            pytest.fail('Missing existing client must never cause registration')
    with pytest.raises(V4HttpsOAuthAcceptanceError, match='existing OAuth client'):
        asyncio.run(acceptance._oauth_token(
            Client(), url='https://mcp.example/mcp', origin='https://mcp.example',
            issuer='https://mcp.example/mcp/oauth', username='synthetic-user', password='synthetic-password',
            client_state_file=tmp_path/'missing.json', include_operation_scope=True, require_existing_client=True,
        ))
    assert calls == ['get','get'] and not (tmp_path/'missing.json').exists()
