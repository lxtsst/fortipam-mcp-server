"""Private build-29 independent reviewer denial; never a generic review relay."""
from collections.abc import Callable
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import threading
import time
from typing import Any, cast
from urllib.parse import urlsplit

import httpx

from .job_request_deny_contract import compile_job_request_deny_body, job_request_denied_readback
from .local_user_reset_fixture_preflight import _actor_context
from .secret_metadata_http_transport import SecretMetadataHttpTransportConfig, _ssl_context

_UNAVAILABLE = "The fixed Job Request denial transport is unavailable."
_LIMIT = 1_048_576
_QUEUE = "/api/v2/cmdb/secret/request?with_meta=true&vdom=root"


class JobRequestDenyHttpTransportError(RuntimeError):
    """Do not expose private identities, request contents or upstream errors."""

    def __init__(self, message: str = _UNAVAILABLE, *, stage: str = "preflight") -> None:
        super().__init__(message)
        self.stage = stage


@dataclass(frozen=True, slots=True, repr=False)
class JobRequestDenyBinding:
    request_id: int
    secret_id: int
    job_name: str
    requester: str
    reviewer: str

    def __post_init__(self) -> None:
        # Validate through the same contract, with a synthetic qualified envelope.
        row = {"id": self.request_id, "secret-id": self.secret_id, "request-type": "job",
               "job-name": self.job_name, "user": self.requester, "final-status": "pending",
               "tier1-status": "pending", "start-after-approve": "disable", "duration": 0,
               "start-time": "", "expiration-time": ""}
        envelope = {"version": "v7.0.0", "build": 29, "http_method": "GET", "http_status": 200,
                    "status": "OK", "path": "secret", "name": "request", "results": [row]}
        compile_job_request_deny_body({**envelope, "http_method": "POST"}, envelope,
                                      **self.contract_arguments())

    def contract_arguments(self) -> dict[str, Any]:
        return {"request_id": self.request_id, "secret_id": self.secret_id,
                "job_name": self.job_name, "requester": self.requester,
                "authenticated_reviewer": self.reviewer}


@dataclass(frozen=True, slots=True, repr=False)
class JobRequestDenyInspection:
    body_digest: str


@dataclass(frozen=True, slots=True)
class JobRequestDenyReadback:
    dispatch_consumed: bool
    http_accepted: bool
    denied_and_schedule_preserved: bool
    reviewer_logout_verified: bool


class FortiPamJobRequestDenyHttpTransport:
    """One bound denial with pre-login replay rejection and durable reservation.

    Readback proves only Request denial and unchanged scheduling fields. The
    caller must separately establish that the associated Job did not execute.
    No MCP tool or execution Gate is registered by this private candidate.
    """

    def __init__(self, config: SecretMetadataHttpTransportConfig, binding: JobRequestDenyBinding,
                 credentials: Callable[[], tuple[str, str]], *, claim_path: Path,
                 client_factory: Callable[..., Any] = httpx.Client,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self._config, self._binding = config, binding
        self._credentials, self._claim = credentials, claim_path
        self._client_factory = client_factory
        self._sleep = sleep
        self._lock = threading.Lock()
        self._check_parent()

    def _check_parent(self) -> None:
        try:
            info = self._claim.parent.lstat()
            if (not self._claim.is_absolute() or not stat.S_ISDIR(info.st_mode)
                    or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700):
                raise ValueError
        except Exception:
            raise JobRequestDenyHttpTransportError(_UNAVAILABLE, stage="claim_parent") from None

    def _unconsumed(self) -> None:
        self._check_parent()
        if os.path.lexists(self._claim):
            raise JobRequestDenyHttpTransportError(_UNAVAILABLE)

    def _reserve(self, body: dict[str, object]) -> None:
        self._unconsumed()
        directory = os.open(self._claim.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(directory)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
            fd = os.open(self._claim.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, "w") as file:
                json.dump({"contract": "job-request-deny-claim-v1", "state": "reserved",
                           "replay_permitted": False, "binding_digest": hashlib.sha256(
                               json.dumps(self._binding.contract_arguments(), sort_keys=True).encode()).hexdigest(),
                           "body_digest": hashlib.sha256(
                               json.dumps(body, sort_keys=True).encode()).hexdigest()}, file)
                file.flush()
                os.fsync(file.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)

    @staticmethod
    def _json(response: Any) -> object:
        if response.status_code != 200 or len(response.content) > _LIMIT:
            raise ValueError
        return json.loads(response.content)

    def inspect(self) -> JobRequestDenyInspection:
        return cast(JobRequestDenyInspection, self._run(execute=False))

    def deny_and_readback(self, expected: JobRequestDenyInspection | None = None) -> JobRequestDenyReadback:
        return cast(JobRequestDenyReadback, self._run(execute=True, expected=expected))

    def _run(self, *, execute: bool, expected: JobRequestDenyInspection | None = None) -> JobRequestDenyInspection | JobRequestDenyReadback:
        with self._lock:
            self._unconsumed()
            consumed = accepted = denied = logged_out = False
            inspection: JobRequestDenyInspection | None = None
            login_attempted = False
            failed = False
            stage = "login_page"
            failure_stage = "preflight"
            try:
                with self._client_factory(base_url=self._config.base_url, verify=_ssl_context(self._config),
                        timeout=self._config.timeout_seconds, follow_redirects=False, trust_env=False) as client:
                    try:
                        page = client.get("/remote/login?lang=en")
                        if page.status_code != 200 or 'action="/XX/YY/ZZ/AUTH"' not in page.text:
                            raise ValueError
                        stage = "credential_provider"
                        username, password = self._credentials()
                        if username != self._binding.reviewer or not isinstance(password, str) or not password:
                            raise ValueError
                        stage = "login"
                        login_attempted = True
                        auth = client.post("/XX/YY/ZZ/AUTH", data={"username": username, "password": password,
                            "magic": "0", "4Tredir": "/", "4Tmthd": "0"})
                        del username, password
                        location = auth.headers.get("location", "")
                        parsed = urlsplit(location)
                        if (auth.status_code != 303 or not location.startswith("/")
                                or location.startswith("//") or parsed.scheme or parsed.netloc
                                or parsed.path.startswith("/api/") or len(location) > 2048):
                            raise ValueError
                        client.get(location)
                        stage = "reviewer_identity"
                        state_response = client.get("/api/v2/monitor/web-ui/state")
                        raw = bytearray(state_response.content)
                        try:
                            if state_response.status_code != 200 or len(raw) > _LIMIT:
                                raise ValueError
                            _actor_context(raw, expected_name=self._binding.reviewer)
                            state = json.loads(raw)
                        finally:
                            raw[:] = b"\x00" * len(raw)
                        stage = "csrf"
                        cookie_name = state["results"]["ccsrf_token_cookie_name"]
                        if not isinstance(cookie_name, str):
                            raise ValueError
                        csrf = client.cookies.get(cookie_name)
                        if isinstance(csrf, str):
                            csrf = csrf.strip('"')
                        if not isinstance(csrf, str) or not csrf or any(ord(c) < 33 or ord(c) > 126 for c in csrf):
                            raise ValueError
                        headers = {"X-Requested-With": "XMLHttpRequest", "X-CSRFTOKEN": csrf}
                        stage = "reviewer_queue"
                        queue = self._json(client.post(_QUEUE, headers={**headers, "X-Http-Method-Override": "GET"},
                            json={"json_filter": [{"logic": "and", "filters": [{"key": "query-type",
                                "type": "string", "operator": "exact", "pattern": "reviewer"}]}]}))
                        detail_path = f"/api/v2/cmdb/secret/request/{self._binding.request_id}?with_meta=true&vdom=root"
                        stage = "request_detail"
                        before = self._json(client.get(detail_path))
                        stage = "deny_contract"
                        body = compile_job_request_deny_body(queue, before, **self._binding.contract_arguments())
                        inspection = JobRequestDenyInspection(hashlib.sha256(
                            json.dumps(body, sort_keys=True).encode()).hexdigest())
                        if expected is not None and (
                                not isinstance(expected, JobRequestDenyInspection) or inspection != expected):
                            raise ValueError
                        if execute:
                            stage = "claim_reserve"
                            self._reserve(body)
                            stage = "dispatch"
                            consumed = True
                            try:
                                review = client.post("/api/v2/internal/request-review", json=body, headers=headers)
                                accepted = review.status_code == 200
                            except Exception:
                                # Never resend an ambiguous POST. Read reconciliation only.
                                accepted = False
                            stage = "readback"
                            arguments = self._binding.contract_arguments()
                            del arguments["authenticated_reviewer"]
                            for delay in (0.0, 0.25, 0.5, 1.0):
                                if delay:
                                    self._sleep(delay)
                                try:
                                    after = self._json(client.get(detail_path))
                                    denied = job_request_denied_readback(before, after, **arguments)
                                except Exception:
                                    denied = False
                                if denied:
                                    break
                    except Exception:
                        failed = True
                        failure_stage = stage
                    finally:
                        if login_attempted:
                            try:
                                exit_response = client.get("/logout")
                                revoked = client.get("/api/v2/monitor/web-ui/state")
                                logged_out = (exit_response.status_code in {200, 302, 303}
                                              and revoked.status_code in {401, 403})
                            except Exception:
                                logged_out = False
                if failed or not logged_out:
                    raise JobRequestDenyHttpTransportError(stage=failure_stage if failed else "logout")
                if not execute:
                    if inspection is None:
                        raise ValueError
                    return inspection
                return JobRequestDenyReadback(consumed, accepted, denied, logged_out)
            except JobRequestDenyHttpTransportError:
                raise
            except Exception:
                raise JobRequestDenyHttpTransportError(_UNAVAILABLE, stage=stage) from None
