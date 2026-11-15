from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataHttpTransportConfig,
)
from fortipam_mcp.secret_request_collection_http_transport import (
    SecretRequestCollectionRecord,
    SecretRequestCreatorSnapshot,
)
from fortipam_mcp.secret_request_create_contract import (
    SecretRequestCustomField,
    SecretRequestCreateInput,
    SecretRequestDefaultEvidence,
)
from fortipam_mcp.secret_request_create_http_transport import (
    FortiPamSecretRequestCreateHttpTransport,
    OwnerOnlySecretRequestCreateBindingResolver,
    OwnerOnlySecretRequestCreateDispatchClaim,
    SecretRequestCreateBinding,
    SecretRequestCreateDispatchClaimError,
    SecretRequestCreateTransportOutcome,
)
from fortipam_mcp.secret_request_create_mcp_action import (
    ProtectedSecretRequestCreateMcpAction,
    V4_SECRET_REQUEST_CREATE_EXECUTION_ENV,
    V4_SECRET_REQUEST_CREATE_FEATURE_ENV,
    V4_SECRET_REQUEST_CREATE_PREFIX,
    V4SecretRequestCreateConfigurationError,
    build_v4_secret_request_create_action,
    load_v4_secret_request_create_execution_gate,
    load_v4_secret_request_create_feature,
)
from fortipam_mcp.secret_request_create_prepare import (
    prepare_secret_request_create_intent,
)
from fortipam_mcp.secret_request_http_transport import SecretRequestObservation
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from v4_planning.models import AuthenticatedRequester


_ENVIRONMENT_REF = "request-environment-ref01"
_SCOPE_REF = "request-scope-reference01"
_FORTIPAM_REQUESTER = "synthetic-requester"
_INTENT_REF = "request-intent-reference01"


@pytest.mark.parametrize('witness_mode', ['absent', 'enabled', 'incomplete', 'reused_key'])
@pytest.mark.parametrize('authentication_mode', ['api-bearer', 'bp005-requester-session', 'unknown'])
def test_request_create_http_action_composition_is_explicit_and_owner_bound(
    tmp_path: Path, authentication_mode: str, witness_mode: str,
) -> None:
    assert load_v4_secret_request_create_feature({}) is False
    assert load_v4_secret_request_create_execution_gate({}) is False
    with pytest.raises(V4SecretRequestCreateConfigurationError, match="exactly"):
        load_v4_secret_request_create_feature(
            {V4_SECRET_REQUEST_CREATE_FEATURE_ENV: "TRUE"}
        )

    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    key = state / "request-create.hmac"
    key.write_text("75" * 32, encoding="ascii")
    key.chmod(0o600)
    environment = {
        V4_SECRET_REQUEST_CREATE_FEATURE_ENV: "true",
        V4_SECRET_REQUEST_CREATE_EXECUTION_ENV: "false",
        f"{V4_SECRET_REQUEST_CREATE_PREFIX}INTENT_BINDING_FILE": str(
            state / "intent.json"
        ),
        f"{V4_SECRET_REQUEST_CREATE_PREFIX}DISPATCH_CLAIM_FILE": str(
            state / "dispatch.claim"
        ),
        f"{V4_SECRET_REQUEST_CREATE_PREFIX}HMAC_KEY_FILE": str(key),
        f"{V4_SECRET_REQUEST_CREATE_PREFIX}AUTHORIZED_ENVIRONMENT_REF": (
            _ENVIRONMENT_REF
        ),
        f"{V4_SECRET_REQUEST_CREATE_PREFIX}AUTHORIZED_SCOPE_REF": _SCOPE_REF,
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_ENABLED": "true",
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_BASE_URL": (
            "https://fpa.example"
        ),
        "FPA_HOME_LAB_FPA1_V4_SECRET_METADATA_API_API_TOKEN": (
            "synthetic-token"
        ),
    }

    if witness_mode != "absent":
        environment[f"{V4_SECRET_REQUEST_CREATE_PREFIX}INVOCATION_WITNESS_FILE"] = str(state / "invocation.json")
        if witness_mode != "incomplete":
            witness_key_path = state / "invocation.key"
            witness_key_path.write_text(("75" if witness_mode == "reused_key" else "76") * 32)
            witness_key_path.chmod(0o600)
            environment[f"{V4_SECRET_REQUEST_CREATE_PREFIX}INVOCATION_WITNESS_HMAC_KEY_FILE"] = str(witness_key_path)

    if authentication_mode != 'api-bearer':
        environment[f'{V4_SECRET_REQUEST_CREATE_PREFIX}AUTHENTICATION_MODE'] = authentication_mode
    if authentication_mode == 'bp005-requester-session':
        provider = state / 'provider'
        provider.mkdir(mode=0o700)
        environment['FORTIPAM_MCP_V4_LOCAL_USER_CREATE_ACTION_BP005_USERNAME'] = 'mcp-v4-user-bp005-standard-20261002-1234abcd'
        environment['FORTIPAM_MCP_V4_LOCAL_USER_CREATE_ACTION_BP005_MATERIAL_DIRECTORY'] = str(provider)
    if authentication_mode == 'unknown' or witness_mode in {'incomplete', 'reused_key'}:
        with pytest.raises(V4SecretRequestCreateConfigurationError):
            build_v4_secret_request_create_action(environment)
        return
    action = build_v4_secret_request_create_action(environment)

    assert isinstance(action, ProtectedSecretRequestCreateMcpAction)
    assert (action._transport._invocation_witness_sink is not None) is (witness_mode == "enabled")
    with pytest.raises(RuntimeError):
        action.execute(_INTENT_REF, _principal())


def _principal(subject_ref: str = "requester-subject-ref01") -> V4PlanningPrincipal:
    return V4PlanningPrincipal(
        AuthenticatedRequester(subject_ref, "operator"),
        "b" * 64,
    )


def _binding(principal: V4PlanningPrincipal) -> SecretRequestCreateBinding:
    return SecretRequestCreateBinding(
        _INTENT_REF,
        _FORTIPAM_REQUESTER,
        principal.requester.digest,
        _ENVIRONMENT_REF,
        _SCOPE_REF,
        4_000_000_000,
    )


def _write_binding(
    path: Path,
    binding: SecretRequestCreateBinding,
    request: SecretRequestCreateInput,
) -> None:
    path.write_text(
        json.dumps(
            {
                "contract": "fortipam-v4-secret-request-create-intent-v1",
                "version": "1.0.0",
                "intent_ref": binding.intent_ref,
                "fortipam_requester": binding.fortipam_requester,
                "requester_digest": binding.requester_digest,
                "environment_ref": binding.environment_ref,
                "scope_ref": binding.scope_ref,
                "expires_at": binding.expires_at,
                "submission_mode": binding.submission_mode,
                "secret_id": request.secret_id,
                "request_type": request.request_type,
                "start_after_approve": request.start_after_approve,
                "start_time": request.start_time,
                "expiration_time": request.expiration_time,
                "duration": request.duration,
                "comments": request.comments,
                "timezone": request.timezone,
                "job_name": request.job_name,
                "custom_fields": [
                    {
                        "name": item.name,
                        "value": item.value,
                        "required": item.required,
                    }
                    for item in request.custom_fields
                ],
            }
        )
    )
    path.chmod(0o600)


def _request() -> SecretRequestCreateInput:
    return SecretRequestCreateInput(
        requester=_FORTIPAM_REQUESTER,
        secret_id=83,
        request_type="launcher",
        start_after_approve="enable",
        start_time="",
        expiration_time="",
        duration=30,
        comments="synthetic-comment",
        timezone="UTC",
        custom_fields=(
            SecretRequestCustomField("Ticket", "protected-field-value", True),
        ),
    )


def test_owner_only_intent_resolves_job_request_for_approval_window(
    tmp_path: Path,
) -> None:
    principal = _principal()
    binding = _binding(principal)
    request = SecretRequestCreateInput(
        requester=_FORTIPAM_REQUESTER,
        secret_id=83,
        request_type="job",
        start_after_approve="disable",
        start_time="",
        expiration_time="2026-09-30 12:30:00",
        duration=0,
        comments="synthetic-job-acceptance",
        timezone="Asia/Shanghai",
        job_name="synthetic-disabled-job",
    )
    path = tmp_path / "job-intent.json"
    prepare_secret_request_create_intent(path, binding=binding, request=request)

    prepared = OwnerOnlySecretRequestCreateBindingResolver(path).resolve(
        intent_ref=binding.intent_ref,
        requester_digest=principal.requester.digest,
        environment_ref=_ENVIRONMENT_REF,
        scope_ref=_SCOPE_REF,
    )

    assert prepared.request.request_type == "job"
    assert prepared.request.body(SecretRequestDefaultEvidence()) == {
        "id": 0,
        "user": _FORTIPAM_REQUESTER,
        "secret-id": 83,
        "request-type": "job",
        "start-after-approve": "disable",
        "start-time": "",
        "expiration-time": "2026-09-30 12:30:00",
        "duration": 0,
        "comments": "synthetic-job-acceptance",
        "timezone": "Asia/Shanghai",
        "field": [],
        "job-name": "synthetic-disabled-job",
    }


def test_job_request_dispatch_binds_only_the_new_job_delta(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    principal = _principal()
    request = SecretRequestCreateInput(
        requester=_FORTIPAM_REQUESTER,
        secret_id=83,
        request_type="job",
        start_after_approve="disable",
        start_time="",
        expiration_time="2026-09-30 12:30:00",
        duration=0,
        comments="synthetic-job-acceptance",
        timezone="Asia/Shanghai",
        job_name="synthetic-disabled-job",
    )
    binding_path = tmp_path / "job-intent.json"
    prepare_secret_request_create_intent(
        binding_path, binding=_binding(principal), request=request,
    )
    claim_path = tmp_path / "job-create.claim"

    class JobConnection(_Connection):
        def request(self, method, url, body, headers) -> None:
            assert claim_path.is_file()
            assert method == "POST"
            assert url == "/api/v2/cmdb/secret/request?with_meta=true&vdom=root"
            assert headers["Content-Type"] == "application/json"
            assert json.loads(bytes(body)) == request.body(SecretRequestDefaultEvidence())
            calls.append("post")

    class JobDetailObserver(_DetailObserver):
        def observe(self, request_id, *, expected_secret_id, expected_request_type="launcher"):
            assert (request_id, expected_secret_id, expected_request_type) == (71, 83, "job")
            calls.append("detail")
            return SecretRequestObservation(True, "job", "pending", "tier1", "unknown")

    collection = _Collection(calls, [
        SecretRequestCreatorSnapshot((), "7.0.0", 29),
        SecretRequestCreatorSnapshot(
            (SecretRequestCollectionRecord(71, 83, "job", 1_790_000_001),),
            "7.0.0", 29,
        ),
    ])
    monkeypatch.setattr(
        "fortipam_mcp.secret_request_create_http_transport._ssl_context",
        lambda _config: object(),
    )
    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig("https://fpa.example", "synthetic-token", 5, None),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(binding_path),
        dispatch_claim=OwnerOnlySecretRequestCreateDispatchClaim(claim_path, b"k" * 32),
        authorized_environment_ref=_ENVIRONMENT_REF,
        authorized_scope_ref=_SCOPE_REF,
        connection_factory=lambda *_args, **_kwargs: JobConnection(calls, claim_path),
        actor_inspector=_ActorInspector(),
        default_inspector=_DefaultInspector(calls),
        collection=collection,
        detail_observer=JobDetailObserver(calls),
    )

    result = ProtectedSecretRequestCreateMcpAction(
        transport, execution_enabled=True,
    ).execute(_INTENT_REF, principal)

    assert result["outcome"] == "bound"
    assert result["request_bound"] is True
    assert result["request_identifiers_returned"] is False
    assert calls == [
        "default", "collection", "post", "response-close", "connection-close",
        "collection", "detail",
    ]


class _DefaultInspector:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def inspect(self) -> SecretRequestDefaultEvidence:
        self.calls.append("default")
        return SecretRequestDefaultEvidence()


class _ActorInspector:
    def inspect(self, expected_requester: str) -> None:
        assert expected_requester == _FORTIPAM_REQUESTER


class _MismatchedActorInspector:
    def inspect(self, expected_requester: str) -> None:
        assert expected_requester == _FORTIPAM_REQUESTER
        raise RuntimeError("synthetic actor mismatch")


class _Collection:
    def __init__(
        self,
        calls: list[str],
        snapshots: list[SecretRequestCreatorSnapshot],
    ) -> None:
        self.calls = calls
        self.snapshots = snapshots

    def snapshot(self) -> SecretRequestCreatorSnapshot:
        self.calls.append("collection")
        return self.snapshots.pop(0)


class _Response:
    def __init__(self, calls: list[str], status: int = 200) -> None:
        self.calls = calls
        self.status = status

    def read(self) -> bytes:
        raise AssertionError("POST response body must not be read")

    def readinto(self, _view: memoryview) -> int:
        raise AssertionError("POST response body must not be read")

    def close(self) -> None:
        self.calls.append("response-close")


class _DetailObserver:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def observe(
        self,
        request_id: int,
        *,
        expected_secret_id: int,
        expected_request_type: str = "launcher",
    ) -> SecretRequestObservation:
        assert request_id == 71
        assert expected_secret_id == 83
        assert expected_request_type == "launcher"
        self.calls.append("detail")
        return SecretRequestObservation(
            True,
            "launcher",
            "pending",
            "tier1",
            "needed",
        )


class _Connection:
    def __init__(
        self,
        calls: list[str],
        claim_path: Path,
        *,
        response_status: int = 200,
    ) -> None:
        self.calls = calls
        self.claim_path = claim_path
        self.response = _Response(calls, response_status)
        self.body: bytearray | None = None
        self.body_matches = False

    def request(self, method, url, body, headers) -> None:
        assert self.claim_path.is_file()
        self.calls.append("post")
        self.body = body.obj
        self.body_matches = (
            method == "POST"
            and url == "/api/v2/cmdb/secret/request?with_meta=true&vdom=root"
            and headers["Content-Type"] == "application/json"
            and json.loads(bytes(body))
            == {
                "id": 0,
                "user": "synthetic-requester",
                "secret-id": 83,
                "request-type": "launcher",
                "start-after-approve": "enable",
                "start-time": "",
                "expiration-time": "",
                "duration": 30,
                "comments": "synthetic-comment",
                "timezone": "UTC",
                "field": [
                    {
                        "id": 1,
                        "q_origin_key": 1,
                        "name": "Ticket",
                        "value": "protected-field-value",
                    }
                ],
            }
        )

    def getresponse(self) -> _Response:
        return self.response

    def close(self) -> None:
        self.calls.append("connection-close")


class _FailingFinalizeClaim(OwnerOnlySecretRequestCreateDispatchClaim):
    def finalize(
        self,
        *,
        terminal_outcome: str,
        failure_stage: str,
        http_status_class: str,
        post_http_status: int,
    ) -> None:
        del terminal_outcome, failure_stage, http_status_class, post_http_status
        raise SecretRequestCreateDispatchClaimError(
            "The FortiPAM Secret-request create transport is unavailable."
        )


@pytest.mark.parametrize("stale_reads", [0, 1, 12, 39])
def test_one_shot_create_binds_unique_delta_and_terminal_replay_is_local(
    monkeypatch,
    tmp_path: Path,
    stale_reads: int,
) -> None:
    calls: list[str] = []
    existing = SecretRequestCollectionRecord(
        70, 83, "launcher", 1_790_000_000
    )
    created = SecretRequestCollectionRecord(
        71, 83, "launcher", 1_790_000_001
    )
    collection = _Collection(
        calls,
        [SecretRequestCreatorSnapshot((existing,), "7.0.0", 29)]
        + [SecretRequestCreatorSnapshot((existing,), "7.0.0", 29)] * stale_reads
        + [SecretRequestCreatorSnapshot((existing, created), "7.0.0", 29)],
    )
    monkeypatch.setattr(
        "fortipam_mcp.secret_request_create_http_transport.time.sleep",
        lambda _seconds: None,
    )
    principal = _principal()
    binding = _binding(principal)
    request = _request()
    binding_path = tmp_path / "request-create-binding.json"
    _write_binding(binding_path, binding, request)
    claim_path = tmp_path / "request-create.claim"
    connection = _Connection(calls, claim_path)
    monkeypatch.setattr(
        "fortipam_mcp.secret_request_create_http_transport._ssl_context",
        lambda _config: object(),
    )
    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example",
            "synthetic-token",
            5,
            None,
        ),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(binding_path),
        dispatch_claim=OwnerOnlySecretRequestCreateDispatchClaim(
            claim_path,
            b"k" * 32,
        ),
        authorized_environment_ref=_ENVIRONMENT_REF,
        authorized_scope_ref=_SCOPE_REF,
        connection_factory=lambda *_args, **_kwargs: connection,
        actor_inspector=_ActorInspector(),
        default_inspector=_DefaultInspector(calls),
        collection=collection,
        detail_observer=_DetailObserver(calls),
    )
    action = ProtectedSecretRequestCreateMcpAction(
        transport,
        execution_enabled=True,
    )
    public_result = action.execute(_INTENT_REF, principal)
    first = transport.create(_INTENT_REF, principal=principal)
    replay = transport.create(_INTENT_REF, principal=principal)

    assert public_result == {
        "contract": "fortipam-v4-secret-request-create-result-v1",
        "outcome": "bound",
        "request_bound": True,
        "reconciliation_required": False,
        "raw_values_returned": False,
        "request_identifiers_returned": False,
        "request_intent_returned": False,
    }
    assert first.outcome is SecretRequestCreateTransportOutcome.BOUND
    assert first.protected_record == created
    assert first.raw_values_returned is False
    assert replay is first
    assert calls == [
        "default",
        "collection",
        "post",
        "response-close",
        "connection-close",
    ] + ["collection"] * (stale_reads + 1) + ["detail"]
    assert connection.body_matches is True
    assert connection.body is not None
    assert not any(connection.body)
    claim = json.loads(claim_path.read_text())
    assert set(claim) == {
        "contract",
        "dispatch_attempted",
        "failure_stage",
        "http_status_class",
        "post_http_status",
        "intent_binding_hmac",
        "retry_allowed",
        "terminal_outcome",
    }
    assert claim["contract"] == "fortipam-v4-secret-request-create-claim-v1"
    assert claim["dispatch_attempted"] is True
    assert claim["retry_allowed"] is False
    assert claim["terminal_outcome"] == "bound"
    assert claim["failure_stage"] == "none"
    assert claim["http_status_class"] == "none"
    assert claim["post_http_status"] == 200
    assert len(claim["intent_binding_hmac"]) == 64
    assert _FORTIPAM_REQUESTER not in claim_path.read_text()
    assert "synthetic-comment" not in claim_path.read_text()
    assert "protected-field-value" not in claim_path.read_text()


def test_actor_mismatch_stops_before_claim_or_device_reads(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    principal = _principal()
    binding_path = tmp_path / "request-create-binding.json"
    _write_binding(binding_path, _binding(principal), _request())
    claim_path = tmp_path / "request-create.claim"
    calls: list[str] = []
    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example", "synthetic-token", 5, None,
        ),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(binding_path),
        dispatch_claim=OwnerOnlySecretRequestCreateDispatchClaim(
            claim_path, b"k" * 32,
        ),
        authorized_environment_ref=_ENVIRONMENT_REF,
        authorized_scope_ref=_SCOPE_REF,
        actor_inspector=_MismatchedActorInspector(),
        connection_factory=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("POST connection must not be created")
        ),
        default_inspector=_DefaultInspector(calls),
        collection=_Collection(calls, []),
        detail_observer=_DetailObserver(calls),
    )

    with caplog.at_level(
        logging.WARNING,
        logger="fortipam_mcp.secret_request_create_http_transport",
    ):
        result = transport.create(_INTENT_REF, principal=principal)

    assert result.outcome is SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED
    assert result.protected_record is None
    assert calls == []
    assert not claim_path.exists()
    assert caplog.messages == [
        "Secret request create failed: stage=api_actor_preflight http_status_class=none"
    ]


def test_existing_durable_claim_blocks_restart_before_post(
    monkeypatch,
    tmp_path: Path,
) -> None:
    principal = _principal()
    binding = _binding(principal)
    binding_path = tmp_path / "request-create-binding.json"
    _write_binding(binding_path, binding, _request())
    claim_path = tmp_path / "request-create.claim"
    claim = OwnerOnlySecretRequestCreateDispatchClaim(claim_path, b"k" * 32)
    body = bytearray(
        json.dumps(_request().body(SecretRequestDefaultEvidence())).encode()
    )
    body_view = memoryview(body).toreadonly()
    try:
        claim.claim(body_view, binding=binding)
    finally:
        body_view.release()
        for index in range(len(body)):
            body[index] = 0

    calls: list[str] = []
    monkeypatch.setattr(
        "fortipam_mcp.secret_request_create_http_transport._ssl_context",
        lambda _config: object(),
    )
    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example",
            "synthetic-token",
            5,
            None,
        ),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(binding_path),
        dispatch_claim=claim,
        authorized_environment_ref=_ENVIRONMENT_REF,
        authorized_scope_ref=_SCOPE_REF,
        connection_factory=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("existing claim must prevent connection creation")
        ),
        actor_inspector=_ActorInspector(),
        default_inspector=_DefaultInspector(calls),
        collection=_Collection(calls, [SecretRequestCreatorSnapshot(())]),
        detail_observer=_DetailObserver(calls),
    )

    result = transport.create(_INTENT_REF, principal=principal)

    assert result.outcome is SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED
    assert result.protected_record is None
    assert calls == []


def test_non_success_post_logs_only_stage_and_status_class(
    monkeypatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[str] = []
    principal = _principal()
    binding_path = tmp_path / "request-create-binding.json"
    _write_binding(binding_path, _binding(principal), _request())
    claim_path = tmp_path / "request-create.claim"
    connection = _Connection(calls, claim_path, response_status=403)
    monkeypatch.setattr(
        "fortipam_mcp.secret_request_create_http_transport._ssl_context",
        lambda _config: object(),
    )
    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example",
            "synthetic-token",
            5,
            None,
        ),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(binding_path),
        dispatch_claim=OwnerOnlySecretRequestCreateDispatchClaim(
            claim_path,
            b"k" * 32,
        ),
        authorized_environment_ref=_ENVIRONMENT_REF,
        authorized_scope_ref=_SCOPE_REF,
        connection_factory=lambda *_args, **_kwargs: connection,
        actor_inspector=_ActorInspector(),
        default_inspector=_DefaultInspector(calls),
        collection=_Collection(calls, [SecretRequestCreatorSnapshot(())]),
        detail_observer=_DetailObserver(calls),
    )

    with caplog.at_level(
        logging.WARNING,
        logger="fortipam_mcp.secret_request_create_http_transport",
    ):
        first = transport.create(_INTENT_REF, principal=principal)
        replay = transport.create(_INTENT_REF, principal=principal)

    assert (
        first.outcome
        is SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED
    )
    assert replay is first
    assert claim_path.is_file()
    assert calls.count("post") == 1
    assert calls == [
        "default",
        "collection",
        "post",
        "response-close",
        "connection-close",
    ]
    assert caplog.messages == [
        "Secret request create failed: stage=post http_status_class=http_4xx"
    ]
    claim = json.loads(claim_path.read_text())
    assert claim["terminal_outcome"] == "reconciliation_required"
    assert claim["failure_stage"] == "post"
    assert claim["http_status_class"] == "http_4xx"
    assert claim["post_http_status"] == 403
    assert claim_path.stat().st_mode & 0o777 == 0o600
    log_text = caplog.text
    for protected_value in (
        "synthetic-token",
        _FORTIPAM_REQUESTER,
        "synthetic-comment",
        "protected-field-value",
    ):
        assert protected_value not in log_text
        assert protected_value not in claim_path.read_text()


@pytest.mark.parametrize("stale_after_post", [False, True])
def test_post_dispatch_collection_failure_is_persisted_without_values(
    monkeypatch,
    tmp_path: Path,
    stale_after_post: bool,
) -> None:
    calls: list[str] = []
    principal = _principal()
    binding_path = tmp_path / "request-create-binding.json"
    _write_binding(binding_path, _binding(principal), _request())
    claim_path = tmp_path / "request-create.claim"
    connection = _Connection(calls, claim_path)
    monkeypatch.setattr(
        "fortipam_mcp.secret_request_create_http_transport._ssl_context",
        lambda _config: object(),
    )
    monkeypatch.setattr(
        "fortipam_mcp.secret_request_create_http_transport.time.sleep",
        lambda _seconds: None,
    )
    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example",
            "synthetic-token",
            5,
            None,
        ),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(binding_path),
        dispatch_claim=OwnerOnlySecretRequestCreateDispatchClaim(
            claim_path,
            b"k" * 32,
        ),
        authorized_environment_ref=_ENVIRONMENT_REF,
        authorized_scope_ref=_SCOPE_REF,
        connection_factory=lambda *_args, **_kwargs: connection,
        actor_inspector=_ActorInspector(),
        default_inspector=_DefaultInspector(calls),
        collection=_Collection(
            calls,
            [SecretRequestCreatorSnapshot(())] * (41 if stale_after_post else 1),
        ),
        detail_observer=_DetailObserver(calls),
    )

    result = transport.create(_INTENT_REF, principal=principal)

    assert result.outcome is SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED
    claim = json.loads(claim_path.read_text())
    assert set(claim) == {
        "contract",
        "dispatch_attempted",
        "failure_stage",
        "http_status_class",
        "post_http_status",
        "intent_binding_hmac",
        "retry_allowed",
        "terminal_outcome",
    }
    assert claim["terminal_outcome"] == "reconciliation_required"
    assert claim["failure_stage"] == (
        "delta_bind" if stale_after_post else "creator_snapshot_after"
    )
    assert claim["http_status_class"] == "none"
    assert claim["post_http_status"] == 200
    assert claim["dispatch_attempted"] is True
    assert claim["retry_allowed"] is False
    assert calls.count("post") == 1
    assert calls.count("collection") == (41 if stale_after_post else 2)
    assert claim_path.stat().st_mode & 0o777 == 0o600
    assert tmp_path.stat().st_mode & 0o777 == 0o700
    serialized = claim_path.read_text()
    for protected_value in (
        "synthetic-token",
        _FORTIPAM_REQUESTER,
        "synthetic-comment",
        "protected-field-value",
    ):
        assert protected_value not in serialized

    restarted_claim = OwnerOnlySecretRequestCreateDispatchClaim(
        claim_path,
        b"k" * 32,
    )
    body = bytearray(
        json.dumps(_request().body(SecretRequestDefaultEvidence())).encode()
    )
    body_view = memoryview(body).toreadonly()
    try:
        with pytest.raises(
            SecretRequestCreateDispatchClaimError,
            match="unavailable",
        ):
            restarted_claim.claim(body_view, binding=_binding(principal))
    finally:
        body_view.release()
        for index in range(len(body)):
            body[index] = 0


def test_terminal_persistence_failure_downgrades_bound_result(
    monkeypatch,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    calls: list[str] = []
    created = SecretRequestCollectionRecord(
        71, 83, "launcher", "2026-09-06 12:34:56"
    )
    principal = _principal()
    binding_path = tmp_path / "request-create-binding.json"
    _write_binding(binding_path, _binding(principal), _request())
    claim_path = tmp_path / "request-create.claim"
    connection = _Connection(calls, claim_path)
    monkeypatch.setattr(
        "fortipam_mcp.secret_request_create_http_transport._ssl_context",
        lambda _config: object(),
    )
    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example",
            "synthetic-token",
            5,
            None,
        ),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(binding_path),
        dispatch_claim=_FailingFinalizeClaim(claim_path, b"k" * 32),
        authorized_environment_ref=_ENVIRONMENT_REF,
        authorized_scope_ref=_SCOPE_REF,
        connection_factory=lambda *_args, **_kwargs: connection,
        actor_inspector=_ActorInspector(),
        default_inspector=_DefaultInspector(calls),
        collection=_Collection(
            calls,
            [
                SecretRequestCreatorSnapshot(()),
                SecretRequestCreatorSnapshot((created,)),
            ],
        ),
        detail_observer=_DetailObserver(calls),
    )

    with caplog.at_level(
        logging.WARNING,
        logger="fortipam_mcp.secret_request_create_http_transport",
    ):
        result = transport.create(_INTENT_REF, principal=principal)

    assert result.outcome is SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED
    assert result.protected_record is None
    assert caplog.messages == [
        "Secret request create terminal diagnostic persistence failed"
    ]
    claim = json.loads(claim_path.read_text())
    assert set(claim) == {
        "contract",
        "dispatch_attempted",
        "intent_binding_hmac",
        "retry_allowed",
    }


def test_same_requester_binding_rejects_identity_or_scope_mismatch_before_reads(
    tmp_path: Path,
) -> None:
    principal = _principal()
    binding = _binding(principal)
    binding_path = tmp_path / "request-create-binding.json"
    _write_binding(binding_path, binding, _request())

    for candidate_principal, authorized_scope in (
        (_principal("different-subject-ref01"), _SCOPE_REF),
        (principal, "different-scope-reference01"),
    ):
        calls: list[str] = []
        transport = FortiPamSecretRequestCreateHttpTransport(
            SecretMetadataHttpTransportConfig(
                "https://fpa.example",
                "synthetic-token",
                5,
                None,
            ),
            binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(
                binding_path
            ),
            dispatch_claim=OwnerOnlySecretRequestCreateDispatchClaim(
                tmp_path
                / f"request-create-{len(calls)}-{authorized_scope}.claim",
                b"k" * 32,
            ),
            authorized_environment_ref=_ENVIRONMENT_REF,
            authorized_scope_ref=authorized_scope,
            actor_inspector=_ActorInspector(),
            default_inspector=_DefaultInspector(calls),
            collection=_Collection(calls, []),
            detail_observer=_DetailObserver(calls),
        )
        result = transport.create(_INTENT_REF, principal=candidate_principal)

        assert (
            result.outcome
            is SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED
        )
        assert calls == []


def test_same_requester_binding_must_be_owner_only_before_reads(
    tmp_path: Path,
) -> None:
    principal = _principal()
    binding_path = tmp_path / "request-create-binding.json"
    _write_binding(binding_path, _binding(principal), _request())
    binding_path.chmod(0o644)
    calls: list[str] = []
    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example",
            "synthetic-token",
            5,
            None,
        ),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(binding_path),
        dispatch_claim=OwnerOnlySecretRequestCreateDispatchClaim(
            tmp_path / "request-create.claim",
            b"k" * 32,
        ),
        authorized_environment_ref=_ENVIRONMENT_REF,
        authorized_scope_ref=_SCOPE_REF,
        actor_inspector=_ActorInspector(),
        default_inspector=_DefaultInspector(calls),
        collection=_Collection(calls, []),
        detail_observer=_DetailObserver(calls),
    )

    result = transport.create(_INTENT_REF, principal=principal)

    assert result.outcome is SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED
    assert calls == []


def test_expired_intent_is_rejected_before_reads(tmp_path: Path) -> None:
    principal = _principal()
    binding = _binding(principal)
    binding_path = tmp_path / "request-create-binding.json"
    _write_binding(binding_path, binding, _request())
    calls: list[str] = []
    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example",
            "synthetic-token",
            5,
            None,
        ),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(
            binding_path,
            clock=lambda: binding.expires_at,
        ),
        dispatch_claim=OwnerOnlySecretRequestCreateDispatchClaim(
            tmp_path / "request-create.claim",
            b"k" * 32,
        ),
        authorized_environment_ref=_ENVIRONMENT_REF,
        authorized_scope_ref=_SCOPE_REF,
        actor_inspector=_ActorInspector(),
        default_inspector=_DefaultInspector(calls),
        collection=_Collection(calls, []),
        detail_observer=_DetailObserver(calls),
    )

    result = transport.create(_INTENT_REF, principal=principal)

    assert result.outcome is SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED
    assert calls == []


def test_mcp_candidate_is_default_off_before_resolving_intent(tmp_path: Path) -> None:
    calls: list[str] = []
    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig(
            "https://fpa.example",
            "synthetic-token",
            5,
            None,
        ),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(
            tmp_path / "missing-intent.json"
        ),
        dispatch_claim=OwnerOnlySecretRequestCreateDispatchClaim(
            tmp_path / "request-create.claim",
            b"k" * 32,
        ),
        authorized_environment_ref=_ENVIRONMENT_REF,
        authorized_scope_ref=_SCOPE_REF,
        actor_inspector=_ActorInspector(),
        default_inspector=_DefaultInspector(calls),
        collection=_Collection(calls, []),
        detail_observer=_DetailObserver(calls),
    )

    with pytest.raises(RuntimeError):
        ProtectedSecretRequestCreateMcpAction(transport).execute(
            _INTENT_REF,
            _principal(),
        )

    assert calls == []


@pytest.mark.parametrize("cleanup", ["verified", "unverified", "error"])
def test_requester_logout_precedes_durable_success_and_is_not_replayed(
    tmp_path: Path, monkeypatch, cleanup: str,
) -> None:
    calls: list[str] = []
    principal = _principal()
    binding_path = tmp_path / "binding.json"
    _write_binding(binding_path, _binding(principal), _request())
    claim_path = tmp_path / "dispatch.claim"
    created = SecretRequestCollectionRecord(71, 83, "launcher", 1_790_000_001)
    collection = _Collection(calls, [
        SecretRequestCreatorSnapshot((), "7.0.0", 29),
        SecretRequestCreatorSnapshot((created,), "7.0.0", 29),
    ])
    monkeypatch.setattr(
        "fortipam_mcp.secret_request_create_http_transport._ssl_context",
        lambda _config: object(),
    )
    connection = _Connection(calls, claim_path)

    def finalize_session() -> bool:
        calls.append("logout")
        assert "detail" in calls
        assert json.loads(claim_path.read_text()).get("terminal_outcome") != "bound"
        if cleanup == "error":
            raise RuntimeError("synthetic private error must not escape")
        return cleanup == "verified"

    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig("https://fpa.example", "synthetic-token", 5, None),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(binding_path),
        dispatch_claim=OwnerOnlySecretRequestCreateDispatchClaim(claim_path, b"k" * 32),
        authorized_environment_ref=_ENVIRONMENT_REF,
        authorized_scope_ref=_SCOPE_REF,
        connection_factory=lambda *_args, **_kwargs: connection,
        actor_inspector=_ActorInspector(), default_inspector=_DefaultInspector(calls),
        collection=collection, detail_observer=_DetailObserver(calls),
        session_finalizer=finalize_session,
    )
    result = transport.create(_INTENT_REF, principal=principal)
    assert transport.create(_INTENT_REF, principal=principal) is result
    assert calls.count("post") == calls.count("logout") == 1
    claim = json.loads(claim_path.read_text())
    expected = "bound" if cleanup == "verified" else "reconciliation_required"
    assert result.outcome.value == claim["terminal_outcome"] == expected
    assert claim["failure_stage"] == ("none" if cleanup == "verified" else "requester_session_cleanup")
    assert result.protected_record == (created if cleanup == "verified" else None)


@pytest.mark.parametrize("claim_kind", ["file", "dangling_symlink"])
def test_fresh_transport_rejects_retained_claim_before_actor_login(tmp_path, claim_kind):
    principal = _principal()
    binding_path = tmp_path / "binding.json"
    _write_binding(binding_path, _binding(principal), _request())
    claim_path = tmp_path / "dispatch.claim"
    if claim_kind == "file":
        claim_path.write_bytes(b"retained non-replayable evidence")
        claim_path.chmod(0o600)
    else:
        claim_path.symlink_to(tmp_path / "absent")

    class ForbiddenActor:
        def inspect(self, expected_requester):
            pytest.fail("consumed operation accessed credentials or network")

    transport = FortiPamSecretRequestCreateHttpTransport(
        SecretMetadataHttpTransportConfig("https://fpa.example", "synthetic-token", 5, None),
        binding_resolver=OwnerOnlySecretRequestCreateBindingResolver(binding_path),
        dispatch_claim=OwnerOnlySecretRequestCreateDispatchClaim(claim_path, b"k" * 32),
        authorized_environment_ref=_ENVIRONMENT_REF,
        authorized_scope_ref=_SCOPE_REF, actor_inspector=ForbiddenActor(),
    )
    result = transport.create(_INTENT_REF, principal=principal)
    assert result.outcome is SecretRequestCreateTransportOutcome.RECONCILIATION_REQUIRED
    assert result.protected_record is None
    if claim_kind == "file":
        assert claim_path.read_bytes() == b"retained non-replayable evidence"
    else:
        assert claim_path.is_symlink()
