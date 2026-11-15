from __future__ import annotations

from collections.abc import Iterator
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

import pytest
from mcp.server.auth.provider import AccessToken
from starlette.applications import Starlette
from starlette.testclient import TestClient

from fortipam_mcp.local_oauth import (
    LocalOAuthProvider,
    LocalOAuthSettings,
    hash_local_password,
)
from fortipam_mcp.onboarding_execution_mcp_action import (
    ProtectedAccessDomainOnboardingMcpAction,
    ProtectedSecretOnboardingMcpAction,
)
from fortipam_mcp.approval_and_observe_execution_mcp_action import (
    ProtectedApprovalAndObserveMcpAction,
)
from fortipam_mcp.approver_checkpoint_sidecar import (
    UnixApproverCheckpointClient,
    UnixApproverCheckpointClientSettings,
)
from fortipam_mcp.approver_authority_sidecar import (
    UnixApproverAuthorizationClient,
    UnixApproverAuthorizationClientSettings,
)
from fortipam_mcp.approval_receipt_sidecar import (
    UnixApprovalReceiptAuthenticator,
    UnixApprovalReceiptAuthenticatorSettings,
)
from fortipam_mcp.reference_authority_sidecar import (
    UnixReferenceAuthorityClient,
)
from fortipam_mcp.reference_checkpoint_sidecar import (
    UnixReferenceCheckpointClient,
    UnixReferenceCheckpointClientSettings,
)
from fortipam_mcp.scheme_draft_authority_sidecar import (
    UnixSchemeDraftAuthorityClient,
)
from fortipam_mcp.scheme_draft_checkpoint_sidecar import (
    UnixSchemeDraftCheckpointClient,
    UnixSchemeDraftCheckpointClientSettings,
)
from fortipam_mcp.secret_create_readiness_sidecar import (
    SecretCreateReadinessSidecarError,
    UnixSecretCreateReadinessProxyClient,
    UnixSecretCreateReadinessProxyClientSettings,
)
from fortipam_mcp.approver_delegation_bootstrap import (
    ApproverDelegationBootstrapSettings,
    bootstrap_approver_delegation,
)
from fortipam_mcp.v4_confirmation_http import (
    V4ConfirmationHttpError,
    V4ConfirmationSettings,
)
from fortipam_mcp.v4_plan_runtime import (
    V4_APPROVAL_SCOPE,
    V4PlanningAuthorizationSettings,
    V4PlanningPrincipal,
    approver_from_access_token,
    planning_principal_from_access_token,
)
from fortipam_mcp.v4_runtime_host import (
    V4PersistentPlanningCheckpointSettings,
    V4PersistentReferenceAuthoritySettings,
    V4PersistentSchemeDraftAuthoritySettings,
    V4PlanHostComponents,
    V4SyntheticHostSettings,
    V4UnixReferenceAuthoritySettings,
    V4UnixSecretCreateRuntimeSettings,
    V4UnixSchemeDraftAuthoritySettings,
    V4_PERSISTENT_REFERENCE_AUTHORITY_REF,
    V4_PERSISTENT_SCHEME_DRAFT_AUTHORITY_REF,
    V4_SYNTHETIC_SCHEME_REF,
    V4RuntimeHostError,
    _planning_registry,
    approval_and_observe_v4_plan_host_factory,
    issue_synthetic_reference_grants,
    issue_synthetic_scheme_draft,
    synthetic_host_settings_from_environment,
    synthetic_v4_plan_host_factory,
)
from v4_planning import (
    ApprovalReceiptAuthenticator,
    ApproverAuthorityCheckpointError,
    ApproverAuthorityStoreTail,
    AuthenticatedApprover,
    AuthenticatedRequester,
    MonotonicCheckpointError,
    PersistentApproverAuthorizationAuthority,
    PersistentPlanningCheckpointAuthority,
    PersistentReferenceAuthority,
    PersistentSchemeDraftAuthority,
    PlanningStoreTail,
    PlanningDenied,
)
from v4_planning.persistence import PersistentProtectedPlanningStore


NOW = 1_950_000_000
PASSWORD = "correct-horse-battery-staple"
APPROVER_CHECKPOINT_AUTHORITY_REF = "v4-synthetic-approver-checkpoint-sidecar"
APPROVER_AUTHORITY_REF = "v4-synthetic-approver-authority"


def test_synthetic_planning_registry_keeps_identity_lifecycle_fake_only() -> None:
    registry = _planning_registry(source_backed=False)
    scheme = next(
        item
        for item in registry["schemes"]  # type: ignore[index]
        if item["id"] == "IdentityLifecycleScheme"
    )
    blueprint = next(
        item
        for item in registry["blueprints"]  # type: ignore[index]
        if item["id"] == "FPA-BP-015"
    )
    action = next(
        item
        for item in registry["actions"]  # type: ignore[index]
        if item["id"] == "synthetic-identity-lifecycle-action"
    )

    evidence = scheme["implementation_evidence"]
    assert scheme["blueprint_refs"] == ["FPA-BP-015"]
    assert evidence["evidence_kind"] == "fake_only_contract"
    assert evidence["profile_blueprint_refs"] == ["FPA-BP-015"]
    assert evidence["device_access"] is False
    assert "projection_profile" not in evidence
    assert blueprint["action_refs"] == ["synthetic-identity-lifecycle-action"]
    assert action["risk_tier"] == "medium"
    assert action["executable"] is False


class MutableClock:
    def __init__(self, value: int) -> None:
        self.value = value

    def __call__(self) -> int:
        return self.value


def test_host_components_assemble_source_bound_onboarding_execution_actions() -> None:
    plan_services = object()
    access_source = object()
    secret_source = object()
    approval_source = object()
    acl_action = object()
    folder_action = object()
    group_acl_action = object()
    runner_factory = object()
    target_action = object()
    components = V4PlanHostComponents(  # type: ignore[arg-type]
        plan_services=plan_services,
        confirmation_service=object(),
        access_domain_projection_source=access_source,
        approval_and_observe_projection_source=approval_source,
        secret_onboarding_projection_source=secret_source,
    )

    access_action, secret_action = components.bind_onboarding_execution_mcp_actions(
        acl_action,
        runner_factory,
        folder_action=folder_action,
        group_acl_action=group_acl_action,
        target_action=target_action,
        authorized_environment_ref="onboarding-environment-ref01",
        authorized_scope_ref="onboarding-scope-ref001",
        authorized_secret_environment_ref="secret-environment-ref0001",
        authorized_secret_scope_ref="secret-scope-ref00000001",
        execution_enabled=True,
    )

    assert isinstance(access_action, ProtectedAccessDomainOnboardingMcpAction)
    assert isinstance(secret_action, ProtectedSecretOnboardingMcpAction)
    for action in (access_action, secret_action):
        assert action._plan_services is plan_services
        assert action._coordinator._comparisons is plan_services
        assert action._execution_enabled is True
    assert access_action._authorized_environment_ref == "onboarding-environment-ref01"
    assert access_action._authorized_scope_ref == "onboarding-scope-ref001"
    assert secret_action._authorized_environment_ref == "secret-environment-ref0001"
    assert secret_action._authorized_scope_ref == "secret-scope-ref00000001"
    assert access_action._coordinator._resolver._plan_services is plan_services
    assert access_action._coordinator._resolver._projection_source is access_source
    assert access_action._coordinator._resolver._acl_action is acl_action
    assert access_action._coordinator._resolver._folder_action is folder_action
    assert access_action._coordinator._resolver._group_acl_action is group_acl_action
    secret_router = secret_action._coordinator._resolver
    assert secret_router._plan_services is plan_services
    assert secret_router._secret_only._projection_source is secret_source
    assert secret_router._secret_only._runner_factory is runner_factory
    assert secret_router._secret_only._target_action is target_action
    assert secret_router._combined._access_domain._projection_source is access_source
    assert secret_router._combined._access_domain._group_acl_action is group_acl_action

    combined_action = (
        components.bind_existing_domain_linux_onboarding_execution_mcp_action(
            acl_action,
            runner_factory,
            group_acl_action=group_acl_action,
            target_action=target_action,
            authorized_environment_ref="onboarding-environment-ref01",
            authorized_scope_ref="combined-onboarding-scope01",
        )
    )
    combined_resolver = combined_action._coordinator._resolver
    assert isinstance(combined_action, ProtectedSecretOnboardingMcpAction)
    assert combined_resolver._plan_services is plan_services
    assert combined_resolver._access_domain._projection_source is access_source
    assert combined_resolver._access_domain._group_acl_action is group_acl_action
    assert combined_resolver._secret_onboarding._projection_source is secret_source
    assert combined_resolver._secret_onboarding._runner_factory is runner_factory
    assert combined_resolver._secret_onboarding._target_action is target_action
    assert combined_action._authorized_scope_ref == "combined-onboarding-scope01"

    class ApprovalRunnerFactory:
        def bind(self, *_args: object, **_kwargs: object) -> object:
            return object()

    approval_action = components.bind_approval_and_observe_execution_mcp_action(
        ApprovalRunnerFactory(),  # type: ignore[arg-type]
        authorized_environment_ref="approval-environment-ref01",
        authorized_scope_ref="approval-scope-reference01",
    )

    assert isinstance(approval_action, ProtectedApprovalAndObserveMcpAction)
    assert approval_action._plan_services is plan_services
    assert approval_action._coordinator._comparisons is plan_services
    assert approval_action._coordinator._resolver._projection_source is approval_source
    assert approval_action._execution_enabled is False


def test_source_backed_projection_host_binding_must_be_complete(
    tmp_path: Path,
) -> None:
    settings = V4SyntheticHostSettings(
        tmp_path / "planning.sqlite3",
        tmp_path / "planning.hmac",
    )
    with pytest.raises(V4RuntimeHostError, match="binding must be complete"):
        synthetic_v4_plan_host_factory(
            settings,
            projection_contract_resolver=lambda _scheme, _object: None,  # type: ignore[arg-type,return-value]
        )
    with pytest.raises(V4RuntimeHostError, match="binding must be complete"):
        synthetic_v4_plan_host_factory(
            settings,
            projection_provider_factory=lambda _engine: None,  # type: ignore[arg-type,return-value]
        )


def test_approval_and_observe_factory_requires_both_authorities(
    tmp_path: Path,
) -> None:
    class SecretTransport:
        def inspect_approval_projection(self, *_args: object) -> object:
            return object()

    class ApprovalProfileTransport:
        def readback(self, *_args: object) -> object:
            return object()

    class BindingResolver:
        def resolve(self, *_args: object) -> object:
            return object()

    base = V4SyntheticHostSettings(
        tmp_path / "planning.sqlite3",
        tmp_path / "planning.hmac",
        V4PersistentReferenceAuthoritySettings(
            tmp_path / "reference.sqlite3",
            tmp_path / "reference.hmac",
        ),
    )
    dependencies = {
        "secret_transport": SecretTransport(),
        "approval_profile_transport": ApprovalProfileTransport(),
        "binding_resolver": BindingResolver(),
    }

    with pytest.raises(V4RuntimeHostError, match="Scheme Draft Authority"):
        approval_and_observe_v4_plan_host_factory(base, **dependencies)  # type: ignore[arg-type]

    configured = V4SyntheticHostSettings(
        base.planning_database_path,
        base.planning_hmac_key_path,
        base.reference_authority,
        V4PersistentSchemeDraftAuthoritySettings(
            tmp_path / "draft.sqlite3",
            tmp_path / "draft.hmac",
        ),
    )

    assert callable(
        approval_and_observe_v4_plan_host_factory(  # type: ignore[arg-type]
            configured,
            **dependencies,
        )
    )


def test_source_backed_host_environment_requires_binding_and_reference_authority(
    tmp_path: Path,
) -> None:
    environment = {
        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": "source-backed-access-domain",
        "FORTIPAM_MCP_V4_PLAN_STORE_DB": str(tmp_path / "planning.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_STORE_HMAC_KEY_FILE": str(tmp_path / "planning.hmac"),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_DB": str(
            tmp_path / "reference.sqlite3"
        ),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_HMAC_KEY_FILE": str(
            tmp_path / "reference.hmac"
        ),
        "FORTIPAM_MCP_V4_PLAN_ACCESS_DOMAIN_BINDING_FILE": str(
            tmp_path / "access-domain-binding.json"
        ),
    }

    settings = synthetic_host_settings_from_environment(environment)

    assert settings is not None
    assert settings.host_mode == "source-backed-access-domain"
    assert settings.access_domain_binding_path == (
        tmp_path / "access-domain-binding.json"
    )
    without_binding = dict(environment)
    del without_binding["FORTIPAM_MCP_V4_PLAN_ACCESS_DOMAIN_BINDING_FILE"]
    with pytest.raises(V4RuntimeHostError, match="requires one binding file"):
        synthetic_host_settings_from_environment(without_binding)

    without_reference = {
        key: value
        for key, value in environment.items()
        if "REFERENCE_AUTHORITY" not in key
    }
    with pytest.raises(V4RuntimeHostError, match="requires a Reference Authority"):
        synthetic_host_settings_from_environment(without_reference)


def test_secret_source_host_environment_requires_draft_authority_and_binding(
    tmp_path: Path,
) -> None:
    environment = {
        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": "source-backed-secret-onboarding",
        "FORTIPAM_MCP_V4_PLAN_STORE_DB": str(tmp_path / "planning.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_STORE_HMAC_KEY_FILE": str(tmp_path / "planning.hmac"),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_DB": str(
            tmp_path / "reference.sqlite3"
        ),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_HMAC_KEY_FILE": str(
            tmp_path / "reference.hmac"
        ),
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_DB": str(
            tmp_path / "draft.sqlite3"
        ),
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE": str(
            tmp_path / "draft.hmac"
        ),
        "FORTIPAM_MCP_V4_PLAN_SECRET_ONBOARDING_BINDING_FILE": str(
            tmp_path / "secret-binding.json"
        ),
    }

    settings = synthetic_host_settings_from_environment(environment)

    assert settings is not None
    assert settings.host_mode == "source-backed-secret-onboarding"
    assert settings.secret_onboarding_binding_path == (
        tmp_path / "secret-binding.json"
    )
    without_draft = {
        key: value
        for key, value in environment.items()
        if "SCHEME_DRAFT_AUTHORITY" not in key
    }
    with pytest.raises(V4RuntimeHostError, match="requires a Scheme Draft Authority"):
        synthetic_host_settings_from_environment(without_draft)
    without_binding = dict(environment)
    del without_binding["FORTIPAM_MCP_V4_PLAN_SECRET_ONBOARDING_BINDING_FILE"]
    with pytest.raises(V4RuntimeHostError, match="requires one binding file"):
        synthetic_host_settings_from_environment(without_binding)

    combined = {
        **environment,
        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": "source-backed-onboarding",
        "FORTIPAM_MCP_V4_PLAN_ACCESS_DOMAIN_BINDING_FILE": str(
            tmp_path / "access-binding.json"
        ),
    }
    combined_settings = synthetic_host_settings_from_environment(combined)
    assert combined_settings is not None
    assert combined_settings.host_mode == "source-backed-onboarding"
    assert combined_settings.access_domain_binding_path == (
        tmp_path / "access-binding.json"
    )
    assert combined_settings.secret_onboarding_binding_path == (
        tmp_path / "secret-binding.json"
    )


def test_approval_source_host_environment_requires_draft_authority_and_binding(
    tmp_path: Path,
) -> None:
    environment = {
        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": "source-backed-approval-and-observe",
        "FORTIPAM_MCP_V4_PLAN_STORE_DB": str(tmp_path / "planning.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_STORE_HMAC_KEY_FILE": str(tmp_path / "planning.hmac"),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_DB": str(
            tmp_path / "reference.sqlite3"
        ),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_HMAC_KEY_FILE": str(
            tmp_path / "reference.hmac"
        ),
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_DB": str(
            tmp_path / "draft.sqlite3"
        ),
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE": str(
            tmp_path / "draft.hmac"
        ),
        "FORTIPAM_MCP_V4_PLAN_APPROVAL_AND_OBSERVE_BINDING_FILE": str(
            tmp_path / "approval-binding.json"
        ),
        "FORTIPAM_MCP_V4_PLAN_SECRET_REQUEST_OBSERVATION_BINDING_FILE": str(
            tmp_path / "request-observation.json"
        ),
    }

    settings = synthetic_host_settings_from_environment(environment)

    assert settings is not None
    assert settings.host_mode == "source-backed-approval-and-observe"
    assert settings.approval_and_observe_binding_path == (
        tmp_path / "approval-binding.json"
    )
    assert settings.access_domain_binding_path is None
    assert settings.secret_onboarding_binding_path is None
    assert settings.secret_request_observation_binding_path == (
        tmp_path / "request-observation.json"
    )

    without_draft = {
        key: value
        for key, value in environment.items()
        if "SCHEME_DRAFT_AUTHORITY" not in key
    }
    with pytest.raises(V4RuntimeHostError, match="requires a Scheme Draft Authority"):
        synthetic_host_settings_from_environment(without_draft)

    without_binding = dict(environment)
    del without_binding[
        "FORTIPAM_MCP_V4_PLAN_APPROVAL_AND_OBSERVE_BINDING_FILE"
    ]
    with pytest.raises(V4RuntimeHostError, match="approval host requires one binding"):
        synthetic_host_settings_from_environment(without_binding)


@pytest.fixture
def approver_checkpoint_sidecar(
    tmp_path: Path,
) -> Iterator[tuple[UnixApproverCheckpointClient, Path]]:
    state = tmp_path / "approver-checkpoint-sidecar"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    key_path = _owner_file(state / "checkpoint.hmac", b"k" * 32)
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    socket_dir = Path(tempfile.mkdtemp(prefix="fah-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    socket_path = socket_dir / "checkpoint.sock"
    environment = {
        **os.environ,
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_DATABASE": str(
            state / "checkpoint.sqlite3"
        ),
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_HMAC_KEY_FILE": str(key_path),
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_AUTHORITY_REF": (
            APPROVER_CHECKPOINT_AUTHORITY_REF
        ),
        "FORTIPAM_MCP_V4_APPROVER_CHECKPOINT_SOCKET": str(socket_path),
        "PYTHONPATH": "src:.",
    }
    process = subprocess.Popen(
        (sys.executable, "-m", "fortipam_mcp.approver_checkpoint_sidecar"),
        cwd=Path(__file__).resolve().parents[1],
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and not socket_path.exists():
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr is not None else b""
            raise AssertionError(f"Approver sidecar stopped before ready: {stderr!r}")
        time.sleep(0.02)
    if not socket_path.exists():
        process.terminate()
        process.wait(timeout=5.0)
        raise AssertionError("Approver sidecar did not create its Unix socket")
    yield (
        UnixApproverCheckpointClient(
            UnixApproverCheckpointClientSettings(
                socket_path,
                APPROVER_CHECKPOINT_AUTHORITY_REF,
            )
        ),
        socket_path,
    )
    process.terminate()
    try:
        process.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5.0)
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
    socket_dir.rmdir()


class _ApproverAuthoritySidecarFactory:
    def __init__(self, socket_dir: Path) -> None:
        self._socket_dir = socket_dir
        self.socket_path = socket_dir / "authority.sock"
        self._process: subprocess.Popen[bytes] | None = None

    def start(
        self,
        *,
        database_path: Path,
        hmac_key_path: Path,
        checkpoint_socket_path: Path,
        checkpoint_store_ref: str,
    ) -> UnixApproverAuthorizationClient:
        if self._process is not None:
            raise AssertionError("Approver Authority sidecar is already running")
        environment = {
            **os.environ,
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_DATABASE": str(database_path),
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_HMAC_KEY_FILE": str(
                hmac_key_path
            ),
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_REF": APPROVER_AUTHORITY_REF,
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_CHECKPOINT_SOCKET": str(
                checkpoint_socket_path
            ),
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_CHECKPOINT_REF": (
                APPROVER_CHECKPOINT_AUTHORITY_REF
            ),
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_CHECKPOINT_STORE_REF": (
                checkpoint_store_ref
            ),
            "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_SOCKET": str(self.socket_path),
            "PYTHONPATH": "src:.",
        }
        process = subprocess.Popen(
            (sys.executable, "-m", "fortipam_mcp.approver_authority_sidecar"),
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not self.socket_path.exists():
            if process.poll() is not None:
                stderr = process.stderr.read() if process.stderr is not None else b""
                raise AssertionError(
                    f"Approver Authority sidecar stopped before ready: {stderr!r}"
                )
            time.sleep(0.02)
        if not self.socket_path.exists():
            process.terminate()
            process.wait(timeout=5.0)
            raise AssertionError("Approver Authority sidecar did not create its socket")
        self._process = process
        client = UnixApproverAuthorizationClient(
            UnixApproverAuthorizationClientSettings(
                self.socket_path,
                APPROVER_AUTHORITY_REF,
            )
        )
        client.verify_ready()
        return client

    def stop(self) -> None:
        process = self._process
        if process is None:
            return
        process.terminate()
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5.0)
        self._process = None
        if self.socket_path.exists() or self.socket_path.is_symlink():
            self.socket_path.unlink()

    def close(self) -> None:
        self.stop()
        self._socket_dir.rmdir()


@pytest.fixture
def approver_authority_sidecar_factory() -> Iterator[
    _ApproverAuthoritySidecarFactory
]:
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    socket_dir = Path(tempfile.mkdtemp(prefix="faa-chain-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    factory = _ApproverAuthoritySidecarFactory(socket_dir)
    yield factory
    factory.close()


class _ApprovalReceiptSidecarFactory:
    def __init__(self, socket_dir: Path) -> None:
        self._socket_dir = socket_dir
        self.socket_path = socket_dir / "receipt.sock"
        self._process: subprocess.Popen[bytes] | None = None

    def start(self, hmac_key_path: Path) -> UnixApprovalReceiptAuthenticator:
        if self._process is not None:
            raise AssertionError("Approval receipt sidecar is already running")
        environment = {
            **os.environ,
            "FORTIPAM_MCP_V4_APPROVAL_RECEIPT_SIDECAR_HMAC_KEY_FILE": str(
                hmac_key_path
            ),
            "FORTIPAM_MCP_V4_APPROVAL_RECEIPT_SIDECAR_SOCKET": str(
                self.socket_path
            ),
            "PYTHONPATH": "src:.",
        }
        process = subprocess.Popen(
            (sys.executable, "-m", "fortipam_mcp.approval_receipt_sidecar"),
            cwd=Path(__file__).resolve().parents[1],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not self.socket_path.exists():
            if process.poll() is not None:
                stderr = process.stderr.read() if process.stderr is not None else b""
                raise AssertionError(
                    f"Approval receipt sidecar stopped before ready: {stderr!r}"
                )
            time.sleep(0.02)
        if not self.socket_path.exists():
            process.terminate()
            process.wait(timeout=5.0)
            raise AssertionError("Approval receipt sidecar did not create its socket")
        self._process = process
        client = UnixApprovalReceiptAuthenticator(
            UnixApprovalReceiptAuthenticatorSettings(self.socket_path)
        )
        client.verify_ready()
        return client

    def stop(self) -> None:
        process = self._process
        if process is None:
            return
        process.terminate()
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5.0)
        self._process = None
        if self.socket_path.exists() or self.socket_path.is_symlink():
            self.socket_path.unlink()

    def close(self) -> None:
        self.stop()
        self._socket_dir.rmdir()


@pytest.fixture
def approval_receipt_sidecar_factory() -> Iterator[_ApprovalReceiptSidecarFactory]:
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    socket_dir = Path(tempfile.mkdtemp(prefix="far-chain-", dir=scratch))
    os.chmod(socket_dir, 0o700)
    factory = _ApprovalReceiptSidecarFactory(socket_dir)
    yield factory
    factory.close()


class _PlanningInputSidecarFactory:
    def __init__(self, scratch: Path) -> None:
        self._scratch = scratch
        self._entries: dict[Path, tuple[subprocess.Popen[bytes] | None, Path]] = {}

    def create(
        self,
        *,
        module: str,
        prefix: str,
        socket_name: str,
        socket_environment_name: str,
        environment: dict[str, str],
    ) -> Path:
        socket_dir = Path(tempfile.mkdtemp(prefix=prefix, dir=self._scratch))
        os.chmod(socket_dir, 0o700)
        socket_path = socket_dir / socket_name
        self._entries[socket_path] = (None, socket_dir)
        self.restart(
            socket_path,
            module=module,
            socket_environment_name=socket_environment_name,
            environment=environment,
        )
        return socket_path

    def restart(
        self,
        socket_path: Path,
        *,
        module: str,
        socket_environment_name: str,
        environment: dict[str, str],
    ) -> None:
        process, socket_dir = self._entries[socket_path]
        if process is not None:
            raise AssertionError("Planning-input sidecar is already running")
        process_environment = {
            **os.environ,
            **environment,
            socket_environment_name: str(socket_path),
            "PYTHONPATH": "src:.",
        }
        process = subprocess.Popen(
            (sys.executable, "-m", module),
            cwd=Path(__file__).resolve().parents[1],
            env=process_environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self._entries[socket_path] = (process, socket_dir)
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and not socket_path.exists():
            if process.poll() is not None:
                stderr = process.stderr.read() if process.stderr is not None else b""
                raise AssertionError(
                    f"Planning-input sidecar stopped before ready: {stderr!r}"
                )
            time.sleep(0.02)
        if not socket_path.exists():
            self.stop(socket_path)
            raise AssertionError("Planning-input sidecar did not create its socket")

    def stop(self, socket_path: Path) -> None:
        process, socket_dir = self._entries[socket_path]
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5.0)
        self._entries[socket_path] = (None, socket_dir)
        if socket_path.exists() or socket_path.is_symlink():
            socket_path.unlink()

    def close(self) -> None:
        for socket_path in tuple(self._entries):
            self.stop(socket_path)
            _process, socket_dir = self._entries.pop(socket_path)
            socket_dir.rmdir()


@pytest.fixture
def planning_input_sidecar_factory() -> Iterator[_PlanningInputSidecarFactory]:
    scratch = Path(__file__).resolve().parents[1] / ".codex_tmp"
    scratch.mkdir(mode=0o700, exist_ok=True)
    factory = _PlanningInputSidecarFactory(scratch)
    yield factory
    factory.close()


class ExternalCheckpoint:
    authority_ref = "v4-external-checkpoint-test"

    def __init__(self, store_ref: str) -> None:
        self.tail = PlanningStoreTail(store_ref, 0, "chain-root")

    def verify(self, tail: PlanningStoreTail) -> None:
        if tail != self.tail:
            raise MonotonicCheckpointError("checkpoint mismatch")

    def advance(
        self,
        previous: PlanningStoreTail,
        current: PlanningStoreTail,
    ) -> None:
        if previous != self.tail or current.sequence != previous.sequence + 1:
            raise MonotonicCheckpointError("checkpoint compare-and-swap failed")
        self.tail = current


class ApproverExternalCheckpoint:
    authority_ref = "v4-approver-external-checkpoint-test"

    def __init__(self, store_ref: str) -> None:
        self.tail = ApproverAuthorityStoreTail.empty(store_ref)

    def verify(self, tail: ApproverAuthorityStoreTail) -> None:
        if tail != self.tail:
            raise ApproverAuthorityCheckpointError("checkpoint mismatch")

    def advance(
        self,
        previous: ApproverAuthorityStoreTail,
        current: ApproverAuthorityStoreTail,
    ) -> None:
        valid_event_advance = (
            current.sequence == previous.sequence + 1
            and current.last_seen_at >= previous.last_seen_at
        )
        valid_time_advance = (
            current.sequence == previous.sequence
            and current.chain_mac == previous.chain_mac
            and current.last_seen_at > previous.last_seen_at
        )
        if (
            previous != self.tail
            or current.store_ref != previous.store_ref
            or not (valid_event_advance or valid_time_advance)
        ):
            raise ApproverAuthorityCheckpointError(
                "checkpoint compare-and-swap failed"
            )
        self.tail = current


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def test_synthetic_host_environment_accepts_only_complete_distinct_state_paths(
    tmp_path: Path,
) -> None:
    assert (
        synthetic_host_settings_from_environment(
            {
                "FORTIPAM_MCP_V4_APPROVAL_RECEIPT_HMAC_KEY_FILE": str(
                    tmp_path / "must-not-load.hmac"
                )
            }
        )
        is None
    )
    environment = {
        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": "synthetic",
        "FORTIPAM_MCP_V4_PLAN_STORE_DB": str(tmp_path / "planning.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_STORE_HMAC_KEY_FILE": str(tmp_path / "planning.hmac"),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_DB": str(
            tmp_path / "reference.sqlite3"
        ),
        "FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_HMAC_KEY_FILE": str(
            tmp_path / "reference.hmac"
        ),
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_DB": str(
            tmp_path / "draft.sqlite3"
        ),
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE": str(
            tmp_path / "draft.hmac"
        ),
        "FORTIPAM_MCP_V4_PLAN_SECRET_CREATE_READINESS_SOCKET": str(
            tmp_path / "secret-readiness.sock"
        ),
    }

    settings = synthetic_host_settings_from_environment(environment)

    assert settings == V4SyntheticHostSettings(
        tmp_path / "planning.sqlite3",
        tmp_path / "planning.hmac",
        V4PersistentReferenceAuthoritySettings(
            tmp_path / "reference.sqlite3",
            tmp_path / "reference.hmac",
        ),
        V4PersistentSchemeDraftAuthoritySettings(
            tmp_path / "draft.sqlite3",
            tmp_path / "draft.hmac",
        ),
        secret_create_runtime=V4UnixSecretCreateRuntimeSettings(
            tmp_path / "secret-readiness.sock"
        ),
    )
    del environment["FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_HMAC_KEY_FILE"]
    with pytest.raises(V4RuntimeHostError, match="both state paths"):
        synthetic_host_settings_from_environment(environment)
    environment["FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_HMAC_KEY_FILE"] = str(
        tmp_path / "planning.hmac"
    )
    with pytest.raises(V4RuntimeHostError, match="state paths are invalid"):
        synthetic_host_settings_from_environment(environment)
    environment["FORTIPAM_MCP_V4_PLAN_REFERENCE_AUTHORITY_HMAC_KEY_FILE"] = str(
        tmp_path / "reference.hmac"
    )
    del environment[
        "FORTIPAM_MCP_V4_PLAN_SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE"
    ]
    with pytest.raises(V4RuntimeHostError, match="Scheme Draft authority requires"):
        synthetic_host_settings_from_environment(environment)


def test_secret_create_runtime_environment_requires_absolute_distinct_socket(
    tmp_path: Path,
) -> None:
    environment = {
        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": "synthetic",
        "FORTIPAM_MCP_V4_PLAN_STORE_DB": str(tmp_path / "planning.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_STORE_HMAC_KEY_FILE": str(tmp_path / "planning.hmac"),
        "FORTIPAM_MCP_V4_PLAN_SECRET_CREATE_READINESS_SOCKET": "relative.sock",
    }
    with pytest.raises(V4RuntimeHostError, match="state paths are invalid"):
        synthetic_host_settings_from_environment(environment)
    environment["FORTIPAM_MCP_V4_PLAN_SECRET_CREATE_READINESS_SOCKET"] = str(
        tmp_path / "planning.sqlite3"
    )
    with pytest.raises(V4RuntimeHostError, match="state paths are invalid"):
        synthetic_host_settings_from_environment(environment)


def test_persistent_checkpoint_environment_requires_complete_distinct_binding(
    tmp_path: Path,
) -> None:
    environment = {
        "FORTIPAM_MCP_V4_PLAN_HOST_MODE": "synthetic",
        "FORTIPAM_MCP_V4_PLAN_STORE_DB": str(tmp_path / "planning.sqlite3"),
        "FORTIPAM_MCP_V4_PLAN_STORE_HMAC_KEY_FILE": str(tmp_path / "planning.hmac"),
        "FORTIPAM_MCP_V4_PLAN_CHECKPOINT_AUTHORITY_DB": str(
            tmp_path / "checkpoint.sqlite3"
        ),
        "FORTIPAM_MCP_V4_PLAN_CHECKPOINT_AUTHORITY_HMAC_KEY_FILE": str(
            tmp_path / "checkpoint.hmac"
        ),
        "FORTIPAM_MCP_V4_PLAN_CHECKPOINT_STORE_REF": "v4-planning-store-test",
    }

    assert synthetic_host_settings_from_environment(environment) == (
        V4SyntheticHostSettings(
            tmp_path / "planning.sqlite3",
            tmp_path / "planning.hmac",
            planning_checkpoint=V4PersistentPlanningCheckpointSettings(
                tmp_path / "checkpoint.sqlite3",
                tmp_path / "checkpoint.hmac",
                "v4-planning-store-test",
            ),
        )
    )
    del environment["FORTIPAM_MCP_V4_PLAN_CHECKPOINT_STORE_REF"]
    with pytest.raises(V4RuntimeHostError, match="complete state and store"):
        synthetic_host_settings_from_environment(environment)
    environment["FORTIPAM_MCP_V4_PLAN_CHECKPOINT_STORE_REF"] = "short"
    with pytest.raises(V4RuntimeHostError, match="state paths are invalid"):
        synthetic_host_settings_from_environment(environment)


def test_persistent_checkpoint_authority_binds_host_and_detects_planning_rollback(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    oauth = tmp_path / "oauth"
    oauth.mkdir(mode=0o700)
    os.chmod(oauth, 0o700)
    planning_key = _owner_file(state / "planning.hmac", b"p" * 32)
    checkpoint_key = _owner_file(state / "checkpoint.hmac", b"k" * 32)
    confirmation_key = _owner_file(state / "confirmation.hmac", b"c" * 32)
    receipt_key = _owner_file(state / "receipt.hmac", b"r" * 32)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(PASSWORD, salt=b"0123456789abcdef"),
        )
    )
    planning_database = state / "planning.sqlite3"
    settings = V4SyntheticHostSettings(
        planning_database,
        planning_key,
        planning_checkpoint=V4PersistentPlanningCheckpointSettings(
            state / "checkpoint.sqlite3",
            checkpoint_key,
            "v4-planning-store-test",
        ),
    )
    factory = synthetic_v4_plan_host_factory(settings, clock=lambda: NOW)
    confirmation_settings = V4ConfirmationSettings(
        state / "confirmation.sqlite3",
        confirmation_key,
        receipt_key,
    )
    components = factory(provider, confirmation_settings)
    empty_database = planning_database.read_bytes()
    principal = V4PlanningPrincipal(
        AuthenticatedRequester("a" * 64, "operator"),
        "b" * 64,
    )

    status = components.plan_services.status()
    assert isinstance(
        components.planning_checkpoint_authority,
        PersistentPlanningCheckpointAuthority,
    )
    assert status["monotonic_checkpoint_protocol_bound"] is True
    assert "external_monotonic_checkpoint_unbound" in status["blocker_codes"]
    components.plan_services.preview(V4_SYNTHETIC_SCHEME_REF, principal)
    restarted = factory(provider, confirmation_settings)
    assert restarted.plan_services.status()[
        "monotonic_checkpoint_protocol_bound"
    ] is True

    planning_database.write_bytes(empty_database)
    with pytest.raises(V4RuntimeHostError, match="initialization failed closed"):
        factory(provider, confirmation_settings)


def test_persistent_checkpoint_key_must_be_independent_from_planning_store(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    oauth = tmp_path / "oauth"
    oauth.mkdir(mode=0o700)
    os.chmod(oauth, 0o700)
    planning_key = _owner_file(state / "planning.hmac", b"p" * 32)
    checkpoint_key = _owner_file(state / "checkpoint.hmac", b"p" * 32)
    confirmation_key = _owner_file(state / "confirmation.hmac", b"c" * 32)
    receipt_key = _owner_file(state / "receipt.hmac", b"r" * 32)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(PASSWORD, salt=b"0123456789abcdef"),
        )
    )
    factory = synthetic_v4_plan_host_factory(
        V4SyntheticHostSettings(
            state / "planning.sqlite3",
            planning_key,
            planning_checkpoint=V4PersistentPlanningCheckpointSettings(
                state / "checkpoint.sqlite3",
                checkpoint_key,
                "v4-planning-store-test",
            ),
        )
    )

    with pytest.raises(V4RuntimeHostError, match="must be independent"):
        factory(
            provider,
            V4ConfirmationSettings(
                state / "confirmation.sqlite3",
                confirmation_key,
                receipt_key,
            ),
        )


def test_host_reports_private_runtime_readiness_without_execution_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    oauth = tmp_path / "oauth"
    oauth.mkdir(mode=0o700)
    os.chmod(oauth, 0o700)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(
                PASSWORD,
                salt=b"0123456789abcdef",
            ),
        )
    )
    readiness_client = UnixSecretCreateReadinessProxyClient(
        UnixSecretCreateReadinessProxyClientSettings(state / "readiness.sock")
    )
    monkeypatch.setattr(
        UnixSecretCreateReadinessProxyClient,
        "verify_ready",
        lambda self: None,
    )
    monkeypatch.setattr(
        UnixSecretCreateReadinessProxyClient,
        "is_available",
        lambda self: True,
    )
    factory = synthetic_v4_plan_host_factory(
        V4SyntheticHostSettings(
            state / "planning.sqlite3",
            _owner_file(state / "planning.hmac", b"p" * 32),
            secret_create_runtime=V4UnixSecretCreateRuntimeSettings(
                state / "readiness.sock"
            ),
        ),
    )
    confirmation_settings = V4ConfirmationSettings(
        state / "confirmation.sqlite3",
        _owner_file(state / "confirmation.hmac", b"c" * 32),
        _owner_file(state / "receipt.hmac", b"r" * 32),
    )
    components = factory(provider, confirmation_settings)
    status = components.plan_services.status()

    assert status["secret_create_private_runtime_protocol_bound"] is False
    assert status["secret_create_readiness_proxy_protocol_bound"] is True
    assert status["secret_create_private_runtime_available"] is True
    assert status["dispatchable"] is False
    assert status["executor_mcp_exposed"] is False
    assert "product_idempotency_unproven" in status["blocker_codes"]
    assert not hasattr(components, "secret_create_runtime_client")

    with pytest.raises(V4RuntimeHostError, match="exactly one binding"):
        synthetic_v4_plan_host_factory(
            V4SyntheticHostSettings(
                state / "duplicate.sqlite3",
                state / "planning.hmac",
                secret_create_runtime=V4UnixSecretCreateRuntimeSettings(
                    state / "readiness.sock"
                ),
            ),
            secret_create_readiness_proxy_client=readiness_client,
        )

    def unavailable(self: UnixSecretCreateReadinessProxyClient) -> None:
        del self
        raise SecretCreateReadinessSidecarError("unavailable")

    monkeypatch.setattr(
        UnixSecretCreateReadinessProxyClient,
        "verify_ready",
        unavailable,
    )
    monkeypatch.setattr(
        UnixSecretCreateReadinessProxyClient,
        "is_available",
        lambda self: False,
    )
    unavailable_status = components.plan_services.status()
    assert unavailable_status["secret_create_private_runtime_protocol_bound"] is False
    assert unavailable_status["secret_create_readiness_proxy_protocol_bound"] is True
    assert unavailable_status["secret_create_private_runtime_available"] is False
    assert unavailable_status["dispatchable"] is False
    with pytest.raises(V4RuntimeHostError, match="initialization failed closed"):
        factory(provider, confirmation_settings)
    with pytest.raises(V4RuntimeHostError, match="binding is invalid"):
        synthetic_v4_plan_host_factory(
            V4SyntheticHostSettings(
                state / "unused.sqlite3",
                state / "planning.hmac",
            ),
            secret_create_readiness_proxy_client=object(),  # type: ignore[arg-type]
        )


def test_persistent_scheme_draft_authority_binds_host_issuance(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    oauth = tmp_path / "oauth"
    oauth.mkdir(mode=0o700)
    os.chmod(oauth, 0o700)
    planning_key = _owner_file(state / "planning.hmac", b"p" * 32)
    draft_key = _owner_file(state / "draft.hmac", b"d" * 32)
    confirmation_key = _owner_file(state / "confirmation.hmac", b"c" * 32)
    receipt_key = _owner_file(state / "receipt.hmac", b"r" * 32)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(PASSWORD, salt=b"0123456789abcdef"),
        )
    )
    clock = MutableClock(NOW)
    factory = synthetic_v4_plan_host_factory(
        V4SyntheticHostSettings(
            state / "planning.sqlite3",
            planning_key,
            scheme_draft_authority=V4PersistentSchemeDraftAuthoritySettings(
                state / "draft.sqlite3",
                draft_key,
            ),
        ),
        clock=clock,
    )
    components = factory(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            confirmation_key,
            receipt_key,
        ),
    )
    requester = AuthenticatedRequester("a" * 64, "operator")
    principal = V4PlanningPrincipal(requester, "b" * 64)

    assert isinstance(
        components.scheme_draft_authority, PersistentSchemeDraftAuthority
    )
    draft_ref = issue_synthetic_scheme_draft(
        components.scheme_draft_authority,
        requester,
        expires_at=NOW + 600,
        now_epoch=NOW,
    )
    preview = components.plan_services.preview(draft_ref, principal)
    status = components.plan_services.status()

    assert preview["confirmation_state"] == "awaiting_human_reauthentication"
    assert status["scheme_draft_issuance_protocol_bound"] is True
    assert status["scheme_draft_authority_checkpoint_protocol_bound"] is False
    assert status["reference_authorization_protocol_bound"] is False
    assert status["reference_authority_checkpoint_protocol_bound"] is False
    assert "scheme_draft_issuance_unbound" not in status["blocker_codes"]
    assert "synthetic_scheme_draft_refs" not in status


def test_scheme_draft_authority_key_must_be_independent(tmp_path: Path) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    oauth = tmp_path / "oauth"
    oauth.mkdir(mode=0o700)
    os.chmod(oauth, 0o700)
    planning_key = _owner_file(state / "planning.hmac", b"p" * 32)
    draft_key = _owner_file(state / "draft.hmac", b"p" * 32)
    confirmation_key = _owner_file(state / "confirmation.hmac", b"c" * 32)
    receipt_key = _owner_file(state / "receipt.hmac", b"r" * 32)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(PASSWORD, salt=b"0123456789abcdef"),
        )
    )
    factory = synthetic_v4_plan_host_factory(
        V4SyntheticHostSettings(
            state / "planning.sqlite3",
            planning_key,
            scheme_draft_authority=V4PersistentSchemeDraftAuthoritySettings(
                state / "draft.sqlite3",
                draft_key,
            ),
        )
    )

    with pytest.raises(V4RuntimeHostError, match="must be independent"):
        factory(
            provider,
            V4ConfirmationSettings(
                state / "confirmation.sqlite3",
                confirmation_key,
                receipt_key,
            ),
        )


def test_synthetic_host_runs_exact_browser_confirmation_to_non_executable_plan(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    oauth = tmp_path / "oauth"
    oauth.mkdir(mode=0o700)
    os.chmod(oauth, 0o700)
    planning_key = _owner_file(
        state / "planning.hmac",
        b"planning-key-0000000000000000000000000000000000",
    )
    confirmation_key = _owner_file(
        state / "confirmation.hmac",
        b"confirmation-key-00000000000000000000000000000000",
    )
    receipt_key = _owner_file(
        state / "receipt.hmac",
        b"receipt-key-00000000000000000000000000000000000",
    )
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(
                PASSWORD,
                salt=b"0123456789abcdef",
            ),
        )
    )
    clock = MutableClock(NOW)
    approval_authenticator = ApprovalReceiptAuthenticator(b"a" * 32)
    factory = synthetic_v4_plan_host_factory(
        V4SyntheticHostSettings(state / "planning.sqlite3", planning_key),
        clock=clock,
        approval_receipt_authenticator=approval_authenticator,
    )
    components = factory(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            confirmation_key,
            receipt_key,
        ),
    )
    requester = AuthenticatedRequester("a" * 64, "operator")
    principal = V4PlanningPrincipal(requester, "b" * 64)

    status = components.plan_services.status()
    assert status["synthetic_scheme_draft_refs"] == [V4_SYNTHETIC_SCHEME_REF]
    assert status["confirmation_transport_bound"] is True
    assert status["monotonic_checkpoint_protocol_bound"] is False
    assert status["approval_receipt_authenticator_protocol_bound"] is True
    assert status["approver_authorization_protocol_bound"] is False
    assert status["approver_authority_checkpoint_protocol_bound"] is False
    assert status["scheme_draft_authority_checkpoint_protocol_bound"] is False
    assert status["reference_authorization_protocol_bound"] is False
    assert status["reference_authority_checkpoint_protocol_bound"] is False
    assert "approval_receipt_not_independently_signed" not in status["blocker_codes"]
    assert "independent_approver_identity_unbound" in status["blocker_codes"]
    assert "external_monotonic_checkpoint_unbound" in status["blocker_codes"]
    assert "scheme_draft_issuance_unbound" in status["blocker_codes"]
    assert status["scheme_draft_issuance_protocol_bound"] is False
    assert status["device_access"] is False
    preview = components.plan_services.preview(V4_SYNTHETIC_SCHEME_REF, principal)
    assert preview["confirmation_state"] == "awaiting_human_reauthentication"
    url = str(preview["confirmation_url"])
    path = url.removeprefix("https://mcp.example.com")

    with TestClient(
        Starlette(routes=components.confirmation_service.routes()),
        base_url="https://mcp.example.com",
    ) as client:
        page = client.get(path)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert csrf is not None
        clock.value = NOW + 1
        review = client.post(
            path,
            data={
                "csrf_token": csrf.group(1),
                "username": "operator",
                "password": PASSWORD,
                "action": "review",
            },
            headers={"origin": "https://mcp.example.com"},
        )
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', review.text)
        assert csrf is not None
        clock.value = NOW + 2
        recorded = client.post(
            path,
            data={"csrf_token": csrf.group(1), "action": "affirm"},
            headers={"origin": "https://mcp.example.com"},
        )
        assert recorded.status_code == 200

    clock.value = NOW + 3
    components = factory(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            confirmation_key,
            receipt_key,
        ),
    )
    original_claim = components.confirmation_service.claim
    claim_attempts = 0

    def fail_first_claim(*args: object, **kwargs: object) -> None:
        nonlocal claim_attempts
        claim_attempts += 1
        if claim_attempts == 1:
            raise V4ConfirmationHttpError("injected post-planning claim failure")
        original_claim(*args, **kwargs)  # type: ignore[arg-type]

    components.confirmation_service.claim = fail_first_claim  # type: ignore[method-assign]
    preview_revision = preview["revision"]
    assert type(preview_revision) is int
    with pytest.raises(V4ConfirmationHttpError, match="injected"):
        components.plan_services.confirm(
            str(preview["summary_ref"]),
            preview_revision,
            principal,
        )
    confirmation = components.plan_services.confirm(
        str(preview["summary_ref"]),
        preview_revision,
        principal,
    )
    clock.value = NOW + 4
    components = factory(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            confirmation_key,
            receipt_key,
        ),
    )
    plan = components.plan_services.prepare(
        str(preview["summary_ref"]),
        str(confirmation["confirmation_ref"]),
        principal,
    )
    assert plan["dispatchable"] is False
    assert plan["executor_runtime_packaged"] is False
    assert plan["adapter_registry_bound"] is False

    restarted = PersistentProtectedPlanningStore(
        state / "planning.sqlite3",
        planning_key,
        clock=lambda: NOW + 5,
    )
    assert restarted.get_plan(str(plan["plan_ref"])).dispatchable is False

    workflow = components.plan_services._facade._workflow  # noqa: SLF001
    clock.value = NOW + 5
    decision = workflow.request_approval(
        str(plan["plan_ref"]),
        requester,
        now_epoch=clock.value,
    )
    clock.value = NOW + 6
    receipt = workflow.approve(
        decision.decision_ref,
        AuthenticatedApprover("synthetic-independent-approver"),
        now_epoch=clock.value,
    )
    assert approval_authenticator.verify(receipt) is True

    unbound_factory = synthetic_v4_plan_host_factory(
        V4SyntheticHostSettings(state / "planning.sqlite3", planning_key),
        clock=clock,
    )
    with pytest.raises(V4RuntimeHostError, match="initialization failed closed"):
        unbound_factory(
            provider,
            V4ConfirmationSettings(
                state / "confirmation.sqlite3",
                confirmation_key,
                receipt_key,
            ),
        )

    clock.value = NOW + 7
    components = factory(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            confirmation_key,
            receipt_key,
        ),
    )
    restarted_workflow = components.plan_services._facade._workflow  # noqa: SLF001
    claim = restarted_workflow.claim_approval(
        receipt.receipt_ref,
        str(plan["plan_ref"]),
        requester,
    )
    assert claim.approval_validated is True
    assert claim.execution_authorized is False
    assert claim.ready_for_dispatch is False


def test_synthetic_host_external_checkpoint_binding_detects_database_rollback(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    oauth = tmp_path / "oauth"
    oauth.mkdir(mode=0o700)
    os.chmod(oauth, 0o700)
    planning_key = _owner_file(state / "planning.hmac", b"p" * 32)
    confirmation_key = _owner_file(state / "confirmation.hmac", b"c" * 32)
    receipt_key = _owner_file(state / "receipt.hmac", b"r" * 32)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(
                PASSWORD,
                salt=b"0123456789abcdef",
            ),
        )
    )
    checkpoint_store_ref = "v4-synthetic-planning-store-test"
    checkpoint = ExternalCheckpoint(checkpoint_store_ref)
    planning_database = state / "planning.sqlite3"
    host_settings = V4SyntheticHostSettings(planning_database, planning_key)
    confirmation_settings = V4ConfirmationSettings(
        state / "confirmation.sqlite3",
        confirmation_key,
        receipt_key,
    )
    factory = synthetic_v4_plan_host_factory(
        host_settings,
        clock=lambda: NOW,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=checkpoint_store_ref,
    )
    components = factory(provider, confirmation_settings)
    empty_database = planning_database.read_bytes()
    principal = V4PlanningPrincipal(
        AuthenticatedRequester("a" * 64, "operator"),
        "b" * 64,
    )

    status = components.plan_services.status()
    assert status["monotonic_checkpoint_protocol_bound"] is True
    assert status["approval_receipt_authenticator_protocol_bound"] is False
    assert status["approver_authorization_protocol_bound"] is False
    assert status["approver_authority_checkpoint_protocol_bound"] is False
    assert "approval_receipt_not_independently_signed" in status["blocker_codes"]
    assert "independent_approver_identity_unbound" in status["blocker_codes"]
    assert "external_monotonic_checkpoint_unbound" in status["blocker_codes"]
    components.plan_services.preview(V4_SYNTHETIC_SCHEME_REF, principal)
    assert checkpoint.tail.sequence == 1

    planning_database.write_bytes(empty_database)
    with pytest.raises(V4RuntimeHostError, match="initialization failed closed"):
        factory(provider, confirmation_settings)


def test_synthetic_host_rejects_incomplete_external_checkpoint_binding(
    tmp_path: Path,
) -> None:
    settings = V4SyntheticHostSettings(
        tmp_path / "planning.sqlite3",
        tmp_path / "planning.hmac",
    )
    checkpoint = ExternalCheckpoint("v4-synthetic-planning-store-test")

    with pytest.raises(V4RuntimeHostError, match="complete trusted binding"):
        synthetic_v4_plan_host_factory(
            settings,
            monotonic_checkpoint=checkpoint,
        )
    with pytest.raises(V4RuntimeHostError, match="complete trusted binding"):
        synthetic_v4_plan_host_factory(
            settings,
            checkpoint_store_ref="v4-synthetic-planning-store-test",
        )


def test_synthetic_host_binds_approval_authenticator_only_at_trusted_composition(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    oauth = tmp_path / "oauth"
    oauth.mkdir(mode=0o700)
    os.chmod(oauth, 0o700)
    planning_key = _owner_file(state / "planning.hmac", b"p" * 32)
    confirmation_key = _owner_file(state / "confirmation.hmac", b"c" * 32)
    receipt_key = _owner_file(state / "receipt.hmac", b"r" * 32)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(PASSWORD, salt=b"0123456789abcdef"),
        )
    )
    authenticator = ApprovalReceiptAuthenticator(b"a" * 32)
    factory = synthetic_v4_plan_host_factory(
        V4SyntheticHostSettings(state / "planning.sqlite3", planning_key),
        clock=lambda: NOW,
        approval_receipt_authenticator=authenticator,
    )
    components = factory(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            confirmation_key,
            receipt_key,
        ),
    )

    status = components.plan_services.status()
    assert status["approval_receipt_authenticator_protocol_bound"] is True
    assert status["approver_authorization_protocol_bound"] is False
    assert "approval_receipt_not_independently_signed" not in status["blocker_codes"]
    assert "independent_approver_identity_unbound" in status["blocker_codes"]
    assert status["dispatchable"] is False
    workflow = components.plan_services._facade._workflow  # noqa: SLF001
    assert workflow._store._approval_receipt_authenticator is authenticator  # noqa: SLF001
    assert workflow._approval_gate._receipt_authenticator is authenticator  # noqa: SLF001

    reused_key = ApprovalReceiptAuthenticator(b"p" * 32)
    reused_factory = synthetic_v4_plan_host_factory(
        V4SyntheticHostSettings(state / "reused.sqlite3", planning_key),
        clock=lambda: NOW,
        approval_receipt_authenticator=reused_key,
    )
    with pytest.raises(V4RuntimeHostError, match="initialization failed closed"):
        reused_factory(
            provider,
            V4ConfirmationSettings(
                state / "reused-confirmation.sqlite3",
                confirmation_key,
                receipt_key,
            ),
        )
    with pytest.raises(V4RuntimeHostError, match="binding is invalid"):
        synthetic_v4_plan_host_factory(
            V4SyntheticHostSettings(state / "invalid.sqlite3", planning_key),
            approval_receipt_authenticator=object(),  # type: ignore[arg-type]
        )


def test_synthetic_host_binds_four_process_authorities_to_oauth_identities(
    tmp_path: Path,
    approver_checkpoint_sidecar: tuple[UnixApproverCheckpointClient, Path],
    approver_authority_sidecar_factory: _ApproverAuthoritySidecarFactory,
    approval_receipt_sidecar_factory: _ApprovalReceiptSidecarFactory,
    planning_input_sidecar_factory: _PlanningInputSidecarFactory,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    oauth = tmp_path / "oauth"
    oauth.mkdir(mode=0o700)
    os.chmod(oauth, 0o700)
    planning_key = _owner_file(state / "planning.hmac", b"p" * 32)
    authority_key = _owner_file(state / "authority.hmac", b"d" * 32)
    receipt_key = _owner_file(state / "approval-receipt.hmac", b"a" * 32)
    reference_key = _owner_file(state / "reference.hmac", b"e" * 32)
    draft_key = _owner_file(state / "draft.hmac", b"f" * 32)
    confirmation_key = _owner_file(state / "confirmation.hmac", b"c" * 32)
    browser_receipt_key = _owner_file(state / "browser-receipt.hmac", b"r" * 32)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(PASSWORD, salt=b"0123456789abcdef"),
        )
    )
    identity_settings = V4PlanningAuthorizationSettings(
        "https://mcp.example.com/fpamcp-v4",
        b"n" * 32,
    )
    common_token: dict[str, object] = {
        "token": "synthetic-sdk-validated-token",
        "client_id": "synthetic-planning-client",
        "expires_at": NOW + 600,
        "resource": "https://mcp.example.com/fpamcp-v4",
        "claims": {"iss": "https://issuer.example/oauth"},
    }
    principal = planning_principal_from_access_token(
        AccessToken(
            **common_token,
            scopes=["fortipam:plan"],
            subject="synthetic-requester",
        ),
        identity_settings,
    )
    approver = approver_from_access_token(
        AccessToken(
            **{
                **common_token,
                "client_id": "synthetic-approval-client",
                "token": "synthetic-sdk-validated-approval-token",
            },
            scopes=[V4_APPROVAL_SCOPE],
            subject="synthetic-independent-approver",
        ),
        identity_settings,
    )
    clock = MutableClock(NOW)
    draft_database = state / "draft.sqlite3"
    draft_checkpoint_key = _owner_file(
        state / "draft-checkpoint.hmac",
        b"h" * 32,
    )
    draft_checkpoint_authority_ref = "v4-scheme-draft-checkpoint-authority"
    draft_checkpoint_store_ref = "v4-scheme-draft-authority-store"
    draft_checkpoint_environment = {
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_DATABASE": str(
            state / "draft-checkpoint.sqlite3"
        ),
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_HMAC_KEY_FILE": str(
            draft_checkpoint_key
        ),
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_AUTHORITY_REF": (
            draft_checkpoint_authority_ref
        ),
    }
    draft_checkpoint_socket = planning_input_sidecar_factory.create(
        module="fortipam_mcp.scheme_draft_checkpoint_sidecar",
        prefix="fdc-",
        socket_name="c.sock",
        socket_environment_name="FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_SOCKET",
        environment=draft_checkpoint_environment,
    )
    draft_checkpoint_client = UnixSchemeDraftCheckpointClient(
        UnixSchemeDraftCheckpointClientSettings(
            draft_checkpoint_socket,
            draft_checkpoint_authority_ref,
        )
    )
    draft_authority = PersistentSchemeDraftAuthority(
        draft_database,
        draft_key,
        authority_ref=V4_PERSISTENT_SCHEME_DRAFT_AUTHORITY_REF,
        monotonic_checkpoint=draft_checkpoint_client,
        checkpoint_store_ref=draft_checkpoint_store_ref,
        clock=clock,
    )
    draft_ref = issue_synthetic_scheme_draft(
        draft_authority,
        principal.requester,
        expires_at=NOW + 600,
        now_epoch=NOW,
    )
    issued_draft_database = draft_database.read_bytes()
    reference_database = state / "reference.sqlite3"
    reference_checkpoint_key = _owner_file(
        state / "reference-checkpoint.hmac",
        b"g" * 32,
    )
    reference_checkpoint_authority_ref = "v4-reference-checkpoint-authority"
    reference_checkpoint_store_ref = "v4-reference-authority-store"
    reference_checkpoint_environment = {
        "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_DATABASE": str(
            state / "reference-checkpoint.sqlite3"
        ),
        "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_HMAC_KEY_FILE": str(
            reference_checkpoint_key
        ),
        "FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_AUTHORITY_REF": (
            reference_checkpoint_authority_ref
        ),
    }
    reference_checkpoint_socket = planning_input_sidecar_factory.create(
        module="fortipam_mcp.reference_checkpoint_sidecar",
        prefix="frc-",
        socket_name="c.sock",
        socket_environment_name="FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_SOCKET",
        environment=reference_checkpoint_environment,
    )
    reference_checkpoint_client = UnixReferenceCheckpointClient(
        UnixReferenceCheckpointClientSettings(
            reference_checkpoint_socket,
            reference_checkpoint_authority_ref,
        )
    )
    reference_authority = PersistentReferenceAuthority(
        reference_database,
        reference_key,
        authority_ref=V4_PERSISTENT_REFERENCE_AUTHORITY_REF,
        monotonic_checkpoint=reference_checkpoint_client,
        checkpoint_store_ref=reference_checkpoint_store_ref,
        clock=clock,
    )
    reference_grant_refs = issue_synthetic_reference_grants(
        reference_authority,
        requester_digest=principal.requester.digest,
        expires_at=NOW + 600,
        now_epoch=NOW,
    )
    draft_sidecar_environment = {
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_DATABASE": str(draft_database),
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_HMAC_KEY_FILE": str(draft_key),
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_REF": (
            V4_PERSISTENT_SCHEME_DRAFT_AUTHORITY_REF
        ),
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_CHECKPOINT_SOCKET": str(
            draft_checkpoint_socket
        ),
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_CHECKPOINT_REF": (
            draft_checkpoint_authority_ref
        ),
        "FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_CHECKPOINT_STORE_REF": (
            draft_checkpoint_store_ref
        ),
    }
    draft_socket = planning_input_sidecar_factory.create(
        module="fortipam_mcp.scheme_draft_authority_sidecar",
        prefix="fsd-chain-",
        socket_name="draft.sock",
        socket_environment_name="FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_SOCKET",
        environment=draft_sidecar_environment,
    )
    reference_sidecar_environment = {
        "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_DATABASE": str(reference_database),
        "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_HMAC_KEY_FILE": str(reference_key),
        "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_REF": (
            V4_PERSISTENT_REFERENCE_AUTHORITY_REF
        ),
        "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_CHECKPOINT_SOCKET": str(
            reference_checkpoint_socket
        ),
        "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_CHECKPOINT_REF": (
            reference_checkpoint_authority_ref
        ),
        "FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_CHECKPOINT_STORE_REF": (
            reference_checkpoint_store_ref
        ),
    }
    reference_socket = planning_input_sidecar_factory.create(
        module="fortipam_mcp.reference_authority_sidecar",
        prefix="fra-chain-",
        socket_name="reference.sock",
        socket_environment_name="FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_SOCKET",
        environment=reference_sidecar_environment,
    )
    authority_database = state / "authority.sqlite3"
    authority_checkpoint_store_ref = "v4-synthetic-approver-store-test"
    _authority_checkpoint, authority_checkpoint_socket = approver_checkpoint_sidecar
    authority_client = approver_authority_sidecar_factory.start(
        database_path=authority_database,
        hmac_key_path=authority_key,
        checkpoint_socket_path=authority_checkpoint_socket,
        checkpoint_store_ref=authority_checkpoint_store_ref,
    )
    authenticator = approval_receipt_sidecar_factory.start(receipt_key)
    host_settings = V4SyntheticHostSettings(
        planning_database_path=state / "planning.sqlite3",
        planning_hmac_key_path=planning_key,
        scheme_draft_sidecar=V4UnixSchemeDraftAuthoritySettings(
            draft_socket,
            V4_PERSISTENT_SCHEME_DRAFT_AUTHORITY_REF,
        ),
        reference_sidecar=V4UnixReferenceAuthoritySettings(
            reference_socket,
            V4_PERSISTENT_REFERENCE_AUTHORITY_REF,
        ),
    )
    confirmation_settings = V4ConfirmationSettings(
        state / "confirmation.sqlite3",
        confirmation_key,
        browser_receipt_key,
    )

    def build(
        bound_authority: UnixApproverAuthorizationClient,
    ):
        return synthetic_v4_plan_host_factory(
            host_settings,
            clock=clock,
            approval_receipt_authenticator=authenticator,
            approver_authorization_authority=bound_authority,
        )(provider, confirmation_settings)

    components = build(authority_client)
    status = components.plan_services.status()
    assert status["approver_authorization_protocol_bound"] is True
    assert status["approver_authority_checkpoint_protocol_bound"] is True
    assert status["approval_receipt_authenticator_protocol_bound"] is True
    assert status["scheme_draft_authority_checkpoint_protocol_bound"] is True
    assert status["reference_authorization_protocol_bound"] is True
    assert status["reference_authority_checkpoint_protocol_bound"] is True
    assert "approval_receipt_not_independently_signed" not in status["blocker_codes"]
    assert "independent_approver_identity_unbound" in status["blocker_codes"]
    assert status["dispatchable"] is False
    assert components.scheme_draft_authority is None
    assert isinstance(components.scheme_draft_client, UnixSchemeDraftAuthorityClient)
    assert components.reference_authority is None
    assert isinstance(components.reference_client, UnixReferenceAuthorityClient)

    preview = components.plan_services.preview(draft_ref, principal)
    assert preview["reference_authority_ref"] == V4_PERSISTENT_REFERENCE_AUTHORITY_REF
    path = str(preview["confirmation_url"]).removeprefix(
        "https://mcp.example.com"
    )
    with TestClient(
        Starlette(routes=components.confirmation_service.routes()),
        base_url="https://mcp.example.com",
    ) as client:
        page = client.get(path)
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert csrf is not None
        clock.value = NOW + 1
        review = client.post(
            path,
            data={
                "csrf_token": csrf.group(1),
                "username": "operator",
                "password": PASSWORD,
                "action": "review",
            },
            headers={"origin": "https://mcp.example.com"},
        )
        csrf = re.search(r'name="csrf_token" value="([^"]+)"', review.text)
        assert csrf is not None
        clock.value = NOW + 2
        assert client.post(
            path,
            data={"csrf_token": csrf.group(1), "action": "affirm"},
            headers={"origin": "https://mcp.example.com"},
        ).status_code == 200

    revision = preview["revision"]
    assert type(revision) is int
    clock.value = NOW + 3
    confirmation = components.plan_services.confirm(
        str(preview["summary_ref"]),
        revision,
        principal,
    )
    clock.value = NOW + 4
    plan_result = components.plan_services.prepare(
        str(preview["summary_ref"]),
        str(confirmation["confirmation_ref"]),
        principal,
    )
    workflow = components.plan_services._facade._workflow  # noqa: SLF001
    assert workflow._approval_gate._approver_authorizer is authority_client  # noqa: SLF001
    assert workflow._approval_gate._receipt_authenticator is authenticator  # noqa: SLF001
    assert workflow._store._approval_receipt_authenticator is authenticator  # noqa: SLF001
    plan = workflow._store.get_plan(str(plan_result["plan_ref"]))  # noqa: SLF001
    decision = workflow.request_approval(
        plan.plan_ref,
        principal.requester,
        now_epoch=NOW + 5,
    )
    delegation_input = state / "approver-bootstrap-input.json"
    delegation_output = state / "approver-bootstrap-output.json"
    delegation_input.write_text(
        json.dumps(
            {
                "action_bindings": [
                    {
                        "action_id": line.action_family_ref,
                        "action_version": line.action_family_version,
                    }
                    for line in plan.lines
                ],
                "approver": {
                    "identity_authority_ref": approver.identity_authority_ref,
                    "subject_namespace": approver.subject_namespace,
                    "subject_ref": approver.subject_ref,
                },
                "environment_ref": plan.environment_ref,
                "expires_at": NOW + 120,
                "policy_version": decision.policy_version,
                "scope_ref": plan.scope_ref,
            }
        ),
        encoding="utf-8",
    )
    os.chmod(delegation_input, 0o600)
    bootstrap_approver_delegation(
        ApproverDelegationBootstrapSettings(
            authority_database,
            authority_key,
            "v4-synthetic-approver-authority",
            authority_checkpoint_socket,
            APPROVER_CHECKPOINT_AUTHORITY_REF,
            authority_checkpoint_store_ref,
            delegation_input,
            delegation_output,
        ),
        now_epoch=NOW + 5,
    )
    delegation_ref = json.loads(delegation_output.read_text(encoding="utf-8"))[
        "delegation_ref"
    ]
    delegation_input.unlink()
    delegation_output.unlink()
    issued_database = authority_database.read_bytes()

    clock.value = NOW + 6
    components = build(authority_client)
    workflow = components.plan_services._facade._workflow  # noqa: SLF001
    receipt = workflow.approve(
        decision.decision_ref,
        approver,
        requester=principal.requester,
        now_epoch=NOW + 6,
    )
    assert receipt.approver_authority_ref == authority_client.authority_ref
    assert receipt.approver_authorization_digest is not None
    assert receipt.execution_authorized is False
    assert authenticator.verify(receipt) is True

    authorized_database = authority_database.read_bytes()
    authority_database.write_bytes(issued_database)
    with pytest.raises(V4RuntimeHostError, match="initialization failed closed"):
        build(authority_client)
    authority_database.write_bytes(authorized_database)

    assert components.scheme_draft_client is not None
    components.scheme_draft_client.resolve(draft_ref, principal.requester)
    current_draft_database = draft_database.read_bytes()
    draft_database.write_bytes(issued_draft_database)
    with pytest.raises(V4RuntimeHostError, match="initialization failed closed"):
        build(authority_client)
    draft_database.write_bytes(current_draft_database)

    planning_input_sidecar_factory.stop(draft_socket)
    planning_input_sidecar_factory.stop(draft_checkpoint_socket)
    planning_input_sidecar_factory.stop(reference_socket)
    planning_input_sidecar_factory.stop(reference_checkpoint_socket)
    approver_authority_sidecar_factory.stop()
    approval_receipt_sidecar_factory.stop()
    clock.value = NOW + 7
    planning_input_sidecar_factory.restart(
        draft_checkpoint_socket,
        module="fortipam_mcp.scheme_draft_checkpoint_sidecar",
        socket_environment_name="FORTIPAM_MCP_V4_SCHEME_DRAFT_CHECKPOINT_SOCKET",
        environment=draft_checkpoint_environment,
    )
    planning_input_sidecar_factory.restart(
        draft_socket,
        module="fortipam_mcp.scheme_draft_authority_sidecar",
        socket_environment_name="FORTIPAM_MCP_V4_SCHEME_DRAFT_AUTHORITY_SOCKET",
        environment=draft_sidecar_environment,
    )
    planning_input_sidecar_factory.restart(
        reference_checkpoint_socket,
        module="fortipam_mcp.reference_checkpoint_sidecar",
        socket_environment_name="FORTIPAM_MCP_V4_REFERENCE_CHECKPOINT_SOCKET",
        environment=reference_checkpoint_environment,
    )
    planning_input_sidecar_factory.restart(
        reference_socket,
        module="fortipam_mcp.reference_authority_sidecar",
        socket_environment_name="FORTIPAM_MCP_V4_REFERENCE_AUTHORITY_SOCKET",
        environment=reference_sidecar_environment,
    )
    restarted_client = approver_authority_sidecar_factory.start(
        database_path=authority_database,
        hmac_key_path=authority_key,
        checkpoint_socket_path=authority_checkpoint_socket,
        checkpoint_store_ref=authority_checkpoint_store_ref,
    )
    restarted_authenticator = approval_receipt_sidecar_factory.start(receipt_key)
    authenticator = restarted_authenticator
    components = build(restarted_client)
    workflow = components.plan_services._facade._workflow  # noqa: SLF001
    assert isinstance(components.scheme_draft_client, UnixSchemeDraftAuthorityClient)
    assert isinstance(components.reference_client, UnixReferenceAuthorityClient)
    assert workflow._approval_gate._approver_authorizer is restarted_client  # noqa: SLF001
    assert workflow._approval_gate._receipt_authenticator is restarted_authenticator  # noqa: SLF001
    assert workflow._store._approval_receipt_authenticator is restarted_authenticator  # noqa: SLF001
    claim = workflow.claim_approval(
        receipt.receipt_ref,
        plan.plan_ref,
        principal.requester,
    )
    assert claim.approval_validated is True
    assert claim.execution_authorized is False
    assert claim.ready_for_dispatch is False
    assert delegation_ref.encode("utf-8") not in authority_database.read_bytes()
    assert draft_ref.encode("utf-8") not in draft_database.read_bytes()
    assert all(
        grant_ref.encode("utf-8") not in reference_database.read_bytes()
        for grant_ref in reference_grant_refs
    )
    assert not delegation_input.exists()
    assert not delegation_output.exists()


def test_synthetic_host_rejects_invalid_or_key_reusing_approver_authority(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    planning_key = _owner_file(state / "planning.hmac", b"p" * 32)
    authority_key = _owner_file(state / "authority.hmac", b"d" * 32)
    authority = PersistentApproverAuthorizationAuthority(
        state / "authority.sqlite3",
        authority_key,
        authority_ref="v4-synthetic-approver-authority",
    )
    settings = V4SyntheticHostSettings(state / "planning.sqlite3", planning_key)
    with pytest.raises(V4RuntimeHostError, match="requires signed receipts"):
        synthetic_v4_plan_host_factory(
            settings,
            approver_authorization_authority=authority,
        )
    with pytest.raises(V4RuntimeHostError, match="rollback checkpoint"):
        synthetic_v4_plan_host_factory(
            settings,
            approval_receipt_authenticator=ApprovalReceiptAuthenticator(b"a" * 32),
            approver_authorization_authority=authority,
        )
    with pytest.raises(V4RuntimeHostError, match="binding is invalid"):
        synthetic_v4_plan_host_factory(
            settings,
            approval_receipt_authenticator=ApprovalReceiptAuthenticator(b"a" * 32),
            approver_authorization_authority=object(),  # type: ignore[arg-type]
        )

    reused_receipt_key = _owner_file(state / "reused-receipt.hmac", b"a" * 32)
    receipt_key_authority = PersistentApproverAuthorizationAuthority(
        state / "reused-receipt.sqlite3",
        reused_receipt_key,
        authority_ref="v4-reused-receipt-key-authority",
        monotonic_checkpoint=ApproverExternalCheckpoint(
            "v4-reused-receipt-checkpoint-store"
        ),
        checkpoint_store_ref="v4-reused-receipt-checkpoint-store",
    )
    with pytest.raises(V4RuntimeHostError, match="receipt HMAC keys"):
        synthetic_v4_plan_host_factory(
            settings,
            approval_receipt_authenticator=ApprovalReceiptAuthenticator(b"a" * 32),
            approver_authorization_authority=receipt_key_authority,
        )

    planning_key_authority = PersistentApproverAuthorizationAuthority(
        state / "reused-planning.sqlite3",
        planning_key,
        authority_ref="v4-reused-planning-key-authority",
        monotonic_checkpoint=ApproverExternalCheckpoint(
            "v4-reused-planning-checkpoint-store"
        ),
        checkpoint_store_ref="v4-reused-planning-checkpoint-store",
    )
    provider_state = tmp_path / "oauth"
    provider_state.mkdir(mode=0o700)
    os.chmod(provider_state, 0o700)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=provider_state / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(PASSWORD, salt=b"0123456789abcdef"),
        )
    )
    confirmation_key = _owner_file(state / "confirmation.hmac", b"c" * 32)
    browser_receipt_key = _owner_file(state / "browser-receipt.hmac", b"r" * 32)
    factory = synthetic_v4_plan_host_factory(
        settings,
        approval_receipt_authenticator=ApprovalReceiptAuthenticator(b"a" * 32),
        approver_authorization_authority=planning_key_authority,
    )
    with pytest.raises(V4RuntimeHostError, match="planning-store HMAC keys"):
        factory(
            provider,
            V4ConfirmationSettings(
                state / "confirmation.sqlite3",
                confirmation_key,
                browser_receipt_key,
            ),
        )


def test_persistent_reference_authority_binds_to_host_only_after_exact_grants(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    os.chmod(state, 0o700)
    oauth = tmp_path / "oauth"
    oauth.mkdir(mode=0o700)
    os.chmod(oauth, 0o700)
    planning_key = _owner_file(state / "planning.hmac", b"p" * 32)
    reference_key = _owner_file(state / "reference.hmac", b"r" * 32)
    confirmation_key = _owner_file(state / "confirmation.hmac", b"c" * 32)
    receipt_key = _owner_file(state / "receipt.hmac", b"e" * 32)
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(
                PASSWORD,
                salt=b"0123456789abcdef",
            ),
        )
    )
    requester = AuthenticatedRequester("a" * 64, "operator")
    principal = V4PlanningPrincipal(requester, "b" * 64)
    clock = MutableClock(NOW)
    reference_database = state / "reference.sqlite3"
    authority = PersistentReferenceAuthority(
        reference_database,
        reference_key,
        authority_ref=V4_PERSISTENT_REFERENCE_AUTHORITY_REF,
        clock=clock,
    )
    factory = synthetic_v4_plan_host_factory(
        V4SyntheticHostSettings(
            state / "planning.sqlite3",
            planning_key,
            V4PersistentReferenceAuthoritySettings(
                reference_database,
                reference_key,
            ),
        ),
        clock=clock,
    )
    confirmation_settings = V4ConfirmationSettings(
        state / "confirmation.sqlite3",
        confirmation_key,
        receipt_key,
    )
    components = factory(provider, confirmation_settings)

    with pytest.raises(PlanningDenied, match="Reference is not authorized"):
        components.plan_services.preview(V4_SYNTHETIC_SCHEME_REF, principal)

    grant_refs = issue_synthetic_reference_grants(
        authority,
        requester_digest=requester.digest,
        expires_at=NOW + 600,
        now_epoch=NOW,
    )
    assert grant_refs
    components = factory(provider, confirmation_settings)
    preview = components.plan_services.preview(V4_SYNTHETIC_SCHEME_REF, principal)

    assert preview["reference_authority_ref"] == V4_PERSISTENT_REFERENCE_AUTHORITY_REF
    assert preview["reference_authorization_expires_at"] == NOW + 60
    assert preview["expires_at"] == NOW + 60
    status = components.plan_services.status()
    assert status["reference_authorization_protocol_bound"] is True
    assert status["reference_authority_checkpoint_protocol_bound"] is False
    assert status["device_access"] is False
    assert status["dispatchable"] is False
    stored = reference_database.read_bytes()
    for value in (
        "synthetic-lab-environment",
        "synthetic-access-scope",
        "synthetic-owner-reference",
        "synthetic-public-folder-reference",
        *grant_refs,
    ):
        assert value.encode("utf-8") not in stored


@pytest.mark.parametrize("missing", [None, "reference", "draft", "host_mode"])
def test_target_bound_web_host_requires_authorities_and_selects_only_fixed_contract(monkeypatch, missing):
    from types import SimpleNamespace
    from fortipam_mcp import v4_runtime_host as module
    from test_target_bound_web_projection_reader import planning_source, Transport
    from v4_planning import ObjectClass, SchemeId

    _, source = planning_source(Transport())
    settings = SimpleNamespace(
        host_mode="source-backed-secret-onboarding", reference_authority=object(),
        reference_sidecar=None, scheme_draft_authority=object(), scheme_draft_sidecar=None,
    )
    if missing == "reference":
        settings.reference_authority = None
    elif missing == "draft":
        settings.scheme_draft_authority = None
    elif missing == "host_mode":
        settings.host_mode = "source-backed-onboarding"
    captured = {}
    def compose(actual_settings, **kwargs):
        assert actual_settings is settings
        captured.update(kwargs)
        return "factory"
    monkeypatch.setattr(module, "synthetic_v4_plan_host_factory", compose)
    if missing:
        with pytest.raises(V4RuntimeHostError):
            module.target_bound_web_v4_plan_host_factory(
                settings, binding=source._binding, secret_transport=source._transport,
            )
        assert captured == {}
        return
    assert module.target_bound_web_v4_plan_host_factory(
        settings, binding=source._binding, secret_transport=source._transport,
    ) == "factory"
    provider = captured["projection_provider_factory"](None)
    assert provider._binding == source._binding
    resolver = captured["projection_contract_resolver"]
    for cls in (ObjectClass.FOLDER_BINDING, ObjectClass.TEMPLATE_BINDING,
                ObjectClass.WEB_TARGET_BINDING, ObjectClass.TARGET_BOUND_WEB_SECRET_METADATA):
        assert resolver(SchemeId.SECRET_ONBOARDING, cls).object_class is cls
    with pytest.raises(V4RuntimeHostError):
        resolver(SchemeId.SECRET_ONBOARDING, ObjectClass.WEB_SECRET_METADATA)
    with pytest.raises(V4RuntimeHostError):
        resolver(SchemeId.ACCESS_DOMAIN, ObjectClass.FOLDER_BINDING)
