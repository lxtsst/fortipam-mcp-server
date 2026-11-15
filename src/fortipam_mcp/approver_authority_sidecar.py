"""Process-separated Unix-socket service for V4 Approver authorization."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import socket
import stat
from typing import Mapping, cast

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from v4_planning import (
    ApproverAuthorizationDecision,
    ApproverAuthorityError,
    AuthenticatedApprover,
    AuthenticatedRequester,
    ChangeKind,
    ObjectClass,
    PersistentApproverAuthorizationAuthority,
    PlanLine,
    PlanPolicyDecision,
    PlanState,
    PreparedPlan,
    SchemeId,
)
from v4_planning.models import PlanningContractError, require_ref

from .approver_checkpoint_sidecar import (
    UnixApproverCheckpointClient,
    UnixApproverCheckpointClientSettings,
)


APPROVER_AUTHORITY_DATABASE_ENV = "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_DATABASE"
APPROVER_AUTHORITY_HMAC_KEY_FILE_ENV = (
    "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_HMAC_KEY_FILE"
)
APPROVER_AUTHORITY_REF_ENV = "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_REF"
APPROVER_AUTHORITY_CHECKPOINT_SOCKET_ENV = (
    "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_CHECKPOINT_SOCKET"
)
APPROVER_AUTHORITY_CHECKPOINT_REF_ENV = (
    "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_CHECKPOINT_REF"
)
APPROVER_AUTHORITY_CHECKPOINT_STORE_REF_ENV = (
    "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_CHECKPOINT_STORE_REF"
)
APPROVER_AUTHORITY_SOCKET_ENV = "FORTIPAM_MCP_V4_APPROVER_AUTHORITY_SOCKET"
_MAX_BODY_BYTES = 65_536


class ApproverAuthoritySidecarError(ApproverAuthorityError):
    """Stable failure for the process-separated Approver Authority boundary."""


@dataclass(frozen=True, slots=True)
class ApproverAuthoritySidecarSettings:
    database_path: Path
    hmac_key_path: Path
    authority_ref: str
    checkpoint_socket_path: Path
    checkpoint_authority_ref: str
    checkpoint_store_ref: str
    socket_path: Path

    def __post_init__(self) -> None:
        paths = (
            self.database_path,
            self.hmac_key_path,
            self.checkpoint_socket_path,
            self.socket_path,
        )
        try:
            require_ref(self.authority_ref, "Approver Authority sidecar authority_ref")
            require_ref(
                self.checkpoint_authority_ref,
                "Approver Authority checkpoint authority_ref",
            )
            require_ref(
                self.checkpoint_store_ref,
                "Approver Authority checkpoint store_ref",
            )
        except PlanningContractError as exc:
            raise ApproverAuthoritySidecarError(
                "Approver Authority sidecar configuration is invalid."
            ) from exc
        if (
            self.authority_ref == self.checkpoint_authority_ref
            or any(not isinstance(path, Path) or not path.is_absolute() for path in paths)
            or len(set(paths)) != len(paths)
        ):
            raise ApproverAuthoritySidecarError(
                "Approver Authority sidecar configuration is invalid."
            )


@dataclass(frozen=True, slots=True)
class UnixApproverAuthorizationClientSettings:
    socket_path: Path
    authority_ref: str
    timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        try:
            require_ref(self.authority_ref, "Approver Authority client authority_ref")
        except PlanningContractError as exc:
            raise ApproverAuthoritySidecarError(
                "Approver Authority client configuration is invalid."
            ) from exc
        if (
            not isinstance(self.socket_path, Path)
            or not self.socket_path.is_absolute()
            or type(self.timeout_seconds) is not float
            or not 0.1 <= self.timeout_seconds <= 10.0
        ):
            raise ApproverAuthoritySidecarError(
                "Approver Authority client configuration is invalid."
            )


class UnixApproverAuthorizationClient:
    """Use exact Approver authorization through one owner-only UDS."""

    def __init__(self, settings: UnixApproverAuthorizationClientSettings) -> None:
        if not isinstance(settings, UnixApproverAuthorizationClientSettings):
            raise ApproverAuthoritySidecarError(
                "Approver Authority client configuration is invalid."
            )
        self._settings = settings
        self.authority_ref = settings.authority_ref

    @property
    def monotonic_checkpoint_protocol_bound(self) -> bool:
        """Report the mandatory checkpointed service contract."""

        return True

    def shares_key_material_with(self, candidate: object) -> bool:
        """The client owns no Authority HMAC key material to share."""

        del candidate
        return False

    def verify_ready(self) -> None:
        """Require the remote Authority and checkpoint to revalidate."""

        response = self._post(
            "/v1/approver-authority/ready",
            {"authority_ref": self.authority_ref},
        )
        if response.status_code != 204 or response.content:
            raise ApproverAuthoritySidecarError(
                "Approver Authority sidecar rejected readiness."
            )

    def authorize(
        self,
        plan: PreparedPlan,
        decision: PlanPolicyDecision,
        requester: AuthenticatedRequester,
        approver: AuthenticatedApprover,
        *,
        now_epoch: int,
    ) -> ApproverAuthorizationDecision:
        """Return one exact non-executable decision from the remote Authority."""

        response = self._post(
            "/v1/approver-authority/authorize",
            {
                "approver": _approver_payload(approver),
                "authority_ref": self.authority_ref,
                "now_epoch": now_epoch,
                "plan": _plan_payload(plan),
                "policy_decision": _policy_payload(decision),
                "requester": _requester_payload(requester),
            },
        )
        if response.status_code != 200:
            raise ApproverAuthoritySidecarError(
                "Approver Authority sidecar rejected authorization."
            )
        try:
            value = response.json()
            mapping = _mapping(value, {"decision"})
            return _authorization_from_payload(mapping["decision"])
        except (ValueError, TypeError, PlanningContractError):
            raise ApproverAuthoritySidecarError(
                "Approver Authority sidecar response is invalid."
            ) from None

    def _post(self, path: str, payload: dict[str, object]) -> httpx.Response:
        _assert_owner_only_socket(self._settings.socket_path)
        transport = httpx.HTTPTransport(uds=str(self._settings.socket_path))
        try:
            with httpx.Client(
                transport=transport,
                base_url="http://approver-authority-sidecar",
                timeout=self._settings.timeout_seconds,
                trust_env=False,
            ) as client:
                return client.post(path, json=payload)
        except (httpx.HTTPError, OSError):
            raise ApproverAuthoritySidecarError(
                "Approver Authority sidecar is unavailable."
            ) from None


def create_approver_authority_sidecar_app(
    authority: PersistentApproverAuthorizationAuthority,
) -> Starlette:
    """Create readiness and exact authorization routes only."""

    if not isinstance(authority, PersistentApproverAuthorizationAuthority):
        raise ApproverAuthoritySidecarError(
            "Approver Authority sidecar Authority is invalid."
        )

    async def ready(request: Request) -> Response:
        try:
            payload = await _payload(request)
            if payload != {"authority_ref": authority.authority_ref}:
                raise ApproverAuthoritySidecarError(
                    "Approver Authority request is invalid."
                )
            authority.verify_ready()
        except (ApproverAuthorityError, PlanningContractError):
            return JSONResponse({"status": "rejected"}, status_code=409)
        return Response(status_code=204)

    async def authorize(request: Request) -> Response:
        try:
            payload = await _payload(request)
            expected = {
                "approver",
                "authority_ref",
                "now_epoch",
                "plan",
                "policy_decision",
                "requester",
            }
            if set(payload) != expected or payload["authority_ref"] != authority.authority_ref:
                raise ApproverAuthoritySidecarError(
                    "Approver Authority request is invalid."
                )
            decision = authority.authorize(
                _plan_from_payload(payload["plan"]),
                _policy_from_payload(payload["policy_decision"]),
                _requester_from_payload(payload["requester"]),
                _approver_from_payload(payload["approver"]),
                now_epoch=_integer(payload, "now_epoch"),
            )
        except (ApproverAuthorityError, PlanningContractError, TypeError, ValueError):
            return JSONResponse({"status": "rejected"}, status_code=409)
        return JSONResponse({"decision": _authorization_payload(decision)})

    return Starlette(
        routes=(
            Route("/v1/approver-authority/ready", ready, methods=["POST"]),
            Route(
                "/v1/approver-authority/authorize",
                authorize,
                methods=["POST"],
            ),
        )
    )


def authority_sidecar_settings_from_environment(
    environment: Mapping[str, str],
) -> ApproverAuthoritySidecarSettings:
    """Load one complete service configuration without reading key content."""

    names = (
        APPROVER_AUTHORITY_DATABASE_ENV,
        APPROVER_AUTHORITY_HMAC_KEY_FILE_ENV,
        APPROVER_AUTHORITY_REF_ENV,
        APPROVER_AUTHORITY_CHECKPOINT_SOCKET_ENV,
        APPROVER_AUTHORITY_CHECKPOINT_REF_ENV,
        APPROVER_AUTHORITY_CHECKPOINT_STORE_REF_ENV,
        APPROVER_AUTHORITY_SOCKET_ENV,
    )
    values = {name: _value(environment, name) for name in names}
    if any(value is None for value in values.values()):
        raise ApproverAuthoritySidecarError(
            "Approver Authority sidecar configuration is incomplete."
        )
    return ApproverAuthoritySidecarSettings(
        database_path=Path(
            cast(str, values[APPROVER_AUTHORITY_DATABASE_ENV])
        ).expanduser(),
        hmac_key_path=Path(
            cast(str, values[APPROVER_AUTHORITY_HMAC_KEY_FILE_ENV])
        ).expanduser(),
        authority_ref=cast(str, values[APPROVER_AUTHORITY_REF_ENV]),
        checkpoint_socket_path=Path(
            cast(str, values[APPROVER_AUTHORITY_CHECKPOINT_SOCKET_ENV])
        ).expanduser(),
        checkpoint_authority_ref=cast(
            str,
            values[APPROVER_AUTHORITY_CHECKPOINT_REF_ENV],
        ),
        checkpoint_store_ref=cast(
            str,
            values[APPROVER_AUTHORITY_CHECKPOINT_STORE_REF_ENV],
        ),
        socket_path=Path(
            cast(str, values[APPROVER_AUTHORITY_SOCKET_ENV])
        ).expanduser(),
    )


async def _payload(request: Request) -> dict[str, object]:
    if request.headers.get("content-type", "").split(";", 1)[0] != "application/json":
        raise ApproverAuthoritySidecarError(
            "Approver Authority request is invalid."
        )
    body = await request.body()
    if not body or len(body) > _MAX_BODY_BYTES:
        raise ApproverAuthoritySidecarError(
            "Approver Authority request is invalid."
        )
    try:
        value = await request.json()
    except Exception:
        raise ApproverAuthoritySidecarError(
            "Approver Authority request is invalid."
        ) from None
    return _mapping(value)


def _plan_payload(plan: PreparedPlan) -> dict[str, object]:
    if not isinstance(plan, PreparedPlan):
        raise ApproverAuthoritySidecarError(
            "Approver Authority plan is invalid."
        )
    payload = cast(dict[str, object], plan.canonical_content())
    payload["plan_digest"] = plan.plan_digest
    payload["state"] = plan.state.value
    return payload


def _plan_from_payload(value: object) -> PreparedPlan:
    keys = {
        "adapter_registry_bound",
        "confirmation_digest",
        "confirmation_ref",
        "created_at",
        "dispatchable",
        "environment_ref",
        "executor_mcp_exposed",
        "executor_runtime_packaged",
        "expires_at",
        "lines",
        "plan_digest",
        "plan_ref",
        "planner_mcp_exposed",
        "planner_runtime_packaged",
        "registry_schema_version",
        "requester_digest",
        "revision",
        "scheme_id",
        "scheme_version",
        "scope_ref",
        "state",
        "summary_digest",
        "summary_ref",
        "summary_revision",
    }
    item = _mapping(value, keys)
    lines = item["lines"]
    if type(lines) is not list or not 1 <= len(lines) <= 19:
        raise ApproverAuthoritySidecarError("Approver Authority plan is invalid.")
    return PreparedPlan(
        plan_ref=_string(item, "plan_ref"),
        revision=_integer(item, "revision"),
        state=PlanState(_string(item, "state")),
        summary_ref=_string(item, "summary_ref"),
        summary_revision=_integer(item, "summary_revision"),
        summary_digest=_string(item, "summary_digest"),
        confirmation_ref=_string(item, "confirmation_ref"),
        confirmation_digest=_string(item, "confirmation_digest"),
        requester_digest=_string(item, "requester_digest"),
        environment_ref=_string(item, "environment_ref"),
        scope_ref=_string(item, "scope_ref"),
        scheme_id=SchemeId(_string(item, "scheme_id")),
        scheme_version=_string(item, "scheme_version"),
        registry_schema_version=_string(item, "registry_schema_version"),
        created_at=_integer(item, "created_at"),
        expires_at=_integer(item, "expires_at"),
        lines=tuple(_line_from_payload(line) for line in lines),
        dispatchable=_boolean(item, "dispatchable"),
        adapter_registry_bound=_boolean(item, "adapter_registry_bound"),
        planner_runtime_packaged=_boolean(item, "planner_runtime_packaged"),
        planner_mcp_exposed=_boolean(item, "planner_mcp_exposed"),
        executor_runtime_packaged=_boolean(item, "executor_runtime_packaged"),
        executor_mcp_exposed=_boolean(item, "executor_mcp_exposed"),
        plan_digest=_string(item, "plan_digest"),
    )


def _line_from_payload(value: object) -> PlanLine:
    keys = {
        "action_family_ref",
        "action_family_version",
        "adapter",
        "change_kind",
        "depends_on",
        "dispatchable",
        "expected_current_digest",
        "expected_state_digest",
        "line_ref",
        "projection_contract_ref",
        "target_class",
        "target_ref",
    }
    item = _mapping(value, keys)
    dependencies = item["depends_on"]
    if type(dependencies) is not list or not all(
        type(dependency) is str for dependency in dependencies
    ):
        raise ApproverAuthoritySidecarError("Approver Authority plan is invalid.")
    return PlanLine(
        line_ref=_string(item, "line_ref"),
        action_family_ref=_string(item, "action_family_ref"),
        action_family_version=_string(item, "action_family_version"),
        target_ref=_string(item, "target_ref"),
        target_class=ObjectClass(_string(item, "target_class")),
        change_kind=ChangeKind(_string(item, "change_kind")),
        expected_current_digest=_string(item, "expected_current_digest"),
        expected_state_digest=_string(item, "expected_state_digest"),
        projection_contract_ref=_string(item, "projection_contract_ref"),
        depends_on=tuple(cast(list[str], dependencies)),
        dispatchable=_boolean(item, "dispatchable"),
        adapter=_string(item, "adapter"),
    )


def _policy_payload(decision: PlanPolicyDecision) -> dict[str, object]:
    if not isinstance(decision, PlanPolicyDecision):
        raise ApproverAuthoritySidecarError(
            "Approver Authority policy decision is invalid."
        )
    payload = cast(dict[str, object], decision.canonical_content())
    payload["decision_digest"] = decision.decision_digest
    return payload


def _policy_from_payload(value: object) -> PlanPolicyDecision:
    keys = {
        "approval_class",
        "decision_digest",
        "decision_ref",
        "execution_authorized",
        "expires_at",
        "issued_at",
        "outcome",
        "plan_digest",
        "plan_ref",
        "policy_version",
        "requester_digest",
        "requester_subject_digest",
        "separation_required",
    }
    item = _mapping(value, keys)
    return PlanPolicyDecision(
        decision_ref=_string(item, "decision_ref"),
        plan_ref=_string(item, "plan_ref"),
        plan_digest=_string(item, "plan_digest"),
        requester_digest=_string(item, "requester_digest"),
        requester_subject_digest=_string(item, "requester_subject_digest"),
        outcome=_string(item, "outcome"),
        approval_class=_string(item, "approval_class"),
        separation_required=_boolean(item, "separation_required"),
        execution_authorized=_boolean(item, "execution_authorized"),
        policy_version=_string(item, "policy_version"),
        issued_at=_integer(item, "issued_at"),
        expires_at=_integer(item, "expires_at"),
        decision_digest=_string(item, "decision_digest"),
    )


def _requester_payload(requester: AuthenticatedRequester) -> dict[str, object]:
    if not isinstance(requester, AuthenticatedRequester):
        raise ApproverAuthoritySidecarError(
            "Approver Authority requester is invalid."
        )
    return {
        "identity_authority_ref": requester.identity_authority_ref,
        "principal_class": requester.principal_class,
        "subject_namespace": requester.subject_namespace,
        "subject_ref": requester.subject_ref,
    }


def _requester_from_payload(value: object) -> AuthenticatedRequester:
    item = _identity_mapping(value)
    return AuthenticatedRequester(
        subject_ref=_string(item, "subject_ref"),
        principal_class=_string(item, "principal_class"),
        identity_authority_ref=_optional_string(item, "identity_authority_ref"),
        subject_namespace=_optional_string(item, "subject_namespace"),
    )


def _approver_payload(approver: AuthenticatedApprover) -> dict[str, object]:
    if not isinstance(approver, AuthenticatedApprover):
        raise ApproverAuthoritySidecarError(
            "Approver Authority approver is invalid."
        )
    return {
        "identity_authority_ref": approver.identity_authority_ref,
        "principal_class": approver.principal_class,
        "subject_namespace": approver.subject_namespace,
        "subject_ref": approver.subject_ref,
    }


def _approver_from_payload(value: object) -> AuthenticatedApprover:
    item = _identity_mapping(value)
    return AuthenticatedApprover(
        subject_ref=_string(item, "subject_ref"),
        principal_class=_string(item, "principal_class"),
        identity_authority_ref=_optional_string(item, "identity_authority_ref"),
        subject_namespace=_optional_string(item, "subject_namespace"),
    )


def _identity_mapping(value: object) -> dict[str, object]:
    return _mapping(
        value,
        {
            "identity_authority_ref",
            "principal_class",
            "subject_namespace",
            "subject_ref",
        },
    )


def _authorization_payload(
    decision: ApproverAuthorizationDecision,
) -> dict[str, object]:
    payload = cast(dict[str, object], decision.canonical_content())
    payload["authorization_digest"] = decision.authorization_digest
    return payload


def _authorization_from_payload(value: object) -> ApproverAuthorizationDecision:
    keys = {
        "action_set_digest",
        "approval_class",
        "approver_digest",
        "approver_identity_digest",
        "authority_ref",
        "authorization_digest",
        "authorization_ref",
        "authorized",
        "checked_at",
        "delegated_role",
        "delegation_digest",
        "environment_digest",
        "execution_authorized",
        "executor_separation_required",
        "expires_at",
        "identity_authority_ref",
        "plan_digest",
        "plan_ref",
        "policy_decision_digest",
        "policy_decision_ref",
        "policy_version",
        "requester_digest",
        "requester_identity_digest",
        "scope_digest",
        "separation_required",
        "subject_namespace",
    }
    item = _mapping(value, keys)
    return ApproverAuthorizationDecision(
        authorization_ref=_string(item, "authorization_ref"),
        authority_ref=_string(item, "authority_ref"),
        plan_ref=_string(item, "plan_ref"),
        plan_digest=_string(item, "plan_digest"),
        policy_decision_ref=_string(item, "policy_decision_ref"),
        policy_decision_digest=_string(item, "policy_decision_digest"),
        policy_version=_string(item, "policy_version"),
        requester_digest=_string(item, "requester_digest"),
        requester_identity_digest=_string(item, "requester_identity_digest"),
        approver_digest=_string(item, "approver_digest"),
        approver_identity_digest=_string(item, "approver_identity_digest"),
        identity_authority_ref=_string(item, "identity_authority_ref"),
        subject_namespace=_string(item, "subject_namespace"),
        environment_digest=_string(item, "environment_digest"),
        scope_digest=_string(item, "scope_digest"),
        action_set_digest=_string(item, "action_set_digest"),
        delegation_digest=_string(item, "delegation_digest"),
        delegated_role=_string(item, "delegated_role"),
        approval_class=_string(item, "approval_class"),
        separation_required=_boolean(item, "separation_required"),
        executor_separation_required=_boolean(
            item,
            "executor_separation_required",
        ),
        authorized=_boolean(item, "authorized"),
        execution_authorized=_boolean(item, "execution_authorized"),
        checked_at=_integer(item, "checked_at"),
        expires_at=_integer(item, "expires_at"),
        authorization_digest=_string(item, "authorization_digest"),
    )


def _mapping(
    value: object,
    keys: set[str] | None = None,
) -> dict[str, object]:
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise ApproverAuthoritySidecarError("Approver Authority value is invalid.")
    item = cast(dict[str, object], value)
    if keys is not None and set(item) != keys:
        raise ApproverAuthoritySidecarError("Approver Authority value is invalid.")
    return item


def _string(value: Mapping[str, object], name: str) -> str:
    item = value.get(name)
    if type(item) is not str:
        raise ApproverAuthoritySidecarError("Approver Authority value is invalid.")
    return item


def _optional_string(value: Mapping[str, object], name: str) -> str | None:
    item = value.get(name)
    if item is not None and type(item) is not str:
        raise ApproverAuthoritySidecarError("Approver Authority value is invalid.")
    return cast(str | None, item)


def _integer(value: Mapping[str, object], name: str) -> int:
    item = value.get(name)
    if type(item) is not int:
        raise ApproverAuthoritySidecarError("Approver Authority value is invalid.")
    return item


def _boolean(value: Mapping[str, object], name: str) -> bool:
    item = value.get(name)
    if type(item) is not bool:
        raise ApproverAuthoritySidecarError("Approver Authority value is invalid.")
    return item


def _assert_owner_only_socket(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise ApproverAuthoritySidecarError(
            "Approver Authority sidecar is unavailable."
        ) from None
    if (
        path.is_symlink()
        or not stat.S_ISSOCK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ApproverAuthoritySidecarError(
            "Approver Authority sidecar boundary is invalid."
        )


def _assert_owner_only_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ApproverAuthoritySidecarError(
            "Approver Authority sidecar directory is unavailable."
        ) from exc
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ApproverAuthoritySidecarError(
            "Approver Authority sidecar directory must be owner-only."
        )


def _value(environment: Mapping[str, str], name: str) -> str | None:
    raw = environment.get(name)
    if type(raw) is not str:
        return None
    value = raw.strip()
    return value or None


def main() -> None:
    """Run the Approver Authority on one owner-only Unix-domain socket."""

    import uvicorn

    settings = authority_sidecar_settings_from_environment(os.environ)
    _assert_owner_only_directory(settings.socket_path.parent)
    if settings.socket_path.exists() or settings.socket_path.is_symlink():
        raise ApproverAuthoritySidecarError(
            "Approver Authority sidecar socket already exists."
        )
    checkpoint = UnixApproverCheckpointClient(
        UnixApproverCheckpointClientSettings(
            settings.checkpoint_socket_path,
            settings.checkpoint_authority_ref,
        )
    )
    authority = PersistentApproverAuthorizationAuthority(
        settings.database_path,
        settings.hmac_key_path,
        authority_ref=settings.authority_ref,
        monotonic_checkpoint=checkpoint,
        checkpoint_store_ref=settings.checkpoint_store_ref,
    )
    os.umask(0o177)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(settings.socket_path))
        settings.socket_path.chmod(0o600)
        listener.listen(128)
        config = uvicorn.Config(
            create_approver_authority_sidecar_app(authority),
            access_log=False,
            log_level="warning",
        )
        uvicorn.Server(config).run(sockets=[listener])
    finally:
        listener.close()
        if settings.socket_path.exists() and not settings.socket_path.is_symlink():
            settings.socket_path.unlink()


if __name__ == "__main__":
    main()


__all__ = [
    "ApproverAuthoritySidecarError",
    "ApproverAuthoritySidecarSettings",
    "UnixApproverAuthorizationClient",
    "UnixApproverAuthorizationClientSettings",
    "authority_sidecar_settings_from_environment",
    "create_approver_authority_sidecar_app",
]
