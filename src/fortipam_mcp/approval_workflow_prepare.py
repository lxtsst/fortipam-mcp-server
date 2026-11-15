"""Prepare one private BP008 approval-policy bundle without issuing authority."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import secrets
import stat
import sys
from typing import Literal, Mapping, cast

from v4_planning import (
    DesiredObject,
    FieldKind,
    ObjectClass,
    SchemeDraft,
    SchemeId,
    scheme_draft_as_mapping,
)
from v4_planning.canonical import canonical_json
from v4_planning.models import require_digest, require_ref

from .approval_and_observe_projection_source import (
    ApprovalAndObserveBinding,
    SOURCE_CONTRACT,
    SOURCE_REF,
    SOURCE_VERSION,
    approval_and_observe_projection_contract,
)
from .secret_request_http_transport import (
    REQUEST_BINDING_CONTRACT,
    REQUEST_BINDING_VERSION,
    SecretRequestObservationBinding,
)
from .secret_request_create_contract import (
    SecretRequestCreateContractError,
    SecretRequestCreateInput,
    SecretRequestCustomField,
)
from .secret_request_create_http_transport import (
    REQUEST_CREATE_INTENT_CONTRACT,
    REQUEST_CREATE_INTENT_VERSION,
)


PROFILE_PATH_ENV = "FORTIPAM_MCP_V4_APPROVAL_WORKFLOW_PROFILE"
OUTPUT_DIRECTORY_ENV = "FORTIPAM_MCP_V4_APPROVAL_WORKFLOW_OUTPUT_DIR"
PROFILE_CONTRACT = "fortipam-approval-workflow-private-profile-v1"
PROFILE_VERSION = "1.0.0"
PROFILE_OBSERVATION_VERSION = "1.1.0"
PROFILE_REQUEST_CREATE_VERSION = "1.2.0"
BINDING_NAME = "approval-and-observe-binding.json"
OBSERVATION_BINDING_NAME = "secret-request-observation-binding.json"
OBSERVATION_REF_NAME = "secret-request-observation-ref.json"
CREATE_INTENT_BINDING_NAME = "secret-request-create-intent.json"
CREATE_INTENT_REF_NAME = "secret-request-create-intent-ref.json"
DRAFT_INPUT_NAME = "scheme-draft-bootstrap-input.json"
REFERENCE_INPUT_NAME = "reference-bootstrap-input.json"
_MAX_PROFILE_BYTES = 524_288


class ApprovalWorkflowPrepareError(RuntimeError):
    """Stable failure for the private BP008 preparation boundary."""


@dataclass(frozen=True, slots=True)
class ApprovalWorkflowPrepareSettings:
    profile_path: Path
    output_directory: Path

    def __post_init__(self) -> None:
        if (
            not self.profile_path.is_absolute()
            or not self.output_directory.is_absolute()
            or self.profile_path == self.output_directory
        ):
            raise ApprovalWorkflowPrepareError(
                "Approval workflow preparation configuration is invalid."
            )


def settings_from_environment(
    environment: Mapping[str, str],
) -> ApprovalWorkflowPrepareSettings:
    """Load the two protected paths without accepting inline profile content."""

    profile = _environment_value(environment, PROFILE_PATH_ENV)
    output = _environment_value(environment, OUTPUT_DIRECTORY_ENV)
    if profile is None or output is None:
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation configuration is incomplete."
        )
    return ApprovalWorkflowPrepareSettings(
        Path(profile).expanduser(),
        Path(output).expanduser(),
    )


def prepare_approval_workflow_bundle(
    settings: ApprovalWorkflowPrepareSettings,
) -> None:
    """Create one binding and two Authority inputs without disclosing values."""

    if not isinstance(settings, ApprovalWorkflowPrepareSettings):
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation configuration is invalid."
        )
    _assert_owner_only(settings.profile_path.parent, directory=True)
    _assert_owner_only(settings.profile_path, directory=False)
    _assert_owner_only(settings.output_directory, directory=True)
    bundle = _build_bundle(_load_profile(settings.profile_path))
    allowed_names = {
        BINDING_NAME,
        DRAFT_INPUT_NAME,
        REFERENCE_INPUT_NAME,
        OBSERVATION_BINDING_NAME,
        OBSERVATION_REF_NAME,
        CREATE_INTENT_BINDING_NAME,
        CREATE_INTENT_REF_NAME,
    }
    base_names = {BINDING_NAME, DRAFT_INPUT_NAME, REFERENCE_INPUT_NAME}
    if frozenset(bundle) not in {
        frozenset(base_names),
        frozenset(base_names | {OBSERVATION_BINDING_NAME, OBSERVATION_REF_NAME}),
        frozenset(base_names | {CREATE_INTENT_BINDING_NAME, CREATE_INTENT_REF_NAME}),
    }:
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation output is unavailable."
        )
    paths = {name: settings.output_directory / name for name in bundle}
    reserved_paths = (
        settings.output_directory / name for name in allowed_names
    )
    if any(path.exists() or path.is_symlink() for path in reserved_paths):
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation output is unavailable."
        )
    created: list[Path] = []
    try:
        for name, path in paths.items():
            _write_private_json(
                path,
                bundle[name],
                canonical=name != CREATE_INTENT_BINDING_NAME,
            )
            created.append(path)
    except ApprovalWorkflowPrepareError:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise


def _build_bundle(profile: Mapping[str, object]) -> dict[str, dict[str, object]]:
    base_fields = {
        "contract",
        "version",
        "requester_digest",
        "environment_ref",
        "scope_ref",
        "expires_at",
        "approval_profile_name",
        "folder_path",
        "secret_name",
        "secret_id",
    }
    version = _string(profile, "version")
    create_fields = {
        "fortipam_requester",
        "request_type",
        "start_after_approve",
        "start_time",
        "expiration_time",
        "duration",
        "comments",
        "timezone",
        "job_name",
        "custom_fields",
    }
    expected_by_version = {
        PROFILE_VERSION: base_fields,
        PROFILE_OBSERVATION_VERSION: base_fields | {"request_id", "request_type"},
        PROFILE_REQUEST_CREATE_VERSION: base_fields | create_fields,
    }
    expected = expected_by_version.get(version)
    if (
        expected is None
        or set(profile) != expected
        or profile.get("contract") != PROFILE_CONTRACT
    ):
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        )
    requester_digest = _digest(profile, "requester_digest")
    environment_ref = _ref(profile, "environment_ref")
    scope_ref = _ref(profile, "scope_ref")
    expires_at = _integer(profile, "expires_at")
    secret_id = _integer(profile, "secret_id")
    if expires_at <= 0 or not 0 < secret_id <= 2_147_483_647:
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        )

    approval_profile_name = _selector(profile, "approval_profile_name", 128)
    folder_path = _selector(profile, "folder_path", 1024)
    secret_name = _selector(profile, "secret_name", 128)
    if any(part in {"", ".", ".."} for part in folder_path.split("/")):
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        )

    owner_ref = _new_ref("owner")
    audience_ref = _new_ref("audience")
    evidence_ref = _new_ref("evidence")
    approval_profile_object_ref = _new_ref("approval-profile-binding")
    approval_profile_ref = _new_ref("approval-profile")
    secret_approval_object_ref = _new_ref("secret-approval-binding")
    binding = ApprovalAndObserveBinding(
        approval_profile_object_ref=approval_profile_object_ref,
        approval_profile_ref=approval_profile_ref,
        approval_profile_name=approval_profile_name,
        secret_approval_object_ref=secret_approval_object_ref,
        folder_path=folder_path,
        secret_name=secret_name,
        secret_id=secret_id,
    )
    draft = SchemeDraft(
        scheme_id=SchemeId.APPROVAL_AND_OBSERVE,
        scheme_version="1.0.0",
        registry_schema_version="1.1.0",
        blueprint_ref="FPA-BP-008",
        environment_ref=environment_ref,
        scope_ref=scope_ref,
        owner_ref=owner_ref,
        audience_ref=audience_ref,
        outcome_code="require_interactive_approval",
        desired_objects=(
            _desired(
                approval_profile_object_ref,
                ObjectClass.APPROVAL_PROFILE_BINDING,
                {
                    "profile_mode": "single_tier",
                    "profile_ref": approval_profile_ref,
                },
            ),
            _desired(
                secret_approval_object_ref,
                ObjectClass.SECRET_APPROVAL_BINDING,
                {
                    "approval_profile_attached": True,
                    "interactive_approval_required": True,
                    "job_approval_required": False,
                    "owner_bypass_allowed": False,
                },
            ),
        ),
        approval_class="independent_approval",
        separation_required=True,
        risk_class="high",
        external_effects=("interactive_approval_policy_change",),
        assumption_codes=("single_tier_profile_prevalidated",),
        excluded_scope_codes=("approval_request", "session_launch"),
        verification_codes=("secret_approval_relation_readback",),
        stop_codes=("current_state_drift", "projection_unavailable"),
        evidence_policy="redacted_contract_evidence",
        maintenance_class="none",
        reversibility_class="manual_reconciliation_only",
        evidence_refs=(evidence_ref,),
        unresolved_gap_codes=(),
        reconciliation_strategy="reconcile_or_manual",
        summary_ttl_seconds=300,
    )
    bundle: dict[str, dict[str, object]] = {
        BINDING_NAME: {
            "contract": SOURCE_CONTRACT,
            "version": SOURCE_VERSION,
            "requester_digest": requester_digest,
            "environment_ref": environment_ref,
            "scope_ref": scope_ref,
            **asdict(binding),
        },
        DRAFT_INPUT_NAME: {
            "draft": scheme_draft_as_mapping(draft),
            "expires_at": expires_at,
            "requester_digest": requester_digest,
        },
        REFERENCE_INPUT_NAME: {
            "references": _reference_bindings(draft),
            "requester_digest": requester_digest,
            "environment_ref": environment_ref,
            "scope_ref": scope_ref,
            "expires_at": expires_at,
        },
    }
    if version == PROFILE_OBSERVATION_VERSION:
        request_id = _integer(profile, "request_id")
        request_type = _string(profile, "request_type")
        if (
            not 0 < request_id <= 2_147_483_647
            or request_type not in {"launcher", "job"}
        ):
            raise ApprovalWorkflowPrepareError(
                "Approval workflow preparation input is invalid."
            )
        request_ref = _new_ref("request-observation")
        observation = SecretRequestObservationBinding(
            request_ref=request_ref,
            request_id=request_id,
            secret_id=secret_id,
            requester_digest=requester_digest,
            environment_ref=environment_ref,
            scope_ref=scope_ref,
            request_type=cast(Literal["launcher", "job"], request_type),
        )
        bundle[OBSERVATION_BINDING_NAME] = {
            "contract": REQUEST_BINDING_CONTRACT,
            "version": REQUEST_BINDING_VERSION,
            **asdict(observation),
        }
        bundle[OBSERVATION_REF_NAME] = {"request_ref": request_ref}
    elif version == PROFILE_REQUEST_CREATE_VERSION:
        try:
            request = SecretRequestCreateInput(
                requester=_string(profile, "fortipam_requester"),
                secret_id=secret_id,
                request_type=_request_type(profile),
                start_after_approve=_start_after_approve(profile),
                start_time=_string(profile, "start_time"),
                expiration_time=_string(profile, "expiration_time"),
                duration=_integer(profile, "duration"),
                comments=_string(profile, "comments"),
                timezone=_string(profile, "timezone"),
                job_name=_optional_string(profile, "job_name"),
                custom_fields=_request_custom_fields(profile),
            )
        except SecretRequestCreateContractError:
            raise ApprovalWorkflowPrepareError(
                "Approval workflow preparation input is invalid."
            ) from None
        intent_ref = _new_ref("request-create-intent")
        bundle[CREATE_INTENT_BINDING_NAME] = {
            "contract": REQUEST_CREATE_INTENT_CONTRACT,
            "version": REQUEST_CREATE_INTENT_VERSION,
            "intent_ref": intent_ref,
            "fortipam_requester": request.requester,
            "requester_digest": requester_digest,
            "environment_ref": environment_ref,
            "scope_ref": scope_ref,
            "expires_at": expires_at,
            "submission_mode": "same_requester",
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
        bundle[CREATE_INTENT_REF_NAME] = {"intent_ref": intent_ref}
    return bundle


def _reference_bindings(draft: SchemeDraft) -> list[dict[str, str]]:
    values: set[tuple[str, str]] = {
        (draft.environment_ref, "environment"),
        (draft.scope_ref, "scope"),
        (draft.owner_ref, "owner"),
        (draft.audience_ref, "audience"),
        *((item, "evidence") for item in draft.evidence_refs),
        (SOURCE_REF, "projection_source"),
    }
    for item in draft.desired_objects:
        kind = (
            "approval_profile_binding"
            if item.object_class is ObjectClass.APPROVAL_PROFILE_BINDING
            else "secret_approval_binding"
        )
        values.add((item.object_ref, f"object_{kind}"))
        contract = approval_and_observe_projection_contract(item.object_class)
        values.update(
            (value, f"field_{name}")
            for name, value in item.desired_fields
            if contract.rules[name].kind is FieldKind.REFERENCE
            and type(value) is str
        )
    return [
        {"reference": reference, "reference_kind": kind}
        for reference, kind in sorted(values)
    ]


def _desired(
    object_ref: str,
    object_class: ObjectClass,
    fields: Mapping[str, bool | str],
) -> DesiredObject:
    return DesiredObject(object_ref, object_class, True, tuple(sorted(fields.items())))


def _new_ref(kind: str) -> str:
    return f"bp008-{kind}-{secrets.token_hex(12)}"


def _load_profile(path: Path) -> Mapping[str, object]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    content = bytearray()
    try:
        descriptor = os.open(path, flags)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or not 0 < metadata.st_size <= _MAX_PROFILE_BYTES
            ):
                raise ApprovalWorkflowPrepareError(
                    "Approval workflow preparation input is unavailable."
                )
            content = bytearray(os.read(descriptor, _MAX_PROFILE_BYTES + 1))
        finally:
            os.close(descriptor)
        value = json.loads(content)
    except ApprovalWorkflowPrepareError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is unavailable."
        ) from None
    finally:
        for index in range(len(content)):
            content[index] = 0
    if type(value) is not dict or not all(type(key) is str for key in value):
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        )
    return cast(dict[str, object], value)


def _write_private_json(
    path: Path,
    value: Mapping[str, object],
    *,
    canonical: bool = True,
) -> None:
    encoded = (
        canonical_json(value)
        if canonical
        else json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    content = bytearray(encoded.encode("utf-8") + b"\n")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        try:
            offset = 0
            while offset < len(content):
                offset += os.write(descriptor, content[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chmod(path, 0o600)
    except OSError:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation output is unavailable."
        ) from None
    finally:
        for index in range(len(content)):
            content[index] = 0


def _assert_owner_only(path: Path, *, directory: bool) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation protected path is unavailable."
        ) from None
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        path.is_symlink()
        or not expected_type(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation protected path must be owner-only."
        )


def _environment_value(environment: Mapping[str, str], name: str) -> str | None:
    value = environment.get(name)
    if type(value) is not str or not value.strip():
        return None
    return value.strip()


def _string(mapping: Mapping[str, object], name: str) -> str:
    value = mapping.get(name)
    if type(value) is not str:
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        )
    return value


def _selector(mapping: Mapping[str, object], name: str, maximum: int) -> str:
    value = _string(mapping, name)
    if (
        not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        )
    return value


def _integer(mapping: Mapping[str, object], name: str) -> int:
    value = mapping.get(name)
    if type(value) is not int:
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        )
    return value


def _optional_string(mapping: Mapping[str, object], name: str) -> str | None:
    value = mapping.get(name)
    if value is not None and type(value) is not str:
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        )
    return value


def _request_type(
    mapping: Mapping[str, object],
) -> Literal["launcher", "job"]:
    value = _string(mapping, "request_type")
    if value not in {"launcher", "job"}:
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        )
    return cast(Literal["launcher", "job"], value)


def _start_after_approve(
    mapping: Mapping[str, object],
) -> Literal["enable", "disable"]:
    value = _string(mapping, "start_after_approve")
    if value not in {"enable", "disable"}:
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        )
    return cast(Literal["enable", "disable"], value)


def _request_custom_fields(
    mapping: Mapping[str, object],
) -> tuple[SecretRequestCustomField, ...]:
    value = mapping.get("custom_fields")
    if type(value) is not list:
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        )
    result: list[SecretRequestCustomField] = []
    for item in value:
        if type(item) is not dict or set(item) != {"name", "value", "required"}:
            raise ApprovalWorkflowPrepareError(
                "Approval workflow preparation input is invalid."
            )
        required = item.get("required")
        if type(required) is not bool:
            raise ApprovalWorkflowPrepareError(
                "Approval workflow preparation input is invalid."
            )
        result.append(
            SecretRequestCustomField(
                name=_string(item, "name"),
                value=_string(item, "value"),
                required=required,
            )
        )
    return tuple(result)


def _ref(mapping: Mapping[str, object], name: str) -> str:
    try:
        return require_ref(_string(mapping, name), name)
    except ValueError:
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        ) from None


def _digest(mapping: Mapping[str, object], name: str) -> str:
    try:
        return require_digest(_string(mapping, name), name)
    except ValueError:
        raise ApprovalWorkflowPrepareError(
            "Approval workflow preparation input is invalid."
        ) from None


def main() -> None:
    try:
        prepare_approval_workflow_bundle(settings_from_environment(os.environ))
    except ApprovalWorkflowPrepareError:
        sys.stderr.write('{"status":"failed"}\n')
        raise SystemExit(1) from None
    sys.stdout.write('{"status":"prepared"}\n')


if __name__ == "__main__":
    main()


__all__ = [
    "ApprovalWorkflowPrepareError",
    "ApprovalWorkflowPrepareSettings",
    "BINDING_NAME",
    "CREATE_INTENT_BINDING_NAME",
    "CREATE_INTENT_REF_NAME",
    "DRAFT_INPUT_NAME",
    "OBSERVATION_BINDING_NAME",
    "OBSERVATION_REF_NAME",
    "OUTPUT_DIRECTORY_ENV",
    "PROFILE_CONTRACT",
    "PROFILE_OBSERVATION_VERSION",
    "PROFILE_REQUEST_CREATE_VERSION",
    "PROFILE_PATH_ENV",
    "PROFILE_VERSION",
    "REFERENCE_INPUT_NAME",
    "prepare_approval_workflow_bundle",
    "settings_from_environment",
]
