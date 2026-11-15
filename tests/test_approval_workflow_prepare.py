from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from fortipam_mcp.approval_and_observe_projection_source import (
    OwnerOnlyApprovalAndObserveBindingResolver,
)
from fortipam_mcp.approval_workflow_prepare import (
    ApprovalWorkflowPrepareError,
    ApprovalWorkflowPrepareSettings,
    BINDING_NAME,
    CREATE_INTENT_BINDING_NAME,
    CREATE_INTENT_REF_NAME,
    DRAFT_INPUT_NAME,
    OBSERVATION_BINDING_NAME,
    OBSERVATION_REF_NAME,
    OUTPUT_DIRECTORY_ENV,
    PROFILE_CONTRACT,
    PROFILE_OBSERVATION_VERSION,
    PROFILE_REQUEST_CREATE_VERSION,
    PROFILE_PATH_ENV,
    PROFILE_VERSION,
    REFERENCE_INPUT_NAME,
    prepare_approval_workflow_bundle,
)
from fortipam_mcp.secret_request_http_transport import (
    OwnerOnlySecretRequestObservationBindingResolver,
    SecretRequestHttpTransportError,
)
from fortipam_mcp.secret_request_create_http_transport import (
    OwnerOnlySecretRequestCreateBindingResolver,
)
from fortipam_mcp.reference_grant_bootstrap import (
    ReferenceGrantBootstrapSettings,
    bootstrap_reference_grants,
)
from fortipam_mcp.scheme_draft_bootstrap import (
    SchemeDraftBootstrapSettings,
    bootstrap_scheme_draft,
)
from v4_planning import (
    AuthenticatedRequester,
    ObjectClass,
    PersistentReferenceAuthority,
    PersistentSchemeDraftAuthority,
    SchemeId,
    scheme_draft_from_mapping,
)


NOW = 1_950_000_000
REQUESTER = AuthenticatedRequester("bp008-profile-requester", "operator")


def _owner_directory(path: Path) -> Path:
    path.mkdir(mode=0o700, parents=True)
    os.chmod(path, 0o700)
    return path


def _owner_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    os.chmod(path, 0o600)
    return path


def _profile() -> dict[str, object]:
    return {
        "contract": PROFILE_CONTRACT,
        "version": PROFILE_VERSION,
        "requester_digest": REQUESTER.digest,
        "environment_ref": "bp008-test-environment",
        "scope_ref": "bp008-test-scope",
        "expires_at": NOW + 600,
        "approval_profile_name": "private-profile-marker",
        "folder_path": "private/folder-marker",
        "secret_name": "private-secret-marker",
        "secret_id": 42,
    }


def _settings(tmp_path: Path) -> ApprovalWorkflowPrepareSettings:
    private = _owner_directory(tmp_path / "private")
    output = _owner_directory(tmp_path / "output")
    profile = _owner_file(
        private / "profile.json",
        json.dumps(_profile()).encode("utf-8"),
    )
    return ApprovalWorkflowPrepareSettings(profile, output)


def test_prepare_bundle_feeds_existing_resolvers_and_authorities(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    prepare_approval_workflow_bundle(settings)

    paths = {
        name: settings.output_directory / name
        for name in (BINDING_NAME, DRAFT_INPUT_NAME, REFERENCE_INPUT_NAME)
    }
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths.values())
    draft_input = json.loads(paths[DRAFT_INPUT_NAME].read_text(encoding="utf-8"))
    draft = scheme_draft_from_mapping(draft_input["draft"])
    assert draft.scheme_id is SchemeId.APPROVAL_AND_OBSERVE
    assert draft.blueprint_ref == "FPA-BP-008"
    assert [item.object_class for item in draft.desired_objects] == [
        ObjectClass.APPROVAL_PROFILE_BINDING,
        ObjectClass.SECRET_APPROVAL_BINDING,
    ]
    binding = OwnerOnlyApprovalAndObserveBindingResolver(
        paths[BINDING_NAME]
    ).resolve(draft, REQUESTER)
    assert binding.secret_id == 42

    public_inputs = (
        paths[DRAFT_INPUT_NAME].read_text(encoding="utf-8")
        + paths[REFERENCE_INPUT_NAME].read_text(encoding="utf-8")
    )
    for private_value in (
        "private-profile-marker",
        "private/folder-marker",
        "private-secret-marker",
    ):
        assert private_value not in public_inputs

    state = _owner_directory(tmp_path / "state")
    draft_key = _owner_file(state / "draft.hmac", b"d" * 32)
    draft_output = settings.output_directory / "draft-ref.json"
    draft_settings = SchemeDraftBootstrapSettings(
        state / "draft.sqlite3",
        draft_key,
        "bp008-draft-authority",
        paths[DRAFT_INPUT_NAME],
        draft_output,
    )
    bootstrap_scheme_draft(draft_settings, now_epoch=NOW)
    draft_ref = json.loads(draft_output.read_text(encoding="utf-8"))[
        "scheme_draft_ref"
    ]
    assert PersistentSchemeDraftAuthority(
        draft_settings.database_path,
        draft_key,
        authority_ref=draft_settings.authority_ref,
        clock=lambda: NOW,
    ).resolve(draft_ref, REQUESTER) == draft

    reference_key = _owner_file(state / "reference.hmac", b"r" * 32)
    reference_output = settings.output_directory / "reference-grants.json"
    reference_settings = ReferenceGrantBootstrapSettings(
        state / "reference.sqlite3",
        reference_key,
        "bp008-reference-authority",
        paths[REFERENCE_INPUT_NAME],
        reference_output,
    )
    bootstrap_reference_grants(reference_settings, now_epoch=NOW)
    reference_input = json.loads(paths[REFERENCE_INPUT_NAME].read_text(encoding="utf-8"))
    authority = PersistentReferenceAuthority(
        reference_settings.database_path,
        reference_key,
        authority_ref=reference_settings.authority_ref,
        clock=lambda: NOW,
    )
    assert all(
        authority.authorize(
            item["reference"],
            reference_kind=item["reference_kind"],
            requester_digest=REQUESTER.digest,
            environment_ref=draft.environment_ref,
            scope_ref=draft.scope_ref,
            now_epoch=NOW,
        ).authorized
        for item in reference_input["references"]
    )


def test_prepare_cli_is_non_disclosing_and_rejects_extra_material(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path / "success")
    result = subprocess.run(
        (sys.executable, "-m", "fortipam_mcp.approval_workflow_prepare"),
        cwd=Path(__file__).resolve().parents[1],
        env={
            **os.environ,
            PROFILE_PATH_ENV: str(settings.profile_path),
            OUTPUT_DIRECTORY_ENV: str(settings.output_directory),
            "PYTHONPATH": "src:.",
        },
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout == '{"status":"prepared"}\n'
    assert result.stderr == ""
    assert "private-" not in result.stdout + result.stderr

    rejected = _settings(tmp_path / "rejected")
    profile = json.loads(rejected.profile_path.read_text(encoding="utf-8"))
    profile["password"] = "must-not-reflect"
    rejected.profile_path.write_text(json.dumps(profile), encoding="utf-8")
    os.chmod(rejected.profile_path, 0o600)
    with pytest.raises(ApprovalWorkflowPrepareError, match="input is invalid") as exc:
        prepare_approval_workflow_bundle(rejected)
    assert "must-not-reflect" not in str(exc.value)
    assert not any(rejected.output_directory.iterdir())


def test_prepare_can_bind_one_existing_request_without_exposing_ids(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    profile = json.loads(settings.profile_path.read_text(encoding="utf-8"))
    profile.update(
        {
            "version": PROFILE_OBSERVATION_VERSION,
            "request_id": 71,
            "request_type": "launcher",
        }
    )
    settings.profile_path.write_text(json.dumps(profile), encoding="utf-8")
    settings.profile_path.chmod(0o600)

    prepare_approval_workflow_bundle(settings)

    names = {path.name for path in settings.output_directory.iterdir()}
    assert names == {
        BINDING_NAME,
        DRAFT_INPUT_NAME,
        REFERENCE_INPUT_NAME,
        OBSERVATION_BINDING_NAME,
        OBSERVATION_REF_NAME,
    }
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in settings.output_directory.iterdir()
    )
    ref_payload = json.loads(
        (settings.output_directory / OBSERVATION_REF_NAME).read_text(
            encoding="utf-8"
        )
    )
    request_ref = ref_payload["request_ref"]
    binding = OwnerOnlySecretRequestObservationBindingResolver(
        settings.output_directory / OBSERVATION_BINDING_NAME
    ).resolve(
        request_ref,
        requester_digest=REQUESTER.digest,
        environment_ref="bp008-test-environment",
        scope_ref="bp008-test-scope",
    )
    assert binding.request_id == 71
    assert binding.secret_id == 42
    assert binding.request_type == "launcher"
    with pytest.raises(SecretRequestHttpTransportError):
        OwnerOnlySecretRequestObservationBindingResolver(
            settings.output_directory / OBSERVATION_BINDING_NAME
        ).resolve(
            request_ref,
            requester_digest=REQUESTER.digest,
            environment_ref="bp008-test-environment",
            scope_ref="different-scope-reference",
        )

    public_inputs = (
        (settings.output_directory / DRAFT_INPUT_NAME).read_text(encoding="utf-8")
        + (settings.output_directory / REFERENCE_INPUT_NAME).read_text(
            encoding="utf-8"
        )
        + (settings.output_directory / OBSERVATION_REF_NAME).read_text(
            encoding="utf-8"
        )
    )
    assert '"request_id":71' not in public_inputs
    assert '"secret_id":42' not in public_inputs

    observation_path = settings.output_directory / OBSERVATION_BINDING_NAME
    observation_path.chmod(0o640)
    with pytest.raises(SecretRequestHttpTransportError):
        OwnerOnlySecretRequestObservationBindingResolver(observation_path).resolve(
            request_ref,
            requester_digest=REQUESTER.digest,
            environment_ref="bp008-test-environment",
            scope_ref="bp008-test-scope",
        )


def test_prepare_can_stage_protected_create_intent_with_public_ref_only(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    profile = json.loads(settings.profile_path.read_text(encoding="utf-8"))
    profile.update(
        {
            "version": PROFILE_REQUEST_CREATE_VERSION,
            "fortipam_requester": "private-requester-marker",
            "request_type": "launcher",
            "start_after_approve": "enable",
            "start_time": "",
            "expiration_time": "",
            "duration": 30,
            "comments": "private-comment-marker",
            "timezone": "UTC",
            "job_name": None,
            "custom_fields": [
                {
                    "name": "Ticket",
                    "value": "private-field-marker",
                    "required": True,
                }
            ],
        }
    )
    settings.profile_path.write_text(json.dumps(profile), encoding="utf-8")
    settings.profile_path.chmod(0o600)

    prepare_approval_workflow_bundle(settings)

    names = {path.name for path in settings.output_directory.iterdir()}
    assert names == {
        BINDING_NAME,
        DRAFT_INPUT_NAME,
        REFERENCE_INPUT_NAME,
        CREATE_INTENT_BINDING_NAME,
        CREATE_INTENT_REF_NAME,
    }
    assert all(
        stat.S_IMODE(path.stat().st_mode) == 0o600
        for path in settings.output_directory.iterdir()
    )
    ref_path = settings.output_directory / CREATE_INTENT_REF_NAME
    intent_ref = json.loads(ref_path.read_text(encoding="utf-8"))["intent_ref"]
    prepared = OwnerOnlySecretRequestCreateBindingResolver(
        settings.output_directory / CREATE_INTENT_BINDING_NAME
    ).resolve(
        intent_ref=intent_ref,
        requester_digest=REQUESTER.digest,
        environment_ref="bp008-test-environment",
        scope_ref="bp008-test-scope",
    )
    assert prepared.request.secret_id == 42
    assert prepared.request.requester == "private-requester-marker"
    assert prepared.request.comments == "private-comment-marker"
    assert prepared.request.custom_fields[0].value == "private-field-marker"

    public_inputs = (
        (settings.output_directory / DRAFT_INPUT_NAME).read_text(encoding="utf-8")
        + (settings.output_directory / REFERENCE_INPUT_NAME).read_text(
            encoding="utf-8"
        )
        + ref_path.read_text(encoding="utf-8")
    )
    for private_value in (
        '"secret_id":42',
        "private-requester-marker",
        "private-comment-marker",
        "private-field-marker",
    ):
        assert private_value not in public_inputs
