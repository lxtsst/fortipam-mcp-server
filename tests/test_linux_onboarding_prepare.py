from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from fortipam_mcp.access_domain_projection_source import (
    OwnerOnlyAccessDomainBindingResolver,
    access_domain_projection_contract,
)
from fortipam_mcp.linux_onboarding_prepare import (
    ACCESS_BINDING_NAME,
    DRAFT_INPUT_NAME,
    LinuxOnboardingPrepareError,
    LinuxOnboardingPrepareSettings,
    MATERIAL_PROVIDER_CLASS_ENV,
    MCP_PUBLIC_URL_ENV,
    PROFILE_CONTRACT,
    PROFILE_VERSION,
    REFERENCE_INPUT_NAME,
    SECRET_BINDING_NAME,
    SECRET_OUTPUT_DIRECTORY_ENV,
    SECRET_PROFILE_CONTRACT,
    SECRET_PROFILE_PATH_ENV,
    SECRET_PROFILE_VERSION,
    prepare_linux_onboarding_bundle,
    settings_from_environment,
)
from fortipam_mcp.reference_grant_bootstrap import (
    ReferenceGrantBootstrapSettings,
    bootstrap_reference_grants,
)
from fortipam_mcp.scheme_draft_bootstrap import (
    SchemeDraftBootstrapSettings,
    bootstrap_scheme_draft,
)
from fortipam_mcp.secret_onboarding_projection_source import (
    OwnerOnlySecretOnboardingBindingResolver,
    SecretOnboardingBinding,
    SecretOnboardingProjectionSourceError,
    WebSecretOnboardingBinding,
    secret_onboarding_projection_contract,
)
from scripts.v4_registry import load_registry
from v4_planning import (
    AuthenticatedRequester,
    AuthoritativeProjection,
    M2PlanningEngine,
    ObjectClass,
    PersistentReferenceAuthority,
    PersistentSchemeDraftAuthority,
    scheme_draft_from_mapping,
)
from v4_planning.material_provider import MaterialProviderClass


NOW = 1_950_000_000
REQUESTER = AuthenticatedRequester("bp005-profile-requester", "operator")


class _Issuer:
    def __init__(self) -> None:
        self._count = 0

    def issue(self, purpose: str) -> str:
        self._count += 1
        return f"{purpose}-bp005-preparation-{self._count:04d}"


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
        "environment_ref": "bp005-test-environment",
        "scope_ref": "bp005-test-scope",
        "expires_at": NOW + 600,
        "folder_name": "private-folder-marker",
        "folder_path": "private/folder/private-folder-marker",
        "parent_folder_id": 9,
        "owner_principal_name": "private-owner-marker",
        "owner_subject_class": "user",
        "acl_relations": [
            {
                "principal_name": "private-group-marker",
                "subject_class": "group",
                "permission": "use",
                "folder_permission": "view",
                "secret_permission": "view",
            }
        ],
        "target_name": "private-target-marker",
        "target_protocol": "ssh",
        "target_ipv4_address": "192.0.2.20",
        "template_name": "private-template-marker",
        "secret_name": "private-secret-marker",
        "launcher_name": None,
    }


def _settings(tmp_path: Path) -> LinuxOnboardingPrepareSettings:
    private = _owner_directory(tmp_path / "private")
    output = _owner_directory(tmp_path / "output")
    profile = _owner_file(
        private / "profile.json",
        json.dumps(_profile()).encode("utf-8"),
    )
    return LinuxOnboardingPrepareSettings(profile, output)


def _secret_profile(blueprint_ref: str) -> dict[str, object]:
    if blueprint_ref == "FPA-BP-005":
        profile = _profile()
        profile["contract"] = SECRET_PROFILE_CONTRACT
        profile["version"] = SECRET_PROFILE_VERSION
        profile["blueprint_ref"] = blueprint_ref
        return profile
    common: dict[str, object] = {
        "contract": SECRET_PROFILE_CONTRACT,
        "version": SECRET_PROFILE_VERSION,
        "blueprint_ref": blueprint_ref,
        "requester_digest": REQUESTER.digest,
        "environment_ref": f"{blueprint_ref.lower()}-test-environment",
        "scope_ref": f"{blueprint_ref.lower()}-test-scope",
        "expires_at": NOW + 600,
        "folder_path": "private/profile/folder",
        "secret_name": "private-profile-secret",
    }
    if blueprint_ref == "FPA-BP-006":
        return {
            **common,
            "target_name": "private-rdp-target",
            "target_ipv4_address": "192.0.2.60",
            "template_name": "private-windows-template",
            "launcher_name": "private-rdp-launcher",
            "policy_folder_id": 17,
            "policy_folder_name": "private-policy-folder",
            "policy_profile_name": "private-rdp-policy",
            "rdp_event_filter_profile_name": "mcp-v4-rdp-event-filter-private",
        }
    return {**common, "web_url": "https://private.example.test/login"}


def _secret_settings(
    tmp_path: Path,
    blueprint_ref: str,
) -> LinuxOnboardingPrepareSettings:
    private = _owner_directory(tmp_path / "private")
    output = _owner_directory(tmp_path / "output")
    profile = _owner_file(
        private / "profile.json",
        json.dumps(_secret_profile(blueprint_ref)).encode("utf-8"),
    )
    return LinuxOnboardingPrepareSettings(profile, output)


def test_prepare_bundle_feeds_existing_resolvers_and_authorities(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    prepare_linux_onboarding_bundle(settings)

    paths = {
        name: settings.output_directory / name
        for name in (
            ACCESS_BINDING_NAME,
            SECRET_BINDING_NAME,
            DRAFT_INPUT_NAME,
            REFERENCE_INPUT_NAME,
        )
    }
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths.values())
    draft_input = json.loads(paths[DRAFT_INPUT_NAME].read_text(encoding="utf-8"))
    draft = scheme_draft_from_mapping(draft_input["draft"])
    classes = [item.object_class for item in draft.desired_objects]
    assert classes.count(ObjectClass.PUBLIC_FOLDER) == 1
    assert classes.count(ObjectClass.ACCESS_GRANT) == 1
    assert classes.count(ObjectClass.FOLDER_BINDING) == 1
    folder = next(
        item for item in draft.desired_objects if item.object_class is ObjectClass.PUBLIC_FOLDER
    )
    folder_binding = next(
        item for item in draft.desired_objects if item.object_class is ObjectClass.FOLDER_BINDING
    )
    assert dict(folder_binding.desired_fields)["folder_ref"] == folder.object_ref

    access_binding = OwnerOnlyAccessDomainBindingResolver(
        paths[ACCESS_BINDING_NAME]
    ).resolve(draft, REQUESTER)
    secret_binding = OwnerOnlySecretOnboardingBindingResolver(
        paths[SECRET_BINDING_NAME]
    ).resolve(draft, REQUESTER)
    assert OwnerOnlySecretOnboardingBindingResolver(
        paths[SECRET_BINDING_NAME]
    ).bound_secret_name() == "private-secret-marker"
    assert access_binding.folder_object_ref == folder.object_ref
    assert secret_binding.folder_ref == folder.object_ref

    rendered_public_inputs = (
        paths[DRAFT_INPUT_NAME].read_text(encoding="utf-8")
        + paths[REFERENCE_INPUT_NAME].read_text(encoding="utf-8")
    )
    for private_value in (
        "private-folder-marker",
        "private/folder/private-folder-marker",
        "private-owner-marker",
        "private-group-marker",
        "private-target-marker",
        "192.0.2.20",
        "private-template-marker",
        "private-secret-marker",
    ):
        assert private_value not in rendered_public_inputs

    state = _owner_directory(tmp_path / "state")
    draft_key = _owner_file(state / "draft.hmac", b"d" * 32)
    draft_output = settings.output_directory / "draft-ref.json"
    draft_settings = SchemeDraftBootstrapSettings(
        state / "draft.sqlite3",
        draft_key,
        "bp005-draft-authority",
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
        "bp005-reference-authority",
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
    engine = M2PlanningEngine(
        load_registry(),
        _Issuer(),
        authority,
        projection_contract_resolver=lambda _scheme, object_class: (
            access_domain_projection_contract(object_class)
            if object_class in {ObjectClass.PUBLIC_FOLDER, ObjectClass.ACCESS_GRANT}
            else secret_onboarding_projection_contract(object_class)
        ),
    )
    projections = tuple(
        AuthoritativeProjection.from_mapping(
            contract=engine.projection_contract(draft.scheme_id, item.object_class),
            object_ref=item.object_ref,
            observed_at=NOW,
            fresh_until=NOW + 300,
            fields=(
                {"exists": True, **dict(item.desired_fields)}
                if item.object_class is ObjectClass.TEMPLATE_BINDING
                else {"exists": False}
            ),
        )
        for item in draft.desired_objects
    )
    summary = engine.compile_summary(draft, REQUESTER, projections, now_epoch=NOW)
    assert summary.blueprint_ref == "FPA-BP-005"
    assert summary.requester_digest == REQUESTER.digest


@pytest.mark.parametrize(
    ("blueprint_ref", "expected_classes", "binding_type"),
    (
        (
            "FPA-BP-006",
            [
                ObjectClass.FOLDER_BINDING,
                ObjectClass.TARGET,
                ObjectClass.TEMPLATE_BINDING,
                ObjectClass.SECRET_METADATA,
                ObjectClass.LAUNCHER_BINDING,
                ObjectClass.POLICY_BINDING,
                ObjectClass.RDP_EVENT_FILTER_BINDING,
            ],
            SecretOnboardingBinding,
        ),
        (
            "FPA-BP-007",
            [
                ObjectClass.FOLDER_BINDING,
                ObjectClass.TEMPLATE_BINDING,
                ObjectClass.WEB_SECRET_METADATA,
            ],
            WebSecretOnboardingBinding,
        ),
    ),
)
def test_shared_prepare_supports_closed_secret_profiles(
    tmp_path: Path,
    blueprint_ref: str,
    expected_classes: list[ObjectClass],
    binding_type: type[SecretOnboardingBinding] | type[WebSecretOnboardingBinding],
) -> None:
    settings = _secret_settings(tmp_path, blueprint_ref)
    prepare_linux_onboarding_bundle(settings)

    paths = {
        name: settings.output_directory / name
        for name in (SECRET_BINDING_NAME, DRAFT_INPUT_NAME, REFERENCE_INPUT_NAME)
    }
    assert set(path.name for path in settings.output_directory.iterdir()) == set(paths)
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths.values())
    draft_input = json.loads(paths[DRAFT_INPUT_NAME].read_text(encoding="utf-8"))
    draft = scheme_draft_from_mapping(draft_input["draft"])
    assert draft.blueprint_ref == blueprint_ref
    assert [item.object_class for item in draft.desired_objects] == expected_classes
    binding = OwnerOnlySecretOnboardingBindingResolver(
        paths[SECRET_BINDING_NAME]
    ).resolve(draft, REQUESTER)
    assert isinstance(binding, binding_type)

    public_inputs = (
        paths[DRAFT_INPUT_NAME].read_text(encoding="utf-8")
        + paths[REFERENCE_INPUT_NAME].read_text(encoding="utf-8")
    )
    for private_value in (
        "private/profile/folder",
        "private-profile-secret",
        "private-rdp-target",
        "192.0.2.60",
        "private-windows-template",
        "private-rdp-launcher",
        "private-policy-folder",
        "private-rdp-policy",
        "mcp-v4-rdp-event-filter-private",
        "https://private.example.test/login",
    ):
        assert private_value not in public_inputs

    state = _owner_directory(tmp_path / "state")
    reference_key = _owner_file(state / "reference.hmac", b"r" * 32)
    reference_output = settings.output_directory / "reference-grants.json"
    reference_settings = ReferenceGrantBootstrapSettings(
        state / "reference.sqlite3",
        reference_key,
        f"{blueprint_ref.lower()}-reference-authority",
        paths[REFERENCE_INPUT_NAME],
        reference_output,
    )
    bootstrap_reference_grants(reference_settings, now_epoch=NOW)
    authority = PersistentReferenceAuthority(
        reference_settings.database_path,
        reference_key,
        authority_ref=reference_settings.authority_ref,
        clock=lambda: NOW,
    )
    engine = M2PlanningEngine(
        load_registry(),
        _Issuer(),
        authority,
        projection_contract_resolver=lambda _scheme, object_class: (
            secret_onboarding_projection_contract(object_class)
        ),
    )
    projections = tuple(
        AuthoritativeProjection.from_mapping(
            contract=engine.projection_contract(draft.scheme_id, item.object_class),
            object_ref=item.object_ref,
            observed_at=NOW,
            fresh_until=NOW + 300,
            fields=(
                {"exists": False}
                if item.object_class
                in {ObjectClass.SECRET_METADATA, ObjectClass.WEB_SECRET_METADATA}
                else {"exists": True, **dict(item.desired_fields)}
            ),
        )
        for item in draft.desired_objects
    )
    summary = engine.compile_summary(draft, REQUESTER, projections, now_epoch=NOW)
    assert summary.blueprint_ref == blueprint_ref


def test_shared_environment_pair_is_exact_and_cannot_mix_with_legacy(
    tmp_path: Path,
) -> None:
    settings = _secret_settings(tmp_path, "FPA-BP-007")
    environment = {
        SECRET_PROFILE_PATH_ENV: str(settings.profile_path),
        SECRET_OUTPUT_DIRECTORY_ENV: str(settings.output_directory),
    }
    assert settings_from_environment(environment) == settings

    environment["FORTIPAM_MCP_V4_LINUX_ONBOARDING_PROFILE"] = str(
        settings.profile_path
    )
    with pytest.raises(
        LinuxOnboardingPrepareError,
        match="configuration is incomplete",
    ):
        settings_from_environment(environment)


def test_shared_prepare_can_select_central_lab_material_provider(
    tmp_path: Path,
) -> None:
    settings = _secret_settings(tmp_path, "FPA-BP-007")
    environment = {
        SECRET_PROFILE_PATH_ENV: str(settings.profile_path),
        SECRET_OUTPUT_DIRECTORY_ENV: str(settings.output_directory),
        MATERIAL_PROVIDER_CLASS_ENV: (
            MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE.value
        ),
    }

    selected = settings_from_environment(environment)
    prepare_linux_onboarding_bundle(selected)

    draft = scheme_draft_from_mapping(
        json.loads(
            (selected.output_directory / DRAFT_INPUT_NAME).read_text(
                encoding="utf-8"
            )
        )["draft"]
    )
    assert draft.material_reference_metadata is not None
    assert draft.material_reference_metadata.provider_class == (
        MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE.value
    )


def test_bp007_prepare_rejects_the_mcp_public_route(tmp_path: Path) -> None:
    settings = _secret_settings(tmp_path, "FPA-BP-007")
    profile = json.loads(settings.profile_path.read_text(encoding="utf-8"))
    profile["web_url"] = "https://private.example.test:18443/fpamcp/login"
    settings.profile_path.write_text(json.dumps(profile), encoding="utf-8")
    os.chmod(settings.profile_path, 0o600)

    selected = settings_from_environment(
        {
            SECRET_PROFILE_PATH_ENV: str(settings.profile_path),
            SECRET_OUTPUT_DIRECTORY_ENV: str(settings.output_directory),
            MCP_PUBLIC_URL_ENV: "https://private.example.test:18443/fpamcp",
        }
    )

    with pytest.raises(LinuxOnboardingPrepareError, match="input is invalid"):
        prepare_linux_onboarding_bundle(selected)
    assert not any(settings.output_directory.iterdir())


def test_bp007_prepare_allows_an_independent_path_on_the_mcp_origin(
    tmp_path: Path,
) -> None:
    settings = _secret_settings(tmp_path, "FPA-BP-007")
    profile = json.loads(settings.profile_path.read_text(encoding="utf-8"))
    profile["web_url"] = "https://private.example.test:18443/bp007-web-fixture/login"
    settings.profile_path.write_text(json.dumps(profile), encoding="utf-8")
    os.chmod(settings.profile_path, 0o600)

    selected = settings_from_environment(
        {
            SECRET_PROFILE_PATH_ENV: str(settings.profile_path),
            SECRET_OUTPUT_DIRECTORY_ENV: str(settings.output_directory),
            MCP_PUBLIC_URL_ENV: "https://private.example.test:18443/fpamcp",
        }
    )
    prepare_linux_onboarding_bundle(selected)
    assert (settings.output_directory / SECRET_BINDING_NAME).is_file()


def test_shared_profile_preserves_composite_bp005_bundle(tmp_path: Path) -> None:
    settings = _secret_settings(tmp_path, "FPA-BP-005")
    prepare_linux_onboarding_bundle(settings)

    assert {path.name for path in settings.output_directory.iterdir()} == {
        ACCESS_BINDING_NAME,
        SECRET_BINDING_NAME,
        DRAFT_INPUT_NAME,
        REFERENCE_INPUT_NAME,
    }
    draft_input = json.loads(
        (settings.output_directory / DRAFT_INPUT_NAME).read_text(encoding="utf-8")
    )
    assert draft_input["draft"]["blueprint_ref"] == "FPA-BP-005"


def test_bp005_profile_accepts_existing_root_level_public_folder(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    profile = json.loads(settings.profile_path.read_text(encoding="utf-8"))
    profile["parent_folder_id"] = 0
    settings.profile_path.write_text(json.dumps(profile), encoding="utf-8")
    os.chmod(settings.profile_path, 0o600)

    prepare_linux_onboarding_bundle(settings)

    draft = scheme_draft_from_mapping(
        json.loads(
            (settings.output_directory / DRAFT_INPUT_NAME).read_text(encoding="utf-8")
        )["draft"]
    )
    binding = OwnerOnlyAccessDomainBindingResolver(
        settings.output_directory / ACCESS_BINDING_NAME
    ).resolve(draft, REQUESTER)
    assert binding.parent_folder_id == 0


def test_prepare_cli_is_non_disclosing_and_rejects_extra_material(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path / "success")
    result = subprocess.run(
        (sys.executable, "-m", "fortipam_mcp.linux_onboarding_prepare"),
        cwd=Path(__file__).resolve().parents[1],
        env={
            **os.environ,
            "FORTIPAM_MCP_V4_LINUX_ONBOARDING_PROFILE": str(settings.profile_path),
            "FORTIPAM_MCP_V4_LINUX_ONBOARDING_OUTPUT_DIR": str(
                settings.output_directory
            ),
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
    with pytest.raises(LinuxOnboardingPrepareError, match="input is invalid") as exc:
        prepare_linux_onboarding_bundle(rejected)
    assert "must-not-reflect" not in str(exc.value)
    assert not any(rejected.output_directory.iterdir())

    duplicate = _settings(tmp_path / "duplicate")
    profile = json.loads(duplicate.profile_path.read_text(encoding="utf-8"))
    profile["acl_relations"].append(dict(profile["acl_relations"][0]))
    duplicate.profile_path.write_text(json.dumps(profile), encoding="utf-8")
    os.chmod(duplicate.profile_path, 0o600)
    with pytest.raises(LinuxOnboardingPrepareError, match="input is invalid"):
        prepare_linux_onboarding_bundle(duplicate)
    assert not any(duplicate.output_directory.iterdir())


@pytest.mark.parametrize("profile_version", ["1.1.0", "1.2.0"])
def test_bp006_reuse_bundle_preserves_existing_identity_without_material(tmp_path: Path, profile_version: str) -> None:
    settings = _secret_settings(tmp_path, "FPA-BP-006")
    profile = _secret_profile("FPA-BP-006")
    for key in ("launcher_name", "policy_folder_id", "policy_folder_name", "policy_profile_name"):
        profile.pop(key)
    profile.update(version=profile_version, mode="existing_session_controls", existing_secret_id=42, inherit_permission=False, preserved_identity_relations_digest="1" * 64)
    settings.profile_path.write_text(json.dumps(profile), encoding="utf-8")
    if profile_version == "1.1.0":
        with pytest.raises(LinuxOnboardingPrepareError):
            prepare_linux_onboarding_bundle(settings)
        assert not any(settings.output_directory.iterdir())
        return
    prepare_linux_onboarding_bundle(settings)
    raw = json.loads((settings.output_directory / SECRET_BINDING_NAME).read_text())
    assert raw["version"] == "1.9.0"
    assert raw["existing_secret_id"] == 42
    draft = scheme_draft_from_mapping(json.loads((settings.output_directory / DRAFT_INPUT_NAME).read_text())["draft"])
    assert draft.material_reference_metadata is None
    assert len(draft.desired_objects) == 6
    secret = next(item for item in draft.desired_objects if item.object_class is ObjectClass.SECRET_METADATA)
    assert dict(secret.desired_fields) == {"inherit_permission": False}
    binding = OwnerOnlySecretOnboardingBindingResolver(settings.output_directory / SECRET_BINDING_NAME).resolve(draft, REQUESTER)
    assert isinstance(binding, SecretOnboardingBinding)
    assert binding.existing_secret_id == 42
    assert binding.template_name == profile["template_name"]
    references = json.loads((settings.output_directory / REFERENCE_INPUT_NAME).read_text())["references"]
    controls = next(item for item in draft.desired_objects if item.object_class is ObjectClass.SECRET_SESSION_CONTROLS_BINDING)
    contract = secret_onboarding_projection_contract(controls.object_class)
    assert {"reference": contract.source_ref, "reference_kind": "projection_source"} in references
    public_text = (settings.output_directory / DRAFT_INPUT_NAME).read_text() + (settings.output_directory / REFERENCE_INPUT_NAME).read_text()
    assert str(profile["secret_name"]) not in public_text
    assert "existing_secret_id" not in public_text
    raw["version"] = "1.8.0"
    path = settings.output_directory / SECRET_BINDING_NAME
    path.write_text(json.dumps(raw))
    with pytest.raises(SecretOnboardingProjectionSourceError):
        OwnerOnlySecretOnboardingBindingResolver(path).resolve(draft, REQUESTER)


@pytest.mark.parametrize("profile_version", ["1.1.0", "1.2.0"])
def test_bp007_existing_service_bundle_is_material_free_and_pinned(tmp_path: Path, profile_version: str) -> None:
    settings = _secret_settings(tmp_path, "FPA-BP-007")
    profile = _secret_profile("FPA-BP-007")
    profile.update(version=profile_version, mode="existing_web_service", existing_secret_id=42)
    settings.profile_path.write_text(json.dumps(profile), encoding="utf-8")
    if profile_version == "1.1.0":
        with pytest.raises(LinuxOnboardingPrepareError):
            prepare_linux_onboarding_bundle(settings)
        assert not any(settings.output_directory.iterdir())
        return
    prepare_linux_onboarding_bundle(settings)
    draft_path = settings.output_directory / DRAFT_INPUT_NAME
    draft = scheme_draft_from_mapping(json.loads(draft_path.read_text())["draft"])
    assert draft.material_reference_metadata is None
    assert len(draft.desired_objects) == 4
    service = next(item for item in draft.desired_objects if item.object_class is ObjectClass.WEB_SECRET_SERVICE_BINDING)
    assert service.desired_exists and dict(service.desired_fields) == {"http_service_enabled": True}
    binding = OwnerOnlySecretOnboardingBindingResolver(settings.output_directory / SECRET_BINDING_NAME).resolve(draft, REQUESTER)
    assert isinstance(binding, WebSecretOnboardingBinding)
    assert binding.existing_secret_id == 42 and binding.service_object_ref == service.object_ref
    public_text = draft_path.read_text() + (settings.output_directory / REFERENCE_INPUT_NAME).read_text()
    assert "existing_secret_id" not in public_text
    assert str(profile["secret_name"]) not in public_text


def test_collector_bundle_keeps_private_selectors_out_of_draft_and_grants(tmp_path):
    from fortipam_mcp.linux_onboarding_prepare import COLLECTOR_BINDING_NAME, COLLECTOR_PROFILE_VERSION
    from fortipam_mcp.secret_create_191_private_adapter import load_winrm_collector_private_binding
    from fortipam_mcp.winrm_collector_projection_reader import winrm_collector_projection_contract

    settings = _secret_settings(tmp_path, "FPA-BP-006")
    profile = _secret_profile("FPA-BP-006")
    for key in ("launcher_name", "policy_folder_id", "policy_folder_name", "policy_profile_name"):
        profile.pop(key)
    profile.update(version=COLLECTOR_PROFILE_VERSION, workflow_variant="winrm_collector",
                   template_name="Windows Machine", folder_owner_name="private-collector-owner",
                   witness_folder_path="private/witness-folder", witness_secret_name="private-witness-secret")
    settings.profile_path.write_text(json.dumps(profile))
    prepare_linux_onboarding_bundle(settings)
    assert {p.name for p in settings.output_directory.iterdir()} == {
        SECRET_BINDING_NAME, COLLECTOR_BINDING_NAME, DRAFT_INPUT_NAME, REFERENCE_INPUT_NAME,
    }
    private = load_winrm_collector_private_binding(settings.output_directory / COLLECTOR_BINDING_NAME)
    draft_payload = json.loads((settings.output_directory / DRAFT_INPUT_NAME).read_text())
    draft = scheme_draft_from_mapping(draft_payload["draft"])
    bound = OwnerOnlySecretOnboardingBindingResolver(settings.output_directory / SECRET_BINDING_NAME).resolve(draft, REQUESTER)
    assert bound.secret_name == private.secret_name and bound.target_name == private.target_name
    assert draft.external_effects == ("privileged_credential_registration",)
    assert draft.material_reference_metadata.provider_class == MaterialProviderClass.CENTRAL_LAB_INVENTORY_REFERENCE.value
    assert {o.object_class for o in draft.desired_objects} == {
        ObjectClass.FOLDER_BINDING, ObjectClass.TARGET, ObjectClass.TEMPLATE_BINDING, ObjectClass.WINRM_COLLECTOR_METADATA,
    }
    grants = json.loads((settings.output_directory / REFERENCE_INPUT_NAME).read_text())
    sources = [r["reference"] for r in grants["references"] if r["reference_kind"] == "projection_source"]
    assert sources == [winrm_collector_projection_contract().source_ref]
    public = json.dumps([draft_payload, grants])
    for key in ("folder_owner_name", "witness_secret_name", "target_ipv4_address", "secret_name"):
        assert profile[key] not in public
    assert stat.S_IMODE((settings.output_directory / COLLECTOR_BINDING_NAME).stat().st_mode) == 0o600
    with pytest.raises(LinuxOnboardingPrepareError):
        prepare_linux_onboarding_bundle(settings)
