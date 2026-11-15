from __future__ import annotations

from fortipam_mcp.secret_metadata_http_transport import SecretSessionControlsFolderPolicy

import json
from dataclasses import asdict, replace
from pathlib import Path

import pytest

from fortipam_mcp.launcher_ssh_transport import (
    LauncherInspection,
    LauncherUpdateBaselineReadback,
)
from fortipam_mcp.access_domain_projection_source import (
    AccessDomainFolderBinding,
    BoundAclRelation,
    SOURCE_REF as ACCESS_SOURCE_REF,
)
from fortipam_mcp.local_oauth import (
    LocalOAuthProvider,
    LocalOAuthSettings,
    hash_local_password,
)
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataProjectionInspection,
    SecretSessionControlsProjectionInspection,
    secret_session_controls_event_filter_profile_digest,
)
from fortipam_mcp.recording_policy_http_transport import RecordingPolicyInspection
from fortipam_mcp.rdp_event_filter_ssh_transport import RdpEventFilterReadback
from fortipam_mcp.secret_onboarding_projection_source import (
    FortiPamSecretOnboardingProjectionSource,
    LEGACY_SOURCE_VERSION,
    OwnerOnlySecretOnboardingBindingResolver,
    SECRET_SESSION_CONTROLS_BINDING_VERSION,
    SECRET_SESSION_CONTROLS_SOURCE_CONTRACT,
    SECRET_SESSION_CONTROLS_SOURCE_REF,
    SECRET_SESSION_CONTROLS_SOURCE_VERSION,
    SOURCE_CONTRACT,
    SOURCE_REF,
    SOURCE_VERSION,
    SecretOnboardingBinding,
    SecretOnboardingProjectionSourceError,
    WebSecretOnboardingBinding,
    secret_onboarding_binding_digest,
)
from fortipam_mcp.target_contract import TargetInspection
from fortipam_mcp.secret_policy_ssh_transport import SecretPolicyUpdateBaseline
from fortipam_mcp.v4_confirmation_http import V4ConfirmationSettings
from fortipam_mcp.v4_plan_runtime import V4PlanningPrincipal
from fortipam_mcp.v4_runtime_host import (
    V4PersistentReferenceAuthoritySettings,
    V4PersistentSchemeDraftAuthoritySettings,
    V4RuntimeHostError,
    V4SyntheticHostSettings,
    issue_synthetic_reference_grants,
    issue_synthetic_scheme_draft,
    onboarding_v4_plan_host_factory,
    secret_onboarding_v4_plan_host_factory,
)
from v4_planning import (
    AuthenticatedRequester,
    canonical_digest,
    DesiredObject,
    MaterialReferenceMetadata,
    ObjectClass,
    SchemeDraft,
    SchemeId,
)


class SecretTransport:
    def __init__(
        self,
        *,
        exists: bool = False,
        verified: bool = True,
        folder_exists: bool = True,
        template_exists: bool = True,
        rdp_clipboard_control_compatible: bool = False,
        session_controls: SecretSessionControlsProjectionInspection | None = None,
        inherit_permission_matches: bool | None = None,
    ) -> None:
        self.exists = exists
        self.verified = verified
        self.folder_exists = folder_exists
        self.template_exists = template_exists
        self.rdp_clipboard_control_compatible = rdp_clipboard_control_compatible
        self.session_controls = session_controls
        self.inherit_permission_matches = (
            verified
            if inherit_permission_matches is None
            else inherit_permission_matches
        )

    def inspect_projection(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
        target_name: str,
        *,
        expected_rdp_event_filter_profile: str | None = None,
    ) -> SecretMetadataProjectionInspection:
        assert (folder_path, secret_name, template, target_name) == (
            "private/folder",
            "mcp-v4-secret-metadata-linux01",
            "private-template",
            "private-target",
        )
        return SecretMetadataProjectionInspection(
            self.exists,
            self.folder_exists,
            self.template_exists,
            self.exists and self.verified,
            self.exists and self.verified,
            self.exists and self.verified,
            self.exists and self.inherit_permission_matches,
            self.exists and not self.verified,
            self.exists
            and self.verified
            and expected_rdp_event_filter_profile
            == "mcp-v4-rdp-event-filter-existing",
            rdp_clipboard_control_compatible=(
                self.exists and self.rdp_clipboard_control_compatible
            ),
        )

    def inspect_web_projection(
        self,
        folder_path: str,
        secret_name: str,
        template: str,
    ) -> SecretMetadataProjectionInspection:
        assert (folder_path, secret_name, template) == (
            "private/folder",
            "mcp-v4-secret-metadata-web01",
            "Web Account",
        )
        return SecretMetadataProjectionInspection(
            self.exists,
            self.folder_exists,
            self.template_exists,
            self.exists and self.verified,
            self.exists and self.verified,
            self.exists and self.verified,
            self.exists and self.verified,
            self.exists and not self.verified,
            recording_matches=self.exists and self.verified,
        )

    def inspect_session_controls_projection(
        self,
        folder_path: str,
        secret_name: str,
        expected_template: str,
        expected_target: str,
        expected_rdp_event_filter_profile: str,
        *,
        expected_secret_id: int,
    ) -> SecretSessionControlsProjectionInspection:
        assert (
            folder_path,
            secret_name,
            expected_template,
            expected_target,
            expected_rdp_event_filter_profile,
            expected_secret_id,
        ) == (
            "private/folder",
            "mcp-v4-secret-metadata-linux01",
            "private-template",
            "private-target",
            "mcp-v4-rdp-event-filter-existing",
            23,
        )
        assert self.session_controls is not None
        return self.session_controls


class TargetTransport:
    def __init__(self, *, exists: bool = True) -> None:
        self.exists = exists

    def inspect(self, target_name: str) -> TargetInspection:
        assert target_name == "private-target"
        return TargetInspection(self.exists)


class LauncherTransport:
    def inspect(self, launcher_name: str) -> LauncherInspection:
        assert launcher_name == "private-launcher"
        return LauncherInspection(True)

    def update_baseline_readback(
        self,
        launcher_name: str,
    ) -> LauncherUpdateBaselineReadback:
        raise AssertionError(f"Unexpected RDP launcher read for {launcher_name!r}")


class RdpLauncherTransport(LauncherTransport):
    def __init__(self, *, verified: bool = True) -> None:
        self.verified = verified

    def update_baseline_readback(
        self,
        launcher_name: str,
    ) -> LauncherUpdateBaselineReadback:
        assert launcher_name == "private-launcher"
        return LauncherUpdateBaselineReadback(
            launcher_name_exists=True,
            type_is_rdp=self.verified,
            mstsc_executable_present=True,
            native_rdp_parameter_present=True,
            cmdkey_initial_command_present=True,
            cmdkey_clean_command_present=True,
            launch_timeout_is_default=True,
        )


class RdpEventFilterTransport:
    def readback(self, profile_name: str) -> RdpEventFilterReadback:
        assert profile_name == "mcp-v4-rdp-event-filter-existing"
        return RdpEventFilterReadback(True, True, True, True)


class FolderPolicyTransport:
    def __init__(
        self,
        *,
        policy_name: str = "mcp-v4-secret-policy-rdp-01",
        resolved_folder_id: int = 17,
    ) -> None:
        self.policy_name = policy_name
        self.resolved_folder_id = resolved_folder_id

    def verify_folder_policy_binding(
        self,
        folder_path: str,
        *,
        expected_folder_id: int,
        expected_folder_name: str,
        expected_policy_name: str,
    ) -> bool:
        assert folder_path == "private/folder"
        assert expected_folder_id == 17
        assert expected_folder_name == "folder"
        return (
            self.resolved_folder_id == expected_folder_id
            and self.policy_name == expected_policy_name
        )


class SecretPolicyClipboardTransport:
    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled

    def read_session_security_baseline(self, policy_name: str) -> SecretPolicyUpdateBaseline:
        assert policy_name == "mcp-v4-secret-policy-rdp-01"
        return SecretPolicyUpdateBaseline(True, True, self.enabled)


class RecordingPolicyTransport:
    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled

    def inspect(self, policy_name: str) -> RecordingPolicyInspection:
        assert policy_name == "mcp-v4-secret-policy-rdp-01"
        return RecordingPolicyInspection(True, self.enabled, "a" * 64)


class FolderTransport:
    def __init__(
        self,
        *,
        folder_present: bool = True,
        owner_present: bool = True,
        grant_present: bool = True,
    ) -> None:
        self.folder_present = folder_present
        self.owner_present = owner_present
        self.grant_present = grant_present

    def read_collection(self) -> dict[str, object]:
        child = {
            "id": 17,
            "name": "private-product-folder",
            "parent-folder": 9,
            "folder-type": "public",
            "user-permission": (
                [
                    {
                        "user-name": [{"name": "private-owner-name"}],
                        "folder-permission": "Owner",
                        "secret-permission": "Owner",
                    }
                ]
                if self.owner_present
                else []
            ),
            "group-permission": (
                [
                    {
                        "group-name": [{"name": "private-group-name"}],
                        "folder-permission": "View",
                        "secret-permission": "View",
                    }
                ]
                if self.grant_present
                else []
            ),
        }
        return {
            "results": [
                {"id": 9, "name": "private-parent-folder"},
                *([child] if self.folder_present else []),
            ]
        }


class AccessResolver:
    def resolve(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> AccessDomainFolderBinding:
        del draft, requester
        return AccessDomainFolderBinding(
            folder_object_ref="synthetic-public-folder-reference",
            folder_name="private-product-folder",
            parent_folder_id=9,
            owner_ref="synthetic-owner-reference",
            owner_principal_name="private-owner-name",
            owner_subject_class="user",
            acl_relations=(
                BoundAclRelation(
                    object_ref="synthetic-access-grant-reference",
                    subject_ref="synthetic-group-reference",
                    subject_class="group",
                    principal_name="private-group-name",
                    permission="use",
                    folder_permission="view",
                    secret_permission="view",
                ),
            ),
        )


class Resolver:
    def __init__(self, binding: SecretOnboardingBinding | None = None) -> None:
        self._binding = binding or _binding()

    def resolve(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> SecretOnboardingBinding:
        del requester
        if draft.scope_ref == "combined-linux-scope":
            return replace(
                self._binding,
                folder_ref="synthetic-public-folder-reference",
            )
        return self._binding


class RdpResolver:
    def resolve(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> SecretOnboardingBinding:
        del draft, requester
        return _rdp_binding()


class WebResolver:
    def resolve(
        self,
        draft: SchemeDraft,
        requester: AuthenticatedRequester,
    ) -> WebSecretOnboardingBinding:
        del draft, requester
        return _web_binding()


def _desired(
    object_ref: str,
    object_class: ObjectClass,
    fields: dict[str, bool | str],
) -> DesiredObject:
    return DesiredObject(
        object_ref=object_ref,
        object_class=object_class,
        desired_exists=True,
        desired_fields=tuple(sorted(fields.items())),
    )


def _draft() -> SchemeDraft:
    return SchemeDraft(
        scheme_id=SchemeId.SECRET_ONBOARDING,
        scheme_version="1.0.0",
        registry_schema_version="1.1.0",
        blueprint_ref="FPA-BP-005",
        environment_ref="secret-source-environment",
        scope_ref="secret-source-scope",
        owner_ref="secret-source-owner",
        audience_ref="secret-source-audience",
        outcome_code="onboard_privileged_resource",
        desired_objects=(
            _desired(
                "folder-binding-ref",
                ObjectClass.FOLDER_BINDING,
                {"folder_ref": "approved-folder-ref"},
            ),
            _desired(
                "target-object-ref",
                ObjectClass.TARGET,
                {"connectivity_profile_ref": "ssh-profile-ref", "protocol": "ssh"},
            ),
            _desired(
                "template-binding-ref",
                ObjectClass.TEMPLATE_BINDING,
                {"compatibility": "compatible", "template_ref": "approved-template-ref"},
            ),
            _desired(
                "secret-metadata-ref",
                ObjectClass.SECRET_METADATA,
                {"inherit_permission": True},
            ),
            _desired(
                "launcher-binding-ref",
                ObjectClass.LAUNCHER_BINDING,
                {"launcher_profile_ref": "approved-launcher-ref"},
            ),
        ),
        approval_class="independent_approval",
        separation_required=True,
        risk_class="high",
        external_effects=("privileged_access_metadata_change",),
        assumption_codes=("folder_relationship_prevalidated",),
        excluded_scope_codes=("credential_material", "session_launch"),
        verification_codes=("association_readback", "launch_readiness_metadata"),
        stop_codes=("current_state_drift", "material_unavailable"),
        evidence_policy="redacted_contract_evidence",
        maintenance_class="maintenance_window_required",
        reversibility_class="manual_reconciliation_only",
        evidence_refs=("secret-source-evidence",),
        unresolved_gap_codes=(),
        reconciliation_strategy="reconcile_or_manual",
        summary_ttl_seconds=300,
        material_reference_metadata=MaterialReferenceMetadata(
            provider_class="external_vault_lease",
            purpose="initial_onboarding",
            lifecycle="available",
        ),
    )


def _binding() -> SecretOnboardingBinding:
    return SecretOnboardingBinding(
        folder_object_ref="folder-binding-ref",
        folder_path="private/folder",
        folder_ref="approved-folder-ref",
        target_object_ref="target-object-ref",
        target_name="private-target",
        target_protocol="ssh",
        connectivity_profile_ref="ssh-profile-ref",
        target_ipv4_address="192.0.2.10",
        template_object_ref="template-binding-ref",
        template_name="private-template",
        template_ref="approved-template-ref",
        secret_object_ref="secret-metadata-ref",
        secret_name="mcp-v4-secret-metadata-linux01",
        launcher_object_ref="launcher-binding-ref",
        launcher_name="private-launcher",
        launcher_profile_ref="approved-launcher-ref",
    )


def _rdp_draft() -> SchemeDraft:
    draft = _draft()
    desired = list(draft.desired_objects)
    desired[1] = _desired(
        "target-object-ref",
        ObjectClass.TARGET,
        {"connectivity_profile_ref": "rdp-profile-ref", "protocol": "rdp"},
    )
    desired.append(
        _desired(
            "policy-binding-ref",
            ObjectClass.POLICY_BINDING,
            {"policy_profile_ref": "approved-rdp-policy-ref"},
        )
    )
    return replace(
        draft,
        blueprint_ref="FPA-BP-006",
        outcome_code="onboard_windows_rdp_resource",
        desired_objects=tuple(desired),
    )


def _rdp_binding() -> SecretOnboardingBinding:
    return replace(
        _binding(),
        target_protocol="rdp",
        connectivity_profile_ref="rdp-profile-ref",
        policy_object_ref="policy-binding-ref",
        policy_folder_id=17,
        policy_folder_name="folder",
        policy_profile_name="mcp-v4-secret-policy-rdp-01",
        policy_profile_ref="approved-rdp-policy-ref",
    )


def _session_controls_draft() -> SchemeDraft:
    draft = _rdp_draft()
    retained = tuple(
        item
        for item in draft.desired_objects
        if item.object_class
        not in {ObjectClass.LAUNCHER_BINDING, ObjectClass.POLICY_BINDING}
    )
    return replace(
        draft,
        desired_objects=(
            *retained,
            _desired(
                "rdp-event-filter-binding-ref",
                ObjectClass.RDP_EVENT_FILTER_BINDING,
                {"profile_ref": "approved-rdp-event-filter-ref"},
            ),
            _desired(
                "secret-session-controls-ref",
                ObjectClass.SECRET_SESSION_CONTROLS_BINDING,
                {
                    "clipboard_blocking_enabled": True,
                    "event_filter_profile_digest": (
                        secret_session_controls_event_filter_profile_digest(
                            "mcp-v4-rdp-event-filter-existing"
                        )
                    ),
                    "preserved_identity_digest": "b" * 64,
                    "profile_ref": "approved-rdp-event-filter-ref",
                    "rdp_event_filter_enabled": True,
                    "rdp_event_filter_profile_matches": True,
                    "recording_enabled": True,
                },
            ),
        ),
        material_reference_metadata=None,
    )


def _session_controls_binding() -> SecretOnboardingBinding:
    return replace(
        _rdp_binding(),
        launcher_object_ref=None,
        launcher_name=None,
        launcher_profile_ref=None,
        policy_object_ref=None,
        policy_folder_id=None,
        policy_folder_name=None,
        policy_profile_name=None,
        policy_profile_ref=None,
        rdp_event_filter_object_ref="rdp-event-filter-binding-ref",
        rdp_event_filter_profile_name="mcp-v4-rdp-event-filter-existing",
        rdp_event_filter_profile_ref="approved-rdp-event-filter-ref",
        secret_session_controls_object_ref="secret-session-controls-ref",
        existing_secret_id=23,
        session_controls_identity_digest="b" * 64,
    )


def _session_controls_projection(
    *,
    inherit_permission: bool = True,
    proxy_enabled: bool = True,
    tcp_forwarding_disabled: bool = True,
    event_filter_profile_digest: str = "a" * 64,
    preserved_identity_digest: str = "b" * 64,
) -> SecretSessionControlsProjectionInspection:
    return SecretSessionControlsProjectionInspection(
            original_name="mcp-v4-secret-metadata-01",
            original_template="private-template",
            folder_policy=SecretSessionControlsFolderPolicy(17, "folder", "mcp-v4-secret-policy-test", "not-set", "not-set", "not-set"),
        recording_enabled=False,
        clipboard_blocking_enabled=False,
        rdp_event_filter_enabled=False,
        rdp_event_filter_profile_matches=False,
        rdp_event_filter_profile_digest=event_filter_profile_digest,
        proxy_enabled=proxy_enabled,
        rdp_tcp_forwarding_disabled=tcp_forwarding_disabled,
        inherit_permission_matches=inherit_permission,
        preserved_identity_relations_digest=preserved_identity_digest,
    )


def _web_draft() -> SchemeDraft:
    draft = _draft()
    return replace(
        draft,
        blueprint_ref="FPA-BP-007",
        outcome_code="onboard_web_account",
        desired_objects=(
            draft.desired_objects[0],
            draft.desired_objects[2],
            _desired(
                "web-secret-metadata-ref",
                ObjectClass.WEB_SECRET_METADATA,
                {"inherit_permission": True, "session_recording": True},
            ),
        ),
    )


def _web_binding() -> WebSecretOnboardingBinding:
    return WebSecretOnboardingBinding(
        folder_object_ref="folder-binding-ref",
        folder_path="private/folder",
        folder_ref="approved-folder-ref",
        template_object_ref="template-binding-ref",
        template_name="Web Account",
        template_ref="approved-template-ref",
        secret_object_ref="web-secret-metadata-ref",
        secret_name="mcp-v4-secret-metadata-web01",
        web_url="https://app.example.test/login",
        session_recording=True,
    )


def test_private_binding_digest_is_opaque_and_covers_selector_drift() -> None:
    linux = _binding()
    web = _web_binding()

    assert linux.folder_path not in repr(linux)
    assert linux.secret_name not in repr(linux)
    assert web.web_url not in repr(web)
    assert web.secret_name not in repr(web)
    assert secret_onboarding_binding_digest(linux) != secret_onboarding_binding_digest(
        replace(linux, secret_name="different-private-secret")
    )
    assert secret_onboarding_binding_digest(web) != secret_onboarding_binding_digest(
        replace(web, web_url="https://different.example.test/login")
    )
    legacy_binding = asdict(linux)
    legacy_binding.pop("secret_session_controls_object_ref")
    legacy_binding.pop("existing_secret_id")
    legacy_binding.pop("session_controls_identity_digest")
    assert secret_onboarding_binding_digest(linux) == canonical_digest(
        {
            "binding_type": "SecretOnboardingBinding",
            "binding": legacy_binding,
        }
    )


def test_web_account_projection_has_no_target_and_requires_recording() -> None:
    transport = SecretTransport()
    source = FortiPamSecretOnboardingProjectionSource(
        transport,
        None,
        None,
        WebResolver(),
    )

    projections = source.project(
        _web_draft(),
        AuthenticatedRequester("secret-source-requester", "operator"),
        now_epoch=1_800_000_000,
    )

    assert len(projections) == 3
    secret = next(
        item
        for item in projections
        if item.contract.object_class is ObjectClass.WEB_SECRET_METADATA
    )
    assert dict(secret.fields) == {"exists": False}
    transport.exists = True
    existing = source.project(
        _web_draft(),
        AuthenticatedRequester("secret-source-requester", "operator"),
        now_epoch=1_800_000_001,
    )
    secret = next(
        item
        for item in existing
        if item.contract.object_class is ObjectClass.WEB_SECRET_METADATA
    )
    assert dict(secret.fields) == {
        "exists": True,
        "inherit_permission": True,
        "session_recording": True,
    }


def test_linux_projection_without_target_transport_is_unavailable() -> None:
    source = FortiPamSecretOnboardingProjectionSource(
        SecretTransport(), None, LauncherTransport(), Resolver(),
    )
    with pytest.raises(SecretOnboardingProjectionSourceError):
        source.project(
            _draft(), AuthenticatedRequester("secret-source-requester", "operator"),
            now_epoch=1_800_000_000,
        )


def test_new_secret_projection_is_complete_and_does_not_return_selectors() -> None:
    source = FortiPamSecretOnboardingProjectionSource(
        SecretTransport(),
        TargetTransport(),
        LauncherTransport(),
        Resolver(),
    )

    projections = source.project(
        _draft(),
        AuthenticatedRequester("secret-source-requester", "operator"),
        now_epoch=1_800_000_000,
    )

    assert len(projections) == 5
    assert {item.contract.source_ref for item in projections} == {SOURCE_REF}
    assert all(item.fresh_until == 1_800_000_300 for item in projections)
    secret = next(
        item
        for item in projections
        if item.contract.object_class is ObjectClass.SECRET_METADATA
    )
    assert dict(secret.fields) == {"exists": False}
    rendered = json.dumps([item.as_dict() for item in projections], sort_keys=True)
    for private_value in (
        "private/folder",
        "private-target",
        "192.0.2.10",
        "private-template",
        "private-launcher",
        "mcp-v4-secret-metadata-linux01",
    ):
        assert private_value not in rendered


def test_windows_rdp_profile_requires_existing_dependencies_and_full_launcher_evidence() -> None:
    draft = _rdp_draft()
    requester = AuthenticatedRequester("secret-source-requester", "operator")
    source = FortiPamSecretOnboardingProjectionSource(
        SecretTransport(),
        TargetTransport(),
        RdpLauncherTransport(),
        RdpResolver(),
        FolderPolicyTransport(),
        SecretPolicyClipboardTransport(),
        RecordingPolicyTransport(),
    )

    projections = source.project(draft, requester, now_epoch=1_800_000_000)

    assert {
        item.contract.object_class: item.values["exists"] for item in projections
    } == {
        ObjectClass.FOLDER_BINDING: True,
        ObjectClass.TARGET: True,
        ObjectClass.TEMPLATE_BINDING: True,
        ObjectClass.SECRET_METADATA: False,
        ObjectClass.LAUNCHER_BINDING: True,
        ObjectClass.POLICY_BINDING: True,
    }
    assert {item.contract.version for item in projections} == {SOURCE_VERSION}
    policy = next(
        item
        for item in projections
        if item.contract.object_class is ObjectClass.POLICY_BINDING
    )
    assert policy.values == {
        "exists": True,
        "policy_profile_ref": "approved-rdp-policy-ref",
    }
    rendered = json.dumps([item.as_dict() for item in projections], sort_keys=True)
    for private_value in (
        "private/folder",
        "private-target",
        "192.0.2.10",
        "private-template",
        "private-launcher",
        "mcp-v4-secret-metadata-linux01",
        "mcp-v4-secret-policy-rdp-01",
    ):
        assert private_value not in rendered


    invalid_cases = (
        FortiPamSecretOnboardingProjectionSource(
            SecretTransport(folder_exists=False),
            TargetTransport(),
            RdpLauncherTransport(),
            RdpResolver(),
            FolderPolicyTransport(),
            SecretPolicyClipboardTransport(),
            RecordingPolicyTransport(),
        ),
        FortiPamSecretOnboardingProjectionSource(
            SecretTransport(),
            TargetTransport(exists=False),
            RdpLauncherTransport(),
            RdpResolver(),
            FolderPolicyTransport(),
            SecretPolicyClipboardTransport(),
            RecordingPolicyTransport(),
        ),
        FortiPamSecretOnboardingProjectionSource(
            SecretTransport(template_exists=False),
            TargetTransport(),
            RdpLauncherTransport(),
            RdpResolver(),
            FolderPolicyTransport(),
            SecretPolicyClipboardTransport(),
            RecordingPolicyTransport(),
        ),
        FortiPamSecretOnboardingProjectionSource(
            SecretTransport(),
            TargetTransport(),
            RdpLauncherTransport(verified=False),
            RdpResolver(),
            FolderPolicyTransport(),
            SecretPolicyClipboardTransport(),
            RecordingPolicyTransport(),
        ),
        FortiPamSecretOnboardingProjectionSource(
            SecretTransport(),
            TargetTransport(),
            RdpLauncherTransport(),
            RdpResolver(),
            FolderPolicyTransport(policy_name="different-rdp-policy"),
            SecretPolicyClipboardTransport(),
            RecordingPolicyTransport(),
        ),
        FortiPamSecretOnboardingProjectionSource(
            SecretTransport(),
            TargetTransport(),
            RdpLauncherTransport(),
            RdpResolver(),
            FolderPolicyTransport(resolved_folder_id=18),
            SecretPolicyClipboardTransport(),
            RecordingPolicyTransport(),
        ),
        FortiPamSecretOnboardingProjectionSource(
            SecretTransport(),
            TargetTransport(),
            RdpLauncherTransport(),
            RdpResolver(),
            FolderPolicyTransport(),
            SecretPolicyClipboardTransport(enabled=False),
            RecordingPolicyTransport(),
        ),
        FortiPamSecretOnboardingProjectionSource(
            SecretTransport(),
            TargetTransport(),
            RdpLauncherTransport(),
            RdpResolver(),
            FolderPolicyTransport(),
            SecretPolicyClipboardTransport(),
            RecordingPolicyTransport(enabled=False),
        ),
    )
    for invalid_source in invalid_cases:
        with pytest.raises(SecretOnboardingProjectionSourceError):
            invalid_source.project(draft, requester, now_epoch=1_800_000_000)

    mismatched_desired = list(draft.desired_objects)
    mismatched_desired[1] = _draft().desired_objects[1]
    mismatched_protocol = replace(draft, desired_objects=tuple(mismatched_desired))
    without_launcher = replace(
        draft,
        desired_objects=tuple(
            item
            for item in draft.desired_objects
            if item.object_class is not ObjectClass.LAUNCHER_BINDING
        ),
    )
    without_policy = replace(
        draft,
        desired_objects=tuple(
            item
            for item in draft.desired_objects
            if item.object_class is not ObjectClass.POLICY_BINDING
        ),
    )
    for invalid_draft in (mismatched_protocol, without_launcher, without_policy):
        with pytest.raises(SecretOnboardingProjectionSourceError):
            source.project(invalid_draft, requester, now_epoch=1_800_000_000)

    with pytest.raises(SecretOnboardingProjectionSourceError):
        replace(_rdp_binding(), policy_profile_ref=None)


def test_windows_rdp_profile_binds_verified_event_filter_without_exposing_name() -> None:
    draft = _rdp_draft()
    draft = replace(
        draft,
        desired_objects=(
            *draft.desired_objects,
            _desired(
                "rdp-event-filter-binding-ref",
                ObjectClass.RDP_EVENT_FILTER_BINDING,
                {"profile_ref": "approved-rdp-event-filter-ref"},
            ),
        ),
    )
    binding = replace(
        _rdp_binding(),
        rdp_event_filter_object_ref="rdp-event-filter-binding-ref",
        rdp_event_filter_profile_name="mcp-v4-rdp-event-filter-existing",
        rdp_event_filter_profile_ref="approved-rdp-event-filter-ref",
    )
    source = FortiPamSecretOnboardingProjectionSource(
        SecretTransport(),
        TargetTransport(),
        RdpLauncherTransport(),
        Resolver(binding),
        FolderPolicyTransport(),
        SecretPolicyClipboardTransport(),
        RecordingPolicyTransport(),
        RdpEventFilterTransport(),
    )

    projections = source.project(
        draft,
        AuthenticatedRequester("secret-source-requester", "operator"),
        now_epoch=1_800_000_000,
    )

    event_filter = next(
        item
        for item in projections
        if item.contract.object_class is ObjectClass.RDP_EVENT_FILTER_BINDING
    )
    assert event_filter.values == {
        "exists": True,
        "profile_ref": "approved-rdp-event-filter-ref",
    }
    assert "mcp-v4-rdp-event-filter-existing" not in json.dumps(
        [item.as_dict() for item in projections],
        sort_keys=True,
    )


def test_existing_secret_controls_project_current_false_state_separately_from_profile() -> None:
    source = FortiPamSecretOnboardingProjectionSource(
        SecretTransport(
            exists=True,
            session_controls=_session_controls_projection(),
        ),
        TargetTransport(),
        None,
        Resolver(_session_controls_binding()),
        rdp_event_filter_transport=RdpEventFilterTransport(),
    )

    projections = source.project(
        _session_controls_draft(),
        AuthenticatedRequester("secret-source-requester", "operator"),
        now_epoch=1_800_000_000,
    )

    assert len(projections) == 6
    controls = next(
        item
        for item in projections
        if item.contract.object_class
        is ObjectClass.SECRET_SESSION_CONTROLS_BINDING
    )
    event_filter = next(
        item
        for item in projections
        if item.contract.object_class is ObjectClass.RDP_EVENT_FILTER_BINDING
    )
    assert controls.values == {
        "clipboard_blocking_enabled": False,
        "event_filter_profile_digest": "a" * 64,
        "exists": True,
        "preserved_identity_digest": "b" * 64,
        "profile_ref": "approved-rdp-event-filter-ref",
        "rdp_event_filter_enabled": False,
        "rdp_event_filter_profile_matches": False,
        "recording_enabled": False,
    }
    assert event_filter.values == {
        "exists": True,
        "profile_ref": "approved-rdp-event-filter-ref",
    }
    assert controls.contract.contract_id == SECRET_SESSION_CONTROLS_SOURCE_CONTRACT
    assert controls.contract.version == SECRET_SESSION_CONTROLS_SOURCE_VERSION
    assert controls.contract.source_ref == SECRET_SESSION_CONTROLS_SOURCE_REF
    assert all(
        item.contract.contract_id == SOURCE_CONTRACT
        and item.contract.version == SOURCE_VERSION
        and item.contract.source_ref == SOURCE_REF
        for item in projections
        if item is not controls
    )
    rendered = json.dumps([item.as_dict() for item in projections], sort_keys=True)
    for private_value in (
        "private/folder",
        "private-target",
        "private-template",
        "mcp-v4-secret-metadata-linux01",
        "mcp-v4-rdp-event-filter-existing",
        "23",
    ):
        assert private_value not in rendered


def test_existing_secret_controls_project_actual_inheritance_state() -> None:
    source = FortiPamSecretOnboardingProjectionSource(
        SecretTransport(
            exists=True,
            inherit_permission_matches=False,
            session_controls=_session_controls_projection(
                inherit_permission=False,
            ),
        ),
        TargetTransport(),
        None,
        Resolver(_session_controls_binding()),
        rdp_event_filter_transport=RdpEventFilterTransport(),
    )

    draft = _session_controls_draft()
    draft = replace(
        draft,
        desired_objects=tuple(
            replace(
                item,
                desired_fields=(("inherit_permission", False),),
            )
            if item.object_class is ObjectClass.SECRET_METADATA
            else item
            for item in draft.desired_objects
        ),
    )
    projections = source.project(
        draft,
        AuthenticatedRequester("secret-source-requester", "operator"),
        now_epoch=1_800_000_000,
    )

    secret = next(
        item
        for item in projections
        if item.contract.object_class is ObjectClass.SECRET_METADATA
    )
    assert secret.values == {"exists": True, "inherit_permission": False}


def test_existing_secret_controls_project_exact_digest_drift() -> None:
    source = FortiPamSecretOnboardingProjectionSource(
        SecretTransport(
            exists=True,
            session_controls=_session_controls_projection(
                event_filter_profile_digest="c" * 64,
                preserved_identity_digest="d" * 64,
            ),
        ),
        TargetTransport(),
        None,
        Resolver(_session_controls_binding()),
        rdp_event_filter_transport=RdpEventFilterTransport(),
    )

    projections = source.project(
        _session_controls_draft(),
        AuthenticatedRequester("secret-source-requester", "operator"),
        now_epoch=1_800_000_000,
    )

    controls = next(
        item
        for item in projections
        if item.contract.object_class
        is ObjectClass.SECRET_SESSION_CONTROLS_BINDING
    )
    assert controls.values["event_filter_profile_digest"] == "c" * 64
    assert controls.values["preserved_identity_digest"] == "d" * 64
    desired = dict(
        next(
            item
            for item in _session_controls_draft().desired_objects
            if item.object_class
            is ObjectClass.SECRET_SESSION_CONTROLS_BINDING
        ).desired_fields
    )
    assert controls.values["event_filter_profile_digest"] != desired[
        "event_filter_profile_digest"
    ]
    assert controls.values["preserved_identity_digest"] != desired[
        "preserved_identity_digest"
    ]


@pytest.mark.parametrize(
    "secret_transport",
    [
        SecretTransport(
            exists=False,
            session_controls=_session_controls_projection(),
        ),
        SecretTransport(
            exists=True,
            session_controls=_session_controls_projection(proxy_enabled=False),
        ),
        SecretTransport(
            exists=True,
            session_controls=_session_controls_projection(
                tcp_forwarding_disabled=False,
            ),
        ),
    ],
)
def test_existing_secret_controls_reject_missing_secret_or_incompatible_path(
    secret_transport: SecretTransport,
) -> None:
    source = FortiPamSecretOnboardingProjectionSource(
        secret_transport,
        TargetTransport(),
        None,
        Resolver(_session_controls_binding()),
        rdp_event_filter_transport=RdpEventFilterTransport(),
    )

    with pytest.raises(SecretOnboardingProjectionSourceError):
        source.project(
            _session_controls_draft(),
            AuthenticatedRequester("secret-source-requester", "operator"),
            now_epoch=1_800_000_000,
        )


def test_windows_rdp_existing_secret_requires_supported_clipboard_control_path() -> None:
    draft = _rdp_draft()
    requester = AuthenticatedRequester("secret-source-requester", "operator")

    def source_for(
        compatible: bool,
    ) -> FortiPamSecretOnboardingProjectionSource:
        return FortiPamSecretOnboardingProjectionSource(
            SecretTransport(
                exists=True,
                rdp_clipboard_control_compatible=compatible,
            ),
            TargetTransport(),
            RdpLauncherTransport(),
            RdpResolver(),
            FolderPolicyTransport(),
            SecretPolicyClipboardTransport(),
            RecordingPolicyTransport(),
        )

    source_for(True).project(draft, requester, now_epoch=1_800_000_000)
    with pytest.raises(SecretOnboardingProjectionSourceError):
        source_for(False).project(draft, requester, now_epoch=1_800_000_000)


def test_existing_secret_is_rejected_when_safe_relationship_is_unverified() -> None:
    source = FortiPamSecretOnboardingProjectionSource(
        SecretTransport(exists=True, verified=False),
        TargetTransport(),
        LauncherTransport(),
        Resolver(),
    )

    with pytest.raises(SecretOnboardingProjectionSourceError):
        source.project(
            _draft(),
            AuthenticatedRequester("secret-source-requester", "operator"),
            now_epoch=1_800_000_000,
        )


def test_existing_secret_accepts_only_complete_metadata_relations() -> None:
    source = FortiPamSecretOnboardingProjectionSource(
        SecretTransport(exists=True),
        TargetTransport(),
        LauncherTransport(),
        Resolver(),
    )

    projections = source.project(
        _draft(),
        AuthenticatedRequester("secret-source-requester", "operator"),
        now_epoch=1_800_000_000,
    )

    secret = next(
        item
        for item in projections
        if item.contract.object_class is ObjectClass.SECRET_METADATA
    )
    assert dict(secret.fields) == {"exists": True, "inherit_permission": True}


def test_binding_must_match_the_exact_scheme_semantics() -> None:
    draft = _draft()
    changed = list(draft.desired_objects)
    changed[1] = _desired(
        "target-object-ref",
        ObjectClass.TARGET,
        {"connectivity_profile_ref": "ssh-profile-ref", "protocol": "sftp"},
    )
    mismatched = replace(draft, desired_objects=tuple(changed))
    source = FortiPamSecretOnboardingProjectionSource(
        SecretTransport(),
        TargetTransport(),
        LauncherTransport(),
        Resolver(),
    )

    with pytest.raises(SecretOnboardingProjectionSourceError):
        source.project(
            mismatched,
            AuthenticatedRequester("secret-source-requester", "operator"),
            now_epoch=1_800_000_000,
        )


def test_owner_only_resolver_binds_requester_and_scope(tmp_path: Path) -> None:
    draft = _draft()
    requester = AuthenticatedRequester("secret-source-requester", "operator")
    binding = _binding()
    binding_payload = asdict(binding)
    for field in (
        "policy_object_ref",
        "policy_folder_id",
        "policy_folder_name",
        "policy_profile_name",
        "policy_profile_ref",
        "rdp_event_filter_object_ref",
        "rdp_event_filter_profile_name",
        "rdp_event_filter_profile_ref",
        "secret_session_controls_object_ref",
        "existing_secret_id",
        "session_controls_identity_digest",
    ):
        binding_payload.pop(field)
    binding_payload.update(
        {
            "secret_account_type": "local",
            "secret_enabled": True,
            "secret_lifecycle_class": "managed",
        }
    )
    path = tmp_path / "secret-binding.json"
    path.write_text(
        json.dumps(
            {
                "contract": SOURCE_CONTRACT,
                "version": LEGACY_SOURCE_VERSION,
                "requester_digest": requester.digest,
                "environment_ref": draft.environment_ref,
                "scope_ref": draft.scope_ref,
                **binding_payload,
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    resolver = OwnerOnlySecretOnboardingBindingResolver(path)

    assert resolver.resolve(draft, requester) == binding
    with pytest.raises(SecretOnboardingProjectionSourceError):
        resolver.resolve(
            draft,
            AuthenticatedRequester("different-requester", "operator"),
        )


def test_owner_only_resolver_accepts_exact_session_controls_binding(
    tmp_path: Path,
) -> None:
    draft = _session_controls_draft()
    requester = AuthenticatedRequester("secret-source-requester", "operator")
    binding = _session_controls_binding()
    binding_payload = asdict(binding)
    for field in (
        "policy_object_ref",
        "policy_folder_id",
        "policy_folder_name",
        "policy_profile_name",
        "policy_profile_ref",
    ):
        binding_payload.pop(field)
    path = tmp_path / "secret-session-controls-binding.json"
    path.write_text(
        json.dumps(
            {
                "contract": SOURCE_CONTRACT,
                "version": SECRET_SESSION_CONTROLS_BINDING_VERSION,
                "requester_digest": requester.digest,
                "environment_ref": draft.environment_ref,
                "scope_ref": draft.scope_ref,
                **binding_payload,
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)

    resolved = OwnerOnlySecretOnboardingBindingResolver(path).resolve(
        draft,
        requester,
    )

    assert resolved == binding
    assert resolved.existing_secret_id == 23
    assert resolved.secret_session_controls_object_ref == (
        "secret-session-controls-ref"
    )
    assert resolved.session_controls_identity_digest == "b" * 64
    invalid_payload = json.loads(path.read_text(encoding="utf-8"))
    invalid_payload["version"] = SOURCE_VERSION
    path.write_text(json.dumps(invalid_payload), encoding="utf-8")
    with pytest.raises(SecretOnboardingProjectionSourceError):
        OwnerOnlySecretOnboardingBindingResolver(path).resolve(draft, requester)

    invalid_payload = json.loads(
        json.dumps(
            {
                "contract": SOURCE_CONTRACT,
                "version": SECRET_SESSION_CONTROLS_BINDING_VERSION,
                "requester_digest": requester.digest,
                "environment_ref": draft.environment_ref,
                "scope_ref": draft.scope_ref,
                **binding_payload,
            }
        )
    )
    invalid_payload["session_controls_identity_digest"] = "not-a-digest"
    path.write_text(json.dumps(invalid_payload), encoding="utf-8")
    with pytest.raises(SecretOnboardingProjectionSourceError):
        OwnerOnlySecretOnboardingBindingResolver(path).resolve(draft, requester)
    invalid_payload["session_controls_identity_digest"] = "b" * 64
    invalid_payload["version"] = SECRET_SESSION_CONTROLS_BINDING_VERSION
    invalid_payload.pop("existing_secret_id")
    path.write_text(json.dumps(invalid_payload), encoding="utf-8")
    with pytest.raises(SecretOnboardingProjectionSourceError):
        OwnerOnlySecretOnboardingBindingResolver(path).resolve(draft, requester)


def test_owner_only_resolver_accepts_exact_web_account_binding(tmp_path: Path) -> None:
    draft = _web_draft()
    requester = AuthenticatedRequester("secret-source-requester", "operator")
    binding = _web_binding()
    path = tmp_path / "web-secret-binding.json"
    path.write_text(
        json.dumps(
            {
                "contract": SOURCE_CONTRACT,
                "version": SOURCE_VERSION,
                "requester_digest": requester.digest,
                "environment_ref": draft.environment_ref,
                "scope_ref": draft.scope_ref,
                **asdict(binding),
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)

    assert OwnerOnlySecretOnboardingBindingResolver(path).resolve(
        draft,
        requester,
    ) == binding


def test_secret_source_host_requires_both_authorities(tmp_path: Path) -> None:
    settings = V4SyntheticHostSettings(
        tmp_path / "planning.sqlite3",
        tmp_path / "planning.hmac",
        reference_authority=V4PersistentReferenceAuthoritySettings(
            tmp_path / "reference.sqlite3",
            tmp_path / "reference.hmac",
        ),
    )

    with pytest.raises(V4RuntimeHostError, match="Scheme Draft Authority"):
        secret_onboarding_v4_plan_host_factory(
            settings,
            secret_transport=SecretTransport(),
            target_transport=TargetTransport(),
            launcher_transport=LauncherTransport(),
            binding_resolver=Resolver(),
        )


@pytest.mark.parametrize("profile", ["linux", "collector", "web"])
def test_secret_source_host_runs_sanitized_end_to_end_preview(tmp_path: Path, profile: str) -> None:
    now = 1_800_000_000
    state = tmp_path / "state"
    oauth = tmp_path / "oauth"
    state.mkdir(mode=0o700)
    oauth.mkdir(mode=0o700)

    def owner_file(name: str, value: bytes) -> Path:
        path = state / name
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    requester = AuthenticatedRequester("a" * 64, "operator")
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(
                "correct-horse-battery-staple",
                salt=b"0123456789abcdef",
            ),
        )
    )
    settings = V4SyntheticHostSettings(
        state / "planning.sqlite3",
        owner_file("planning.hmac", b"p" * 32),
        reference_authority=V4PersistentReferenceAuthoritySettings(
            state / "reference.sqlite3",
            owner_file("reference.hmac", b"r" * 32),
        ),
        scheme_draft_authority=V4PersistentSchemeDraftAuthoritySettings(
            state / "draft.sqlite3",
            owner_file("draft.hmac", b"d" * 32),
        ),
    )
    draft = _draft()
    source_ref = SOURCE_REF
    collector_binding = None
    selected_transport = SecretTransport()
    selected_resolver = Resolver()
    if profile == "web":
        draft = _web_draft()
        selected_resolver = WebResolver()
    if profile == "collector":
        from test_secret_create_lab_auto_runtime import _collector_context
        from fortipam_mcp.secret_metadata_http_transport import SecretMetadataInspection
        from fortipam_mcp.winrm_collector_projection_reader import winrm_collector_projection_contract
        _, bound, collector_binding, draft, _ = _collector_context()
        source_ref = winrm_collector_projection_contract().source_ref

        class CollectorResolver:
            def resolve(self, requested, principal):
                assert requested == draft and principal == requester
                return bound

        class CollectorTransport(SecretTransport):
            def inspect(self, *args):
                return SecretMetadataInspection(False, True, True)

            def verify_winrm_collector_preflight(self, *args):
                return True

        selected_transport = CollectorTransport()
        selected_resolver = CollectorResolver()
    components = secret_onboarding_v4_plan_host_factory(
        settings,
        secret_transport=selected_transport,
        target_transport=None if profile == "web" else TargetTransport(),
        launcher_transport=LauncherTransport(),
        binding_resolver=selected_resolver,
        collector_binding=collector_binding,
        clock=lambda: now,
    )(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            owner_file("confirmation.hmac", b"c" * 32),
            owner_file("receipt.hmac", b"e" * 32),
        ),
    )
    draft_authority = components.scheme_draft_authority
    reference_authority = components.reference_authority
    assert draft_authority is not None
    assert reference_authority is not None
    draft_ref = draft_authority.issue(
        draft,
        requester,
        expires_at=now + 300,
        now_epoch=now,
    )
    object_kinds = {
        ObjectClass.FOLDER_BINDING: "folder_binding",
        ObjectClass.TARGET: "target",
        ObjectClass.TEMPLATE_BINDING: "template_binding",
        ObjectClass.SECRET_METADATA: "secret_metadata",
        ObjectClass.WEB_SECRET_METADATA: "web_secret_metadata",
        ObjectClass.WINRM_COLLECTOR_METADATA: "winrm_collector_metadata",
        ObjectClass.LAUNCHER_BINDING: "launcher_binding",
    }
    bindings = {
        (source_ref, "projection_source"),
        (draft.environment_ref, "environment"),
        (draft.scope_ref, "scope"),
        (draft.owner_ref, "owner"),
        (draft.audience_ref, "audience"),
        *((value, "evidence") for value in draft.evidence_refs),
    }
    for desired in draft.desired_objects:
        bindings.add((desired.object_ref, f"object_{object_kinds[desired.object_class]}"))
        bindings.update(
            (value, f"field_{name}")
            for name, value in desired.desired_fields
            if name.endswith("_ref") and isinstance(value, str)
        )
    reference_authority.issue_many(
        tuple(sorted(bindings)),
        requester_digest=requester.digest,
        environment_ref=draft.environment_ref,
        scope_ref=draft.scope_ref,
        expires_at=now + 300,
        now_epoch=now,
    )

    preview = components.plan_services.preview(
        draft_ref,
        V4PlanningPrincipal(requester, "b" * 64),
    )

    assert preview["state"] == "awaiting_confirmation"
    assert preview["current_state_digest"]
    assert preview["proposed_changes_digest"]
    assert preview["expected_state_digest"]
    status = components.plan_services.status()
    assert status["projection_mode"] == "source_backed"
    assert status["projection_contract_registered"] is True
    assert status["device_access"] is True
    blocker_codes = status["blocker_codes"]
    assert isinstance(blocker_codes, list)
    assert "live_projection_unbound" not in blocker_codes
    rendered = json.dumps(preview, sort_keys=True)
    for private_value in (
        "private/folder",
        "private-target",
        "192.0.2.10",
        "private-template",
        "private-launcher",
        "mcp-v4-secret-metadata-linux01",
    ):
        assert private_value not in rendered


def test_combined_host_previews_both_onboarding_schemes_without_restart(
    tmp_path: Path,
) -> None:
    now = 1_800_000_000
    state = tmp_path / "state"
    oauth = tmp_path / "oauth"
    state.mkdir(mode=0o700)
    oauth.mkdir(mode=0o700)

    def owner_file(name: str, value: bytes) -> Path:
        path = state / name
        path.write_bytes(value)
        path.chmod(0o600)
        return path

    requester = AuthenticatedRequester("a" * 64, "operator")
    provider = LocalOAuthProvider(
        LocalOAuthSettings(
            issuer="https://mcp.example.com/fpamcp-v4/oauth",
            resource="https://mcp.example.com/fpamcp-v4",
            database_path=oauth / "oauth.sqlite3",
            username="operator",
            password_hash=hash_local_password(
                "correct-horse-battery-staple",
                salt=b"0123456789abcdef",
            ),
        )
    )
    settings = V4SyntheticHostSettings(
        state / "planning.sqlite3",
        owner_file("planning.hmac", b"p" * 32),
        reference_authority=V4PersistentReferenceAuthoritySettings(
            state / "reference.sqlite3",
            owner_file("reference.hmac", b"r" * 32),
        ),
        scheme_draft_authority=V4PersistentSchemeDraftAuthoritySettings(
            state / "draft.sqlite3",
            owner_file("draft.hmac", b"d" * 32),
        ),
    )
    components = onboarding_v4_plan_host_factory(
        settings,
        folder_transport=FolderTransport(),
        access_domain_binding_resolver=AccessResolver(),
        secret_transport=SecretTransport(),
        target_transport=TargetTransport(),
        launcher_transport=LauncherTransport(),
        secret_binding_resolver=Resolver(),
        clock=lambda: now,
    )(
        provider,
        V4ConfirmationSettings(
            state / "confirmation.sqlite3",
            owner_file("confirmation.hmac", b"c" * 32),
            owner_file("receipt.hmac", b"e" * 32),
        ),
    )
    draft_authority = components.scheme_draft_authority
    reference_authority = components.reference_authority
    assert draft_authority is not None
    assert reference_authority is not None

    access_ref = issue_synthetic_scheme_draft(
        draft_authority,
        requester,
        expires_at=now + 300,
        now_epoch=now,
    )
    issue_synthetic_reference_grants(
        reference_authority,
        requester_digest=requester.digest,
        expires_at=now + 300,
        now_epoch=now,
    )
    reference_authority.issue_many(
        ((ACCESS_SOURCE_REF, "projection_source"),),
        requester_digest=requester.digest,
        environment_ref="synthetic-lab-environment",
        scope_ref="synthetic-access-scope",
        expires_at=now + 300,
        now_epoch=now,
    )

    secret_draft = _draft()
    secret_ref = draft_authority.issue(
        secret_draft,
        requester,
        expires_at=now + 300,
        now_epoch=now,
    )
    object_kinds = {
        ObjectClass.FOLDER_BINDING: "folder_binding",
        ObjectClass.TARGET: "target",
        ObjectClass.TEMPLATE_BINDING: "template_binding",
        ObjectClass.SECRET_METADATA: "secret_metadata",
        ObjectClass.LAUNCHER_BINDING: "launcher_binding",
    }
    bindings = {
        (SOURCE_REF, "projection_source"),
        (secret_draft.environment_ref, "environment"),
        (secret_draft.scope_ref, "scope"),
        (secret_draft.owner_ref, "owner"),
        (secret_draft.audience_ref, "audience"),
        *((value, "evidence") for value in secret_draft.evidence_refs),
    }
    for desired in secret_draft.desired_objects:
        bindings.add((desired.object_ref, f"object_{object_kinds[desired.object_class]}"))
        bindings.update(
            (value, f"field_{name}")
            for name, value in desired.desired_fields
            if name.endswith("_ref") and isinstance(value, str)
        )
    reference_authority.issue_many(
        tuple(sorted(bindings)),
        requester_digest=requester.digest,
        environment_ref=secret_draft.environment_ref,
        scope_ref=secret_draft.scope_ref,
        expires_at=now + 300,
        now_epoch=now,
    )
    composite_secret_objects = tuple(
        replace(
            item,
            desired_fields=(
                ("folder_ref", "synthetic-public-folder-reference"),
            ),
        )
        if item.object_class is ObjectClass.FOLDER_BINDING
        else item
        for item in secret_draft.desired_objects
    )
    composite_draft = replace(
        secret_draft,
        owner_ref="synthetic-owner-reference",
        scope_ref="combined-linux-scope",
        desired_objects=(
            _desired(
                "synthetic-public-folder-reference",
                ObjectClass.PUBLIC_FOLDER,
                {
                    "enabled": True,
                    "owner_ref": "synthetic-owner-reference",
                },
            ),
            _desired(
                "synthetic-access-grant-reference",
                ObjectClass.ACCESS_GRANT,
                {
                    "permission": "use",
                    "subject_class": "group",
                    "subject_ref": "synthetic-group-reference",
                },
            ),
            *composite_secret_objects,
        ),
    )
    composite_ref = draft_authority.issue(
        composite_draft,
        requester,
        expires_at=now + 300,
        now_epoch=now,
    )
    composite_kinds = {
        ObjectClass.PUBLIC_FOLDER: "public_folder",
        ObjectClass.ACCESS_GRANT: "access_grant",
        **object_kinds,
    }
    composite_bindings = {
        (ACCESS_SOURCE_REF, "projection_source"),
        (SOURCE_REF, "projection_source"),
        (composite_draft.environment_ref, "environment"),
        (composite_draft.scope_ref, "scope"),
        (composite_draft.owner_ref, "owner"),
        (composite_draft.audience_ref, "audience"),
        *((value, "evidence") for value in composite_draft.evidence_refs),
    }
    for desired in composite_draft.desired_objects:
        composite_bindings.add(
            (
                desired.object_ref,
                f"object_{composite_kinds[desired.object_class]}",
            )
        )
        composite_bindings.update(
            (value, f"field_{name}")
            for name, value in desired.desired_fields
            if name.endswith("_ref") and isinstance(value, str)
        )
    reference_authority.issue_many(
        tuple(sorted(composite_bindings)),
        requester_digest=requester.digest,
        environment_ref=composite_draft.environment_ref,
        scope_ref=composite_draft.scope_ref,
        expires_at=now + 300,
        now_epoch=now,
    )
    principal = V4PlanningPrincipal(requester, "b" * 64)

    access_preview = components.plan_services.preview(access_ref, principal)
    secret_preview = components.plan_services.preview(secret_ref, principal)
    composite_preview = components.plan_services.preview(composite_ref, principal)

    assert access_preview["state"] == "awaiting_confirmation"
    assert secret_preview["state"] == "awaiting_confirmation"
    assert composite_preview["state"] == "awaiting_confirmation"
    assert access_preview["summary_ref"] != secret_preview["summary_ref"]
    assert composite_preview["summary_ref"] not in {
        access_preview["summary_ref"],
        secret_preview["summary_ref"],
    }
    status = components.plan_services.status()
    assert status["projection_mode"] == "source_backed"
    assert status["projection_contract_registered"] is True
    assert status["device_access"] is True
    blocker_codes = status["blocker_codes"]
    assert isinstance(blocker_codes, list)
    assert "live_projection_unbound" not in blocker_codes
    assert status["dispatchable"] is False
    assert status["product_write_enabled"] is False


@pytest.mark.parametrize("service_enabled", [False, True])
def test_existing_web_service_projection_uses_observed_state_and_pinned_id(service_enabled):
    binding = replace(_web_binding(), service_object_ref="web-service-object-ref", existing_secret_id=24)
    draft = _web_draft()
    draft = replace(draft, material_reference_metadata=None, desired_objects=(
        *draft.desired_objects,
        _desired("web-service-object-ref", ObjectClass.WEB_SECRET_SERVICE_BINDING,
                 {"http_service_enabled": True}),
    ))
    class Resolver:
        def resolve(self, draft, requester):
            return binding
    class Reader(SecretTransport):
        def inspect_web_projection(self, folder, name, template, *, expected_secret_id):
            assert (folder, name, template, expected_secret_id) == (
                binding.folder_path, binding.secret_name, "Web Account", 24,
            )
            return SecretMetadataProjectionInspection(
                True, True, True, True, True, True, True, False,
                recording_matches=True, http_service_enabled=service_enabled,
            )
    source = FortiPamSecretOnboardingProjectionSource(Reader(), TargetTransport(), None, Resolver())
    projections = source.project(
        draft, AuthenticatedRequester("secret-source-requester", "operator"), now_epoch=1_800_000_000,
    )
    service = next(p for p in projections if p.object_ref == "web-service-object-ref")
    assert dict(service.fields) == {"exists": True, "http_service_enabled": service_enabled}
    assert len(projections) == 4


@pytest.mark.parametrize("changes", [
    {"service_object_ref": "web-service-object-ref"},
    {"existing_secret_id": 24},
    {"service_object_ref": "web-service-object-ref", "existing_secret_id": True},
])
def test_web_service_binding_requires_complete_exact_identity(changes):
    with pytest.raises(SecretOnboardingProjectionSourceError):
        replace(_web_binding(), **changes)
