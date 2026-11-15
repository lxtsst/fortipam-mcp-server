from __future__ import annotations

from dataclasses import replace

import pytest

from fortipam_mcp.secret_create_191_private_adapter import (
    SecretCreate191TargetBinding,
    SecretCreate191WebBinding,
)
from fortipam_mcp.secret_create_191_projection_reader import (
    SECRET_CREATE_191_PROJECTION_UNAVAILABLE,
    SecretCreate191ProjectionReader,
    SecretCreate191ProjectionReaderError,
)
from fortipam_mcp.secret_metadata_http_transport import (
    SecretMetadataProjectionInspection,
)
from fortipam_mcp.secret_onboarding_projection_source import (
    SecretOnboardingBinding,
    WebSecretOnboardingBinding,
    secret_onboarding_projection_contract,
)
from v4_planning import (
    AuthoritativeProjection,
    M4ExecutionPlan,
    ObjectClass,
    canonical_digest,
)
from v4_planning.secret_create_adapter import (
    SECRET_CREATE_ACTION_ID,
    SECRET_CREATE_ACTION_VERSION,
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
    )


def _expected_digest(binding: SecretOnboardingBinding, *, exists: bool) -> str:
    fields: dict[str, bool | str] = {"exists": exists}
    if exists:
        fields["inherit_permission"] = True
    return AuthoritativeProjection.from_mapping(
        contract=secret_onboarding_projection_contract(ObjectClass.SECRET_METADATA),
        object_ref=binding.secret_object_ref,
        observed_at=10,
        fresh_until=11,
        fields=fields,
    ).state_digest


def _plan(binding: SecretOnboardingBinding, *, target_ref: str | None = None):
    values = {
        "action_id": SECRET_CREATE_ACTION_ID,
        "action_version": SECRET_CREATE_ACTION_VERSION,
        "adapter_ref": "fortipam-191-secret-create-private-adapter",
        "approval_digest": "a" * 64,
        "compensation_ref": None,
        "confirmation_digest": "b" * 64,
        "expected_current_digest": _expected_digest(binding, exists=False),
        "expected_state_digest": _expected_digest(binding, exists=True),
        "expires_at": 2_000,
        "idempotency_digest": "c" * 64,
        "parameters_digest": "d" * 64,
        "plan_ref": "secret-create-m4-plan-ref01",
        "requester_digest": "e" * 64,
        "revision": 1,
        "summary_digest": "f" * 64,
        "target_ref": target_ref or binding.secret_object_ref,
    }
    return M4ExecutionPlan(**values, plan_digest=canonical_digest(values))


class _Transport:
    def __init__(self) -> None:
        self.inspection = SecretMetadataProjectionInspection(
            False,
            True,
            True,
            False,
            False,
            False,
            False,
            False,
        )

    def inspect_projection(
        self,
        folder_path,
        secret_name,
        template_name,
        target_name,
        *,
        expected_rdp_event_filter_profile=None,
    ):
        assert (folder_path, secret_name, template_name, target_name) == (
            "private/folder",
            "mcp-v4-secret-metadata-linux01",
            "private-template",
            "private-target",
        )
        return self.inspection

    def inspect_web_projection(self, folder_path, secret_name, template_name):
        assert (folder_path, secret_name, template_name) == (
            "private/folder",
            "mcp-v4-secret-metadata-web01",
            "Web Account",
        )
        return self.inspection


def test_reader_accepts_exact_recorded_non_target_web_account() -> None:
    binding = WebSecretOnboardingBinding(
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

    def digest(*, exists: bool) -> str:
        fields = {"exists": exists}
        if exists:
            fields.update({"inherit_permission": True, "session_recording": True})
        return AuthoritativeProjection.from_mapping(
            contract=secret_onboarding_projection_contract(
                ObjectClass.WEB_SECRET_METADATA
            ),
            object_ref=binding.secret_object_ref,
            observed_at=10,
            fresh_until=11,
            fields=fields,
        ).state_digest

    values = {
        "action_id": SECRET_CREATE_ACTION_ID,
        "action_version": SECRET_CREATE_ACTION_VERSION,
        "adapter_ref": "fortipam-191-secret-create-private-adapter",
        "approval_digest": "a" * 64,
        "compensation_ref": None,
        "confirmation_digest": "b" * 64,
        "expected_current_digest": digest(exists=False),
        "expected_state_digest": digest(exists=True),
        "expires_at": 2_000,
        "idempotency_digest": "c" * 64,
        "parameters_digest": "d" * 64,
        "plan_ref": "secret-create-m4-plan-ref01",
        "requester_digest": "e" * 64,
        "revision": 1,
        "summary_digest": "f" * 64,
        "target_ref": binding.secret_object_ref,
    }
    plan = M4ExecutionPlan(**values, plan_digest=canonical_digest(values))
    transport = _Transport()
    reader = SecretCreate191ProjectionReader(
        binding,
        SecretCreate191WebBinding(
            "fortipam-191-web-secret-create-private-v1",
            "1.9.1",
            plan.plan_digest,
            binding.folder_path,
            binding.secret_name,
            binding.template_name,
            binding.web_url,
            True,
        ),
        transport,
    )

    assert reader.read_current(plan) == digest(exists=False)
    transport.inspection = SecretMetadataProjectionInspection(
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        recording_matches=True,
    )
    with pytest.raises(SecretCreate191ProjectionReaderError, match="unavailable"):
        reader.read_postcondition(plan)
    transport.inspection = replace(transport.inspection, http_service_enabled=True)
    assert reader.read_postcondition(plan) == digest(exists=True)
    transport.inspection = replace(transport.inspection, recording_matches=False)
    with pytest.raises(SecretCreate191ProjectionReaderError, match="unavailable"):
        reader.read_postcondition(plan)


def test_reader_accepts_absence_then_exact_metadata_relation_postcondition() -> None:
    binding = _binding()
    plan = _plan(binding)
    transport = _Transport()
    reader = SecretCreate191ProjectionReader(
        binding,
        SecretCreate191TargetBinding(
            "fortipam-191-secret-create-private-v1",
            "1.9.1",
            plan.plan_digest,
            binding.folder_path,
            binding.secret_name,
            binding.template_name,
            binding.target_name,
            "192.0.2.10",
        ),
        transport,
    )

    assert reader.read_current(plan) == _expected_digest(binding, exists=False)
    transport.inspection = SecretMetadataProjectionInspection(
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
    )
    with pytest.raises(SecretCreate191ProjectionReaderError, match="unavailable"):
        reader.read_current(plan)
    assert reader.read_postcondition(plan) == _expected_digest(binding, exists=True)

    transport.inspection = replace(transport.inspection, target_matches=False)
    with pytest.raises(SecretCreate191ProjectionReaderError, match="unavailable"):
        reader.read_postcondition(plan)


def test_reader_accepts_exact_windows_rdp_dependency_binding() -> None:
    binding = replace(
        _binding(),
        target_protocol="rdp",
        connectivity_profile_ref="rdp-profile-ref",
        launcher_object_ref="launcher-binding-ref",
        launcher_name="remote-desktop-windows",
        launcher_profile_ref="native-rdp-profile-ref",
        policy_object_ref="policy-binding-ref",
        policy_folder_id=17,
        policy_folder_name="folder",
        policy_profile_name="rdp-policy",
        policy_profile_ref="rdp-policy-profile-ref",
        rdp_event_filter_object_ref="rdp-event-filter-binding-ref",
        rdp_event_filter_profile_name="mcp-v4-rdp-event-filter-existing",
        rdp_event_filter_profile_ref="rdp-event-filter-profile-ref",
    )
    plan = _plan(binding)
    transport = _Transport()
    reader = SecretCreate191ProjectionReader(
        binding,
        SecretCreate191TargetBinding(
            "fortipam-191-secret-create-private-v1",
            "1.9.1",
            plan.plan_digest,
            binding.folder_path,
            binding.secret_name,
            binding.template_name,
            binding.target_name,
            binding.target_ipv4_address,
            binding.rdp_event_filter_profile_name,
            rdp_service_enabled=True,
        ),
        transport,
    )

    assert reader.read_current(plan) == _expected_digest(binding, exists=False)
    transport.inspection = SecretMetadataProjectionInspection(
        True,
        True,
        True,
        True,
        True,
        True,
        True,
        False,
        False,
    )
    with pytest.raises(SecretCreate191ProjectionReaderError, match="unavailable"):
        reader.read_postcondition(plan)
    transport.inspection = replace(
        transport.inspection,
        rdp_event_filter_matches=True,
    )
    with pytest.raises(SecretCreate191ProjectionReaderError, match="unavailable"):
        reader.read_postcondition(plan)
    transport.inspection = replace(transport.inspection, rdp_service_enabled=True)
    assert reader.read_postcondition(plan) == _expected_digest(binding, exists=True)


def test_build29_linux_ssh_postcondition_requires_ssh_service() -> None:
    class LinuxTransport(_Transport):
        def inspect_projection(self, *args, **kwargs):
            return self.inspection

    binding = replace(_binding(), template_name="Unix Account (SSH Password)")
    plan = _plan(binding)
    transport = LinuxTransport()
    reader = SecretCreate191ProjectionReader(
        binding,
        SecretCreate191TargetBinding(
            "fortipam-700-build29-linux-ssh-create-candidate-v1", "7.0.0",
            plan.plan_digest, binding.folder_path, binding.secret_name,
            "Unix Account (SSH Password)", binding.target_name,
            binding.target_ipv4_address, target_product_build=29,
        ),
        transport,
    )
    transport.inspection = SecretMetadataProjectionInspection(
        True, True, True, True, True, True, True, False,
    )
    with pytest.raises(SecretCreate191ProjectionReaderError, match="unavailable"):
        reader.read_postcondition(plan)
    transport.inspection = replace(transport.inspection, ssh_service_enabled=True)
    assert reader.read_postcondition(plan) == _expected_digest(binding, exists=True)


def test_build29_linux_v2_postcondition_requires_sftp_and_recording() -> None:
    class LinuxTransport(_Transport):
        def inspect_projection(self, *args, **kwargs):
            return self.inspection

    binding = replace(_binding(), template_name="Unix Account (SSH Password)")
    plan = _plan(binding)
    transport = LinuxTransport()
    reader = SecretCreate191ProjectionReader(
        binding,
        SecretCreate191TargetBinding(
            "fortipam-700-build29-linux-ssh-sftp-recording-create-candidate-v2",
            "7.0.0", plan.plan_digest, binding.folder_path, binding.secret_name,
            binding.template_name, binding.target_name, binding.target_ipv4_address,
            target_product_build=29,
        ),
        transport,
    )
    baseline = SecretMetadataProjectionInspection(
        True, True, True, True, True, True, True, False,
        ssh_service_enabled=True,
    )
    transport.inspection = baseline
    with pytest.raises(SecretCreate191ProjectionReaderError, match="unavailable"):
        reader.read_postcondition(plan)
    transport.inspection = replace(baseline, sftp_service_enabled=True)
    with pytest.raises(SecretCreate191ProjectionReaderError, match="unavailable"):
        reader.read_postcondition(plan)
    transport.inspection = replace(transport.inspection, recording_matches=True)
    assert reader.read_postcondition(plan) == _expected_digest(binding, exists=True)


@pytest.mark.parametrize("missing", ["rdp_service_enabled", "recording_matches",
                                    "clipboard_blocking_matches", "rdp_clipboard_control_compatible"])
def test_build29_rdp_postcondition_requires_recording_and_compatible_clipboard(missing) -> None:
    from test_secret_onboarding_projection_source import _rdp_binding
    binding = replace(_rdp_binding(), template_name="Windows Machine")
    plan = _plan(binding)
    class RdpTransport(_Transport):
        def inspect_projection(self, folder, secret, template, target, **kwargs):
            assert (folder, secret, template, target) == (
                binding.folder_path, binding.secret_name, binding.template_name,
                binding.target_name,
            )
            return self.inspection

    transport = RdpTransport()
    reader = SecretCreate191ProjectionReader(
        binding,
        SecretCreate191TargetBinding(
            "fortipam-700-build29-windows-rdp-create-candidate-v1", "7.0.0",
            plan.plan_digest, binding.folder_path, binding.secret_name,
            binding.template_name, binding.target_name, binding.target_ipv4_address,
            binding.rdp_event_filter_profile_name, True, 29,
        ), transport,
    )
    baseline = SecretMetadataProjectionInspection(
        True, True, True, True, True, True, True, False,
        rdp_event_filter_matches=True, rdp_service_enabled=True,
        recording_matches=True, clipboard_blocking_matches=True,
        rdp_clipboard_control_compatible=True,
    )
    transport.inspection = replace(baseline, **{missing: False})
    with pytest.raises(SecretCreate191ProjectionReaderError):
        reader.read_postcondition(plan)
    transport.inspection = baseline
    assert reader.read_postcondition(plan) == _expected_digest(binding, exists=True)


def test_reader_rejects_wrong_binding_relation_or_plan_without_disclosure() -> None:
    binding = _binding()
    plan = _plan(binding)
    transport = _Transport()
    target_binding = SecretCreate191TargetBinding(
        "fortipam-191-secret-create-private-v1",
        "1.9.1",
        plan.plan_digest,
        binding.folder_path,
        binding.secret_name,
        binding.template_name,
        binding.target_name,
        "192.0.2.10",
    )
    with pytest.raises(
        SecretCreate191ProjectionReaderError,
        match=SECRET_CREATE_191_PROJECTION_UNAVAILABLE,
    ):
        SecretCreate191ProjectionReader(
            binding,
            replace(target_binding, folder_path="different/folder"),
            transport,
        )
    with pytest.raises(
        SecretCreate191ProjectionReaderError,
        match=SECRET_CREATE_191_PROJECTION_UNAVAILABLE,
    ):
        SecretCreate191ProjectionReader(
            binding,
            replace(target_binding, target_name="different-target"),
            transport,
        )

    reader = SecretCreate191ProjectionReader(binding, target_binding, transport)
    with pytest.raises(SecretCreate191ProjectionReaderError, match="unavailable"):
        reader.read_current(_plan(binding, target_ref="different-secret-ref01"))

    for inspection in (
        replace(transport.inspection, folder_exists=False),
        replace(transport.inspection, template_exists=False),
    ):
        transport.inspection = inspection
        with pytest.raises(SecretCreate191ProjectionReaderError, match="unavailable"):
            reader.read_current(plan)
