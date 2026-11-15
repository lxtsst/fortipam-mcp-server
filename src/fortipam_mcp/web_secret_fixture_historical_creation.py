"""Read original Web fixture custody after restart; never renew execution.

The original deterministic M4 calculation is checked against the existing
successful claim and original signed metadata/native ACK. No provider, lease,
POST, Tool or recovery authority is constructed. Historical inputs cannot
qualify a source observation or reopen a consumed operation.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from v4_planning import ChangeKind, ObjectClass, PreparedPlan, SchemeDraft, SchemeId, canonical_digest
from v4_planning.material_provider import C3MaterialBinding, _OpaqueC3Object

from .m4_execution_store import PersistentM4ExecutionStateStore
from .secret_create_191_http_transport import FortiPam191SecretCreateHttpTransport
from .secret_create_191_private_adapter import SecretCreate191WebBinding
from .secret_create_lab_auto_runtime import (
    LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_ADAPTER_REF,
    LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE,
    LabAutoSecretCreatePromoter,
)
from .secret_create_m4_runtime import SecretCreateM4ExecutionBinding
from .secret_metadata_http_transport import FortiPamSecretMetadataHttpTransport, SecretMetadataHttpTransportConfig
from .secret_onboarding_projection_source import WebSecretOnboardingBinding
from .web_secret_create_ack import WebSecretCreateAckCapture
from .web_secret_fixture_creation_record import (
    WebSecretFixtureAcknowledgedCreation,
    WebSecretFixtureCreationRecord,
)

_ERROR = "The original private Web fixture custody is unavailable."


class WebSecretFixtureHistoricalCreationError(ValueError):
    """Categorical refusal without identities, keys or native data."""


@dataclass(frozen=True, slots=True, repr=False)
class WebSecretFixtureHistoricalCreation(_OpaqueC3Object):
    """Original custody only; not a normally admitted or recovery fixture."""

    _record: WebSecretFixtureCreationRecord
    _original: WebSecretFixtureAcknowledgedCreation
    _display_name = "WebSecretFixtureHistoricalCreation"

    def read_original(self) -> WebSecretFixtureAcknowledgedCreation:
        try:
            if self._record.read_acknowledged_creation() != self._original:
                raise ValueError
            return self._original
        except Exception:
            raise WebSecretFixtureHistoricalCreationError(_ERROR) from None


def read_historical_web_fixture_creation(
    config: SecretMetadataHttpTransportConfig,
    *,
    original_plan: PreparedPlan,
    original_draft: SchemeDraft,
    onboarding_binding: WebSecretOnboardingBinding,
    original_promoter: LabAutoSecretCreatePromoter,
    execution_store: PersistentM4ExecutionStateStore,
    expected_store_digest: str,
    serial_digest: str,
    directory: Path,
    key_file: Path,
    original_ack_capture: WebSecretCreateAckCapture | None = None,
) -> WebSecretFixtureHistoricalCreation:
    """Recalculate original context solely to authenticate retained records.

    Trusted composition supplies the original protected paths, authority key
    and plan/draft inputs. Calculation retains their original expiry; it never
    calls promote, advances a clock, issues a grant or resolves material.
    The original signed record independently binds that context, namespace,
    key, native identity and successful M4 claim. A missing original record,
    ACK or ledger refuses; no replacement store is opened here.
    """
    try:
        if (type(config) is not SecretMetadataHttpTransportConfig
                or type(original_plan) is not PreparedPlan or type(original_draft) is not SchemeDraft
                or type(onboarding_binding) is not WebSecretOnboardingBinding
                or type(original_promoter) is not LabAutoSecretCreatePromoter
                or type(execution_store) is not PersistentM4ExecutionStateStore):
            raise ValueError
        plan, draft, binding, promoter = original_plan, original_draft, onboarding_binding, original_promoter
        if (canonical_digest(plan.canonical_content()) != plan.plan_digest or len(plan.lines) != 1
                or plan.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.scheme_id is not SchemeId.SECRET_ONBOARDING
                or draft.blueprint_ref != "FPA-BP-007" or draft.outcome_code != "onboard_web_account"
                or promoter.product_profile != LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_PROFILE
                or (plan.environment_ref, plan.scope_ref) != (draft.environment_ref, draft.scope_ref)
                or (plan.environment_ref, plan.scope_ref) != (promoter._environment_ref, promoter._scope_ref)
                or binding.template_name != "Web Account" or binding.session_recording is not True):
            raise ValueError
        line = plan.lines[0]
        desired = next(item for item in draft.desired_objects if item.object_ref == line.target_ref)
        material = draft.material_reference_metadata
        if (line.change_kind is not ChangeKind.CREATE or line.depends_on
                or line.target_class is not ObjectClass.WEB_SECRET_METADATA
                or line.target_ref != binding.secret_object_ref
                or desired.object_class is not ObjectClass.WEB_SECRET_METADATA or not desired.desired_exists
                or dict(desired.desired_fields) != {"inherit_permission": True, "session_recording": True}
                or material is None or material.provider_class != "central_lab_inventory_reference"
                or material.purpose != "initial_onboarding" or material.lifecycle != "available"):
            raise ValueError
        execution_store.verify_ready()
        artifacts = promoter._derive_original_artifacts(plan, line.line_ref, draft=draft,
            onboarding_binding=binding, adapter_ref=LAB_AUTO_SECRET_CREATE_WEB_700_CANDIDATE_ADAPTER_REF)
        # This locator-free object is never passed to a provider or dispatcher.
        execution = SecretCreateM4ExecutionBinding(artifacts.plan, artifacts.authorization, C3MaterialBinding(),
            artifacts.lease_request, artifacts.policy_decision_digest, artifacts.scope_digest, artifacts.audience_digest)
        create = SecretCreate191WebBinding("fortipam-700-build29-web-secret-create-candidate-v1", "7.0.0",
            artifacts.plan.plan_digest, binding.folder_path, binding.secret_name, binding.template_name,
            binding.web_url, binding.session_recording, target_product_build=29)
        capture = (WebSecretCreateAckCapture(serial_digest, None, observe_source=True)
                   if original_ack_capture is None else original_ack_capture)
        if type(capture) is not WebSecretCreateAckCapture or capture.serial_digest != serial_digest:
            raise ValueError
        capture.__post_init__()
        transport = FortiPam191SecretCreateHttpTransport(config,
            metadata_transport=FortiPamSecretMetadataHttpTransport(config, bound_secret_name=binding.secret_name),
            web_ack_capture=capture)
        record = WebSecretFixtureCreationRecord(config, transport=transport, create_binding=create,
            execution_binding=execution, execution_store=execution_store, serial_digest=serial_digest,
            expected_store_digest=expected_store_digest, directory=directory, key_file=key_file)
        original = record.read_acknowledged_creation()
        # No expired artifact or reconstructed HTTP observation escapes this boundary.
        return WebSecretFixtureHistoricalCreation(record, original)
    except Exception:
        raise WebSecretFixtureHistoricalCreationError(_ERROR) from None
