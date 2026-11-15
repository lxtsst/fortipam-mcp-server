"""Private build29 glass-breaking state projection and exact two-body draft.

No role edit, credential access, dispatch, session effect, native ACK or inverse
custody is supplied. Explicit current-actor flags prove neither account/session
scope nor a safely isolated emergency drill. Deactivation is a separate action.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass,replace
import hashlib
import json
from typing import Any

from v4_planning import canonical_digest
from v4_planning.material_provider import _OpaqueC3Object
from v4_planning.models import require_digest
from . import secret_bulk_import_metadata as metadata
from .email_alert_general_contract import _encoded,_specs,_values
from .local_user_reset_fixture_preflight import _actor_context
from .local_user_reset_projection import _object_spans,_sanitize_value
from .secret_metadata_http_transport import _zeroize_mutable
from .target_lifecycle_dependencies import _envelope,_spans

CONTRACT = 'fortipam-build29-glass-break-private-local/v1'
STATE_PATH = '/api/v2/monitor/web-ui/state'
ACTIVATE_PATH = '/api/v2/monitor/user/break-glass/activate'
DEACTIVATE_PATH = '/api/v2/monitor/user/break-glass/deactivate'
_ERROR = 'The private glass-breaking contract is unavailable.'


def _profile_specs(fields: object) -> dict[str,Any]:
    if not isinstance(fields,Mapping): raise ValueError
    specs = _specs(fields)
    flag=specs.get('glass-breaking')
    if flag is None or flag.get('type')!='option' or flag.get('options')!=['disable','enable']: raise ValueError
    return specs


def glass_break_profile_schema_digest(fields: object) -> str:
    try: return canonical_digest(_profile_specs(fields))
    except Exception: raise ValueError(_ERROR) from None


@dataclass(frozen=True,slots=True,repr=False)
class GlassBreakBinding(_OpaqueC3Object):
    source_digest: str
    actor_name: str
    serial_digest: str
    profile_schema_digest: str

    def __post_init__(self) -> None:
        for value in (self.source_digest,self.serial_digest,self.profile_schema_digest): require_digest(value,'glass-breaking source')
        if (type(self.actor_name) is not str or not 1 <= len(self.actor_name.encode('utf-8')) <= 64
                or any(ord(character)<33 or ord(character)==127 for character in self.actor_name)): raise ValueError

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,source=self.source_digest,serial=self.serial_digest,
            actor=hashlib.sha256(self.actor_name.encode('utf-8')).hexdigest(),profile_schema=self.profile_schema_digest))


@dataclass(frozen=True,slots=True,repr=False)
class GlassBreakState(_OpaqueC3Object):
    binding_digest: str
    actor_context_digest: str
    profile_digest: str
    eligible: bool
    promoted: bool

    def __post_init__(self) -> None:
        for value in (self.binding_digest,self.actor_context_digest,self.profile_digest): require_digest(value,'glass-breaking state')
        if type(self.eligible) is not bool or type(self.promoted) is not bool: raise ValueError

    @property
    def digest(self) -> str:
        self.__post_init__()
        return canonical_digest(dict(contract=CONTRACT,binding=self.binding_digest,actor=self.actor_context_digest,
            profile=self.profile_digest,eligible=self.eligible,promoted=self.promoted))


def project_glass_break_state(raw: bytearray, binding: GlassBreakBinding, profile_schema: object) -> GlassBreakState:
    safe_profile=bytearray()
    try:
        if type(binding) is not GlassBreakBinding or type(raw) is not bytearray or not 0<len(raw)<=1048576: raise ValueError
        binding.__post_init__(); specs=_profile_specs(profile_schema)
        # Match the classified type tree before traversing current response
        # spans. Unrelated web-ui values and schema defaults never enter hashes.
        if canonical_digest(specs)!=binding.profile_schema_digest: raise ValueError
        root=_spans(raw)
        if 'serial' not in root: raise ValueError
        results=_envelope(raw,path='web-ui',name='state',serial_digest=binding.serial_digest,monitor=True)
        actor_context=_actor_context(raw,expected_name=binding.actor_name)
        state=metadata._object_spans(raw,*results,frozenset({'admin'}))
        actor=metadata._object_spans(raw,*state['admin'],frozenset({'profile','promoted_admin'}))
        profile=_object_spans(raw,*actor['profile'])
        if set(profile)!=set(specs): raise ValueError
        safe_profile.append(123)
        for index,(name,span) in enumerate(profile.items()):
            if index: safe_profile.append(44)
            safe_profile.extend(_encoded(name)); safe_profile.append(58)
            _sanitize_value(raw,*span,specs[name],safe_profile,depth=1)
        safe_profile.append(125); selected=json.loads(safe_profile); _values(selected,specs)
        permission=selected['glass-breaking']; promoted=metadata._scalar(raw,actor['promoted_admin'])
        if permission not in ('enable','disable') or type(promoted) is not bool: raise ValueError
        return GlassBreakState(binding.digest,actor_context,hashlib.sha256(_encoded(selected)).hexdigest(),permission=='enable',promoted)
    except Exception: raise ValueError(_ERROR) from None
    finally:
        _zeroize_mutable(safe_profile)
        if type(raw) is bytearray: _zeroize_mutable(raw)


@dataclass(frozen=True,slots=True,repr=False)
class GlassBreakIncident(_OpaqueC3Object):
    incident_binding_digest: str
    reason: str

    def __post_init__(self) -> None:
        require_digest(self.incident_binding_digest,'glass-breaking incident')
        # A conservative local profile, not a claimed native/UI size limit.
        if (type(self.reason) is not str or not self.reason.strip() or len(self.reason.encode('utf-8'))>256
                or not self.reason.isascii() or any(ord(c)<32 or ord(c)==127 for c in self.reason)): raise ValueError

    @property
    def digest(self) -> str:
        return canonical_digest(dict(contract=CONTRACT,incident=self.incident_binding_digest,
            reason=hashlib.sha256(self.reason.encode('utf-8')).hexdigest()))


@dataclass(frozen=True,slots=True,repr=False)
class GlassBreakPlan(_OpaqueC3Object):
    baseline: GlassBreakState
    incident: GlassBreakIncident

    def __post_init__(self) -> None:
        if type(self.baseline) is not GlassBreakState or type(self.incident) is not GlassBreakIncident: raise ValueError(_ERROR)
        self.baseline.__post_init__(); self.incident.__post_init__()
        if not self.baseline.eligible or self.baseline.promoted: raise ValueError(_ERROR)

    @property
    def digest(self) -> str:
        self.__post_init__()
        return canonical_digest(dict(contract=CONTRACT,baseline=self.baseline.digest,incident=self.incident.digest))

    def expected(self) -> GlassBreakState:
        self.__post_init__(); return replace(self.baseline,promoted=True)

    def compile(self, current: GlassBreakState, *, deactivate: bool=False) -> bytearray:
        try:
            self.__post_init__()
            if type(current) is not GlassBreakState or type(deactivate) is not bool: raise ValueError
            expected=self.expected() if deactivate else self.baseline
            if current.digest!=expected.digest: raise ValueError
            return bytearray(_encoded({} if deactivate else dict(comments=self.incident.reason)))
        except Exception: raise ValueError(_ERROR) from None

    def preview(self) -> dict[str,object]:
        self.__post_init__()
        return dict(contract=CONTRACT,
            **{'Current State':dict(explicit_native_mode_off=True,exact_role_flag_enabled=True,
                    complete_supplied_role_profile_compared=True,non_sponsored_non_guest_actor=True),
               'Proposed Changes':dict(request_activation_for_current_actor=True,protected_reason_bound=True,role_edit_requested=False,
                    secret_enumeration_or_cleartext_access_requested=False),
               'Expected State':dict(explicit_mode_true_readback_required=True,original_role_profile_preservation_required=True,
                    original_activation_receipt_required_for_deactivation=True,independent_deactivation_grant_required=True,
                    out_of_band_deactivation_required=True,post_incident_review_rotation_plan_required=True),
               'Security Changes':dict(normal_access_controls_bypassed=True,all_folders_secrets_requests_and_launches_affected=True,
                    cleartext_access_becomes_possible=True,reason_may_be_retained_in_audit=True,
                    notification_may_be_sent=True,logout_does_not_prove_deactivation=True,
                    no_native_automatic_expiry_established=True,late_exit_does_not_verify_duration=True,
                    exit_does_not_recall_notifications_or_disclosures=True)},
            activation_ready=False,execution_authorized=False,access_elevated=False,native_subject_or_session_scope_verified=False,
            native_ack_qualified=False,isolated_drill_verified=False,independent_observer_verified=False,
            reason_retention_verified=False,audit_recording_verified=False,notification_scope_verified=False,
            independent_deactivation_verified=False)
