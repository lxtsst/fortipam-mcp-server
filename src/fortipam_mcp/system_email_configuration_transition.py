"""Private source-bound SMTP C/P/E and restoration comparisons, without I/O.

The native SDK omits three fields. Their preservation, source schema and device
identity must match separately from its twelve-field request. These comparisons
do not qualify backend enum conversion, an ACK, isolation, permission or recovery
ownership, and cannot dispatch a request or authorize a message.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hmac
import json
from typing import Any

from v4_planning.material_provider import _OpaqueC3Object

from .system_email_configuration_contract import SystemEmailEmptyAuthDraft
from .system_email_native_source import SystemEmailSourceBoundDraft

CONTRACT="fortipam-build29-email-server-empty-auth-transition/v1"
_ERROR="The private system-email transition is unavailable."


@dataclass(frozen=True,slots=True,repr=False)
class SystemEmailConfigurationTransition(_OpaqueC3Object):
    """A readback comparator, not an operation, ownership seal or rollback right."""
    original: SystemEmailSourceBoundDraft
    proposed: SystemEmailEmptyAuthDraft

    def _verify(self,observed: SystemEmailSourceBoundDraft,expected: SystemEmailEmptyAuthDraft) -> None:
        if type(observed) is not SystemEmailSourceBoundDraft:
            raise ValueError(_ERROR)
        pairs=((observed.source_serial_digest,self.original.source_serial_digest),
            (observed.source_schema_digest,self.original.source_schema_digest),
            (observed.draft.request_digest,expected.request_digest),
            (observed.draft.unforwarded_state_digest,self.original.draft.unforwarded_state_digest))
        if not all(hmac.compare_digest(actual,wanted)for actual,wanted in pairs):
            raise ValueError(_ERROR)

    def verify_applied(self,observed: SystemEmailSourceBoundDraft) -> None:
        self._verify(observed,self.proposed)

    def verify_restored(self,observed: SystemEmailSourceBoundDraft) -> None:
        self._verify(observed,self.original.draft)

    def preview(self) -> dict[str,object]:
        """Describe the actual field delta without returning private values."""
        current=json.loads(self.original.draft._wire)
        proposed=json.loads(self.proposed._wire)
        changed=sorted(field for field in current if current[field]!=proposed[field])
        return {"contract":CONTRACT,
            "Current State":{"complete_source_bound":True,"empty_disabled_authentication":True},
            "Proposed Changes":{"changed_fields":changed,"sdk_omitted_fields_unchanged":True},
            "Expected State":{"same_device_and_schema":True,"forwarded_values_match_proposal":True,
                "omitted_values_match_original":True},
            "configuration_write_authorized":False,"smtp_send_authorized":False}

    def summary(self) -> dict[str,object]:
        return dict(contract=CONTRACT,source_device_and_schema_bound=True,
            forwarded_field_count=12,unforwarded_preservation_field_count=3,
            configuration_write_authorized=False,smtp_send_authorized=False,
            original_ack_qualified=False,independent_restoration_authorized=False,
            backend_type_conversion_qualified=False,protected_values_returned=False)


def prepare_system_email_transition(original: SystemEmailSourceBoundDraft,
        proposed: Mapping[str,Any]) -> SystemEmailConfigurationTransition:
    """Bind a private proposal while refusing edits the native SDK cannot emit."""
    if type(original) is not SystemEmailSourceBoundDraft:
        raise ValueError(_ERROR)
    draft=original.prepare_proposal(proposed)
    if not hmac.compare_digest(draft.unforwarded_state_digest,original.draft.unforwarded_state_digest):
        raise ValueError(_ERROR)
    return SystemEmailConfigurationTransition(original,draft)
