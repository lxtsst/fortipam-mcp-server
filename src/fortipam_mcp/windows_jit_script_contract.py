"""Private fixed Windows local-group JIT Script pair; no transport or authority.

Use the retained seven-field build29 API profile, including plural comments.
The exact official $USER placeholder stays private and unresolved. Defining or
matching these Scripts does not configure a Secret or prove privilege effects.
"""
from __future__ import annotations

import re

from .checkout_script_contract import _definition_matches, _require_blank_default

CONTRACT = 'fortipam-build29-windows-jit-fixed-script-pair-local/v1'
_ERROR = 'The private Windows JIT Script pair is unavailable.'
_NONCE = re.compile(r'[a-f0-9]{8}\Z')


def _script_names(nonce: str) -> tuple[str,str]:
    if type(nonce) is not str or _NONCE.fullmatch(nonce) is None: raise ValueError
    return 'MCPV4JitGrant'+nonce,'MCPV4JitRevoke'+nonce


def compile_windows_jit_script_pair(default: object, *, nonce: str) -> tuple[dict[str,str],dict[str,str]]:
    """Compile one constant standalone-host profile; never accept script input."""
    try:
        names = _script_names(nonce)
        _require_blank_default(default)
        def body(*, grant: bool) -> dict[str,str]:
            return {'name':names[0 if grant else 1],'type':'powershell',
                'comments':'Fixed standalone Windows JIT local candidate',
                'script':('Add' if grant else 'Remove')+'-LocalGroupMember -Group Administrators -Member $USER',
                'expect-type':'success','expect-string':'','log-trigger':'any'}
        return body(grant=True),body(grant=False)
    except Exception: raise ValueError(_ERROR) from None


def windows_jit_script_pair_matches(default: object, grant: object, revoke: object, *, nonce: str) -> bool:
    """Match two fixed detail definitions; supplies no create/execute receipt."""
    try:
        expected_grant,expected_revoke = compile_windows_jit_script_pair(default,nonce=nonce)
        return (_definition_matches(grant,expected_grant,detail=True)
            and _definition_matches(revoke,expected_revoke,detail=True))
    except Exception: return False


def preview_windows_jit_script_pair(default: object, *, nonce: str) -> dict[str,object]:
    """Value-free C/P/E for a definition-only prerequisite, not a JIT policy."""
    compile_windows_jit_script_pair(default,nonce=nonce)
    return {'contract':CONTRACT,
        'Current State':dict(blank_powershell_default_observed_locally=True,script_namespace_absence_verified=False,
            original_secret_target_subject_custody_verified=False,usable_primary_context_verified=False),
        'Proposed Changes':dict(fixed_standalone_windows_script_count=2,local_group_add_remove_pair=True,
            secret_assignment_changed=False,script_execution_requested=False),
        'Expected State':dict(seven_field_definition_readback_required=True,script_result_evidence_required=True,
            independent_membership_and_logon_token_effects_required=True),
        'Security Changes':dict(scripts_define_administrator_membership_mutations=True,
            script_failure_blocks_checkout=False,existing_logon_privilege_removed_by_group_removal=False),
        'execution_authorized':False,'native_backend_qualified':False,'configuration_ready':False,
        'secret_jit_policy_configured':False,'script_result_qualified':False,'jit_privilege_effect_verified':False,
        'independent_recovery_verified':False,'device_write_executed':False}
