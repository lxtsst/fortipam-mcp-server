"""The existing clone workflow uses opaque URL-safe refs, not LDAP MAC refs."""
from types import SimpleNamespace
import asyncio
import secrets
import time

import pytest

from scripts.v4_launcher_clone_mcp_acceptance import run_launcher_clone_mcp_acceptance


class Session:
    def __init__(self): self.calls = []
    async def initialize(self): pass
    async def list_tools(self):
        return SimpleNamespace(tools=[SimpleNamespace(name=verb+'_v4_launcher_clone'+suffix+'_700')
            for suffix in ('','_recovery') for verb in ('preview','confirm','execute_confirmed')])
    async def call_tool(self, name, arguments):
        from fortipam_mcp.launcher_clone_live_workflow import CONTRACT
        self.calls.append(name); recovery='_recovery_' in name
        if name.startswith('preview'):
            body={'contract':CONTRACT,'preview_ref':'launcher-clone-preview-'+secrets.token_urlsafe(24),
                'expires_at':int(time.time())+600,'Current State':{'source_preserved':True,'destination_present':recovery,
                    'zero_references':True,'verified_creation_required':recovery},
                'Proposed Changes':{'operation':'remove_owned_clone' if recovery else 'clone_fixed_rdp_launcher',
                    'source_changes':False,'associations_or_launches':False},
                'Expected State':{'source_preserved':True,'destination_present':not recovery,
                    'full_configuration_preserved':True,'unrelated_launcher_metadata_preserved':True},'device_write_executed':False}
        elif name.startswith('confirm'):
            body={'contract':CONTRACT,'authorization_ref':'launcher-clone-authorized-'+secrets.token_urlsafe(24),
                'confirmation':'recorded','execution':'authorized_once','device_write_executed':False}
        else:
            body={'contract':CONTRACT,'outcome':'succeeded','verification':'verified','intent_consumed':True,
                'recovery':recovery,'raw_response_returned':False,'parameter_values_returned':False}
        return SimpleNamespace(is_error=False,structured_content=body)


def test_shared_session_accepts_actual_clone_refs_and_reserves_each_phase_once(tmp_path):
    tmp_path.chmod(0o700); session=Session()
    proof=asyncio.run(run_launcher_clone_mcp_acceptance(session,tmp_path))
    assert proof['completed'] and proof['mcp_dispatches']==2 and len(session.calls)==6
    with pytest.raises(Exception):asyncio.run(run_launcher_clone_mcp_acceptance(session,tmp_path))
    assert len(session.calls)==6
