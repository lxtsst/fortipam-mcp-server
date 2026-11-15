"""Only the observed local no-domain profile may omit the IDP relation."""
from copy import deepcopy
import json

import pytest

from fortipam_mcp.ems_tag_identity_contract import admin_catalog, qualify_admin_detail
from test_ems_tag_identity_sources import fixture
from test_ems_tag_contract import envelope


def test_optional_local_idps_preserves_raw_absence_and_never_defaults_other_profiles():
    data=fixture();local=deepcopy(data['user'])
    local.update(name='synthetic-local-user',user_type='EMS',role_uid='synthetic-role',is_global=False,allow_all_domains=False)
    local.pop('idps')
    row=admin_catalog(envelope([{k:local[k] for k in ('id','name','user_type','vdom')}]))[0]
    result=qualify_admin_detail(envelope(local),row,frozenset(data['details']))
    assert 'idps' not in json.loads(result)
    explicit=qualify_admin_detail(envelope({**local,'idps':[]}),row,frozenset(data['details']))
    assert result!=explicit and json.loads(explicit)['idps']==[]
    for patch in ({'user_type':'BuiltIn'},{'user_type':'SAML'},{'allow_all_domains':True},{'idps':None},{'idps':False}):
        changed={**local,**patch}
        catalog=admin_catalog(envelope([{k:changed[k] for k in ('id','name','user_type','vdom')}]))[0]
        with pytest.raises(ValueError):qualify_admin_detail(envelope(changed),catalog,frozenset(data['details']))
