"""A prospective account cannot broaden host/domain scope or carry material."""
from dataclasses import replace

import pytest

from fortipam_mcp.ems_tag_admin_contract import ProspectiveEmsTagManagerAccount


def test_account_metadata_fixes_the_narrow_profile_without_password_material():
    draft = ProspectiveEmsTagManagerAccount("synthetic-role-uid", "a" * 32, "192.0.2.10/32")
    body = draft._metadata_body
    assert set(body) == {"role_uid", "vdom", "comments", "trusted_hosts_enabled", "trusted_hosts",
                         "name", "allow_all_domains", "idp_guids", "is_global"}
    assert body["vdom"] is None and body["is_global"] is False and body["allow_all_domains"] is False
    assert body["idp_guids"] == [] and body["trusted_hosts_enabled"] is True
    assert body["trusted_hosts"] == ["192.0.2.10/32"]
    original = draft.parameters_digest
    body["trusted_hosts"].append("0.0.0.0/0")
    body["idp_guids"].append("synthetic-domain")
    body["password"] = "synthetic-only"
    assert draft.parameters_digest == original and "password" not in draft._metadata_body
    assert "synthetic-role-uid" not in repr(draft)
    assert replace(draft, role_uid="another-role").parameters_digest != original
    assert replace(draft, trusted_host="192.0.2.11/32").parameters_digest != original


@pytest.mark.parametrize("host", ["192.0.2.10", "192.0.2.0/24", "0.0.0.0/0", "0.0.0.0/32",
                                 "127.0.0.1/32", "224.0.0.1/32", "169.254.1.1/32", "::1/128", True])
def test_broader_or_nonphysical_host_shapes_are_refused(host):
    with pytest.raises(ValueError, match="^The prospective EMS tag-manager account is unavailable\\.$"):
        ProspectiveEmsTagManagerAccount("synthetic-role-uid", "a" * 32, host)


def test_account_nonce_or_role_path_cannot_redirect_a_proposal():
    for uid, nonce in [(17, "a" * 32), ("../other", "a" * 32), ("role", "../nonce")]:
        with pytest.raises(ValueError): ProspectiveEmsTagManagerAccount(uid, nonce, "192.0.2.10/32")
