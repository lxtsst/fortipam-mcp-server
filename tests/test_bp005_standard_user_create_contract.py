from __future__ import annotations

import json
import pickle

import pytest

from fortipam_mcp.bp005_standard_user_create_contract import (
    Bp005StandardUserCreateError,
    prepare_bp005_standard_user_create,
    verify_bp005_standard_user_created_detail,
)
from fortipam_mcp.local_user_reset_fixture_create import (
    LocalUserResetFixtureCreateError,
    prepare_bp005_standard_user_base_create,
    prepare_local_user_reset_fixture_create,
)
from v4_planning.material_provider import MaterialAccessDenied

from test_local_user_reset_fixture_create import _defaults
from test_local_user_reset_name_reader import NAME as RESET_NAME
from test_local_user_reset_projection import _body

NAME = "mcp-v4-user-bp005-standard-synthetic"


def _draft():
    schema, defaults = _defaults()
    content = _body(defaults, action="default")
    try:
        return prepare_bp005_standard_user_create(content, schema, username=NAME), defaults
    finally:
        assert not any(content)


def test_standard_user_body_pins_enabled_role_without_password() -> None:
    draft, _ = _draft()
    body = json.loads(draft._wire)
    assert body["name"] == NAME
    assert body["accprofile"] == "pam_standard_user"
    assert body["status"] == "enable"
    assert "password" not in body


def test_standard_user_detail_requires_enabled_profile_and_complete_readback() -> None:
    draft, _ = _draft()
    row = json.loads(draft._wire)
    row.update(id=17, q_ref=0)
    content = _body(row, mkey=NAME)
    observed = verify_bp005_standard_user_created_detail(content, draft)
    assert observed.username == NAME and observed.user_id == 17
    assert len(observed.request_digest) == len(observed.readback_digest) == 64
    assert not any(content)


@pytest.mark.parametrize("field,value", [
    ("accprofile", "Guest"), ("status", "disable"),
])
def test_standard_user_detail_rejects_guest_or_disabled_state(field: str, value: str) -> None:
    draft, _ = _draft()
    row = json.loads(draft._wire)
    row.update(id=17, q_ref=0, **{field: value})
    content = _body(row, mkey=NAME)
    with pytest.raises(Bp005StandardUserCreateError):
        verify_bp005_standard_user_created_detail(content, draft)
    assert not any(content)


def test_standard_user_detail_rejects_drift_in_other_fields() -> None:
    draft, _ = _draft()
    row = json.loads(draft._wire)
    row.update(id=17, q_ref=0, comments="unexpected-change")
    content = _body(row, mkey=NAME)
    with pytest.raises(Bp005StandardUserCreateError):
        verify_bp005_standard_user_created_detail(content, draft)
    assert not any(content)


def test_standard_user_password_is_added_only_to_private_one_shot_wire() -> None:
    draft, _ = _draft()
    material = bytearray(b"Synthetic-Standard-Password-7!")
    with memoryview(material) as view:
        encoded = draft._encode(view)
        try:
            body = json.loads(encoded)
            assert body.pop("password") == material.decode("ascii")
            assert body == json.loads(draft._wire)
            assert material.decode("ascii") not in repr(draft)
        finally:
            encoded[:] = b"\x00" * len(encoded)
    with pytest.raises(MaterialAccessDenied):
        pickle.dumps(draft)


def test_bp005_and_bp002_user_name_scopes_do_not_overlap() -> None:
    schema, defaults = _defaults()
    content = _body(defaults, action="default")
    with pytest.raises(LocalUserResetFixtureCreateError):
        prepare_bp005_standard_user_base_create(content, schema, username=RESET_NAME)
    assert not any(content)

    content = _body(defaults, action="default")
    with pytest.raises(LocalUserResetFixtureCreateError):
        prepare_local_user_reset_fixture_create(
            content, schema, username=NAME, access_profile="Guest",
        )
    assert not any(content)
