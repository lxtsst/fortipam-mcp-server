from __future__ import annotations

from ipaddress import IPv4Address
import stat

import pytest

from scripts.v4_role_create_mcp_oauth_acceptance import (
    RoleCreateMcpOAuthAcceptanceError,
    _contains_role_create_acceptance_error,
    _is_private_ip_lab_url,
    _read_preview_ref,
    _write_preview_state,
)


PRIVATE_LAB_IPV4 = str(IPv4Address(0x0A00020C))
OTHER_PRIVATE_IPV4 = str(IPv4Address(0xC0A8020C))


def test_preview_reference_is_owner_only_and_single_use(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"

    _write_preview_state(path, "role-create-preview-opaque")

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert _read_preview_ref(path) == "role-create-preview-opaque"
    with pytest.raises(RoleCreateMcpOAuthAcceptanceError):
        _write_preview_state(path, "role-create-preview-other")


def test_preview_reference_rejects_other_action_prefix(tmp_path) -> None:
    directory = tmp_path / "state"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    path = directory / "preview.json"
    path.write_text('{"preview_ref":"password-policy-preview-opaque"}', encoding="utf-8")
    path.chmod(0o600)

    with pytest.raises(RoleCreateMcpOAuthAcceptanceError):
        _read_preview_ref(path)


def test_callback_failure_is_recognized_inside_task_groups() -> None:
    wrapped = ExceptionGroup(
        "outer",
        [ExceptionGroup("inner", [RoleCreateMcpOAuthAcceptanceError("failed")])],
    )

    assert _contains_role_create_acceptance_error(wrapped) is True
    assert _contains_role_create_acceptance_error(ExceptionGroup("other", [ValueError()])) is False


def test_private_http_lab_exception_is_limited_to_a_path_based_10_network_url() -> None:
    assert _is_private_ip_lab_url(f"http://{PRIVATE_LAB_IPV4}/fpamcp") is True
    assert _is_private_ip_lab_url(f"https://{PRIVATE_LAB_IPV4}/fpamcp") is False
    assert _is_private_ip_lab_url(f"http://{OTHER_PRIVATE_IPV4}/fpamcp") is False
    assert _is_private_ip_lab_url(f"http://{PRIVATE_LAB_IPV4}") is False
    assert (
        _is_private_ip_lab_url(f"http://{PRIVATE_LAB_IPV4}:8080/fpamcp")
        is False
    )
