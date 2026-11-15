from __future__ import annotations

from collections.abc import Callable

import pytest

from fortipam_mcp.bp015_sponsored_group_create_contract import (
    CREATE_METHOD,
    CREATE_PATH,
    DEFAULT_METHOD,
    DEFAULT_QUERY,
    FORTIPAM_BUILD,
    FORTIPAM_VERSION,
    SCHEMA_REF,
    SponsoredGroupCreateContractError,
    SponsoredGroupCreateInput,
    SponsoredGroupDefaultEvidence,
    validate_sponsored_group_default_response,
)


def _default_response() -> dict[str, object]:
    return {
        "action": "default",
        "build": 29,
        "http_method": "GET",
        "http_status": 200,
        "name": "group",
        "path": "user",
        "results": {
            "access": "everyone",
            "auth-concurrent-override": "disable",
            "auth-concurrent-value": 0,
            "authtimeout": 0,
            "company": "private-company",
            "creation-time": "2026-09-22 09:00:00",
            "email": "private@example.test",
            "expire": 1_789_867_200,
            "expire-type": "time",
            "group-max-users": 10,
            "group-type": "firewall",
            "guest": [],
            "http-digest-realm": "private-realm",
            "id": 0,
            "logic-type": "or",
            "match": [],
            "max-accounts": 0,
            "member": [],
            "mobile-phone": "private-phone",
            "multiple-guest-add": "disable",
            "name": "",
            "password": "private-password",
            "sms-custom-server": "private-custom-sms",
            "sms-server": "private-sms",
            "sponsor": "private-sponsor",
            "sso-attribute-value": "private-sso",
            "user-id": "private-user-id",
            "user-name": "private-user-name",
            "user-permission": [],
        },
        "revision": "synthetic-revision",
        "serial": "synthetic-serial",
        "status": "success",
        "vdom": "root",
        "version": "v7.0.0",
    }


def test_default_fixture_compiles_the_exact_minimized_sponsored_group_body() -> None:
    evidence = validate_sponsored_group_default_response(_default_response())
    request = SponsoredGroupCreateInput(
        group_name="sponsor_group-01",
        owner_name="sponsor.owner",
        maximum_members=10_000,
    )

    assert CREATE_METHOD == "POST"
    assert CREATE_PATH == "/api/v2/cmdb/user/group"
    assert DEFAULT_METHOD == "GET"
    assert DEFAULT_QUERY == "action=default&with_meta=true"
    assert SCHEMA_REF == "fortipam-7.0.0-build29-bp015-sponsored-group-create-candidate-v1"
    assert FORTIPAM_VERSION == "7.0.0"
    assert FORTIPAM_BUILD == 29
    assert evidence == SponsoredGroupDefaultEvidence()
    assert request.body(evidence) == {
        "name": "sponsor_group-01",
        "group-type": "sponsor",
        "group-max-users": 10_000,
        "access": "customized",
        "user-permission": [
            {
                "id": 1,
                "permission": "owner",
                "user-name": [{"name": "sponsor.owner"}],
            }
        ],
        "member": [],
    }


def test_evidence_and_input_repr_do_not_expose_default_or_input_values() -> None:
    evidence = validate_sponsored_group_default_response(_default_response())
    request = SponsoredGroupCreateInput("private-group", "private-owner", 1)

    assert "private-password" not in repr(evidence)
    assert "private-company" not in repr(evidence)
    assert "private-group" not in repr(request)
    assert "private-owner" not in repr(request)


@pytest.mark.parametrize(
    "mutate",
    (
        lambda response: response.__setitem__("version", "v7.0.1"),
        lambda response: response.__setitem__("build", 30),
        lambda response: response.__setitem__("status", "failed"),
        lambda response: response.__setitem__("unexpected", True),
        lambda response: response["results"].__setitem__("unexpected", True),  # type: ignore[index,union-attr]
        lambda response: response["results"].__setitem__("password", 1),  # type: ignore[index,union-attr]
        lambda response: response["results"].__setitem__("group-max-users", True),  # type: ignore[index,union-attr]
        lambda response: response["results"].__setitem__("member", ["drift"]),  # type: ignore[index,union-attr]
        lambda response: response["results"].__setitem__("access", "customized"),  # type: ignore[index,union-attr]
    ),
)
def test_default_validation_fails_closed_for_version_key_type_value_or_list_drift(
    mutate: Callable[[dict[str, object]], None],
) -> None:
    response = _default_response()
    mutate(response)

    with pytest.raises(SponsoredGroupCreateContractError):
        validate_sponsored_group_default_response(response)


@pytest.mark.parametrize(
    "group_name,owner_name,maximum_members",
    (
        ("bad name", "owner", 1),
        ("group", "bad/name", 1),
        ("group", "owner", True),
        ("group", "owner", 0),
        ("group", "owner", 10_001),
    ),
)
def test_input_rejects_invalid_identifier_or_member_bound(
    group_name: object, owner_name: object, maximum_members: object
) -> None:
    with pytest.raises(SponsoredGroupCreateContractError):
        SponsoredGroupCreateInput(group_name, owner_name, maximum_members)  # type: ignore[arg-type]


def test_body_has_only_the_contract_fields_and_no_default_or_frontend_wide_fields() -> None:
    evidence = validate_sponsored_group_default_response(_default_response())
    body = SponsoredGroupCreateInput("candidate-group", "candidate-owner", 1).body(evidence)

    assert set(body) == {
        "name",
        "group-type",
        "group-max-users",
        "access",
        "user-permission",
        "member",
    }
    forbidden = {
        "$originalName",
        "id",
        "match",
        "password",
        "company",
        "creation-time",
        "expire-type",
        "sms-server",
        "sponsor",
        "user-id",
        "guest",
    }
    assert forbidden.isdisjoint(body)


def test_evidence_rejects_unsupported_or_forged_state_and_body_requires_exact_type() -> None:
    with pytest.raises(SponsoredGroupCreateContractError):
        SponsoredGroupDefaultEvidence(create_contract_ready=True)  # type: ignore[arg-type]
    with pytest.raises(SponsoredGroupCreateContractError):
        SponsoredGroupDefaultEvidence(create_method="GET")  # type: ignore[arg-type]

    request = SponsoredGroupCreateInput("candidate-group", "candidate-owner", 1)
    with pytest.raises(SponsoredGroupCreateContractError):
        request.body(object())  # type: ignore[arg-type]
