from __future__ import annotations

from copy import deepcopy

import pytest

from fortipam_mcp.catalog import RuntimeCatalog
from scripts.accept_v16_identity import (
    V16_NEGATIVE_READ_PATHS,
    _assert_cataloged_v16_negative_reads,
    _assert_password_changer_projection,
)
from scripts.accept_least_privilege_identity import IdentityAcceptanceError


def _password_changer_result() -> dict[str, object]:
    return {
        "status_code": 200,
        "response_body_returned": False,
        "posture": {
            "contract": "fortipam_password_changer_configuration_posture_v1",
            "changer_inventory_state": "present",
            "changer_count_band": "multiple",
            "fortios_7_6_3_documented_label_observed": True,
            "label_observation": "documented_label_observed",
            "observation_scope": "configuration_label_only",
            "target_compatibility_assessed": False,
            "job_health_assessed": False,
            "response_body_returned": False,
            "name_values_returned": False,
            "description_values_returned": False,
            "procedure_values_returned": False,
            "authentication_mode_values_returned": False,
            "reference_values_returned": False,
            "origin_values_returned": False,
            "credential_values_returned": False,
            "raw_field_values_returned": False,
        },
    }


def test_v16_negative_reads_cover_cross_domain_and_secret_siblings() -> None:
    assert V16_NEGATIVE_READ_PATHS == (
        "/api/v2/cmdb/user/group",
        "/api/v2/cmdb/router/static",
        "/api/v2/cmdb/antivirus/profile",
        "/api/v2/cmdb/vpn.ssl.web/realm",
        "/api/v2/monitor/wanopt/history",
        "/api/v2/cmdb/secret/classification-tag",
        "/api/v2/cmdb/secret/client-software",
        "/api/v2/cmdb/secret/event-filter-profile",
        "/api/v2/cmdb/secret/password-policy",
        "/api/v2/cmdb/secret/dependency-updater",
        "/api/v2/cmdb/secret/launcher",
    )
    catalog = RuntimeCatalog.load()
    assert all(
        catalog.find("GET", path) is not None
        for path in V16_NEGATIVE_READ_PATHS
    )
    _assert_cataloged_v16_negative_reads()


def test_password_changer_acceptance_checks_the_closed_contract() -> None:
    _assert_password_changer_projection(_password_changer_result())

    invalid = deepcopy(_password_changer_result())
    posture = invalid["posture"]
    assert isinstance(posture, dict)
    posture["target_compatibility_assessed"] = True
    with pytest.raises(IdentityAcceptanceError, match="posture contract"):
        _assert_password_changer_projection(invalid)

    disclosing = deepcopy(_password_changer_result())
    posture = disclosing["posture"]
    assert isinstance(posture, dict)
    posture["procedure_values_returned"] = True
    with pytest.raises(IdentityAcceptanceError, match="non-disclosure"):
        _assert_password_changer_projection(disclosing)


@pytest.mark.parametrize("unsafe_value", ["private-sensitive-value", {"secret": 1}])
def test_v16_identity_acceptance_rejects_non_boolean_label_signal(
    unsafe_value: object,
) -> None:
    invalid = deepcopy(_password_changer_result())
    posture = invalid["posture"]
    assert isinstance(posture, dict)
    posture["fortios_7_6_3_documented_label_observed"] = unsafe_value
    with pytest.raises(IdentityAcceptanceError, match="posture contract"):
        _assert_password_changer_projection(invalid)


def test_v16_identity_acceptance_rejects_contradiction_and_extra_key() -> None:
    contradictory = deepcopy(_password_changer_result())
    posture = contradictory["posture"]
    assert isinstance(posture, dict)
    posture["label_observation"] = "not_observed"
    with pytest.raises(IdentityAcceptanceError, match="posture contract"):
        _assert_password_changer_projection(contradictory)

    extra = deepcopy(_password_changer_result())
    posture = extra["posture"]
    assert isinstance(posture, dict)
    posture["private_extension"] = "private-sensitive-value"
    with pytest.raises(IdentityAcceptanceError, match="posture contract"):
        _assert_password_changer_projection(extra)
