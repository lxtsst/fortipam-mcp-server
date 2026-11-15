from __future__ import annotations

import asyncio
from copy import deepcopy
import json
from pathlib import Path

import pytest

from fortipam_mcp.config import HA_CONFIGURATION_PATH
from fortipam_mcp.cli_parsers import (
    project_ha_checksum_cluster,
    project_ha_configuration,
    project_ha_status,
)
from fortipam_mcp.ha_reconciliation import (
    BoundHaReconciliation,
    HA_RECONCILIATION_FEATURE_ENV,
    HA_RECONCILIATION_PREREQUISITES_ENV,
    HA_RECONCILIATION_QUERY_PERMISSION_ENV,
    HaReconciliationError,
    HaReconciliationPrerequisites,
    HaReconciliationQueryPermission,
    HaReconciliationRuntimeBinding,
    OwnerOnlyHaReconciliationPrerequisiteProvider,
    OwnerOnlyHaReconciliationQueryPermissionProvider,
    V4_HA_RECONCILIATION_CONTRACT,
    assess_ha_reconciliation,
    load_ha_reconciliation_feature,
    prerequisite_provider_from_environment,
    query_permission_provider_from_environment,
    runtime_binding_from_environment,
)


def _api(mode: str = "standalone") -> dict[str, object]:
    return {
        "scenario": "ha_sync",
        "operation": "GET",
        "path": HA_CONFIGURATION_PATH,
        "sensitivity": "ha_configuration_posture",
        "status_code": 200,
        "content_type": "application/json",
        "response_body_returned": False,
        "posture": {
            "contract": "fortipam_ha_configuration_posture_v1",
            "ha_enabled": mode != "standalone",
            "topology_mode": mode,
            "heartbeat_authentication_enabled": True,
            "heartbeat_encryption_enabled": True,
            "heartbeat_interface_configured": True,
            "monitored_interface_configured": True,
            "dedicated_management_enabled": False,
            "management_interface_entry_count": 0,
            "unicast_heartbeat_enabled": False,
            "unicast_peer_entry_count": 0,
            "session_pickup_enabled": True,
            "connectionless_session_pickup_enabled": False,
            "override_enabled": False,
            "synchronization_state": "not_observed",
            "response_body_returned": False,
            "serial_values_returned": False,
            "network_values_returned": False,
            "interface_values_returned": False,
            "group_values_returned": False,
            "credential_values_returned": False,
            "priority_values_returned": False,
            "checksum_values_returned": False,
        },
    }


def _cli(workflow_id: str, evidence: dict[str, object]) -> dict[str, object]:
    return {
        "workflow_id": workflow_id,
        "execution_status": "completed",
        "evidence": evidence,
        "raw_cli_returned": False,
        "credential_values_returned": False,
    }


def _configuration(mode: str = "standalone") -> dict[str, object]:
    return _cli(
        "ha_configuration",
        {
            "evidence_status": "complete",
            "ha_mode": mode,
            "session_pickup": "enabled",
            "override_state": "disabled",
            "configuration_security": "enabled",
            "identity_values_returned": False,
            "network_values_returned": False,
            "group_name_returned": False,
            "password_values_returned": False,
            "priority_values_returned": False,
            "exact_checksum_returned": False,
            "raw_cli_returned": False,
        },
    )


def _status(mode: str = "standalone") -> dict[str, object]:
    return _cli(
        "ha_status",
        {
            "evidence_status": "complete",
            "ha_mode": mode,
            "ha_health": "healthy",
            "member_count_band": "single" if mode == "standalone" else "multiple",
            "configuration_sync": (
                "not_applicable" if mode == "standalone" else "synchronized"
            ),
            "peer_identity_returned": False,
            "network_values_returned": False,
            "exact_time_returned": False,
            "raw_cli_returned": False,
        },
    )


def _checksum(mode: str = "standalone") -> dict[str, object]:
    if mode == "standalone":
        evidence = {
            "evidence_status": "complete",
            "ha_mode": "standalone",
            "checksum_assessment": "not_applicable",
            "member_count_band": "single",
            "exact_checksum_returned": False,
            "member_identity_returned": False,
            "table_name_returned": False,
            "raw_cli_returned": False,
        }
    else:
        evidence = {
            "evidence_status": "complete",
            "member_count_band": "multiple",
            "global_agreement": "matched",
            "root_agreement": "matched",
            "overall_agreement": "matched",
            "mismatch_scope_count_band": "zero",
            "exact_checksum_returned": False,
            "member_identity_returned": False,
            "table_name_returned": False,
            "raw_cli_returned": False,
            "ha_mode": mode,
            "checksum_assessment": "synchronized",
            "detail_evidence": "not_required",
        }
    return _cli("ha_checksum", evidence)


def _assess(
    *,
    mode: str = "standalone",
    api: dict[str, object] | None = None,
    configuration: dict[str, object] | None = None,
    status: dict[str, object] | None = None,
    checksum: dict[str, object] | None = None,
    **overrides: bool,
) -> dict[str, object]:
    attestations = {
        "expected_member_inventory_verified": True,
        "expected_roles_verified": True,
        "compatibility_verified": True,
        "heartbeat_health_verified": True,
        "maintenance_failover_reviewed": True,
        "local_evidence_accounted_for": True,
    }
    attestations.update(overrides)
    return assess_ha_reconciliation(
        _api(mode) if api is None else api,
        _configuration(mode) if configuration is None else configuration,
        _status(mode) if status is None else status,
        _checksum(mode) if checksum is None else checksum,
        **attestations,
    )


@pytest.mark.parametrize("mode", ["standalone", "active_passive"])
def test_consistent_evidence_is_only_eligible_for_operator_review(mode: str) -> None:
    result = _assess(mode=mode)

    assert result["contract"] == V4_HA_RECONCILIATION_CONTRACT
    assert result["action_family"] == "ha.reconcile"
    assert result["assessment_status"] == "eligible_for_operator_review"
    assert result["missing_requirements"] == []
    assert result["operator_review_ready"] is True
    assert result["automatic_repair_enabled"] is False
    assert result["synchronization_dispatched"] is False
    assert result["failover_dispatched"] is False
    assert result["configuration_written"] is False
    assert result["execution_authorized"] is False


def test_missing_expected_inventory_fails_closed_without_identifiers() -> None:
    result = _assess(expected_member_inventory_verified=False)

    assert result["assessment_status"] == "not_assessed"
    assert result["missing_requirements"] == [
        "expected_member_inventory_verified"
    ]
    assert result["operator_review_ready"] is False
    serialized = json.dumps(result, sort_keys=True)
    assert "PRIVATE" not in serialized
    assert result["member_identity_returned"] is False
    assert result["network_values_returned"] is False
    assert result["checksum_values_returned"] is False


def test_mode_disagreement_is_contradictory() -> None:
    result = _assess(configuration=_configuration("active_passive"))
    assert result["assessment_status"] == "contradictory"


def test_degraded_and_out_of_sync_are_distinct_closed_states() -> None:
    degraded = _status("active_passive")
    degraded_evidence = degraded["evidence"]
    assert isinstance(degraded_evidence, dict)
    degraded_evidence["ha_health"] = "degraded"
    assert _assess(mode="active_passive", status=degraded)[
        "assessment_status"
    ] == "degraded"

    out_of_sync = _checksum("active_passive")
    checksum_evidence = out_of_sync["evidence"]
    assert isinstance(checksum_evidence, dict)
    checksum_evidence["global_agreement"] = "mismatched"
    checksum_evidence["checksum_assessment"] = "out_of_sync"
    checksum_evidence["mismatch_scope_count_band"] = "one"
    checksum_evidence["detail_evidence"] = "collected"
    assert _assess(mode="active_passive", checksum=out_of_sync)[
        "assessment_status"
    ] == "out_of_sync"


def test_active_active_and_partial_evidence_remain_not_assessed() -> None:
    assert _assess(mode="active_active")["assessment_status"] == "not_assessed"
    partial = _configuration()
    evidence = partial["evidence"]
    assert isinstance(evidence, dict)
    evidence["evidence_status"] = "partial"
    assert _assess(configuration=partial)["assessment_status"] == "not_assessed"


def test_schema_extensions_and_disclosure_flags_are_rejected() -> None:
    extra = _status()
    extra["private_member"] = "must-not-cross"
    disclosed = deepcopy(_checksum())
    evidence = disclosed["evidence"]
    assert isinstance(evidence, dict)
    evidence["exact_checksum_returned"] = True

    for status, checksum in ((extra, _checksum()), (_status(), disclosed)):
        with pytest.raises(HaReconciliationError):
            _assess(status=status, checksum=checksum)


def test_non_boolean_attestation_is_rejected() -> None:
    with pytest.raises(HaReconciliationError, match="must be boolean"):
        _assess(expected_roles_verified=1)  # type: ignore[arg-type]


def test_existing_cli_projectors_feed_the_exact_cluster_contract() -> None:
    configuration = _cli(
        "ha_configuration",
        project_ha_configuration(
            b"show system ha\r\n"
            b"config system ha\r\n"
            b"set mode a-p\r\n"
            b"set session-pickup enable\r\n"
            b"set override disable\r\n"
            b"set encryption enable\r\n"
            b"set authentication enable\r\n"
            b"end\r\nprivate #\r\n"
        ),
    )
    status = _cli(
        "ha_status",
        project_ha_status(
            b"get system ha status\r\n"
            b"HA Health Status: OK\r\n"
            b"Mode: HA A-P\r\n"
            b"Configuration Status:\r\n"
            b"PRIVATE-A: in-sync\r\n"
            b"PRIVATE-B: in-sync\r\n"
            b"private #\r\n"
        ),
    )
    checksum_evidence = project_ha_checksum_cluster(
        b"diagnose sys ha checksum cluster\r\n"
        b"================== PRIVATE-A ==================\r\n"
        b"checksum\r\n"
        b"global: 11111111111111111111111111111111\r\n"
        b"root: 22222222222222222222222222222222\r\n"
        b"all: 33333333333333333333333333333333\r\n"
        b"================== PRIVATE-B ==================\r\n"
        b"checksum\r\n"
        b"global: 11111111111111111111111111111111\r\n"
        b"root: 22222222222222222222222222222222\r\n"
        b"all: 33333333333333333333333333333333\r\n"
        b"private #\r\n"
    )
    checksum_evidence.update(
        {
            "ha_mode": "active_passive",
            "checksum_assessment": "synchronized",
            "detail_evidence": "not_required",
        }
    )
    result = _assess(
        mode="active_passive",
        configuration=configuration,
        status=status,
        checksum=_cli("ha_checksum", checksum_evidence),
    )

    assert result["assessment_status"] == "eligible_for_operator_review"
    assert "PRIVATE" not in json.dumps(result, sort_keys=True)


def _prerequisites(**overrides: bool) -> HaReconciliationPrerequisites:
    values = {
        "expected_member_inventory_verified": True,
        "expected_roles_verified": True,
        "compatibility_verified": True,
        "heartbeat_health_verified": True,
        "maintenance_failover_reviewed": True,
        "local_evidence_accounted_for": True,
    }
    values.update(overrides)
    return HaReconciliationPrerequisites(**values)


def test_bound_composition_collects_each_fixed_source_once() -> None:
    calls: list[str] = []

    def collector(name: str, result: dict[str, object]):
        async def collect() -> dict[str, object]:
            calls.append(name)
            return deepcopy(result)

        return collect

    bound = BoundHaReconciliation(
        api_configuration_collector=collector("api", _api()),
        cli_configuration_collector=collector("configuration", _configuration()),
        cli_status_collector=collector("status", _status()),
        cli_checksum_collector=collector("checksum", _checksum()),
        prerequisite_provider=_prerequisites,
    )
    result = asyncio.run(bound.assess())

    assert result["assessment_status"] == "eligible_for_operator_review"
    assert sorted(calls) == ["api", "checksum", "configuration", "status"]


def test_bound_composition_requires_typed_internal_prerequisites() -> None:
    async def collect_api() -> dict[str, object]:
        return _api()

    with pytest.raises(HaReconciliationError, match="provider is invalid"):
        asyncio.run(
            BoundHaReconciliation(
                api_configuration_collector=collect_api,
                cli_configuration_collector=lambda: asyncio.sleep(
                    0, result=_configuration()
                ),
                cli_status_collector=lambda: asyncio.sleep(0, result=_status()),
                cli_checksum_collector=lambda: asyncio.sleep(
                    0, result=_checksum()
                ),
                prerequisite_provider=lambda: {"trusted": True},  # type: ignore[arg-type,return-value]
            ).assess()
        )


def test_bound_composition_wraps_collector_failure_without_detail() -> None:
    async def fail() -> dict[str, object]:
        raise RuntimeError("private-collector-detail")

    async def collect_configuration() -> dict[str, object]:
        return _configuration()

    async def collect_status() -> dict[str, object]:
        return _status()

    async def collect_checksum() -> dict[str, object]:
        return _checksum()

    bound = BoundHaReconciliation(
        api_configuration_collector=fail,
        cli_configuration_collector=collect_configuration,
        cli_status_collector=collect_status,
        cli_checksum_collector=collect_checksum,
        prerequisite_provider=_prerequisites,
    )
    with pytest.raises(HaReconciliationError) as caught:
        asyncio.run(bound.assess())
    assert str(caught.value) == "HA reconciliation evidence collection failed."
    assert "private" not in str(caught.value).lower()


def test_prerequisite_type_rejects_integer_booleans() -> None:
    with pytest.raises(HaReconciliationError, match="must be boolean"):
        _prerequisites(expected_roles_verified=1)  # type: ignore[arg-type]


def _write_prerequisites(path: Path, **overrides: object) -> None:
    payload: dict[str, object] = {
        "schema_version": "1",
        "target_version": "1.9.1",
        "expected_member_inventory_verified": True,
        "expected_roles_verified": True,
        "compatibility_verified": True,
        "heartbeat_health_verified": True,
        "maintenance_failover_reviewed": True,
        "local_evidence_accounted_for": True,
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)


def test_owner_only_provider_reads_exact_value_free_record(tmp_path: Path) -> None:
    directory = tmp_path / "ha"
    directory.mkdir(mode=0o700)
    path = directory / "prerequisites.json"
    _write_prerequisites(path, heartbeat_health_verified=False)

    provider = OwnerOnlyHaReconciliationPrerequisiteProvider(path)
    result = provider()

    assert result.heartbeat_health_verified is False
    assert set(result.as_kwargs()) == {
        "expected_member_inventory_verified",
        "expected_roles_verified",
        "compatibility_verified",
        "heartbeat_health_verified",
        "maintenance_failover_reviewed",
        "local_evidence_accounted_for",
    }


def test_environment_provider_is_optional_and_requires_absolute_path(
    tmp_path: Path,
) -> None:
    assert prerequisite_provider_from_environment({}) is None
    with pytest.raises(HaReconciliationError):
        prerequisite_provider_from_environment(
            {HA_RECONCILIATION_PREREQUISITES_ENV: "relative.json"}
        )

    directory = tmp_path / "ha"
    directory.mkdir(mode=0o700)
    path = directory / "prerequisites.json"
    _write_prerequisites(path)
    provider = prerequisite_provider_from_environment(
        {HA_RECONCILIATION_PREREQUISITES_ENV: str(path)}
    )
    assert isinstance(provider, OwnerOnlyHaReconciliationPrerequisiteProvider)
    assert provider().expected_member_inventory_verified is True


@pytest.mark.parametrize(
    "mutation",
    [
        {"schema_version": "2"},
        {"target_version": "1.9.0"},
        {"expected_roles_verified": 1},
        {"private_member": "must-not-accept"},
    ],
)
def test_owner_only_provider_rejects_schema_or_value_drift(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    directory = tmp_path / "ha"
    directory.mkdir(mode=0o700)
    path = directory / "prerequisites.json"
    _write_prerequisites(path, **mutation)

    with pytest.raises(HaReconciliationError) as caught:
        OwnerOnlyHaReconciliationPrerequisiteProvider(path)()
    assert str(caught.value) == "HA reconciliation prerequisites are unavailable."
    assert "private" not in str(caught.value).lower()


def test_owner_only_provider_rejects_weak_permissions_and_symlink(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "ha"
    directory.mkdir(mode=0o700)
    path = directory / "prerequisites.json"
    _write_prerequisites(path)
    path.chmod(0o644)
    with pytest.raises(HaReconciliationError):
        OwnerOnlyHaReconciliationPrerequisiteProvider(path)()

    path.chmod(0o600)
    link = directory / "link.json"
    link.symlink_to(path)
    with pytest.raises(HaReconciliationError):
        OwnerOnlyHaReconciliationPrerequisiteProvider(link)()


def test_owner_only_provider_requires_owner_only_parent(tmp_path: Path) -> None:
    directory = tmp_path / "ha"
    directory.mkdir(mode=0o700)
    path = directory / "prerequisites.json"
    _write_prerequisites(path)
    directory.chmod(0o755)

    with pytest.raises(HaReconciliationError):
        OwnerOnlyHaReconciliationPrerequisiteProvider(path)()


def _query_permission(**overrides: bool) -> HaReconciliationQueryPermission:
    values = {
        "api_configuration_read_verified": True,
        "cli_configuration_read_verified": True,
        "cli_status_read_verified": True,
        "cli_checksum_read_verified": True,
        "dedicated_identity_verified": True,
        "cross_domain_denial_verified": True,
    }
    values.update(overrides)
    return HaReconciliationQueryPermission(**values)


def _write_query_permission(path: Path, **overrides: object) -> None:
    payload: dict[str, object] = {
        "schema_version": "1",
        "target_version": "1.9.1",
        "api_configuration_read_verified": True,
        "cli_configuration_read_verified": True,
        "cli_status_read_verified": True,
        "cli_checksum_read_verified": True,
        "dedicated_identity_verified": True,
        "cross_domain_denial_verified": True,
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")
    path.chmod(0o600)


def _bound_for_runtime(calls: list[str]) -> BoundHaReconciliation:
    def collector(name: str, result: dict[str, object]):
        async def collect() -> dict[str, object]:
            calls.append(name)
            return deepcopy(result)

        return collect

    return BoundHaReconciliation(
        api_configuration_collector=collector("api", _api()),
        cli_configuration_collector=collector("configuration", _configuration()),
        cli_status_collector=collector("status", _status()),
        cli_checksum_collector=collector("checksum", _checksum()),
        prerequisite_provider=_prerequisites,
    )


def test_query_permission_is_exact_boolean_and_all_categories_required() -> None:
    assert _query_permission().verified is True
    assert _query_permission(cli_status_read_verified=False).verified is False
    with pytest.raises(HaReconciliationError, match="must be boolean"):
        _query_permission(dedicated_identity_verified=1)  # type: ignore[arg-type]


def test_runtime_binding_checks_permission_before_collecting() -> None:
    calls: list[str] = []
    binding = HaReconciliationRuntimeBinding(
        _bound_for_runtime(calls),
        lambda: _query_permission(cross_domain_denial_verified=False),
    )

    with pytest.raises(HaReconciliationError, match="permission is unavailable"):
        asyncio.run(binding.assess())
    assert calls == []


def test_runtime_binding_returns_only_the_existing_projection() -> None:
    calls: list[str] = []
    binding = HaReconciliationRuntimeBinding(
        _bound_for_runtime(calls), _query_permission
    )

    result = asyncio.run(binding.assess())

    assert result["assessment_status"] == "eligible_for_operator_review"
    assert sorted(calls) == ["api", "checksum", "configuration", "status"]


def test_runtime_feature_is_exact_and_disabled_by_default() -> None:
    assert load_ha_reconciliation_feature({}) is False
    assert load_ha_reconciliation_feature(
        {HA_RECONCILIATION_FEATURE_ENV: "false"}
    ) is False
    assert load_ha_reconciliation_feature(
        {HA_RECONCILIATION_FEATURE_ENV: "true"}
    ) is True
    with pytest.raises(HaReconciliationError, match="exactly true or false"):
        load_ha_reconciliation_feature(
            {HA_RECONCILIATION_FEATURE_ENV: "TRUE"}
        )


def test_owner_only_query_permission_provider_and_environment_binding(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "permission"
    directory.mkdir(mode=0o700)
    path = directory / "query.json"
    _write_query_permission(path)
    environment = {
        HA_RECONCILIATION_FEATURE_ENV: "true",
        HA_RECONCILIATION_QUERY_PERMISSION_ENV: str(path),
    }

    provider = query_permission_provider_from_environment(environment)
    assert isinstance(provider, OwnerOnlyHaReconciliationQueryPermissionProvider)
    assert provider().verified is True
    calls: list[str] = []
    binding = runtime_binding_from_environment(
        environment, _bound_for_runtime(calls)
    )
    assert isinstance(binding, HaReconciliationRuntimeBinding)
    assert asyncio.run(binding.assess())["operator_review_ready"] is True


def test_disabled_runtime_does_not_read_permission_and_enabled_requires_it() -> None:
    calls: list[str] = []
    composition = _bound_for_runtime(calls)
    assert runtime_binding_from_environment({}, composition) is None
    assert query_permission_provider_from_environment({}) is None
    with pytest.raises(HaReconciliationError, match="permission is unavailable"):
        runtime_binding_from_environment(
            {HA_RECONCILIATION_FEATURE_ENV: "true"}, composition
        )
    assert calls == []


@pytest.mark.parametrize(
    "mutation",
    [
        {"schema_version": "2"},
        {"target_version": "1.9.0"},
        {"cli_checksum_read_verified": 1},
        {"private_identity": "must-not-accept"},
    ],
)
def test_query_permission_provider_rejects_schema_or_value_drift(
    tmp_path: Path, mutation: dict[str, object]
) -> None:
    directory = tmp_path / "permission"
    directory.mkdir(mode=0o700)
    path = directory / "query.json"
    _write_query_permission(path, **mutation)

    with pytest.raises(HaReconciliationError) as caught:
        OwnerOnlyHaReconciliationQueryPermissionProvider(path)()
    assert str(caught.value) == "HA reconciliation query permission is unavailable."
    assert "private" not in str(caught.value).lower()
