from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3

from mcp.server.auth.provider import AccessToken
import pytest

from fortipam_mcp.config import HA_CONFIGURATION_PATH
from fortipam_mcp.diagnostic_service import (
    DIAGNOSTIC_FAILURE,
    DIAGNOSTIC_UNAVAILABLE,
    DiagnosticServiceError,
    DiagnosticServiceSettings,
    FortiPamDiagnosticService,
    diagnostic_settings_from_environment,
)
from fortipam_mcp.ha_reconciliation import (
    BoundHaReconciliation,
    HaReconciliationPrerequisites,
    HaReconciliationQueryPermission,
    HaReconciliationRuntimeBinding,
)


NOW = datetime(2026, 8, 22, 12, tzinfo=UTC)
RESOURCE = "https://mcp.example.test/fpamcp"
KEY = b"k" * 32


def _token(
    *,
    subject: str = "operator-one",
    scopes: list[str] | None = None,
    resource: str = RESOURCE,
) -> AccessToken:
    return AccessToken(
        token="verified-token",
        client_id="client-one",
        scopes=["fortipam:read", "fortipam:diagnostic"]
        if scopes is None
        else scopes,
        expires_at=2_000_000_000,
        resource=resource,
        subject=subject,
        claims={"iss": "https://issuer.example.test"},
    )


def _api_result(*, mode: str = "standalone", enabled: bool = False) -> dict[str, object]:
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
            "ha_enabled": enabled,
            "topology_mode": mode,
            "heartbeat_authentication_enabled": True,
            "heartbeat_encryption_enabled": True,
            "heartbeat_interface_configured": True,
            "monitored_interface_configured": False,
            "dedicated_management_enabled": False,
            "management_interface_entry_count": 0,
            "unicast_heartbeat_enabled": False,
            "unicast_peer_entry_count": 0,
            "session_pickup_enabled": False,
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


def _cli_result(*, mode: str = "standalone") -> dict[str, object]:
    return {
        "workflow_id": "ha_configuration",
        "execution_status": "completed",
        "evidence": {
            "evidence_status": "complete",
            "ha_mode": mode,
            "session_pickup": "disabled",
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
        "raw_cli_returned": False,
        "credential_values_returned": False,
    }


def _status_result() -> dict[str, object]:
    return {
        "workflow_id": "ha_status",
        "execution_status": "completed",
        "evidence": {
            "evidence_status": "complete",
            "ha_mode": "standalone",
            "ha_health": "healthy",
            "member_count_band": "single",
            "configuration_sync": "not_applicable",
            "peer_identity_returned": False,
            "network_values_returned": False,
            "exact_time_returned": False,
            "raw_cli_returned": False,
        },
        "raw_cli_returned": False,
        "credential_values_returned": False,
    }


def _checksum_result() -> dict[str, object]:
    return {
        "workflow_id": "ha_checksum",
        "execution_status": "completed",
        "evidence": {
            "evidence_status": "complete",
            "ha_mode": "standalone",
            "checksum_assessment": "not_applicable",
            "member_count_band": "single",
            "exact_checksum_returned": False,
            "member_identity_returned": False,
            "table_name_returned": False,
            "raw_cli_returned": False,
        },
        "raw_cli_returned": False,
        "credential_values_returned": False,
    }


def _bound_reconciliation(
    *, invalid_status: bool = False, calls: list[str] | None = None
) -> HaReconciliationRuntimeBinding:
    def collector(name: str, result: dict[str, object]):
        async def collect() -> dict[str, object]:
            if calls is not None:
                calls.append(name)
            return deepcopy(result)

        return collect

    status = _status_result()
    if invalid_status:
        status["private_detail"] = "must-not-leak"
    composition = BoundHaReconciliation(
        api_configuration_collector=collector("api", _api_result()),
        cli_configuration_collector=collector("configuration", _cli_result()),
        cli_status_collector=collector("status", status),
        cli_checksum_collector=collector("checksum", _checksum_result()),
        prerequisite_provider=lambda: HaReconciliationPrerequisites(
            expected_member_inventory_verified=True,
            expected_roles_verified=True,
            compatibility_verified=True,
            heartbeat_health_verified=True,
            maintenance_failover_reviewed=True,
            local_evidence_accounted_for=True,
        ),
    )
    return HaReconciliationRuntimeBinding(
        composition,
        lambda: HaReconciliationQueryPermission(
            api_configuration_read_verified=True,
            cli_configuration_read_verified=True,
            cli_status_read_verified=True,
            cli_checksum_read_verified=True,
            dedicated_identity_verified=True,
            cross_domain_denial_verified=True,
        ),
    )


def _service(
    tmp_path: Path,
    *,
    api_result: dict[str, object] | None = None,
    cli_result: dict[str, object] | None = None,
    reconciliation: HaReconciliationRuntimeBinding | None = None,
    clock: object = None,
) -> FortiPamDiagnosticService:
    api = _api_result() if api_result is None else api_result
    cli = _cli_result() if cli_result is None else cli_result

    async def collect_api() -> dict[str, object]:
        return deepcopy(api)

    async def collect_cli() -> dict[str, object]:
        return deepcopy(cli)

    return FortiPamDiagnosticService(
        DiagnosticServiceSettings(tmp_path / "state" / "diagnostic.sqlite3", KEY, RESOURCE),
        ha_api_collector=collect_api,
        ha_cli_collector=collect_cli,
        ha_reconciliation=reconciliation,
        clock=(lambda: NOW) if clock is None else clock,  # type: ignore[arg-type]
    )


def test_create_and_compare_return_only_closed_status(tmp_path: Path) -> None:
    service = _service(tmp_path)
    assert asyncio.run(service.create_ha_baseline(_token(), "known-ha")) == {
        "status": "created"
    }
    assert asyncio.run(service.compare_ha_baseline(_token(), "known-ha")) == {
        "status": "unchanged"
    }

    database = tmp_path / "state" / "diagnostic.sqlite3"
    with sqlite3.connect(database) as connection:
        events = connection.execute(
            "SELECT event_type, outcome FROM audit_events ORDER BY sequence"
        ).fetchall()
    assert events == [
        ("baseline_create", "accepted"),
        ("baseline_compare", "unchanged"),
    ]


def test_compare_reports_changed_missing_and_stale_without_values(tmp_path: Path) -> None:
    original = _service(tmp_path)
    asyncio.run(original.create_ha_baseline(_token(), "known-ha"))

    changed = _service(
        tmp_path,
        api_result=_api_result(mode="active_passive", enabled=True),
    )
    assert asyncio.run(changed.compare_ha_baseline(_token(), "known-ha")) == {
        "status": "changed"
    }
    assert asyncio.run(changed.compare_ha_baseline(_token(), "missing-ha")) == {
        "status": "not_assessed"
    }

    stale = _service(tmp_path, clock=lambda: NOW + timedelta(minutes=6))
    assert asyncio.run(stale.compare_ha_baseline(_token(), "known-ha")) == {
        "status": "stale"
    }


def test_principal_namespaces_are_isolated(tmp_path: Path) -> None:
    service = _service(tmp_path)
    asyncio.run(
        service.create_ha_baseline(_token(subject="operator-one"), "known-ha")
    )
    assert asyncio.run(
        service.compare_ha_baseline(_token(subject="operator-two"), "known-ha")
    ) == {"status": "not_assessed"}


def test_duplicate_create_is_denied_and_audited_without_identifier(tmp_path: Path) -> None:
    service = _service(tmp_path)
    asyncio.run(service.create_ha_baseline(_token(), "known-ha"))
    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_FAILURE):
        asyncio.run(service.create_ha_baseline(_token(), "known-ha"))
    raw = (tmp_path / "state" / "diagnostic.sqlite3").read_bytes()
    assert b"known-ha" not in raw
    with sqlite3.connect(tmp_path / "state" / "diagnostic.sqlite3") as connection:
        outcomes = connection.execute(
            "SELECT outcome FROM audit_events ORDER BY sequence"
        ).fetchall()
    assert outcomes == [("accepted",), ("rejected",)]


def test_correlation_returns_only_relationship_status(tmp_path: Path) -> None:
    service = _service(tmp_path)
    result = asyncio.run(service.correlate_ha_api_cli(_token()))
    assert result == {"status": "operationally_consistent"}
    assert set(result) == {"status"}


def test_correlation_detects_contradiction(tmp_path: Path) -> None:
    service = _service(
        tmp_path,
        api_result=_api_result(mode="active_passive", enabled=True),
        cli_result=_cli_result(mode="active_active"),
    )
    assert asyncio.run(service.correlate_ha_api_cli(_token())) == {
        "status": "contradictory"
    }


def test_reconciliation_is_authenticated_minimized_and_audited(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    service = _service(
        tmp_path,
        reconciliation=_bound_reconciliation(calls=calls),
    )

    result = asyncio.run(service.reconcile_ha(_token()))

    assert result == {"status": "eligible_for_operator_review"}
    assert sorted(calls) == ["api", "checksum", "configuration", "status"]
    database = tmp_path / "state" / "diagnostic.sqlite3"
    with sqlite3.connect(database) as connection:
        event = connection.execute(
            "SELECT event_type, profile, contract_id, contract_version, outcome "
            "FROM audit_events"
        ).fetchone()
    assert event == (
        "ha_reconcile",
        "ha_reconciliation",
        "fortipam_v4_ha_reconciliation_assessment_v1",
        "1",
        "eligible_for_operator_review",
    )
    stored = database.read_bytes()
    assert b"operator-one" not in stored
    assert b"verified-token" not in stored


def test_reconciliation_denies_missing_binding_and_scope_before_collection(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    unbound = _service(tmp_path / "unbound")
    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_UNAVAILABLE):
        asyncio.run(unbound.reconcile_ha(_token()))

    bound = _service(
        tmp_path / "scope",
        reconciliation=_bound_reconciliation(calls=calls),
    )
    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_UNAVAILABLE):
        asyncio.run(bound.reconcile_ha(_token(scopes=["fortipam:read"])))
    assert calls == []


def test_reconciliation_failure_is_non_disclosing_and_audited(
    tmp_path: Path,
) -> None:
    service = _service(
        tmp_path,
        reconciliation=_bound_reconciliation(invalid_status=True),
    )

    with pytest.raises(DiagnosticServiceError) as caught:
        asyncio.run(service.reconcile_ha(_token()))

    assert str(caught.value) == DIAGNOSTIC_FAILURE
    assert "private_detail" not in str(caught.value)
    with sqlite3.connect(tmp_path / "state" / "diagnostic.sqlite3") as connection:
        assert connection.execute(
            "SELECT event_type, outcome FROM audit_events"
        ).fetchall() == [("ha_reconcile", "rejected")]


def test_reconciliation_constructor_rejects_untyped_binding(tmp_path: Path) -> None:
    async def collect() -> dict[str, object]:
        return {}

    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_UNAVAILABLE):
        FortiPamDiagnosticService(
            DiagnosticServiceSettings(tmp_path / "state.db", KEY, RESOURCE),
            ha_api_collector=collect,
            ha_cli_collector=collect,
            ha_reconciliation=object(),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "token",
    [
        None,
        _token(scopes=["fortipam:read"]),
        _token(resource="https://other.example.test/fpamcp"),
    ],
)
def test_stdio_static_bearer_and_wrong_scope_are_denied(
    tmp_path: Path, token: AccessToken | None
) -> None:
    service = _service(tmp_path)
    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_UNAVAILABLE):
        asyncio.run(service.create_ha_baseline(token, "known-ha"))


def test_collector_schema_failure_is_non_disclosing_and_audited(tmp_path: Path) -> None:
    invalid = _api_result()
    invalid["token"] = "must-not-leak"
    service = _service(tmp_path, api_result=invalid)
    with pytest.raises(DiagnosticServiceError) as caught:
        asyncio.run(service.create_ha_baseline(_token(), "known-ha"))
    assert str(caught.value) == DIAGNOSTIC_FAILURE
    assert "token" not in str(caught.value).lower()
    with sqlite3.connect(tmp_path / "state" / "diagnostic.sqlite3") as connection:
        assert connection.execute("SELECT outcome FROM audit_events").fetchall() == [
            ("rejected",)
        ]


def test_unexpected_collector_failure_is_wrapped_and_non_disclosing(
    tmp_path: Path,
) -> None:
    async def failed_collector() -> dict[str, object]:
        raise RuntimeError("private-transport-detail")

    service = FortiPamDiagnosticService(
        DiagnosticServiceSettings(tmp_path / "state.db", KEY, RESOURCE),
        ha_api_collector=failed_collector,
        ha_cli_collector=failed_collector,
        clock=lambda: NOW,
    )
    with pytest.raises(DiagnosticServiceError) as caught:
        asyncio.run(service.create_ha_baseline(_token(), "known-ha"))
    assert str(caught.value) == DIAGNOSTIC_FAILURE
    assert "private-transport-detail" not in str(caught.value)


def test_settings_and_clock_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_UNAVAILABLE):
        DiagnosticServiceSettings(Path("relative.db"), KEY, RESOURCE)
    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_UNAVAILABLE):
        DiagnosticServiceSettings(tmp_path / "state.db", b"short", RESOURCE)
    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_UNAVAILABLE):
        DiagnosticServiceSettings(
            tmp_path / "state.db", KEY, "http://mcp.example.test/fpamcp"
        )
    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_UNAVAILABLE):
        DiagnosticServiceSettings(  # type: ignore[arg-type]
            "not-a-path", KEY, RESOURCE
        )


def test_environment_settings_are_all_or_nothing_and_owner_only(tmp_path: Path) -> None:
    key_file = tmp_path / "diagnostic.key"
    key_file.write_text("ab" * 32 + "\n", encoding="ascii")
    key_file.chmod(0o600)
    environment = {
        "FORTIPAM_MCP_DIAGNOSTIC_DB": str(tmp_path / "state" / "diagnostic.db"),
        "FORTIPAM_MCP_DIAGNOSTIC_HMAC_KEY_FILE": str(key_file),
    }
    settings = diagnostic_settings_from_environment(
        environment, expected_resource=RESOURCE
    )
    assert settings is not None
    assert settings.hmac_key == bytes.fromhex("ab" * 32)

    assert diagnostic_settings_from_environment({}, expected_resource=RESOURCE) is None
    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_UNAVAILABLE):
        diagnostic_settings_from_environment(
            {"FORTIPAM_MCP_DIAGNOSTIC_DB": str(tmp_path / "state.db")},
            expected_resource=RESOURCE,
        )

    key_file.chmod(0o644)
    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_UNAVAILABLE):
        diagnostic_settings_from_environment(environment, expected_resource=RESOURCE)


def test_environment_settings_reject_key_symlink_and_bad_encoding(tmp_path: Path) -> None:
    real_key = tmp_path / "real.key"
    real_key.write_text("ab" * 32, encoding="ascii")
    real_key.chmod(0o600)
    link = tmp_path / "link.key"
    link.symlink_to(real_key)
    environment = {
        "FORTIPAM_MCP_DIAGNOSTIC_DB": str(tmp_path / "state.db"),
        "FORTIPAM_MCP_DIAGNOSTIC_HMAC_KEY_FILE": str(link),
    }
    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_UNAVAILABLE):
        diagnostic_settings_from_environment(environment, expected_resource=RESOURCE)

    real_key.write_text("AB" * 32, encoding="ascii")
    with pytest.raises(DiagnosticServiceError, match=DIAGNOSTIC_UNAVAILABLE):
        diagnostic_settings_from_environment(
            {**environment, "FORTIPAM_MCP_DIAGNOSTIC_HMAC_KEY_FILE": str(real_key)},
            expected_resource=RESOURCE,
        )
