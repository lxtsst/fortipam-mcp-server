"""Compiled diagnostic profiles over existing minimized FortiPAM Tool results."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Final

from .baseline_drift import (
    ProjectionContract,
    ProjectionContractRegistry,
    ProjectionEnvelope,
    ProjectionFieldContract,
    parse_projection_envelope,
)
from .config import HA_CONFIGURATION_PATH
from .evidence_correlation import (
    MAX_EPOCH,
    CorrelationContract,
    CorrelationRule,
    EvidenceContract,
    EvidenceContractRegistry,
    correlate_evidence,
)

HA_API_BASELINE_PROFILE_ID: Final = "ha_api_posture_v1"
HA_API_CLI_CORRELATION_PROFILE_ID: Final = "ha_api_cli_v1"
PROFILE_FRESHNESS_SECONDS: Final = 300

_MODES: Final = frozenset(
    {"standalone", "active_passive", "active_active", "unknown"}
)
_TOGGLES: Final = frozenset({"enabled", "disabled", "unknown"})
_SECURITY_STATES: Final = frozenset({"enabled", "disabled", "mixed", "unknown"})
_API_TOP_LEVEL_KEYS: Final = frozenset(
    {
        "scenario",
        "operation",
        "path",
        "sensitivity",
        "status_code",
        "content_type",
        "response_body_returned",
        "posture",
    }
)
_API_POSTURE_KEYS: Final = frozenset(
    {
        "contract",
        "ha_enabled",
        "topology_mode",
        "heartbeat_authentication_enabled",
        "heartbeat_encryption_enabled",
        "heartbeat_interface_configured",
        "monitored_interface_configured",
        "dedicated_management_enabled",
        "management_interface_entry_count",
        "unicast_heartbeat_enabled",
        "unicast_peer_entry_count",
        "session_pickup_enabled",
        "connectionless_session_pickup_enabled",
        "override_enabled",
        "synchronization_state",
        "response_body_returned",
        "serial_values_returned",
        "network_values_returned",
        "interface_values_returned",
        "group_values_returned",
        "credential_values_returned",
        "priority_values_returned",
        "checksum_values_returned",
    }
)
_API_OPTIONAL_BOOLEAN_KEYS: Final = frozenset(
    {
        "heartbeat_authentication_enabled",
        "heartbeat_encryption_enabled",
        "dedicated_management_enabled",
        "unicast_heartbeat_enabled",
        "session_pickup_enabled",
        "connectionless_session_pickup_enabled",
        "override_enabled",
    }
)
_API_BOOLEAN_KEYS: Final = frozenset(
    {"heartbeat_interface_configured", "monitored_interface_configured"}
)
_API_COUNT_KEYS: Final = frozenset(
    {"management_interface_entry_count", "unicast_peer_entry_count"}
)
_API_FALSE_FLAGS: Final = frozenset(
    {
        "response_body_returned",
        "serial_values_returned",
        "network_values_returned",
        "interface_values_returned",
        "group_values_returned",
        "credential_values_returned",
        "priority_values_returned",
        "checksum_values_returned",
    }
)
_CLI_TOP_LEVEL_KEYS: Final = frozenset(
    {
        "workflow_id",
        "execution_status",
        "evidence",
        "raw_cli_returned",
        "credential_values_returned",
    }
)
_CLI_EVIDENCE_KEYS: Final = frozenset(
    {
        "evidence_status",
        "ha_mode",
        "session_pickup",
        "override_state",
        "configuration_security",
        "identity_values_returned",
        "network_values_returned",
        "group_name_returned",
        "password_values_returned",
        "priority_values_returned",
        "exact_checksum_returned",
        "raw_cli_returned",
    }
)
_CLI_FALSE_FLAGS: Final = frozenset(
    {
        "identity_values_returned",
        "network_values_returned",
        "group_name_returned",
        "password_values_returned",
        "priority_values_returned",
        "exact_checksum_returned",
        "raw_cli_returned",
    }
)


class DiagnosticProfileError(ValueError):
    """Raised when an existing Tool result cannot satisfy a compiled profile."""


HA_API_PROJECTION_CONTRACT = ProjectionContract(
    contract_id="ha_api_posture",
    version="v1",
    data_class="C1",
    source_product="fortipam",
    source_product_version="1.9.1",
    source_class="fortipam_api",
    scope_class="appliance_singleton",
    required_paths=frozenset({("ha_enabled",), ("topology_mode",)}),
    field_rules=(
        ProjectionFieldContract(("ha_enabled",), "bool", "v1"),
        ProjectionFieldContract(
            ("topology_mode",),
            "string",
            "v1",
            enum_values=frozenset(
                {"standalone", "active_passive", "active_active"}
            ),
        ),
    ),
)
HA_API_PROJECTION_REGISTRY = ProjectionContractRegistry(
    (HA_API_PROJECTION_CONTRACT,)
)

HA_API_EVIDENCE_CONTRACT = EvidenceContract(
    contract_id="ha_api_posture_v1",
    product="fortipam",
    source_class="fortipam_api",
    contract_version="v1",
    allowed_signals=_MODES,
)
HA_CLI_EVIDENCE_CONTRACT = EvidenceContract(
    contract_id="ha_cli_posture_v1",
    product="fortipam",
    source_class="fortipam_cli",
    contract_version="v1",
    allowed_signals=_MODES,
)
HA_EVIDENCE_REGISTRY = EvidenceContractRegistry(
    (HA_API_EVIDENCE_CONTRACT, HA_CLI_EVIDENCE_CONTRACT)
)


def _relationship(left: str, right: str) -> str:
    if "unknown" in {left, right}:
        return "not_assessed"
    if left == right:
        return "operationally_consistent"
    return "contradictory"


HA_API_CLI_CORRELATION_CONTRACT = CorrelationContract(
    contract_id=HA_API_CLI_CORRELATION_PROFILE_ID,
    contract_version="v1",
    participating_contract_ids=(
        HA_API_EVIDENCE_CONTRACT.contract_id,
        HA_CLI_EVIDENCE_CONTRACT.contract_id,
    ),
    tenant_policy="same_tenant_only",
    max_fan_out=2,
    truth_table=tuple(
        CorrelationRule(
            (left, right),
            _relationship(left, right),
            "contract_signal_tuple",
        )
        for left in sorted(_MODES)
        for right in sorted(_MODES)
    ),
)


def project_ha_api_baseline(
    result: Mapping[str, object], observed_at: int | datetime
) -> ProjectionEnvelope:
    """Convert one complete existing API Tool result into a fixed C1 envelope."""

    moment = _observation_time(observed_at)
    posture = _validated_api_posture(result)
    topology_mode = posture["topology_mode"]
    ha_enabled = posture["ha_enabled"]
    if topology_mode == "unknown" or type(ha_enabled) is not bool:
        raise DiagnosticProfileError("HA API evidence is not complete.")
    expected_enabled = topology_mode != "standalone"
    if ha_enabled is not expected_enabled:
        raise DiagnosticProfileError("HA API evidence is contradictory.")

    envelope = {
        "schema_version": "2.3",
        "data_class": "C1",
        "source": {
            "product": "fortipam",
            "product_version": "1.9.1",
            "source_class": "fortipam_api",
        },
        "contract": {"id": "ha_api_posture", "version": "v1"},
        "scope_class": "appliance_singleton",
        "observed_at": _timestamp(moment),
        "fresh_until": _timestamp(
            moment + timedelta(seconds=PROFILE_FRESHNESS_SECONDS)
        ),
        "evidence_state": "complete",
        "projection": {
            "ha_enabled": ha_enabled,
            "topology_mode": topology_mode,
        },
    }
    return parse_projection_envelope(
        envelope,
        HA_API_PROJECTION_REGISTRY,
        require_required_paths=True,
    )


def correlate_ha_api_cli(
    api_result: Mapping[str, object],
    cli_result: Mapping[str, object],
    *,
    api_evidence_ref: str,
    cli_evidence_ref: str,
    tenant_scope: str,
    now_epoch: int,
) -> dict[str, str]:
    """Correlate only fixed HA API and CLI categories under one truth table."""

    _strict_epoch(now_epoch)
    api_posture = _validated_api_posture(api_result)
    cli_evidence = _validated_cli_evidence(cli_result)
    api_mode = api_posture["topology_mode"]
    cli_mode = cli_evidence["ha_mode"]
    if not isinstance(api_mode, str) or not isinstance(cli_mode, str):
        raise DiagnosticProfileError("HA evidence mode is invalid.")
    expected_enabled = None if api_mode == "unknown" else api_mode != "standalone"
    api_complete = (
        type(api_posture["ha_enabled"]) is bool
        and api_posture["ha_enabled"] is expected_enabled
    )
    cli_complete = cli_evidence["evidence_status"] == "complete" and cli_mode != "unknown"
    common = {
        "product": "fortipam",
        "tenant_scope": tenant_scope,
        "contract_version": "v1",
        "authorization_state": "independently_authorized",
        "observed_at": now_epoch,
        "fresh_until": now_epoch + PROFILE_FRESHNESS_SECONDS,
        "confidence_band": "high",
    }
    envelopes = (
        {
            **common,
            "evidence_ref": api_evidence_ref,
            "contract_id": HA_API_EVIDENCE_CONTRACT.contract_id,
            "source_class": HA_API_EVIDENCE_CONTRACT.source_class,
            "principal_class": "fortipam_api_readonly",
            "evidence_state": "observed" if api_complete else "not_assessed",
            "signal": api_mode,
        },
        {
            **common,
            "evidence_ref": cli_evidence_ref,
            "contract_id": HA_CLI_EVIDENCE_CONTRACT.contract_id,
            "source_class": HA_CLI_EVIDENCE_CONTRACT.source_class,
            "principal_class": "fortipam_cli_readonly",
            "evidence_state": "observed" if cli_complete else "not_assessed",
            "signal": cli_mode,
        },
    )
    return correlate_evidence(
        envelopes,
        registry=HA_EVIDENCE_REGISTRY,
        correlation_contract=HA_API_CLI_CORRELATION_CONTRACT,
        now_epoch=now_epoch,
    )


def _validated_api_posture(result: Mapping[str, object]) -> Mapping[str, object]:
    if not isinstance(result, Mapping) or set(result) != _API_TOP_LEVEL_KEYS:
        raise DiagnosticProfileError("HA API result schema is not accepted.")
    status_code = result["status_code"]
    content_type = result["content_type"]
    if (
        result["scenario"] != "ha_sync"
        or result["operation"] != "GET"
        or result["path"] != HA_CONFIGURATION_PATH
        or result["sensitivity"] != "ha_configuration_posture"
        or type(status_code) is not int
        or status_code != 200
        or type(content_type) is not str
        or content_type.split(";", maxsplit=1)[0].strip().lower()
        != "application/json"
        or result["response_body_returned"] is not False
    ):
        raise DiagnosticProfileError("HA API result contract is not accepted.")
    posture = result["posture"]
    if not isinstance(posture, Mapping) or set(posture) != _API_POSTURE_KEYS:
        raise DiagnosticProfileError("HA API posture schema is not accepted.")
    if (
        posture["contract"] != "fortipam_ha_configuration_posture_v1"
        or posture["topology_mode"] not in _MODES
        or posture["synchronization_state"] != "not_observed"
        or type(posture["ha_enabled"]) not in {bool, type(None)}
        or any(type(posture[key]) not in {bool, type(None)} for key in _API_OPTIONAL_BOOLEAN_KEYS)
        or any(type(posture[key]) is not bool for key in _API_BOOLEAN_KEYS)
        or any(type(posture[key]) is not int or posture[key] < 0 for key in _API_COUNT_KEYS)
        or any(posture[key] is not False for key in _API_FALSE_FLAGS)
    ):
        raise DiagnosticProfileError("HA API posture contract is not accepted.")
    return posture


def _validated_cli_evidence(result: Mapping[str, object]) -> Mapping[str, object]:
    if not isinstance(result, Mapping) or set(result) != _CLI_TOP_LEVEL_KEYS:
        raise DiagnosticProfileError("HA CLI result schema is not accepted.")
    if (
        result["workflow_id"] != "ha_configuration"
        or result["execution_status"] != "completed"
        or result["raw_cli_returned"] is not False
        or result["credential_values_returned"] is not False
    ):
        raise DiagnosticProfileError("HA CLI result contract is not accepted.")
    evidence = result["evidence"]
    if not isinstance(evidence, Mapping) or set(evidence) != _CLI_EVIDENCE_KEYS:
        raise DiagnosticProfileError("HA CLI evidence schema is not accepted.")
    if (
        evidence["evidence_status"] not in {"complete", "partial"}
        or evidence["ha_mode"] not in _MODES
        or evidence["session_pickup"] not in _TOGGLES
        or evidence["override_state"] not in _TOGGLES
        or evidence["configuration_security"] not in _SECURITY_STATES
        or any(evidence[key] is not False for key in _CLI_FALSE_FLAGS)
    ):
        raise DiagnosticProfileError("HA CLI evidence contract is not accepted.")
    return evidence


def _observation_time(value: int | datetime) -> datetime:
    if type(value) is int:
        _strict_epoch(value)
        return datetime.fromtimestamp(value, UTC)
    if isinstance(value, datetime) and value.tzinfo is not None:
        normalized = value.astimezone(UTC)
        _strict_epoch(int(normalized.timestamp()))
        return normalized
    raise DiagnosticProfileError("The diagnostic observation clock is invalid.")


def _strict_epoch(value: object) -> int:
    if type(value) is not int or not 0 <= value <= MAX_EPOCH - PROFILE_FRESHNESS_SECONDS:
        raise DiagnosticProfileError("The diagnostic observation clock is invalid.")
    return value


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


__all__ = [
    "DiagnosticProfileError",
    "HA_API_BASELINE_PROFILE_ID",
    "HA_API_CLI_CORRELATION_CONTRACT",
    "HA_API_CLI_CORRELATION_PROFILE_ID",
    "HA_API_PROJECTION_CONTRACT",
    "HA_API_PROJECTION_REGISTRY",
    "correlate_ha_api_cli",
    "project_ha_api_baseline",
]
