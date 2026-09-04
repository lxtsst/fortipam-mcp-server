"""Pure, non-disclosing projections for promoted live posture tools."""

from __future__ import annotations

from typing import Mapping


class PostureContractError(ValueError):
    """Raised when a candidate response cannot satisfy its safe contract."""


OVERALL_HEALTH_COMPONENTS = (
    "system_status",
    "system_global",
    "approval_profile",
    "fortianalyzer_delivery",
    "license_support",
    "ha_configuration",
    "recording_storage",
)


def summarize_overall_health_posture(
    component_results: Mapping[str, object | None],
) -> dict[str, object]:
    """Combine seven accepted reads without returning their underlying data.

    A successful read proves that evidence was observed, not that a component
    is healthy. Risk signals are derived only from the existing minimized
    posture contracts; structural reads remain explicitly ``not_assessed``.
    """

    components: dict[str, dict[str, str]] = {}
    completed_reads = 0
    for name in OVERALL_HEALTH_COMPONENTS:
        result = component_results.get(name)
        if not isinstance(result, Mapping):
            components[name] = {
                "evidence_state": "unavailable",
                "risk_signal": "unknown",
            }
            continue
        completed_reads += 1
        components[name] = {
            "evidence_state": "observed",
            "risk_signal": _component_risk_signal(name, result),
        }

    failed_reads = len(OVERALL_HEALTH_COMPONENTS) - completed_reads
    if completed_reads == len(OVERALL_HEALTH_COMPONENTS):
        evidence_completeness = "complete"
    elif completed_reads == 0:
        evidence_completeness = "unavailable"
    else:
        evidence_completeness = "partial"

    signals = {component["risk_signal"] for component in components.values()}
    if "critical" in signals:
        risk_signal = "critical"
    elif "warning" in signals:
        risk_signal = "warning"
    elif "none_observed" in signals:
        risk_signal = "none_observed"
    else:
        risk_signal = "unknown"

    return {
        "contract": "fortipam_overall_health_posture_v1",
        "evidence_completeness": evidence_completeness,
        "risk_signal": risk_signal,
        "components": components,
        "completed_reads": completed_reads,
        "failed_reads": failed_reads,
        "fixed_route_count": len(OVERALL_HEALTH_COMPONENTS),
        "response_body_returned": False,
        "raw_component_results_returned": False,
        "component_error_details_returned": False,
        "identity_values_returned": False,
        "network_values_returned": False,
        "exact_time_values_returned": False,
        "exact_capacity_values_returned": False,
    }


def summarize_fortianalyzer_delivery_posture(payload: object) -> dict[str, object]:
    """Project only non-identifying FortiAnalyzer delivery posture fields."""

    if not isinstance(payload, Mapping):
        raise PostureContractError("FortiAnalyzer response must be an object.")
    results = payload.get("results")
    if not isinstance(results, Mapping):
        raise PostureContractError(
            "FortiAnalyzer response must contain a configuration object."
        )

    serials = results.get("serial")
    serial_count = len(serials) if isinstance(serials, list) else 0
    return {
        "contract": "fortianalyzer_delivery_posture_v1",
        "enabled": _enabled(results.get("status")),
        "reliable_transport_enabled": _enabled(results.get("reliable")),
        "certificate_verification_enabled": _enabled(
            results.get("certificate-verification")
        ),
        "fortianalyzer_rest_access_enabled": _enabled(
            results.get("access-config")
        ),
        "server_configured": _configured(results.get("server")),
        "registered_serial_count": serial_count,
        "certificate_configured": _configured(results.get("certificate")),
        "preshared_key_configured": _configured(results.get("preshared-key")),
        "source_ip_override_configured": _configured(results.get("source-ip")),
        "interface_override_configured": _configured(results.get("interface")),
        "upload_schedule_configured": any(
            _configured(results.get(key))
            for key in ("upload-option", "upload-interval", "upload-time")
        ),
        "response_body_returned": False,
        "server_value_returned": False,
        "serial_values_returned": False,
        "credential_values_returned": False,
    }


def summarize_license_support_posture(
    payload: object, *, now_epoch: int
) -> dict[str, object]:
    """Project license and support health without identity or exact values."""

    if not isinstance(payload, Mapping):
        raise PostureContractError("License response must be an object.")
    results = payload.get("results")
    if not isinstance(results, Mapping):
        raise PostureContractError(
            "License response must contain a license-status object."
        )
    if now_epoch <= 0:
        raise PostureContractError("License projection requires a valid clock.")

    subscription = _mapping(results.get("subscription"))
    forticare = _mapping(results.get("forticare"))
    support = _mapping(_mapping(forticare.get("support")).get("enhanced"))
    virtual_machine = _mapping(results.get("vm"))
    fortiguard = _mapping(results.get("fortiguard"))
    return {
        "contract": "fortipam_license_support_posture_v1",
        "subscription_state": _status_class(subscription.get("status")),
        "subscription_expiry_band": _expiry_band(
            subscription.get("expires"), now_epoch
        ),
        "user_capacity_state": _capacity_state(
            subscription.get("enabled_users"),
            subscription.get("licensed_users"),
        ),
        "forticare_state": _status_class(forticare.get("status")),
        "support_state": _status_class(support.get("status")),
        "support_expiry_band": _expiry_band(support.get("expires"), now_epoch),
        "vm_license_state": _status_class(virtual_machine.get("status")),
        "vm_license_valid": _boolean(virtual_machine.get("valid")),
        "closed_network_mode": _boolean(virtual_machine.get("closed_network")),
        "fortiguard_connected": _boolean(fortiguard.get("connected")),
        "fortiguard_scheduled_updates_enabled": _boolean(
            fortiguard.get("scheduled_updates_enabled")
        ),
        "response_body_returned": False,
        "identity_values_returned": False,
        "account_values_returned": False,
        "exact_expiry_values_returned": False,
        "capacity_values_returned": False,
        "server_values_returned": False,
    }


def summarize_ha_configuration_posture(payload: object) -> dict[str, object]:
    """Project HA configuration security posture without topology values."""

    if not isinstance(payload, Mapping):
        raise PostureContractError("HA response must be an object.")
    results = payload.get("results")
    if not isinstance(results, Mapping):
        raise PostureContractError(
            "HA response must contain a configuration object."
        )

    topology_mode = _ha_topology_mode(results.get("mode"))
    return {
        "contract": "fortipam_ha_configuration_posture_v1",
        "ha_enabled": _ha_enabled(topology_mode),
        "topology_mode": topology_mode,
        "heartbeat_authentication_enabled": _enabled(
            results.get("authentication")
        ),
        "heartbeat_encryption_enabled": _enabled(results.get("encryption")),
        "heartbeat_interface_configured": _configured(results.get("hbdev")),
        "monitored_interface_configured": _configured(results.get("monitor")),
        "dedicated_management_enabled": _enabled(
            results.get("ha-mgmt-status")
        ),
        "management_interface_entry_count": _list_count(
            results.get("ha-mgmt-interfaces")
        ),
        "unicast_heartbeat_enabled": _enabled(results.get("unicast-status")),
        "unicast_peer_entry_count": _list_count(results.get("unicast-peers")),
        "session_pickup_enabled": _enabled(results.get("session-pickup")),
        "connectionless_session_pickup_enabled": _enabled(
            results.get("session-pickup-connectionless")
        ),
        "override_enabled": _enabled(results.get("override")),
        "synchronization_state": "not_observed",
        "response_body_returned": False,
        "serial_values_returned": False,
        "network_values_returned": False,
        "interface_values_returned": False,
        "group_values_returned": False,
        "credential_values_returned": False,
        "priority_values_returned": False,
        "checksum_values_returned": False,
    }


def summarize_recording_storage_posture(payload: object) -> dict[str, object]:
    """Project video/log disk health without sizes or recording timestamps."""

    if not isinstance(payload, Mapping):
        raise PostureContractError("Storage response must be an object.")
    results = payload.get("results")
    if not isinstance(results, Mapping):
        raise PostureContractError(
            "Storage response must contain a disk-usage object."
        )

    oldest_present = _configured(results.get("oldest video tm_stamp"))
    newest_present = _configured(results.get("newest video tm_stamp"))
    return {
        "contract": "fortipam_recording_storage_posture_v1",
        "video_storage_present": _positive_capacity(
            results.get("video_disk_total_bytes")
        ),
        "video_usage_band": _capacity_usage_band(
            results.get("video_disk_total_bytes"),
            results.get("video_used_bytes"),
        ),
        "log_storage_present": _positive_capacity(results.get("total_bytes")),
        "log_usage_band": _capacity_usage_band(
            results.get("total_bytes"), results.get("used_bytes")
        ),
        "oldest_recording_present": oldest_present,
        "newest_recording_present": newest_present,
        "recording_history_state": _history_state(
            oldest_present, newest_present
        ),
        "response_body_returned": False,
        "capacity_values_returned": False,
        "timestamp_values_returned": False,
        "recording_values_returned": False,
        "identity_values_returned": False,
    }


_FORTIOS_763_DOCUMENTED_LABELS = frozenset(
    {
        "SSH Password (FortiOS 7.6.3 and higher)",
        "SSH Password (FortiOS 7.6.3 or higher)",
    }
)
_PASSWORD_CHANGER_COLLECTION_FIELDS = frozenset(
    {
        "change",
        "change-auth-mode",
        "description",
        "name",
        "new-line-mode",
        "q_origin_key",
        "type",
        "verify",
        "verify-auth-mode",
        "web-change",
        "web-verify",
    }
)


def summarize_password_changer_configuration_posture(
    payload: object,
) -> dict[str, object]:
    """Project only fixed label observations from the changer collection.

    Names are compared in-process against documented labels and are never
    returned. A label match is not proof that a definition is the vendor
    default, unmodified, assigned, or compatible with a target. Procedure,
    description, authentication-mode, reference, and origin values are ignored.
    """

    if not isinstance(payload, Mapping):
        raise PostureContractError("Password-changer response must be an object.")
    results = payload.get("results")
    if not isinstance(results, list):
        raise PostureContractError(
            "Password-changer response must contain a collection."
        )
    if any(not isinstance(entry, Mapping) for entry in results):
        raise PostureContractError(
            "Password-changer collection entries must be objects."
        )
    for entry in results:
        if (
            not set(entry).issubset(_PASSWORD_CHANGER_COLLECTION_FIELDS)
            or not isinstance(entry.get("name"), str)
            or not isinstance(entry.get("type"), str)
        ):
            raise PostureContractError(
                "Password-changer collection schema is not accepted."
            )

    names = {str(entry["name"]) for entry in results}
    documented_label_observed = bool(names & _FORTIOS_763_DOCUMENTED_LABELS)
    return {
        "contract": "fortipam_password_changer_configuration_posture_v1",
        "changer_inventory_state": "none" if not results else "present",
        "changer_count_band": _collection_count_band(len(results)),
        "fortios_7_6_3_documented_label_observed": documented_label_observed,
        "label_observation": (
            "documented_label_observed"
            if documented_label_observed
            else "not_observed"
        ),
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
    }


_EMS_RECORD_FIELDS = frozenset({"name", "cert_status", "conn_status"})
_EMS_CERT_STATUS_FIELDS = frozenset({"status"})
_EMS_CONNECTION_STATUS_FIELDS = frozenset(
    {"ems_name", "ems_status", "ems_status_id", "mgmt_ip", "mgmt_port"}
)
_EMS_CERTIFICATE_POSITIVE_STATES = frozenset({"success"})
_EMS_CERTIFICATE_NEGATIVE_STATES: frozenset[str] = frozenset()
_EMS_CONNECTION_POSITIVE_STATES = frozenset({"success"})
_EMS_CONNECTION_NEGATIVE_STATES: frozenset[str] = frozenset()
_EMS_POSTURE_FIELDS = frozenset(
    {
        "contract",
        "connector_inventory_state",
        "connector_count_band",
        "connection_evidence_completeness",
        "aggregate_connection_state",
        "aggregate_certificate_state",
        "risk_signal",
        "ztna_tag_assignment_assessed",
        "proxy_policy_assessed",
        "endpoint_posture_assessed",
        "secret_launch_assessed",
        "response_body_returned",
        "connector_name_values_returned",
        "network_values_returned",
        "port_values_returned",
        "certificate_values_returned",
        "tag_values_returned",
        "endpoint_values_returned",
        "raw_status_values_returned",
        "raw_field_values_returned",
    }
)
_EMS_POSTURE_FALSE_FLAGS = _EMS_POSTURE_FIELDS - {
    "contract",
    "connector_inventory_state",
    "connector_count_band",
    "connection_evidence_completeness",
    "aggregate_connection_state",
    "aggregate_certificate_state",
    "risk_signal",
}


def summarize_ems_connection_posture(payload: object) -> dict[str, object]:
    """Project aggregate EMS connection evidence without connector values."""

    if not isinstance(payload, Mapping):
        raise PostureContractError("EMS response must be an object.")
    results = payload.get("results")
    if not isinstance(results, list):
        raise PostureContractError("EMS response must contain a collection.")

    connection_states: list[str] = []
    certificate_states: list[str] = []
    for entry in results:
        if not isinstance(entry, Mapping) or set(entry) != _EMS_RECORD_FIELDS:
            raise PostureContractError("EMS collection schema is not accepted.")
        if not isinstance(entry.get("name"), str):
            raise PostureContractError("EMS connector identity shape is invalid.")
        certificate = entry.get("cert_status")
        connection = entry.get("conn_status")
        if (
            not isinstance(certificate, Mapping)
            or set(certificate) != _EMS_CERT_STATUS_FIELDS
            or not isinstance(certificate.get("status"), str)
            or not isinstance(connection, Mapping)
            or set(connection) != _EMS_CONNECTION_STATUS_FIELDS
            or not isinstance(connection.get("ems_name"), str)
            or not isinstance(connection.get("ems_status"), str)
            or type(connection.get("ems_status_id")) is not int
            or not isinstance(connection.get("mgmt_ip"), str)
            or type(connection.get("mgmt_port")) is not int
        ):
            raise PostureContractError("EMS status schema is not accepted.")
        certificate_states.append(_classified_ems_certificate_state(certificate["status"]))
        connection_states.append(_classified_ems_connection_state(connection["ems_status"]))

    connection_state = _aggregate_state(connection_states)
    certificate_state = _aggregate_state(certificate_states)
    if not results:
        risk_signal = "not_applicable"
    elif "negative" in {connection_state, certificate_state} or "mixed" in {
        connection_state,
        certificate_state,
    }:
        risk_signal = "warning"
    elif "unknown" in {connection_state, certificate_state}:
        risk_signal = "unknown"
    else:
        risk_signal = "none_observed"

    posture: dict[str, object] = {
        "contract": "fortipam_ems_connection_posture_v1",
        "connector_inventory_state": "none" if not results else "present",
        "connector_count_band": _collection_count_band(len(results)),
        "connection_evidence_completeness": "complete",
        "aggregate_connection_state": connection_state,
        "aggregate_certificate_state": certificate_state,
        "risk_signal": risk_signal,
        "ztna_tag_assignment_assessed": False,
        "proxy_policy_assessed": False,
        "endpoint_posture_assessed": False,
        "secret_launch_assessed": False,
        "response_body_returned": False,
        "connector_name_values_returned": False,
        "network_values_returned": False,
        "port_values_returned": False,
        "certificate_values_returned": False,
        "tag_values_returned": False,
        "endpoint_values_returned": False,
        "raw_status_values_returned": False,
        "raw_field_values_returned": False,
    }
    validate_ems_connection_posture(posture)
    return posture


def _classified_ems_certificate_state(value: str) -> str:
    if value in _EMS_CERTIFICATE_POSITIVE_STATES:
        return "positive"
    if value in _EMS_CERTIFICATE_NEGATIVE_STATES:
        return "negative"
    return "unknown"


def _classified_ems_connection_state(value: str) -> str:
    if value in _EMS_CONNECTION_POSITIVE_STATES:
        return "positive"
    if value in _EMS_CONNECTION_NEGATIVE_STATES:
        return "negative"
    return "unknown"


def validate_ems_connection_posture(posture: object) -> None:
    """Reject schema drift and internally contradictory EMS projections."""

    if not isinstance(posture, Mapping) or set(posture) != _EMS_POSTURE_FIELDS:
        raise PostureContractError("EMS posture schema is not accepted.")
    inventory_state = posture.get("connector_inventory_state")
    count_band = posture.get("connector_count_band")
    connection_state = posture.get("aggregate_connection_state")
    certificate_state = posture.get("aggregate_certificate_state")
    risk_signal = posture.get("risk_signal")
    allowed_states = {"not_configured", "positive", "negative", "mixed", "unknown"}
    if (
        posture.get("contract") != "fortipam_ems_connection_posture_v1"
        or inventory_state not in {"none", "present"}
        or count_band not in {"none", "single", "multiple"}
        or posture.get("connection_evidence_completeness") != "complete"
        or connection_state not in allowed_states
        or certificate_state not in allowed_states
        or risk_signal not in {"warning", "none_observed", "unknown", "not_applicable"}
        or any(posture.get(flag) is not False for flag in _EMS_POSTURE_FALSE_FLAGS)
    ):
        raise PostureContractError("EMS posture contract is invalid.")
    empty = inventory_state == "none"
    if (
        empty != (count_band == "none")
        or empty != (connection_state == "not_configured")
        or empty != (certificate_state == "not_configured")
        or empty != (risk_signal == "not_applicable")
    ):
        raise PostureContractError("EMS posture state is contradictory.")
    if empty:
        return
    expected_risk = _ems_risk_signal(
        str(connection_state),
        str(certificate_state),
    )
    if risk_signal != expected_risk:
        raise PostureContractError("EMS posture risk is contradictory.")


def _ems_risk_signal(connection_state: str, certificate_state: str) -> str:
    states = {connection_state, certificate_state}
    if "negative" in states or "mixed" in states:
        return "warning"
    if "unknown" in states:
        return "unknown"
    return "none_observed"


def _aggregate_state(states: list[str]) -> str:
    if not states:
        return "not_configured"
    unique = set(states)
    if unique == {"positive"}:
        return "positive"
    if unique == {"negative"}:
        return "negative"
    if "unknown" in unique:
        return "unknown"
    return "mixed"


def _collection_count_band(count: int) -> str:
    if count == 0:
        return "none"
    if count == 1:
        return "single"
    return "multiple"


def _enabled(value: object) -> bool | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().lower()
    if normalized in {"enable", "enabled", "on", "yes"}:
        return True
    if normalized in {"disable", "disabled", "off", "no"}:
        return False
    return None


def _configured(value: object) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        normalized = value.strip().lower()
        return normalized not in {"", "0.0.0.0", "::", "none"}
    return bool(value)


def _mapping(value: object) -> Mapping[object, object]:
    return value if isinstance(value, Mapping) else {}


def _list_count(value: object) -> int:
    return len(value) if isinstance(value, list) else 0


def _ha_topology_mode(value: object) -> str:
    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip().lower().replace("_", "-")
    if normalized in {"standalone", "stand-alone"}:
        return "standalone"
    if normalized in {"a-p", "active-passive"}:
        return "active_passive"
    if normalized in {"a-a", "active-active"}:
        return "active_active"
    return "unknown"


def _ha_enabled(topology_mode: str) -> bool | None:
    if topology_mode == "standalone":
        return False
    if topology_mode in {"active_passive", "active_active"}:
        return True
    return None


def _boolean(value: object) -> bool | None:
    return value if isinstance(value, bool) else None


def _status_class(value: object) -> str:
    if not isinstance(value, str):
        return "unknown"
    normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in {
        "active",
        "available",
        "connected",
        "enabled",
        "entitled",
        "healthy",
        "licensed",
        "registered",
        "supported",
        "valid",
    }:
        return "healthy"
    if normalized in {"expiring", "grace", "warning"}:
        return "warning"
    if normalized in {
        "disconnected",
        "disabled",
        "expired",
        "invalid",
        "unlicensed",
        "unregistered",
        "unsupported",
    }:
        return "critical"
    return "unknown"


def _expiry_band(value: object, now_epoch: int) -> str:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return "unknown"
    remaining = value - now_epoch
    if remaining < 0:
        return "expired"
    if remaining <= 30 * 86_400:
        return "within_30_days"
    if remaining <= 90 * 86_400:
        return "within_90_days"
    return "beyond_90_days"


def _capacity_state(enabled: object, licensed: object) -> str:
    if (
        not isinstance(enabled, int)
        or isinstance(enabled, bool)
        or not isinstance(licensed, int)
        or isinstance(licensed, bool)
        or enabled < 0
        or licensed <= 0
    ):
        return "unknown"
    if enabled > licensed:
        return "over_capacity"
    if enabled == licensed:
        return "at_capacity"
    if enabled / licensed >= 0.8:
        return "near_capacity"
    return "available"


def _integer_capacity(value: object) -> int | None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return None
    return value


def _positive_capacity(value: object) -> bool | None:
    capacity = _integer_capacity(value)
    return None if capacity is None else capacity > 0


def _capacity_usage_band(total: object, used: object) -> str:
    total_capacity = _integer_capacity(total)
    used_capacity = _integer_capacity(used)
    if total_capacity is None or used_capacity is None or total_capacity <= 0:
        return "unknown"
    if used_capacity == 0:
        return "empty"
    ratio = used_capacity / total_capacity
    if ratio < 0.5:
        return "low"
    if ratio < 0.75:
        return "moderate"
    if ratio < 0.9:
        return "high"
    if ratio <= 1:
        return "critical"
    return "over_capacity"


def _history_state(oldest_present: bool, newest_present: bool) -> str:
    if oldest_present and newest_present:
        return "present"
    if not oldest_present and not newest_present:
        return "empty"
    return "partial"


def _component_risk_signal(name: str, result: Mapping[object, object]) -> str:
    if name in {"system_status", "system_global", "approval_profile"}:
        return "not_assessed"
    posture = _mapping(result.get("posture"))
    if name == "fortianalyzer_delivery":
        return _fortianalyzer_risk_signal(posture)
    if name == "license_support":
        return _license_risk_signal(posture)
    if name == "ha_configuration":
        return _ha_risk_signal(posture)
    if name == "recording_storage":
        return _storage_risk_signal(posture)
    return "unknown"


def _fortianalyzer_risk_signal(posture: Mapping[object, object]) -> str:
    enabled = posture.get("enabled")
    if enabled is False:
        return "not_enabled"
    if enabled is not True:
        return "unknown"
    controls = (
        posture.get("reliable_transport_enabled"),
        posture.get("certificate_verification_enabled"),
    )
    if False in controls:
        return "warning"
    if all(control is True for control in controls):
        return "none_observed"
    return "unknown"


def _license_risk_signal(posture: Mapping[object, object]) -> str:
    states = {
        posture.get("subscription_state"),
        posture.get("forticare_state"),
        posture.get("support_state"),
        posture.get("vm_license_state"),
    }
    expiry_bands = {
        posture.get("subscription_expiry_band"),
        posture.get("support_expiry_band"),
    }
    capacity = posture.get("user_capacity_state")
    if "critical" in states or "expired" in expiry_bands or capacity == "over_capacity":
        return "critical"
    if (
        "warning" in states
        or "within_30_days" in expiry_bands
        or capacity in {"near_capacity", "at_capacity"}
    ):
        return "warning"
    if "healthy" in states or capacity == "available":
        return "none_observed"
    return "unknown"


def _ha_risk_signal(posture: Mapping[object, object]) -> str:
    enabled = posture.get("ha_enabled")
    if enabled is False:
        return "not_applicable"
    if enabled is not True:
        return "unknown"
    controls = (
        posture.get("heartbeat_authentication_enabled"),
        posture.get("heartbeat_encryption_enabled"),
    )
    if False in controls:
        return "warning"
    if all(control is True for control in controls):
        return "none_observed"
    return "unknown"


def _storage_risk_signal(posture: Mapping[object, object]) -> str:
    bands = {
        posture.get("video_usage_band"),
        posture.get("log_usage_band"),
    }
    if bands & {"critical", "over_capacity"}:
        return "critical"
    if "high" in bands:
        return "warning"
    if bands & {"empty", "low", "moderate"}:
        return "none_observed"
    return "unknown"
