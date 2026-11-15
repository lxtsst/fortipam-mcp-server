"""Fail-closed FortiPAM 1.9.1 HA reconciliation assessment.

The projector consumes only the already-minimized fixed API and CLI evidence
contracts. It returns categorical readiness and never returns member identity,
network, interface, checksum, configuration, log, recording, or credential
values. Runtime collection and protected expected-topology binding remain
outside this module.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from typing import Final

from .config import HA_CONFIGURATION_PATH


V4_HA_RECONCILIATION_CONTRACT: Final = (
    "fortipam_v4_ha_reconciliation_assessment_v1"
)
HA_RECONCILIATION_STATUSES: Final = frozenset(
    {
        "contradictory",
        "degraded",
        "out_of_sync",
        "not_assessed",
        "eligible_for_operator_review",
    }
)
HA_RECONCILIATION_PREREQUISITES_ENV: Final = (
    "FORTIPAM_MCP_HA_RECONCILIATION_PREREQUISITES_FILE"
)
HA_RECONCILIATION_QUERY_PERMISSION_ENV: Final = (
    "FORTIPAM_MCP_HA_RECONCILIATION_QUERY_PERMISSION_FILE"
)
HA_RECONCILIATION_FEATURE_ENV: Final = (
    "FORTIPAM_MCP_V4_HA_RECONCILIATION_ENABLED"
)
_MAX_PREREQUISITE_FILE_BYTES: Final = 4096

_MODES: Final = frozenset({"standalone", "active_passive", "active_active", "unknown"})
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
_CLI_TOP_LEVEL_KEYS: Final = frozenset(
    {
        "workflow_id",
        "execution_status",
        "evidence",
        "raw_cli_returned",
        "credential_values_returned",
    }
)
_CLI_CONFIG_KEYS: Final = frozenset(
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
_CLI_STATUS_KEYS: Final = frozenset(
    {
        "evidence_status",
        "ha_mode",
        "ha_health",
        "member_count_band",
        "configuration_sync",
        "peer_identity_returned",
        "network_values_returned",
        "exact_time_returned",
        "raw_cli_returned",
    }
)
_CLI_CHECKSUM_STANDALONE_KEYS: Final = frozenset(
    {
        "evidence_status",
        "ha_mode",
        "checksum_assessment",
        "member_count_band",
        "exact_checksum_returned",
        "member_identity_returned",
        "table_name_returned",
        "raw_cli_returned",
    }
)
_CLI_CHECKSUM_CLUSTER_KEYS: Final = frozenset(
    {
        "evidence_status",
        "member_count_band",
        "global_agreement",
        "root_agreement",
        "overall_agreement",
        "mismatch_scope_count_band",
        "exact_checksum_returned",
        "member_identity_returned",
        "table_name_returned",
        "raw_cli_returned",
        "ha_mode",
        "checksum_assessment",
        "detail_evidence",
    }
)
_ATTESTATION_FIELDS: Final = (
    "expected_member_inventory_verified",
    "expected_roles_verified",
    "compatibility_verified",
    "heartbeat_health_verified",
    "maintenance_failover_reviewed",
    "local_evidence_accounted_for",
)
_QUERY_PERMISSION_FIELDS: Final = (
    "api_configuration_read_verified",
    "cli_configuration_read_verified",
    "cli_status_read_verified",
    "cli_checksum_read_verified",
    "dedicated_identity_verified",
    "cross_domain_denial_verified",
)

EvidenceCollector = Callable[[], Awaitable[Mapping[str, object]]]
PrerequisiteProvider = Callable[[], "HaReconciliationPrerequisites"]
QueryPermissionProvider = Callable[[], "HaReconciliationQueryPermission"]


class HaReconciliationError(ValueError):
    """Raised when minimized evidence does not match its exact contract."""


@dataclass(frozen=True, slots=True)
class HaReconciliationPrerequisites:
    """Trusted categorical evidence supplied by internal host composition."""

    expected_member_inventory_verified: bool
    expected_roles_verified: bool
    compatibility_verified: bool
    heartbeat_health_verified: bool
    maintenance_failover_reviewed: bool
    local_evidence_accounted_for: bool

    def __post_init__(self) -> None:
        if any(
            type(getattr(self, field)) is not bool for field in _ATTESTATION_FIELDS
        ):
            raise HaReconciliationError(
                "HA reconciliation prerequisites must be boolean."
            )

    def as_kwargs(self) -> dict[str, bool]:
        """Return only the six fixed boolean fields."""

        return {field: getattr(self, field) for field in _ATTESTATION_FIELDS}


@dataclass(frozen=True, slots=True)
class HaReconciliationQueryPermission:
    """Value-free proof categories required before runtime collection."""

    api_configuration_read_verified: bool
    cli_configuration_read_verified: bool
    cli_status_read_verified: bool
    cli_checksum_read_verified: bool
    dedicated_identity_verified: bool
    cross_domain_denial_verified: bool

    def __post_init__(self) -> None:
        if any(
            type(getattr(self, field)) is not bool
            for field in _QUERY_PERMISSION_FIELDS
        ):
            raise HaReconciliationError(
                "HA reconciliation query permission must be boolean."
            )

    @property
    def verified(self) -> bool:
        """Require every fixed permission category."""

        return all(getattr(self, field) for field in _QUERY_PERMISSION_FIELDS)


class BoundHaReconciliation:
    """Compose four fixed collectors with one trusted prerequisite provider."""

    def __init__(
        self,
        *,
        api_configuration_collector: EvidenceCollector,
        cli_configuration_collector: EvidenceCollector,
        cli_status_collector: EvidenceCollector,
        cli_checksum_collector: EvidenceCollector,
        prerequisite_provider: PrerequisiteProvider,
    ) -> None:
        values = (
            api_configuration_collector,
            cli_configuration_collector,
            cli_status_collector,
            cli_checksum_collector,
            prerequisite_provider,
        )
        if any(not callable(value) for value in values):
            raise HaReconciliationError(
                "HA reconciliation host composition is incomplete."
            )
        self._api_configuration_collector = api_configuration_collector
        self._cli_configuration_collector = cli_configuration_collector
        self._cli_status_collector = cli_status_collector
        self._cli_checksum_collector = cli_checksum_collector
        self._prerequisite_provider = prerequisite_provider

    async def assess(self) -> dict[str, object]:
        """Collect all fixed evidence once and return the strict projection."""

        try:
            prerequisites = self._prerequisite_provider()
            if not isinstance(prerequisites, HaReconciliationPrerequisites):
                raise HaReconciliationError(
                    "HA reconciliation prerequisite provider is invalid."
                )
            api, configuration, status, checksum = await asyncio.gather(
                self._api_configuration_collector(),
                self._cli_configuration_collector(),
                self._cli_status_collector(),
                self._cli_checksum_collector(),
            )
            return assess_ha_reconciliation(
                api,
                configuration,
                status,
                checksum,
                **prerequisites.as_kwargs(),
            )
        except asyncio.CancelledError:
            raise
        except HaReconciliationError:
            raise
        except Exception:
            raise HaReconciliationError(
                "HA reconciliation evidence collection failed."
            ) from None


class HaReconciliationRuntimeBinding:
    """Gate a bound composition on fixed dedicated query-permission proof."""

    def __init__(
        self,
        composition: BoundHaReconciliation,
        query_permission_provider: QueryPermissionProvider,
    ) -> None:
        if not isinstance(composition, BoundHaReconciliation) or not callable(
            query_permission_provider
        ):
            raise HaReconciliationError(
                "HA reconciliation runtime binding is unavailable."
            )
        self._composition = composition
        self._query_permission_provider = query_permission_provider

    async def assess(self) -> dict[str, object]:
        """Verify permission before any fixed evidence collector can run."""

        try:
            permission = self._query_permission_provider()
            if (
                not isinstance(permission, HaReconciliationQueryPermission)
                or not permission.verified
            ):
                raise HaReconciliationError(
                    "HA reconciliation query permission is unavailable."
                )
        except HaReconciliationError:
            raise
        except Exception:
            raise HaReconciliationError(
                "HA reconciliation query permission is unavailable."
            ) from None
        return await self._composition.assess()


class OwnerOnlyHaReconciliationPrerequisiteProvider:
    """Read a value-free prerequisite record from one owner-only local file."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path) or not path.is_absolute():
            raise HaReconciliationError(
                "HA reconciliation prerequisites are unavailable."
            )
        self._path = path

    def __call__(self) -> HaReconciliationPrerequisites:
        try:
            payload = _read_owner_only_prerequisite_file(self._path)
            parsed = json.loads(payload)
            if not isinstance(parsed, dict) or set(parsed) != {
                "schema_version",
                "target_version",
                *_ATTESTATION_FIELDS,
            }:
                raise ValueError
            if (
                parsed["schema_version"] != "1"
                or parsed["target_version"] != "1.9.1"
            ):
                raise ValueError
            return HaReconciliationPrerequisites(
                **{field: parsed[field] for field in _ATTESTATION_FIELDS}
            )
        except (
            HaReconciliationError,
            KeyError,
            OSError,
            TypeError,
            UnicodeError,
            ValueError,
            json.JSONDecodeError,
        ):
            raise HaReconciliationError(
                "HA reconciliation prerequisites are unavailable."
            ) from None


class OwnerOnlyHaReconciliationQueryPermissionProvider:
    """Read exact value-free query-permission categories owner-only."""

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path) or not path.is_absolute():
            raise HaReconciliationError(
                "HA reconciliation query permission is unavailable."
            )
        self._path = path

    def __call__(self) -> HaReconciliationQueryPermission:
        try:
            payload = _read_owner_only_prerequisite_file(self._path)
            parsed = json.loads(payload)
            if not isinstance(parsed, dict) or set(parsed) != {
                "schema_version",
                "target_version",
                *_QUERY_PERMISSION_FIELDS,
            }:
                raise ValueError
            if (
                parsed["schema_version"] != "1"
                or parsed["target_version"] != "1.9.1"
            ):
                raise ValueError
            return HaReconciliationQueryPermission(
                **{field: parsed[field] for field in _QUERY_PERMISSION_FIELDS}
            )
        except (
            HaReconciliationError,
            KeyError,
            OSError,
            TypeError,
            UnicodeError,
            ValueError,
            json.JSONDecodeError,
        ):
            raise HaReconciliationError(
                "HA reconciliation query permission is unavailable."
            ) from None


def prerequisite_provider_from_environment(
    environment: Mapping[str, str],
) -> OwnerOnlyHaReconciliationPrerequisiteProvider | None:
    """Load the optional value-free provider path without reading its record."""

    value = environment.get(HA_RECONCILIATION_PREREQUISITES_ENV)
    if value is None or not value.strip():
        return None
    path = Path(value.strip())
    if not path.is_absolute():
        raise HaReconciliationError(
            "HA reconciliation prerequisites are unavailable."
        )
    return OwnerOnlyHaReconciliationPrerequisiteProvider(path)


def query_permission_provider_from_environment(
    environment: Mapping[str, str],
) -> OwnerOnlyHaReconciliationQueryPermissionProvider | None:
    """Select the optional query-permission provider without reading it."""

    value = environment.get(HA_RECONCILIATION_QUERY_PERMISSION_ENV)
    if value is None or not value.strip():
        return None
    path = Path(value.strip())
    if not path.is_absolute():
        raise HaReconciliationError(
            "HA reconciliation query permission is unavailable."
        )
    return OwnerOnlyHaReconciliationQueryPermissionProvider(path)


def load_ha_reconciliation_feature(environment: Mapping[str, str]) -> bool:
    """Load the exact runtime opt-in, defaulting to disabled."""

    value = environment.get(HA_RECONCILIATION_FEATURE_ENV)
    if value is None or value == "false":
        return False
    if value == "true":
        return True
    raise HaReconciliationError(
        f"{HA_RECONCILIATION_FEATURE_ENV} must be exactly true or false."
    )


def runtime_binding_from_environment(
    environment: Mapping[str, str],
    composition: BoundHaReconciliation,
) -> HaReconciliationRuntimeBinding | None:
    """Bind only an explicitly enabled composition with permission proof."""

    if not load_ha_reconciliation_feature(environment):
        return None
    provider = query_permission_provider_from_environment(environment)
    if provider is None:
        raise HaReconciliationError(
            "HA reconciliation query permission is unavailable."
        )
    return HaReconciliationRuntimeBinding(composition, provider)


def _read_owner_only_prerequisite_file(path: Path) -> str:
    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current /= component
        info = os.lstat(current)
        if stat.S_ISLNK(info.st_mode):
            raise HaReconciliationError(
                "HA reconciliation prerequisites are unavailable."
            )
    parent_info = os.lstat(path.parent)
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or parent_info.st_uid != os.getuid()
        or stat.S_IMODE(parent_info.st_mode) != 0o700
    ):
        raise HaReconciliationError(
            "HA reconciliation prerequisites are unavailable."
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > _MAX_PREREQUISITE_FILE_BYTES
        ):
            raise HaReconciliationError(
                "HA reconciliation prerequisites are unavailable."
            )
        payload = os.read(descriptor, _MAX_PREREQUISITE_FILE_BYTES + 1)
        if len(payload) > _MAX_PREREQUISITE_FILE_BYTES:
            raise HaReconciliationError(
                "HA reconciliation prerequisites are unavailable."
            )
        return payload.decode("utf-8", errors="strict")
    finally:
        os.close(descriptor)


def assess_ha_reconciliation(
    api_configuration: Mapping[str, object],
    cli_configuration: Mapping[str, object],
    cli_status: Mapping[str, object],
    cli_checksum: Mapping[str, object],
    *,
    expected_member_inventory_verified: bool,
    expected_roles_verified: bool,
    compatibility_verified: bool,
    heartbeat_health_verified: bool,
    maintenance_failover_reviewed: bool,
    local_evidence_accounted_for: bool,
) -> dict[str, object]:
    """Assess four minimized evidence records without repair or disclosure."""

    api = _validate_api(api_configuration)
    configuration = _validate_cli_configuration(cli_configuration)
    status = _validate_cli_status(cli_status)
    checksum = _validate_cli_checksum(cli_checksum)
    attestations = {
        "expected_member_inventory_verified": expected_member_inventory_verified,
        "expected_roles_verified": expected_roles_verified,
        "compatibility_verified": compatibility_verified,
        "heartbeat_health_verified": heartbeat_health_verified,
        "maintenance_failover_reviewed": maintenance_failover_reviewed,
        "local_evidence_accounted_for": local_evidence_accounted_for,
    }
    if any(type(value) is not bool for value in attestations.values()):
        raise HaReconciliationError("HA reconciliation attestations must be boolean.")

    modes = {
        api["topology_mode"],
        configuration["ha_mode"],
        status["ha_mode"],
        checksum["ha_mode"],
    }
    expected_enabled = api["topology_mode"] != "standalone"
    if (
        "unknown" not in modes
        and (len(modes) != 1 or api["ha_enabled"] is not expected_enabled)
    ):
        assessment = "contradictory"
    elif (
        "unknown" in modes
        or configuration["evidence_status"] != "complete"
        or status["evidence_status"] != "complete"
        or checksum["evidence_status"] != "complete"
        or api["topology_mode"] == "active_active"
    ):
        assessment = "not_assessed"
    elif status["ha_health"] != "healthy":
        assessment = "degraded"
    elif _out_of_sync(status, checksum):
        assessment = "out_of_sync"
    elif not _topology_shape_is_consistent(api["topology_mode"], status, checksum):
        assessment = "contradictory"
    elif all(attestations.values()):
        assessment = "eligible_for_operator_review"
    else:
        assessment = "not_assessed"

    missing = [name for name in _ATTESTATION_FIELDS if not attestations[name]]
    return {
        "contract": V4_HA_RECONCILIATION_CONTRACT,
        "action_family": "ha.reconcile",
        "target_version": "1.9.1",
        "assessment_status": assessment,
        "evidence_origin": "fixed_minimized_api_cli_plus_categorical_attestations",
        "evidence_source_count": 4,
        "missing_requirements": missing,
        "operator_review_ready": assessment == "eligible_for_operator_review",
        "automatic_repair_enabled": False,
        "synchronization_dispatched": False,
        "failover_dispatched": False,
        "configuration_written": False,
        "execution_authorized": False,
        "raw_source_content_returned": False,
        "member_identity_returned": False,
        "network_values_returned": False,
        "checksum_values_returned": False,
    }


def _validate_api(result: Mapping[str, object]) -> Mapping[str, object]:
    if not isinstance(result, Mapping) or set(result) != _API_TOP_LEVEL_KEYS:
        raise HaReconciliationError("HA API evidence schema is not accepted.")
    content_type = result["content_type"]
    if (
        result["scenario"] != "ha_sync"
        or result["operation"] != "GET"
        or result["path"] != HA_CONFIGURATION_PATH
        or result["sensitivity"] != "ha_configuration_posture"
        or type(result["status_code"]) is not int
        or result["status_code"] != 200
        or type(content_type) is not str
        or content_type.split(";", maxsplit=1)[0].strip().lower()
        != "application/json"
        or result["response_body_returned"] is not False
    ):
        raise HaReconciliationError("HA API evidence contract is not accepted.")
    posture = result["posture"]
    if not isinstance(posture, Mapping) or set(posture) != _API_POSTURE_KEYS:
        raise HaReconciliationError("HA API posture schema is not accepted.")
    if (
        posture["contract"] != "fortipam_ha_configuration_posture_v1"
        or posture["topology_mode"] not in _MODES
        or type(posture["ha_enabled"]) not in {bool, type(None)}
        or posture["synchronization_state"] != "not_observed"
        or any(
            type(posture[key]) not in {bool, type(None)}
            for key in _API_OPTIONAL_BOOLEAN_KEYS
        )
        or any(type(posture[key]) is not bool for key in _API_BOOLEAN_KEYS)
        or any(
            type(posture[key]) is not int or posture[key] < 0
            for key in _API_COUNT_KEYS
        )
        or any(posture[key] is not False for key in _API_FALSE_FLAGS)
    ):
        raise HaReconciliationError("HA API posture contract is not accepted.")
    return posture


def _validate_cli_configuration(result: Mapping[str, object]) -> Mapping[str, object]:
    evidence = _cli_evidence(result, "ha_configuration", _CLI_CONFIG_KEYS)
    if (
        evidence["evidence_status"] not in {"complete", "partial"}
        or evidence["ha_mode"] not in _MODES
        or evidence["session_pickup"] not in {"enabled", "disabled", "unknown"}
        or evidence["override_state"] not in {"enabled", "disabled", "unknown"}
        or evidence["configuration_security"]
        not in {"enabled", "disabled", "mixed", "unknown"}
        or any(
            evidence[key] is not False
            for key in (
                "identity_values_returned",
                "network_values_returned",
                "group_name_returned",
                "password_values_returned",
                "priority_values_returned",
                "exact_checksum_returned",
                "raw_cli_returned",
            )
        )
    ):
        raise HaReconciliationError("HA CLI configuration contract is not accepted.")
    return evidence


def _validate_cli_status(result: Mapping[str, object]) -> Mapping[str, object]:
    evidence = _cli_evidence(result, "ha_status", _CLI_STATUS_KEYS)
    if (
        evidence["evidence_status"] not in {"complete", "partial"}
        or evidence["ha_mode"] not in _MODES
        or evidence["ha_health"] not in {"healthy", "degraded", "unknown"}
        or evidence["member_count_band"] not in {"single", "multiple", "unknown"}
        or evidence["configuration_sync"]
        not in {"synchronized", "out_of_sync", "not_applicable", "unknown"}
        or any(
            evidence[key] is not False
            for key in (
                "peer_identity_returned",
                "network_values_returned",
                "exact_time_returned",
                "raw_cli_returned",
            )
        )
    ):
        raise HaReconciliationError("HA CLI status contract is not accepted.")
    return evidence


def _validate_cli_checksum(result: Mapping[str, object]) -> Mapping[str, object]:
    evidence = _cli_evidence(result, "ha_checksum", None)
    keys = set(evidence)
    if keys == _CLI_CHECKSUM_STANDALONE_KEYS:
        valid = (
            evidence["evidence_status"] == "complete"
            and evidence["ha_mode"] == "standalone"
            and evidence["checksum_assessment"] == "not_applicable"
            and evidence["member_count_band"] == "single"
        )
    elif keys == _CLI_CHECKSUM_CLUSTER_KEYS:
        valid = (
            evidence["evidence_status"] == "complete"
            and evidence["ha_mode"] in {"active_passive", "active_active"}
            and evidence["member_count_band"] == "multiple"
            and evidence["checksum_assessment"] in {"synchronized", "out_of_sync"}
            and all(
                evidence[key] in {"matched", "mismatched"}
                for key in ("global_agreement", "root_agreement", "overall_agreement")
            )
            and evidence["mismatch_scope_count_band"]
            in {"zero", "one", "two_to_five"}
            and evidence["detail_evidence"] in {"not_required", "collected"}
        )
    else:
        raise HaReconciliationError("HA CLI checksum schema is not accepted.")
    if not valid or any(
        evidence[key] is not False
        for key in (
            "exact_checksum_returned",
            "member_identity_returned",
            "table_name_returned",
            "raw_cli_returned",
        )
    ):
        raise HaReconciliationError("HA CLI checksum contract is not accepted.")
    return evidence


def _cli_evidence(
    result: Mapping[str, object],
    workflow_id: str,
    evidence_keys: frozenset[str] | None,
) -> Mapping[str, object]:
    if not isinstance(result, Mapping) or set(result) != _CLI_TOP_LEVEL_KEYS:
        raise HaReconciliationError("HA CLI evidence schema is not accepted.")
    if (
        result["workflow_id"] != workflow_id
        or result["execution_status"] != "completed"
        or result["raw_cli_returned"] is not False
        or result["credential_values_returned"] is not False
    ):
        raise HaReconciliationError("HA CLI evidence contract is not accepted.")
    evidence = result["evidence"]
    if not isinstance(evidence, Mapping) or (
        evidence_keys is not None and set(evidence) != evidence_keys
    ):
        raise HaReconciliationError("HA CLI evidence schema is not accepted.")
    return evidence


def _out_of_sync(
    status: Mapping[str, object], checksum: Mapping[str, object]
) -> bool:
    return (
        status["configuration_sync"] == "out_of_sync"
        or checksum["checksum_assessment"] == "out_of_sync"
        or any(
            checksum.get(key) == "mismatched"
            for key in ("global_agreement", "root_agreement", "overall_agreement")
        )
    )


def _topology_shape_is_consistent(
    mode: object,
    status: Mapping[str, object],
    checksum: Mapping[str, object],
) -> bool:
    if mode == "standalone":
        return (
            status["member_count_band"] == "single"
            and status["configuration_sync"] == "not_applicable"
            and checksum["member_count_band"] == "single"
            and checksum["checksum_assessment"] == "not_applicable"
        )
    if mode == "active_passive":
        return (
            status["member_count_band"] == "multiple"
            and status["configuration_sync"] == "synchronized"
            and checksum["member_count_band"] == "multiple"
            and checksum["checksum_assessment"] == "synchronized"
            and checksum.get("global_agreement") == "matched"
            and checksum.get("root_agreement") == "matched"
            and checksum.get("overall_agreement") == "matched"
            and checksum.get("mismatch_scope_count_band") == "zero"
            and checksum.get("detail_evidence") == "not_required"
        )
    return False


__all__ = [
    "BoundHaReconciliation",
    "HA_RECONCILIATION_FEATURE_ENV",
    "HA_RECONCILIATION_PREREQUISITES_ENV",
    "HA_RECONCILIATION_QUERY_PERMISSION_ENV",
    "HA_RECONCILIATION_STATUSES",
    "HaReconciliationError",
    "HaReconciliationPrerequisites",
    "HaReconciliationQueryPermission",
    "HaReconciliationRuntimeBinding",
    "OwnerOnlyHaReconciliationPrerequisiteProvider",
    "OwnerOnlyHaReconciliationQueryPermissionProvider",
    "V4_HA_RECONCILIATION_CONTRACT",
    "assess_ha_reconciliation",
    "prerequisite_provider_from_environment",
    "query_permission_provider_from_environment",
    "load_ha_reconciliation_feature",
    "runtime_binding_from_environment",
]
