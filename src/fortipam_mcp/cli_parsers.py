"""Strict, non-disclosing projections for fixed FortiPAM CLI evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import re


class CliParseError(ValueError):
    """Raised when CLI output is absent, contradictory, or outside the contract."""


_ANSI_ESCAPE = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_HEX_CHECKSUM = re.compile(r"^[0-9a-fA-F ]{32,95}$")
_MEMBER_HEADER = re.compile(r"^=+\s*([^=]+?)\s*=+$")
_PROMPT_LINE = re.compile(r"^[^\x00-\x1f]{1,126} [#$]$")
_CHECKSUM_CLUSTER_ECHO = "diagnose sys ha checksum cluster"
_CHECKSUM_DETAIL_ECHOES = frozenset(
    {
        "diagnose sys ha checksum show global",
        "diagnose sys ha checksum show root",
    }
)
_HA_CONFIGURATION_SETTINGS = frozenset(
    {
        "mode",
        "group-name",
        "password",
        "hbdev",
        "priority",
        "override",
        "session-pickup",
        "session-pickup-connectionless",
        "encryption",
        "authentication",
        "monitor",
        "ha-mgmt-status",
        "arps",
        "gratuitous-arps",
        "l2ep-eth-type",
        "l2ep-hb-interval",
        "key",
        "vcluster-id",
        "vcluster2",
        "link-failed-signal",
    }
)
_HA_STATUS_FIELDS = frozenset(
    {
        "ha health status",
        "model",
        "mode",
        "current ha mode",
        "group",
        "debug",
        "cluster uptime",
        "cluster state change time",
        "override",
        "system usage stats",
        "hbdev stats",
        "number of vcluster",
        "primary selected using",
        "master selected using",
        "configuration status",
        "primary",
        "secondary",
        "master",
        "slave",
    }
)
_HA_STATUS_EMPTY_SECTION_FIELDS = frozenset(
    {"configuration status", "system usage stats", "hbdev stats"}
)


def project_ha_configuration(output: bytes) -> dict[str, object]:
    """Project fixed ``show system ha`` output into non-disclosing classes."""

    settings = _ha_configuration_settings(output)
    mode_values = _values(settings, "mode")
    mode_classes = {_ha_mode(value) for value in mode_values}
    if len(mode_classes) > 1:
        raise CliParseError("HA configuration contains contradictory mode values")
    mode = next(iter(mode_classes), "unknown")

    session_pickup = _single_toggle_class(settings, "session-pickup")
    override_state = _single_toggle_class(settings, "override")
    security_state = _configuration_security_class(settings)
    return {
        "evidence_status": "complete"
        if mode != "unknown"
        and session_pickup != "unknown"
        and override_state != "unknown"
        else "partial",
        "ha_mode": mode,
        "session_pickup": session_pickup,
        "override_state": override_state,
        "configuration_security": security_state,
        "identity_values_returned": False,
        "network_values_returned": False,
        "group_name_returned": False,
        "password_values_returned": False,
        "priority_values_returned": False,
        "exact_checksum_returned": False,
        "raw_cli_returned": False,
    }


def project_ha_status(output: bytes) -> dict[str, object]:
    """Project HA state without identities, addresses, timestamps, or counters."""

    fields = _field_map(
        output,
        allowed_fields=_HA_STATUS_FIELDS,
        expected_command_echo="get system ha status",
        allow_configuration_members=True,
    )
    mode_values = _values(fields, "mode") or _values(fields, "current ha mode")
    if not mode_values:
        raise CliParseError("HA status lacks a mode field")
    mode_classes = {_ha_mode(value) for value in mode_values}
    if len(mode_classes) != 1:
        raise CliParseError("HA status contains contradictory mode values")
    mode = next(iter(mode_classes))

    health_values = _values(fields, "ha health status")
    health_classes = {_health_class(value) for value in health_values} if health_values else {"unknown"}
    if len(health_classes) != 1:
        raise CliParseError("HA status contains contradictory health values")

    configuration_values = _configuration_status_values(output)
    sync_classes = {_sync_class(value) for value in configuration_values}
    sync_state = _collapse_sync_classes(sync_classes, mode)
    member_count = _member_count_band(configuration_values, mode)

    return {
        "evidence_status": "complete" if health_values and (mode == "standalone" or configuration_values) else "partial",
        "ha_mode": mode,
        "ha_health": next(iter(health_classes)),
        "member_count_band": member_count,
        "configuration_sync": sync_state,
        "peer_identity_returned": False,
        "network_values_returned": False,
        "exact_time_returned": False,
        "raw_cli_returned": False,
    }


def project_ha_checksum_cluster(output: bytes) -> dict[str, object]:
    """Compare cluster checksum values in memory and return only agreement classes."""

    lines = _normalized_lines(output)
    members: dict[str, dict[str, str]] = {}
    current: str | None = None
    in_checksum = False
    for index, line in enumerate(lines):
        lowered = line.lower()
        if index == 0 and lowered == _CHECKSUM_CLUSTER_ECHO:
            continue
        if index == len(lines) - 1 and _PROMPT_LINE.fullmatch(line):
            continue
        header = _MEMBER_HEADER.match(line)
        if header:
            current = header.group(1).strip()
            if not current or current in members:
                raise CliParseError("checksum output contains invalid member sections")
            members[current] = {}
            in_checksum = False
            continue
        if current is None:
            raise CliParseError("checksum output contains an unknown line")
        if lowered == "checksum":
            if in_checksum:
                raise CliParseError("checksum output contains a duplicate section")
            in_checksum = True
            continue
        if not in_checksum or ":" not in line:
            raise CliParseError("checksum output contains an unknown line")
        key, value = (part.strip() for part in line.split(":", 1))
        key = key.lower()
        if key not in {"global", "root", "all"}:
            raise CliParseError("checksum output contains an unknown field")
        if not _HEX_CHECKSUM.fullmatch(value):
            raise CliParseError("checksum output contains an invalid checksum shape")
        normalized = "".join(value.lower().split())
        if key in members[current] and members[current][key] != normalized:
            raise CliParseError("checksum output contains contradictory values")
        members[current][key] = normalized

    if len(members) < 2:
        raise CliParseError("checksum output lacks multiple cluster members")
    if any(set(values) != {"global", "root", "all"} for values in members.values()):
        raise CliParseError("checksum output is incomplete")

    agreement = {
        scope: len({values[scope] for values in members.values()}) == 1
        for scope in ("global", "root", "all")
    }
    mismatch_count = sum(not value for value in agreement.values())
    return {
        "evidence_status": "complete",
        "member_count_band": "multiple",
        "global_agreement": "matched" if agreement["global"] else "mismatched",
        "root_agreement": "matched" if agreement["root"] else "mismatched",
        "overall_agreement": "matched" if agreement["all"] else "mismatched",
        "mismatch_scope_count_band": _count_band(mismatch_count),
        "exact_checksum_returned": False,
        "member_identity_returned": False,
        "table_name_returned": False,
        "raw_cli_returned": False,
    }


def project_checksum_detail_presence(output: bytes) -> dict[str, object]:
    """Confirm only that a bounded detailed checksum listing was available."""

    matching = 0
    lines = _normalized_lines(output)
    for index, line in enumerate(lines):
        lowered = line.lower()
        if index == 0 and lowered in _CHECKSUM_DETAIL_ECHOES:
            continue
        if index == len(lines) - 1 and _PROMPT_LINE.fullmatch(line):
            continue
        if ":" not in line:
            raise CliParseError("checksum detail output contains an unknown line")
        key, value = (part.strip() for part in line.rsplit(":", 1))
        if not key or not _HEX_CHECKSUM.fullmatch(value):
            raise CliParseError("checksum detail output contains an invalid record")
        matching += 1
    if matching == 0:
        raise CliParseError("checksum detail output lacks checksum records")
    return {
        "detail_evidence": "collected",
        "record_count_band": _count_band(matching),
        "exact_checksum_returned": False,
        "table_name_returned": False,
        "raw_cli_returned": False,
    }


def _ha_configuration_settings(output: bytes) -> dict[str, list[str]]:
    """Accept one flat, fixed ``config system ha`` stanza and no extensions."""

    lines = _normalized_lines(output)
    settings: dict[str, list[str]] = {}
    in_stanza = False
    ended = False
    for index, line in enumerate(lines):
        if index == 0 and line.lower() == "show system ha":
            continue
        if index == len(lines) - 1 and _PROMPT_LINE.fullmatch(line):
            continue
        lowered = line.lower()
        if lowered == "config system ha":
            if in_stanza or ended:
                raise CliParseError("HA configuration contains an invalid stanza")
            in_stanza = True
            continue
        if lowered == "end":
            if not in_stanza or ended:
                raise CliParseError("HA configuration contains an invalid terminator")
            ended = True
            continue
        if not in_stanza or ended:
            raise CliParseError("HA configuration contains an unknown line")
        setting = re.fullmatch(r"set ([a-z0-9-]+) (.+)", line, re.IGNORECASE)
        if setting is None:
            raise CliParseError("HA configuration contains an invalid setting")
        key, value = setting.groups()
        key = key.lower()
        if key not in _HA_CONFIGURATION_SETTINGS:
            raise CliParseError("HA configuration contains an unknown setting")
        settings.setdefault(key, []).append(value)
    if not in_stanza or not ended or not settings:
        raise CliParseError("HA configuration stanza is incomplete")
    return settings


def _single_toggle_class(settings: Mapping[str, Sequence[str]], key: str) -> str:
    values = _values(settings, key)
    if not values:
        return "unknown"
    classes = {_toggle_class(value) for value in values}
    if len(classes) != 1:
        raise CliParseError(f"HA configuration contains contradictory {key} values")
    return next(iter(classes))


def _configuration_security_class(settings: Mapping[str, Sequence[str]]) -> str:
    encryption = _single_toggle_class(settings, "encryption")
    authentication = _single_toggle_class(settings, "authentication")
    observed = {value for value in (encryption, authentication) if value != "unknown"}
    if not observed:
        return "unknown"
    if observed == {"enabled"}:
        return "enabled"
    if observed == {"disabled"}:
        return "disabled"
    return "mixed"


def _field_map(
    output: bytes,
    *,
    allowed_fields: frozenset[str],
    expected_command_echo: str,
    allow_configuration_members: bool = False,
) -> dict[str, list[str]]:
    fields: dict[str, list[str]] = {}
    in_configuration_section = False
    lines = _normalized_lines(output)
    for index, line in enumerate(lines):
        if index == 0 and line.lower() == expected_command_echo:
            continue
        if index == len(lines) - 1 and _PROMPT_LINE.fullmatch(line):
            continue
        if ":" not in line:
            raise CliParseError("CLI output contains an unknown line")
        key, value = (part.strip() for part in line.split(":", 1))
        normalized_key = " ".join(key.lower().replace("-", " ").split())
        if normalized_key == "configuration status":
            if normalized_key not in allowed_fields:
                raise CliParseError("CLI output contains an unknown field")
            in_configuration_section = True
            if not value:
                continue
        if (
            normalized_key in _HA_STATUS_EMPTY_SECTION_FIELDS
            and normalized_key in allowed_fields
            and not value
        ):
            continue
        if not normalized_key or not value:
            raise CliParseError("CLI output contains an invalid field")
        if normalized_key not in allowed_fields:
            if (
                allow_configuration_members
                and in_configuration_section
                and _sync_class(value) in {"synchronized", "out_of_sync"}
            ):
                continue
            raise CliParseError("CLI output contains an unknown field")
        fields.setdefault(normalized_key, []).append(value)
    if not fields:
        raise CliParseError("CLI output contains no recognized fields")
    return fields


def _normalized_lines(output: bytes) -> list[str]:
    if not output or b"\x00" in output:
        raise CliParseError("CLI output is absent or binary")
    cleaned = _ANSI_ESCAPE.sub(b"", output).replace(b"\r", b"")
    try:
        text = cleaned.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise CliParseError("CLI output is not valid UTF-8") from exc
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise CliParseError("CLI output is empty")
    return lines


def _values(fields: Mapping[str, Sequence[str]], key: str) -> list[str]:
    return list(fields.get(key, ()))


def _ha_mode(value: str) -> str:
    normalized = " ".join(value.lower().replace("_", "-").split())
    if "standalone" in normalized:
        return "standalone"
    if any(marker in normalized for marker in ("active-passive", "ha a-p", "a-p")):
        return "active_passive"
    if any(marker in normalized for marker in ("active-active", "ha a-a", "a-a")):
        return "active_active"
    return "unknown"


def _health_class(value: str) -> str:
    normalized = value.lower()
    if re.search(r"\b(ok|healthy|good)\b", normalized):
        return "healthy"
    if re.search(r"\b(warn|degraded|down|error|fail|critical)\b", normalized):
        return "degraded"
    return "unknown"


def _toggle_class(value: str) -> str:
    normalized = value.strip().lower()
    if normalized == "enable":
        return "enabled"
    if normalized == "disable":
        return "disabled"
    return "unknown"


def _configuration_status_values(output: bytes) -> list[str]:
    lines = _normalized_lines(output)
    values: list[str] = []
    in_section = False
    for line in lines:
        if line.lower().startswith("configuration status"):
            in_section = True
            continue
        if not in_section:
            continue
        lowered = line.lower()
        if "in-sync" in lowered or "out-of-sync" in lowered or "not synchronized" in lowered:
            values.append(line)
    return values


def _sync_class(value: str) -> str:
    normalized = value.lower()
    if "out-of-sync" in normalized or "not synchronized" in normalized:
        return "out_of_sync"
    if "in-sync" in normalized:
        return "synchronized"
    return "unknown"


def _collapse_sync_classes(classes: set[str], mode: str) -> str:
    if mode == "standalone":
        return "not_applicable"
    if not classes:
        return "unknown"
    if classes == {"synchronized"}:
        return "synchronized"
    if classes == {"out_of_sync"}:
        return "out_of_sync"
    if "synchronized" in classes and "out_of_sync" in classes:
        return "mixed"
    return "unknown"


def _member_count_band(values: Sequence[str], mode: str) -> str:
    if mode == "standalone":
        return "single"
    if not values:
        return "unknown"
    return "single" if len(values) == 1 else "multiple"


def _count_band(count: int) -> str:
    if count == 0:
        return "zero"
    if count == 1:
        return "one"
    if count <= 5:
        return "two_to_five"
    return "more_than_five"
