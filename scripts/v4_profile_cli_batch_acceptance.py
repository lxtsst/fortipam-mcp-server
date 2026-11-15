#!/usr/bin/env python3
"""Execute the confirmed bounded V4 Profile CLI batch without disclosures."""

from __future__ import annotations

import argparse
from dataclasses import fields, is_dataclass
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Mapping, Protocol

from fortipam_mcp.antivirus_profile_ssh_transport import (
    AntivirusProfileSshTransportConfig,
    FortiPamAntivirusProfileSshTransport,
)
from fortipam_mcp.rdp_event_filter_ssh_transport import (
    FortiPamRdpEventFilterSshTransport,
    RdpEventFilterSshTransportConfig,
)
from fortipam_mcp.ssh_filter_ssh_transport import (
    FortiPamSshFilterSshTransport,
    SshFilterSshTransportConfig,
)


_SOURCE_PREFIX = "FPA_HOME_LAB_FPA1_"
_BATCH = (
    ("antivirus_profile", "mcp-v4-av-profile-b20"),
    ("rdp_event_filter", "mcp-v4-rdp-event-filter-b20"),
    ("ssh_filter", "mcp-v4-ssh-filter-b20"),
)


class ProfileBatchAcceptanceError(RuntimeError):
    """Raised for a non-disclosing batch preflight or readback failure."""


class _ProfileTransport(Protocol):
    def inspect(self, profile_name: str) -> object: ...

    def create_and_readback(self, profile_name: str) -> object: ...

    def readback(self, profile_name: str) -> object: ...


def run_confirmed_profile_batch(
    source_environment: Mapping[str, str],
    known_hosts_file: Path,
) -> dict[str, object]:
    """Recheck and execute only the already-confirmed three-profile batch."""

    host = _source_value(source_environment, "SSH_IP")
    username = _source_value(source_environment, "USERNAME")
    password = _source_value(source_environment, "PASSWORD")
    port = _positive_int(_source_value(source_environment, "SSH_PORT"), "SSH port")
    with _private_known_hosts_copy(known_hosts_file) as private_known_hosts:
        transports: dict[str, _ProfileTransport] = {
            "antivirus_profile": FortiPamAntivirusProfileSshTransport(
                AntivirusProfileSshTransportConfig(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    known_hosts_file=private_known_hosts,
                    timeout_seconds=15,
                )
            ),
            "rdp_event_filter": FortiPamRdpEventFilterSshTransport(
                RdpEventFilterSshTransportConfig(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    known_hosts_file=private_known_hosts,
                    timeout_seconds=15,
                )
            ),
            "ssh_filter": FortiPamSshFilterSshTransport(
                SshFilterSshTransportConfig(
                    host=host,
                    port=port,
                    username=username,
                    password=password,
                    known_hosts_file=private_known_hosts,
                    timeout_seconds=15,
                )
            ),
        }
        return _execute_batch(transports)


def run_confirmed_profile_action(
    source_environment: Mapping[str, str],
    known_hosts_file: Path,
    action_kind: str,
) -> dict[str, object]:
    """Execute one independently human-confirmed Profile action exactly once."""

    host = _source_value(source_environment, "SSH_IP")
    username = _source_value(source_environment, "USERNAME")
    password = _source_value(source_environment, "PASSWORD")
    port = _positive_int(_source_value(source_environment, "SSH_PORT"), "SSH port")
    with _private_known_hosts_copy(known_hosts_file) as private_known_hosts:
        transports: dict[str, _ProfileTransport] = {
            "antivirus_profile": FortiPamAntivirusProfileSshTransport(
                AntivirusProfileSshTransportConfig(host, port, username, password, private_known_hosts, 15)
            ),
            "rdp_event_filter": FortiPamRdpEventFilterSshTransport(
                RdpEventFilterSshTransportConfig(host, port, username, password, private_known_hosts, 15)
            ),
            "ssh_filter": FortiPamSshFilterSshTransport(
                SshFilterSshTransportConfig(host, port, username, password, private_known_hosts, 15)
            ),
        }
        return _execute_one(transports, action_kind)


def inspect_confirmed_profile_batch(
    source_environment: Mapping[str, str],
    known_hosts_file: Path,
) -> dict[str, object]:
    """Return only the fixed three-object existence projection after a stop."""

    host = _source_value(source_environment, "SSH_IP")
    username = _source_value(source_environment, "USERNAME")
    password = _source_value(source_environment, "PASSWORD")
    port = _positive_int(_source_value(source_environment, "SSH_PORT"), "SSH port")
    with _private_known_hosts_copy(known_hosts_file) as private_known_hosts:
        transports: dict[str, _ProfileTransport] = {
            "antivirus_profile": FortiPamAntivirusProfileSshTransport(
                AntivirusProfileSshTransportConfig(host, port, username, password, private_known_hosts, 15)
            ),
            "rdp_event_filter": FortiPamRdpEventFilterSshTransport(
                RdpEventFilterSshTransportConfig(host, port, username, password, private_known_hosts, 15)
            ),
            "ssh_filter": FortiPamSshFilterSshTransport(
                SshFilterSshTransportConfig(host, port, username, password, private_known_hosts, 15)
            ),
        }
        projection: dict[str, object] = {
            "contract": "fortipam_v4_confirmed_profile_cli_batch_b20_inspection_v1",
            "credential_values_returned": False,
            "raw_cli_output_returned": False,
        }
        for kind, name in _BATCH:
            exists = getattr(transports[kind].inspect(name), "profile_name_exists", None)
            projection[f"{kind}_exists"] = exists is True
            if exists is not True:
                projection[f"{kind}_readback_verified"] = None
            else:
                readback = transports[kind].readback(name)
                projection[f"{kind}_readback_verified"] = (
                    getattr(readback, "verified", None) is True
                )
                if is_dataclass(readback):
                    for field in fields(readback):
                        value = getattr(readback, field.name)
                        if isinstance(value, bool):
                            projection[f"{kind}_{field.name}"] = value
        return projection


def _execute_batch(transports: Mapping[str, _ProfileTransport]) -> dict[str, object]:
    """Ensure a complete absent baseline before any of the three writes."""

    if set(transports) != {kind for kind, _ in _BATCH}:
        raise ProfileBatchAcceptanceError("Profile batch transport configuration is invalid.")
    for kind, name in _BATCH:
        if getattr(transports[kind].inspect(name), "profile_name_exists", None) is not False:
            raise ProfileBatchAcceptanceError("Profile batch current state has drifted.")
    verified: dict[str, bool] = {}
    for kind, name in _BATCH:
        if getattr(transports[kind].inspect(name), "profile_name_exists", None) is not False:
            raise ProfileBatchAcceptanceError("Profile batch pre-write state has drifted.")
        readback = transports[kind].create_and_readback(name)
        if getattr(readback, "verified", None) is not True:
            raise ProfileBatchAcceptanceError("Profile batch readback was not verified.")
        verified[kind] = True
    return {
        "contract": "fortipam_v4_confirmed_profile_cli_batch_b20_v1",
        "preflight_absent": True,
        "antivirus_profile_verified": verified["antivirus_profile"],
        "rdp_event_filter_verified": verified["rdp_event_filter"],
        "ssh_filter_verified": verified["ssh_filter"],
        "credential_values_returned": False,
        "raw_cli_output_returned": False,
    }


def _execute_one(transports: Mapping[str, _ProfileTransport], action_kind: str) -> dict[str, object]:
    names = dict(_BATCH)
    if action_kind not in names or set(transports) != set(names):
        raise ProfileBatchAcceptanceError("Profile action configuration is invalid.")
    transport = transports[action_kind]
    profile_name = names[action_kind]
    if getattr(transport.inspect(profile_name), "profile_name_exists", None) is not False:
        raise ProfileBatchAcceptanceError("Profile action current state has drifted.")
    if getattr(transport.inspect(profile_name), "profile_name_exists", None) is not False:
        raise ProfileBatchAcceptanceError("Profile action pre-write state has drifted.")
    if getattr(transport.create_and_readback(profile_name), "verified", None) is not True:
        raise ProfileBatchAcceptanceError("Profile action readback was not verified.")
    return {
        "contract": "fortipam_v4_confirmed_profile_cli_action_b20_v1",
        "action_kind": action_kind,
        "preflight_absent": True,
        "readback_verified": True,
        "credential_values_returned": False,
        "raw_cli_output_returned": False,
    }


def _source_value(environment: Mapping[str, str], suffix: str) -> str:
    value = environment.get(f"{_SOURCE_PREFIX}{suffix}", "").strip()
    if not value:
        raise ProfileBatchAcceptanceError("Profile batch source configuration is unavailable.")
    return value


def _positive_int(value: str, label: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise ProfileBatchAcceptanceError(f"Profile batch {label} is invalid.") from exc
    if not 1 <= number <= 65535:
        raise ProfileBatchAcceptanceError(f"Profile batch {label} is invalid.")
    return number


class _private_known_hosts_copy:
    def __init__(self, source: Path) -> None:
        self._source = source
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self.path: Path | None = None

    def __enter__(self) -> Path:
        metadata = self._source.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ProfileBatchAcceptanceError("Profile batch known_hosts source is unsafe.")
        self._temporary = tempfile.TemporaryDirectory(prefix="fortipam-v4-profile-hosts-")
        self.path = Path(self._temporary.name) / "known_hosts"
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, self._source.read_bytes())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.path.chmod(0o600)
        return self.path

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self._temporary is not None:
            self._temporary.cleanup()


def _parse_environment(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ProfileBatchAcceptanceError("Profile batch source configuration is unavailable.") from exc
    values: dict[str, str] = {}
    for line in lines:
        if "=" not in line or line.lstrip().startswith("#"):
            continue
        key, value = line.split("=", 1)
        values[key] = value
    return values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-environment", type=Path, required=True)
    parser.add_argument("--known-hosts-file", type=Path, required=True)
    parser.add_argument("--inspect-only", action="store_true")
    parser.add_argument("--execute-kind", choices=[kind for kind, _ in _BATCH])
    args = parser.parse_args()
    try:
        source_environment = _parse_environment(args.source_environment)
        if args.inspect_only and args.execute_kind is not None:
            raise ProfileBatchAcceptanceError("Inspection and execution cannot be combined.")
        result = (
            inspect_confirmed_profile_batch(source_environment, args.known_hosts_file)
            if args.inspect_only
            else run_confirmed_profile_action(
                source_environment, args.known_hosts_file, args.execute_kind
            )
            if args.execute_kind is not None
            else run_confirmed_profile_batch(source_environment, args.known_hosts_file)
        )
    except (ProfileBatchAcceptanceError, OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from None
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
