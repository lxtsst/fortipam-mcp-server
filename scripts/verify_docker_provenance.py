#!/usr/bin/env python3
"""Verify the non-sensitive Docker provenance and runtime security contract."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
import re
import subprocess
from typing import Any


APP_WHEEL_LABEL = "org.opencontainers.image.fortipam.app-wheel-sha256"
EXPECTED_USER = "10001:10001"
EXPECTED_IMAGE_ENTRYPOINT = ["fortipam-mcp-server"]
EXPECTED_MEMORY_BYTES = 256 * 1024 * 1024
EXPECTED_NANO_CPUS = 1_000_000_000
EXPECTED_PIDS_LIMIT = 128
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_WHEEL_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1"})


class DockerProvenanceError(RuntimeError):
    """Raised when Docker inspection cannot produce a safe verification result."""


def verify_provenance(
    *,
    image: str,
    expected_image_id: str,
    expected_wheel_sha256: str,
    container: str,
    expected_entrypoint: str = "fortipam-mcp-server",
    loopback_host_port: int | None = None,
    allowed_readonly_mounts: Sequence[str] = (),
    allowed_writable_mounts: Sequence[str] = (),
) -> dict[str, object]:
    """Inspect one image and container, returning only safe verification facts."""

    _validate_image_id(expected_image_id)
    _validate_wheel_sha256(expected_wheel_sha256)
    if not expected_entrypoint or any(
        character in expected_entrypoint for character in ("\x00", "\r", "\n")
    ):
        raise DockerProvenanceError("expected entrypoint is invalid")
    allowed_readonly_targets = _validate_mount_targets(allowed_readonly_mounts)
    allowed_writable_targets = _validate_mount_targets(allowed_writable_mounts)
    if allowed_readonly_targets & allowed_writable_targets:
        raise DockerProvenanceError("mount target cannot be both read-only and writable")
    if loopback_host_port is not None and not 1 <= loopback_host_port <= 65535:
        raise DockerProvenanceError("loopback host port is outside the valid range")

    image_document = _docker_inspect(("image", "inspect", image))
    container_document = _docker_inspect(("inspect", container))
    image_id = _string(image_document.get("Id"))
    image_config = _mapping(image_document.get("Config", {}))
    labels = image_config.get("Labels")
    labels_map = _mapping(labels)
    wheel_label = _string(labels_map.get(APP_WHEEL_LABEL))

    config = _mapping(container_document.get("Config", {}))
    host_config = _mapping(container_document.get("HostConfig", {}))
    image_match = _string(container_document.get("Image")) == expected_image_id
    entrypoint = config.get("Entrypoint")
    cap_drop = _string_list(host_config.get("CapDrop"))
    cap_add = _string_list(host_config.get("CapAdd"))
    security_opt = {
        value.lower() for value in _string_list(host_config.get("SecurityOpt"))
    }
    tmpfs = _mapping(host_config.get("Tmpfs"))
    tmpfs_options = _option_set(tmpfs.get("/tmp"))

    port_bindings = host_config.get("PortBindings")
    if not isinstance(port_bindings, Mapping) or not port_bindings:
        port_bindings = _mapping(
            _mapping(container_document.get("NetworkSettings", {})).get("Ports")
        )
    published_ports, ports_document_valid = _published_ports(port_bindings)
    loopback_ports = all(
        binding_host in _LOOPBACK_HOSTS for binding_host, _ in published_ports
    )
    expected_port_present = (
        loopback_host_port is None
        or any(port == loopback_host_port for _, port in published_ports)
    )

    mounts = container_document.get("Mounts")
    mounts_document_valid = isinstance(mounts, list)
    mount_items: list[object] = mounts if isinstance(mounts, list) else []
    readonly_mount_count = 0
    writable_mount_count = 0
    readonly_mounts_allowlisted = True
    writable_mounts_allowlisted = True
    mount_targets_unique = True
    seen_mount_targets: set[str] = set()
    for item in mount_items:
        mount = _mapping(item)
        destination = _string(mount.get("Destination"))
        if not destination or destination in seen_mount_targets:
            mount_targets_unique = False
        seen_mount_targets.add(destination)
        if mount.get("RW") is True:
            writable_mount_count += 1
            if destination not in allowed_writable_targets:
                writable_mounts_allowlisted = False
        elif mount.get("RW") is False:
            readonly_mount_count += 1
            if destination not in allowed_readonly_targets:
                readonly_mounts_allowlisted = False
        else:
            writable_mount_count += 1
            writable_mounts_allowlisted = False

    checks: dict[str, bool] = {
        "image_id_match": image_id == expected_image_id,
        "container_image_match": image_match,
        "wheel_label_match": wheel_label == expected_wheel_sha256,
        "image_user_match": image_config.get("User") == EXPECTED_USER,
        "image_entrypoint_match": (
            image_config.get("Entrypoint") == EXPECTED_IMAGE_ENTRYPOINT
        ),
        "container_user_match": config.get("User") == EXPECTED_USER,
        "container_entrypoint_match": entrypoint == [expected_entrypoint],
        "read_only_rootfs": host_config.get("ReadonlyRootfs") is True,
        "cap_drop_all": "ALL" in {value.upper() for value in cap_drop},
        "no_cap_add": not cap_add,
        "no_new_privileges": "no-new-privileges:true" in security_opt,
        "memory_limit_match": host_config.get("Memory") == EXPECTED_MEMORY_BYTES,
        "cpu_limit_match": host_config.get("NanoCpus") == EXPECTED_NANO_CPUS,
        "pids_limit_match": host_config.get("PidsLimit") == EXPECTED_PIDS_LIMIT,
        "tmpfs_limit_match": {
            "noexec",
            "nosuid",
            "size=16m",
        }.issubset(tmpfs_options),
        "published_ports_loopback_only": loopback_ports,
        "expected_loopback_port_present": expected_port_present,
        "ports_document_valid": ports_document_valid,
        "mounts_document_valid": mounts_document_valid,
        "mount_targets_unique": mount_targets_unique,
        "readonly_mounts_allowlisted": readonly_mounts_allowlisted,
        "writable_mounts_allowlisted": writable_mounts_allowlisted,
    }
    result: dict[str, object] = {
        "passed": all(checks.values()),
        **checks,
        "published_port_count": len(published_ports),
        "readonly_mount_count": readonly_mount_count,
        "writable_mount_count": writable_mount_count,
        "image_id": image_id if _IMAGE_ID.fullmatch(image_id) else "",
        "wheel_label_sha256": wheel_label if _WHEEL_SHA256.fullmatch(wheel_label) else "",
    }
    return result


def _docker_inspect(arguments: Sequence[str]) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            ("docker", *arguments),
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise DockerProvenanceError("docker inspect failed") from exc
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise DockerProvenanceError("docker inspect returned invalid JSON") from exc
    if not isinstance(payload, list) or len(payload) != 1 or not isinstance(payload[0], Mapping):
        raise DockerProvenanceError("docker inspect returned an unexpected document")
    return dict(payload[0])


def _mapping(value: object) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str)]


def _option_set(value: object) -> set[str]:
    if isinstance(value, str):
        return {part.strip().lower() for part in value.split(",") if part.strip()}
    if isinstance(value, list):
        return {item.strip().lower() for item in value if isinstance(item, str) and item.strip()}
    return set()


def _published_ports(value: Mapping[str, Any]) -> tuple[list[tuple[str, int]], bool]:
    ports: list[tuple[str, int]] = []
    valid = True
    for bindings in value.values():
        if not isinstance(bindings, list):
            if bindings is not None:
                valid = False
            continue
        for binding in bindings:
            item = _mapping(binding)
            host = _string(item.get("HostIp"))
            try:
                port = int(_string(item.get("HostPort")))
            except ValueError:
                valid = False
                continue
            if not host or not 1 <= port <= 65535:
                valid = False
                continue
            ports.append((host, port))
    return ports, valid


def _validate_image_id(value: str) -> None:
    if not _IMAGE_ID.fullmatch(value):
        raise DockerProvenanceError("expected image ID must be a sha256 digest")


def _validate_wheel_sha256(value: str) -> None:
    if not _WHEEL_SHA256.fullmatch(value):
        raise DockerProvenanceError("expected wheel SHA-256 is invalid")


def _validate_mount_targets(values: Sequence[str]) -> frozenset[str]:
    targets = frozenset(values)
    if any(not target.startswith("/") or "\x00" in target for target in targets):
        raise DockerProvenanceError("writable mount target must be an absolute path")
    return targets


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-image-id", required=True)
    parser.add_argument("--expected-wheel-sha256", required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument("--expected-entrypoint", default="fortipam-mcp-server")
    parser.add_argument("--loopback-host-port", type=int)
    parser.add_argument("--allow-readonly-mount", action="append", default=[])
    parser.add_argument("--allow-writable-mount", action="append", default=[])
    return parser


def main(argv: list[str] | None = None) -> None:
    args = _parser().parse_args(argv)
    try:
        result = verify_provenance(
            image=args.image,
            expected_image_id=args.expected_image_id,
            expected_wheel_sha256=args.expected_wheel_sha256,
            container=args.container,
            expected_entrypoint=args.expected_entrypoint,
            loopback_host_port=args.loopback_host_port,
            allowed_readonly_mounts=args.allow_readonly_mount,
            allowed_writable_mounts=args.allow_writable_mount,
        )
    except DockerProvenanceError:
        print(json.dumps({"passed": False, "inspection_error": True}, sort_keys=True))
        raise SystemExit(1) from None
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["passed"] is not True:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
