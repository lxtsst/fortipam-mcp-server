from __future__ import annotations

import json

import pytest

from scripts import verify_docker_provenance as provenance


IMAGE_ID = "sha256:" + "a" * 64
WHEEL_SHA256 = "b" * 64


def _image() -> dict[str, object]:
    return {
        "Id": IMAGE_ID,
        "Config": {
            "Labels": {provenance.APP_WHEEL_LABEL: WHEEL_SHA256},
            "User": "10001:10001",
            "Entrypoint": ["fortipam-mcp-server"],
        },
    }


def _container(*, writable_mount: bool = False, host_ip: str = "127.0.0.1") -> dict[str, object]:
    return {
        "Image": IMAGE_ID,
        "Config": {"User": "10001:10001", "Entrypoint": ["fortipam-mcp-server"]},
        "HostConfig": {
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "CapAdd": [],
            "SecurityOpt": ["no-new-privileges:true"],
            "Memory": 256 * 1024 * 1024,
            "NanoCpus": 1_000_000_000,
            "PidsLimit": 128,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,size=16m"},
            "PortBindings": {
                "8000/tcp": [{"HostIp": host_ip, "HostPort": "18039"}]
            },
        },
        "Mounts": [
            {"Destination": "/run/secrets/fortipam.env", "RW": writable_mount},
        ],
    }


def test_provenance_passes_and_uses_argv_without_exposing_inspect_payload(monkeypatch) -> None:
    calls: list[tuple[str, ...]] = []
    documents = [json.dumps([_image()]), json.dumps([_container()])]

    def fake_run(command, **kwargs):
        calls.append(tuple(command))
        return type("Completed", (), {"stdout": documents.pop(0)})()

    monkeypatch.setattr(provenance.subprocess, "run", fake_run)
    result = provenance.verify_provenance(
        image="fortipam-mcp-server:2.0.0-lab.2-candidate",
        expected_image_id=IMAGE_ID,
        expected_wheel_sha256=WHEEL_SHA256,
        container="fortipam-mcp-server-lab",
        loopback_host_port=18039,
        allowed_readonly_mounts=("/run/secrets/fortipam.env",),
    )

    assert result["passed"] is True
    assert result["image_id"] == IMAGE_ID
    assert result["published_port_count"] == 1
    assert calls == [
        ("docker", "image", "inspect", "fortipam-mcp-server:2.0.0-lab.2-candidate"),
        ("docker", "inspect", "fortipam-mcp-server-lab"),
    ]
    assert "Env" not in result
    assert "Mounts" not in result


def test_provenance_rejects_non_loopback_and_unallowlisted_writable_mount(monkeypatch) -> None:
    documents = [json.dumps([_image()]), json.dumps([_container(writable_mount=True, host_ip="0.0.0.0")])]

    def fake_run(command, **kwargs):
        return type("Completed", (), {"stdout": documents.pop(0)})()

    monkeypatch.setattr(provenance.subprocess, "run", fake_run)
    result = provenance.verify_provenance(
        image="candidate",
        expected_image_id=IMAGE_ID,
        expected_wheel_sha256=WHEEL_SHA256,
        container="container",
        allowed_readonly_mounts=("/run/secrets/fortipam.env",),
    )

    assert result["passed"] is False
    assert result["published_ports_loopback_only"] is False
    assert result["writable_mounts_allowlisted"] is False


def test_provenance_allows_explicit_writable_mount(monkeypatch) -> None:
    documents = [json.dumps([_image()]), json.dumps([_container(writable_mount=True)])]

    def fake_run(command, **kwargs):
        return type("Completed", (), {"stdout": documents.pop(0)})()

    monkeypatch.setattr(provenance.subprocess, "run", fake_run)
    result = provenance.verify_provenance(
        image="candidate",
        expected_image_id=IMAGE_ID,
        expected_wheel_sha256=WHEEL_SHA256,
        container="container",
        allowed_writable_mounts=("/run/secrets/fortipam.env",),
    )

    assert result["passed"] is True
    assert result["writable_mount_count"] == 1


def test_provenance_rejects_invalid_expected_digests() -> None:
    with pytest.raises(provenance.DockerProvenanceError):
        provenance.verify_provenance(
            image="candidate",
            expected_image_id="not-an-image-id",
            expected_wheel_sha256=WHEEL_SHA256,
            container="container",
        )


def test_provenance_supports_http_entrypoint_and_rejects_unknown_readonly_mount(
    monkeypatch,
) -> None:
    http_container = _container()
    http_container["Config"]["Entrypoint"] = ["fortipam-mcp-http"]
    documents = [json.dumps([_image()]), json.dumps([http_container])]

    def fake_run(command, **kwargs):
        return type("Completed", (), {"stdout": documents.pop(0)})()

    monkeypatch.setattr(provenance.subprocess, "run", fake_run)
    rejected = provenance.verify_provenance(
        image="candidate",
        expected_image_id=IMAGE_ID,
        expected_wheel_sha256=WHEEL_SHA256,
        container="container",
        expected_entrypoint="fortipam-mcp-http",
    )
    assert rejected["passed"] is False
    assert rejected["readonly_mounts_allowlisted"] is False

    documents.extend([json.dumps([_image()]), json.dumps([http_container])])
    accepted = provenance.verify_provenance(
        image="candidate",
        expected_image_id=IMAGE_ID,
        expected_wheel_sha256=WHEEL_SHA256,
        container="container",
        expected_entrypoint="fortipam-mcp-http",
        allowed_readonly_mounts=("/run/secrets/fortipam.env",),
    )
    assert accepted["passed"] is True
