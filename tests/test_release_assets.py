from __future__ import annotations

from pathlib import Path

from fortipam_mcp import __version__


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_release_assets_reference_the_current_wheel() -> None:
    wheel_name = f"fortipam_mcp_server-{__version__}-py3-none-any.whl"

    for relative_path in (
        ".dockerignore",
        "Dockerfile",
        "deploy/docker/download_wheelhouse.sh",
        "deploy/docker/wheelhouse-manifest.sha256",
    ):
        content = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        assert wheel_name in content, relative_path


def test_dockerfile_binds_installed_wheel_to_a_provenance_label() -> None:
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "ARG APP_WHEEL_SHA256" in dockerfile
    assert f"sha256sum /tmp/fortipam_mcp_server-{__version__}-py3-none-any.whl" in dockerfile
    assert "sha256sum --check /tmp/wheelhouse-manifest.sha256" in dockerfile
    assert (
        'org.opencontainers.image.fortipam.app-wheel-sha256="${APP_WHEEL_SHA256}"'
        in dockerfile
    )
