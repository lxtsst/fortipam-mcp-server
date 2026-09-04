from __future__ import annotations

from pathlib import Path
import tomllib

from scripts.check_repository_hygiene import content_findings, path_findings


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_repository_hygiene_allows_sanitized_examples() -> None:
    name = b"FORTIPAM_MCP_HTTP_" + b"BEARER_TOKEN"
    content = name + b"=replace-with-a-random-secret-of-at-least-32-characters\n"

    assert content_findings(content) == set()
    assert path_findings(".env.example") == set()


def test_repository_hygiene_detects_protected_content_without_returning_it() -> None:
    name = b"FPA_HOME_LAB_FPA1_" + b"API_TOKEN"
    content = name + b"=" + b"sensitive-value-for-test" + b"\n"

    assert content_findings(content) == {"non-placeholder-secret-assignment"}
    assert path_findings("config/fortipam.local.json") == {"tracked-local-config"}


def test_repository_hygiene_rejects_runtime_and_secret_paths() -> None:
    assert path_findings("nested/.env.local") == {"tracked-environment-file"}
    assert path_findings("wheelhouse/dependency.whl") == {
        "tracked-runtime-or-secret-directory"
    }
    assert path_findings("certificates/client.pem") == {"tracked-key-or-certificate"}


def test_repository_hygiene_detects_each_private_ipv4_range() -> None:
    addresses = (
        b".".join((b"10", b"20", b"30", b"40")),
        b".".join((b"172", b"16", b"20", b"30")),
        b".".join((b"192", b"168", b"20", b"30")),
    )
    for address in addresses:
        assert content_findings(b"endpoint=" + address) == {"private-ipv4"}


def test_public_repository_security_boundary_is_documented() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    security_model = (PROJECT_ROOT / "docs" / "SECURITY_MODEL.md").read_text(
        encoding="utf-8"
    )

    assert "Never commit credentials" in readme
    assert "arbitrary HTTP" in security_model
    assert "protected material" in security_model


def test_local_presentation_inspection_artifacts_are_ignored() -> None:
    ignore_rules = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")

    assert ".codex_tmp/" in ignore_rules.splitlines()
    assert "*.inspect.ndjson" in ignore_rules.splitlines()


def test_security_support_line_matches_package_minor_version() -> None:
    metadata = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    version = metadata["project"]["version"]
    supported_line = ".".join(version.split(".")[:2]) + ".x"
    security_policy = (PROJECT_ROOT / "SECURITY.md").read_text(encoding="utf-8")

    assert f"`{supported_line}`" in security_policy
