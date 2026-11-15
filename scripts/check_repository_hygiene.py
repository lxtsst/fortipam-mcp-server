#!/usr/bin/env python3
"""Fail safely when tracked Git content appears to contain protected material."""

from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path, PurePosixPath
import re
import subprocess


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAFE_ASSIGNMENT_MARKERS = (
    b"replace-with",
    b"example",
    b"placeholder",
    b"not-a-real",
    b"dummy",
    b"<",
    b"${",
)
SENSITIVE_ASSIGNMENTS = frozenset(
    {
        b"FPA_HOME_LAB_FPA1_API_TOKEN",
        b"FORTIPAM_MCP_HTTP_BEARER_TOKEN",
        b"FORTIPAM_MCP_HTTP_OAUTH_CLIENT_SECRET",
    }
)
CONTENT_RULES = (
    (
        "private-key",
        re.compile(b"-----BEGIN " + rb"(?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    ("github-token", re.compile(rb"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b")),
    ("openai-token", re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    (
        "private-ipv4",
        re.compile(
            rb"(?<![0-9.])(?:"
            rb"10(?:\.[0-9]{1,3}){3}|"
            rb"192\.168(?:\.[0-9]{1,3}){2}|"
            rb"172\.(?:1[6-9]|2[0-9]|3[01])(?:\.[0-9]{1,3}){2}"
            rb")(?![0-9.])"
        ),
    ),
    ("private-lab-domain", re.compile(rb"\b[a-z0-9.-]+\.fortivip\.com\b", re.I)),
    ("macos-user-path", re.compile(rb"/Users/[A-Za-z0-9._-]+/")),
    ("linux-user-path", re.compile(rb"/home/[A-Za-z0-9._-]+/")),
)
ASSIGNMENT_PATTERN = re.compile(
    rb"(?m)^([A-Z][A-Z0-9_]+)=([^\r\n]*)$"
)


class RepositoryHygieneError(RuntimeError):
    """Report only aggregate finding classes, never matched paths or values."""

    def __init__(self, finding_counts: Counter[str]) -> None:
        payload = {
            "finding_counts": dict(sorted(finding_counts.items())),
            "matched_paths_reported": False,
            "protected_values_reported": False,
            "status": "failed",
        }
        super().__init__(json.dumps(payload, indent=2, sort_keys=True))


def content_findings(content: bytes) -> set[str]:
    """Return rule identifiers without returning matched protected content."""

    findings = {
        rule_name for rule_name, pattern in CONTENT_RULES if pattern.search(content)
    }
    for match in ASSIGNMENT_PATTERN.finditer(content):
        name, raw_value = match.groups()
        if name not in SENSITIVE_ASSIGNMENTS:
            continue
        value = raw_value.strip().lower()
        if not value or any(marker in value for marker in SAFE_ASSIGNMENT_MARKERS):
            continue
        findings.add("non-placeholder-secret-assignment")
    return findings


def path_findings(path: str) -> set[str]:
    """Return forbidden tracked-path findings for one repository path."""

    normalized = PurePosixPath(path)
    findings: set[str] = set()
    if normalized.name == ".env" or (
        normalized.name.startswith(".env.") and normalized.name != ".env.example"
    ):
        findings.add("tracked-environment-file")
    if normalized.suffix.lower() in {".key", ".pem", ".p12", ".pfx"}:
        findings.add("tracked-key-or-certificate")
    if normalized.name.endswith(".local.json"):
        findings.add("tracked-local-config")
    if any(part in {"secrets", "wheelhouse", "dist", "build"} for part in normalized.parts):
        findings.add("tracked-runtime-or-secret-directory")
    return findings


def _git_output(project_root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ("git", *arguments),
        cwd=project_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def scan_repository(project_root: Path = PROJECT_ROOT) -> dict[str, object]:
    """Scan tracked files and reachable history without printing matched values."""

    project_root = project_root.resolve()
    paths = [
        item.decode("utf-8")
        for item in _git_output(
            project_root,
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ).split(b"\0")
        if item
    ]
    findings: Counter[str] = Counter()
    for path in paths:
        for rule in sorted(path_findings(path)):
            findings[f"working-tree:{rule}"] += 1
        candidate = project_root / path
        if not candidate.exists():
            continue
        if candidate.is_symlink():
            findings["working-tree:symbolic-link"] += 1
            continue
        content = candidate.read_bytes()
        for rule in sorted(content_findings(content)):
            findings[f"working-tree:{rule}"] += 1

    history = _git_output(
        project_root, "log", "--all", "--no-color", "--format=", "-p"
    )
    for rule in sorted(content_findings(history)):
        findings[f"reachable-history:{rule}"] += 1
    history_paths = {
        item.decode("utf-8", errors="replace")
        for item in _git_output(
            project_root,
            "log",
            "--all",
            "--no-color",
            "--format=",
            "--name-only",
            "-z",
        ).split(b"\0")
        if item
    }
    for path in sorted(history_paths):
        for rule in sorted(path_findings(path)):
            findings[f"reachable-history-path:{rule}"] += 1

    if findings:
        raise RepositoryHygieneError(findings)
    return {
        "matched_paths_reported": False,
        "status": "passed",
        "working_tree_file_count": len(paths),
        "reachable_history_scanned": True,
        "protected_values_reported": False,
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Scan one Git repository for protected-content indicators."
    )
    parser.add_argument(
        "--repository",
        type=Path,
        default=PROJECT_ROOT,
        help="Repository to scan; defaults to the project containing this script.",
    )
    args = parser.parse_args(argv)
    try:
        result = scan_repository(args.repository)
    except RepositoryHygieneError as exc:
        print(str(exc))
        raise SystemExit(1) from None
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
