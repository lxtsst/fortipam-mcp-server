"""Run CI checks with private raw logs and a minimized public summary."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.verify_release import _prepare_log_directory, deterministic_checks

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NATIVE_TESTS = (
    "tests/test_secret_bulk_import_action_process.py",
    "tests/test_secret_bulk_import_row_execution.py",
    "tests/test_secret_bulk_import_row_process.py",
    "tests/test_secret_bulk_import_runtime.py",
    "tests/test_secret_bulk_import_submission_process.py",
    "tests/test_secret_bulk_import_submission_process_runtime.py",
)
FAILED_TEST = re.compile(
    r"^(?:FAILED|ERROR) (tests/test_[A-Za-z0-9_]+\.py)::([A-Za-z0-9_:]+)"
)
COUNTS = re.compile(r"\b([0-9]+) (passed|failed|skipped|errors?|deselected)\b")
CHECK_FAILURE = re.compile(r"Release verification check '([a-z_]+)' failed with exit code [0-9]+\.")
CHECK_NAMES = frozenset(check.name for check in deterministic_checks(sys.executable)) | {
    "wheel_build", "wheel_install", "installed_import", "installed_mcp_stdio",
}


def failure_phase(text: str) -> str | None:
    match = CHECK_FAILURE.search(text)
    return match[1] if match is not None and match[1] in CHECK_NAMES else None


def pytest_summary(text: str) -> dict[str, object]:
    """Return counts and test names, excluding parameters and raw diagnostics."""
    failed: set[str] = set()
    counts: dict[str, int] = {}
    for line in text.splitlines():
        match = FAILED_TEST.match(line)
        if match is not None:
            failed.add(f"{match[1]}::{match[2]}")
        if re.search(r"\bin [0-9.]+s\b", line):
            values = COUNTS.findall(line)
            if values:
                counts = {name: int(count) for count, name in values}
    return {"counts": counts, "failed_tests": sorted(failed)}


def tail_text(path: Path) -> str:
    with path.open("rb") as handle:
        handle.seek(0, 2)
        handle.seek(max(0, handle.tell() - 4 * 1024 * 1024))
        return handle.read().decode("utf-8", errors="replace")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=("release", "native-macos"), default="release")
    parser.add_argument("--log-directory", type=Path, required=True)
    args = parser.parse_args()
    if args.scope == "native-macos" and sys.platform != "darwin":
        parser.error("Native macOS qualification requires a macOS runner.")
    logs = _prepare_log_directory(args.log_directory)
    command = (
        [sys.executable, "scripts/verify_release.py", "--log-directory", str(logs)]
        if args.scope == "release"
        else [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-q", *NATIVE_TESTS]
    )
    started = time.monotonic()
    with tempfile.NamedTemporaryFile(dir=logs, prefix="command-", suffix=".log") as output:
        process = subprocess.Popen(command, cwd=PROJECT_ROOT, stdout=output, stderr=output)
        while True:
            try:
                code = process.wait(timeout=60)
                break
            except subprocess.TimeoutExpired:
                print(json.dumps({"scope": args.scope, "status": "running",
                                  "elapsed_seconds": int(time.monotonic() - started)}), flush=True)
        diagnostic = logs / "pytest.log" if args.scope == "release" else Path(output.name)
        summary = pytest_summary(tail_text(diagnostic)) if diagnostic.is_file() else {}
        print(json.dumps({"scope": args.scope, "status": "passed" if code == 0 else "failed",
                          "exit_code": code, "failed_check": failure_phase(tail_text(Path(output.name))),
                          **summary}), flush=True)
        return code if code >= 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
