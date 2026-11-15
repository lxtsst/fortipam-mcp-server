"""Build the separate FortiPAM V4 plan-only pre-release wheel."""

from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DESCRIPTOR = PROJECT_ROOT / "packaging" / "v4-plan-only"
SOURCE_PACKAGE = PROJECT_ROOT / "v4_planning"


class V4PlanRuntimeBuildError(RuntimeError):
    """Raised when the isolated plan-only package cannot be built safely."""


def build(output_directory: Path) -> Path:
    """Stage authoritative sources, build one wheel, and return its path."""

    output_directory = output_directory.resolve()
    output_directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fortipam-v4-plan-runtime-") as name:
        staging = Path(name)
        shutil.copytree(SOURCE_PACKAGE, staging / "v4_planning")
        shutil.copy2(PACKAGE_DESCRIPTOR / "pyproject.toml", staging / "pyproject.toml")
        shutil.copy2(PACKAGE_DESCRIPTOR / "README.md", staging / "README.md")
        shutil.copy2(PROJECT_ROOT / "LICENSE", staging / "LICENSE")
        result = subprocess.run(
            (
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(output_directory),
                str(staging),
            ),
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise V4PlanRuntimeBuildError(
                "The isolated V4 plan-only wheel build failed."
            )
    wheels = sorted(output_directory.glob("fortipam_mcp_v4_plan_runtime-4.0.0b7-*.whl"))
    if len(wheels) != 1:
        raise V4PlanRuntimeBuildError(
            "The V4 plan-only build did not produce exactly one expected wheel."
        )
    return wheels[0]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args(argv)
    wheel = build(args.output_directory)
    print(wheel.name)


if __name__ == "__main__":
    main()
