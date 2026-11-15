#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python_command="${PYTHON_COMMAND:-${project_root}/.venv/bin/python}"
output_directory="${1:-${project_root}/deploy/docker/wheelhouse}"

# Application wheel: fortipam_mcp_server-4.0.0b109-py3-none-any.whl
# Download the exact Linux wheels recorded in the release manifest, including
# transitive dependencies. Resolver-selected newer wheels would fail the image's
# manifest verification.
requirements_file="$(mktemp)"
trap 'rm -f "${requirements_file}"' EXIT
"${python_command}" - "${project_root}" "${requirements_file}" <<'PYTHON'
from pathlib import Path
import sys

root = Path(sys.argv[1])
requirements = []
for line in (root / "deploy/docker/wheelhouse-manifest.sha256").read_text().splitlines():
    digest, filename = line.split()
    name, version = filename.split("-", 2)[:2]
    requirement = ((root / "dist" / filename).as_uri()
                   if name == "fortipam_mcp_server" else f"{name}=={version}")
    requirements.append(f"{requirement} --hash=sha256:{digest}")
Path(sys.argv[2]).write_text("\n".join(requirements) + "\n")
PYTHON

mkdir -p "${output_directory}"
find "${output_directory}" -maxdepth 1 -type f \
  -name 'fortipam_mcp_server-*.whl' -delete
"${python_command}" -m pip download \
  --dest "${output_directory}" \
  --only-binary=:all: \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 312 \
  --abi cp312 \
  --constraint "${project_root}/deploy/docker/runtime-constraints.txt" \
  --require-hashes \
  --requirement "${requirements_file}"
