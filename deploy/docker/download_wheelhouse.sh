#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
python_command="${PYTHON_COMMAND:-${project_root}/.venv/bin/python}"
output_directory="${1:-${project_root}/deploy/docker/wheelhouse}"

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
  "${project_root}/dist/fortipam_mcp_server-4.0.0b108-py3-none-any.whl"
