#!/usr/bin/env bash
set -euo pipefail

container_name="${FORTIPAM_MCP_CONTAINER_NAME:-fortipam-mcp-server-lab}"
exec docker exec -i "${container_name}" fortipam-mcp-server
