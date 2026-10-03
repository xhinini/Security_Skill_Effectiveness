#!/usr/bin/env bash
# Live integration smoke test for the security-advisories MCP server.
# Runs integration_test.py inside the server's uv environment. Hits live
# vulnerability APIs, so it's a manual check (run after changing the server),
# not CI. Network failures are skips, not failures.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$here/../mcp-server"
exec uv run python "$here/integration_test.py"
