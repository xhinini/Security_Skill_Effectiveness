#!/usr/bin/env python3
"""Permit local source inspection while blocking acquisition and execution."""

from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path


READ_ONLY_COMMANDS = {
    "bandit",
    "codeql",
    "cppcheck",
    "file",
    "find",
    "gitleaks",
    "grep",
    "head",
    "jq",
    "ls",
    "pip-audit",
    "rg",
    "sed",
    "semgrep",
    "tail",
    "wc",
    "which",
}
SHELL_CONTROL = re.compile(r"(?:[;&|<>`\n]|\$\(|\$\{)")


def reject(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError) as exc:
        reject(f"local review policy could not parse tool request: {exc}")
    if event.get("tool_name") != "Bash":
        return 0
    command = str((event.get("tool_input") or {}).get("command", "")).strip()
    if not command or SHELL_CONTROL.search(command):
        reject("empty commands and shell control operators are disabled")
    try:
        words = shlex.split(command)
    except ValueError as exc:
        reject(f"invalid shell command: {exc}")
    executable = Path(words[0]).name
    if executable in READ_ONLY_COMMANDS:
        return 0
    if executable in {"git", "gh"} and words[1:] == ["--version"]:
        return 0
    reject(f"Bash command {executable!r} is outside the local-review allowlist")


if __name__ == "__main__":
    raise SystemExit(main())
