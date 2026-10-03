#!/usr/bin/env python3
"""Run a selected Claude Code skill over the public 148-case manifest."""

from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_SKILL_NAME = "security-review"
DEFAULT_SKILL_INVOCATION = "/security-review"
DEFAULT_SKILL_REPOSITORY = "https://github.com/joe-bell/cva.git"
DEFAULT_SKILL_REF = "main"
DEFAULT_SKILL_SOURCE_PATH = ".agents/skills/security-review"
DEFAULT_TOOLS = ["Read", "Grep", "Glob"]
CASE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise SystemExit(f"CSV has no header: {path}")
        return list(reader)


def index_rows(rows: list[dict[str, str]], label: str) -> dict[str, dict[str, str]]:
    indexed: dict[str, dict[str, str]] = {}
    for row in rows:
        case_id = (row.get("case_id") or "").strip()
        if not case_id:
            raise SystemExit(f"{label} contains an empty case_id")
        if not CASE_ID_RE.fullmatch(case_id):
            raise SystemExit(f"{label} contains an unsafe case_id: {case_id!r}")
        if case_id in indexed:
            raise SystemExit(f"{label} contains duplicate case_id: {case_id}")
        indexed[case_id] = row
    return indexed


def target_paths(raw: str, case_id: str) -> list[str]:
    paths = [item.strip() for item in raw.split(";") if item.strip()]
    if not paths:
        raise SystemExit(f"public manifest has no target files for {case_id}")
    for item in paths:
        candidate = Path(item)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise SystemExit(f"unsafe target file for {case_id}: {item}")
    return paths


def ensure_skill_cache(
    cache: Path,
    repository: str,
    ref: str,
    source_path: str,
) -> Path:
    skill_path = cache / source_path
    if (skill_path / "SKILL.md").is_file():
        return skill_path

    installer = Path(__file__).with_name("install_skill.py")
    subprocess.run(
        [
            sys.executable,
            str(installer),
            "--repository",
            repository,
            "--ref",
            ref,
            "--source-path",
            source_path,
            "--output",
            str(cache),
        ],
        check=True,
    )
    return skill_path


def git_revision(path: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip()


def build_prompt(
    invocation: str,
    files: list[str],
    template: str | None,
    source_subdirectory: str | None = None,
) -> str:
    displayed_files = [
        f"{source_subdirectory.rstrip('/')}/{path}" if source_subdirectory else path
        for path in files
    ]
    listed = "\n".join(f"- {path}" for path in displayed_files)
    focus_args = " ".join(f"--focus {shlex.quote(path)}" for path in displayed_files)
    resolved_invocation = invocation.replace("{FOCUS_ARGS}", focus_args).strip()
    if template is not None:
        target_arguments = " ".join(shlex.quote(path) for path in displayed_files)
        return (
            template.replace("{SKILL_INVOCATION}", resolved_invocation)
            .replace("{TARGET_FILES}", listed)
            .replace("{TARGET_ARGUMENTS}", target_arguments)
        )
    return f"""{resolved_invocation}

Review all target files listed below according to the selected skill:

{listed}

Inspect these target files first. You may inspect other files inside the supplied
repository only when needed to understand types, macros, callers, callees,
control flow, and data flow.

Do not use the internet, external files, Git history, CVE databases, patches,
fixed files, private metadata, or anything outside the supplied repository and
the selected skill. Do not modify files.

Follow the selected skill's normal output format. Do not modify files.
"""


def load_skill_config(path: Path | None) -> tuple[dict[str, Any], str | None]:
    if path is None:
        return {}, None
    with path.open(encoding="utf-8") as handle:
        config = json.load(handle)
    if not isinstance(config, dict):
        raise SystemExit(f"skill config must contain a JSON object: {path}")
    prompt_template = config.get("prompt_template")
    if prompt_template is None:
        return config, None
    if not isinstance(prompt_template, str):
        raise SystemExit(f"prompt_template must be a string: {path}")
    template_path = Path(prompt_template)
    if not template_path.is_absolute():
        template_path = path.parent / template_path
    try:
        return config, template_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"cannot read prompt template {template_path}: {exc}") from exc


def extract_final_events(path: Path) -> dict[str, Any]:
    last_result: dict[str, Any] | None = None
    last_assistant: dict[str, Any] | None = None
    malformed_lines = 0
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                malformed_lines += 1
                continue
            if not isinstance(event, dict):
                continue
            if event.get("type") == "result":
                last_result = event
            if event.get("type") == "assistant":
                last_assistant = event
    return {
        "result_event": last_result,
        "last_assistant_event": last_assistant,
        "malformed_lines": malformed_lines,
    }


def terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=5)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def repository_inventory(root: Path) -> dict[str, tuple[int, int, int, str | None]]:
    """Capture cheap metadata sufficient to detect model-created repository changes."""
    inventory: dict[str, tuple[int, int, int, str | None]] = {}
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".claude":
            continue
        stat = path.lstat()
        link_target = os.readlink(path) if path.is_symlink() else None
        inventory[relative.as_posix()] = (
            stat.st_mode,
            stat.st_size,
            stat.st_mtime_ns,
            link_target,
        )
    return inventory


def repository_changes(
    before: dict[str, tuple[int, int, int, str | None]],
    after: dict[str, tuple[int, int, int, str | None]],
    allowed: set[str],
) -> list[str]:
    changed: list[str] = []
    for name in sorted(set(before) | set(after)):
        if name in allowed or any(
            (pattern.endswith("/") and (name == pattern[:-1] or name.startswith(pattern)))
            or fnmatch.fnmatchcase(name, pattern)
            for pattern in allowed
        ):
            continue
        if before.get(name) != after.get(name):
            changed.append(name)
    return changed


def run_case(
    *,
    args: argparse.Namespace,
    public_row: dict[str, str],
    private_row: dict[str, str],
    skill_source: Path,
    skill_revision: str | None,
    skill_support_files: list[dict[str, str]],
    prompt_template: str | None,
    output_root: Path,
    work_root: Path,
) -> str:
    case_id = public_row["case_id"].strip()
    files = target_paths(public_row.get("target_files", ""), case_id)
    parent_hash = (private_row.get("parent_hash") or "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", parent_hash):
        raise RuntimeError(f"invalid parent_hash for {case_id}")

    case_output = output_root / case_id
    case_output.mkdir(parents=True, exist_ok=True)
    run_metadata_path = case_output / "run.json"
    if run_metadata_path.exists() and not args.rerun:
        try:
            previous_run = json.loads(run_metadata_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            previous_run = {}
        if previous_run.get("status") == "completed":
            print(f"skip {case_id}: completed run already exists")
            return "skipped"
        print(f"retry {case_id}: previous run was not completed")

    prompt = build_prompt(
        args.skill_invocation,
        files,
        prompt_template,
        args.source_subdirectory,
    )
    (case_output / "prompt.txt").write_text(prompt, encoding="utf-8")
    trajectory_path = case_output / "trajectory.jsonl"
    stderr_path = case_output / "stderr.log"
    materialize_log_path = case_output / "materialize.log"
    final_path = case_output / "final.json"
    started_at = utc_now()
    started_clock = time.monotonic()
    command = [
        args.claude_command,
        "--print",
        "--verbose",
        "--tools",
        ",".join(args.tools),
        "--disallowedTools",
        "WebSearch,WebFetch",
        "--permission-mode",
        args.permission_mode,
        "--output-format",
        "stream-json",
        "--no-session-persistence",
        "--no-chrome",
        "--strict-mcp-config",
        "--mcp-config",
        str(args.mcp_config) if args.mcp_config else '{"mcpServers":{}}',
        "--setting-sources",
        "user,project",
    ]
    if args.claude_settings is not None:
        command.extend(["--settings", str(args.claude_settings)])
    if args.model:
        command.extend(["--model", args.model])
    if args.effort:
        command.extend(["--effort", args.effort])
    if args.max_budget_usd is not None:
        command.extend(["--max-budget-usd", str(args.max_budget_usd)])
    command.extend(["-p", prompt])

    workspace = Path(tempfile.mkdtemp(prefix=f"{case_id}-", dir=work_root))
    repository_root = workspace / "repository"
    status = "failed"
    return_code: int | None = None
    error_message: str | None = None
    timed_out = False
    before_inventory: dict[str, tuple[int, int, int, str | None]] | None = None
    try:
        materializer = Path(__file__).with_name("materialize_repository_case.py")
        source_root = (
            repository_root / args.source_subdirectory
            if args.source_subdirectory
            else repository_root
        )
        source_root.parent.mkdir(parents=True, exist_ok=True)
        materialize = subprocess.run(
            [
                sys.executable,
                str(materializer),
                "--repo",
                str(args.repo_mirror),
                "--manifest",
                str(args.private_manifest),
                "--case-id",
                case_id,
                "--output",
                str(source_root),
            ],
            capture_output=True,
            text=True,
        )
        materialize_log_path.write_text(
            materialize.stdout + materialize.stderr,
            encoding="utf-8",
        )
        if materialize.returncode:
            raise RuntimeError(
                f"materialization failed with exit code {materialize.returncode}"
            )

        skill_destination = repository_root / ".claude" / "skills" / args.skill_name
        skill_destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(skill_source, skill_destination)
        for support in skill_support_files:
            source = args.skill_cache / support["source"]
            destination = (skill_destination / support["destination"]).resolve()
            if not source.is_file():
                raise RuntimeError(f"skill support file is missing: {source}")
            if not destination.is_relative_to(skill_destination.parent.resolve()):
                raise RuntimeError(
                    f"skill support destination escapes the skills directory: {destination}"
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

        for workspace_file in args.workspace_files:
            destination = repository_root / workspace_file["destination"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            if "source" in workspace_file:
                source = args.skill_cache / workspace_file["source"]
                if not source.is_file():
                    raise RuntimeError(f"workspace support file is missing: {source}")
                shutil.copy2(source, destination)
            else:
                content = workspace_file["content"]
                content = content.replace("{CASE_ID}", case_id)
                content = content.replace(
                    "{TARGET_FILES_JSON}", json.dumps(
                        [
                            f"{args.source_subdirectory.rstrip('/')}/{path}"
                            if args.source_subdirectory else path
                            for path in files
                        ]
                    )
                )
                destination.write_text(content, encoding="utf-8")

        if args.codeql_focus_config:
            codeql_config = skill_destination / "codeql-targets.yml"
            codeql_config.write_text(
                "paths:\n" + "".join(f"  - {path}\n" for path in files),
                encoding="utf-8",
            )

        if args.enforce_output_only:
            outside_links = [
                path.relative_to(repository_root).as_posix()
                for path in repository_root.rglob("*")
                if path.is_symlink()
                and not Path(os.path.realpath(path)).is_relative_to(repository_root.resolve())
            ]
            if outside_links:
                raise RuntimeError(
                    "repository contains symlinks outside its root: "
                    + ", ".join(outside_links[:10])
                )
            before_inventory = repository_inventory(repository_root)

        with trajectory_path.open("w", encoding="utf-8") as trajectory, stderr_path.open(
            "w", encoding="utf-8"
        ) as stderr:
            process = subprocess.Popen(
                command,
                cwd=repository_root,
                stdout=trajectory,
                stderr=stderr,
                text=True,
                start_new_session=True,
            )
            try:
                return_code = process.wait(timeout=args.timeout_seconds)
            except subprocess.TimeoutExpired:
                timed_out = True
                terminate_process(process)
                return_code = process.returncode

        status = "timeout" if timed_out else ("completed" if return_code == 0 else "failed")
        if before_inventory is not None:
            allowed_output_paths = set(args.collect_artifact) | set(args.allowed_output_paths)
            for output_name in allowed_output_paths.copy():
                output_path = Path(output_name)
                allowed_output_paths.update(
                    str(parent) for parent in output_path.parents if str(parent) != "."
                )
            changed_paths = repository_changes(
                before_inventory,
                repository_inventory(repository_root),
                allowed_output_paths,
            )
            if changed_paths:
                status = "failed"
                if return_code == 0:
                    return_code = 1
                error_message = (
                    "repository output policy violated; changed paths: "
                    + ", ".join(changed_paths[:20])
                )
        collected_artifacts: list[str] = []
        artifact_errors: list[str] = []
        for name in args.collect_artifact:
            matches = sorted(repository_root.glob(name)) if any(c in name for c in "*?[") else [repository_root / name]
            matches = [source for source in matches if source.is_file() and not source.is_symlink()]
            if not matches:
                artifact_errors.append(f"required artifact missing or unsafe: {name}")
                continue
            for source in matches:
                relative = source.relative_to(repository_root).as_posix()
                destination = case_output / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                collected_artifacts.append(relative)
        if args.collect_artifact and artifact_errors:
            status = "failed"
            if return_code == 0:
                return_code = 1
            artifact_message = "; ".join(artifact_errors)
            error_message = (
                f"{error_message}; {artifact_message}" if error_message else artifact_message
            )
        json_artifact = repository_root / "VULN-FINDINGS.json"
        if "VULN-FINDINGS.json" in args.collect_artifact and json_artifact.is_file():
            try:
                parsed_artifact = json.loads(json_artifact.read_text(encoding="utf-8"))
                if not isinstance(parsed_artifact, dict):
                    raise ValueError("top-level JSON value is not an object")
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
                status = "failed"
                if return_code == 0:
                    return_code = 1
                artifact_message = f"invalid VULN-FINDINGS.json: {exc}"
                error_message = (
                    f"{error_message}; {artifact_message}" if error_message else artifact_message
                )
        final_payload = extract_final_events(trajectory_path)
        result_event = final_payload.get("result_event") or {}
        result_message = str(result_event.get("result") or "")
        result_error = str(result_event.get("error") or "")
        is_usage_limit = result_error == "rate_limit" or bool(
            re.search(
                r"you(?:'|’)ve hit your (?:session|usage|rate) limit|claude usage limit reached",
                result_message,
                re.IGNORECASE,
            )
        )
        if is_usage_limit:
            status = "rate_limited"
            if return_code == 0:
                return_code = 1
            limit_message = str(result_event.get("result") or "Claude usage limit reached")
            error_message = f"Claude usage limit: {limit_message}"
        write_json(
            final_path,
            {
                "case_id": case_id,
                "skill_name": args.skill_name,
                "status": status,
                "exit_code": return_code,
                **final_payload,
            },
        )
    except Exception as exc:  # Keep the batch moving and record the failed case.
        error_message = str(exc)
        write_json(
            final_path,
            {
                "case_id": case_id,
                "skill_name": args.skill_name,
                "status": status,
                "exit_code": return_code,
                "error": error_message,
            },
        )
    finally:
        if not args.keep_workspaces:
            shutil.rmtree(workspace, ignore_errors=True)

    metadata = {
        "case_id": case_id,
        "skill_name": args.skill_name,
        "result_name": args.result_name,
        "target_files": files,
        "started_at": started_at,
        "finished_at": utc_now(),
        "duration_seconds": round(time.monotonic() - started_clock, 3),
        "status": status,
        "exit_code": return_code,
        "error": error_message,
        "skill_repository": args.skill_repository,
        "skill_ref": args.skill_ref,
        "skill_revision": skill_revision,
        "skill_support_files": skill_support_files,
        "tool_allowlist": args.tools,
        "permission_mode": args.permission_mode,
        "batch_workers": args.workers,
        "model": args.model,
        "effort": args.effort,
        "max_budget_usd": args.max_budget_usd,
        "timeout_seconds": args.timeout_seconds,
        "claude_settings": str(args.claude_settings) if args.claude_settings else None,
        "collected_artifacts": args.collect_artifact,
        "workspace_deleted": not args.keep_workspaces,
        "trajectory_file": str(trajectory_path.name),
        "final_file": str(final_path.name),
    }
    write_json(run_metadata_path, metadata)
    print(f"{status:9} {case_id}  " + "; ".join(files))
    return status


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo-mirror",
        type=Path,
        required=True,
        help="Local bare Linux mirror created by setup_server.sh.",
    )
    parser.add_argument(
        "--enforce-output-only",
        action="store_true",
        help="Fail a case if Claude changes repository paths other than collected artifacts.",
    )
    parser.add_argument(
        "--private-manifest",
        type=Path,
        required=True,
        help="Operator-only CSV with at least case_id,parent_hash.",
    )
    parser.add_argument(
        "--public-manifest",
        type=Path,
        default=Path("public/cases.csv"),
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("results"),
        help="Directory for trajectories and run metadata.",
    )
    parser.add_argument(
        "--work-root",
        type=Path,
        default=Path(".runtime/workspaces"),
        help="Scratch directory; each case is deleted after completion by default.",
    )
    parser.add_argument("--case-id", action="append", help="Run only this case; repeatable.")
    parser.add_argument("--limit", type=int, help="Run at most this many cases in manifest order.")
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of cases to run concurrently. Each case uses an isolated workspace.",
    )
    parser.add_argument("--rerun", action="store_true", help="Rerun cases with existing run.json files.")
    parser.add_argument("--keep-workspaces", action="store_true", help="Keep materialized trees for inspection.")
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    parser.add_argument("--claude-command", default="claude")
    parser.add_argument(
        "--claude-settings",
        type=Path,
        help="Explicit Claude Code settings used to enforce tool sandboxing.",
    )
    parser.add_argument(
        "--mcp-config",
        type=Path,
        help="Explicit MCP configuration; defaults to an empty server set.",
    )
    parser.add_argument(
        "--collect-artifact",
        action="append",
        default=None,
        help="Repository-relative result file to preserve before workspace cleanup; repeatable.",
    )
    parser.add_argument("--model")
    parser.add_argument(
        "--effort",
        choices=["low", "medium", "high", "xhigh", "max"],
        help="Claude Code reasoning effort for each case.",
    )
    parser.add_argument("--max-budget-usd", type=float)
    parser.add_argument("--permission-mode", default="dontAsk")
    parser.add_argument("--skill-config", type=Path, help="JSON config for one skill experiment.")
    parser.add_argument("--skill-name")
    parser.add_argument("--result-name")
    parser.add_argument("--skill-invocation")
    parser.add_argument("--skill-repository")
    parser.add_argument("--skill-ref")
    parser.add_argument("--skill-source-path")
    parser.add_argument("--prompt-template", type=Path)
    parser.add_argument(
        "--skill-cache",
        type=Path,
        default=None,
        help="Sparse checkout containing the selected skill.",
    )
    parser.add_argument(
        "--tools",
        nargs="+",
        default=None,
        help="Allowed Claude tools. Default is Read Grep Glob.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    skill_config, config_template = load_skill_config(args.skill_config)
    args.skill_name = args.skill_name or skill_config.get("skill_name") or DEFAULT_SKILL_NAME
    args.result_name = args.result_name or skill_config.get("result_name") or args.skill_name
    args.skill_invocation = (
        args.skill_invocation
        or skill_config.get("skill_invocation")
        or DEFAULT_SKILL_INVOCATION
    )
    args.skill_repository = (
        args.skill_repository
        or skill_config.get("skill_repository")
        or DEFAULT_SKILL_REPOSITORY
    )
    args.skill_ref = args.skill_ref or skill_config.get("skill_ref") or DEFAULT_SKILL_REF
    args.skill_source_path = (
        args.skill_source_path
        or skill_config.get("skill_source_path")
        or DEFAULT_SKILL_SOURCE_PATH
    )
    args.tools = args.tools or skill_config.get("default_tools") or DEFAULT_TOOLS
    args.collect_artifact = args.collect_artifact or skill_config.get("collect_artifacts") or []
    args.allowed_output_paths = skill_config.get("allowed_output_paths") or []
    skill_support_files = skill_config.get("support_files") or []
    args.enforce_output_only = bool(
        args.enforce_output_only or skill_config.get("enforce_output_only", False)
    )
    args.source_subdirectory = skill_config.get("source_subdirectory")
    args.workspace_files = skill_config.get("workspace_files") or []
    configured_mcp = skill_config.get("mcp_config")
    if args.mcp_config is None and configured_mcp:
        args.mcp_config = Path(configured_mcp)
        if not args.mcp_config.is_absolute():
            args.mcp_config = path.parent / args.mcp_config if (path := args.skill_config) else args.mcp_config
    args.codeql_focus_config = bool(skill_config.get("codeql_focus_config", False))
    if not isinstance(args.tools, list) or not all(isinstance(tool, str) for tool in args.tools):
        raise SystemExit("skill tools must be a list of strings")
    if not isinstance(args.collect_artifact, list) or not all(
        isinstance(name, str) for name in args.collect_artifact
    ):
        raise SystemExit("collect_artifacts must be a list of strings")
    if not isinstance(args.allowed_output_paths, list) or not all(
        isinstance(name, str) for name in args.allowed_output_paths
    ):
        raise SystemExit("allowed_output_paths must be a list of strings")
    if not isinstance(skill_support_files, list):
        raise SystemExit("support_files must be a list")
    for support in skill_support_files:
        if not isinstance(support, dict) or set(support) != {"source", "destination"}:
            raise SystemExit("each support_files entry must contain source and destination")
        source_value = support["source"]
        source_path = Path(source_value)
        if (
            not isinstance(source_value, str)
            or source_path.is_absolute()
            or ".." in source_path.parts
        ):
            raise SystemExit(f"unsafe support file source: {source_value!r}")
        destination_value = support["destination"]
        destination_path = Path(destination_value)
        if not isinstance(destination_value, str) or destination_path.is_absolute():
            raise SystemExit(f"unsafe support file destination: {destination_value!r}")
    if args.source_subdirectory:
        source_subdirectory = Path(args.source_subdirectory)
        if source_subdirectory.is_absolute() or ".." in source_subdirectory.parts:
            raise SystemExit(f"unsafe source_subdirectory: {args.source_subdirectory!r}")
    if not isinstance(args.workspace_files, list):
        raise SystemExit("workspace_files must be a list")
    for workspace_file in args.workspace_files:
        if not isinstance(workspace_file, dict) or "destination" not in workspace_file:
            raise SystemExit("each workspace file needs a destination")
        if ("source" in workspace_file) == ("content" in workspace_file):
            raise SystemExit("each workspace file needs exactly one of source or content")
        destination = Path(workspace_file["destination"])
        if destination.is_absolute() or ".." in destination.parts:
            raise SystemExit(f"unsafe workspace destination: {destination}")
    for name in args.collect_artifact:
        artifact = Path(name)
        if artifact.is_absolute() or ".." in artifact.parts:
            raise SystemExit(f"unsafe collected artifact path: {name!r}")
    for name in args.allowed_output_paths:
        allowed_path = Path(name)
        if allowed_path.is_absolute() or ".." in allowed_path.parts or str(allowed_path) == ".":
            raise SystemExit(f"unsafe allowed output path: {name!r}")
    if args.prompt_template is not None:
        try:
            prompt_template = args.prompt_template.read_text(encoding="utf-8")
        except OSError as exc:
            raise SystemExit(f"cannot read prompt template {args.prompt_template}: {exc}") from exc
    else:
        prompt_template = config_template
    if args.skill_cache is None:
        args.skill_cache = Path(".runtime/skill-cache") / args.skill_name
    if not CASE_ID_RE.fullmatch(args.skill_name):
        raise SystemExit(f"unsafe skill name: {args.skill_name}")
    if not CASE_ID_RE.fullmatch(args.result_name):
        raise SystemExit(f"unsafe result name: {args.result_name}")
    if args.limit is not None and args.limit < 1:
        raise SystemExit("--limit must be positive")
    if args.timeout_seconds < 1:
        raise SystemExit("--timeout-seconds must be positive")
    if args.workers < 1:
        raise SystemExit("--workers must be positive")
    if not args.repo_mirror.is_dir():
        raise SystemExit(f"Linux mirror directory does not exist: {args.repo_mirror}")
    if not args.private_manifest.is_file():
        raise SystemExit(f"private manifest does not exist: {args.private_manifest}")
    if not args.public_manifest.is_file():
        raise SystemExit(f"public manifest does not exist: {args.public_manifest}")
    if args.claude_settings is not None and not args.claude_settings.is_file():
        raise SystemExit(f"Claude settings file does not exist: {args.claude_settings}")
    if args.mcp_config is not None and not args.mcp_config.is_file():
        raise SystemExit(f"MCP config file does not exist: {args.mcp_config}")

    public_rows = read_csv_rows(args.public_manifest)
    public_index = index_rows(public_rows, "public manifest")
    private_rows = read_csv_rows(args.private_manifest)
    if not private_rows:
        raise SystemExit("private manifest is empty")
    private_index = index_rows(private_rows, "private manifest")
    if "parent_hash" not in private_rows[0]:
        raise SystemExit("private manifest must contain parent_hash")

    requested = set(args.case_id or public_index)
    unknown = requested.difference(public_index)
    if unknown:
        raise SystemExit(f"unknown case IDs: {sorted(unknown)}")
    missing_private = requested.difference(private_index)
    if missing_private:
        raise SystemExit(f"private manifest is missing case IDs: {sorted(missing_private)}")
    ordered_rows = [row for row in public_rows if row["case_id"] in requested]
    if args.limit is not None:
        ordered_rows = ordered_rows[: args.limit]

    args.output_root = args.output_root / args.result_name
    args.output_root.mkdir(parents=True, exist_ok=True)
    args.work_root.mkdir(parents=True, exist_ok=True)
    skill_source = ensure_skill_cache(
        args.skill_cache,
        args.skill_repository,
        args.skill_ref,
        args.skill_source_path,
    )
    skill_revision = git_revision(args.skill_cache)

    def execute(public_row: dict[str, str]) -> str:
        case_id = public_row["case_id"]
        return run_case(
            args=args,
            public_row=public_row,
            private_row=private_index[case_id],
            skill_source=skill_source,
            skill_revision=skill_revision,
            skill_support_files=skill_support_files,
            prompt_template=prompt_template,
            output_root=args.output_root,
            work_root=args.work_root,
        )

    counts: dict[str, int] = {}
    if args.workers == 1:
        statuses = (execute(public_row) for public_row in ordered_rows)
        for status in statuses:
            counts[status] = counts.get(status, 0) + 1
    else:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(execute, public_row) for public_row in ordered_rows]
            for future in as_completed(futures):
                status = future.result()
                counts[status] = counts.get(status, 0) + 1

    print(f"summary: {counts}")
    return 0 if not counts.get("failed") and not counts.get("timeout") else 1


if __name__ == "__main__":
    raise SystemExit(main())
