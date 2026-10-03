#!/usr/bin/env python3
"""Single Claude Code entry point for canonical train/test cases."""
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--split', choices=['train', 'test'], required=True)
    p.add_argument('--skill', required=True)
    p.add_argument('--variant', choices=['original', 'refined'], default='original')
    p.add_argument('--model', required=True, help='Exact provider model identifier; recorded unchanged.')
    p.add_argument('--effort', choices=['low', 'medium', 'high', 'xhigh'])
    p.add_argument('--provider', choices=['subscription', 'openrouter', 'deepseek'], default='subscription')
    p.add_argument('--mirror', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--work', type=Path, required=True)
    p.add_argument('--workers', type=int, default=1)
    p.add_argument('--case-id', action='append', default=[])
    p.add_argument('--prepare-only', action='store_true')
    args = p.parse_args()
    if args.work.resolve() == args.output.resolve():
        p.error('work and output must be separate')
    skills = json.loads((BASE / 'config/skills.json').read_text())['skills']
    selected = next((s for s in skills if s['key'] == args.skill), None)
    if selected is None:
        p.error('unknown skill')
    skill = BASE / 'skills' / args.variant / args.skill
    if not (skill / 'SKILL.md').is_file():
        p.error('selected skill snapshot is unavailable')
    # Configuration is generated outside the model workspace and contains no keys.
    config_dir = args.output.resolve() / '_operator'
    config_dir.mkdir(parents=True, exist_ok=True)
    cache = config_dir / 'skill-cache'
    cache.mkdir(exist_ok=True)
    if not (cache / 'selected').exists():
        shutil.copytree(skill, cache / 'selected')
    elif (cache / 'selected/SKILL.md').read_bytes() != (skill / 'SKILL.md').read_bytes():
        p.error('output contains a different skill snapshot; use a new output directory')
    for item in selected.get('support_files', []) + selected.get('workspace_files', []):
        if 'source' in item:
            source = BASE / item['packaged_source']
            destination = cache / item['source']
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                shutil.copy2(source, destination)
    prompt = selected['native_prompt']
    prompt = re.sub(r'All\s+Claude agents and subagents must use Haiku 4\.5\.', 'All agents and subagents must use the configured evaluation model.', prompt)
    prompt = re.sub(r'Haiku\s+4\.5', 'the configured evaluation model', prompt, flags=re.I)
    prompt = (BASE / 'prompt.txt').read_text().replace('{NATIVE_TASK}', prompt)
    (config_dir / 'prompt.txt').write_text(prompt)
    config = {
        'skill_name': selected['skill_name'], 'result_name': args.skill,
        'skill_invocation': selected.get('invocation', '/' + selected['skill_name']),
        'skill_repository': selected['repo'], 'skill_ref': selected['ref'],
        'skill_source_path': 'selected', 'prompt_template': 'prompt.txt',
        'default_tools': selected.get('tools', ['Read', 'Grep', 'Glob', 'Bash', 'Task', 'Write']),
        'collect_artifacts': selected.get('collect_artifacts', []),
        'allowed_output_paths': selected.get('allowed_output_paths', []),
        'workspace_files': [{k: v for k, v in f.items() if k != 'packaged_source'} for f in selected.get('workspace_files', [])],
        'support_files': [{k: v for k, v in f.items() if k != 'packaged_source'} for f in selected.get('support_files', [])],
        'source_subdirectory': selected.get('source_subdirectory'), 'enforce_output_only': True,
    }
    (config_dir / 'skill.json').write_text(json.dumps(config, indent=2))
    guard = BASE / 'scripts/guard_local_review_tools.py'
    settings = {
        'permissions': {'allow': config['default_tools'], 'deny': ['WebSearch', 'WebFetch', 'Edit', 'NotebookEdit', 'Read(../**)', 'Read(/**)']},
        'hooks': {'PreToolUse': [{'matcher': 'Bash', 'hooks': [{'type': 'command', 'command': shlex.join([sys.executable, str(guard)])}]}]},
        'sandbox': {'enabled': True, 'failIfUnavailable': True, 'autoAllowBashIfSandboxed': True,
                    'allowUnsandboxedCommands': False, 'network': {'allowedDomains': []},
                    'filesystem': {'denyRead': [str(BASE / 'evaluator'), str(BASE / 'operator'), str(args.output.resolve()), str(args.mirror.resolve())]}}
    }
    (config_dir / 'settings.json').write_text(json.dumps(settings, indent=2))
    (config_dir / 'mcp.json').write_text('{"mcpServers": {}}\n')
    env = os.environ.copy()
    if args.provider != 'subscription':
        key_name = 'OPENROUTER_API_KEY' if args.provider == 'openrouter' else 'DEEPSEEK_API_KEY'
        if not env.get(key_name) and not args.prepare_only:
            p.error(f'provide {key_name} in the environment')
        env['ANTHROPIC_BASE_URL'] = 'https://openrouter.ai/api' if args.provider == 'openrouter' else 'https://api.deepseek.com/anthropic'
        env['ANTHROPIC_AUTH_TOKEN'] = env.get(key_name, '')
        env['ANTHROPIC_API_KEY'] = ''
    for name in ['ANTHROPIC_DEFAULT_OPUS_MODEL', 'ANTHROPIC_DEFAULT_SONNET_MODEL', 'ANTHROPIC_DEFAULT_HAIKU_MODEL', 'CLAUDE_CODE_SUBAGENT_MODEL']:
        env[name] = args.model
    cmd = [sys.executable, str(BASE / 'scripts/run_native_skill_batch.py'), '--repo-mirror', str(args.mirror.resolve()),
           '--private-manifest', str(BASE / 'operator' / args.split / 'runner_manifest.csv'),
           '--public-manifest', str(BASE / 'datasets' / args.split / 'cases.csv'),
           '--skill-cache', str(cache), '--skill-config', str(config_dir / 'skill.json'),
           '--claude-settings', str(config_dir / 'settings.json'), '--mcp-config', str(config_dir / 'mcp.json'),
           '--output-root', str(args.output.resolve()), '--work-root', str(args.work.resolve()),
           '--model', args.model, '--workers', str(args.workers), '--enforce-output-only']
    if args.effort:
        cmd += ['--effort', args.effort]
    for case in args.case_id:
        cmd += ['--case-id', case]
    (config_dir / 'command.json').write_text(json.dumps(cmd, indent=2))
    if args.prepare_only:
        print('Prepared configuration; no model calls made.')
        return 0
    return subprocess.call(cmd, env=env)


if __name__ == '__main__':
    raise SystemExit(main())
