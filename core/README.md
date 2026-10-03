# Skill-Based Vulnerability Detection

100 training cases (`case_001`–`case_100`), 100 held-out test cases (`case_101`–`case_200`), 37 original skills and five refined skills.

## Models

| Group | Model | Requested effort |
|---|---|---|
| big-open | [DeepSeek V4 Pro](https://openrouter.ai/deepseek/deepseek-v4-pro#providers) | high |
| big-closed | Sonnet 5 | high |
| small-closed | Haiku 4.5 | — |
| small-open | [DeepSeek V3.2](https://openrouter.ai/deepseek/deepseek-v3.2) | high |

Exact identifiers: `config/evaluation_models.json`. Recorded settings and run status: `indexes/runs.jsonl` and `COVERAGE.json`. Some runs failed or remain pending.

## Run

Extract `replication-core.zip` and enter `replication/`. The archive includes required `operator/` manifests missing from this `core/` directory.

Requires Git, Python 3.10+, authenticated Claude Code, sandbox dependencies and each skill's tools.

```bash
git clone --mirror https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git linux-stable.git
python3 run.py --split train --skill abstract-state-analyzer \
  --variant original --provider subscription --model claude-sonnet-5 \
  --effort high --mirror ./linux-stable.git --output ./runs/example \
  --work ./work/example --case-id case_001
```

Use `--split test` for testing, `--variant refined` for refined skills, or `--prepare-only` to generate configuration without model calls. Omit `--case-id` to run the full split. Use separate output directories for each configuration.

For OpenRouter, use `--provider openrouter`, set `OPENROUTER_API_KEY` and pass the model identifier through `--model`.

Keep evaluator data, historical results and the Git mirror outside model workspaces. Training semantic labels are provisional; see `evaluator/ground_truth_audit.json`.

Skill list: [SKILLS.md](SKILLS.md). Selected refinements: `config/frozen_skills.json`.
