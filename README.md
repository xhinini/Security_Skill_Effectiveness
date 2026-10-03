# Security_Skill_Effectiveness

Replication package for evaluating and refining security-review skills on Linux code: 100 training cases and 100 held-out test cases.

## Models

| Group | Model | Reasoning effort |
|---|---|---|
| big-open | [DeepSeek V4 Pro](https://openrouter.ai/deepseek/deepseek-v4-pro#providers) | high |
| big-closed | Sonnet 5 | high |
| small-closed | Haiku 4.5 | — |
| small-open | [DeepSeek V3.2](https://openrouter.ai/deepseek/deepseek-v3.2) | high |

## Files

| File | Contents |
|---|---|
| `replication-core.zip` | Datasets, runner, prompts, skills, configuration, indexes and reports |
| `case-evidence.zip` | Target-file snapshots and fixing patches |
| `training-{group}.zip` | Training records for each model group |
| `refinement.zip` | Refinement rounds, skill snapshots, patches and metrics |
| `testing.zip` | Original and refined skill test records |
| `core/` | Extracted replication files |

## Usage

See [core/README.md](core/README.md) for setup, execution and scoring. See [core/SKILLS.md](core/SKILLS.md) for skill indices.
