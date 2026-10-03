# scripts/

Helpers the skill points at. Each one is a focused tool, not a framework.

## post-findings.sh

Reads the JSON sidecar `report.json` (see `../SKILL.md` Step 6) and
posts one batched GitHub review with each finding as an inline comment.

```bash
# Common invocations
./post-findings.sh --dry-run                 # preview without posting
./post-findings.sh                           # default: >=medium, <=50
./post-findings.sh --min-severity high       # only critical + high
./post-findings.sh --summary-only            # banner only, no inline
./post-findings.sh --findings ./out.json --pr 42 --repo me/proj
```

### Inputs

| Flag             | Default                            | Meaning                                                            |
| ---------------- | ---------------------------------- | ------------------------------------------------------------------ |
| `--findings`     | `$WORKDIR/report.json` or `./report.json` | Path to the JSON sidecar                                    |
| `--pr`           | Detected via `gh pr view --json number`   | PR number to post on                                        |
| `--repo`         | Detected via `gh repo view`               | `owner/name`                                                |
| `--min-severity` | `medium`                                  | `critical` / `high` / `medium` / `low`                      |
| `--max-comments` | `50`                                      | Cap on inline comments (oldest-by-severity trimmed)         |
| `--summary-only` | off                                       | Post one review body, no inline comments                    |
| `--dry-run`      | off                                       | Print what would be posted; exit 0                          |

### Sidecar contract

The script expects this shape (all fields except `file` are optional and
defaulted; missing fields don't error):

```json
{
  "summary": "3 KEV · 7 EPSS≥0.5 · 41 other",
  "findings": [
    {
      "file": "path/to/file.py:42",
      "rule": "python.django.security.injection.sql.sql-injection",
      "category": "SQL injection",
      "severity": "critical",
      "composite": 100,
      "reachable": "yes",
      "confidence": "High",
      "kev": true,
      "epss": 0.94,
      "source": "semgrep",
      "message": "f-string concatenation into a raw SQL query.",
      "suggested_fix": "Use cursor.execute('... = %s', (user_id,))"
    }
  ]
}
```

### Requirements

- `gh` (GitHub CLI) logged in or `GH_TOKEN` set
- `jq`
- Bash 3.2+ (works on stock macOS bash)

### Exit codes

- `0` posted (or dry-run printed) successfully
- `1` no findings at or above the threshold (nothing to post)
- `2` usage / environment error
