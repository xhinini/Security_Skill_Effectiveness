# Report Template

Use this structure. Drop sections that don't apply. Lead with the worst finding.

---

## Security Review — `<commit-sha or PR title>`

**Scope:** `<files changed>` (`+N -M` lines across `<n>` files)
**Banner:** `<n> KEV · <m> EPSS≥0.5 · <k> other`
**Scanners run:** semgrep ✓, osv-scanner ✓, trivy ✓, gitleaks ✓, trufflehog ✓, bandit ✓, zizmor —, hadolint —, checkov —, syft+grype ✓ (`—` means N/A for this diff; missing tools should appear in the run-summary JSON below)
**Live CVE data:** via `security-advisories` MCP (or note absent)
**Verdict:** ⛔ Block / ⚠️ Fix before merge / ✅ Looks clean / 🔍 Needs human eyes

---

## Critical findings

> Only items that are exploitable now and have material impact. If none, write "None."

### 1. `<short descriptive title>`

| Field      | Value                                                            |
| ---------- | ---------------------------------------------------------------- |
| File       | `path/to/file.py:42`                                             |
| Category   | SQL injection / IDOR / RCE via deserialization / etc.            |
| CWE / CVE  | CWE-89 / CVE-2024-XXXXX (if applicable)                          |
| Source     | semgrep rule `python.django.security.injection.sql.sql-injection`|
| Confidence | High (scanner-confirmed) / Medium (pattern match, verify) / Low (heuristic) |
| Composite  | 92 (KEV: yes, EPSS: 0.78, CVSS: 9.8)                              |

**What's wrong:**
> 2–4 sentences explaining the actual vulnerability in plain language. Show the relevant code snippet.

**Why it's exploitable:**
> What an attacker would do, what they'd get, what they need to start (no auth? auth'd user? specific role?).

**Suggested fix:**
```python
# Before
query = f"SELECT * FROM users WHERE id = {user_id}"

# After
query = "SELECT * FROM users WHERE id = %s"
cursor.execute(query, (user_id,))
```

---

## High-severity findings

(Same structure, condensed. Each finding carries `Confidence` and either a `Composite` row for CVEs or a one-line equivalent for code findings.)

---

## Medium / hardening

(Short bullet list — one line each — with file:line, confidence, and a one-line suggestion. No need to expand each.)

- `auth/middleware.py:88` [confidence: High] — JWT expiry not checked; add `exp` validation
- `api/upload.py:31` [confidence: Medium] — no size limit on upload body; add `MAX_UPLOAD_BYTES`

---

## Dependency vulnerabilities

(Skip section if none. Every row carries a `reachable` tag per Step 3's reachability gate.)

| Package  | Version | Advisory       | Composite | KEV | EPSS | CVSS | Reachable | Fixed in | Notes                                              |
| -------- | ------- | -------------- | --------- | --- | ---- | ---- | --------- | -------- | -------------------------------------------------- |
| requests | 2.19.1  | CVE-2018-18074 | 65        | no  | 0.12 | 7.5  | yes       | 2.20.0   | exposes Authorization header on redirect           |
| log4j-core | 2.14.1 | CVE-2021-44228 | 100      | yes | 0.94 | 10.0 | yes       | 2.17.1   | Log4Shell — KEV, immediate                          |
| jinja2   | 3.0.0   | CVE-2024-22195 | 35        | no  | 0.04 | 6.1  | no        | 3.1.3    | template autoescape; vulnerable function not called |

Sort by `Composite` desc. Unreachable findings demote into the "Dependency hygiene" subsection rather than blocking.

### Dependency hygiene (unreachable / informational)

(Short bullet list of CVEs present in the version set but with no call-graph evidence of use.)

- `jinja2 3.0.0` — CVE-2024-22195 not reachable; bump opportunistically

---

## Secrets

(Skip section if none. Tag with detector + verification status.)

- `config/db.example.yaml:12` [gitleaks, verified-live via TruffleHog] — real Postgres URL with credentials. Rotate, then move to env.
- `tests/fixtures/jwt.txt:1` [gitleaks, NOT verified] — JWT shape, likely test data. Confirm.

---

## False positives / not actionable

> Findings you decided not to flag, with a one-line reason each. This is important — it shows the user you saw them and made a judgment call, not that you missed them.

- semgrep `generic.html-templates.security.unquoted-attribute-var` on `templates/admin.html:14` — value is a numeric ID from the trusted session, not user input

---

## What was NOT reviewed

> Be honest about coverage.

- Dynamic / runtime analysis (no fuzzing performed)
- Browser-side XSS in rendered output (no headless browser run)
- AuthN flows end-to-end (would need integration test harness)
- The `vendor/` directory (out of scope)

---

## Suggested next steps

> Maximum 3 bullets. Concrete actions, in priority order.

1. Patch the SQL injection in `users.py:42` before merging.
2. Bump `requests` to `≥2.32.0` to clear CVE-2018-18074 and CVE-2023-32681.
3. Add a Semgrep custom rule for the project's `unsafe_eval` helper.

---

## Run summary

Required. Lets the reader sanity-check that the scanners actually ran.

```json
{
  "scanners": {
    "semgrep":     {"ran": true,  "files": 87,  "findings": 12, "took_ms": 4200},
    "osv-scanner": {"ran": true,  "deps": 312,  "findings": 5,  "took_ms": 1800},
    "trivy":       {"ran": true,  "findings": 0,  "took_ms": 6100},
    "gitleaks":    {"ran": true,  "findings": 0,  "took_ms": 400},
    "trufflehog":  {"ran": true,  "findings": 0,  "verified": 0, "took_ms": 2100},
    "bandit":      {"ran": true,  "files": 14, "findings": 1, "took_ms": 900},
    "zizmor":      {"ran": false, "reason": "no .github/workflows in diff"},
    "hadolint":    {"ran": false, "reason": "not installed"},
    "checkov":     {"ran": false, "reason": "no IaC files in diff"},
    "syft+grype":  {"ran": true,  "components": 312, "findings": 5, "took_ms": 9200},
    "spotbugs":    {"ran": true,  "timed_out": true, "took_ms": 300000, "reason": "exceeded 300s budget"}
  },
  "mcp": {
    "calls": 23,
    "kev_hits": 3,
    "epss_high_hits": 7,
    "reachability_verified": 12,
    "reachability_unknown": 4
  },
  "checklist": {
    "categories_walked": 22,
    "items_flagged": 8
  }
}
```

## Confidence convention

Every finding carries one of:

- **High** — confirmed by a scanner with a deterministic rule, OR demonstrated exploit, OR direct call-graph evidence
- **Medium** — pattern match or heuristic; the model believes it but manual verification is recommended
- **Low** — speculative or environmental; flag for awareness, may be a false positive

If a finding is Low confidence, it should usually live in "Medium / hardening" or below, not "Critical / High."

## Machine-readable sidecar (optional)

When run in CI mode or when the caller passes `--sarif` / `--json`, the skill should ALSO emit one of:

- `<workdir>/report.sarif` — SARIF 2.1.0 for GitHub Advanced Security / Azure DevOps / generic SCA tools
- `<workdir>/report.json` — flat finding list with the same fields as the markdown report (file, line, rule, severity, composite, reachable, confidence, source, suggested_fix)

This is what makes the skill composable with `gh api` / PR-comment automation / dashboards. The markdown report is for humans; the sidecar is for tools.
