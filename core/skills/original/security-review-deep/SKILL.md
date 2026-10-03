---
name: security-review-deep
description: "Scanner-grounded security audit, distinct from the built-in /security-review. Runs the right scanners (semgrep, osv-scanner, trivy, gitleaks, bandit), queries live CVE data via MCP, applies a 24-category threat-model checklist, and produces a triaged report. Trigger on \"deep security review\", \"full security audit\", \"check for CVEs\", \"scan my dependencies\" \u2014 and proactively after changes touching auth, input handling, file/network I/O, crypto, or dependency upgrades."
---

# Security Review

A disciplined, repeatable process for catching vulnerabilities in a code change. Designed to make any model — large or small — review like a senior security engineer by combining deterministic scanners, live advisory data, and a structured threat-model walkthrough.

## When to use this skill

- After a commit, in a pre-push hook, or in CI
- When reviewing a PR or diff
- When auditing a dependency upgrade
- When the user asks "is this safe?" or anything in the same neighborhood
- Proactively after the user finishes work that touches sensitive surface area (auth, file I/O, deserialization, network, crypto, IPC, parsing user input)

If unsure whether to trigger: trigger. False positives here are cheap; missing a vuln is not.

## The process

Always work in this order. **Do not skip to LLM analysis without running the scanners first** — that's how you end up hallucinating CVE numbers and missing real issues.

### Step 1 — Scope the change

Determine what to review:

```bash
# For a post-commit / pre-push review:
git diff HEAD~1 HEAD --stat
git diff HEAD~1 HEAD

# For a PR review (against main):
git diff origin/main...HEAD --stat
git diff origin/main...HEAD

# For an audit of the whole repo:
# scope is everything; note this and warn the user it will be slower
```

Capture:
- list of changed files
- any dependency manifests touched (`package.json`, `package-lock.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `go.mod`, `pom.xml`, `Gemfile.lock`, etc.)
- whether the change touches any **sensitive surface** (see checklist below)
- **languages and frameworks present in the diff**. This decides which Step 2 scanners run. Read the file extensions and a few imports, then list them explicitly, e.g.:

  ```
  languages: Python (Flask), Go, TypeScript (React), shell, Dockerfile
  iac:       Terraform, GitHub Actions
  ```

  Languages absent from the diff skip their Step 2 scanner; record `"ran": false, "reason": "language not in diff"` in the run summary. This is what stops the model from blindly invoking `gosec` on a Python-only change.

### Step 2 — Run the deterministic scanners

Run all available scanners on the scoped change. Don't try to *be* the scanner — use them. Route by file type: only run a scanner if its target language / surface appears in the diff (or, for whole-repo audits, the repo).

#### Always-on (regardless of language)

```bash
WORKDIR="${TMPDIR:-/tmp}/security-review-$$"
mkdir -p "$WORKDIR"

# Wrap every scanner in a 300s budget so one hung tool can't block the
# whole review. Falls back to running bare if no `timeout` is on PATH
# (on macOS install GNU coreutils: `brew install coreutils`).
TIMEOUT=$(command -v timeout || command -v gtimeout || true)
TO() { [[ -n "$TIMEOUT" ]] && "$TIMEOUT" 300 "$@" || "$@"; }
# Convention: a scanner that hit the budget exits 124; record
# {"ran": true, "timed_out": true} for that tool in the run summary
# rather than dropping the layer silently.

# SAST — pattern-based vuln detection, multi-language
TO semgrep --config=p/default --config=p/security-audit \
        --config=p/owasp-top-ten --config=p/cwe-top-25 \
        --json --quiet <changed-files-or-dir> > "$WORKDIR/semgrep.json"

# Dependency CVEs (Google's OSV aggregator)
TO osv-scanner scan source -r --format=json --output="$WORKDIR/osv.json" .

# Filesystem / IaC / container vulns; also includes lockfile scanning
TO trivy fs --severity HIGH,CRITICAL --format=json --output="$WORKDIR/trivy.json" .

# Secrets — fast regex layer
TO gitleaks detect --no-banner --report-format=json --report-path="$WORKDIR/gitleaks.json"

# Secrets — live-credential verification (different findings than gitleaks; run both)
TO trufflehog filesystem . --json --no-update > "$WORKDIR/trufflehog.json"
```

Wrap the language-specific and CI/IaC scanner blocks below with the same `TO` helper; the per-scanner block omits the wrapping only for brevity.

Gitleaks catches secret-shaped strings via regex; TruffleHog verifies whether a detected secret is *live* against 20+ providers. The two find different things; run both and union the results.

#### Language-specific (gate by file extension in the diff)

```bash
# Python (*.py) — common security antipatterns the model often misses
bandit -r <python-paths> -f json -o "$WORKDIR/bandit.json"

# Go (*.go) — gosec for code patterns, govulncheck for reachable dep vulns
gosec -fmt=json -out="$WORKDIR/gosec.json" ./...
govulncheck -json ./... > "$WORKDIR/govulncheck.json"

# JavaScript / TypeScript (*.js, *.ts, *.jsx, *.tsx)
njsscan --json -o "$WORKDIR/njsscan.json" .

# Ruby / Rails (Gemfile + config/application.rb present)
brakeman -f json -o "$WORKDIR/brakeman.json" --no-progress

# Shell (*.sh, *.bash) — quoting and command-injection catches
shellcheck -f json <shell-files> > "$WORKDIR/shellcheck.json"

# Java / Kotlin (*.java, *.kt, pom.xml, build.gradle)
spotbugs -textui -xml:withMessages -output "$WORKDIR/spotbugs.xml" \
         -pluginList find-sec-bugs.jar <build-output-dirs>

# Rust (Cargo.toml present) — CVE deps, unsafe blocks, panic-prone code
cargo audit --json > "$WORKDIR/cargo-audit.json"
cargo geiger --output-format Json > "$WORKDIR/cargo-geiger.json"
cargo clippy --all-targets --message-format=json -- \
    -W clippy::unwrap_used -W clippy::expect_used \
    -W clippy::panic -W clippy::indexing_slicing \
    > "$WORKDIR/clippy.json"

# C / C++ (*.c, *.cc, *.cpp, *.h, *.hpp) — classic memory-safety class
flawfinder --csv <c-paths> > "$WORKDIR/flawfinder.csv"
cppcheck --enable=warning,performance,portability \
         --output-file="$WORKDIR/cppcheck.txt" --xml <c-paths>
clang-tidy <c-paths> \
    -checks='clang-analyzer-security.*,clang-analyzer-core.*,bugprone-*' \
    > "$WORKDIR/clang-tidy.txt"

# .NET (*.cs, *.csproj, *.sln) — Roslyn-based security analyzer
security-scan <solution.sln> --export="$WORKDIR/security-code-scan.sarif"

# PHP (*.php, composer.json) — taint-mode (psalm) catches injection
# across function boundaries; psalm taint is currently the strongest
# free PHP SAST.
vendor/bin/psalm --taint-analysis --report="$WORKDIR/psalm.sarif"
```

Scanner alternatives worth knowing about:

- **Opengrep** (Jan 2025 community fork of Semgrep CE) is a drop-in
  replacement if Semgrep's licensing changes bite. Same rule format,
  same JSON / SARIF output, same `--config=p/...` packs work. Swap
  the binary name if you need to.

#### CI / build / infra surface (gate by file presence)

```bash
# GitHub Actions (.github/workflows/*.yml) — workflow-injection,
# pull_request_target misuse, over-privileged tokens. Non-negotiable in
# 2026 after the March 2026 aquasecurity/trivy-action -> LiteLLM PyPI
# compromise.
zizmor --format=json .github/workflows/ > "$WORKDIR/zizmor.json"

# Dockerfile (Dockerfile, **/Dockerfile.*) — author-time issues trivy misses
hadolint --format=json $(find . -name 'Dockerfile*' -not -path '*/node_modules/*') > "$WORKDIR/hadolint.json"

# IaC: Terraform (*.tf), Kubernetes (k8s/, helm/), CloudFormation, ARM,
# Bicep, Serverless. Checkov is the broadest open-source IaC scanner in
# 2026 (tfsec is deprecated, terrascan is archived).
checkov -d . --framework all -o json -s --skip-path node_modules > "$WORKDIR/checkov.json"

# Kubernetes manifest quality (k8s/, helm/, *.yaml with `kind:`). Checkov
# catches policy violations; kube-score catches operational misses
# (resource limits, readiness probes, security contexts) the policy
# scanners miss. Optional layer; run if K8s manifests are present.
kube-score score $(find . -path '*/k8s/*.yaml' -o -path '*/helm/*.yaml') \
            --output-format json > "$WORKDIR/kube-score.json"

# SBOM + cross-check vuln scanning (independent of OSV; surfaces
# advisories OSV occasionally misses, and produces an artifact you can
# diff over time).
syft . -o cyclonedx-json > "$WORKDIR/sbom.cdx.json"
grype sbom:"$WORKDIR/sbom.cdx.json" -o json > "$WORKDIR/grype.json"
```

If any tool is missing, note it and continue with the rest. Record the absence in the run-summary JSON (Step 6) as `"ran": false, "reason": "not installed"`. Do not refuse to proceed.

Read each JSON output and build a unified findings list with: file, line, rule, severity, message, raw tool source.

#### Cross-cutting passes

In addition to the file-scoped scanners, run these on every review:

```bash
# Secrets in history, not just the current diff. Gitleaks/trufflehog
# default to "what's in the working tree;" attacker access to git
# objects exposes everything previously committed. Look back at least
# 30 days, more if the repo's young.
trufflehog git "file://$(pwd)" --since-commit="HEAD~200" \
  --json --no-update > "$WORKDIR/trufflehog-history.json"

# Regression check: if a previous review exists for this repo, diff
# the new findings against the old. Any finding that is NEW (was not
# present in the previous report) is a regression and earns a tag in
# the report. Findings that existed before are still flagged but
# de-emphasized.
PREV=".security-reviews/last.json"
[[ -f "$PREV" ]] && comm -13 \
    <(jq -r '.findings[].id' "$PREV" | sort) \
    <(jq -r '.findings[].id' "$WORKDIR/report.json" 2>/dev/null | sort) \
    > "$WORKDIR/regressions.txt" || true

# Test coverage on changed security-relevant lines. Run the project's
# coverage tool (pytest --cov / jest --coverage / cargo tarpaulin) and
# cross-reference the uncovered lines against the diff. A new auth
# check or input validator with no test is a real risk.
```

For each of these, omit gracefully if the tool isn't installed or the
artifact doesn't exist; record in the run summary.

#### Heavier passes for a schedule (CodeQL)

Some scanners are too slow for per-PR but worth running nightly or
weekly. CodeQL is the canonical example: database-backed semantic
analysis with interprocedural taint tracking that catches injection
across function boundaries semgrep / bandit miss. Build time is
minutes to 30+ minutes for large repos, so it does not belong in
the fast path.

Recommended pattern: run CodeQL in a scheduled GitHub Actions job
(free for public repos via Code Scanning; paid for private). Persist
the SARIF artifact to a known path, and let the next per-PR review
ingest it as a "last full-pass" finding set.

```yaml
# .github/workflows/codeql.yml (excerpt)
on:
  schedule: [{cron: "17 4 * * *"}]   # daily 04:17 UTC
jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions: {contents: read, security-events: write}
    strategy:
      matrix:
        language: [python, javascript, go]
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with: {languages: '${{ matrix.language }}', queries: security-extended}
      - uses: github/codeql-action/analyze@v3
        with: {output: codeql-results}
      - uses: actions/upload-artifact@v4
        with:
          name: codeql-${{ matrix.language }}-sarif
          path: codeql-results
```

The skill then reads `.security-reviews/codeql-latest.sarif` (or
wherever the artifact lands) in Step 2 alongside the per-PR scanners.
Findings get a `source: codeql, age: <days-since-job>` tag so the
reader knows they're from the nightly pass, not the live diff.

Don't try to run CodeQL inline in the per-PR skill invocation; the
latency makes the skill unusable. Schedule it, ingest it.

### Step 3 — Pull live advisory context (MCP first, scanners as fallback)

**If the `security-advisories` MCP server is registered, use it before any
other dependency-scanning approach.** It's faster, doesn't need a venv, and
returns structured data Claude can cite without paraphrasing.

Order of preference for dependency CVE lookups:
1. **MCP** for everything in this order per finding:
   - `check_dependencies_bulk` for a whole lockfile, `check_package` for
     one bumped dep.
   - `composite_risk(cve_id)` for any CVE that surfaces. This rolls CVSS
     (NVD) + EPSS (FIRST.org) + KEV membership (CISA) into a single
     0-100 score and triage bucket. Use this to rank findings instead of
     re-deriving the math in prose.
   - `kev_lookup(cve_id)` if you only need the "actively exploited?" bit.
   - `epss_score(cve_id)` if you only need the exploit-probability bit.
   - `latest_safe_version(ecosystem, name, current_version)` for an
     upgrade target. Returns each advisory's fix versions and a
     best-effort smallest version that clears all of them. Cite this
     verbatim in the "Suggested fix" block.
   - `ghsa_get(ghsa_id)` / `lookup_cve(cve_id)` for full advisory text.
   - `package_health(ecosystem, name)` for maintenance signals (last
     release date, total releases, maintainer count, archived /
     yanked status). Run this on any *new* dependency the diff
     adds — abandonware and typosquats are senior-reviewer concerns
     OSV won't surface. PyPI + npm supported natively.
2. **osv-scanner** if the MCP isn't registered.
3. Hand-rolled OSV.dev API calls (curl, Python urllib) only as a last resort
   if both above fail.

Do NOT fall back to "recall the CVE from memory" — that's how CVE IDs get
hallucinated. If the tools aren't available, say so explicitly in the report.

NVD enrichment dropped to ~15-20% of CVEs in April 2026, so `lookup_cve`
results may be sparse. OSV + GHSA + KEV is now the primary trio; treat NVD
as supplementary.

#### Reachability gate (apply to every dep CVE before flagging)

Most OSV findings are NOT reachable from your code. Industry estimates put
unreachable CVEs at ~90% of raw output. Before listing a dep CVE in the
report, do one of:

1. **Direct check**: grep the codebase for the vulnerable function/class
   named in the advisory's `details`. If it's not imported or called,
   mark `reachable: no` and demote to the "Dependency hygiene" section
   instead of "Critical / High."
2. **Tool check** if the language supports it:
   - Go: `govulncheck ./...` (reports reachability against Go's vuln DB)
   - Python: `pip-audit --strict` (limited reachability heuristics)
   - Rust: `cargo-audit` + manual import check
3. **Explicit unknown**: mark `reachable: unknown` and explain why you
   couldn't verify (vulnerable symbol not named in advisory, deep
   transitive dep, etc.).

Every dep finding in the report must carry a `reachable: yes/no/unknown`
tag. Don't silently drop unreachable findings; surface them as "known
vulnerable version present but no call-graph evidence of use."

### Step 4 — Apply the threat-model checklist to the diff

This is where the LLM adds value beyond scanners. For **every changed file**, walk the checklist below and write down what you find. Do not just say "looks good" — name the specific function, line, and reason for each item you clear or flag.

Read `references/threat-checklist.md` for the full list. The top categories:

1. **Trust boundaries** — does this code cross one (user → server, low-priv → high-priv, network → process)? What data flows across?
2. **Input validation** — every external input typed, length-checked, content-validated before use
3. **Injection sinks** — SQL, command, LDAP, XPath, template, log, header, NoSQL, ORM-raw
4. **AuthN / AuthZ** — is every new endpoint/handler protected? Is the check before the side effect? Are object-level permissions enforced (IDOR)?
5. **Secrets / credentials** — hardcoded, logged, sent to telemetry, embedded in URLs, committed to repo?
6. **Crypto** — algorithm choice, key length, IV/nonce reuse, MAC-then-encrypt errors, custom crypto (red flag)
7. **Deserialization** — pickle, yaml.load (not safe_load), Java/PHP unserialize, anything that turns bytes into objects
8. **SSRF / file inclusion** — URL or path constructed from user input and then fetched/opened
9. **Race conditions / TOCTOU** — check-then-use patterns on files, tokens, balances
10. **Error handling** — stack traces leaked, exceptions swallowed silently, fail-open patterns
11. **Logging & PII** — secrets, tokens, full PII in logs; unbounded log growth
12. **Dependencies** — covered by Step 3, but also: typosquats, abandoned packages, suspicious new maintainers
13. **Supply chain** — install/build scripts, postinstall hooks, dynamic code loading
14. **Concurrency** — shared mutable state, locking
15. **Resource exhaustion** — unbounded loops, allocations, recursion, regex (ReDoS)
16. **Web-app cross-cutting** — CSRF, CORS, open redirect, security headers, cookie flags, cache poisoning, host header injection
17. **Protocol-specific** — GraphQL (introspection, depth, complexity, batching), WebSocket (origin, auth on connect), gRPC, webhook signature verification + replay protection
18. **Authorization matrix** — for every new endpoint write a one-line `caller / side_effect / lesser_role_result` row and verify the answer. IDOR lives here; scanners do not catch it.
19. **Business logic** — payment / coupon / refund abuse, workflow step skipping, race-on-balance, signed-message replay, state-machine bypass, mass assignment
20. **LLM / AI agent / MCP** — direct + indirect prompt injection, insecure output handling, excessive agency, system-prompt leakage, RAG poisoning, unbounded consumption; MCP-specific tool-arg validation, no shell from args, SSRF in fetch tools, auth on connect
21. **Negative space** — for each addition, ask what *wasn't* added: route missing from auth allowlist, PII field missing from log scrubber, weakened control in the deletion side of the diff, new background job using elevated creds
22. **AI-generated code red flags** — if the diff looks AI-shaped, do an extra pass on input handling, error paths, and duplicate helpers; AI-generated code carries ~2.74x the vuln density on average. Also walk the "looks done but isn't" sub-list: validators that don't validate, tests that test nothing, dead branches, half-refactored identifiers, TODO/FIXME left in production paths, feature flags that don't kill, retry loops with no upper bound.
23. **Memory safety and unsafe constructs** — only when Rust / C / C++ / Go is in the diff. Rust: `unsafe` blocks need `// SAFETY:` justification; no `.unwrap()` / `.expect()` / `panic!()` / `todo!()` on reachable paths; integer overflow handling explicit. C/C++: bounded buffer ops, no format-string holes, UAF / double-free / uninitialized memory, integer overflow on size arithmetic. Go: errors checked at every call site, `context.Context` propagated, no goroutine leaks, no `defer` in loops.
24. **Context-specific surfaces (when relevant)** — Mobile (cert pinning, deep-link validation, exported components, Keychain/Keystore, WebView hardening). Cloud IAM (no `*:*`, OIDC trust-policy wildcards, AssumeRole chains, KMS key policies, VPC SGs, audit-log integrity). Skip the sub-block that doesn't apply.

For each item: ✅ cleared (with brief reason), ⚠️ flagged (with file:line + explanation), or N/A.

### Step 5 — Triage and prioritize

You will likely have more findings than the user wants to act on. Rank by **exploitability × impact**, not by scanner severity alone:

- **Critical** — exploitable now, no auth required, leads to RCE / data exfil / auth bypass
- **High** — exploitable with some condition (auth'd user, specific input), or undermines a security boundary
- **Medium** — defense-in-depth issues, hardening gaps, theoretical-but-real
- **Low** — informational, style, "should fix eventually"
- **Noise** — scanner false positives. Explicitly mark these and explain *why* it's a false positive — don't just drop them.

#### Triage rules baked into the workflow

For every CVE that appears (in OSV output, dep findings, or anywhere
else), call `composite_risk(cve_id)` and apply these rules:

1. **CISA KEV → Critical**, regardless of CVSS. KEV membership means
   the bug is being actively weaponized in the wild; that beats any
   abstract severity score.
2. **EPSS >= 0.5 → minimum High**. FIRST.org's exploit-prediction
   model is 0.0-1.0 for "exploited in the next 30 days." Half-likely
   is more dangerous than most CVSS-8 issues that nobody has weaponized.
3. **CVSS alone → bucket by score × 10** (so CVSS 9.0 → 90, "Critical").
4. **Reachability beats severity**. A CVSS 9.8 in an unreachable
   transitive dep is Medium hygiene at best; a CVSS 6.5 in a hot
   code path on a user-facing route is High.

The `composite_score` returned by `composite_risk` already encodes
rules 1-3. Use it as the default order within each bucket.

### Step 6 — Output the report

Use the format in `references/report-template.md`. Key principles:

- **Lead with what's actually exploitable.** Don't bury a CRITICAL under 40 LOW findings.
- **Every finding gets a fix.** Suggested patch, not just "be more careful."
- **Cite the source** for every claim — which scanner, which CVE, which line of code.
- **Distinguish what you ran from what you didn't.** "Semgrep + OSV + Trivy on the diff. Did not run dynamic analysis or fuzzing."
- **No padding.** No "in conclusion, security is important." End when the work ends.

Required at the top of the report (banner):

- Counts: KEV findings, EPSS >= 0.5 findings, other.
- For example: `3 KEV · 7 EPSS≥0.5 · 41 other`.

Required at the bottom of the report (run summary):

```json
{
  "scanners": {
    "semgrep":     {"ran": true, "files": 87, "findings": 12, "took_ms": 4200},
    "osv-scanner": {"ran": true, "deps": 312, "findings": 5, "took_ms": 1800},
    "trivy":       {"ran": true, "findings": 0,  "took_ms": 6100},
    "gitleaks":    {"ran": true, "findings": 0,  "took_ms": 400},
    "bandit":      {"ran": true, "files": 14, "findings": 1, "took_ms": 900}
  },
  "mcp": {
    "calls": 23,
    "kev_hits": 3,
    "epss_high_hits": 7
  }
}
```

A sloppy run and a thorough run should look obviously different. If a
scanner was unavailable, set `"ran": false` and `"reason": "..."`.

Every dependency finding must carry a `reachable: yes/no/unknown` tag
(per Step 3's reachability gate).

Every finding (code OR dep) carries a `Confidence` tag:

- **High** — confirmed by a deterministic scanner rule, demonstrated exploit, or direct call-graph evidence
- **Medium** — pattern match or heuristic; verification recommended before acting
- **Low** — speculative; flag for awareness, may be a false positive

If a finding is Low confidence it generally belongs in "Medium /
hardening" or below, not "Critical / High." See
`references/report-template.md` for the full convention.

If the caller asks for CI-friendly output (or passes `--sarif` /
`--json`), also emit a sidecar alongside the markdown report:

- `report.sarif` (SARIF 2.1.0) — for GitHub Advanced Security,
  Azure DevOps, generic SCA tools, and the built-in `/code-review
  --comment` machinery
- `report.json` — flat finding list with `{file, line, rule,
  severity, composite, reachable, confidence, source, suggested_fix,
  message, kev, epss, category}` and an optional top-level `summary`
  string for the banner

The markdown report is for humans; the sidecar is for tools. Both
must reference the same findings; do not silently drop entries when
serializing.

#### Posting findings as PR review comments

`scripts/post-findings.sh` reads `report.json` and posts one batched
GitHub review per run, with each finding rendered as an inline comment
at the `file:line` it points to. Severity-threshold and max-comments
configurable; defaults are `--min-severity medium --max-comments 50`.

```bash
# Auto-detects current repo + PR via `gh`. Set WORKDIR or pass --findings.
./scripts/post-findings.sh --dry-run            # preview without posting
./scripts/post-findings.sh                      # post one review
./scripts/post-findings.sh --summary-only       # banner only, no inline
./scripts/post-findings.sh --min-severity high  # critical + high only
```

Requires `gh` (logged in) and `jq`. Use this when the skill runs in CI
and you want findings to land on the PR rather than only in the agent's
output. Sample CI step:

```yaml
- name: Post security findings to PR
  if: github.event_name == 'pull_request'
  env:
    GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    ./skills/security-review-deep/scripts/post-findings.sh \
        --findings "$WORKDIR/report.json" \
        --min-severity high
```

If everything passes, the report can be three lines. If it doesn't, it can be ten pages. Length follows findings, never the other way around.

### Step 7 — Capture project-specific patterns for next time

Before signing off, ask the question that closes the learning loop:

> Did this review surface a pattern specific to *this codebase* that should become a deterministic check next time?

Common candidates:

- A project-internal helper that's unsafe by construction (e.g. an in-house `run_command` that always passes `shell=True`) — write a semgrep rule that flags any call.
- A wrapper that LOOKS like a safe helper but isn't (e.g. `db.execute_safe(...)` that string-formats internally) — write a rule that flags calls.
- A field name that should always be redacted in logs (e.g. `customer.ssn`, `token.value`) — write a rule that flags any log statement referencing it.
- A convention the team agreed on but only humans enforce (e.g. "money goes through `Money.from_decimal`, never `float`") — write a rule that flags `float(...)` near monetary identifiers.

If you find one, draft a semgrep rule and append it to `.semgrep/project-rules.yml` (create the file if absent). Then add `--config=.semgrep/project-rules.yml` to the Step 2 semgrep invocation so the next review picks it up automatically.

Minimum useful rule template:

```yaml
rules:
  - id: project.unsafe-run-command
    message: |
      Internal `run_command(...)` always uses `shell=True`. Use
      `subprocess.run([...], shell=False)` directly, or rework the
      helper to take a list.
    severity: WARNING
    languages: [python]
    pattern: run_command(...)
```

Include the new rule in the report's "Suggested next steps" so the user knows what was added. One rule per review is plenty — chasing more than that is bikeshedding.

## Failure modes to actively avoid

- **Hallucinating CVE numbers.** Only cite CVEs returned by `lookup_cve` or present in scanner output. Never reconstruct from memory.
- **"It looks fine."** If you haven't run the scanners or walked the checklist, you don't know that.
- **Over-trusting a single scanner.** Semgrep misses things OSV catches and vice versa. Run multiple.
- **Treating scanner severity as final.** A CRITICAL Semgrep finding on dead code is less important than a MEDIUM one in a live auth path. Re-rank based on context.
- **Burying lede.** Top of the report is the worst finding, always.
- **Dropping findings without explanation.** If you decide a finding is a false positive, say so and say why. Never silently omit.
- **Never cite a CVE ID that didn't come directly from a tool output.**
  Every CVE-XXXX-NNNN in the report must be traceable to a specific tool
  invocation (MCP `lookup_cve`, OSV-Scanner JSON, GHSA advisory result). If
  you find yourself typing a CVE ID from memory or inference, stop — call
  `lookup_cve` to verify it exists and matches your claim, or remove it.

## Lightweight mode

If the user wants something fast (pre-commit hook, sub-30-second turnaround):

1. Run only `semgrep --config=p/security-audit` and `gitleaks` on the diff. Add `zizmor` if any `.github/workflows/*.yml` is touched and `hadolint` if any `Dockerfile*` is touched — both are fast and catch a class of issues nothing else does.
2. Skip the MCP live-CVE pass unless a dependency manifest was touched
3. Apply only the top 5 checklist categories (1, 2, 3, 4, 5)
4. Output a compact one-screen report

Tell the user this is the lightweight pass and a fuller review can be run separately.

## Installing the scanners

The full Step 2 stack relies on tools that aren't all installed by default. On macOS:

```bash
brew install semgrep gitleaks trivy hadolint shellcheck
pipx install bandit checkov trufflehog zizmor
go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install golang.org/x/vuln/cmd/govulncheck@latest
cargo install cargo-audit
gem install brakeman
# njsscan
pipx install njsscan
# syft + grype
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh  | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
```

Missing tools should be noted in the report's run-summary JSON (`"ran": false, "reason": "not installed"`) rather than blocking the review.

## When you're stuck

If a scanner errors out, capture the error verbatim, note which scanner, and continue with the others. The review is still valuable even if one tool is broken.

If the diff is enormous (>2000 lines changed), tell the user up front: full review will take time, and offer to either (a) batch by directory, or (b) focus on the most sensitive files first based on filename heuristics (anything matching `auth`, `login`, `password`, `crypto`, `admin`, `payment`, `upload`, `parse`, `exec`, `*.sql`, etc.).

## Tested versions

The scanner versions the skill was last exercised against. Drift past these is expected and almost always fine; `install.sh --check` is the live source of truth for what's actually on the system. If a finding looks wrong, the first thing to check is whether the tool version has shifted enough that its rule IDs or output schema changed.

| Tool         | Last-tested version |
| ------------ | ------------------- |
| semgrep      | 1.164.0             |
| bandit       | 1.9.4               |
| gitleaks     | 8.30.1              |
| trufflehog   | (not installed locally; latest stable) |
| trivy        | 0.70.0              |
| osv-scanner  | 2.3.8               |
| pip-audit    | 2.10.0              |
| zizmor       | latest stable (Trail of Bits release, May 2026) |
| hadolint     | latest stable       |
| checkov      | latest stable       |
| syft / grype | latest stable       |
| njsscan      | latest stable       |
| MCP server   | this repo, current commit |

Update this table when a known-good upgrade lands, not on every release.
