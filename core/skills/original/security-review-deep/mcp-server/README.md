# security-advisories MCP server

Live vulnerability, exploit-intelligence, and package-health lookups for
any MCP client (Claude Code, Claude Desktop, or any other MCP-aware
host). Pairs with the `security-review-deep` skill in this repo but
works standalone.

The server's job is grounding. LLMs hallucinate CVE IDs, invent CVSS
scores, misstate KEV membership, and pick upgrade targets from training
data that's already months stale. This server fronts six authoritative
sources behind a small set of well-typed tools so the model can cite
real data with a `source` and `fetched_at` instead of inventing it.

## Data sources

| Source        | Used by                                                   | Best for                                                            |
| ------------- | --------------------------------------------------------- | ------------------------------------------------------------------- |
| OSV.dev       | `check_package`, `check_dependencies_bulk`, `latest_safe_version` | "Is this package@version vulnerable?" + per-advisory fix-version data |
| GitHub GHSA   | `ghsa_get`, `ghsa_search`                                  | Rich advisory metadata, CVSS vectors, patched ranges                |
| NVD           | `lookup_cve`, `recent_critical_cves`, `composite_risk`     | Canonical CVE record. As of April 2026, NVD enriches only ~15-20% of incoming CVEs (KEV-prioritized); treat as supplementary, not primary. |
| CISA KEV      | `kev_lookup`, `composite_risk`                             | "Is this CVE being weaponized in the wild *right now*?"             |
| FIRST EPSS    | `epss_score`, `composite_risk`                             | Exploit-prediction probability for the next 30 days (0.0–1.0)       |
| PyPI / npm registry | `package_health`                                     | Maintainer / release-cadence / abandonware signals                  |

## The 11 tools

Every tool returns a dict that includes `source` (which upstream the
data came from) and `fetched_at` (ISO timestamp) so the report can
cite provenance. Bad inputs raise `ValueError`; missing-upstream data
returns a structured `error` field rather than throwing.

### Vulnerability lookups (OSV-backed)

**`check_package(ecosystem, name, version=None)`** — does this exact
package (and optionally version) have known vulnerabilities? OSV
covers PyPI, npm, crates.io, Go vuln DB, Maven, NuGet, RubyGems,
Packagist, Pub, Hex, SwiftURL, ConanCenter, plus distro feeds
(Debian / Ubuntu / Alpine).

```python
await check_package("pip", "requests", "2.19.1")
# → {
#     "package": "requests",
#     "ecosystem": "PyPI",
#     "version": "2.19.1",
#     "vulnerability_count": 7,
#     "vulnerabilities": [
#       {"id": "GHSA-...", "cve_ids": ["CVE-2018-18074"],
#        "summary": "...", "severity_cvss": "7.5", "severity_type": "CVSS_V3",
#        "fixed_versions": ["2.20.0"], "published": "...",
#        "references": ["https://...", ...]},
#       ...
#     ],
#     "source": "osv.dev",
#     "fetched_at": "2026-05-28T..."
#   }
```

Checks performed:

- Ecosystem name normalised via the alias map (`pip` → `PyPI`, `node`
  → `npm`, etc.); unknown values pass through with a length cap.
- CVSS severity prefers v4 if present, then v3.1, then v3.0.
- Every advisory's `affected.ranges.events` walked for `fixed` markers
  so the model can suggest an upgrade target.

---

**`check_dependencies_bulk(dependencies)`** — same as `check_package`
but for a whole lockfile in one round trip. Capped at 1000 entries
per call.

```python
await check_dependencies_bulk([
    {"ecosystem": "pip", "name": "requests", "version": "2.19.1"},
    {"ecosystem": "pip", "name": "jinja2",   "version": "2.10"},
    {"ecosystem": "npm", "name": "lodash",   "version": "4.17.0"},
])
# → {
#     "checked": 3,
#     "vulnerable_count": 3,
#     "vulnerable": {
#       "PyPI/requests@2.19.1": [ {...}, {...} ],
#       "PyPI/jinja2@2.10":   [ {...} ],
#       "npm/lodash@4.17.0":  [ {...} ]
#     },
#     "source": "osv.dev",
#     "fetched_at": "..."
#   }
```

Implementation notes: OSV's `/querybatch` returns stubs (id only),
which the server hydrates concurrently (`asyncio.Semaphore(16)`) so
big lockfiles complete in seconds rather than minutes.

---

**`latest_safe_version(ecosystem, name, current_version)`** — given a
vulnerable package@version, return the *minimum* upgrade target that
clears every advisory currently affecting it.

```python
await latest_safe_version("pip", "requests", "2.19.1")
# → {
#     "package": "requests",
#     "current_version": "2.19.1",
#     "current_advisories": ["GHSA-...", "PYSEC-2018-28", ...],
#     "fixes_per_advisory": {
#       "GHSA-9hjg-9r4m-mvj7": ["2.32.4"],
#       "GHSA-x84v-xcm2-53pg": ["2.20.0"],
#       "PYSEC-2018-28":       ["2.20.0", "<commit-sha>"],
#       ...
#     },
#     "minimum_clear_all": "2.33.0",
#     "note": "best-effort version parser; verify against release notes"
#   }
```

How `minimum_clear_all` is computed:

1. For each advisory, collect all `fixed` markers from OSV's affected
   ranges.
2. For each advisory, find the smallest fix version *strictly greater
   than* `current_version` (per a PEP-440-ish best-effort parser).
3. Take the `max` of those per-advisory minimums. That's the smallest
   version that satisfies every advisory simultaneously.
4. Returns `null` if any advisory has no fix after `current_version`
   (e.g. a still-unpatched CVE).

---

### CVE / advisory direct lookups

**`lookup_cve(cve_id)`** — fetch the full NVD record for a CVE.

```python
await lookup_cve("CVE-2021-44228")
# → {
#     "id": "CVE-2021-44228",
#     "description": "Apache Log4j2 ...",
#     "cvss_score": 10.0,
#     "severity": "CRITICAL",
#     "cvss_vector": "CVSS:3.1/AV:N/AC:L/...",
#     "cwes": ["CWE-20", "CWE-502", "CWE-917"],
#     "published": "...",
#     "last_modified": "...",
#     "references": ["https://...", ...],
#     "source": "nvd.nist.gov"
#   }
```

CVSS preference: v4.0 → v3.1 → v3.0. Sparse responses are common since
April 2026; pair with `check_package` for software CVEs.

---

**`recent_critical_cves(days=7, keyword=None)`** — list new HIGH /
CRITICAL CVEs published in the last N days. NVD caps `days` at 120.

```python
await recent_critical_cves(days=14, keyword="openssl")
# → {
#     "days_searched": 14,
#     "keyword": "openssl",
#     "count": 3,
#     "cves": [ {...}, {...}, {...} ],
#     "source": "nvd.nist.gov"
#   }
```

Useful for the "did anything new drop affecting us?" question. Two
NVD calls under the hood (one for HIGH, one for CRITICAL), merged
and sorted newest-first.

---

**`ghsa_get(ghsa_id)`** — full GitHub Security Advisory by id.

```python
await ghsa_get("GHSA-jfh8-c2jp-5v3q")
# → {
#     "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
#     "cve_id": "CVE-2021-44228",
#     "summary": "Remote code injection in Log4j",
#     "description": "...",
#     "severity": "critical",
#     "cvss_score": 10.0,
#     "cvss_vector": "...",
#     "vulnerabilities": [
#       {"package": "org.apache.logging.log4j:log4j-core",
#        "ecosystem": "Maven",
#        "vulnerable_version_range": "...",
#        "patched_versions": "2.17.1"},
#       ...
#     ],
#     "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q"
#   }
```

---

**`ghsa_search(query="", ecosystem=None, severity=None, limit=10)`** —
best-effort search of GitHub advisories.

```python
await ghsa_search("CVE-2021-44228")           # exact CVE forward
await ghsa_search("GHSA-jfh8-c2jp-5v3q")      # exact GHSA forward
await ghsa_search("xss", ecosystem="npm", severity="critical", limit=5)
```

**Honest caveat**: GitHub's REST advisory endpoint has no full-text
search and returns advisories newest-first. A free-text query like
`"log4j"` will MISS historical advisories. For "every advisory
affecting package X," use `check_package(ecosystem, name)` instead.
This tool is most reliable for direct CVE-id / GHSA-id pass-through.

---

### Triage signals

**`kev_lookup(cve_id)`** — is this CVE in CISA's Known Exploited
Vulnerabilities catalog?

```python
await kev_lookup("CVE-2021-44228")
# → {
#     "cve_id": "CVE-2021-44228",
#     "in_kev": true,
#     "vendor_project": "Apache",
#     "product": "Log4j2",
#     "vulnerability_name": "Apache Log4j2 RCE",
#     "date_added": "2021-12-10",
#     "short_description": "...",
#     "required_action": "Apply updates per vendor instructions",
#     "due_date": "2021-12-24",
#     "known_ransomware_use": "Known",
#     "cwes": ["CWE-20", ...],
#     "source": "cisa.gov/kev"
#   }
```

KEV is the strongest "this is actively being exploited" signal
available. By skill convention, KEV membership bumps a finding to
**Critical** regardless of CVSS. The full ~1600-entry catalog is
cached for one hour per process.

---

**`epss_score(cve_id)`** — FIRST.org's EPSS exploit-prediction score.

```python
await epss_score("CVE-2021-44228")
# → {
#     "cve_id": "CVE-2021-44228",
#     "score": 0.94358,        # probability of exploitation in next 30 days
#     "percentile": 0.99963,   # rank vs all scored CVEs
#     "as_of": "2026-05-27",
#     "source": "first.org/epss"
#   }
```

Skill convention: `score >= 0.5` bumps a finding to at least **High**
regardless of CVSS.

---

**`composite_risk(cve_id)`** — combined triage signal: CVSS (NVD) +
EPSS (FIRST.org) + KEV (CISA) + a derived 0-100 composite score. Use
this to rank findings instead of re-deriving the math in prose.

```python
await composite_risk("CVE-2021-44228")
# → {
#     "cve_id": "CVE-2021-44228",
#     "composite_score": 100.0,
#     "triage_bucket": "Critical",
#     "cvss_score": 10.0,
#     "cvss_severity": "CRITICAL",
#     "epss_score": 0.94358,
#     "in_kev": true,
#     "cwes": ["CWE-20", ...],
#     "description": "...",
#     "rationale": "CISA KEV: actively exploited in the wild; "
#                  "EPSS 0.94: high exploitation probability; CVSS 10.0",
#     "sources": ["nvd.nist.gov", "first.org/epss", "cisa.gov/kev"]
#   }
```

Fetches NVD + EPSS + KEV in parallel under the hood (`asyncio.gather`).

#### Composite scoring rule

| Bucket    | Composite | Trigger conditions                                       |
| --------- | --------- | -------------------------------------------------------- |
| Critical  | ≥ 90      | In CISA KEV, OR CVSS 9+ with EPSS ≥ 0.5                  |
| High      | 70-89     | EPSS ≥ 0.5, OR CVSS 7-9                                  |
| Medium    | 40-69     | CVSS 4-7                                                 |
| Low       | 1-39      | CVSS < 4                                                 |
| Unknown   | 0         | No NVD / EPSS / KEV data available                       |

Weighting:

- KEV membership floors composite at **90** (Critical), regardless of CVSS.
- EPSS ≥ 0.5 floors composite at **70** (High).
- Otherwise composite = `max(CVSS * 10, EPSS * 100)`.

This is the heuristic that lets the skill compress 32 dep CVEs down
to "3 Critical, 7 High, 6 Medium, ..." instead of dumping the whole
list as urgent.

---

### Package health

**`package_health(ecosystem, name)`** — maintenance signals for a
package: latest release date, days since release, total releases,
maintainer count, repository URL, yanked / archived status, plus a
`signals` list of warnings.

```python
await package_health("pip", "requests")
# → {
#     "ecosystem": "PyPI",
#     "name": "requests",
#     "latest_version": "2.34.2",
#     "latest_release_at": "2026-05-14T19:25:26",
#     "days_since_release": 13,
#     "total_releases": 163,
#     "repository_url": "https://github.com/psf/requests",
#     "summary": "...",
#     "yanked": false,
#     "signals": [],   # active package; no concerns
#     "source": "pypi.org"
#   }

await package_health("pip", "pyaes")    # an abandoned crypto package
# → {
#     ...
#     "latest_release_at": "2017-09-20T21:17:54",
#     "days_since_release": 3171,
#     "signals": ["no release in 3171 days"],
#     ...
#   }
```

Signals raised:

| Signal                                  | Trigger                                              |
| --------------------------------------- | ---------------------------------------------------- |
| `"no release in N days"`                | latest release older than 2 years (730 days)         |
| `"very few releases (typosquat risk)"`  | fewer than 3 versions ever published                 |
| `"single maintainer"` *(npm only)*      | exactly one maintainer entry                         |
| `"latest version yanked"` *(PyPI only)* | the latest version is marked yanked                  |

Supported ecosystems: **PyPI**, **npm**. Other ecosystems return a
stub with `"note": "package_health not yet supported for ecosystem X"`
rather than failing.

This is the senior-reviewer "should I depend on this at all?" check
that pairs with the "is this version vulnerable?" check.

## Defensive limits and caching

These are circuit-breakers, not security boundaries. The upstreams
queried here are all trusted (cisa.gov, nist.gov, first.org, osv.dev,
api.github.com, pypi.org, registry.npmjs.org); the caps just prevent a
runaway response from blowing up the agent's context window or memory.

| Constant                    | Value      | Effect                                                                       |
| --------------------------- | ---------- | ---------------------------------------------------------------------------- |
| `MAX_RESPONSE_BYTES`        | 10 MiB     | Any upstream JSON body larger than this raises `ValueError` per call         |
| `MAX_STR_LEN`               | 256 chars  | String inputs (keywords, version strings, summaries) are truncated           |
| `MAX_BULK_DEPS`             | 1000       | `check_dependencies_bulk` rejects larger lockfiles                           |
| `MAX_RECENT_DAYS`           | 120 days   | `recent_critical_cves` clamps its `days` arg (NVD API hard limit)            |
| `OSV_HYDRATE_CONCURRENCY`   | 16         | Parallel-fetch budget inside `check_dependencies_bulk`                       |
| KEV cache TTL               | 3600 s     | KEV catalog (~2 MB JSON) cached for one hour per process; lazy refresh       |
| HTTP timeouts               | 20-30 s    | Per-request timeout on every upstream call                                   |

## Input validation

Every tool validates its inputs before forwarding to the upstream:

| Field             | Rule                                                                 | Raises if violated |
| ----------------- | -------------------------------------------------------------------- | ------------------ |
| `cve_id`          | `^CVE-\d{4}-\d{4,7}$` (case-insensitive, uppercased on return)       | `ValueError`       |
| `ghsa_id`         | `^GHSA(-[0-9a-z]{4}){3}$` (case-insensitive, uppercased on return)   | `ValueError`       |
| `ecosystem`       | normalized via alias map (pip → PyPI, node → npm, ...); unknowns capped to 256 chars | `ValueError` on empty / non-string |
| `name` (package)  | `^[A-Za-z0-9._@/+-]{1,200}$`                                          | `ValueError`       |
| `version`         | capped at 256 chars                                                  | (truncated, not raised) |
| `dependencies` list | length ≤ 1000                                                      | `ValueError`       |
| `days`            | positive int, clamped to 120                                         | `ValueError` on non-int / ≤ 0 |
| `severity` filter | `low` / `medium` / `high` / `critical` only                          | `ValueError`       |
| `vuln_id` (internal, for `_fetch_osv_by_id`) | no `/` or `..`                            | returns `None`     |

The point of all this is that a malformed model-generated argument
fails fast with a clear error instead of being silently forwarded and
either being rejected by the upstream with a confusing message or, in
the worst case, being misinterpreted.

## Install

```bash
cd skills/security-review-deep/mcp-server
uv sync                    # or: pip install -e .
```

Register with Claude Code (user scope, so it's available in every
project):

```bash
claude mcp add --scope user security-advisories -- \
    uv --directory "$(pwd)" run mcp_security_server.py
```

The repo's top-level `install.sh` does this automatically when run
with the security-tools prompt accepted.

For Claude Desktop, add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "security-advisories": {
      "command": "uv",
      "args": ["--directory", "/abs/path/to/mcp-server", "run", "mcp_security_server.py"]
    }
  }
}
```

## Optional environment

| Variable        | Effect                                                       |
| --------------- | ------------------------------------------------------------ |
| `GITHUB_TOKEN`  | Lifts GHSA REST rate limit from 60/hr → 5000/hr. No scopes required. |
| `NVD_API_KEY`   | Lifts NVD rate limit (request a free key at nvd.nist.gov/developers/request-an-api-key) |

Neither is required for normal use. CISA KEV, FIRST EPSS, OSV.dev,
PyPI, and the npm registry all have no auth.

If you don't set `NVD_API_KEY` and you fan out a lot of CVE lookups in
quick succession (e.g. on a big lockfile), expect to see 429 responses
on some NVD calls. The skill's run-summary JSON records these so the
absence is visible, but `composite_risk` will still return EPSS + KEV
data (it parallel-fetches all three sources and tolerates partial
failure of any one).

## Provenance

Every tool's return dict includes:

- `source` — which upstream the data came from (`"osv.dev"`,
  `"nvd.nist.gov"`, `"cisa.gov/kev"`, `"first.org/epss"`,
  `"api.github.com/advisories"`, `"pypi.org"`, `"registry.npmjs.org"`)
- `fetched_at` — ISO 8601 UTC timestamp of the fetch

This is how the skill's report cites every claim and how the model
notices stale caches. Never strip these in the rendered report.

## Failure modes the server handles

| Situation                                        | Behavior                                                              |
| ------------------------------------------------ | --------------------------------------------------------------------- |
| Upstream 404                                     | Returns `None` from the helper; tool returns a structured `error` dict |
| Upstream 429                                     | Raised through; skill logs it in the run-summary                       |
| Upstream returns body > 10 MiB                   | `ValueError` raised; never silently truncated                         |
| CVE/GHSA id malformed                            | `ValueError` before any HTTP call                                     |
| NVD has no record for a CVE (common since April 2026) | Returns `{"error": "No CVE found for X", "id": "X"}`              |
| EPSS has no score yet                            | Returns `{"score": null, "note": "no EPSS score yet"}`                |
| Bulk hydration partial failure                   | Failed entries silently dropped from the result; successful ones returned |
| KEV cache stale (older than 1 hour)              | Re-fetched lazily on the next call                                    |

## Testing

A live smoke test lives at `../tests/run_integration.sh`. It calls the
server's tools against stable identifiers (Log4Shell in KEV, `requests`
on PyPI) and checks structural invariants. It hits live APIs, so it's a
manual check — run it after changing this file; network failures are
reported as skips, not failures. See `../tests/README.md`.

```bash
../tests/run_integration.sh
# Result: pass=8 fail=0 skip=0
```

Bandit and Semgrep should stay clean against `mcp_security_server.py`:

```bash
bandit -ll -ii mcp_security_server.py
semgrep --config=p/security-audit --config=p/owasp-top-ten mcp_security_server.py
```

## Why six sources

Each source covers a different question the skill needs to answer:

1. **Is the package vulnerable at this version?** → OSV
2. **What does the CVE actually say?** → NVD (when enriched) or GHSA
3. **Is anyone exploiting it right now?** → CISA KEV
4. **What's the probability of weaponization in the next 30 days?** → EPSS
5. **What should I upgrade to?** → OSV via `latest_safe_version`
6. **Is this package even maintained?** → PyPI / npm registry via `package_health`

A model with only one of these will systematically over- or
under-react. CVSS-only triage treats every 9.8 as the world ending.
OSV-only triage drowns the user in 30 dep advisories with no priority
signal. NVD-only triage misses 80% of post-April-2026 CVEs entirely.
The combination is what makes the triage usable.
