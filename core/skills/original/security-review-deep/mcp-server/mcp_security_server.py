"""
Security Advisories MCP Server
==============================

Exposes live vulnerability lookups to any MCP client (Claude Code, Claude
Desktop, etc.). Queries six complementary sources:

  - OSV.dev      Google's aggregator (GHSA, PyPI, RustSec, npm, Go vuln
                 DB, OSS-Fuzz). Best for "is this package@version
                 vulnerable?"
  - GitHub GHSA  Authoritative advisory data with CVSS, fix versions,
                 patched ranges. Better metadata than NVD for packages.
  - NVD          Canonical CVE database. NVD enrichment dropped to
                 ~15-20% of CVEs in April 2026 (KEV-prioritized), so
                 don't rely on it alone.
  - CISA KEV     Known Exploited Vulnerabilities catalog. Strongest
                 signal that a CVE is being weaponized in the wild.
  - EPSS         FIRST.org's exploit-prediction score (0.0-1.0 over the
                 next 30 days).
  - Composite    CVSS + EPSS + KEV folded into one 0-100 triage score.

Run with:   uv run mcp_security_server.py
            (or: python mcp_security_server.py)

Add to Claude Code:
    claude mcp add security-advisories -- python /path/to/mcp_security_server.py

Optional env vars:
    GITHUB_TOKEN   bumps GHSA rate limit from 60/hr to 5000/hr
    NVD_API_KEY    bumps NVD rate limit (request at nvd.nist.gov)
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("security-advisories")

# --- API endpoints --------------------------------------------------------

OSV_API = "https://api.osv.dev/v1"
GHSA_REST = "https://api.github.com"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
EPSS_API = "https://api.first.org/data/v1/epss"

# --- Defensive limits -----------------------------------------------------
# Circuit-breakers, not security boundaries. The upstreams here are
# trusted; the caps just prevent a runaway response from blowing up the
# agent's context window or memory.

MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB
MAX_STR_LEN = 256
MAX_BULK_DEPS = 1000
MAX_RECENT_DAYS = 120  # NVD API hard limit
OSV_HYDRATE_CONCURRENCY = 16

# --- Input validators -----------------------------------------------------

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA(-[0-9a-z]{4}){3}$", re.IGNORECASE)
_PKG_NAME_RE = re.compile(r"^[A-Za-z0-9._@/+-]{1,200}$")

# OSV's ecosystem identifiers don't always match what users type. Map
# common package-manager names to OSV ecosystem strings. Unknown values
# pass through with a length cap (OSV will return a 400 for nonsense).
ECOSYSTEM_ALIASES = {
    "pip": "PyPI", "pypi": "PyPI", "python": "PyPI",
    "npm": "npm", "node": "npm", "nodejs": "npm",
    "cargo": "crates.io", "rust": "crates.io",
    "go": "Go", "golang": "Go",
    "maven": "Maven", "java": "Maven",
    "nuget": "NuGet", "dotnet": "NuGet",
    "gem": "RubyGems", "ruby": "RubyGems",
    "composer": "Packagist", "php": "Packagist",
    "pub": "Pub", "dart": "Pub",
    "hex": "Hex", "elixir": "Hex",
    "swift": "SwiftURL", "swiftpm": "SwiftURL",
    "conan": "ConanCenter",
}


def _check_cve(cve_id: str) -> str:
    if not isinstance(cve_id, str) or not _CVE_RE.match(cve_id.strip()):
        raise ValueError(f"invalid CVE id: {cve_id!r}; expected CVE-YYYY-NNNN")
    return cve_id.strip().upper()


def _check_ghsa(ghsa_id: str) -> str:
    if not isinstance(ghsa_id, str) or not _GHSA_RE.match(ghsa_id.strip()):
        raise ValueError(
            f"invalid GHSA id: {ghsa_id!r}; expected GHSA-xxxx-xxxx-xxxx"
        )
    return ghsa_id.strip().upper()


def _check_ecosystem(name: str) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ValueError("ecosystem must be a non-empty string")
    return ECOSYSTEM_ALIASES.get(name.lower(), _cap(name, MAX_STR_LEN))


def _check_pkg_name(name: str) -> str:
    if not isinstance(name, str) or not _PKG_NAME_RE.match(name):
        raise ValueError(f"invalid package name: {name!r}")
    return name


def _cap(s: Any, n: int = MAX_STR_LEN) -> str:
    if s is None:
        return ""
    return str(s)[:n]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --- HTTP plumbing --------------------------------------------------------


def _gh_headers() -> dict[str, str]:
    h = {"Accept": "application/vnd.github+json"}
    if t := os.environ.get("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {t}"
    return h


def _nvd_headers() -> dict[str, str]:
    h: dict[str, str] = {}
    if k := os.environ.get("NVD_API_KEY"):
        h["apiKey"] = k
    return h


async def _get_json(
    client: httpx.AsyncClient, url: str, **kwargs
) -> dict | list | None:
    """GET + JSON decode with a body-size circuit breaker. Returns None on
    404 so callers can branch on "not found"."""
    r = await client.get(url, **kwargs)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    if len(r.content) > MAX_RESPONSE_BYTES:
        raise ValueError(
            f"response from {url} exceeded {MAX_RESPONSE_BYTES} bytes"
        )
    return r.json()


async def _post_json(
    client: httpx.AsyncClient, url: str, body: dict
) -> dict:
    r = await client.post(url, json=body)
    r.raise_for_status()
    if len(r.content) > MAX_RESPONSE_BYTES:
        raise ValueError(
            f"response from {url} exceeded {MAX_RESPONSE_BYTES} bytes"
        )
    return r.json()


# --- KEV catalog cache ----------------------------------------------------
# The KEV catalog is ~2 MB JSON updated daily. Refetching per call is
# wasteful; cache for an hour and rebuild a CVE-keyed index on load.

_KEV_CACHE: dict[str, Any] = {"fetched_at": 0.0, "by_cve": {}}
_KEV_TTL = 3600.0


async def _load_kev(client: httpx.AsyncClient) -> dict[str, dict]:
    now = time.time()
    if _KEV_CACHE["by_cve"] and (now - _KEV_CACHE["fetched_at"]) < _KEV_TTL:
        return _KEV_CACHE["by_cve"]
    data = await _get_json(client, KEV_URL)
    if not data:
        # Failed fetch: serve the stale index rather than caching an empty
        # one, which would silently answer "not in KEV" for the next hour.
        return _KEV_CACHE["by_cve"]
    by_cve = {
        v["cveID"]: v for v in data.get("vulnerabilities", [])
    }
    _KEV_CACHE.update(fetched_at=now, by_cve=by_cve)
    return by_cve


# --- Tools: OSV-based package lookups -------------------------------------


@mcp.tool()
async def check_package(
    ecosystem: str,
    name: str,
    version: str | None = None,
) -> dict[str, Any]:
    """Check whether a specific package (and optionally version) has known
    vulnerabilities via OSV.dev.

    Args:
        ecosystem: Package manager. One of: pip, npm, cargo, go, maven,
                   nuget, gem, composer, pub, hex, swift, conan
                   (aliases accepted).
        name:      Package name (e.g. "requests", "lodash", "log4j-core").
        version:   Optional exact version. If omitted, returns every
                   known advisory for the package across all versions.

    Returns:
        dict with keys: package, ecosystem, version, vulnerability_count,
        vulnerabilities (each with id, summary, severity, fixed versions,
        references), source, fetched_at.
    """
    eco = _check_ecosystem(ecosystem)
    name = _check_pkg_name(name)
    if version is not None:
        version = _cap(version)

    query: dict[str, Any] = {"package": {"name": name, "ecosystem": eco}}
    if version:
        query["version"] = version

    async with httpx.AsyncClient(timeout=20) as client:
        data = await _post_json(client, f"{OSV_API}/query", query)

    vulns = data.get("vulns", []) or []
    return {
        "package": name,
        "ecosystem": eco,
        "version": version,
        "vulnerability_count": len(vulns),
        "vulnerabilities": [_summarize_osv(v) for v in vulns],
        "source": "osv.dev",
        "fetched_at": _now(),
    }


@mcp.tool()
async def check_dependencies_bulk(
    dependencies: list[dict[str, str]],
) -> dict[str, Any]:
    """Check a list of dependencies in one round trip. Use this for a
    full lockfile instead of N check_package calls.

    Args:
        dependencies: List of {"ecosystem": ..., "name": ..., "version": ...}
                      dicts. version is optional per entry. Capped at
                      1000 entries.

    Returns:
        dict mapping "ecosystem/name@version" -> list of vulnerability
        summaries. Only includes entries that have at least one
        vulnerability.
    """
    if not isinstance(dependencies, list):
        raise ValueError("dependencies must be a list")
    if len(dependencies) > MAX_BULK_DEPS:
        raise ValueError(
            f"too many dependencies ({len(dependencies)} > {MAX_BULK_DEPS})"
        )

    queries: list[dict[str, Any]] = []
    keys: list[str] = []
    for dep in dependencies:
        eco = _check_ecosystem(dep["ecosystem"])
        nm = _check_pkg_name(dep["name"])
        ver = _cap(dep.get("version")) or None
        q: dict[str, Any] = {"package": {"name": nm, "ecosystem": eco}}
        if ver:
            q["version"] = ver
        queries.append(q)
        keys.append(f"{eco}/{nm}@{ver or '*'}")

    async with httpx.AsyncClient(timeout=30) as client:
        data = await _post_json(
            client, f"{OSV_API}/querybatch", {"queries": queries}
        )

        # Batch results are stubs (id only). Hydrate concurrently;
        # the previous version did this serially and was slow on big
        # lockfiles.
        stub_pairs: list[tuple[int, str]] = []
        for idx, result in enumerate(data.get("results", []) or []):
            for stub in result.get("vulns", []) or []:
                stub_pairs.append((idx, stub["id"]))

        full_by_id: dict[str, dict] = {}
        if stub_pairs:
            unique_ids = list({sid for _, sid in stub_pairs})
            sem = asyncio.Semaphore(OSV_HYDRATE_CONCURRENCY)

            async def fetch(sid: str) -> tuple[str, dict | None]:
                async with sem:
                    return sid, await _fetch_osv_by_id(client, sid)

            for res in await asyncio.gather(
                *(fetch(s) for s in unique_ids), return_exceptions=True
            ):
                # A single OSV 429/timeout must not sink the whole lockfile
                # scan: drop the failed entry, keep the rest. The isinstance
                # guard covers both raised exceptions and 404 (None) results.
                if isinstance(res, tuple):
                    sid, full = res
                    if isinstance(full, dict):
                        full_by_id[sid] = full

    results: dict[str, list[dict]] = {}
    for idx, sid in stub_pairs:
        full = full_by_id.get(sid)
        if full:
            results.setdefault(keys[idx], []).append(_summarize_osv(full))

    return {
        "checked": len(dependencies),
        "vulnerable_count": len(results),
        "vulnerable": results,
        "source": "osv.dev",
        "fetched_at": _now(),
    }


@mcp.tool()
async def latest_safe_version(
    ecosystem: str,
    name: str,
    current_version: str,
) -> dict[str, Any]:
    """For a vulnerable package@version, suggest minimum upgrade targets.
    Returns each advisory's fix versions plus a best-effort smallest
    version that clears every advisory currently affecting this version.

    Args:
        ecosystem:       Package manager (aliases accepted).
        name:            Package name.
        current_version: The version in use (and presumably vulnerable).
    """
    eco = _check_ecosystem(ecosystem)
    name = _check_pkg_name(name)
    current_version = _cap(current_version)

    query = {
        "package": {"name": name, "ecosystem": eco},
        "version": current_version,
    }
    async with httpx.AsyncClient(timeout=20) as client:
        data = await _post_json(client, f"{OSV_API}/query", query)

    vulns = data.get("vulns", []) or []
    if not vulns:
        return {
            "package": name,
            "ecosystem": eco,
            "current_version": current_version,
            "current_advisories": [],
            "note": "current version has no known advisories per OSV",
            "source": "osv.dev",
            "fetched_at": _now(),
        }

    fixes_per_vuln: dict[str, list[str]] = {}
    for v in vulns:
        vid = v.get("id", "")
        fixes: set[str] = set()
        for affected in v.get("affected", []) or []:
            for r in affected.get("ranges", []) or []:
                for ev in r.get("events", []) or []:
                    if "fixed" in ev:
                        fixes.add(ev["fixed"])
        fixes_per_vuln[vid] = sorted(fixes, key=_version_key)

    # Smallest version that clears every advisory: for each advisory,
    # find the smallest fix strictly after current_version, then take
    # the max of those minimums.
    cur_key = _version_key(current_version)
    per_vuln_min: list[str | None] = []
    for fixes in fixes_per_vuln.values():
        candidates = [f for f in fixes if _version_key(f) > cur_key]
        per_vuln_min.append(candidates[0] if candidates else None)

    if all(per_vuln_min):
        minimum_clear_all = max(per_vuln_min, key=_version_key)
    else:
        minimum_clear_all = None

    return {
        "package": name,
        "ecosystem": eco,
        "current_version": current_version,
        "current_advisories": list(fixes_per_vuln.keys()),
        "fixes_per_advisory": fixes_per_vuln,
        "minimum_clear_all": minimum_clear_all,
        "note": (
            "minimum_clear_all is a best-effort suggestion via a "
            "best-effort version parser; verify against the package's "
            "release notes before upgrading"
        ),
        "source": "osv.dev",
        "fetched_at": _now(),
    }


# --- Tools: NVD ----------------------------------------------------------


@mcp.tool()
async def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Fetch full details for a specific CVE by ID from the NVD.

    NVD coverage dropped sharply in April 2026: only ~15-20% of incoming
    CVEs receive full enrichment, prioritized by KEV membership and
    federal use. If this returns sparse data, also try check_package for
    software CVEs, or accept that NVD just doesn't have it yet.
    """
    cve_id = _check_cve(cve_id)
    async with httpx.AsyncClient(timeout=20) as client:
        data = await _get_json(
            client,
            NVD_API,
            params={"cveId": cve_id},
            headers=_nvd_headers(),
        )
    items = (data or {}).get("vulnerabilities", []) if data else []
    if not items:
        return {
            "error": f"No CVE found for {cve_id}",
            "id": cve_id,
            "source": "nvd.nist.gov",
            "fetched_at": _now(),
        }
    summary = _summarize_nvd(items[0]["cve"])
    summary["source"] = "nvd.nist.gov"
    summary["fetched_at"] = _now()
    return summary


@mcp.tool()
async def recent_critical_cves(
    days: int = 7,
    keyword: str | None = None,
) -> dict[str, Any]:
    """List recently published HIGH/CRITICAL CVEs from the NVD. Useful
    for "what new zero-days dropped this week?" or filtering by a
    technology you depend on.

    Args:
        days:    Look back this many days (max 120; NVD API limit).
        keyword: Optional case-insensitive substring against CVE
                 descriptions (e.g. "openssl", "nginx", "kubernetes").
    """
    if not isinstance(days, int) or days < 1:
        raise ValueError("days must be a positive integer")
    days = min(days, MAX_RECENT_DAYS)
    if keyword is not None:
        keyword = _cap(keyword)

    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    base = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    if keyword:
        base["keywordSearch"] = keyword

    results: list[dict[str, Any]] = []
    total_available = 0
    truncated = False
    async with httpx.AsyncClient(timeout=30) as client:
        # NVD only accepts one severity at a time.
        for sev in ("HIGH", "CRITICAL"):
            params = {**base, "cvssV3Severity": sev}
            data = await _get_json(
                client, NVD_API, params=params, headers=_nvd_headers()
            ) or {}
            page = data.get("vulnerabilities", []) or []
            for item in page:
                results.append(_summarize_nvd(item["cve"]))
            # No pagination: a busy window has more than one page of each
            # severity. Surface that instead of returning a complete-looking
            # subset, the way ghsa_search does.
            total_available += data.get("totalResults", len(page))
            if data.get("totalResults", 0) > len(page):
                truncated = True

    results.sort(key=lambda x: x.get("published", ""), reverse=True)
    return {
        "days_searched": days,
        "keyword": keyword,
        "count": len(results),
        "total_available": total_available,
        "result_may_be_truncated": truncated,
        "cves": results,
        "source": "nvd.nist.gov",
        "fetched_at": _now(),
    }


# --- Tools: GHSA ---------------------------------------------------------


@mcp.tool()
async def ghsa_get(ghsa_id: str) -> dict[str, Any]:
    """Fetch a single GitHub Security Advisory by GHSA ID. Use this when
    you have a GHSA-xxxx-xxxx-xxxx identifier and want the full record
    (CVSS, patched ranges, affected packages, references)."""
    ghsa_id = _check_ghsa(ghsa_id)
    async with httpx.AsyncClient(timeout=20) as client:
        a = await _get_json(
            client,
            f"{GHSA_REST}/advisories/{ghsa_id}",
            headers=_gh_headers(),
        )
    if not a:
        return {
            "error": f"No advisory found for {ghsa_id}",
            "ghsa_id": ghsa_id,
            "source": "api.github.com/advisories",
            "fetched_at": _now(),
        }
    summary = _summarize_ghsa(a)
    summary["source"] = "api.github.com/advisories"
    summary["fetched_at"] = _now()
    return summary


@mcp.tool()
async def ghsa_search(
    query: str = "",
    ecosystem: str | None = None,
    severity: str | None = None,
    limit: int = 10,
) -> dict[str, Any]:
    """Search GitHub Security Advisories. Forwards exact CVE / GHSA ids
    to the matching REST field filter; otherwise falls back to a
    best-effort substring search over the newest 100 advisories that
    match the ecosystem + severity filters.

    Caveat: GitHub's REST advisory endpoint has no full-text search,
    and results are sorted newest-first. A free-text query like
    "log4j" will MISS historical advisories. For "find every advisory
    affecting package X," use check_package(ecosystem, name) instead;
    for a known CVE or GHSA id, pass it directly here or use
    ghsa_get(ghsa_id).

    Args:
        query:     Free-text (best-effort), or a CVE id, or a GHSA id.
        ecosystem: Optional package ecosystem filter (pip, npm, ...).
        severity:  Optional severity filter: low | medium | high | critical.
        limit:     Max advisories returned (clamped to 50).
    """
    query = _cap(query)
    limit = max(1, min(int(limit), 50))

    qs = query.strip()
    direct_id = _CVE_RE.match(qs) or _GHSA_RE.match(qs)
    # GitHub's REST API has no free-text search field. When the caller
    # passes a non-id query, fetch a full 100-result page and substring-
    # filter on the client; otherwise just fetch up to `limit`.
    params: dict[str, Any] = {
        "per_page": limit if direct_id or not query else 100,
        "type": "reviewed",
    }

    if _CVE_RE.match(qs):
        params["cve_id"] = qs.upper()
    elif _GHSA_RE.match(qs):
        params["ghsa_id"] = qs.upper()

    if ecosystem:
        eco = _check_ecosystem(ecosystem)
        # GitHub's ecosystem filter is lowercase.
        params["ecosystem"] = eco.lower()
    if severity:
        sev = severity.lower()
        if sev not in {"low", "medium", "high", "critical"}:
            raise ValueError(
                "severity must be one of: low, medium, high, critical"
            )
        params["severity"] = sev

    async with httpx.AsyncClient(timeout=20) as client:
        advisories = await _get_json(
            client,
            f"{GHSA_REST}/advisories",
            params=params,
            headers=_gh_headers(),
        )
    advisories = advisories or []

    # If we didn't apply a direct-id filter and the caller passed a
    # free-text query, substring-filter the current page and warn that
    # more matches may exist further in.
    truncated = False
    if query and "cve_id" not in params and "ghsa_id" not in params:
        q = query.lower()
        filtered = [
            a for a in advisories
            if q in (a.get("summary") or "").lower()
            or q in (a.get("description") or "").lower()
        ]
        truncated = len(advisories) == limit and len(filtered) < len(advisories)
        advisories = filtered[:limit]

    return {
        "query": query,
        "ecosystem": ecosystem,
        "severity": severity,
        "count": len(advisories),
        "advisories": [_summarize_ghsa(a) for a in advisories],
        "result_may_be_truncated": truncated,
        "source": "api.github.com/advisories",
        "fetched_at": _now(),
        "note": (
            "Use ghsa_get for the full record of a single advisory. "
            "Pass a CVE or GHSA id as `query` for an exact lookup."
        ),
    }


# --- Tools: KEV / EPSS / composite triage --------------------------------


@mcp.tool()
async def kev_lookup(cve_id: str) -> dict[str, Any]:
    """Check whether a CVE appears in CISA's Known Exploited Vulnerabilities
    catalog. KEV membership is the strongest available signal that a CVE
    is being actively weaponized; treat KEV findings as Critical
    regardless of CVSS score."""
    cve_id = _check_cve(cve_id)
    async with httpx.AsyncClient(timeout=30) as client:
        by_cve = await _load_kev(client)
    entry = by_cve.get(cve_id)
    if not entry:
        return {
            "cve_id": cve_id,
            "in_kev": False,
            "source": "cisa.gov/kev",
            "fetched_at": _now(),
        }
    return {
        "cve_id": cve_id,
        "in_kev": True,
        "vendor_project": entry.get("vendorProject"),
        "product": entry.get("product"),
        "vulnerability_name": entry.get("vulnerabilityName"),
        "date_added": entry.get("dateAdded"),
        "short_description": _cap(entry.get("shortDescription"), 600),
        "required_action": _cap(entry.get("requiredAction"), 600),
        "due_date": entry.get("dueDate"),
        "known_ransomware_use": entry.get("knownRansomwareCampaignUse"),
        "cwes": entry.get("cwes") or [],
        "notes": _cap(entry.get("notes"), 400),
        "source": "cisa.gov/kev",
        "fetched_at": _now(),
    }


@mcp.tool()
async def epss_score(cve_id: str) -> dict[str, Any]:
    """Fetch FIRST.org's EPSS exploit-prediction score for a CVE. The
    score is a 0.0-1.0 probability that the CVE will be exploited in the
    next 30 days; percentile is its rank relative to all scored CVEs.

    Rule of thumb: EPSS >= 0.5 bumps a finding to at least High priority
    regardless of CVSS."""
    cve_id = _check_cve(cve_id)
    async with httpx.AsyncClient(timeout=20) as client:
        data = await _get_json(client, EPSS_API, params={"cve": cve_id})
    rows = (data or {}).get("data") or []
    if not rows:
        return {
            "cve_id": cve_id,
            "score": None,
            "percentile": None,
            "note": "no EPSS score yet (NVD must publish the CVE first)",
            "source": "first.org/epss",
            "fetched_at": _now(),
        }
    row = rows[0]
    return {
        "cve_id": cve_id,
        "score": float(row.get("epss") or 0.0),
        "percentile": float(row.get("percentile") or 0.0),
        "as_of": row.get("date"),
        "source": "first.org/epss",
        "fetched_at": _now(),
    }


@mcp.tool()
async def composite_risk(cve_id: str) -> dict[str, Any]:
    """Combined triage signal for a CVE: CVSS (from NVD) + EPSS + KEV
    membership, plus a derived 0-100 composite score. Use this to rank
    findings rather than re-deriving the math in prose.

    Composite weighting:
      KEV membership   floors composite at 90 (Critical)
      EPSS >= 0.5      floors composite at 70 (High)
      otherwise        max(CVSS*10, EPSS*100)
    """
    cve_id = _check_cve(cve_id)

    async with httpx.AsyncClient(timeout=30) as client:
        nvd_task = _get_json(
            client, NVD_API, params={"cveId": cve_id}, headers=_nvd_headers()
        )
        epss_task = _get_json(client, EPSS_API, params={"cve": cve_id})
        kev_task = _load_kev(client)
        nvd_data, epss_data, kev_by_cve = await asyncio.gather(
            nvd_task, epss_task, kev_task, return_exceptions=True
        )

    cvss_score: float | None = None
    severity: str | None = None
    description: str | None = None
    cwes: list[str] = []
    if isinstance(nvd_data, dict):
        items = nvd_data.get("vulnerabilities", []) or []
        if items:
            s = _summarize_nvd(items[0]["cve"])
            cvss_score = s.get("cvss_score")
            severity = s.get("severity")
            description = s.get("description")
            cwes = s.get("cwes") or []

    epss = 0.0
    if isinstance(epss_data, dict):
        rows = epss_data.get("data") or []
        if rows:
            epss = float(rows[0].get("epss") or 0.0)

    in_kev = isinstance(kev_by_cve, dict) and cve_id in kev_by_cve

    base = (cvss_score or 0.0) * 10.0
    composite = max(base, epss * 100.0)
    if epss >= 0.5:
        composite = max(composite, 70.0)
    if in_kev:
        composite = max(composite, 90.0)
    composite = round(min(composite, 100.0), 1)

    if composite >= 90:
        bucket = "Critical"
    elif composite >= 70:
        bucket = "High"
    elif composite >= 40:
        bucket = "Medium"
    elif composite > 0:
        bucket = "Low"
    else:
        bucket = "Unknown"

    return {
        "cve_id": cve_id,
        "composite_score": composite,
        "triage_bucket": bucket,
        "cvss_score": cvss_score,
        "cvss_severity": severity,
        "epss_score": epss,
        "in_kev": in_kev,
        "cwes": cwes,
        "description": description,
        "rationale": _compose_rationale(cvss_score, epss, in_kev),
        "sources": ["nvd.nist.gov", "first.org/epss", "cisa.gov/kev"],
        "fetched_at": _now(),
    }


# --- Tools: package health signals ---------------------------------------


@mcp.tool()
async def package_health(ecosystem: str, name: str) -> dict[str, Any]:
    """Lightweight maintenance signals for a package: latest release date,
    days since release, total releases, maintainer count, repository
    URL, archived / yanked status. Native support: PyPI, npm. Other
    ecosystems return a stub.

    Use this to catch abandonware (no release in 2+ years),
    single-maintainer risk, and very-new packages that might be
    typosquats. A senior reviewer asks "should I depend on this at
    all?" alongside "is this version vulnerable?"
    """
    eco = _check_ecosystem(ecosystem)
    name = _check_pkg_name(name)

    if eco == "PyPI":
        return await _package_health_pypi(name)
    if eco == "npm":
        return await _package_health_npm(name)

    return {
        "ecosystem": eco,
        "name": name,
        "note": f"package_health not yet supported for ecosystem {eco}",
        "supported_ecosystems": ["PyPI", "npm"],
        "fetched_at": _now(),
    }


# --- Helpers --------------------------------------------------------------


async def _fetch_osv_by_id(
    client: httpx.AsyncClient, vuln_id: str
) -> dict | None:
    # vuln_id comes from OSV's own response, so it's trusted-ish, but
    # cap and reject obvious path traversal anyway.
    if not isinstance(vuln_id, str) or "/" in vuln_id or ".." in vuln_id:
        return None
    return await _get_json(client, f"{OSV_API}/vulns/{_cap(vuln_id)}")


def _summarize_osv(v: dict) -> dict[str, Any]:
    # Prefer CVSS v4 if present, then v3.
    severity = None
    severity_type = None
    for kind in ("CVSS_V4", "CVSS_V3"):
        for s in v.get("severity", []) or []:
            if s.get("type") == kind:
                severity = s.get("score")
                severity_type = kind
                break
        if severity:
            break

    fixed_versions: set[str] = set()
    for affected in v.get("affected", []) or []:
        for r in affected.get("ranges", []) or []:
            for event in r.get("events", []) or []:
                if "fixed" in event:
                    fixed_versions.add(event["fixed"])

    aliases = v.get("aliases", []) or []
    cve_ids = [a for a in aliases if a.startswith("CVE-")]

    return {
        "id": v.get("id"),
        "cve_ids": cve_ids,
        "summary": v.get("summary"),
        "details": _cap(v.get("details"), 500),
        "severity_cvss": severity,
        "severity_type": severity_type,
        "fixed_versions": sorted(fixed_versions, key=_version_key),
        "published": v.get("published"),
        "references": [
            r.get("url") for r in (v.get("references") or [])[:5]
        ],
    }


def _summarize_nvd(cve: dict) -> dict[str, Any]:
    descs = cve.get("descriptions", []) or []
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

    metrics = cve.get("metrics", {}) or {}
    cvss: float | None = None
    severity: str | None = None
    vector: str | None = None
    # Prefer v4 (still rare in 2026), then v3.1, then v3.0.
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if entries := metrics.get(key):
            data = entries[0].get("cvssData", {})
            cvss = data.get("baseScore")
            severity = data.get("baseSeverity")
            vector = data.get("vectorString")
            break

    cwes: set[str] = set()
    for weakness in cve.get("weaknesses", []) or []:
        for d in weakness.get("description", []) or []:
            value = d.get("value", "")
            if value.startswith("CWE-"):
                cwes.add(value)

    return {
        "id": cve.get("id"),
        "description": _cap(desc, 600),
        "cvss_score": cvss,
        "severity": severity,
        "cvss_vector": vector,
        "cwes": sorted(cwes),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "references": [
            r.get("url") for r in (cve.get("references") or [])[:5]
        ],
    }


def _summarize_ghsa(a: dict) -> dict[str, Any]:
    cvss = a.get("cvss") or {}
    return {
        "ghsa_id": a.get("ghsa_id"),
        "cve_id": a.get("cve_id"),
        "summary": _cap(a.get("summary"), 300),
        "description": _cap(a.get("description"), 600),
        "severity": a.get("severity"),
        "cvss_score": cvss.get("score"),
        "cvss_vector": cvss.get("vector_string"),
        "published": a.get("published_at"),
        "vulnerabilities": [
            {
                "package": (v.get("package") or {}).get("name"),
                "ecosystem": (v.get("package") or {}).get("ecosystem"),
                "vulnerable_version_range": v.get("vulnerable_version_range"),
                "patched_versions": v.get("patched_versions"),
            }
            for v in (a.get("vulnerabilities") or [])
        ],
        "html_url": a.get("html_url"),
    }


def _compose_rationale(
    cvss: float | None, epss: float, in_kev: bool
) -> str:
    bits: list[str] = []
    if in_kev:
        bits.append("CISA KEV: actively exploited in the wild")
    if epss >= 0.5:
        bits.append(f"EPSS {epss:.2f}: high exploitation probability")
    elif epss > 0:
        bits.append(f"EPSS {epss:.2f}")
    if cvss is not None:
        bits.append(f"CVSS {cvss}")
    return "; ".join(bits) or "no scoring data available"


async def _package_health_pypi(name: str) -> dict[str, Any]:
    url = f"https://pypi.org/pypi/{name}/json"
    async with httpx.AsyncClient(timeout=20) as client:
        data = await _get_json(client, url)
    if not data:
        return {
            "ecosystem": "PyPI",
            "name": name,
            "error": "not found on pypi.org",
            "source": "pypi.org",
            "fetched_at": _now(),
        }

    info = data.get("info") or {}
    releases = data.get("releases") or {}
    latest_version = info.get("version")
    latest_upload = None
    if latest_version and releases.get(latest_version):
        latest_upload = (releases[latest_version][0] or {}).get("upload_time")

    days_since = _days_since_iso(latest_upload)

    repo_url = None
    purls = info.get("project_urls") or {}
    for key in ("Source", "Repository", "Homepage", "Home"):
        if purls.get(key):
            repo_url = purls[key]
            break
    repo_url = repo_url or info.get("home_page") or None

    signals = []
    if days_since is not None and days_since > 730:
        signals.append(f"no release in {days_since} days")
    if len(releases) < 3:
        signals.append("very few releases (typosquat risk)")
    if info.get("yanked"):
        signals.append("latest version yanked")

    return {
        "ecosystem": "PyPI",
        "name": name,
        "latest_version": latest_version,
        "latest_release_at": latest_upload,
        "days_since_release": days_since,
        "total_releases": len(releases),
        "repository_url": repo_url,
        "summary": _cap(info.get("summary"), 300),
        "yanked": bool(info.get("yanked")),
        "signals": signals,
        "source": "pypi.org",
        "fetched_at": _now(),
    }


async def _package_health_npm(name: str) -> dict[str, Any]:
    # Encode `/` in scoped names: @scope/foo -> @scope%2Ffoo
    encoded = name.replace("/", "%2F")
    url = f"https://registry.npmjs.org/{encoded}"
    async with httpx.AsyncClient(timeout=20) as client:
        data = await _get_json(client, url)
    if not data:
        return {
            "ecosystem": "npm",
            "name": name,
            "error": "not found on registry.npmjs.org",
            "source": "registry.npmjs.org",
            "fetched_at": _now(),
        }

    dist = data.get("dist-tags") or {}
    times = data.get("time") or {}
    latest = dist.get("latest")
    latest_time = times.get(latest) if latest else times.get("modified")
    days_since = _days_since_iso(latest_time)

    maintainers = data.get("maintainers") or []
    repo = (data.get("repository") or {}).get("url")

    signals = []
    if days_since is not None and days_since > 730:
        signals.append(f"no release in {days_since} days")
    if len(maintainers) <= 1:
        signals.append("single maintainer")
    versions = data.get("versions") or {}
    if len(versions) < 3:
        signals.append("very few releases (typosquat risk)")

    return {
        "ecosystem": "npm",
        "name": name,
        "latest_version": latest,
        "latest_release_at": latest_time,
        "days_since_release": days_since,
        "total_releases": len(versions),
        "maintainer_count": len(maintainers),
        "repository_url": repo,
        "summary": _cap(data.get("description"), 300),
        "signals": signals,
        "source": "registry.npmjs.org",
        "fetched_at": _now(),
    }


def _days_since_iso(ts: str | None) -> int | None:
    if not ts:
        return None
    # Accept both "2026-05-14T19:25:26" and "...Z" / "+00:00" suffixes.
    s = ts.rstrip("Z")
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except ValueError:
        return None


def _version_key(v: str) -> tuple:
    """Best-effort version sort key. Splits on common separators,
    converts numeric segments to zero-padded strings so a tuple compare
    works. Handles common PEP 440, semver, and package-manager versions.
    Not a complete implementation of either spec; verify suggested
    upgrades against the package's release notes."""
    if not v:
        return ()
    parts = re.split(r"[.\-_+]", str(v))
    out: list[tuple[int, str]] = []
    for p in parts:
        if p.isdigit():
            out.append((0, p.zfill(10)))
        else:
            # Split mixed segments like "1rc2" into numeric + suffix.
            m = re.match(r"(\d+)([A-Za-z].*)$", p)
            if m:
                out.append((0, m.group(1).zfill(10)))
                out.append((1, m.group(2)))
            else:
                out.append((1, p))
    return tuple(out)


if __name__ == "__main__":
    mcp.run()
