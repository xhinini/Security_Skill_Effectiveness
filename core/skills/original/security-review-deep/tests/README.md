# Integration test

A live smoke test for the `mcp-server/` security-advisories server. It calls
the server's tools against well-known, stable identifiers and checks structural
invariants.

```bash
./run_integration.sh
# Result: pass=8 fail=0 skip=0
```

What it covers:
- **Offline validation** (always runs): the input validators reject malformed
  CVE ids and package names.
- **Live API checks** (skipped if no network): Log4Shell (`CVE-2021-44228`) is
  reported in CISA KEV, `composite_risk` returns a valid 0-100 score,
  `epss_score` returns a score field, `package_health` resolves `requests`, and
  `recent_critical_cves` exposes its truncation fields.

Design notes:
- **No fixtures.** The server's tools take identifiers (CVE ids, package
  names), not directories, so there is nothing vulnerable to seed — no fake
  secrets, no vulnerable dependency manifest, nothing GitHub secret-scanning,
  push protection, or Dependabot would flag.
- **Live, so manual.** It hits OSV/NVD/GHSA/KEV/EPSS/PyPI. Run it after changing
  the server file, not in CI. A network or upstream-API failure is reported as a
  **skip**, not a failure, so a flaky API doesn't produce false regressions.
- **Exits 1 on a real regression** (a tool that raises, or a broken invariant),
  0 otherwise. Assertions are structural (field presence, ranges, permanent KEV
  membership) rather than volatile values (EPSS scores change daily).

To extend: add a `check(...)` call in `integration_test.py` with a structural
assertion that won't flap on live data.
