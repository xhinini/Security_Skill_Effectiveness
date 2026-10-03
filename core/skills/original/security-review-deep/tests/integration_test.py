"""Live smoke test for the security-advisories MCP server.

Calls the server's tools against well-known, stable identifiers (Log4Shell
is permanently in CISA KEV; `requests` is permanently maintained) and checks
structural invariants. There are no fixtures: the tools take identifiers, not
directories, so nothing vulnerable, no fake secrets, and no dependency
manifest get committed — nothing for GitHub to flag.

Network failures are reported as skips, not failures, so a flaky upstream API
doesn't cry wolf. Real regressions (a tool that raises, or a broken invariant)
fail with exit 1. Run it after changing the server file; see README.md.
"""

import asyncio
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "mcp-server"))
import mcp_security_server as srv  # noqa: E402

KEV_CVE = "CVE-2021-44228"  # Log4Shell — permanently in CISA KEV
NET_ERRORS = (srv.httpx.HTTPError, OSError)

results: list[tuple[str, str]] = []


def record(name: str, status: str, detail: str = "") -> None:
    results.append((name, status))
    mark = {"pass": "✓", "fail": "✗", "skip": "-"}[status]
    print(f"  {mark} {name}" + (f" — {detail}" if detail else ""))


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        raise AssertionError(msg)


def online() -> bool:
    for host in ("api.first.org", "www.cisa.gov"):
        try:
            socket.create_connection((host, 443), timeout=5).close()
            return True
        except OSError:
            continue
    return False


async def check(name, coro, assertion) -> None:
    """Run a live tool call: network error -> skip, broken invariant -> fail."""
    try:
        result = await coro
    except NET_ERRORS as e:
        record(name, "skip", f"network: {type(e).__name__}")
        return
    except Exception as e:  # noqa: BLE001 — any other raise is a real regression
        record(name, "fail", f"{type(e).__name__}: {e}")
        return
    try:
        assertion(result)
        record(name, "pass")
    except AssertionError as e:
        record(name, "fail", str(e))


async def expect_raises(name, factory, exc=ValueError) -> None:
    """Offline, deterministic: input validation must reject bad identifiers."""
    try:
        await factory()
    except exc:
        record(name, "pass")
    except Exception as e:  # noqa: BLE001
        record(name, "fail", f"raised {type(e).__name__}, expected {exc.__name__}")
    else:
        record(name, "fail", "no exception raised")


async def main() -> int:
    print("Offline validation (no network):")
    await expect_raises("lookup_cve rejects malformed id", lambda: srv.lookup_cve("not-a-cve"))
    await expect_raises("kev_lookup rejects malformed id", lambda: srv.kev_lookup("xyz"))
    # A space is disallowed by _PKG_NAME_RE; note `/` and `.` are allowed on
    # purpose (npm scoped names like @scope/pkg), so they are NOT invalid here.
    await expect_raises("package_health rejects bad name", lambda: srv.package_health("PyPI", "foo bar"))

    if not online():
        print("\nNo network reachable — skipping live API checks.")
        for n in ("kev_lookup", "composite_risk", "epss_score", "package_health", "recent_critical_cves"):
            record(f"{n} (live)", "skip", "offline")
    else:
        print("\nLive API checks:")
        await check(
            "kev_lookup reports Log4Shell in KEV",
            srv.kev_lookup(KEV_CVE),
            lambda r: _assert(r.get("in_kev") is True, "Log4Shell should be in KEV"),
        )
        await check(
            "composite_risk returns a valid 0-100 score",
            srv.composite_risk(KEV_CVE),
            lambda r: _assert(
                isinstance(r.get("composite_score"), (int, float))
                and 0 <= r["composite_score"] <= 100
                and r.get("triage_bucket") in {"Critical", "High", "Medium", "Low", "Unknown"},
                f"unexpected composite shape: {r.get('composite_score')!r}/{r.get('triage_bucket')!r}",
            ),
        )
        await check(
            "epss_score returns a score field",
            srv.epss_score(KEV_CVE),
            lambda r: _assert("score" in r, "missing 'score' key"),
        )
        await check(
            "package_health resolves a known package",
            srv.package_health("PyPI", "requests"),
            lambda r: _assert(isinstance(r, dict) and not r.get("error"), f"error: {r.get('error')!r}"),
        )
        await check(
            "recent_critical_cves exposes truncation fields",
            srv.recent_critical_cves(days=3),
            lambda r: _assert(
                isinstance(r.get("cves"), list)
                and isinstance(r.get("result_may_be_truncated"), bool)
                and isinstance(r.get("total_available"), int),
                "missing cves/result_may_be_truncated/total_available",
            ),
        )

    p = sum(1 for _, s in results if s == "pass")
    f = sum(1 for _, s in results if s == "fail")
    sk = sum(1 for _, s in results if s == "skip")
    print(f"\nResult: pass={p} fail={f} skip={sk}")
    return 1 if f else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
