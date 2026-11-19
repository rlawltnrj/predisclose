"""Run the checks for one finding and build a Report."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from predisclose import __version__
from predisclose.checks import activity, fixes, known, route
from predisclose.http import Http, NetworkError, RateLimited
from predisclose.models import CheckResult, Finding, Report
from predisclose.sources import registry

ALL_CHECKS = ("known", "fixes", "activity", "route")
CHECK_NAMES = {
    "known": known.NAME,
    "fixes": fixes.NAME,
    "activity": activity.NAME,
    "route": route.NAME,
}


def _guard(name: str, fn) -> CheckResult:
    try:
        return fn()
    except RateLimited as exc:
        return CheckResult(name, "error", "none", str(exc))
    except NetworkError as exc:
        return CheckResult(name, "error", "none", f"Network error: {exc}")


def run_check(http: Http, finding: Finding, checks: Iterable[str] = ALL_CHECKS) -> Report:
    wanted = [c for c in ALL_CHECKS if c in set(checks)]
    results: list[CheckResult] = []

    # Map a package to its source repository when the user did not give one.
    repo_note = None
    if not finding.repo and finding.package and finding.ecosystem:
        try:
            finding.repo = registry.infer_repo(http, finding.ecosystem, finding.package)
            if finding.repo:
                repo_note = f"Repository {finding.repo} taken from {finding.ecosystem} metadata."
        except (RateLimited, NetworkError):
            pass

    advisories, gather_notes = [], []
    if "known" in wanted or not finding.repo:
        try:
            advisories, gather_notes = known.gather(http, finding)
        except (RateLimited, NetworkError) as exc:
            results.append(CheckResult(known.NAME, "error", "none", str(exc)))
            wanted = [c for c in wanted if c != "known"]

    if not finding.repo:
        hint = next((a.repo_hint for a in advisories if a.repo_hint), None)
        if hint:
            finding.repo = hint
            repo_note = f"Repository {hint} taken from advisory data."

    if "known" in wanted:
        result = known.check(http, finding, advisories, gather_notes)
        if repo_note:
            result.notes.append(repo_note)
        results.append(result)
    if "fixes" in wanted:
        results.append(_guard(fixes.NAME, lambda: fixes.check(http, finding, advisories)))
    if "activity" in wanted:
        results.append(_guard(activity.NAME, lambda: activity.check(http, finding)))
    if "route" in wanted:
        results.append(_guard(route.NAME, lambda: route.check(http, finding.repo)))

    return Report(
        tool_version=__version__,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        finding=finding,
        results=results,
        queries=list(http.queries),
    )
