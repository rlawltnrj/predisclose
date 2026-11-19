"""Run the checks for one finding and build a Report."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from predisclose import __version__
from predisclose.checks import activity, fixes, known, route
from predisclose.http import Http, NetworkError, RateLimited
from predisclose.models import CheckResult, Finding, Report
from predisclose.sources import github, registry

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
    except Exception as exc:  # one strange public record must not stop the other checks
        return CheckResult(name, "error", "none", f"Unexpected data ({type(exc).__name__}): {exc}")


def run_check(http: Http, finding: Finding, checks: Iterable[str] = ALL_CHECKS) -> Report:
    wanted = [c for c in ALL_CHECKS if c in set(checks)]
    results: list[CheckResult] = []
    repo_note = None
    package_problem = None  # set when the registry says the package does not exist
    repo_problem = None  # set when GitHub says the repository does not exist

    # Map a package to its source repository when the user did not give one, and catch typos:
    # a misspelled package name would otherwise look like "no public record".
    if finding.package and finding.ecosystem:
        try:
            inferred, exists = registry.lookup(http, finding.ecosystem, finding.package)
        except Exception:
            inferred, exists = None, None
        if exists is False and not http.dry_run:
            package_problem = (
                f"{finding.ecosystem} has no package named {finding.package!r}. Check the spelling: "
                "results for a wrong name say nothing about your finding."
            )
        if not finding.repo and inferred:
            finding.repo = inferred
            repo_note = f"Repository {inferred} taken from {finding.ecosystem} metadata."

    if finding.repo and not http.dry_run and not package_problem:
        try:
            if github.repo_info(http, finding.repo) is None:
                repo_problem = f"Repository {finding.repo} not found or not public. Check the name."
        except Exception:
            pass

    advisories, gather_notes = [], []
    if not package_problem and ("known" in wanted or not finding.repo):
        try:
            advisories, gather_notes = known.gather(http, finding)
        except Exception as exc:
            message = str(exc) if isinstance(exc, (RateLimited, NetworkError)) else (
                f"Unexpected data ({type(exc).__name__}): {exc}"
            )
            results.append(CheckResult(known.NAME, "error", "none", message))
            wanted = [c for c in wanted if c != "known"]

    if not finding.repo:
        hint = next((a.repo_hint for a in advisories if a.repo_hint), None)
        if hint:
            finding.repo = hint
            repo_note = f"Repository {hint} taken from advisory data."

    def blocked(name: str, needs_repo: bool) -> CheckResult | None:
        if package_problem:
            return CheckResult(name, "error", "none", package_problem)
        if repo_problem and (needs_repo or not finding.package):
            return CheckResult(name, "error", "none", repo_problem)
        return None

    if "known" in wanted:
        result = blocked(known.NAME, needs_repo=False) or _guard(
            known.NAME, lambda: known.check(http, finding, advisories, gather_notes)
        )
        if repo_note and result.status != "error":
            result.notes.append(repo_note)
        results.append(result)
    if "fixes" in wanted:
        results.append(
            blocked(fixes.NAME, needs_repo=True)
            or _guard(fixes.NAME, lambda: fixes.check(http, finding, advisories))
        )
    if "activity" in wanted:
        results.append(
            blocked(activity.NAME, needs_repo=False)
            or _guard(activity.NAME, lambda: activity.check(http, finding))
        )
    if "route" in wanted:
        results.append(
            blocked(route.NAME, needs_repo=True) or _guard(route.NAME, lambda: route.check(http, finding.repo))
        )

    return Report(
        tool_version=__version__,
        generated_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        finding=finding,
        results=results,
        queries=list(http.queries),
    )
