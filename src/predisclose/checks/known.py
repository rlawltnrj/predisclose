"""Check 1: is there already a public record of this issue?"""

from __future__ import annotations

import re
from collections.abc import Callable

from predisclose.checks.similarity import score
from predisclose.ecosystems import GHSA_ECOSYSTEM
from predisclose.http import Http, NetworkError, RateLimited
from predisclose.models import LEVELS, CheckResult, Evidence, Finding, max_level, plural
from predisclose.sources import ghsa, github, osv
from predisclose.sources.advisory import Advisory, merge

NAME = "public_record"


_EXACT_VERSION = re.compile(r"(\d+!)?v?\d+(\.\d+)*([.+_-]?[0-9A-Za-z][0-9A-Za-z.+_-]*)?")


# Words that name many versions, or a moving branch head rather than a tested release.
_RANGE_WORDS = {"latest", "stable", "next", "head", "any", "all", "*",
                "main", "master", "develop", "dev", "trunk", "default"}


def looks_like_range(version: str) -> bool:
    """True for things that name many versions (4.x, 2.10.*, >=1.0, ^1.2, ~1.2, latest), as opposed
    to one release or a tag name such as curl-8_0_0 or openssl-3.0.0."""
    v = version.strip()
    if not v or v.lower() in _RANGE_WORDS or "*" in v or " " in v:
        return True
    if v[0] in "<>=^~![(":  # comparators and Maven/NuGet ranges such as [1.0,2.0)
        return True
    # A number followed by an "x" segment: 4.x, 1.x.x, release-1.x, node-v18.x (not 1.0.0-x.1)
    return bool(re.search(r"\d\.[xX](?=$|\.)", v))


def is_exact_version(version: str) -> bool:
    """True for something like 1.2.3, v0.16.0, 2.0.0-rc1, 20260522 or a Go pseudo-version;
    False for ranges and words such as 4.x, 2.10.*, >=1.0 or latest."""
    v = version.strip()
    if "*" in v or not _EXACT_VERSION.fullmatch(v):
        return False
    # "x" is a wildcard only in the numeric part (4.x, 1.x.x), not in a suffix like 1.0.0-x.1.
    core = re.split(r"[-+]", v, maxsplit=1)[0]
    return not any(part.lower() == "x" for part in core.split("."))


def gather(http: Http, finding: Finding) -> tuple[list[Advisory], list[str]]:
    """
    Collect advisories that affect the target. Returns (advisories, notes).
    If one source fails, the other's results are kept with a note saying the list is incomplete;
    if nothing could be collected because of a failure, the failure is raised (never "none found").
    """
    notes: list[str] = []
    found: list[Advisory] = []
    failures: list[str] = []

    def collect(fetch: Callable[[], list[Advisory]]) -> list[Advisory]:
        try:
            return fetch()
        except (NetworkError, RateLimited) as exc:
            failures.append(str(exc))
            return []

    if finding.package and finding.ecosystem:
        version = finding.version
        if version and not is_exact_version(version):
            # OSV answers a range or a word like "latest" with most advisories, which would then
            # be labelled "affects this version". Ask without a version instead and say so.
            notes.append(f"{version!r} is not an exact version, so advisories are not filtered by version.")
            version = None
        found += collect(lambda: osv.query_package(http, finding.ecosystem, finding.package, version))
        ghsa_eco = GHSA_ECOSYSTEM.get(finding.ecosystem)
        if ghsa_eco:
            from_ghsa = collect(lambda: ghsa.query_affects(http, ghsa_eco, finding.package, version))
            if len(from_ghsa) >= ghsa.PAGE:
                notes.append(f"GitHub returned its maximum of {ghsa.PAGE} advisories; older ones may be missing.")
            found += from_ghsa
        if not finding.version:
            notes.append("No version given: showing every advisory for the package.")
    elif finding.repo:
        if finding.version:
            resolved = github.resolve_version(http, finding.repo, finding.version)
            if resolved:
                found += collect(lambda: osv.query_commit(http, resolved[1]))
            else:
                notes.append(f"Could not find tag or commit {finding.version!r} in {finding.repo}.")
        from_repo = collect(lambda: ghsa.repo_advisories(http, finding.repo))
        if len(from_repo) >= ghsa.PAGE:
            notes.append(
                f"GitHub returned its maximum of {ghsa.PAGE} repository advisories; older ones may be missing."
            )
        found += from_repo
        notes.append("Repository advisories are not filtered by version.")
    if failures and not found:
        raise NetworkError("; ".join(failures))
    merged = merge(found)
    withdrawn = [a for a in merged if a.withdrawn]
    if withdrawn:
        notes.append(
            f"Left out {plural(len(withdrawn), 'withdrawn advisory', 'withdrawn advisories')}: "
            + ", ".join(a.display_id() for a in withdrawn[:5])
        )
    if failures:
        notes.insert(0, "Incomplete: " + "; ".join(failures) + ". Only the other source's advisories are shown.")
    return [a for a in merged if not a.withdrawn], notes


def check(http: Http, finding: Finding, advisories: list[Advisory], notes: list[str]) -> CheckResult:
    if not (finding.package or finding.repo):
        return CheckResult(NAME, "skipped", "none", "Need --pkg or --repo.")
    if http.dry_run:
        return CheckResult(NAME, "skipped", "none", "Dry run: nothing was sent.")

    evidence: list[Evidence] = []
    for adv in advisories:
        level, reasons = score(adv, finding)
        evidence.append(
            Evidence(
                source="+".join(sorted(adv.sources)),
                id=adv.display_id(),
                title=adv.title(),
                url=adv.url,
                date=(adv.published or "")[:10] or None,
                level=level,
                reasons=reasons,
            )
        )
    evidence.sort(key=lambda e: (LEVELS.index(e.level), e.date or ""), reverse=True)

    if not evidence:
        if finding.package:
            notes.append(
                "Advisories are filed per package. If this package mostly bundles others (for example "
                "rails, whose code lives in actionpack, activerecord and so on), check those too."
            )
        return CheckResult(
            NAME,
            "none",
            "none",
            f"No public advisory found for {finding.target()}.",
            notes=notes,
        )
    strong = sum(e.level == "strong" for e in evidence)
    medium = sum(e.level == "medium" for e in evidence)
    checked = sum(a.version_checked for a in advisories)
    unchecked = len(advisories) - checked
    what = f"{finding.ecosystem} {finding.package}" if finding.package else finding.repo
    if checked and not unchecked:
        summary = f"{plural(checked, 'public advisory', 'public advisories')} affect"
        summary += f"{'s' if checked == 1 else ''} {finding.target()}"
    elif checked:
        summary = (
            f"{plural(checked, 'public advisory', 'public advisories')} affect{'s' if checked == 1 else ''} "
            f"{finding.target()}, plus {unchecked} more for {what} not filtered by version"
        )
    else:
        count = plural(len(evidence), "public advisory", "public advisories")
        summary = f"{count} for {what} (not filtered by version)"
    if finding.cwe or finding.files or finding.functions or finding.keywords:
        summary += f"; {strong} strong and {medium} medium {'match' if strong + medium == 1 else 'matches'}"
        if strong:
            summary += " - likely already known"
    else:
        summary += "; add --cwe/--file/--function to rank them"
    if any(n.startswith("Incomplete:") for n in notes):
        summary += " (incomplete: one advisory source failed, see notes)"
    return CheckResult(
        NAME, "found", max_level([e.level for e in evidence]), summary, evidence, notes
    )
