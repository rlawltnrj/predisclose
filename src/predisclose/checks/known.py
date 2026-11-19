"""Check 1: is there already a public record of this issue?"""

from __future__ import annotations

from predisclose.checks.similarity import score
from predisclose.ecosystems import GHSA_ECOSYSTEM
from predisclose.http import Http
from predisclose.models import LEVELS, CheckResult, Evidence, Finding, max_level, plural
from predisclose.sources import ghsa, github, osv
from predisclose.sources.advisory import Advisory, merge

NAME = "public_record"


def gather(http: Http, finding: Finding) -> tuple[list[Advisory], list[str]]:
    """Collect advisories that affect the target. Returns (advisories, notes)."""
    notes: list[str] = []
    found: list[Advisory] = []
    if finding.package and finding.ecosystem:
        found += osv.query_package(http, finding.ecosystem, finding.package, finding.version)
        ghsa_eco = GHSA_ECOSYSTEM.get(finding.ecosystem)
        if ghsa_eco:
            found += ghsa.query_affects(http, ghsa_eco, finding.package, finding.version)
        if not finding.version:
            notes.append("No version given: showing every advisory for the package.")
    elif finding.repo:
        if finding.version:
            resolved = github.resolve_version(http, finding.repo, finding.version)
            if resolved:
                found += osv.query_commit(http, resolved[1])
            else:
                notes.append(f"Could not find tag or commit {finding.version!r} in {finding.repo}.")
        found += ghsa.repo_advisories(http, finding.repo)
        notes.append("Repository advisories are not filtered by version.")
    return merge(found), notes


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
        return CheckResult(
            NAME,
            "none",
            "none",
            f"No public advisory found for {finding.target()}.",
            notes=notes,
        )
    strong = sum(e.level == "strong" for e in evidence)
    medium = sum(e.level == "medium" for e in evidence)
    summary = f"{plural(len(evidence), 'public advisory', 'public advisories')} affect"
    summary += f"{'s' if len(evidence) == 1 else ''} {finding.target()}"
    if finding.cwe or finding.files or finding.functions or finding.keywords:
        summary += f"; {strong} strong and {medium} medium {'match' if strong + medium == 1 else 'matches'}"
        if strong:
            summary += " - likely already known"
    else:
        summary += "; add --cwe/--file/--function to rank them"
    return CheckResult(
        NAME, "found", max_level([e.level for e in evidence]), summary, evidence, notes
    )
