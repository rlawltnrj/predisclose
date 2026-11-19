"""Check 3: has this area had advisories recently? Busy areas get more parallel reports."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from predisclose.checks.similarity import score
from predisclose.http import Http
from predisclose.models import CheckResult, Evidence, Finding, plural
from predisclose.sources import ghsa, osv
from predisclose.sources.advisory import Advisory, merge

NAME = "recent_activity"


def check(http: Http, finding: Finding, *, days: int = 365, now: datetime | None = None) -> CheckResult:
    if not (finding.package or finding.repo):
        return CheckResult(NAME, "skipped", "none", "Need --pkg or --repo.")
    if http.dry_run:
        return CheckResult(NAME, "skipped", "none", "Dry run: nothing was sent.")

    advisories: list[Advisory] = []
    if finding.package and finding.ecosystem:
        advisories = osv.query_package(http, finding.ecosystem, finding.package)
    if finding.repo:
        advisories += ghsa.repo_advisories(http, finding.repo)
    advisories = merge(advisories)

    cutoff = ((now or datetime.now(UTC)) - timedelta(days=days)).strftime("%Y-%m-%d")
    recent = [a for a in advisories if (a.published or "")[:10] >= cutoff]
    has_hints = bool(finding.cwe or finding.files or finding.functions)

    evidence: list[Evidence] = []
    similar = 0
    for adv in recent:
        level, reasons = score(adv, finding)
        is_similar = has_hints and level in ("medium", "strong")
        similar += is_similar
        evidence.append(
            Evidence(
                source="+".join(sorted(adv.sources)),
                id=adv.display_id(),
                title=adv.title(),
                url=adv.url,
                date=(adv.published or "")[:10] or None,
                level="medium" if is_similar else "info",
                reasons=[r for r in reasons if r not in ("affects this version", "same project")]
                or ["published recently"],
            )
        )
    evidence.sort(key=lambda e: e.date or "", reverse=True)

    if not recent:
        return CheckResult(
            NAME, "none", "none", f"No advisories published in the last {days} days."
        )
    summary = f"{plural(len(recent), 'advisory', 'advisories')} published in the last {days} days"
    notes: list[str] = []
    if similar:
        summary += f"; {similar} {'looks' if similar == 1 else 'look'} similar to your finding"
        notes.append(
            "Areas with recent similar advisories attract parallel reports. Check the "
            "public records carefully before writing your report."
        )
    level = "medium" if similar else "info"
    return CheckResult(NAME, "found", level, summary, evidence, notes)
