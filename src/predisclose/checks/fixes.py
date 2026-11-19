"""Check 2: has the code been changed publicly since the tested version?"""

from __future__ import annotations

import posixpath
import re

from predisclose.checks.known import looks_like_range
from predisclose.checks.similarity import score
from predisclose.http import Http
from predisclose.models import LEVELS, CheckResult, Evidence, Finding, max_level, plural
from predisclose.sources import github
from predisclose.sources.advisory import Advisory

NAME = "public_fix"

SECURITY_TERMS = re.compile(
    r"\b(security|vulnerab\w*|cve-\d{4}-\d+|ghsa-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}|exploit\w*|"
    r"injection|xss|csrf|ssrf|xxe|traversal|overflow|sanitiz\w*|escap\w*|unsafe|bypass|"
    r"denial of service|redos|leak\w*|privilege\w*|deserializ\w*|authentication|authorization)\b",
    re.IGNORECASE,
)

ALWAYS = "Re-test on the latest release yourself before reporting."
COMMIT_URL = re.compile(r"/commit/([0-9a-f]{7,40})", re.IGNORECASE)


def known_fix_commits(advisories: list[Advisory]) -> dict[str, str]:
    """Commit sha (lowercase, any length >= 7) -> advisory id, from public advisory references."""
    out: dict[str, str] = {}
    for adv in advisories:
        for url in adv.fix_refs:
            m = COMMIT_URL.search(url)
            if m:
                out.setdefault(m.group(1).lower(), adv.display_id())
    return out


def referenced_fixes(finding: Finding, advisories: list[Advisory], seen: set[str]) -> list[Evidence]:
    """Fix commits named by advisories that resemble the finding (they may sit on a release branch)."""
    out: list[Evidence] = []
    for adv in advisories:
        level, _ = score(adv, finding)
        if level not in ("medium", "strong"):
            continue
        for url in adv.fix_refs:
            m = COMMIT_URL.search(url)
            if not m:
                continue
            sha = m.group(1).lower()
            if any(s.startswith(sha) or sha.startswith(s) for s in seen):
                continue
            seen.add(sha)
            out.append(
                Evidence(
                    source="advisory",
                    id=sha[:12],
                    title=f"Fix commit referenced by {adv.display_id()}",
                    url=url,
                    level="medium",
                    reasons=[f"public fix for {adv.display_id()}", "compare it with the code you tested"],
                )
            )
    return out


def _advisory_for(sha: str, fixes: dict[str, str]) -> str | None:
    s = sha.lower()
    for known_sha, adv_id in fixes.items():
        if s.startswith(known_sha) or known_sha.startswith(s[: len(known_sha)]):
            return adv_id
    return None


def _first_line(text: str) -> str:
    return (text or "").strip().split("\n", 1)[0][:140]


def resolve_paths(http: Http, repo: str, refs: list[str], path: str) -> tuple[list[str], list[str]]:
    """
    Map what the user typed (a full path, a partial path, or a bare file name) to real paths
    at the tested version and on the default branch, so moved files are still followed.
    Returns (paths, notes).
    """
    wanted = path.strip().strip("/")
    found: list[str] = []
    notes: list[str] = []
    for ref in refs:
        listing = github.tree_paths(http, repo, ref)
        if listing is None:
            continue
        paths, truncated = listing
        if truncated:
            notes.append(f"File list at {ref} is truncated; pass the full path to be exact.")
        exact = [p for p in paths if p == wanted]
        suffix = [p for p in paths if p.endswith("/" + wanted)]
        same_name = [p for p in paths if posixpath.basename(p) == posixpath.basename(wanted)]
        for p in (exact or suffix or same_name)[:5]:
            if p not in found:
                found.append(p)
    if not found:
        found = [wanted]
        notes.append(f"{wanted}: not found in the file list; searching history for it as typed.")
    elif len(found) > 1:
        notes.append(f"{wanted}: following {', '.join(found)}.")
    return found, notes


def check(http: Http, finding: Finding, advisories: list[Advisory] | None = None) -> CheckResult:
    if http.dry_run:
        return CheckResult(NAME, "skipped", "none", "Dry run: nothing was sent.")
    if not finding.repo:
        return CheckResult(NAME, "skipped", "none", "Need a repository (--repo, or a package we can map to one).")
    if not finding.version:
        return CheckResult(NAME, "skipped", "none", "Need --version to know where to start.")

    if looks_like_range(finding.version):
        return CheckResult(
            NAME,
            "skipped",
            "none",
            f"{finding.version!r} is not an exact version; pass the tag or commit you tested.",
            notes=[ALWAYS],
        )
    resolved = github.resolve_version(http, finding.repo, finding.version, finding.package)
    if not resolved:
        return CheckResult(
            NAME,
            "skipped",
            "none",
            f"No tag or commit {finding.version!r} found in {finding.repo}.",
            notes=["Pass the exact tag or commit sha with --version.", ALWAYS],
        )
    ref, sha, since = resolved
    fixes = known_fix_commits(advisories or [])
    evidence: list[Evidence] = []
    notes = [ALWAYS, "Only commits on the default branch are listed."]

    if finding.files:
        by_sha: dict[str, Evidence] = {}
        for typed in finding.files:
            paths, path_notes = resolve_paths(http, finding.repo, [sha, "HEAD"], typed)
            notes += path_notes
            for path in paths:
                commits = github.commits_since(http, finding.repo, since, path=path)
                if len(commits) >= 100:
                    notes.append(f"{path}: showing the latest 100 commits only.")
                for c in commits:
                    csha = str(c.get("sha", ""))
                    if csha == sha:
                        continue
                    if csha in by_sha:
                        reason = f"changed {path}"
                        if reason not in by_sha[csha].reasons:
                            by_sha[csha].reasons.insert(0, reason)
                        continue
                    message = (c.get("commit") or {}).get("message") or ""
                    hit = SECURITY_TERMS.search(message)
                    linked = _advisory_for(csha, fixes)
                    committed = ((c.get("commit") or {}).get("committer") or {}).get("date") or ""
                    reasons = [f"changed {path}"]
                    if linked:
                        reasons.append(f"public fix for {linked}")
                    if hit:
                        reasons.append(f"message mentions '{hit.group(0)}'")
                    by_sha[csha] = Evidence(
                        source="github",
                        id=csha[:12],
                        title=_first_line(message),
                        url=str(c.get("html_url") or ""),
                        date=committed[:10] or None,
                        level="medium" if (hit or linked) else "info",
                        reasons=reasons,
                    )
        evidence = list(by_sha.values())
        evidence += referenced_fixes(finding, advisories or [], seen=set(by_sha))
        flagged = sum(e.level == "medium" for e in evidence)
        linked_count = sum(any(r.startswith("public fix for") for r in e.reasons) for e in evidence)
        if not evidence:
            return CheckResult(
                NAME,
                "none",
                "none",
                f"No commits changed {', '.join(finding.files)} since {ref} ({since[:10]}).",
                notes=notes,
            )
        summary = (
            f"{plural(len(evidence), 'commit')} changed {', '.join(finding.files)} since {ref} ({since[:10]}); "
            f"{flagged} {'looks' if flagged == 1 else 'look'} security-related"
            + (f" ({linked_count} linked to public advisories)" if linked_count else "")
        )
    else:
        own_tags = {ref, finding.version, f"v{finding.version}"}
        for rel in github.releases(http, finding.repo):
            published = str(rel.get("published_at") or "")
            tag = str(rel.get("tag_name") or "")
            if not published or published <= since or tag in own_tags:
                continue
            body = f"{rel.get('name') or ''}\n{rel.get('body') or ''}"
            hit = SECURITY_TERMS.search(body)
            if not hit:
                continue
            evidence.append(
                Evidence(
                    source="github",
                    id=str(rel.get("tag_name") or ""),
                    title=_first_line(str(rel.get("name") or rel.get("tag_name") or "")),
                    url=str(rel.get("html_url") or ""),
                    date=published[:10],
                    level="medium",
                    reasons=[f"release notes mention '{hit.group(0)}'"],
                )
            )
        notes.append("Add --file to list commits that touched the affected code.")
        if not evidence:
            return CheckResult(
                NAME,
                "none",
                "none",
                f"No release since {ref} ({since[:10]}) mentions security terms "
                "(many projects don't describe fixes in release notes; pass --file to check commits).",
                notes=notes,
            )
        summary = (
            f"{plural(len(evidence), 'release')} since {ref} ({since[:10]}) "
            f"{'mentions' if len(evidence) == 1 else 'mention'} security terms"
        )

    evidence.sort(key=lambda e: (LEVELS.index(e.level), e.date or ""), reverse=True)
    return CheckResult(NAME, "found", max_level([e.level for e in evidence]), summary, evidence, notes)
