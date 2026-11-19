"""A common shape for advisories from OSV and the GitHub Advisory Database, plus merging."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Advisory:
    id: str
    aliases: set[str] = field(default_factory=set)
    summary: str = ""
    details: str = ""
    published: str | None = None
    cwes: set[str] = field(default_factory=set)
    functions: set[str] = field(default_factory=set)
    url: str = ""
    sources: set[str] = field(default_factory=set)
    fix_refs: list[str] = field(default_factory=list)
    repo_hint: str | None = None
    version_checked: bool = True

    def all_ids(self) -> set[str]:
        return {self.id, *self.aliases}

    def display_id(self) -> str:
        for prefix in ("GHSA-", "CVE-"):
            for candidate in sorted(self.all_ids()):
                if candidate.startswith(prefix):
                    return candidate
        return self.id

    def title(self) -> str:
        text = self.summary.strip() or self.details.strip().split("\n", 1)[0]
        return text[:140] if text else "(no summary)"


def merge(advisories: list[Advisory]) -> list[Advisory]:
    """Combine records that describe the same advisory: any chain of shared ids or aliases."""
    parent = list(range(len(advisories)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    owner: dict[str, int] = {}
    for i, adv in enumerate(advisories):
        for ident in adv.all_ids():
            if ident in owner:
                parent[find(i)] = find(owner[ident])
            else:
                owner[ident] = i

    groups: dict[int, list[Advisory]] = {}
    for i, adv in enumerate(advisories):
        groups.setdefault(find(i), []).append(adv)
    return [_combine(group) for group in groups.values()]


def _combine(group: list[Advisory]) -> Advisory:
    target = group[0]
    for adv in group[1:]:
        target.aliases |= adv.all_ids()
        target.cwes |= adv.cwes
        target.functions |= adv.functions
        target.sources |= adv.sources
        for ref in adv.fix_refs:
            if ref not in target.fix_refs:
                target.fix_refs.append(ref)
        if len(adv.details) > len(target.details):
            target.details = adv.details
        if not target.summary and adv.summary:
            target.summary = adv.summary
        if not target.published and adv.published:
            target.published = adv.published
        if not target.repo_hint and adv.repo_hint:
            target.repo_hint = adv.repo_hint
        if adv.url.startswith("https://github.com/advisories/"):
            target.url = adv.url
        target.version_checked = target.version_checked or adv.version_checked
    target.aliases.discard(target.id)
    return target
