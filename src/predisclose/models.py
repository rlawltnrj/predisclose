"""Plain data types shared by every check."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Ordered from weakest to strongest.
LEVELS = ("none", "info", "weak", "medium", "strong")

DISCLAIMER = (
    "No public record does not mean the issue is new: reports sent privately by others "
    "are not visible to anyone but the maintainers. Re-test on the latest release and "
    "follow the project's security policy."
)


def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else (many or word + 's')}"


def max_level(levels: list[str]) -> str:
    best = "none"
    for level in levels:
        if LEVELS.index(level) > LEVELS.index(best):
            best = level
    return best


@dataclass
class Finding:
    """What the user tells us. Free-text descriptions never live here: they stay local."""

    ecosystem: str | None = None  # OSV ecosystem name, e.g. "PyPI"
    package: str | None = None
    version: str | None = None
    repo: str | None = None  # "owner/name" on GitHub
    cwe: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)

    def target(self) -> str:
        if self.package:
            text = f"{self.ecosystem} {self.package}"
        elif self.repo:
            text = self.repo
        else:
            text = "(no target)"
        if self.version:
            text += f" {self.version}"
        return text


@dataclass
class Evidence:
    source: str
    id: str
    title: str
    url: str
    date: str | None = None
    level: str = "weak"
    reasons: list[str] = field(default_factory=list)


@dataclass
class CheckResult:
    check: str  # public_record | public_fix | recent_activity | where_to_report
    status: str  # found | none | skipped | error
    level: str  # one of LEVELS
    summary: str
    evidence: list[Evidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Report:
    tool_version: str
    generated_at: str
    finding: Finding
    results: list[CheckResult]
    queries: list[str]
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
