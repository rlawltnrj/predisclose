"""Input parsing: ecosystems, package specs, repositories, CWE ids."""

from __future__ import annotations

import re

# User-friendly names -> OSV ecosystem names.
ALIASES = {
    "pypi": "PyPI",
    "pip": "PyPI",
    "python": "PyPI",
    "npm": "npm",
    "node": "npm",
    "crates.io": "crates.io",
    "crates": "crates.io",
    "cargo": "crates.io",
    "rust": "crates.io",
    "go": "Go",
    "golang": "Go",
    "maven": "Maven",
    "nuget": "NuGet",
    "rubygems": "RubyGems",
    "gem": "RubyGems",
    "packagist": "Packagist",
    "composer": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
    "actions": "GitHub Actions",
    "github-actions": "GitHub Actions",
    "swift": "SwiftURL",
}

# OSV ecosystem names -> GitHub Advisory Database ecosystem names.
GHSA_ECOSYSTEM = {
    "PyPI": "pip",
    "npm": "npm",
    "crates.io": "rust",
    "Go": "go",
    "Maven": "maven",
    "NuGet": "nuget",
    "RubyGems": "rubygems",
    "Packagist": "composer",
    "Pub": "pub",
    "Hex": "erlang",
    "GitHub Actions": "actions",
    "SwiftURL": "swift",
}


def parse_package(spec: str) -> tuple[str, str]:
    """'pypi:jinja2' -> ('PyPI', 'jinja2'). Maven keeps 'group:artifact' after the first colon."""
    if ":" not in spec:
        raise ValueError(f"package must look like ECOSYSTEM:NAME (e.g. pypi:jinja2), got {spec!r}")
    eco, name = spec.split(":", 1)
    key = eco.strip().lower()
    if key not in ALIASES:
        known = ", ".join(sorted(set(ALIASES)))
        raise ValueError(f"unknown ecosystem {eco!r}; known: {known}")
    name = name.strip()
    if not name:
        raise ValueError("package name is empty")
    return ALIASES[key], name


_GITHUB_URL = re.compile(r"(?:^|[/@])(?:www\.)?github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")
# github.com/<these>/... are GitHub pages, not repositories.
_NOT_OWNERS = {
    "sponsors", "orgs", "marketplace", "apps", "settings", "features", "topics", "collections",
    "enterprise", "about", "pricing", "login", "notifications", "explore", "users", "security",
    "advisories", "site", "contact", "readme", "trending", "events", "customer-stories",
}
_OWNER_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def parse_repo(text: str | None) -> str | None:
    """Accept 'owner/name', a GitHub URL, or a git URL. Returns 'owner/name' or None."""
    if not text:
        return None
    t = text.strip()
    m = _GITHUB_URL.search(t)
    if m:
        owner, name = m.group(1), m.group(2)
    elif _OWNER_NAME.fullmatch(t):
        owner, name = t.split("/", 1)
    else:
        return None
    name = name.removesuffix(".git")
    if not owner or not name or owner in {".", ".."} or name in {".", ".."}:
        return None
    if owner.lower() in _NOT_OWNERS:
        return None
    return f"{owner}/{name}"


def normalize_cwe(value: str) -> str:
    """'79', 'cwe-79', 'CWE-79' -> 'CWE-79'."""
    v = value.strip().upper()
    if v.startswith("CWE-"):
        v = v[4:]
    if not v.isdigit():
        raise ValueError(f"CWE must be a number like 79 or CWE-79, got {value!r}")
    return f"CWE-{int(v)}"


_SHA = re.compile(r"[0-9a-f]{7,40}")


def looks_like_sha(value: str) -> bool:
    v = value.lower()
    # A date-like version such as 20231215 is all digits; a real abbreviated sha almost never is.
    return bool(_SHA.fullmatch(v)) and (len(v) == 40 or any(c in "abcdef" for c in v))
