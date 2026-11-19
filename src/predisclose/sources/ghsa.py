"""GitHub Advisory Database (global advisories) and published repository advisories."""

from __future__ import annotations

from typing import Any

from predisclose.ecosystems import parse_repo
from predisclose.http import Http
from predisclose.sources.advisory import Advisory

API = "https://api.github.com"


def query_affects(
    http: Http, ghsa_ecosystem: str, name: str, version: str | None = None
) -> list[Advisory]:
    affects = f"{name}@{version}" if version else name
    status, data = http.get_json(
        f"{API}/advisories",
        params={"ecosystem": ghsa_ecosystem, "affects": affects, "per_page": 100},
    )
    if status != 200 or not isinstance(data, list):
        return []
    return [to_advisory(a, version_checked=bool(version)) for a in data]


def repo_advisories(http: Http, repo: str) -> list[Advisory]:
    """Published advisories of one repository. These are not filtered by version."""
    status, data = http.get_json(
        f"{API}/repos/{repo}/security-advisories", params={"state": "published", "per_page": 100}
    )
    if status != 200 or not isinstance(data, list):
        return []
    return [to_advisory(a, version_checked=False) for a in data]


def to_advisory(a: dict[str, Any], *, version_checked: bool) -> Advisory:
    ghsa_id = str(a.get("ghsa_id", ""))
    aliases: set[str] = set()
    if a.get("cve_id"):
        aliases.add(str(a["cve_id"]))
    for ident in a.get("identifiers") or []:
        value = ident.get("value")
        if value:
            aliases.add(str(value))
    aliases.discard(ghsa_id)

    cwes: set[str] = set()
    for c in a.get("cwes") or []:
        if isinstance(c, dict) and c.get("cwe_id"):
            cwes.add(str(c["cwe_id"]).upper())
        elif isinstance(c, str):
            cwes.add(c.upper())
    cwes.update(str(c).upper() for c in a.get("cwe_ids") or [])

    functions: set[str] = set()
    for vuln in a.get("vulnerabilities") or []:
        functions.update(str(f) for f in vuln.get("vulnerable_functions") or [])

    refs = [str(r) if not isinstance(r, dict) else str(r.get("url") or "") for r in a.get("references") or []]
    fix_refs = [r for r in refs if "/commit/" in r]

    return Advisory(
        id=ghsa_id,
        aliases=aliases,
        summary=str(a.get("summary") or ""),
        details=str(a.get("description") or ""),
        published=a.get("published_at"),
        cwes=cwes,
        functions=functions,
        url=str(a.get("html_url") or f"https://github.com/advisories/{ghsa_id}"),
        sources={"ghsa"},
        repo_hint=parse_repo(a.get("source_code_location") or ""),
        fix_refs=fix_refs,
        version_checked=version_checked,
    )
