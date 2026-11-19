"""OSV (https://osv.dev): free, no key needed."""

from __future__ import annotations

from typing import Any

from predisclose.http import Http, NetworkError
from predisclose.sources.advisory import Advisory

QUERY_URL = "https://api.osv.dev/v1/query"


def query_package(
    http: Http, ecosystem: str, name: str, version: str | None = None
) -> list[Advisory]:
    body: dict[str, Any] = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        body["version"] = version
    advisories = [to_advisory(v) for v in _paged(http, body)]
    if not version:
        for adv in advisories:
            adv.version_checked = False
    return advisories


def query_commit(http: Http, sha: str) -> list[Advisory]:
    return [to_advisory(v) for v in _paged(http, {"commit": sha})]


def _paged(http: Http, body: dict[str, Any], max_pages: int = 5) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    token = None
    for _ in range(max_pages):
        payload = dict(body)
        if token:
            payload["page_token"] = token
        status, data = http.post_json(QUERY_URL, payload)
        if http.dry_run:
            break
        # A failed answer must not read as "no advisories": that is the worst false negative.
        if status != 200 or not isinstance(data, dict):
            raise NetworkError(f"OSV query failed (HTTP {status})")
        out.extend(data.get("vulns") or [])
        token = data.get("next_page_token")
        if not token:
            break
    return out


def to_advisory(v: dict[str, Any]) -> Advisory:
    vid = str(v.get("id", ""))
    db = v.get("database_specific") or {}
    cwes = {str(c).upper() for c in (db.get("cwe_ids") or [])}
    functions: set[str] = set()
    for affected in v.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        eco_specific = affected.get("ecosystem_specific") or {}
        for imp in eco_specific.get("imports") or []:  # Go vulndb style
            if isinstance(imp, dict):
                functions.update(str(s) for s in imp.get("symbols") or [] if s)
        functions.update(str(s) for s in eco_specific.get("affected_functions") or [])
    fix_refs = [
        str(r.get("url") or "")
        for r in v.get("references") or []
        if isinstance(r, dict) and (r.get("type") == "FIX" or "/commit/" in str(r.get("url") or ""))
    ]
    return Advisory(
        id=vid,
        aliases={str(a) for a in v.get("aliases") or []},
        summary=str(v.get("summary") or ""),
        details=str(v.get("details") or ""),
        published=v.get("published"),
        cwes=cwes,
        functions=functions,
        url=f"https://osv.dev/vulnerability/{vid}",
        sources={"osv"},
        fix_refs=[u for u in fix_refs if u],
        withdrawn=bool(v.get("withdrawn")),
    )
